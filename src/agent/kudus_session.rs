//! agent kudus 会话：kudus:// 拨号 + Register/Config + 可靠传输 + 建流。
//! 与 `quic_session.rs` 语义对齐：SYN→SYN-ACK→Register→心跳→
//! Config/ConfigAck/Register 收敛→隧道泵。差异只在传输：
//! UDP datagram + XChaCha20-Poly1305（key=SHA256(token)），24B 随机 nonce 全隐身。
use crate::common::kudus::*;
use crate::common::proto::*;
use crate::common::quic::{decode_dgram, encode_dgram};
use super::{AgentFileConfig, Upstream};
use std::{collections::HashMap, net::SocketAddr, sync::Arc};
use tokio::{io::AsyncWriteExt, net::TcpStream, sync::{mpsc, RwLock}};

pub(crate) struct KCtx {
    pub(crate) proxies: RwLock<Vec<ProxyConfig>>,
    pub(crate) link_tasks: tokio::sync::Mutex<std::collections::HashMap<String, tokio::task::AbortHandle>>,
    pub(crate) streams: RwLock<HashMap<u32, mpsc::UnboundedSender<Vec<u8>>>>,
    pub(crate) pending: RwLock<HashMap<u32, Vec<Vec<u8>>>>,
}

/// 发包器：hdr + proto_frame 封包（mpsc 发 bytes，写泵统一 send_to 保序）。
#[derive(Clone)]
pub(crate) struct Pkt {
    pub(crate) out: mpsc::UnboundedSender<Vec<u8>>,
    pub(crate) key: [u8; 32],
    pub(crate) session: u32,
    pub(crate) next_seq: Arc<std::sync::atomic::AtomicU32>,
}

impl Pkt {
    pub(crate) fn send(&self, flags: u8, ack: u32, sack: [u8; 32], body: &[u8]) -> anyhow::Result<()> {
        let seq = self.next_seq.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let h = KudusHdr { ver: 1, flags, seq, ack, sack, ts_ms: now_ms() };
        let mut plain = encode_hdr(&h).to_vec();
        plain.extend_from_slice(body);
        if 4 + 24 + plain.len() + 16 > KUDUS_MAX_UDP {
            anyhow::bail!("kudus oversize frame ({}B)", plain.len());
        }
        let n = fresh_nonce();
        self.out
            .send(encode_packet(self.session, &n, &seal(&self.key, &n, &plain)))
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        Ok(())
    }
    pub(crate) fn send_ctrl(&self, m: &ClientMsg) -> anyhow::Result<()> {
        let j = serde_json::to_vec(m)?;
        self.send(FLAG_DATA, 0, [0u8; 32], &j)
    }
}

pub(crate) async fn session(
    up: Upstream,
    cfg: AgentFileConfig,
    status: Arc<RwLock<super::web::AgentStatus>>,
    kudus_out: super::egress::KudusOutHolder,
) -> anyhow::Result<()> {
    let (host, port) = match crate::common::quic::parse_server_url(&up.server_url) {
        crate::common::quic::Transport::Kudus { host, port } => (host, port),
        _ => anyhow::bail!("kudus: bad --server scheme (want kudus://host:port)"),
    };
    let addr: SocketAddr = format!("{host}:{port}").parse()?;
    let sock = Arc::new(tokio::net::UdpSocket::bind("0.0.0.0:0").await?);
    sock.connect(addr).await?;
    let key = derive_key(&up.token);
    let session_id: u32 = {
        use rand::RngCore;
        rand::thread_rng().next_u32()
    };
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let pkt = Pkt {
        out: out_tx.clone(),
        key,
        session: session_id,
        next_seq: Arc::new(std::sync::atomic::AtomicU32::new(1)),
    };
    *kudus_out.write().await = Some(pkt.clone());
    let ctx = Arc::new(KCtx {
        proxies: RwLock::new(cfg.proxies.clone()),
        link_tasks: tokio::sync::Mutex::new(HashMap::new()),
        streams: RwLock::new(HashMap::new()),
        pending: RwLock::new(HashMap::new()),
    });
    let kudus_link_holder = kudus_out.clone();
    super::link::sync_link_listeners_kudus(&ctx, &cfg.proxies, &up.hostname, &kudus_link_holder).await;
    // 写泵：datagram 串行 send_to（保序，SYN 重传也经此）。
    let wsock = sock.clone();
    let writer = tokio::spawn(async move {
        while let Some(d) = out_rx.recv().await {
            if wsock.send(&d).await.is_err() {
                break;
            }
        }
    });
    // 读泵：recv → 解密 → ts/seq 过滤 → 分发通道。
    let (dec_tx, mut dec_rx) = mpsc::unbounded_channel::<(KudusHdr, Vec<u8>)>();
    let rsock = sock.clone();
    let rkey = key;
    let reader = tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        let mut win = crate::server::kudus::SeqWindow::new(0);
        loop {
            let n = match rsock.recv(&mut buf).await {
                Ok(n) => n,
                Err(_) => break,
            };
            let Some((sess, nonce, ct)) = decode_packet(&buf[..n]) else {
                continue;
            };
            if sess != session_id {
                continue;
            }
            let Some(plain) = open(&rkey, nonce, ct) else {
                continue; // 黑洞包：丢
            };
            let Some((h, body)) = decode_hdr(&plain) else {
                continue;
            };
            if !crate::server::kudus::ts_fresh(h.ts_ms) {
                continue;
            }
            if h.flags & FLAG_DATA != 0 && !win.check(h.seq) {
                continue;
            }
            if dec_tx.send((h, body.to_vec())).is_err() {
                break;
            }
        }
    });
    // SYN（Hello）+ 等 SYN-ACK（Welcome，15s）
    let hello = ClientMsg::Hello {
        hostname: up.hostname.clone(),
        version: VERSION.into(),
        token: up.token.clone(),
    };
    let hj = serde_json::to_vec(&hello)?;
    pkt.send(FLAG_SYN, 0, [0u8; 32], &hj)?;
    let interval = loop {
        match tokio::time::timeout(std::time::Duration::from_secs(15), dec_rx.recv()).await {
            Ok(Some((h, body))) => {
                if h.flags & (FLAG_SYN | FLAG_ACK) == 0 {
                    continue;
                }
                match serde_json::from_slice::<ServerMsg>(&body)? {
                    ServerMsg::Welcome { interval, .. } => break interval,
                    ServerMsg::Error { reason } => anyhow::bail!("kudus server rejected: {reason}"),
                    _ => anyhow::bail!("kudus: expect welcome"),
                }
            }
            _ => anyhow::bail!("kudus: no welcome"),
        }
    };
    tracing::info!("kudus welcomed, heartbeat {interval}s");
    {
        let mut st = status.write().await;
        st.online = true;
        st.transport = "kudus".into();
        st.last_error = None;
    }
    pkt.send_ctrl(&ClientMsg::Register { proxies: cfg.proxies.clone() })?;
    // ping loop
    {
        let p = pkt.clone();
        tokio::spawn(async move {
            let mut iv = tokio::time::interval(std::time::Duration::from_secs(interval.max(5)));
            loop {
                iv.tick().await;
                let m = ClientMsg::Ping { ts: chrono::Utc::now().timestamp() };
                if p.send_ctrl(&m).is_err() {
                    break;
                }
            }
        });
    }
    // 主分发循环
    loop {
        let Some((h, body)) = dec_rx.recv().await else {
            break;
        };
        if h.flags & FLAG_FIN != 0 {
            // server FIN：回 ACK 即关。
            let _ = pkt.send(FLAG_ACK, h.seq, [0u8; 32], b"bye");
            break;
        }
        if let Ok(sm) = serde_json::from_slice::<ServerMsg>(&body) {
            match sm {
                ServerMsg::Pong { ts } => {
                    let now = chrono::Utc::now().timestamp();
                    let ms = ((now - ts).max(0) as u64).saturating_mul(1000);
                    status.write().await.rtt_ms = Some(ms);
                }
                ServerMsg::Open { stream, kind, host, port } => {
                    let ctx = ctx.clone();
                    let p = pkt.clone();
                    tokio::spawn(async move {
                        if let Err(e) = open_stream(ctx, p, stream, kind, host, port).await {
                            tracing::warn!("kudus open stream {stream} failed: {e:#}");
                        }
                    });
                }
                ServerMsg::Ping { ts } => {
                    let _ = pkt.send_ctrl(&ClientMsg::Pong { ts });
                }
                ServerMsg::Close { stream, .. } => {
                    ctx.streams.write().await.remove(&stream);
                    super::egress::egress_streams().write().await.remove(&stream);
                }
                ServerMsg::Config { proxies } => {
                    *ctx.proxies.write().await = proxies.clone();
                    super::link::sync_link_listeners_kudus(&ctx, &proxies, &up.hostname, &kudus_link_holder).await;
                    {
                        let mut st = status.write().await;
                        st.proxies = proxies.clone();
                    }
                    let _ = pkt.send_ctrl(&ClientMsg::ConfigAck { ok: true });
                    let _ = pkt.send_ctrl(&ClientMsg::Register { proxies });
                    tracing::info!("kudus hot config applied");
                }
                _ => {}
            }
            continue;
        }
        if let Some((id, payload)) = decode_data(&body) {
            deliver(&ctx, id, payload).await;
        }
    }
    // 本端 FIN（200ms ×3 尽力）
    for _ in 0..3 {
        let _ = pkt.send(FLAG_FIN, 0, [0u8; 32], b"bye");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    *kudus_out.write().await = None;
    writer.abort();
    reader.abort();
    anyhow::Ok(())
}

async fn deliver(ctx: &Arc<KCtx>, id: u32, payload: &[u8]) {
    if let Some(tx) = ctx.streams.read().await.get(&id).cloned() {
        let _ = tx.send(payload.to_vec());
    } else if payload.is_empty() && super::egress::egress_streams().read().await.contains_key(&id) {
        super::egress::egress_streams().write().await.remove(&id);
    } else if let Some(tx) = super::egress::egress_streams().read().await.get(&id).cloned() {
        let _ = tx.send(payload.to_vec());
    } else {
        ctx.pending.write().await.entry(id).or_default().push(payload.to_vec());
    }
}

/// 数据发送：裸字节包封 DATA 帧；UDP 包先套 dgram 帧保边界。
fn send_data(pkt: &Pkt, sid: u32, payload: &[u8], is_udp: bool) {
    let inner = if is_udp { encode_dgram(payload) } else { payload.to_vec() };
    let _ = pkt.send(FLAG_DATA, 0, [0u8; 32], &encode_data(sid, &inner));
}

async fn open_stream(
    ctx: Arc<KCtx>,
    pkt: Pkt,
    sid: u32,
    kind: String,
    host: String,
    port: u16,
) -> anyhow::Result<()> {
    if kind == "udp" {
        return open_udp_stream(ctx, pkt, sid, port).await;
    }
    if kind == "link" {
        let local = TcpStream::connect((host.as_str(), port)).await?;
        return pump_tcp(ctx, pkt, sid, local, false).await;
    }
    let proxies = ctx.proxies.read().await.clone();
    let target = if kind == "http" {
        proxies.iter().find(|p| {
            p.enabled && p.domains.iter().any(|d| d.eq_ignore_ascii_case(&host))
        })
    } else {
        proxies
            .iter()
            .find(|p| p.enabled && p.remote_port == port && (p.ptype == "tcp" || p.ptype == "https"))
            .or_else(|| proxies.iter().find(|p| p.enabled && (p.ptype == "tcp" || p.ptype == "https")))
    };
    let Some(p) = target else {
        let e = ClientMsg::Close { stream: sid, reason: "no route".into() };
        let _ = pkt.send_ctrl(&e);
        return Ok(());
    };
    let local = TcpStream::connect((p.local_ip.as_str(), p.local_port)).await?;
    tracing::debug!("kudus stream {sid} -> {}:{}", p.local_ip, p.local_port);
    pump_tcp(ctx, pkt, sid, local, kind == "http").await
}

async fn pump_tcp(
    ctx: Arc<KCtx>,
    pkt: Pkt,
    sid: u32,
    local: TcpStream,
    is_http: bool,
) -> anyhow::Result<()> {
    use super::stream::http_response_pump;
    let (dtx, mut drx) = mpsc::unbounded_channel::<Vec<u8>>();
    let early = ctx.pending.write().await.remove(&sid).unwrap_or_default();
    for chunk in early {
        let _ = dtx.send(chunk);
    }
    ctx.streams.write().await.insert(sid, dtx);
    let (lr, mut lw) = local.into_split();
    let ctx2 = ctx.clone();
    let ws_to_local = tokio::spawn(async move {
        while let Some(chunk) = drx.recv().await {
            if lw.write_all(&chunk).await.is_err() {
                break;
            }
        }
    });
    if is_http {
        let local_to_ws = tokio::spawn(http_response_pump(
            super::stream::KudusSender(pkt.clone()),
            sid,
            lr,
        ));
        let _ = local_to_ws.await;
        ws_to_local.abort();
    } else {
        let pkt2 = pkt.clone();
        let mut local_to_ws = tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            let mut b = vec![0u8; 32 * 1024];
            let mut lr = lr;
            loop {
                match lr.read(&mut b).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => send_data(&pkt2, sid, &b[..n], false),
                }
            }
        });
        let mut ws_to_local = ws_to_local;
        tokio::select! {
            _ = &mut ws_to_local => { local_to_ws.abort(); }
            _ = &mut local_to_ws => { ws_to_local.abort(); }
        }
    }
    ctx2.streams.write().await.remove(&sid);
    let e = ClientMsg::Close { stream: sid, reason: "eof".into() };
    let _ = pkt.send_ctrl(&e);
    Ok(())
}

async fn open_udp_stream(ctx: Arc<KCtx>, pkt: Pkt, sid: u32, port: u16) -> anyhow::Result<()> {
    let proxies = ctx.proxies.read().await.clone();
    let target = proxies
        .iter()
        .find(|p| p.enabled && p.ptype == "udp" && p.remote_port == port)
        .or_else(|| proxies.iter().find(|p| p.enabled && p.ptype == "udp"));
    let Some(p) = target else {
        let e = ClientMsg::Close { stream: sid, reason: "no route".into() };
        let _ = pkt.send_ctrl(&e);
        return Ok(());
    };
    let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
    sock.connect((p.local_ip.as_str(), p.local_port)).await?;
    let sock = Arc::new(sock);
    tracing::debug!("kudus udp stream {sid} -> {}:{}", p.local_ip, p.local_port);
    let (dtx, mut drx) = mpsc::unbounded_channel::<Vec<u8>>();
    let early = ctx.pending.write().await.remove(&sid).unwrap_or_default();
    for chunk in early {
        let _ = dtx.send(chunk);
    }
    ctx.streams.write().await.insert(sid, dtx);
    let w = sock.clone();
    let ws_to_udp = tokio::spawn(async move {
        loop {
            match tokio::time::timeout(std::time::Duration::from_secs(120), drx.recv()).await {
                Ok(Some(dg)) => {
                    let mut off = 0;
                    let mut any = false;
                    while let Some((one, used)) = decode_dgram(&dg[off..]) {
                        off += used;
                        any = true;
                        if w.send(one).await.is_err() {
                            return;
                        }
                    }
                    if !any {
                        let _ = w.send(&dg).await;
                    }
                }
                _ => break,
            }
        }
    });
    let pkt3 = pkt.clone();
    let r = sock.clone();
    let udp_to_ws = tokio::spawn(async move {
        let mut b = vec![0u8; 65535];
        loop {
            match r.recv(&mut b).await {
                Ok(0) | Err(_) => break,
                Ok(n) => send_data(&pkt3, sid, &b[..n], true),
            }
        }
    });
    let _ = tokio::join!(ws_to_udp, udp_to_ws);
    ctx.streams.write().await.remove(&sid);
    let e = ClientMsg::Close { stream: sid, reason: "eof".into() };
    let _ = pkt.send_ctrl(&e);
    Ok(())
}

use std::time::Duration;
