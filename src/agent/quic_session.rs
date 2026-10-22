//! agent QUIC 会话：quic:// 拨号 + Register/Config + control 复用分发 + 建流。
//! 与 `session.rs`（WSS）语义对齐：Hello→Welcome→Register→心跳→
//! Config/ConfigAck/Register 收敛→隧道泵。差异只在传输：
//! control stream 走 length-prefixed JSON，数据经 control 复用帧
//! `[stream:u32 BE][payload]`（UDP 包套 dgram 内帧保边界）。
use crate::common::proto::*;
use crate::common::quic::{decode_dgram, decode_frames, encode_dgram, encode_frame, CONTROL_MAX};
use super::{AgentFileConfig, Upstream};
// http_response_pump 经 pump_tcp 内联引用（见下），此处不直接用。
use std::{collections::HashMap, sync::Arc};
use tokio::{io::AsyncWriteExt, net::TcpStream, sync::{mpsc, RwLock}};

pub(crate) struct QCtx {
    pub(crate) proxies: RwLock<Vec<ProxyConfig>>,
    pub(crate) link_tasks: tokio::sync::Mutex<std::collections::HashMap<String, tokio::task::AbortHandle>>,
    pub(crate) streams: RwLock<HashMap<u32, mpsc::UnboundedSender<Vec<u8>>>>,
    pub(crate) pending: RwLock<HashMap<u32, Vec<Vec<u8>>>>,
    /// 发往 server 的 control 帧（JSON 或复用二进制），由写泵串行写 control stream。
    pub(crate) out: mpsc::UnboundedSender<Vec<u8>>,
}

/// 跳过链校验的 verifier：自签证书只防被动窃听，真认证靠 token（见 design §4）。
/// 根因→修法：`rustls::client::danger` 必须配 CryptoProvider，否则 `NoProvider`
/// 建连即炸；此处用 ring provider（与 quinn rustls-ring 特性同源）。
#[derive(Debug)]
struct SkipVerify(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for SkipVerify {
    fn verify_server_cert(
        &self,
        _end: &rustls::pki_types::CertificateDer<'_>,
        _in: &[rustls::pki_types::CertificateDer<'_>],
        _name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _msg: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _msg: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

async fn read_frame(recv: &mut quinn::RecvStream) -> anyhow::Result<Vec<u8>> {
    let mut hdr = [0u8; 4];
    recv.read_exact(&mut hdr).await?;
    let len = u32::from_be_bytes(hdr) as usize;
    if len > CONTROL_MAX {
        anyhow::bail!("control frame too large");
    }
    let mut body = vec![0u8; len];
    recv.read_exact(&mut body).await?;
    Ok(body)
}

pub(crate) fn send_ctrl(out: &mpsc::UnboundedSender<Vec<u8>>, m: &ClientMsg) -> anyhow::Result<()> {
    let j = serde_json::to_vec(m)?;
    out.send(encode_frame(&j))
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(())
}

pub(crate) async fn session(
    up: Upstream,
    cfg: AgentFileConfig,
    status: Arc<RwLock<super::web::AgentStatus>>,
    quic_out: super::egress::QuicOutHolder,
) -> anyhow::Result<()> {
    let (host, port) = match crate::common::quic::parse_server_url(&up.server_url) {
        crate::common::quic::Transport::Quic { host, port } => (host, port),
        _ => anyhow::bail!("quic: bad --server scheme (want quic://host:port)"),
    };
    let addr: std::net::SocketAddr = crate::common::quic::resolve_server_addr(&host, port).await?;
    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse()?)?;
    let mut crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipVerify(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))))
        .with_no_client_auth();
    crypto.alpn_protocols = vec![b"neutrino/1".to_vec()];
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?,
    )));
    let conn = endpoint.connect(addr, "neutrino-quic")?.await?;
    tracing::info!("quic connected to {host}:{port}");
    let (mut ctl_send, mut ctl_recv) = conn.open_bi().await?;
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    *quic_out.write().await = Some(out_tx.clone());
    super::admin::set_sender(Some(super::admin::AdminSender::Quic(out_tx.clone()))).await;
    let ctx = Arc::new(QCtx {
        proxies: RwLock::new(cfg.proxies.clone()),
        link_tasks: tokio::sync::Mutex::new(HashMap::new()),
        streams: RwLock::new(HashMap::new()),
        pending: RwLock::new(HashMap::new()),
        out: out_tx.clone(),
    });
    let quic_link_holder = quic_out.clone();
    super::link::sync_link_listeners_quic(&ctx, &cfg.proxies, &up.hostname, &quic_link_holder).await;
    // 写泵：control 帧串行写（JSON len 帧 + 复用二进制帧都经此通道保序）。
    let writer = tokio::spawn(async move {
        while let Some(f) = out_rx.recv().await {
            if ctl_send.write_all(&f).await.is_err() {
                break;
            }
        }
    });
    // hello
    send_ctrl(
        &out_tx,
        &ClientMsg::Hello {
            hostname: up.hostname.clone(),
            version: VERSION.into(),
            token: up.token.clone(),
        },
    )?;
    // welcome (15s)
    let wbody =
        match tokio::time::timeout(std::time::Duration::from_secs(15), read_frame(&mut ctl_recv)).await
        {
            Ok(Ok(b)) => b,
            _ => anyhow::bail!("quic: no welcome"),
        };
    let interval = match serde_json::from_slice::<ServerMsg>(&wbody)? {
        ServerMsg::Welcome { interval, .. } => interval,
        ServerMsg::Error { reason } => anyhow::bail!("quic server rejected: {reason}"),
        _ => anyhow::bail!("quic: expect welcome"),
    };
    tracing::info!("quic welcomed, heartbeat {interval}s");
    {
        let mut st = status.write().await;
        st.online = true;
        st.transport = "quic".into();
        st.last_error = None;
    }
    send_ctrl(&out_tx, &ClientMsg::Register { proxies: cfg.proxies.clone() })?;
    // ping loop
    {
        let out = out_tx.clone();
        tokio::spawn(async move {
            let mut iv = tokio::time::interval(std::time::Duration::from_secs(
                interval.max(5),
            ));
            loop {
                iv.tick().await;
                let p = ClientMsg::Ping { ts: chrono::Utc::now().timestamp() };
                if send_ctrl(&out, &p).is_err() {
                    break;
                }
            }
        });
    }
    // reader loop：control stream 帧可能是 JSON 控制，也可能是复用二进制数据。
    let mut buf = Vec::new();
    let mut tmp = vec![0u8; 32 * 1024];
    loop {
        use quinn::RecvStream;
        let n = RecvStream::read(&mut ctl_recv, &mut tmp).await?;
        let Some(n) = n else { break };
        if n == 0 {
            continue;
        }
        buf.extend_from_slice(&tmp[..n]);
        let (frames, used) = decode_frames(&buf);
        if used == 0 && buf.len() > CONTROL_MAX + 4 {
            anyhow::bail!("quic: control frame too large");
        }
        buf.drain(..used);
        for body in frames {
            if let Ok(sm) = serde_json::from_slice::<ServerMsg>(&body) {
                match sm {
                    ServerMsg::Pong { ts } => {
                        let now = chrono::Utc::now().timestamp();
                        let ms = ((now - ts).max(0) as u64).saturating_mul(1000);
                        status.write().await.rtt_ms = Some(ms);
                    }
                    ServerMsg::Open { stream, kind, host, port } => {
                        let ctx = ctx.clone();
                        tokio::spawn(async move {
                            if let Err(e) = open_stream(ctx, stream, kind, host, port).await {
                                tracing::warn!("quic open stream {stream} failed: {e:#}");
                            }
                        });
                    }
                    ServerMsg::Ping { ts } => {
                        let _ = send_ctrl(&out_tx, &ClientMsg::Pong { ts });
                    }
                    ServerMsg::AdminResp { req_id, status, body } => {
                        super::admin::on_admin_resp(req_id, status, body).await;
                    }
                    ServerMsg::Close { stream, .. } => {
                        ctx.streams.write().await.remove(&stream);
                        super::egress::egress_streams().write().await.remove(&stream);
                    }
                    ServerMsg::Config { proxies } => {
                        *ctx.proxies.write().await = proxies.clone();
                        super::link::sync_link_listeners_quic(&ctx, &proxies, &up.hostname, &quic_link_holder).await;
                        {
                            let mut st = status.write().await;
                            st.proxies = proxies.clone();
                        }
                        let _ = send_ctrl(&out_tx, &ClientMsg::ConfigAck { ok: true });
                        let _ = send_ctrl(&out_tx, &ClientMsg::Register { proxies });
                        tracing::info!("quic hot config applied");
                    }
                    _ => {}
                }
                continue;
            }
            if let Some((id, payload)) = decode_data(&body) {
                // server 下发的 UDP 包带 dgram 内帧：逐个拆投；非 dgram 即裸 TCP/HTTP 字节。
                let mut off = 0;
                let mut delivered = false;
                while let Some((dg, used)) = decode_dgram(&payload[off..]) {
                    off += used;
                    delivered = true;
                    deliver(&ctx, id, dg).await;
                }
                if !delivered {
                    deliver(&ctx, id, payload).await;
                }
            }
        }
    }
    *quic_out.write().await = None;
    super::admin::set_sender(None).await;
    writer.abort();
    anyhow::Ok(())
}

async fn deliver(ctx: &Arc<QCtx>, id: u32, payload: &[u8]) {
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

/// 数据发送：裸字节包复用帧；UDP 包先套 dgram 帧保边界。
fn send_data(ctx: &QCtx, sid: u32, payload: &[u8], is_udp: bool) {
    let inner = if is_udp { encode_dgram(payload) } else { payload.to_vec() };
    let _ = ctx.out.send(encode_frame(&encode_data(sid, &inner)));
}

/// http 统一走 pump_tcp（响应泵在内部分流），tcp/link 走 tcp 泵；
/// udp 走 connected UDP 泵。is_http 只在 pump_tcp 内决定读侧泵。
async fn open_stream(ctx: Arc<QCtx>, sid: u32, kind: String, host: String, port: u16) -> anyhow::Result<()> {
    if kind == "udp" {
        return open_udp_stream(ctx, sid, port).await;
    }
    if kind == "link" {
        let local = TcpStream::connect((host.as_str(), port)).await?;
        return pump_tcp(ctx, sid, local, false).await;
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
        let _ = send_ctrl(&ctx.out, &e);
        return Ok(());
    };
    let local = TcpStream::connect((p.local_ip.as_str(), p.local_port)).await?;
    tracing::debug!("quic stream {sid} -> {}:{}", p.local_ip, p.local_port);
    pump_tcp(ctx, sid, local, kind == "http").await
}

/// TCP/HTTP 泵：local socket ↔ control 复用帧。is_http 时读侧用 http_response_pump
///（响应边界即收尾），否则双向 select（任一方向 EOF 即收尾）。
async fn pump_tcp(ctx: Arc<QCtx>, sid: u32, local: TcpStream, is_http: bool) -> anyhow::Result<()> {
    use super::stream::http_response_pump;
    let (dtx, mut drx) = mpsc::unbounded_channel::<Vec<u8>>();
    let early = ctx.pending.write().await.remove(&sid).unwrap_or_default();
    for chunk in early {
        let _ = dtx.send(chunk);
    }
    ctx.streams.write().await.insert(sid, dtx);
    let (lr, mut lw) = local.into_split();    let ctx2 = ctx.clone();
    let ws_to_local = tokio::spawn(async move {
        while let Some(chunk) = drx.recv().await {
            if lw.write_all(&chunk).await.is_err() {
                break;
            }
        }
    });
    if is_http {
        // 与 WSS 版同一只响应泵（Content-Length/chunked/close 三分支），
        // 发送端换成 QuicSender（复用帧），泵逻辑零分叉。
        let local_to_ws = tokio::spawn(http_response_pump(
            super::stream::QuicSender(ctx.out.clone()),
            sid,
            lr,
        ));
        // keep-alive 后端不会 FIN，不能等 ws->local 的 EOF：响应读完即收尾。
        let _ = local_to_ws.await;
        ws_to_local.abort();
    } else {
        let mut local_to_ws = tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            let mut b = vec![0u8; 32 * 1024];
            let mut lr = lr;
            loop {
                match lr.read(&mut b).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => send_data(&ctx, sid, &b[..n], false),
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
    let _ = send_ctrl(&ctx2.out, &e);
    Ok(())
}

async fn open_udp_stream(ctx: Arc<QCtx>, sid: u32, port: u16) -> anyhow::Result<()> {
    let proxies = ctx.proxies.read().await.clone();
    let target = proxies
        .iter()
        .find(|p| p.enabled && p.ptype == "udp" && p.remote_port == port)
        .or_else(|| proxies.iter().find(|p| p.enabled && p.ptype == "udp"));
    let Some(p) = target else {
        let e = ClientMsg::Close { stream: sid, reason: "no route".into() };
        let _ = send_ctrl(&ctx.out, &e);
        return Ok(());
    };
    let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
    sock.connect((p.local_ip.as_str(), p.local_port)).await?;
    let sock = Arc::new(sock);
    tracing::debug!("quic udp stream {sid} -> {}:{}", p.local_ip, p.local_port);
    let (dtx, mut drx) = mpsc::unbounded_channel::<Vec<u8>>();
    let early = ctx.pending.write().await.remove(&sid).unwrap_or_default();
    for chunk in early {
        // 早到的是 dgram 内帧裸包：直接喂
        let _ = dtx.send(chunk);
    }
    ctx.streams.write().await.insert(sid, dtx);
    let w = sock.clone();
    let ws_to_udp = tokio::spawn(async move {
        loop {
            match tokio::time::timeout(std::time::Duration::from_secs(120), drx.recv()).await {
                Ok(Some(dg)) => {
                    // stream 内 dgram 帧可能是粘连的多包：逐个拆发
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
    let ctx3 = ctx.clone();
    let r = sock.clone();
    let udp_to_ws = tokio::spawn(async move {
        let mut b = vec![0u8; 65535];
        loop {
            match r.recv(&mut b).await {
                Ok(0) | Err(_) => break,
                Ok(n) => send_data(&ctx3, sid, &b[..n], true),
            }
        }
    });
    let _ = tokio::join!(ws_to_udp, udp_to_ws);
    ctx.streams.write().await.remove(&sid);
    let e = ClientMsg::Close { stream: sid, reason: "eof".into() };
    let _ = send_ctrl(&ctx.out, &e);
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn quic_requires_port() {
        assert!(matches!(
            crate::common::quic::parse_server_url("quic://h:1"),
            crate::common::quic::Transport::Quic { .. }
        ));
        assert!(matches!(
            crate::common::quic::parse_server_url("quic://h"),
            crate::common::quic::Transport::Invalid
        ));
    }
}
