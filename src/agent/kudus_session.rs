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
    // 可靠发送上下文：重传缓冲 + 对端 ACK 快照（累计+sack，收包侧更新）。
    // 根因→修法：旧 next_seq 发完即忘，跨机丢包即永久少块（avatar/blob 截断）；
    // 现 DATA 帧先进 retx 登记、ACK 清、超时重发。seq 0 保留（SYN/FIN/纯 ACK）。
    pub(crate) rel: Arc<std::sync::Mutex<RelSend>>,
}

pub(crate) struct RelSend {
    retx: crate::common::kudus::RetxBuf,
    ack: u32,
    sack: [u8; 32],
}

impl RelSend {
    pub(crate) fn new() -> Self {
        Self { retx: crate::common::kudus::RetxBuf::new(1), ack: 0, sack: [0u8; 32] }
    }
}

impl Pkt {
    /// 组一帧 datagram 并经写泵发出（调用方已定好 flags/seq/ack/sack）。
    fn emit(&self, flags: u8, seq: u32, ack: u32, sack: [u8; 32], body: &[u8]) -> anyhow::Result<()> {
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
    fn ack_snap(&self) -> (u32, [u8; 32]) {
        let r = self.rel.lock().unwrap();
        (r.ack, r.sack)
    }
    /// 发一帧当前 ACK 快照（收包回执用；纯 ACK 不占可靠序列）。
    pub(crate) fn send_ack_only(&self) {
        let (ack, sack) = self.ack_snap();
        let _ = self.emit(FLAG_ACK, 0, ack, sack, &[]);
    }
    /// 对端 ACK 到达：清重传缓冲。
    pub(crate) fn on_ack(&self, ack: u32, sack: [u8; 32]) {
        self.rel.lock().unwrap().retx.on_ack(ack, &sack);
    }
    /// 收包侧推进 ACK 快照（主循环从重排缓冲取 ack()/sack() 后调用）。
    pub(crate) fn set_ack(&self, ack: u32, sack: [u8; 32]) {
        let mut r = self.rel.lock().unwrap();
        r.ack = ack;
        r.sack = sack;
    }
    pub(crate) fn send(&self, flags: u8, _ack: u32, _sack: [u8; 32], body: &[u8]) -> anyhow::Result<()> {
        if flags & FLAG_DATA != 0 {
            // 可靠 DATA：登记重传后发（捎带当前收包 ACK 快照）。
            // 注意：单次 lock 拿全三件——double-lock 会把 2MB 搬运的临界区串成 4000 次加锁
            // （blob 219608/2M 即此）。
            let (seq, ack, sack) = {
                let mut r = self.rel.lock().unwrap();
                let s = r.retx.on_send(body.to_vec());
                (s, r.ack, r.sack)
            };
            self.emit(flags, seq, ack, sack, body)
        } else {
            let (ack, sack) = self.ack_snap();
            self.emit(flags, 0, ack, sack, body)
        }
    }
    pub(crate) fn send_ctrl(&self, m: &ClientMsg) -> anyhow::Result<()> {
        // 根因→修法：Register/Config 一消息一帧，代理多时 3320B 级 JSON 超
        // KUDUS_MAX_UDP 被整包丢。现按 KUDUS_CTRL_CHUNK 切片，每片独立 DATA 帧
        // 独立 seq（走可靠重传+重排），对端 CtrlReasm 重组后整条解析。
        let j = serde_json::to_vec(m)?;
        for frag in crate::common::kudus::split_ctrl_frame(&j) {
            self.send(FLAG_DATA, 0, [0u8; 32], &frag)?;
        }
        Ok(())
    }
    /// 字节流发送（TCP/HTTP/egress/link）：按 [`KUDUS_DATA_CHUNK`] 切片，
    /// 每片独立 DATA 帧独立 seq（接收侧重排缓冲保序，跨机乱序/丢包可恢复）。
    /// 根因→修法：泵单次 read 可达 32KB，单 datagram 装不下会整包丢（静默断流），
    /// 必须在此切片；UDP 数据报语义不可切（见下 `send_udp`）。
    /// 注意：agent 上行 TCP 同样先套 dgram 帧（与 server 下行对称），否则 server 读循环
    /// decode_dgram 拆帧错位——e2e 里 got 0 即上行 256KB 全被当成坏帧丢了。
    /// 背压：retx 未确认超 256 包时让出等 ACK（异步 sleep，不占 reactor）——
    /// 根因→修法：旧无界发送，2MB 切 2000 帧瞬间灌满 UDP 发射队列+对端重排窗，
    /// 丢包雪崩后重传泵+写泵双双 100% 空转（blob 首传 ok、次传 hang 即此）。
    /// 注意：旧 `std::thread::sleep` 版会卡死单线程 reactor 上所有同 task 的流
    /// （单连接的 2000 帧没发完，同 task 第二个连接的 Open 永不到——次传 hang 即此）。
    pub(crate) async fn wait_window(&self) {
        for _ in 0..3000 {
            let n = self.rel.lock().map(|r| r.retx.len()).unwrap_or(0);
            if n < 256 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }
    pub(crate) fn send_data_stream(&self, sid: u32, chunk: &[u8]) {
        if chunk.is_empty() {
            let _ = self.send(FLAG_DATA, 0, [0u8; 32], &encode_data(sid, chunk));
            return;
        }
        for piece in chunk.chunks(KUDUS_DATA_CHUNK) {
            let inner = crate::common::quic::encode_dgram(piece);
            if self.send(FLAG_DATA, 0, [0u8; 32], &encode_data(sid, &inner)).is_err() {
                break;
            }
        }
    }
    /// 单个 UDP 数据报发送：必须装进一个 datagram（保边界不可切），超限丢包 + warn。
    /// 与 QUIC `encode_dgram_checked` 超限语义对齐：典型 UDP（DNS/语音/游戏包 <1200B）无影响。
    pub(crate) fn send_udp(&self, sid: u32, dg: &[u8]) {
        let inner = encode_dgram(dg);
        if 4 + 24 + HDR_LEN + inner.len() + 16 > KUDUS_MAX_UDP {
            tracing::warn!("kudus udp datagram too large ({}B), dropped", dg.len());
            return;
        }
        let _ = self.send(FLAG_DATA, 0, [0u8; 32], &encode_data(sid, &inner));
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
    let addr: SocketAddr = crate::common::quic::resolve_server_addr(&host, port).await?;
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
        rel: Arc::new(std::sync::Mutex::new(RelSend::new())),
    };
    // 重传泵：50ms 扫一次超时未确认包，原样重发（带当前 ACK 快照）。
    // 注意：take+resend 之间 rel 锁零持有还是一次拿完——写泵上行 2MB 时长占锁，
    // 重传泵若阻塞等锁会被拖成串行，RTO 形同虚设（与 server 侧 try_lock 对称）。
    {
        use std::sync::TryLockError;
        let p = pkt.clone();
        tokio::spawn(async move {
            let mut iv = tokio::time::interval(std::time::Duration::from_millis(50));
            loop {
                iv.tick().await;
                let due = match p.rel.try_lock() {
                    Ok(mut r) => {
                        let d = r.retx.take_expired(crate::common::kudus::KUDUS_RTO, crate::common::kudus::now_ms());
                        let snap = (r.ack, r.sack);
                        drop(r);
                        d.into_iter().map(|(s, b)| (s, b, snap)).collect::<Vec<_>>()
                    }
                    Err(TryLockError::WouldBlock) => continue,
                    Err(TryLockError::Poisoned(_)) => continue,
                };
                for (seq, body, (ack, sack)) in due {
                    let h = crate::common::kudus::KudusHdr { ver: 1, flags: crate::common::kudus::FLAG_DATA, seq, ack, sack, ts_ms: crate::common::kudus::now_ms() };
                    let mut plain = crate::common::kudus::encode_hdr(&h).to_vec();
                    plain.extend_from_slice(&body);
                    if 4 + 24 + plain.len() + 16 > crate::common::kudus::KUDUS_MAX_UDP {
                        continue;
                    }
                    let n = crate::common::kudus::fresh_nonce();
                    p.out.send(crate::common::kudus::encode_packet(p.session, &n, &crate::common::kudus::seal(&p.key, &n, &plain))).ok();
                }
            }
        });
    }
    *kudus_out.write().await = Some(pkt.clone());
    super::admin::set_sender(Some(super::admin::AdminSender::Kudus(pkt.clone()))).await;
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
    let rpkt = pkt.clone();
    let reader = tokio::spawn(async move { 
        let pkt = rpkt; // 读泵内 ACK/重排专用克隆（主循环仍持有一份）
        let mut buf = vec![0u8; 2048];
        // server 下行 seq 从 KUDUS_SEQ_GAP 起跳（与 agent 上行 seq 域隔离，见 common 注释）。
        let mut rxbuf = crate::common::kudus::ReorderBuf::new(crate::common::kudus::KUDUS_SEQ_GAP);
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
            // ACK 处理：所有包（DATA/ACK/控制）都可能捎带 ack，清重传缓冲。
            // 根因→修法：旧代码 ack=0 发完即忘，对端 ACK 也没人读，重传无从触发。
            pkt.on_ack(h.ack, h.sack);
            if h.flags & FLAG_DATA != 0 {
                // 纯 ACK/DATA 的 ack 域直接进重传缓冲（捎带确认）。
                // 根因→修法：旧代码只读了重排没读确认，重传永远不清、洞永远不补。
                // 注意：重排窗口锚定 KUDUS_SEQ_GAP，只收 server 下行 DATA；
                // server 15s 心跳 Ping 走控制面（同样 FLAG_DATA 帧但 seq=下行序列），同样进窗保序。
                let ready = rxbuf.push(h.seq, body.to_vec());
                for body in ready {
                    if dec_tx.send((h, (body))).is_err() {
                        break;
                    }
                }
                // 重排推进即更新 ACK 快照 + 立刻回纯 ACK（丢包即 SACK 催补）。
                pkt.set_ack(rxbuf.ack(), rxbuf.sack());
                pkt.send_ack_only();
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
    tracing::info!("kudus welcomed (heartbeat adaptive 15~30s, server interval {interval}s ignored)");
    {
        let mut st = status.write().await;
        st.online = true;
        st.transport = "kudus".into();
        st.last_error = None;
    }
    pkt.send_ctrl(&ClientMsg::Register { proxies: cfg.proxies.clone() })?;
    // ping loop：Heartbeat 自适应（慢 15~30s / 快 5~8s）+ 每次随机防对齐。
    // 根因→修法：固定 30s 多 agent 齐步走惊群；丢包不加密则重传泵独转、
    // 对端久无确认。lossy = 本端重传缓冲非空（发的包对端还没确认）。
    {
        let p = pkt.clone();
        tokio::spawn(async move {
            let mut hb = crate::common::kudus::Heartbeat::new();
            loop {
                let lossy = p.rel.lock().map(|r| r.retx.len() > 0).unwrap_or(false);
                tokio::time::sleep(hb.next_interval(lossy)).await;
                let m = ClientMsg::Ping { ts: chrono::Utc::now().timestamp() };
                if p.send_ctrl(&m).is_err() {
                    break;
                }
            }
        });
    }
    // 主分发循环（看门狗：75s 无 server 任何帧即判死，bail 走外层 backoff 重连。
    // 根因→修法：旧裸 recv 永等，server OOM 重启后 agent 卡旧会话无感知
    // （macmini 2026-10-21 现场）。握手完成后的主循环才计时。）
    // 控制分片重组槽（Config 分片跨包累计，可靠重排已保序）。
    let mut ctrl_reasm = crate::common::kudus::CtrlReasm::new();
    loop {
        let (h, body) = match tokio::time::timeout(
            std::time::Duration::from_secs(crate::common::kudus::KUDUS_IDLE_KICK_SECS as u64),
            dec_rx.recv(),
        )
        .await
        {
            Ok(Some(v)) => v,
            _ => anyhow::bail!("kudus heartbeat timeout: no server frame"),
        };
        if h.flags & FLAG_FIN != 0 {
            // server FIN：回 ACK 即关。
            let _ = pkt.send(FLAG_ACK, h.seq, [0u8; 32], b"bye");
            break;
        }
        // 控制分片先重组（与 server 侧对称）：sid==CTRL_SID 即分片，攒齐前不解析。
        let body = match decode_data(&body) {
            Some((id, payload)) if id == KUDUS_CTRL_SID => {
                match ctrl_reasm.feed(payload) {
                    Some(full) => full,
                    None => continue,
                }
            }
            _ => body,
        };
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
                ServerMsg::AdminResp { req_id, status, body } => {
                    super::admin::on_admin_resp(req_id, status, body).await;
                }
                ServerMsg::Close { stream, .. } => {
                    // server eof 语义（与 WSS/QUIC 对齐）：主表删后，link/egress 泵侧推空包
                    // 触发 to_local 退出；纯删表不推包会导致 client 侧 hang 住不断（已现网踩坑）。
                    ctx.streams.write().await.remove(&stream);
                    if let Some(tx) = super::egress::egress_streams().write().await.remove(&stream) {
                        let _ = tx.send(vec![]);
                    }
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
            // server 下行统一 dgram 套帧（TCP 切片亦套帧保边界，与 quic 读循环对称）：
            // 单 datagram 单帧，frame = [sid][dgram(len+payload)]，拆一层即得整片；
            // 非 dgram 即裸字节（兼容控制面空包/EOF）。重排补齐攒出的多包在读泵已逐个
            // 投进 dec 通道，到这里每次 body 恰一帧——无需合并，直接拆一次。
            if let Some((dg, _)) = decode_dgram(payload) {
                deliver(&ctx, id, dg.to_vec()).await;
            } else {
                deliver(&ctx, id, payload.to_vec()).await;
            }
        }
    }
    // 本端 FIN（200ms ×3 尽力）
    for _ in 0..3 {
        let _ = pkt.send(FLAG_FIN, 0, [0u8; 32], b"bye");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    *kudus_out.write().await = None;
    super::admin::set_sender(None).await;
    writer.abort();
    reader.abort();
    anyhow::Ok(())
}

async fn deliver(ctx: &Arc<KCtx>, id: u32, payload: Vec<u8>) {
    if let Some(tx) = ctx.streams.read().await.get(&id).cloned() {
        let _ = tx.send(payload);
    } else if payload.is_empty() {
        // 空载荷 = server eof 标记：删表 + 推空包触发 to_local 退出（同 Close 分支）。
        if let Some(tx) = super::egress::egress_streams().write().await.remove(&id) {
            let _ = tx.send(vec![]);
        }
    } else if let Some(tx) = super::egress::egress_streams().read().await.get(&id).cloned() {
        let _ = tx.send(payload);
    } else {
        ctx.pending.write().await.entry(id).or_default().push(payload);
    }
}

/// 数据发送：裸字节包封 DATA 帧；UDP 包先套 dgram 帧保边界（超限丢包，不切片）。
/// 注意：背压由调用方（wait_window）做，此处只分发不阻塞。
fn send_data(pkt: &Pkt, sid: u32, payload: &[u8], is_udp: bool) {
    if is_udp {
        pkt.send_udp(sid, payload);
    } else {
        pkt.send_data_stream(sid, payload);
    }
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
        // 出口 dial：server 侧 resolve_link 已把 host/port 换成真实目标
        // （link 出口 agent 无需查表，直接拨）。失败即回 Close{link denied}。
        let local = match TcpStream::connect((host.as_str(), port)).await {
            Ok(u) => u,
            Err(e) => {
                tracing::warn!("kudus link egress dial {host}:{port} failed: {e:#}");
                let c = ClientMsg::Close { stream: sid, reason: "link denied".into() };
                let _ = pkt.send_ctrl(&c);
                return Ok(());
            }
        };
        tracing::debug!("kudus link egress stream {sid} -> {host}:{port}");
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
        // 背压：http_response_pump 是同步 Sender trait，内部调 send_data_stream 无等待；
        // 窗口满时泵 task 提前异步等 ACK（不卡 reactor，同泵其他流不受影响）。
        // 根因→修法：旧无界发送，大文件切 2000 帧灌满对端重排窗→丢包雪崩→次传 hang。
        let pktw = pkt.clone();
        let local_to_ws = tokio::spawn(async move {
            pktw.wait_window().await;
            http_response_pump(super::stream::KudusSender(pktw.clone()), sid, lr).await
        });
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
                    Ok(n) => {
                        pkt2.wait_window().await;
                        send_data(&pkt2, sid, &b[..n], false);
                    }
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
            // server 下行已在读循环拆掉 dgram 帧：此处是裸 datagram，直接发。
            // （与 quic 版不同：quic 下行裸帧靠泵内 decode_dgram 兜底；
            // kudus 下行统一套帧，读循环已拆，泵内不再二次拆。）
            match tokio::time::timeout(std::time::Duration::from_secs(120), drx.recv()).await {
                Ok(Some(dg)) => {
                    if w.send(&dg).await.is_err() {
                        return;
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

#[cfg(test)]
mod tests {
    #[test]
    fn heartbeat_contract() {
        // Task 2 依赖 Task 1 的接口形状：改名/改签名即红。
        let mut hb = crate::common::kudus::Heartbeat::new();
        let d = hb.next_interval(false);
        assert!(d >= std::time::Duration::from_secs(15));
        assert_eq!(crate::common::kudus::KUDUS_IDLE_KICK_SECS, 75);
    }
}
