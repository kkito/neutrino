//! server kudus 监听：独立 UDP 端口，XChaCha20-Poly1305 自研可靠传输。
//! 与 `quic.rs::handle_conn` 语义对齐：SYN → Hello 校验 → SYN-ACK →
//! Register/Config 收敛 → 心跳 → 隧道泵。token 错/解密失败一律静默丢包（黑洞）。
use crate::common::kudus::*;
use crate::common::proto::*;
use crate::common::quic::{decode_dgram, encode_dgram};
use crate::server::state::{log_ev, save_state, AgentHandle, AgentInfo, Shared};
use crate::server::tunnel::{on_register, spawn_egress_dial, spawn_link_relay};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, RwLock};

type S = Arc<Shared>;

/// 空 token 直接拒绝：防"没配 token 的 agent 蹭上没配 token 的 server"。
pub(crate) fn check_token(got: &str, want: &str) -> bool {
    if got.is_empty() || want.is_empty() {
        return false;
    }
    got == want
}

/// 时间戳新鲜度：±60s 漂移内算有效（防流量重放，见 design §4）。
pub(crate) fn ts_fresh(ts_ms: u64) -> bool {
    let now = now_ms();
    now.abs_diff(ts_ms) <= 60_000
}

/// seq 去重窗口：已见过/低于左沿即重放，返回 false。
pub(crate) struct SeqWindow {
    base: u32,
    seen: std::collections::HashSet<u32>,
}

impl SeqWindow {
    pub(crate) fn new(base: u32) -> Self {
        Self { base, seen: std::collections::HashSet::new() }
    }
    /// 新 seq 返回 true；重放/过旧返回 false。
    pub(crate) fn check(&mut self, seq: u32) -> bool {
        if self.seen.contains(&seq) || seq == self.base {
            return false;
        }
        let d = seq.wrapping_sub(self.base);
        if d >= 0x8000_0000 {
            return false; // base 之后绕回来的旧 seq：重放/过旧
        }
        if d > 1024 {
            // 大步前跳：窗口前移（丢包太多或初值跳变），旧表清空。
            self.base = seq;
            self.seen.clear();
            self.seen.insert(seq);
            return true;
        }
        self.seen.insert(seq);
        if self.seen.len() > 2048 {
            self.base = seq;
            self.seen.clear();
            self.seen.insert(seq);
        }
        true
    }
}

/// 发包器：把 (hdr, proto_frame) 加密成 datagram 发往对端。
/// UDP 访客包下行：payload 先套 dgram 帧再进复用帧（agent 拆边界用，与 quic.rs 同语）。
#[derive(Clone)]
struct Tx {
    sock: Arc<UdpSocket>,
    peer: Arc<std::sync::RwLock<SocketAddr>>,
    key: [u8; 32],
    session: u32,
}

impl Tx {
    fn send_pkt(&self, hdr: &KudusHdr, body: &[u8]) -> bool {
        let mut plain = encode_hdr(hdr).to_vec();
        plain.extend_from_slice(body);
        if 4 + 24 + plain.len() + 16 > KUDUS_MAX_UDP {
            tracing::warn!("kudus oversize frame dropped ({}B)", plain.len());
            return false;
        }
        let n = fresh_nonce();
        let pkt = encode_packet(self.session, &n, &seal(&self.key, &n, &plain));
        let peer = *self.peer.read().unwrap();
        let sock = self.sock.clone();
        tokio::spawn(async move {
            let _ = sock.send_to(&pkt, peer).await;
        });
        true
    }
}

async fn handle_conn(
    s: S,
    token: Arc<String>,
    sock: Arc<UdpSocket>,
    session: u32,
    mut rx: mpsc::UnboundedReceiver<(SocketAddr, KudusHdr, Vec<u8>)>,
    peer0: SocketAddr,
) {
    let key = derive_key(&token);
    let peer = Arc::new(std::sync::RwLock::new(peer0));
    let tx = Tx { sock: sock.clone(), peer: peer.clone(), key, session };
    // 握手：首包必须是 SYN + Hello（15s 超时）。
    // 注意：超时/错 token 一律静默返回（黑洞，无回包无事件，见 design §2）；
    // 仅 debug 留痕（默认 info 不可见），方便 RUST_LOG=debug 排错。
    let (mut hostname, mut version) = (String::new(), String::new());
    let hello_ok = loop {
        match tokio::time::timeout(Duration::from_secs(15), rx.recv()).await {
            Ok(Some((p, h, body))) => {
                *peer.write().unwrap() = p;
                if h.flags & FLAG_SYN == 0 {
                    continue;
                }
                match serde_json::from_slice::<ClientMsg>(&body) {
                    Ok(ClientMsg::Hello { hostname: hn, version: v, token: tok }) => {
                        if !check_token(&tok, &token) {
                            tracing::debug!("kudus hello bad token from {p}");
                            return; // 黑洞：不回包
                        }
                        hostname = hn;
                        version = v;
                        break true;
                    }
                    _ => {
                        tracing::debug!("kudus non-hello first packet from {p}");
                        return; // 首包非 Hello：丢
                    }
                }
            }
            _ => break false,
        }
    };
    if !hello_ok {
        tracing::debug!("kudus hello timeout session={session:08x}");
        return;
    }
    // 注册：与 quic.rs/ws_loop 同一套 agents/outbox/incoming/pending 表。
    let agent_id = uuid::Uuid::new_v4().to_string()[..8].to_string();
    let (ctl_tx, mut ctl_rx) = mpsc::unbounded_channel::<ServerMsg>();
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<(u32, Vec<u8>)>();
    let incoming: Arc<RwLock<HashMap<u32, mpsc::UnboundedSender<Vec<u8>>>>> =
        Arc::new(RwLock::new(HashMap::new()));
    let pending: Arc<RwLock<HashMap<u32, Vec<Vec<u8>>>>> =
        Arc::new(RwLock::new(HashMap::new()));
    let (prx, ptx) = s.totals.read().await.get(&hostname).cloned().unwrap_or((0, 0));
    {
        s.agents.write().await.insert(
            agent_id.clone(),
            AgentHandle {
                info: AgentInfo {
                    agent_id: agent_id.clone(),
                    hostname: hostname.clone(),
                    version,
                    online_secs: 0,
                    rtt_ms: -1,
                    rx_bytes: prx,
                    tx_bytes: ptx,
                    proxies: vec![],
                },
                connected_at: chrono::Utc::now(),
                ctl: ctl_tx.clone(),
                incoming: incoming.clone(),
                pending: pending.clone(),
            },
        );
        s.outbox.write().await.insert(agent_id.clone(), out_tx.clone());
    }
    log_ev(&s, format!("kudus agent '{hostname}' connected id={agent_id}"));
    // SYN-ACK（Welcome，200/400/800ms ×5 重传，纯尽力）
    let w = serde_json::to_string(&ServerMsg::Welcome {
        agent_id: agent_id.clone(),
        interval: 30,
    })
    .unwrap();
    let mut backoff = [200u64, 400, 800, 800, 800];
    let mut acked = false;
    for wait in backoff.iter_mut() {
        let h = KudusHdr {
            ver: 1,
            flags: FLAG_SYN | FLAG_ACK,
            seq: 0,
            ack: 0,
            sack: [0u8; 32],
            ts_ms: now_ms(),
        };
        tx.send_pkt(&h, w.as_bytes());
        match tokio::time::timeout(Duration::from_millis(*wait), rx.recv()).await {
            Ok(Some((p, h2, body))) => {
                *peer.write().unwrap() = p;
                // 对端 ACK：Register（进入数据态）；重复 SYN：重发 SYN-ACK（下轮循环）。
                if serde_json::from_slice::<ClientMsg>(&body)
                    .map(|m| matches!(m, ClientMsg::Register { .. }))
                    .unwrap_or(false)
                {
                    let _ = h2;
                    // Register 走正常分发（见下读循环重放）：先入队处理
                    on_register_from_body(&s, &agent_id, &hostname, &body).await;
                    acked = true;
                    break;
                }
            }
            _ => {}
        }
    }
    if !acked {
        cleanup(&s, &agent_id, &hostname).await;
        return;
    }
    // server 心跳：每 15s Ping（与 WSS/QUIC 同周期）。
    let last_ping = Arc::new(RwLock::new(None::<std::time::Instant>));
    {
        let ctl = ctl_tx.clone();
        let lp = last_ping.clone();
        tokio::spawn(async move {
            let mut iv = tokio::time::interval(Duration::from_secs(15));
            loop {
                iv.tick().await;
                *lp.write().await = Some(std::time::Instant::now());
                if ctl
                    .send(ServerMsg::Ping {
                        ts: chrono::Utc::now().timestamp(),
                    })
                    .is_err()
                {
                    break;
                }
            }
        });
    }
    // 收发循环：读包（解密在分发层已做）→ 控制/数据分发；写泵（ctl/outbox→datagram）。
    let mut win = SeqWindow::new(0);
    let mut fin_acked = false;
    // 写泵 task：ctl 与 outbox 各自封包发送。
    let txw = tx.clone();
    let aidw = agent_id.clone();
    let sw = s.clone();
    let write_task = tokio::spawn(async move {
        let mut seq: u32 = 1;
        loop {
            tokio::select! {
                Some(m) = ctl_rx.recv() => {
                    let t = serde_json::to_string(&m).unwrap();
                    let h = KudusHdr { ver: 1, flags: FLAG_DATA, seq, ack: 0, sack: [0u8; 32], ts_ms: now_ms() };
                    seq = seq.wrapping_add(1);
                    if !txw.send_pkt(&h, t.as_bytes()) { break; }
                }
                Some((id, payload)) = out_rx.recv() => {
                    // outbox 数据：先按流切片（单 datagram 装不下会整包丢→静默断流），
                    // 每片独立 DATA 帧独立 datagram（UDP 访客下行先套 dgram 帧；与 quic.rs::udp_out 同语）。
                    // 空载荷（EOF 标记）不能丢：chunks 为空时补一帧空包。
                    let pieces: Vec<&[u8]> = if payload.is_empty() {
                        vec![&[][..]]
                    } else {
                        payload.chunks(crate::common::kudus::KUDUS_DATA_CHUNK).collect()
                    };
                    for piece in pieces {
                        let b = if piece.is_empty() {
                            encode_data(id, piece)
                        } else {
                            encode_data(id, &encode_dgram(piece))
                        };
                        let h = KudusHdr { ver: 1, flags: FLAG_DATA, seq, ack: 0, sack: [0u8; 32], ts_ms: now_ms() };
                        seq = seq.wrapping_add(1);
                        if !txw.send_pkt(&h, &b) { break; }
                    }
                    if let Some(hh) = sw.agents.write().await.get_mut(&aidw) {
                        hh.info.tx_bytes += payload.len() as u64;
                    }
                }
                else => break,
            }
        }
    });
    // 读循环
    let read_res = async {
        loop {
            let (p, h, body) = rx.recv().await.ok_or_else(|| anyhow::anyhow!("gone"))?;
            *peer.write().unwrap() = p;
            if !ts_fresh(h.ts_ms) {
                tracing::debug!("kudus stale ts seq={} from {p}", h.seq);
                continue; // 重放旧包：丢
            }
            if h.flags & FLAG_DATA != 0 && !win.check(h.seq) {
                tracing::debug!("kudus replay/dup seq={} from {p}", h.seq);
                continue; // 重复/过旧 seq：丢
            }
            if h.flags & FLAG_FIN != 0 {
                // 对端 FIN：回 ACK 即双向关。
                let ah = KudusHdr {
                    ver: 1,
                    flags: FLAG_ACK,
                    seq: 0,
                    ack: h.seq,
                    sack: [0u8; 32],
                    ts_ms: now_ms(),
                };
                tx.send_pkt(&ah, b"bye");
                fin_acked = true;
                break;
            }
            if let Ok(cm) = serde_json::from_slice::<ClientMsg>(&body) {
                match cm {
                    ClientMsg::Register { proxies } => {
                        on_register(&s, &agent_id, &hostname, proxies).await;
                    }
                    ClientMsg::Ping { ts } => {
                        let _ = ctl_tx.send(ServerMsg::Pong { ts });
                    }
                    ClientMsg::Pong { .. } => {
                        if let Some(t0) = *last_ping.read().await {
                            let ms = t0.elapsed().as_millis() as i64;
                            if let Some(hh) = s.agents.write().await.get_mut(&agent_id) {
                                hh.info.rtt_ms = ms;
                            }
                        }
                    }
                    ClientMsg::Close { stream, .. } => {
                        if let Some(hh) = s.agents.read().await.get(&agent_id) {
                            hh.incoming.write().await.remove(&stream);
                            hh.pending.write().await.remove(&stream);
                        }
                    }
                    ClientMsg::Open { stream, kind, host, port } if kind == "egress" => {
                        spawn_egress_dial(&s, &agent_id, stream, host, port, ctl_tx.clone());
                    }
                    ClientMsg::Open { stream, kind, host, .. } if kind == "link" => {
                        spawn_link_relay(&s, &agent_id, &hostname, stream, host, ctl_tx.clone());
                    }
                    _ => {}
                }
                continue;
            }
            if let Some((id, payload)) = decode_data(&body) {
                // UDP 包带 dgram 内帧：逐个拆投；非 dgram 即裸 TCP/HTTP 字节（egress 下行链路）。
                let mut off = 0;
                let mut delivered = false;
                while let Some((dg, used)) = decode_dgram(&payload[off..]) {
                    off += used;
                    delivered = true;
                    deliver(&s, &agent_id, id, dg).await;
                }
                if !delivered {
                    deliver(&s, &agent_id, id, payload).await;
                }
            }
        }
        #[allow(unreachable_code)]
        anyhow::Ok::<()>(())
    }
    .await;
    let _ = read_res;
    write_task.abort();
    // 本端 FIN（读端结束即关，无半关闭）：200ms ×3 尽力发。
    if !fin_acked {
        for _ in 0..3 {
            let fh = KudusHdr {
                ver: 1,
                flags: FLAG_FIN,
                seq: 0,
                ack: 0,
                sack: [0u8; 32],
                ts_ms: now_ms(),
            };
            tx.send_pkt(&fh, b"bye");
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }
    cleanup(&s, &agent_id, &hostname).await;
    log_ev(&s, format!("kudus agent '{hostname}' disconnected"));
}

async fn on_register_from_body(s: &S, agent_id: &str, hostname: &str, body: &[u8]) {
    if let Ok(ClientMsg::Register { proxies }) = serde_json::from_slice::<ClientMsg>(body) {
        on_register(s, agent_id, hostname, proxies).await;
    }
}

/// agent 发来的数据投递到 incoming，附带 rx 记账（与 quic.rs::deliver 同语义）。
async fn deliver(s: &S, agent_id: &str, id: u32, payload: &[u8]) {
    let waiter = s
        .agents
        .read()
        .await
        .get(agent_id)
        .map(|h| (h.incoming.clone(), h.pending.clone()));
    if let Some((st, pe)) = waiter {
        if let Some(tx) = st.read().await.get(&id).cloned() {
            let _ = tx.send(payload.to_vec());
            if let Some(h) = s.agents.write().await.get_mut(agent_id) {
                h.info.rx_bytes += payload.len() as u64;
            }
        } else {
            let mut p = pe.write().await;
            let e = p.entry(id).or_default();
            if e.len() < 64 {
                e.push(payload.to_vec());
            }
        }
    }
}

/// 下线清理：与 quic.rs::cleanup 一致。
async fn cleanup(s: &S, agent_id: &str, hostname: &str) {
    {
        let mut ag = s.agents.write().await;
        if let Some(h) = ag.remove(agent_id) {
            s.totals.write().await.insert(hostname.to_string(), (h.info.rx_bytes, h.info.tx_bytes));
        }
        s.outbox.write().await.remove(agent_id);
        for v in s.domains.write().await.values_mut() {
            v.retain(|a| *a != agent_id);
        }
        for v in s.tcp_ports.write().await.values_mut() {
            v.retain(|a| *a != agent_id);
        }
    }
    save_state(s).await;
}

/// 绑 UDP + 分发循环：按 session_id 建 task，未知 session 非 SYN 直接丢。
pub(crate) async fn run_kudus(s: S, token: Arc<String>, bind: &str) -> anyhow::Result<()> {
    let sock = Arc::new(UdpSocket::bind(bind).await?);
    tracing::info!("kudus listening on {bind}");
    log_ev(&s, format!("kudus listening {bind}"));
    let key = derive_key(&token);
    let conns: Arc<RwLock<HashMap<u32, mpsc::UnboundedSender<(SocketAddr, KudusHdr, Vec<u8>)>>>> =
        Arc::new(RwLock::new(HashMap::new()));
    let mut buf = vec![0u8; 2048];
    loop {
        let (n, peer) = sock.recv_from(&mut buf).await?;
        let Some((session, nonce, ct)) = decode_packet(&buf[..n]) else {
            tracing::debug!("kudus short packet ({}B) from {peer}", n);
            continue; // 短包：丢
        };
        let Some(plain) = open(&key, nonce, ct) else {
            tracing::debug!("kudus undecryptable packet session={session:08x} from {peer}");
            continue; // 黑洞：解密失败零回包
        };
        let Some((h, body)) = decode_hdr(&plain) else {
            tracing::debug!("kudus bad inner hdr session={session:08x} from {peer}");
            continue;
        };
        let body = body.to_vec();
        if let Some(tx) = conns.read().await.get(&session).cloned() {
            let _ = tx.send((peer, h, body));
            continue;
        }
        // 未知 session：只有 SYN 建连，否则丢。
        if h.flags & FLAG_SYN == 0 {
            continue;
        }
        let (txc, rxc) = mpsc::unbounded_channel();
        conns.write().await.insert(session, txc.clone());
        let _ = txc.send((peer, h, body));
        let (s2, t2, sock2, conns2) = (s.clone(), token.clone(), sock.clone(), conns.clone());
        tokio::spawn(async move {
            handle_conn(s2, t2, sock2, session, rxc, peer).await;
            conns2.write().await.remove(&session);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_seq_is_dropped() {
        let mut seen = SeqWindow::new(100);
        assert!(seen.check(101));
        assert!(!seen.check(101)); // replay
        assert!(!seen.check(50)); // below left edge
    }

    #[test]
    fn stale_ts_is_dropped() {
        assert!(!ts_fresh(crate::common::kudus::now_ms() - 120_000)); // 120s old
        assert!(ts_fresh(crate::common::kudus::now_ms()));
    }

    #[test]
    fn check_token_rejects_empty() {
        assert!(!check_token("", "s3cret"));
        assert!(!check_token("s3cret", ""));
        assert!(check_token("s3cret", "s3cret"));
    }
}
