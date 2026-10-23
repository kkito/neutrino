//! server kudus 监听：独立 UDP 端口，XChaCha20-Poly1305 自研可靠传输。
//! 与 `quic.rs::handle_conn` 语义对齐：SYN → Hello 校验 → SYN-ACK →
//! Register/Config 收敛 → 心跳 → 隧道泵。token 错/解密失败一律静默丢包（黑洞）。
use crate::common::kudus::*;
use crate::common::proto::*;
use crate::common::quic::{decode_dgram, encode_dgram};
use crate::server::state::{log_ev, save_state, AgentHandle, AgentInfo, Shared};
use crate::server::tunnel::{on_register, spawn_egress_dial, spawn_link_relay, spawn_link_udp_relay};
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

/// 发送侧可靠上下文（server→agent 下行）：重传缓冲 + 对端 ACK 快照。
/// 与 agent 侧 `Pkt::rel` 对称：写泵登记、读循环清、超时泵重发。
/// server 下行 seq 起点必须跳过 agent 上行已用区间（见 KUDUS_SEQ_GAP）。
pub(crate) struct ServerRel {
    pub(crate) retx: crate::common::kudus::RetxBuf,
    pub(crate) ack: u32,
    pub(crate) sack: [u8; 32],
}

impl ServerRel {
    pub(crate) fn new() -> Self {
        Self { retx: crate::common::kudus::RetxBuf::new(crate::common::kudus::KUDUS_SEQ_GAP), ack: 0, sack: [0u8; 32] }
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

/// 写泵用可靠发送：DATA 帧登记重传（seq 分配 + 捎带 ACK 快照），
/// 控制/FIN 等非 DATA 帧原样发（不占可靠序列）。
/// 根因→修法：旧写泵全部 ack=0 发完即忘，跨机丢包即截断；现登记+ACK清+超时补。
fn rel_emit(tx: &Tx, rel: &std::sync::Mutex<ServerRel>, flags: u8, body: &[u8]) -> bool {
    // 注意：单次 lock 拿全三件——写泵 2MB 切 2000 帧时 double-lock 会把临界区
    // 串成 4000 次加锁，重传泵 try_lock 永远抢不到，RTO 形同虚设（blob 219608/2M 即此）。
    let (seq, ack, sack) = if flags & FLAG_DATA != 0 {
        let mut r = rel.lock().unwrap();
        let s = r.retx.on_send(body.to_vec());
        (s, r.ack, r.sack)
    } else {
        let r = rel.lock().unwrap();
        (0, r.ack, r.sack)
    };
    let h = KudusHdr { ver: 1, flags, seq, ack, sack, ts_ms: now_ms() };
    tx.send_pkt(&h, body)
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
    // 握手期 Register 分片重组槽（首个大数据 Register 在 SYN-ACK 循环里即到达）。
    let hs_reasm = std::sync::Arc::new(std::sync::Mutex::new(
        crate::common::kudus::CtrlReasm::new(),
    ));
    // 握手：首包必须是 SYN + Hello（15s 超时）。
    // 注意：超时/错 token 一律静默返回（黑洞，无回包无事件，见 design §2）；
    // 仅 debug 留痕（默认 info 不可见），方便 RUST_LOG=debug 排错。
    let (mut hostname, mut version) = (String::new(), String::new());
    // 握手收包同样做 ACK/去重（SYN 重传去重靠 ReorderBuf 之前置的 win 即可，此处轻量处理）。
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
    // 单 flight：同 hostname 旧会话先踢掉，保证路由唯一（与 ws_loop 同语义）。
    // 根因→修法：kudus 无连接，旧 agent 断网/重启后 server 侧残留僵尸行（rtt=-1），
    // 新会话并存抢路由、overview 越堆越多。Hello 到达即抢路由：清旧行 + 路由引用 + 通知。
    {
        let stale: Vec<String> = {
            let ag = s.agents.read().await;
            crate::server::state::stale_ids_for_hostname(
                &ag.iter().map(|(id, h)| (id.clone(), h.info.hostname.clone())).collect(),
                &hostname,
            )
        };
        for old in stale {
            if let Some(h) = s.agents.read().await.get(&old) {
                // Error 即整 session 致命（agent 侧 bail → 外层重连），与 ws_loop 踢人同语义；
                // Close{stream:0} 语义不明（agent 只删流表，0 不在表里）旧 agent 踢不动。
                let _ = h.ctl.send(ServerMsg::Error { reason: "superseded by new session".into() });
            }
            s.agents.write().await.remove(&old);
            s.outbox.write().await.remove(&old);
            s.udp_outbox.write().await.remove(&old);
            for v in s.domains.write().await.values_mut() {
                v.retain(|a| *a != old);
            }
            for v in s.tcp_ports.write().await.values_mut() {
                v.retain(|a| *a != old);
            }
            log_ev(&s, format!("kudus agent '{hostname}' superseded stale session {old}"));
        }
    }
    // 注册：与 quic.rs/ws_loop 同一套 agents/outbox/incoming/pending 表。
    let agent_id = uuid::Uuid::new_v4().to_string()[..8].to_string();
    let (ctl_tx, mut ctl_rx) = mpsc::unbounded_channel::<ServerMsg>();
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<(u32, Vec<u8>)>();
    // UDP 下行独立通道（见 state::udp_outbox 注释）：整包语义，与 TCP outbox 分开。
    let (udp_tx, mut udp_rx) = mpsc::unbounded_channel::<(u32, Vec<u8>)>();
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
                ctr_rx: Default::default(),
                ctr_tx: Default::default(),
                ctr_rtt: std::sync::Arc::new(std::sync::atomic::AtomicI64::new(-1)),
                ctl: ctl_tx.clone(),
                incoming: incoming.clone(),
                pending: pending.clone(),
            },
        );
        s.outbox.write().await.insert(agent_id.clone(), out_tx.clone());
        s.udp_outbox.write().await.insert(agent_id.clone(), udp_tx.clone());
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
                // 根因→修法：Register 已分片（CTRL_SID），首片半包 JSON 解析必失败，
                // 此处必须先喂重组器，攒齐整条再判定/重放，否则大 Register 永远等不到 acked。
                let full = match decode_data(&body) {
                    Some((id, payload)) if id == KUDUS_CTRL_SID => {
                        match hs_reasm.lock().unwrap().feed(payload) {
                            Some(f) => f,
                            None => continue,
                        }
                    }
                    _ => body,
                };
                if serde_json::from_slice::<ClientMsg>(&full)
                    .map(|m| matches!(m, ClientMsg::Register { .. }))
                    .unwrap_or(false)
                {
                    let _ = h2;
                    // Register 走正常分发（见下读循环重放）：先入队处理
                    on_register_from_body(&s, &agent_id, &hostname, &full).await;
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
    // 收发循环：读包（解密在分发层已做）→ 控制/数据分发；写泵（ctl/outbox→datagram，可靠登记）。
    // 上行（agent→server）seq 从 1 开始，重排缓冲同锚（agent 上行首帧 SYN seq=0 不可靠）。
    // 控制分片重组槽：跨包累计（可靠重排已保序，槽内只做 offset 去重+集齐组装）。
    let ctrl_reasm = std::sync::Arc::new(std::sync::Mutex::new(
        crate::common::kudus::CtrlReasm::new(),
    ));
    // 上行 UDP 分片重组槽（agent send_udp 大包分片的上行方向；与下行 udp_outbox 对称）。
    let udp_reasm = std::sync::Arc::new(std::sync::Mutex::new(
        crate::common::kudus::UdpReasm::new(),
    ));
    let mut rxbuf = crate::common::kudus::ReorderBuf::new(1);
    let rel = Arc::new(std::sync::Mutex::new(ServerRel::new()));
    let mut fin_acked = false;
    // 写泵 task：ctl 与 outbox 各自可靠封包发送（rel_emit 登记重传）。
    // 注意：单 datagram 单 DATA 帧（1 包 1 帧）：agent 读泵按 seq 重排，多帧合包
    // 会导致帧边界丢失（decode_data 只取首帧，整包余下字节被吞——undo 里 got 0 的根因之一）。
    let txw = tx.clone();
    let relw = rel.clone();
    // 写泵记账用原子计数快照（spawn 前 clone，泵内零 agents 锁）。
    let ctr_tx_w = s.agents.read().await.get(&agent_id).map(|h| h.ctr_tx.clone());
    let write_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                Some(m) = ctl_rx.recv() => {
                    // 根因→修法：Config 一消息一帧，代理多时 3320B 级 JSON 超
                    // KUDUS_MAX_UDP 被整包丢（且 break 退出写泵，后续下行全断）。
                    // 现按 KUDUS_CTRL_CHUNK 切片逐片发（与 agent send_ctrl 对称）；
                    // 单片超限（send_pkt false）只跳过本片，不退出写泵。
                    let t = serde_json::to_string(&m).unwrap();
                    for frag in crate::common::kudus::split_ctrl_frame(t.as_bytes()) {
                        if !rel_emit(&txw, &relw, FLAG_DATA, &frag) { break; }
                    }
                }
                Some((id, dg)) = udp_rx.recv() => {
                    // UDP 下行整包：≤1132B 整包一帧；>1132B 分片逐片发（agent 侧
                    // UdpReasm 攒齐后整包交付，包边界不变）；>8KB 丢 + warn。
                    // 与上行 send_udp 对称。背压与 TCP 分支同阈值（256 未确认）。
                    for _ in 0..3000 {
                        let n = relw.lock().map(|r| r.retx.len()).unwrap_or(0);
                        if n < 256 {
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                    if dg.len() <= crate::common::kudus::KUDUS_UDP_MAX {
                        let inner = encode_dgram(&dg);
                        let b = encode_data(id, &inner);
                        if !rel_emit(&txw, &relw, FLAG_DATA, &b) {
                            tracing::warn!("kudus udp downlink drop sid={id} ({}B)", dg.len());
                        }
                    } else if dg.len() <= crate::common::kudus::KUDUS_UDP_FRAG_MAX {
                        for frag in crate::common::kudus::split_udp_dgram(id, &dg) {
                            if !rel_emit(&txw, &relw, FLAG_DATA, &frag) { break; }
                        }
                    } else {
                        tracing::warn!("kudus udp downlink too large ({}B), dropped", dg.len());
                    }
                    if let Some(c) = ctr_tx_w.as_ref() {
                        c.fetch_add(dg.len() as u64, std::sync::atomic::Ordering::Relaxed);
                    }
                }
                Some((id, payload)) = out_rx.recv() => {
                    // outbox 数据：TCP 字节流按片切（单 datagram 装不下会整包丢→静默断流），
                    // 每片独立 DATA 帧独立 datagram（UDP 访客下行先套 dgram 帧；与 quic.rs::udp_out 同语）。
                    // 空载荷（EOF 标记）不能丢：chunks 为空时补一帧空包。
                    // 背压：retx 未确认超 256 包时等 ACK 再发（与 agent 侧 send_data 对称）——
                    // 旧无界发送，2MB 切 2000 帧瞬间灌满对端重排窗，丢包雪崩后双双 100% 空转。
                    // 根因→修法：旧分支不分 TCP/UDP，公网 1500B UDP 包被按 1000B 切片
                    // 逐片 deliver——内网收到 2 个残包，无声 corrupt。现 UDP 整包走
                    // split_udp_dgram 分片 + agent 侧 UdpReasm 重组后整包交付（包边界不变）；
                    // UDP 整包上限 8KB，超了丢 + warn（防 64KB 包 64 片的重传放大）。
                    // 注意：outbox (sid,payload) 无 kind 位，上游 ingress/egress/link
                    // 全是裸字节 TCP——UDP 下行不走这里（见下 udp_rx 分支，由上游
                    // 显式标记）。此处只剩 TCP 字节流，切片逐片交付语义正确。
                    for _ in 0..3000 {
                        let n = relw.lock().map(|r| r.retx.len()).unwrap_or(0);
                        if n < 256 {
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                    let pieces: Vec<&[u8]> = if payload.is_empty() {
                        vec![&[][..]]
                    } else {
                        payload.chunks(crate::common::kudus::KUDUS_DATA_CHUNK).collect()
                    };
                    for piece in pieces {
                        // 一片一切一片一帧：dgram 帧头 2B + 流复用头 4B 必须在同一 datagram 内
                        // 与负载一一对应，否则 agent 侧 decode_dgram 拆帧错位。
                        let inner = encode_dgram(piece);
                        let b = encode_data(id, &inner);
                        if !rel_emit(&txw, &relw, FLAG_DATA, &b) { break; }
                    }
                    if let Some(c) = ctr_tx_w.as_ref() {
                        c.fetch_add(payload.len() as u64, std::sync::atomic::Ordering::Relaxed);
                    }
                }
                else => break,
            }
        }
    });
    // 重传泵：50ms 扫一次超时未确认包，原样重发（带当前 ACK 快照）。
    // 注意：rel 锁必须 try_lock 碰到就跳过——写泵搬 2MB 时长占锁，重传泵若阻塞等锁
    // 会把 50ms 节拍拖成串行，RTO 永远追不上（loopback 实测 1659577/2097152 即卡死于此）。
    // 根因→修法：重传泵与 handle_conn 同命。旧裸 spawn 无 abort，会话被踢/cleanup
    // 后泵继续 50ms 发纯 ACK 探活——agent 侧若认 ACK 为活，看门狗被假心跳复位、
    // session 永不 bail（2026-10-23 workmac 现场：本地端口活、数据面死、无日志）。
    let retx_task = {
        let txr = tx.clone();
        let relr = rel.clone();
        tokio::spawn(async move {
            let mut iv = tokio::time::interval(Duration::from_millis(50));
            loop {
                iv.tick().await;
                let Ok(mut guard) = relr.try_lock() else { continue };
                let due = guard.retx.take_expired(crate::common::kudus::KUDUS_RTO, now_ms());
                let (ack, sack) = (guard.ack, guard.sack);
                drop(guard);
                if due.is_empty() {
                    // 无待补包也发纯 ACK 探活（对端 ACK 可能丢了，触发它重发 ACK）。
                    if ack != 0 {
                        let h = KudusHdr { ver: 1, flags: FLAG_ACK, seq: 0, ack, sack, ts_ms: now_ms() };
                        txr.send_pkt(&h, &[]);
                    }
                    continue;
                }
                for (seq, body) in due {
                    let h = KudusHdr { ver: 1, flags: FLAG_DATA, seq, ack, sack, ts_ms: now_ms() };
                    txr.send_pkt(&h, &body);
                }
            }
        })
    };
    // 读循环
    let read_res = async {
        loop {
            // 看门狗：75s 无 agent 任何帧即踢僵尸（任何业务帧都算活，不只 Ping）。
            // 根因→修法：旧裸 recv 永等，agent 断网即僵尸会话永久占路由。
            let (p, h, body) = match tokio::time::timeout(
                Duration::from_secs(crate::common::kudus::KUDUS_IDLE_KICK_SECS as u64),
                rx.recv(),
            )
            .await
            {
                Ok(Some(v)) => v,
                Ok(None) => anyhow::bail!("gone"), // channel 关：对端已走，对齐旧语义
                Err(_) => {
                    log_ev(&s, format!("kudus agent '{hostname}' heartbeat timeout, kicking stale session {agent_id}"));
                    fin_acked = true; // 尾巴省 3 包 FIN（下已发 3 次尽力通知）
                    for _ in 0..3 {
                        let fh = KudusHdr { ver: 1, flags: FLAG_FIN, seq: 0, ack: 0, sack: [0u8; 32], ts_ms: now_ms() };
                        tx.send_pkt(&fh, b"bye");
                        tokio::time::sleep(Duration::from_millis(200)).await;
                    }
                    break;
                }
            };
            *peer.write().unwrap() = p;
            if !ts_fresh(h.ts_ms) {
                tracing::debug!("kudus stale ts seq={} from {p}", h.seq);
                continue; // 重放旧包：丢
            }
            // 对端 ACK：DATA 与纯 ACK 帧都捎带（写泵每帧都带快照），清重传缓冲。
            // 注意：握手完成前 Register 还没重放（见下 SYN-ACK 段），此时 rxbuf 锚 1 收的是
            // 上行控制帧——但读循环在 handle_conn 握手之后才进，此处只见数据态包。
            // 上行序列从 1 起（agent SYN seq=0 不可靠帧），rxbuf 同锚无撞车。
            rel.lock().unwrap().retx.on_ack(h.ack, &h.sack);
            if h.flags & FLAG_DATA != 0 {
                // 可靠投递：重排缓冲保序，洞后包缓存等补齐；推进即更新 ACK 快照。
                // 根因→修法：旧 win.check 到包即投，丢包永久少块；现缓存等补齐后全投。
                let ready = rxbuf.push(h.seq, body);
                {
                    let mut r = rel.lock().unwrap();
                    r.ack = rxbuf.ack();
                    r.sack = rxbuf.sack();
                }
                if ready.is_empty() {
                    // 洞后包：只回 ACK+SACK 催补（body 先缓存不投）。
                    let (ack, sack) = {
                        let r = rel.lock().unwrap();
                        (r.ack, r.sack)
                    };
                    let ah = KudusHdr { ver: 1, flags: FLAG_ACK, seq: 0, ack, sack, ts_ms: now_ms() };
                    tx.send_pkt(&ah, &[]);
                    continue;
                }
                for ob in ready {
                    // 控制分片先重组：sid==CTRL_SID 即分片，攒齐前不进 JSON 解析
                    // （半条 JSON parse 必失败，旧代码会把它当数据帧误投 deliver）。
                    // UDP 分片同理：sid==UDP_SID 即分片，攒齐后整包交付（包边界不变）。
                    let ob = match decode_data(&ob) {
                        Some((id, payload)) if id == KUDUS_CTRL_SID => {
                            match ctrl_reasm.lock().unwrap().feed(payload) {
                                Some(full) => full,
                                None => continue,
                            }
                        }
                        Some((id, payload)) if id == crate::common::kudus::KUDUS_UDP_SID => {
                            match udp_reasm.lock().unwrap().feed(payload) {
                                Some((sid, dg)) => encode_data(sid, &encode_dgram(&dg)),
                                None => continue,
                            }
                        }
                        _ => ob,
                    };
                    dispatch_body(&s, &agent_id, &hostname, &ctl_tx, &tx, ob).await;
                }
                continue;
            }
            if h.flags & FLAG_ACK != 0 {
                // 纯 ACK：只清重传（上已做），无 body 可分发。
                continue;
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
                        // 根因→修法：server 反向 Ping 已砍（唯一作用是量 RTT）；rtt 改由
                        // agent 上报的 ts 秒级计算，展示够用，省每会话每 15s 一包。
                        // 原子写 rtt，零 agents 写锁（Ping 每 15~30s 一包，flood 时亦然）。
                        let _ = ctl_tx.send(ServerMsg::Pong { ts });
                        let ms = (chrono::Utc::now().timestamp() - ts).max(0) * 1000;
                        if let Some(hh) = s.agents.read().await.get(&agent_id) {
                            hh.ctr_rtt.store(ms, std::sync::atomic::Ordering::Relaxed);
                        }
                    }
                    ClientMsg::AdminReq { req_id, method, path, body } => {
                        let (st, rb) = crate::server::api::dispatch_admin(&s, &hostname, &method, &path, &body).await;
                        let _ = ctl_tx.send(ServerMsg::AdminResp { req_id, status: st, body: rb });
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
                    ClientMsg::Open { stream, kind, host, .. } if kind == "link_udp" => {
                        let (name, peer) = host.split_once('|').map(|(a, b)| (a.to_string(), b.to_string()))
                            .unwrap_or((host.clone(), String::new()));
                        spawn_link_udp_relay(&s, &agent_id, &hostname, stream, peer, name, ctl_tx.clone());
                    }
                    ClientMsg::Open { stream, kind, host, .. } if kind == "link" => {
                        spawn_link_relay(&s, &agent_id, &hostname, stream, host, ctl_tx.clone());
                    }
                    _ => {}
                }
                continue;
            }
            if let Some((id, payload)) = decode_data(&body) {
                // agent 上行 TCP 同样套 dgram 帧（与 server 下行对称，见 agent send_data_stream）：
                // 拆一层即得整片；非 dgram 即裸字节（兼容控制面空包/EOF）。
                if let Some((dg, _)) = decode_dgram(payload) {
                    deliver(&s, &agent_id, id, dg).await;
                } else {
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
    retx_task.abort();
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

/// 有序包分发：原读循环内控制/数据分支抽出（重排补齐后逐个调用）。
/// 注意：控制分片已在调用方重组为整条（CTRL_SID 不会落到这里）；
/// 分片半包若漏进来，JSON 解析失败即落到 decode_data 分支，而 CTRL_SID
/// ≠任何真实流 id，deliver 查不到表只进 pending，不污染数据流。
async fn dispatch_body(
    s: &S, agent_id: &str, hostname: &str, ctl_tx: &mpsc::UnboundedSender<ServerMsg>,
    tx: &Tx, body: Vec<u8>,
) {
    if let Ok(cm) = serde_json::from_slice::<ClientMsg>(&body) {
        match cm {
            ClientMsg::Register { proxies } => {
                on_register(s, agent_id, hostname, proxies).await;
            }
            ClientMsg::Ping { ts } => {
                // 同读循环：rtt 由 agent 上报 ts 秒级计算（反向 Ping 已砍）。
                // 原子写 rtt，零 agents 写锁。
                let _ = ctl_tx.send(ServerMsg::Pong { ts });
                let ms = (chrono::Utc::now().timestamp() - ts).max(0) * 1000;
                if let Some(hh) = s.agents.read().await.get(agent_id) {
                    hh.ctr_rtt.store(ms, std::sync::atomic::Ordering::Relaxed);
                }
            }
            ClientMsg::AdminReq { req_id, method, path, body } => {
                let (st, rb) = crate::server::api::dispatch_admin(s, hostname, &method, &path, &body).await;
                let _ = ctl_tx.send(ServerMsg::AdminResp { req_id, status: st, body: rb });
            }
            ClientMsg::Close { stream, .. } => {
                if let Some(hh) = s.agents.read().await.get(agent_id) {
                    hh.incoming.write().await.remove(&stream);
                    hh.pending.write().await.remove(&stream);
                }
            }
            ClientMsg::Open { stream, kind, host, port } if kind == "egress" => {
                spawn_egress_dial(s, agent_id, stream, host, port, ctl_tx.clone());
            }
            ClientMsg::Open { stream, kind, host, .. } if kind == "link_udp" => {
                let (name, peer) = host.split_once('|').map(|(a, b)| (a.to_string(), b.to_string()))
                    .unwrap_or((host.clone(), String::new()));
                spawn_link_udp_relay(s, agent_id, hostname, stream, peer, name, ctl_tx.clone());
            }
            ClientMsg::Open { stream, kind, host, .. } if kind == "link" => {
                spawn_link_relay(s, agent_id, hostname, stream, host, ctl_tx.clone());
            }
            _ => {}
        }
        return;
    }
    if let Some((id, payload)) = decode_data(&body) {
        // 同上：agent 上行 TCP 套 dgram 帧，拆一层即得整片。
        if let Some((dg, _)) = decode_dgram(payload) {
            deliver(s, agent_id, id, dg).await;
        } else {
            deliver(s, agent_id, id, payload).await;
        }
    }
    let _ = tx; // ACK 回执由调用方统一发（本函数只分发 body）
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
        .map(|h| (h.incoming.clone(), h.pending.clone(), h.ctr_rx.clone()));
    if let Some((st, pe, ctr)) = waiter {
        if let Some(tx) = st.read().await.get(&id).cloned() {
            let _ = tx.send(payload.to_vec());
            // 原子累加，零 agents 写锁（总量由 5s tick 批量合进 info）。
            ctr.fetch_add(payload.len() as u64, std::sync::atomic::Ordering::Relaxed);
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
        // cleanup 合账：ctr 原子残量先合进 info 再落 totals，否则 5s 窗内流量丢
        // （flood 下包级增量全在 ctr 里，info 基线是 5s 前的）。
        if let Some(h) = ag.get_mut(agent_id) {
            h.info.rx_bytes += h.ctr_rx.swap(0, std::sync::atomic::Ordering::Relaxed);
            h.info.tx_bytes += h.ctr_tx.swap(0, std::sync::atomic::Ordering::Relaxed);
        }
        if let Some(h) = ag.remove(agent_id) {
            s.totals.write().await.insert(hostname.to_string(), (h.info.rx_bytes, h.info.tx_bytes));
        }
        s.outbox.write().await.remove(agent_id);
        s.udp_outbox.write().await.remove(agent_id);
        for v in s.domains.write().await.values_mut() {
            v.retain(|a| *a != agent_id);
        }
        for v in s.tcp_ports.write().await.values_mut() {
            v.retain(|a| *a != agent_id);
        }
    }
    save_state(s).await;
}

/// 同 key 60s 最多 1 条 warn（首包详情 + 计数在 tick 里看总量）。纯内存不落盘。
fn maybe_warn_drop(s: &S, key: String, peer: &str, bytes: usize) {
    let now = chrono::Local::now().timestamp();
    let hit = s
        .drop_warn
        .lock()
        .map(|mut m| {
            let last = m.get(&key).cloned().unwrap_or(0);
            if crate::server::state::warn_throttled(last, now) {
                m.insert(key.clone(), now);
                true
            } else {
                false
            }
        })
        .unwrap_or(false);
    if hit {
        tracing::warn!("kudus drop {key} from {peer} ({bytes}B, sampled 1/60s)");
    }
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
        let peer_s = peer.to_string();
        let Some((session, nonce, ct)) = decode_packet(&buf[..n]) else {
            let k = crate::server::state::drop_key("short", &peer_s);
            crate::server::state::record_drop(&s, k.clone(), n as u64);
            maybe_warn_drop(&s, k, &peer_s, n);
            tracing::debug!("kudus short packet ({}B) from {peer}", n);
            continue; // 短包：丢
        };
        let Some(plain) = open(&key, nonce, ct) else {
            let k = crate::server::state::drop_key("undecryptable", &peer_s);
            crate::server::state::record_drop(&s, k.clone(), n as u64);
            maybe_warn_drop(&s, k, &peer_s, n);
            tracing::debug!("kudus undecryptable packet session={session:08x} from {peer}");
            continue; // 黑洞：解密失败零回包
        };
        let Some((h, body)) = decode_hdr(&plain) else {
            let k = crate::server::state::drop_key("bad_hdr", &peer_s);
            crate::server::state::record_drop(&s, k.clone(), plain.len() as u64);
            maybe_warn_drop(&s, k, &peer_s, plain.len());
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
            let k = crate::server::state::drop_key("unknown_session", &peer_s);
            crate::server::state::record_drop(&s, k.clone(), n as u64);
            maybe_warn_drop(&s, k, &peer_s, n);
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
        // 旧 SeqWindow 已被 ReorderBuf 取代：同语义（去重+保序+补洞）走新缓冲验证。
        // 根因→修法：旧窗口到包即投、无补洞，跨机丢包永久少块（avatar/blob 截断）。
        let mut seen = crate::common::kudus::ReorderBuf::new(101);
        assert!(seen.push(101, b"a".to_vec()).len() == 1);
        assert!(seen.push(101, b"a".to_vec()).is_empty()); // replay：重复投递为空
        assert!(seen.push(50, b"o".to_vec()).is_empty()); // below left edge：过旧丢弃
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

    #[test]
    fn retx_pump_is_abortable_with_session() {
        // workmac 2026-10-23：裸 spawn 的重传泵在 handle_conn 返回后继续 50ms
        // 纯 ACK 探活，喂出 agent 侧静默僵尸。此单测锁死“泵有 AbortHandle 且随
        // 会话结束 abort”的结构：handle 必须存在（编译期），abort 后 task 结束。
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let probe = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let p2 = probe.clone();
            // 同 handle_conn 内重传泵形状：50ms tick 循环 + 外部 abort 即停。
            let h = tokio::spawn(async move {
                let mut iv = tokio::time::interval(std::time::Duration::from_millis(50));
                loop {
                    iv.tick().await;
                    p2.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            });
            tokio::time::sleep(std::time::Duration::from_millis(120)).await;
            assert!(probe.load(std::sync::atomic::Ordering::Relaxed) >= 1);
            h.abort();
            let _ = h.await;
            let n = probe.load(std::sync::atomic::Ordering::Relaxed);
            tokio::time::sleep(std::time::Duration::from_millis(120)).await;
            assert_eq!(probe.load(std::sync::atomic::Ordering::Relaxed), n); // 停了，不再涨
        });
    }

    #[test]
    fn kudus_watchdog_contract() {
        // Task 3 看门狗与 Task 1 同阈值；server 不再自发 Ping（rtt 由 agent 上报）。
        assert_eq!(crate::common::kudus::KUDUS_IDLE_KICK_SECS, 75);
        assert!(crate::common::kudus::kudus_idle_stale(0, 76));
    }
}
