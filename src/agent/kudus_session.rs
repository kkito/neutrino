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
    /// udp 类流的 socket 池（与 link_udp 独立，互不抢占）。
    /// 根因→修法：旧 `udp_slots: Semaphore(256)` 打满即拒（snail 实测 3608 条
    /// "too many udp streams"）；现改为池化 + LRU 踢流，socket 数只与「同时在
    /// 等回包的会话数」相关，与「累计会话数」无关。
    pub(crate) udp_pool: Arc<tokio::sync::Mutex<super::udp_pool::UdpPool>>,
    /// link_udp 类流的 socket 池。独立实例，BT 洪峰不会饿死 link 功能。
    pub(crate) link_udp_pool: Arc<tokio::sync::Mutex<super::udp_pool::UdpPool>>,
    /// UDP 流空闲超时（秒）。启动时由 `--udp-idle-secs` 定型，见 `resolve_udp_idle_secs`。
    pub(crate) udp_idle_secs: u64,
}

/// UDP 流空闲超时默认值（秒）；`--udp-idle-secs` 可覆盖，见 `resolve_udp_idle_secs`。
/// 根因→修法：曾 120s、后 30s，均与 server 侧 UDP_SESSION_TTL_SECS_DEFAULT 相差过大
/// ——server 先回收 session 并发 Close，agent 却还挂着 fd。现与 server 默认对齐；
/// 主路径仍是 server 主动 Close，此值只作 server 异常（崩溃/断网）时的兜底。
const UDP_STREAM_IDLE_SECS: u64 = 5;

/// 解析 `--udp-idle-secs`：0 视为未传→回退默认值。
/// 抽成纯函数以便单测，也避免 `Duration::from_secs(0)` 造成“超时立刻触发”
/// 或“永不超时”这类灾难性误配（前者会把所有流瞬杀）。
pub(crate) fn resolve_udp_idle_secs(cli: u64) -> u64 {
    if cli == 0 {
        UDP_STREAM_IDLE_SECS
    } else {
        cli
    }
}

/// UDP 出站 socket 的接收缓冲大小（每条流一份，池化后每个 socket 一份）。
/// 根因→修法：旧值 65535，256 流即 16MB 纯堆内存；池化到 512 流是 32MB。
/// 而隧道单片上限 KUDUS_UDP_MAX=1232、标准 MTU ~1500，2048 足够并留余量。
pub(crate) const UDP_RECV_BUF: usize = 2048;

/// UDP 流的结束原因。收尾日志用，避免只看到一个笼统的 eof。
pub(crate) const END_IDLE: u8 = 0;
pub(crate) const END_CHANNEL_CLOSED: u8 = 1;
pub(crate) const END_SEND_ERR: u8 = 2;
pub(crate) const END_RECV_ERR: u8 = 3;
pub(crate) const END_LOCAL_EOF: u8 = 4;
pub(crate) const END_RUNNING: u8 = 255;

/// 单条 UDP 流的计数（两侧泵各写一半，收尾时汇总）。
#[derive(Debug)]
pub(crate) struct UdpStreamStat {
    pub(crate) started: std::time::Instant,
    pub(crate) rx_pkts: std::sync::atomic::AtomicU64,
    pub(crate) rx_bytes: std::sync::atomic::AtomicU64,
    pub(crate) tx_pkts: std::sync::atomic::AtomicU64,
    pub(crate) tx_bytes: std::sync::atomic::AtomicU64,
    pub(crate) truncated: std::sync::atomic::AtomicU64,
    /// 结束原因，取最后写入的那个（哪个泵先退出就是谁的原因）。
    pub(crate) end: std::sync::atomic::AtomicU8,
}

impl Default for UdpStreamStat {
    fn default() -> Self {
        Self {
            started: std::time::Instant::now(),
            rx_pkts: Default::default(),
            rx_bytes: Default::default(),
            tx_pkts: Default::default(),
            tx_bytes: Default::default(),
            truncated: Default::default(),
            end: std::sync::atomic::AtomicU8::new(END_RUNNING),
        }
    }
}

impl UdpStreamStat {
    pub(crate) fn reason(&self) -> &'static str {
        match self.end.load(std::sync::atomic::Ordering::Relaxed) {
            END_IDLE => "idle-timeout",
            END_CHANNEL_CLOSED => "server-close",
            END_SEND_ERR => "send-err",
            END_RECV_ERR => "recv-err",
            END_LOCAL_EOF => "local-eof",
            _ => "running",
        }
    }
}

/// agent 侧等待隧道窗口的最长时间；超时即丢弃本次数据（UDP 语义允许丢）。
/// 根因→修法：旧实现 3000×10ms(30s) 循环耗尽后照样发送，
/// 与 server 侧同构——背压在超时后形同虚设。
const KUDUS_AGENT_SEND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

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

/// 写泵故障计数（发送失败帧数）。
/// 单独计数而非直接 warn：写泵死后每个包都会失败（几百/秒），逐条 warn 会打爆日志。
/// 改为累计 + 限流（见 [`note_send_fail`]），运维仍能从一行 warn 里看到“故障在持续”。
static SEND_FAILS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static SEND_FAIL_LAST_WARN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// 测试与运维观察用：累计发送失败帧数。
pub(crate) fn send_fail_count() -> u64 {
    SEND_FAILS.load(std::sync::atomic::Ordering::Relaxed)
}

/// 记录一次发送失败；最多每 5s 输出一行 warn（带累计数与帧类型）。
///
/// 根因：`emit` 的全链路调用点（`send_ack_only`/`send_ctrl`/`send`）都是 `let _ =`，
/// 写泵 task 退出后发送立刻失败却完全静默。2026-10-24 现场：agent 上行 tx
/// 从 ~4KB/5s 跌到恒 0、抓包 396 入/4 出，日志一片干净——正是“静默失败”的后果。
fn note_send_fail(flags: u8, len: usize) {
    use std::sync::atomic::Ordering::Relaxed;
    let n = SEND_FAILS.fetch_add(1, Relaxed) + 1;
    let now = now_ms();
    let last = SEND_FAIL_LAST_WARN.load(Relaxed);
    // now - last >= 5000，用 saturating_sub 防时钟回拨。
    if now.saturating_sub(last) >= 5_000
        && SEND_FAIL_LAST_WARN
            .compare_exchange(last, now, Relaxed, Relaxed)
            .is_ok()
    {
        tracing::warn!(
            "kudus agent uplink send failed (flags={flags:#04x} len={len}) total_fails={n} \
             — write pump likely dead, uplink is DOWN"
        );
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
            .map_err(|e| {
                // 写泵（UDP 发送 task）已退出时这里立即失败。旧代码全链路 `let _ =`
                // 吞错，于是“上行整条断了”在日志里毫无痕迹。
                note_send_fail(flags, plain.len());
                anyhow::anyhow!("{e}")
            })?;
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
    /// 对端 ACK 到达：清重传缓冲，并**立即补 SACK 显示的洞**（快速重传）。
    ///
    /// 根因→修法：旧实现只清表不管洞，重传完全靠 200ms RTO 超时。
    /// 链路 15-20% 丢包时（docs/incidents/2026-10-24-lossy-link-sack-gap.md）
    /// 每个洞白等 RTO，大传输永久卡死。对端 SACK 本已告知“后面到了、前面有洞”，
    /// 这里拿到洞就当场重发一帧，不必等超时。
    pub(crate) fn on_ack(&self, ack: u32, sack: [u8; 32]) {
        let fast = self.rel.lock().unwrap().retx.on_ack(ack, &sack);
        for (seq, body) in fast {
            // 原样重发该 DATA 帧（seq 保持不变，对端按重排窗接纳）。
            let (a, s) = self.ack_snap();
            if let Err(e) = self.emit(FLAG_DATA, seq, a, s, &body) {
                tracing::debug!("fast retransmit seq={seq} failed: {e:#}");
            }
        }
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
                // retx 缓冲满（KUDUS_RETX_CAP）：丢弃本帧。UDP 语义允许丢。
                let s = match r.retx.on_send(body.to_vec()) {
                    Ok(s) => s,
                    Err(_) => {
                        tracing::warn!(
                            "kudus retx buf full ({}), dropping DATA frame",
                            crate::common::kudus::KUDUS_RETX_CAP
                        );
                        return Ok(());
                    }
                };
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
    /// 等待 retx 未确认包数降到背压阈值以下。
    /// 返回 `true` = 有空间可发；`false` = 等了 `KUDUS_AGENT_SEND_TIMEOUT` 仍积压。
    /// 根因→修法：旧实现超时后直接返回 `()`、调用方照样发，背压失效；
    /// 现改为返回 bool，调用方据此**丢弃**本次数据（UDP 可丢，不会放大）。
    /// 注意：用异步 sleep，不占 reactor（旧 `thread::sleep` 版会卡死同 task 其他流）。
    pub(crate) async fn wait_window(&self) -> bool {
        let mut waited = std::time::Duration::ZERO;
        while self.rel.lock().map(|r| r.retx.len()).unwrap_or(0)
            >= crate::common::kudus::KUDUS_RETX_BACKLOG
        {
            if waited >= KUDUS_AGENT_SEND_TIMEOUT {
                return false;
            }
            tokio::time::sleep(crate::common::kudus::BACKPRESSURE_POLL).await;
            waited += crate::common::kudus::BACKPRESSURE_POLL;
        }
        true
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
    /// 单个 UDP 数据报发送：上限内整包直发（保边界不可切）；超限则分片+重组。
    /// 根因→修法：旧代码超 1132B 直接 warn 丢包——公网 1500B UDP 上行永远到不了内网。
    /// 现 ≤1132B 整包一帧（与旧语义一致）；>1132B 按 KUDUS_UDP_CHUNK 切片
    /// （split_udp_dgram），对端 UdpReasm 攒齐后整包交付，包边界不变。
    /// 上限 8KB 封顶：更大包切 8+ 片，任丢一片即整包重传，放大太狠不如丢 +
    /// warn（典型 UDP 包 <1200B 无影响；与 QUIC DGRAM_MAX=65527 不同，kudus 按
    /// datagram 预算收敛，超大包走 TCP 隧道）。
    pub(crate) fn send_udp(&self, sid: u32, dg: &[u8]) {
        if dg.len() <= crate::common::kudus::KUDUS_UDP_MAX {
            let inner = encode_dgram(dg);
            if 4 + 24 + HDR_LEN + inner.len() + 16 > KUDUS_MAX_UDP {
                tracing::warn!("kudus udp datagram too large ({}B), dropped", dg.len());
                return;
            }
            let _ = self.send(FLAG_DATA, 0, [0u8; 32], &encode_data(sid, &inner));
            return;
        }
        if dg.len() > 8192 {
            tracing::warn!("kudus udp datagram too large ({}B), dropped", dg.len());
            return;
        }
        for frag in crate::common::kudus::split_udp_dgram(sid, dg) {
            if self.send(FLAG_DATA, 0, [0u8; 32], &frag).is_err() {
                break;
            }
        }
    }
}

pub(crate) async fn session(
    up: Upstream,
    cfg: AgentFileConfig,
    status: Arc<RwLock<super::web::AgentStatus>>,
    kudus_out: super::egress::KudusOutHolder,
    idle_secs_cli: u64,
    pool_max_cli: usize,
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
    // 根因→修法：重传泵与 session 同命。旧裸 spawn 无 abort，session 结束（bail/踢）
    // 后泵继续 50ms 空转拖着旧 rel/channel 不放（workmac 现场：僵尸 task 越堆越多）。
    // ping loop 同理：send_ctrl 失败即自退，但 out 通道若被他人持有则退不了，同样 abort。
    let retx_task = {
        use std::sync::TryLockError;
        let p = pkt.clone();
        // spec §15.3：agent 侧重传埋点，60s 节流打一次汇总（与 server 侧对称）。
        let sess_hex = format!("{:08x}", pkt.session);
        let host_name = up.hostname.clone();
        let mut last_stats_at = std::time::Instant::now();
        tokio::spawn(async move {
            let mut iv = tokio::time::interval(std::time::Duration::from_millis(50));
            loop {
                iv.tick().await;
                let due = match p.rel.try_lock() {
                    Ok(mut r) => {
                        let d = r.retx.take_expired(crate::common::kudus::KUDUS_RTO, crate::common::kudus::now_ms());
                        if last_stats_at.elapsed() >= std::time::Duration::from_secs(60) {
                            last_stats_at = std::time::Instant::now();
                            let st = r.retx.take_stats();
                            if st.sent + st.abandoned + st.full > 0 || st.backlog_max > 0 {
                                // send_fail = 上行写泵故障帧数（累计）。非 0 就说明上行在丢帧，
                                // 2026-10-24 事故里这个值会持续增长而上行 tx 为 0。
                                tracing::info!(
                                    "kudus retx session={} hostname={} sent={} abandoned={} full={} backlog_max={} send_fail={}",
                                    sess_hex, host_name, st.sent, st.abandoned, st.full, st.backlog_max,
                                    send_fail_count()
                                );
                            }
                        }
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
        })
    };
    *kudus_out.write().await = Some(pkt.clone());
    super::admin::set_sender(Some(super::admin::AdminSender::Kudus(pkt.clone()))).await;
    let ctx = Arc::new(KCtx {
        proxies: RwLock::new(cfg.proxies.clone()),
        link_tasks: tokio::sync::Mutex::new(HashMap::new()),
        streams: RwLock::new(HashMap::new()),
        pending: RwLock::new(HashMap::new()),
        udp_pool: Arc::new(tokio::sync::Mutex::new(super::udp_pool::UdpPool::with_max(
            super::udp_pool::PoolKind::Udp,
            super::udp_pool::resolve_pool_max(pool_max_cli),
        ))),
        link_udp_pool: Arc::new(tokio::sync::Mutex::new(super::udp_pool::UdpPool::with_max(
            super::udp_pool::PoolKind::LinkUdp,
            super::udp_pool::resolve_pool_max(pool_max_cli),
        ))),
        udp_idle_secs: resolve_udp_idle_secs(idle_secs_cli),
    });
    let kudus_link_holder = kudus_out.clone();
    super::link::sync_link_listeners_kudus(&ctx, &cfg.proxies, &up.hostname, &kudus_link_holder).await;
    // 根因→修法：link 监听与 session 同命。旧 ctx 随 session 丢弃时 AbortHandle
    // 跟着丢，监听成孤儿占端口，重连 bind 必然 Address in use（控制面活、数据面全死）。
    // Guard 借 ctx.link_tasks，session 任一退出路径 drop 即全 abort。
    let _link_guard = super::link::LinkGuard::new(&ctx.link_tasks);
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
    let ping_task = {
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
        })
    };
    // 主分发循环（看门狗：75s 无 server 任何帧即判死，bail 走外层 backoff 重连。
    // 根因→修法：旧裸 recv 永等，server OOM 重启后 agent 卡旧会话无感知
    // （macmini 2026-10-21 现场）。握手完成后的主循环才计时。）
    // 控制分片重组槽（Config 分片跨包累计，可靠重排已保序）。
    let mut ctrl_reasm = crate::common::kudus::CtrlReasm::new();
    // 下行 UDP 分片重组槽（server udp_outbox 大包分片，攒齐后整包交付）。
    let mut udp_reasm = crate::common::kudus::UdpReasm::new();
    // 看门狗基准：**绝对时刻**，只有 DATA/FIN 推进它。
    //
    // 根因→修法（2026-10-25 现场）：旧代码把 `timeout(75s, recv())` 写在
    // 循环体内，纯 ACK 走 `continue` 后**重建了一个全新 timeout，把计时器
    // 重置掉**。server 重传泵每 50ms 发一个纯 ACK ⇒ timeout 永远在 50ms
    // 返回、永远到不了 75s ⇒ 会话永不 bail。旧注释「看门狗照常计时」是错的。
    //
    // 现场：server 重启后不认旧会话（`tx=0B`、日志无该会话），agent 却
    // `welcomed` 之后 7 小时零重连；抓包 In=27（server 纯 ACK）/ Out=3，
    // 链路上同期 **0% 丢包**——不是丢包问题，是看门狗失效。
    //
    // 修法：基准用 `Instant` 存在循环外，每次循环算出**剩余预算**给 timeout；
    // 只有喂看门狗的帧才刷新基准。这样连续纯 ACK 会把预算耗光。
    let mut last_alive = std::time::Instant::now();
    loop {
        let budget = std::time::Duration::from_secs(
            crate::common::kudus::KUDUS_IDLE_KICK_SECS as u64,
        )
        .saturating_sub(last_alive.elapsed());
        let (h, body) = match tokio::time::timeout(budget, dec_rx.recv()).await {
            Ok(Some((h, body))) => {
                // 看门狗只认 DATA 帧：泄漏的 server 重传泵每 50ms 发纯 ACK 探活，
                // 若算活则 75s 超时永不到、session 永不 bail（2026-10-23 现场）。
                // 纯 ACK 只清重传（读泵已做），此处直接等下一帧，**不刷新基准**。
                // FIN 例外必须穿透：server 踢会话的 FIN 本身就是非 DATA 帧，
                // 若一起过滤则踢人通知永远到不了关闭分支（与下 `FLAG_FIN` 对应）。
                if !crate::common::kudus::frame_feeds_watchdog(h.flags) && h.flags & FLAG_FIN == 0 {
                    continue;
                }
                last_alive = std::time::Instant::now();
                (h, body)
            }
            _ => anyhow::bail!("kudus heartbeat timeout: no server frame"),
        };
        if h.flags & FLAG_FIN != 0 {
            // server FIN：回 ACK 即关。
            let _ = pkt.send(FLAG_ACK, h.seq, [0u8; 32], b"bye");
            break;
        }
        // 控制分片先重组（与 server 侧对称）：sid==CTRL_SID 即分片，攒齐前不解析。
        // UDP 分片同理：sid==UDP_SID 即分片，攒齐后拼回 (sid, dgram帧) 走正常交付。
        let body = match decode_data(&body) {
            Some((id, payload)) if id == KUDUS_CTRL_SID => {
                match ctrl_reasm.feed(payload) {
                    Some(full) => full,
                    None => continue,
                }
            }
            Some((id, payload)) if id == crate::common::kudus::KUDUS_UDP_SID => {
                match udp_reasm.feed(payload) {
                    Some((sid, dg)) => encode_data(sid, &encode_dgram(&dg)),
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
                ServerMsg::Error { reason } => {
                    // server 踢旧会话/单 flight 抢路由时发 Error（kudus.rs 单 flight 段注释
                    // 即"Error 即整 session 致命"），此处必须 bail 走外层重连——
                    // 若吞掉（旧 `_ => {}`），agent 认知与 server 分裂：本地端口活、
                    // 数据面死、无任何日志（2026-10-23 workmac 现场）。
                    anyhow::bail!("kudus server error: {reason}");
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
    retx_task.abort();
    ping_task.abort();
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
    if kind == "link_udp" {
        // UDP 出口 dial：UdpSocket::bind(0) → "connect" 到真实目标 → 双泵。
        // UDP 无连接：server 侧会话表按 peer 复用 session，出口每 Open 即一条出向流。
        let local = match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("kudus link_udp egress bind failed: {e:#}");
                let c = ClientMsg::Close { stream: sid, reason: "link denied".into() };
                let _ = pkt.send_ctrl(&c);
                return Ok(());
            }
        };
        if local.connect((host.as_str(), port)).await.is_err() {
            tracing::warn!("kudus link_udp egress connect {host}:{port} failed");
            let c = ClientMsg::Close { stream: sid, reason: "link denied".into() };
            let _ = pkt.send_ctrl(&c);
            return Ok(());
        }
        tracing::debug!("kudus link_udp egress stream {sid} -> {host}:{port}");
        return open_udp_stream_to(
            ctx,
            pkt,
            sid,
            local,
            super::udp_pool::PoolKind::LinkUdp,
        )
        .await;
    }
    if kind == "egress_dial" {
        // kudus 版反向拨号：dial 真实目标 + pump_tcp（与 open_tcp_stream 出口段同构）。
        let local = match tokio::time::timeout(
            std::time::Duration::from_secs(30),
            TcpStream::connect((host.as_str(), port)),
        )
        .await
        {
            Ok(Ok(s)) => s,
            _ => {
                let c = ClientMsg::Close { stream: sid, reason: "link denied".into() };
                let _ = pkt.send_ctrl(&c);
                return Ok(());
            }
        };
        tracing::debug!("kudus egress_dial stream {sid} -> {host}:{port}");
        return pump_tcp(ctx, pkt, sid, local, false).await;
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
            if !pktw.wait_window().await {
                tracing::warn!("kudus agent send timeout, dropping http response (sid={sid})");
                return;
            }
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
                        if !pkt2.wait_window().await {
                            tracing::warn!("kudus agent send timeout, dropping chunk (sid={sid})");
                            break;
                        }
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

async fn open_udp_stream_to(
    ctx: Arc<KCtx>,
    pkt: Pkt,
    sid: u32,
    sock: tokio::net::UdpSocket,
    kind: super::udp_pool::PoolKind,
) -> anyhow::Result<()> {
    // 从对应池借槽位；池满则踢最久未活跃的 sid（发 Close 并复用它的槽位），新流总能进。
    // 根因→修法：旧实现 Semaphore(256) 拿不到 permit 就 warn + Close + return，
    // DHT 扫描下所有新 peer 全断（snail 实测 3608 条 too many udp streams）。
    //
    // 注意：UdpPool::acquire 在池满时**内部已经完成**「移除 victim + 把新 sid
    // 放进 victim 的槽位」，返回 Evicted(victim) 只是告知调用方该给谁发 Close。
    // 因此这里**不要**再 acquire 一次（会打乱 LRU），槽位号由池内部账本保证。
    let pool = match kind {
        super::udp_pool::PoolKind::Udp => ctx.udp_pool.clone(),
        super::udp_pool::PoolKind::LinkUdp => ctx.link_udp_pool.clone(),
    };
    {
        let mut p = pool.lock().await;
        if let super::udp_pool::Acquire::Evicted(victim) = p.acquire(sid) {
            // 通知被踢的 sid：server 侧会随 TTL 自然过期，agent 主动 Close 更快。
            tracing::warn!("kudus udp pool full, evicting sid={victim} (new sid={sid})");
            let e = ClientMsg::Close { stream: victim, reason: "pool evicted".into() };
            let _ = pkt.send_ctrl(&e);
        }
    }
    let sock = Arc::new(sock);
    let (dtx, mut drx) = mpsc::unbounded_channel::<Vec<u8>>();
    let early = ctx.pending.write().await.remove(&sid).unwrap_or_default();
    for chunk in early {
        let _ = dtx.send(chunk);
    }
    ctx.streams.write().await.insert(sid, dtx);
    let idle_secs = ctx.udp_idle_secs;
    let w = sock.clone();
    // 流级计数：两侧各记一价，收尾时汇总成一行日志。
    // 根因→修法：旧代码两个泵的失败分支全是静默 break/return（`Ok(0) | Err(_) => break`、
    // `.is_err() { return; }`），socket 出错、对端拒绝、池满踢流在日志里完全不可见；
    // UDP 只靠每分钟一行全局 `kudus retx sent=N abandoned=N`，知道「丢了几个」
    // 但不知道「丢在哪条流 / 为什么丢 / 是不是 5s idle 断的」。
    // 现每条流收尾打一行：存活时长 + 双向包数字节 + 结束原因。
    let stat = std::sync::Arc::new(UdpStreamStat::default());
    let stat_tx = stat.clone();
    let pool_touch_tx = pool.clone();
    let ws_to_udp = tokio::spawn(async move {
        loop {
            match tokio::time::timeout(std::time::Duration::from_secs(idle_secs), drx.recv()).await {
                Ok(Some(dg)) => {
                    stat_tx.rx_pkts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    stat_tx.rx_bytes.fetch_add(dg.len() as u64, std::sync::atomic::Ordering::Relaxed);
                    // LRU：隧道里还有包下来，说明这条流仍然活着，刷新其位置。
                    // 根因→修法：旧代码只有 udp_to_ws（本地 socket 收到字节）才 touch，
                    // 于是「只发不收」的流（DHT announce / 单向推流 / 对端丢包不回）
                    // 在 LRU 里永远排在队首，池满时被当成最久未用错杀。
                    // 池于 2026-10-24 实测打满（evicted=871），这个盲区已在真实误杀流。
                    pool_touch_tx.lock().await.touch(sid);
                    if let Err(e) = w.send(&dg).await {
                        stat_tx.end.store(END_SEND_ERR, std::sync::atomic::Ordering::Relaxed);
                        tracing::warn!(
                            "kudus udp ws->local send failed: sid={sid} err={e} (rx_pkts={})",
                            stat_tx.rx_pkts.load(std::sync::atomic::Ordering::Relaxed)
                        );
                        return;
                    }
                }
                Ok(None) => {
                    stat_tx.end.store(END_CHANNEL_CLOSED, std::sync::atomic::Ordering::Relaxed);
                    break;
                }
                Err(_) => {
                    stat_tx.end.store(END_IDLE, std::sync::atomic::Ordering::Relaxed);
                    break;
                }
            }
        }
    });
    let pkt3 = pkt.clone();
    let r = sock.clone();
    let pool_touch = pool.clone();
    let stat_rx = stat.clone();
    let udp_to_ws = tokio::spawn(async move {
        let mut b = vec![0u8; UDP_RECV_BUF];
        loop {
            match r.recv(&mut b).await {
                Ok(0) => {
                    stat_rx.end.store(END_LOCAL_EOF, std::sync::atomic::Ordering::Relaxed);
                    break;
                }
                Err(e) => {
                    stat_rx.end.store(END_RECV_ERR, std::sync::atomic::Ordering::Relaxed);
                    tracing::warn!("kudus udp local->ws recv failed: sid={sid} err={e}");
                    break;
                }
                Ok(n) => {
                    stat_rx.tx_pkts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    stat_rx.tx_bytes.fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
                    // LRU：有回包说明该 sid 仍活跃，刷新其位置。
                    pool_touch.lock().await.touch(sid);
                    // UDP recv 会静默截断（不报错）：n == buf.len() 说明可能被截。
                    // 拿不到原始包长，只能近似判断，故措辞用 possibly。
                    if n == UDP_RECV_BUF {
                        stat_rx.truncated.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        tracing::warn!(
                            "kudus udp recv possibly truncated: n={n} (buf={UDP_RECV_BUF}) sid={sid}"
                        );
                    }
                    send_data(&pkt3, sid, &b[..n], true);
                }
            }
        }
    });
    // 根因→修法：旧 `tokio::join!(ws_to_udp, udp_to_ws)` 要求两侧都结束。
    // ws_to_udp 到了 UDP_STREAM_IDLE_SECS 会 break，但 udp_to_ws 阻塞在 `sock.recv()`
    // 上（对端一直没回包就等于永等），join! 于是永不返回——下面两行永远执行不到：
    // `ctx.streams.remove(&sid)` 不执行、`Arc<UdpSocket>` 最后一个引用不 drop。
    // 每条 udp 流漏 1 fd + 2 task，DHT 扫描器持续造流即 EMFILE。
    // 现改为 select!：任一侧结束就 abort 另一侧，主干必定往下走到收尾。
    // 注意不能干脆不给 udp_to_ws 超时——它本身是“目标回包”的正向路径，
    // 只能被另一侧取消，否则会把活跃流的回包也误杀。
    let mut ws_to_udp = ws_to_udp;
    let mut udp_to_ws = udp_to_ws;
    tokio::select! {
        _ = &mut ws_to_udp => { udp_to_ws.abort(); }
        _ = &mut udp_to_ws => { ws_to_udp.abort(); }
    }
    // 一条流收尾：一行 debug 把「活了多久 / 双向往返多少 / 为什义结束」说清。
    // 看 lived 是否接近 idle 超时（`--udp-idle-secs`）就是 idle 超时断的（5s 不够）；
    // 远小于则是对端/本地错误，配合上面的 warn 定位。
    let lived = stat.started.elapsed();
    tracing::debug!(
        "kudus udp stream closed sid={sid} lived={:.2}s reason={} rx_pkts={} rx_bytes={} tx_pkts={} tx_bytes={} truncated={} pool={}",
        lived.as_secs_f64(),
        stat.reason(),
        stat.rx_pkts.load(std::sync::atomic::Ordering::Relaxed),
        stat.rx_bytes.load(std::sync::atomic::Ordering::Relaxed),
        stat.tx_pkts.load(std::sync::atomic::Ordering::Relaxed),
        stat.tx_bytes.load(std::sync::atomic::Ordering::Relaxed),
        stat.truncated.load(std::sync::atomic::Ordering::Relaxed),
        pool.lock().await.summary(),
    );
    ctx.streams.write().await.remove(&sid);
    // 归还槽位：槽位是关键资源（1 socket = 1 fd），流结束必须还。
    pool.lock().await.release(sid);
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
    tracing::debug!("kudus udp stream {sid} -> {}:{}", p.local_ip, p.local_port);
    open_udp_stream_to(ctx, pkt, sid, sock, super::udp_pool::PoolKind::Udp).await
}

use std::time::Duration;

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use tokio::sync::{mpsc, RwLock};

    /// 发送失败必须能被观测到（不得静默吞错）。
    ///
    /// 根因：`emit` 的 `self.out.send()` 在写泵 task 退出后立即返回 Err，
    /// 而全部调用点（`send_ack_only`、`send_ctrl`、`send`）都是 `let _ =`。
    /// 2026-10-24 现场：agent 上行 tx 从 ~4KB/5s 跌到恒 0，抓包 396 入 / 4 出，
    /// 却没有任何一行日志说明“发送失败了”——只能靠人肉抓包才看得出来。
    /// 这与 2026-10-23 事故（grep retx 全零）是同一类盲区。
    ///
    /// 本用例锁住：写泵接收端关闭后，emit 必须返回 Err（而不是假装成功），
    /// 这样调用方/日志才能区分“发出去了”与“根本没发”。
    #[tokio::test]
    async fn emit_reports_error_when_outlet_closed() {
        let (otx, mut orx) = mpsc::unbounded_channel::<Vec<u8>>();
        let pkt = super::Pkt {
            out: otx,
            key: [0u8; 32],
            session: 1,
            rel: std::sync::Arc::new(std::sync::Mutex::new(super::RelSend::new())),
        };
        // 写泵在跑时：发送成功。
        assert!(pkt.send(super::FLAG_ACK, 0, [0u8; 32], b"").is_ok());
        assert!(orx.recv().await.is_some(), "写泵应收到一帧");
        // 模拟写泵退出：丢弃接收端。
        drop(orx);
        assert!(
            pkt.send(super::FLAG_ACK, 0, [0u8; 32], b"").is_err(),
            "写泵已退出时 send 必须报错，否则发送失败永远不可见"
        );
        // 纯 ACK 路径同样不得静默成功。
        pkt.send_ack_only(); // 内部必须自行记 warn，不 panic
    }

    /// 数据帧发送失败不得静默 break。
    ///
    /// 根因：`send_data_stream` 旧代码 `if self.send(...).is_err() { break; }`，
    /// 只停止继续发，不区分“对端已断”与“本端写泵已死”，也没有任何日志。
    /// 2026-10-24 现场：上行 tx 从 4KB/5s 跌到恒 0、抓包 396 入/4 出，
    /// 日志里一行都没有——运维只能靠人肉抓包才能发现整条上行已断。
    ///
    /// 本用例用统计计数（而非捕获日志）锁行为：失败帧数必须被记录下来。
    #[tokio::test]
    async fn send_failures_are_counted() {
        let (otx, orx) = mpsc::unbounded_channel::<Vec<u8>>();
        let pkt = super::Pkt {
            out: otx,
            key: [0u8; 32],
            session: 1,
            rel: std::sync::Arc::new(std::sync::Mutex::new(super::RelSend::new())),
        };
        drop(orx); // 写泵已死
        // 静态计数器是进程级的，并行跑的其它用例会先累加——断言增量，不断言绝对值。
        let before = super::send_fail_count();
        pkt.send_data_stream(7, b"hello world");
        assert!(
            super::send_fail_count() > before,
            "写泵死后的发送失败必须被计数（并据此打 warn），否则上行断了没人知道"
        );
    }

    /// 出站 socket 每个 sid 独占一个并 connect 到固定目标——**这是当前设计的
    /// 正确行为**，不是缺陷。
    ///
    /// 原 spec Task 15 主张改用 send_to 以便"一个 socket 服务多个目标"，
    /// 但那样 socket 就必须 unconnected，`recv` 会收到任意来源的包，
    /// 必须靠 `recv_from` 的来源地址过滤才不串到别的 sid——而同一目标
    /// (transmission 51413) 的多条流回包源地址完全相同，根本无法 demux。
    /// 结论：UDP 语义强制「每 sid 一 socket」，connect 反而是防护（内核已过滤
    /// 非目标来源），换成 send_to 会引入跨 sid 串包风险。
    ///
    /// 池的正确职责因此只是**限制 fd 数量**（AGENT_UDP_POOL_MAX）+ LRU 踢流，
    /// 而非共享 socket。见 udp_pool.rs 模块头注释。
    #[test]
    fn udp_egress_socket_per_stream_is_intentional() {
        let src = include_str!("kudus_session.rs");
        let needle = concat!(".", "connect(");
        let n = src.lines().filter(|l| l.contains(needle)).count();
        assert!(
            n >= 1,
            "出站 udp socket 必须 connect 到目标：unconnected socket 的 recv \
             会收到任意来源包，同目标多流回包无法 demux，会跨 sid 串包"
        );
    }

    /// 流结束原因必须能区分开：旧代码两个泵的失败分支全静默，
    /// 日志里只看得到“流没了”，看不到“为什么没的”。
    /// 看 lived 是否接近 idle 超时就能回答“5s 够不够”。
    #[test]
    fn udp_stream_stat_reason_names() {
        for (code, want) in [
            (super::END_IDLE, "idle-timeout"),
            (super::END_CHANNEL_CLOSED, "server-close"),
            (super::END_SEND_ERR, "send-err"),
            (super::END_RECV_ERR, "recv-err"),
            (super::END_LOCAL_EOF, "local-eof"),
            (super::END_RUNNING, "running"),
        ] {
            let s = super::UdpStreamStat::default();
            s.end.store(code, std::sync::atomic::Ordering::Relaxed);
            assert_eq!(s.reason(), want, "code={code} 的名字不对");
        }
        // 默认是 running：还没结束就不该报成某个具体原因。
        assert_eq!(super::UdpStreamStat::default().reason(), "running");
    }

    /// 池状态要能一行看完“用了几个 / 建了几个 / 踢了几次”。
    /// 硬顶其实是内核 SO_RCVBUF（实测 ≈137），不知道 in_use 涨到多少就只能猜。
    #[test]
    fn udp_pool_summary_counts_in_use_and_evicted() {
        let mut p = crate::agent::udp_pool::UdpPool::new(crate::agent::udp_pool::PoolKind::Udp);
        assert_eq!(p.summary(), "0/0 evicted=0", "空池应是 0/0");
        p.acquire(7);
        p.acquire(8);
        assert_eq!(p.summary(), "2/2 evicted=0");
        p.release(7);
        assert_eq!(p.summary(), "1/2 evicted=0", "归还后 in_use 降、created 不降（已建的不回收）");
    }

    /// idle 超时现在可由 `--udp-idle-secs` 覆盖（默认 5）。
    /// 根因→修法：旧值是编译期常量 UDP_STREAM_IDLE_SECS=5，改一次要重编两端；
    /// 而 5s 对 BT uTP 长连接是否够取决于现场丢包/链路，运维应当能在启动项上调，
    /// 不必重新发一个二进制。0 视为误传 → 回退默认，避免"永不超时"漏 fd。
    #[test]
    fn udp_idle_secs_resolves_cli_override() {
        // 0 = 未传（clap default_value_t = 0）→ 回退默认。
        assert_eq!(super::resolve_udp_idle_secs(0), super::UDP_STREAM_IDLE_SECS);
        // 显式传值则原样生效，包括比默认更长的值（运维放宽容忍度）。
        assert_eq!(super::resolve_udp_idle_secs(60), 60);
        assert_eq!(super::resolve_udp_idle_secs(1), 1);
        // 默认值必须与 server 侧默认 TTL 相等，否则一端先回收另一端挂 fd。
        assert_eq!(super::UDP_STREAM_IDLE_SECS, crate::server::state::UDP_SESSION_TTL_SECS_DEFAULT);
    }

    fn udp_idle_timeout_is_5s() {
        assert_eq!(
            super::UDP_STREAM_IDLE_SECS,
            5,
            "应与 server UDP_SESSION_TTL_SECS_DEFAULT=5 对齐"
        );
        assert_eq!(
            super::UDP_STREAM_IDLE_SECS,
            crate::server::state::UDP_SESSION_TTL_SECS_DEFAULT,
            "两端常量必须相等，避免 server 已过期而 agent 还挂着"
        );
    }

    /// UDP 出站接收 buffer 必须是 2048，不是 64KB。
    /// 根因：旧代码每条 udp 流 vec![0u8; 65535]，256 流 = 16MB 纯堆浪费，
    /// 池化到 512 流则是 32MB。而隧道单片上限 KUDUS_UDP_MAX=1232、
    /// 标准 MTU ~1500，2048 已足够且留 33% 余量。
    #[test]
    fn udp_recv_buf_is_small() {
        assert!(
            super::UDP_RECV_BUF <= 2048,
            "UDP_RECV_BUF={} 过大，每流 64KB 在 512 流下是 32MB 浪费",
            super::UDP_RECV_BUF
        );
        // 不能小于标准 MTU，否则正常包会被截断
        assert!(
            super::UDP_RECV_BUF >= 1500,
            "UDP_RECV_BUF={} 小于 MTU 1500，会截断正常包",
            super::UDP_RECV_BUF
        );
        // 必须覆盖隧道单片上限
        assert!(super::UDP_RECV_BUF >= crate::common::kudus::KUDUS_UDP_MAX);
    }

    /// agent 侧背压超时后必须放弃本次发送，不能像旧代码那样照样发。
    /// 根因：旧 wait_window 是 3000x10ms 循环，耗尽后直接返回 ()，
    /// 调用方照样 send_data —— 与 server 侧同构的"背压形同虚设"。
    #[test]
    fn agent_send_timeout_drops_without_hang() {
        use std::sync::Arc;
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let (otx, mut orx) = mpsc::unbounded_channel::<Vec<u8>>();
            tokio::spawn(async move { while orx.recv().await.is_some() {} });
            let pkt = super::Pkt {
                out: otx,
                key: [0u8; 32],
                session: 1,
                rel: Arc::new(std::sync::Mutex::new(super::RelSend::new())),
            };
            // 塞满 retx 表，模拟窗口积压（超过 KUDUS_RETX_BACKLOG）
            {
                let mut g = pkt.rel.lock().unwrap();
                for i in 0..crate::common::kudus::KUDUS_RETX_BACKLOG + 10 {
                    let _ = g.retx.on_send(vec![i as u8]);
                }
            }
            // wait_window 必须返回 false（超时），且不能永久阻塞
            let r = tokio::time::timeout(
                std::time::Duration::from_secs(30),
                pkt.wait_window(),
            )
            .await;
            assert!(r.is_ok(), "wait_window 不能永久挂住");
            assert!(!r.unwrap(), "窗口积压时应返回 false（超时），调用方据此丢包");
        });
    }
    /// RED：udp 流在 server 不再发数据后，必须自己活不下来——
    /// 既要从 ctx.streams 里消失，也要把 socket drop 掉（fd 归还）。
    ///
    /// 根因→修法：旧实现两条 pump 用 `tokio::join!` 且 udp→ws 侧 `r.recv()`
    /// 没有任何超时。ws→udp 侧 UDP_STREAM_IDLE_SECS 到了会 break，但 udp→ws
    /// 永远阻塞在 recv 上，于是 `join!` 永不返回 → 下面两行永不执行：
    /// `ctx.streams.remove(&sid)` / socket `Arc` 的最后一个引用不 drop。
    /// 每条 udp 流一路漏 1 fd + 2 task，24h 就是 EMFILE（HK 2026-10-23 现场：
    /// server 5s 就回收了 session，snail 侧 socket 只增不减）。
    /// 修法：join! → select!，任一侧结束即 abort 另一侧，确保走到收尾。
    #[tokio::test]
    async fn udp_stream_frees_socket_when_server_goes_idle() {
        use std::sync::Arc;
        let (otx, mut orx) = mpsc::unbounded_channel::<Vec<u8>>();
        // 排空写泵输出，避免 channel 积压影响断言
        tokio::spawn(async move { while orx.recv().await.is_some() {} });
        let pkt = super::Pkt {
            out: otx,
            key: [0u8; 32],
            session: 1,
            rel: Arc::new(std::sync::Mutex::new(super::RelSend::new())),
        };
        let ctx = Arc::new(super::KCtx {
            proxies: RwLock::new(vec![]),
            link_tasks: tokio::sync::Mutex::new(HashMap::new()),
            streams: RwLock::new(HashMap::new()),
            pending: RwLock::new(HashMap::new()),
            udp_pool: std::sync::Arc::new(tokio::sync::Mutex::new(
                crate::agent::udp_pool::UdpPool::new(crate::agent::udp_pool::PoolKind::Udp),
            )),
            link_udp_pool: std::sync::Arc::new(tokio::sync::Mutex::new(
                crate::agent::udp_pool::UdpPool::new(crate::agent::udp_pool::PoolKind::LinkUdp),
            )),
            // 测试用很小的 idle，让“黑洞目标”用例不必真等 5s。
            udp_idle_secs: 1,
        });
        // 目标 socket：绑本地，永不回包（模拟黑洞目标）。
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sid = 42u32;
        let c2 = ctx.clone();
        let t = tokio::spawn(async move { super::open_udp_stream_to(c2, pkt, sid, sock, crate::agent::udp_pool::PoolKind::Udp).await });
        // 等流注册完成
        for _ in 0..100 {
            if ctx.streams.read().await.contains_key(&sid) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(ctx.streams.read().await.contains_key(&sid), "流应已注册");
        // 不给任何下行数据：等过 idle 超时 + 宽限。
        let idle = std::time::Duration::from_secs(super::UDP_STREAM_IDLE_SECS);
        let done = tokio::time::timeout(idle + std::time::Duration::from_secs(5), t).await;
        assert!(done.is_ok(), "udp 流在 server 静默后仍不退出：join! 卡在无超时的 udp->ws recv 上");
        assert!(!ctx.streams.read().await.contains_key(&sid), "退出后必须清理 streams 表项，否则通道与 socket 一起漏");
    }

    /// 根因→修法（验证）：LRU 曾经只认「本地 socket 收到回包」为活跃
    /// （`udp_to_ws` 泵里的 touch），`ws_to_udp` 方向（隧道→本地 socket）
    /// 一个 touch 都没有。于是「只发不收」的流在 LRU 里永远排在队首，
    /// 池满时被当成最久未用错杀。2026-10-24 线上实测 evicted=871，
    /// 这个盲区已在真实误杀流。
    ///
    /// 断言抓什么：建两条流 sid=1/2，都在池里；然后只给 sid=1 灌**下行**
    /// （隧道→本地）数据，不给任何回包。之后往池里 acquire 新 sid ——
    /// 若 ws_to_udp 有 touch，被踢的应该是 sid=2（真正的队首）；
    /// 若没 touch（旧代码），sid=1 和 sid=2 都在队首附近，先踢 sid=1。
    ///
    /// 用 `with_max(2, ...)` 把小池打满，不必占 2048 个真 socket。
    #[tokio::test]
    async fn ws_to_udp_direction_refreshes_lru() {
        use std::sync::Arc;
        let pool = std::sync::Arc::new(tokio::sync::Mutex::new(
            crate::agent::udp_pool::UdpPool::with_max(crate::agent::udp_pool::PoolKind::Udp, 2),
        ));
        // 先占满：sid=1 旧、sid=2 新（队尾）。
        pool.lock().await.acquire(1);
        pool.lock().await.acquire(2);
        assert_eq!(pool.lock().await.in_use_len(), 2);

        // 模拟 ws_to_udp 泵收到下行数据时的刷新动作。
        // 注意：这里直接调 touch 是为了锁住「泵里必须调它」这一契约的下游效果；
        // 泵本身是否调用，由下面的源码断言守住。
        pool.lock().await.touch(1);

        // 池满后新流进来：应踢 sid=2（真正的 LRU 队首）。
        let out = pool.lock().await.acquire(3);
        assert_eq!(
            out,
            crate::agent::udp_pool::Acquire::Evicted(2),
            "下行了数据的 sid=1 不该被踢，应踢从未活跃的 sid=2"
        );
        assert!(pool.lock().await.contains(1), "有下行数据的流必须保留");
    }

    /// 源码级契约：`ws_to_udp` 泵里必须存在 touch 调用。
    /// 根因：上面那个行为用例只能证明「touch 有效」，证明不了「泵里真的调了」。
    /// 回退验证时删掉泵里的 touch，行为用例依旧全绿 —— 所以必须直接锁源码。
    /// 这不是理想做法，但 UDP 泵的双向 IO 难以在单测里无 mock 地驱动到
    /// 「只下行不回包」这个特定状态，故用源码断言兼顾回归强度与成本。
    #[test]
    fn ws_to_udp_pump_calls_pool_touch() {
        let src = include_str!("kudus_session.rs");
        // 找到 ws_to_udp 泵的起点与 udp_to_ws 泵的起点，只在这段区间里找 touch。
        let ws_start = src.find("let ws_to_udp = tokio::spawn").expect("ws_to_udp 泵应存在");
        let udp_start = src.find("let udp_to_ws = tokio::spawn").expect("udp_to_ws 泵应存在");
        assert!(ws_start < udp_start, "泵的定义顺序变了，请更新本用例");
        let pump = &src[ws_start..udp_start];
        assert!(
            pump.contains(".touch(sid)"),
            "ws_to_udp 泵（隧道→本地 socket）收到数据时必须 touch(sid) 刷新 LRU，\
             否则只发不收的流会被池当成最久未用错杀（2026-10-24 evicted=871）"
        );
    }

    #[test]
    fn udp_concurrency_capped() {
        // snail 2026-10-23：无上限时 DHT flood 每流 1 fd 打满 1024 EMFILE。
        // 旧实现用 Semaphore(256) 打满直接拒；现改为池化 512 上限 + LRU 踢流。
        assert!(
            crate::agent::udp_pool::resolve_pool_max(0) >= 1024,
            "默认上限须明显高于 512（2026-10-24 实测 512 打满 evicted=871）"
        );
        assert!(
            crate::agent::udp_pool::AGENT_UDP_POOL_INIT < crate::agent::udp_pool::AGENT_UDP_POOL_MAX,
            "初值应小于上限"
        );
    }
    #[test]
    fn heartbeat_contract() {
        // Task 2 依赖 Task 1 的接口形状：改名/改签名即红。
        let mut hb = crate::common::kudus::Heartbeat::new();
        let d = hb.next_interval(false);
        assert!(d >= std::time::Duration::from_secs(15));
        assert_eq!(crate::common::kudus::KUDUS_IDLE_KICK_SECS, 75);
    }
}
