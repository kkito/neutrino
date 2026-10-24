//! kudus 传输：自研 UDP 可靠传输，全随机隐身。
//! 包格式：`[session 4B BE 明文][nonce 24B 随机][XChaCha20-Poly1305 密文+16B tag]`。
//! key = SHA256(token)，两边预共享，无协商、无证书、无 TLS。
//! 明文（解密后）= `[ver 1B|flags 1B|seq 4B BE|ack 4B BE|sack 32B|ts_ms 8B BE][proto_frame]`。
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// v1 重传超时：固定 200ms（设计 RTO=max(200ms,2×SRTT)，SRTT 度量 v2 再做）。
pub const KUDUS_RTO: Duration = Duration::from_millis(200);
/// 重排/重传缓冲上限：防对端疯发撑爆内存（超了丢新包，等重传补）。
pub const KUDUS_WINDOW: usize = 512;

/// 背压阈值：retx 未确认包数达到此值即认为窗口积压，需退让等 ACK。
/// 这是「滞回线」，不是硬上限——正常发送在这里停等一下，与 KUDUS_RETX_CAP 不同。
pub const KUDUS_RETX_BACKLOG: usize = 256;

/// retx 缓冲硬容量上限。根因→修法：旧 RetxBuf 无上限，无 ACK 时无限积压
/// （事故实测 8192 包），叠加固定 200ms 重传使流量自我放大 5~40 倍
/// （ratelimit 实测 thru=22.4MB/s vs limit=512KB/s）。
/// 4096 = KUDUS_WINDOW(512) × 8，洁 1232B/包约 5MB 内存上限。
pub const KUDUS_RETX_CAP: usize = 4096;

/// 单个包最大重传次数，超过即放弃并从表移除。
/// 根因→修法：旧 take_expired 重发时刷新 *sent = now，包永不丢弃（无限复活）。
pub const KUDUS_MAX_RETX: u32 = 10;

/// 快速重传每分钟硬上限（单会话）。
///
/// 根因→修法：2026-10-23 kudus 重传风暴把链路打出 42 倍放大，整机网络瘫痪。
/// 快速重传是 2026-10-24 新增的重传路径——虽然有三重软约束（每轮只补最小洞、
/// 每包只补一次、SACK 全零不冒进），但「对端持续回 SACK 时每轮 ACK 都可能
/// 命中一个新洞」，高丢包 + 高包率下仍可能把重传率推高。
/// 这里加一道**硬闸**：一分钟内快速重传超过此数就整体退回纯 RTO 退避，
/// 保证最坏情况也不会自激。200/分钟 ≈ 3.3 包/秒，远低于 RTO 泵的
/// 20 包/秒（50ms 一拍）节奏，正常链路远够用。
pub const FAST_RETX_PER_MIN: usize = 200;

/// 发送背压最长等待。根因→修法：旧 30s（3000×10ms）已证明过宽，
/// 事故中持续近 2 小时；5s 足够正常抖动（窗口 512 包排空远小于 5s）。
pub const KUDUS_BACKPRESSURE_TIMEOUT: Duration = Duration::from_secs(5);

/// 背压轮询间隔。抽出来供 server/agent 三处共用，消除硬编码 10ms。
pub const BACKPRESSURE_POLL: Duration = Duration::from_millis(10);

/// 重传退避上限。200ms 起指数翻倍，最长到 8s 封顶。
pub const KUDUS_RTO_MAX: Duration = Duration::from_secs(8);

/// kudus 看门狗阈值：75s 无任何帧即判死（server/agent 双端共用）。
/// 根因→修法：WSS 的 45s 按"3×15s server Ping"算；kudus agent 上行最坏 30s 一包，
/// 45s 只容忍丢 1 包，75s 容忍连丢 2 包不误踢。WSS 的 IDLE_KICK_SECS 不动。
pub const KUDUS_IDLE_KICK_SECS: i64 = 75;

/// 心跳间隔状态机：慢档 15~30s 随机（防多 agent 对齐惊群 + NAT 保活），
/// 丢包进快档 5~8s 随机，回慢档需连续 3 周期无丢包（迟滞防翻转）。
/// 纯计算 + 计数器，可单测；`lossy` 由调用方传 `retx 非空`。
pub struct Heartbeat {
    fast: bool,
    calm_hit: u8,
}

impl Heartbeat {
    pub fn new() -> Self {
        Self { fast: false, calm_hit: 0 }
    }
    pub fn is_fast(&self) -> bool {
        self.fast
    }
    pub fn next_interval(&mut self, lossy: bool) -> Duration {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        if lossy {
            self.fast = true;
            self.calm_hit = 0;
            Duration::from_secs(rng.gen_range(5..=8))
        } else if self.fast {
            self.calm_hit += 1;
            if self.calm_hit >= 3 {
                self.fast = false;
                self.calm_hit = 0;
                Duration::from_secs(rng.gen_range(15..=30))
            } else {
                Duration::from_secs(rng.gen_range(5..=8))
            }
        } else {
            Duration::from_secs(rng.gen_range(15..=30))
        }
    }
}

/// 看门狗喂食判定：只有 DATA 帧算活（含控制面分片，同样 FLAG_DATA 帧）。
/// 纯 ACK（泄漏重传泵的探活包）/FIN/SYN 一律不算——否则 server 踢掉会话后，
/// 对端靠 50ms 纯 ACK 把 75s 看门狗无限复位，session 永不 bail（2026-10-23 现场）。
pub fn frame_feeds_watchdog(flags: u8) -> bool {
    flags & FLAG_DATA != 0
}

/// 看门狗剩余预算（纯函数）。
///
/// 根因→修法（2026-10-25）：旧代码把 `timeout(75s, recv())` 写在循环体内，
/// 纯 ACK 走 `continue` 后**重建 timeout，把计时器重置掉**。server 重传泵
/// 每 50ms 发一个纯 ACK ⇒ 永远到不了 75s ⇒ 会话永不 bail。
/// 改为「循环外存最后一个活帧时刻，每轮算剩余预算」。
///
/// `last_alive_elapsed_ms` 是距最后一个 DATA/FIN 帧的毫秒数。
/// 返回 `None` 表示已超时（调用方应 bail）。
pub fn watchdog_budget_ms(last_alive_elapsed_ms: u64) -> Option<u64> {
    let kick = KUDUS_IDLE_KICK_SECS as u64 * 1000;
    if last_alive_elapsed_ms >= kick {
        None
    } else {
        Some(kick - last_alive_elapsed_ms)
    }
}

/// 纯判定：now-last_seen 超 75s 即僵尸（kudus 版；WSS 用 state::is_idle_stale 45s，不动）。
pub fn kudus_idle_stale(last_seen_unix: i64, now_unix: i64) -> bool {
    now_unix - last_seen_unix > KUDUS_IDLE_KICK_SECS
}

/// 接收重排缓冲：按 seq 有序投递，洞后包缓存等待补洞。
/// 根因→修法：v1 到包即投，跨机丢包即永久少一块（avatar/blob 截断），必须缓存等补齐。
pub struct ReorderBuf {
    next: u32,
    buf: HashMap<u32, Vec<u8>>,
}

impl ReorderBuf {
    pub fn new(next: u32) -> Self {
        Self { next, buf: HashMap::new() }
    }
    /// 到包：返回可按序投递的 payload。重复/过旧/超窗返回空。
    pub fn push(&mut self, seq: u32, payload: Vec<u8>) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        // 过旧/重复：已投过（next 之前）或已缓存
        if seq.wrapping_sub(self.next) >= 0x8000_0000 || self.buf.contains_key(&seq) {
            return out;
        }
        // 根因→修法（2026-10-24 会话死锁）：旧代码先查 `buf.len() >= KUDUS_WINDOW`
        // 再插入，**连 `seq == next` 的包也被挡住**。一旦某个包彻底丢失
        // （重传达 KUDUS_MAX_RETX 被发送方 abandoned），后续包把 buf 填到 512，
        // 此时**连补上那个洞的包都收不进来**，`next` 永卡 ⇒ `ack()` 不动 ⇒
        // 发送方继续重传→接收方窗口恒满⇒双向死锁，只能重连。
        // 现场：本机→HK 链路 15-20% 丢包，egress 代理跑一阵就全超时，
        // server 日志 `tx=0B`、`sent=3950`（重传泵空转），agent 侧
        // `backlog_max=16` 看着很健康——两边指标都正常却完全不通。
        //
        // 修法：`seq == next` 是唯一能推进窗口的包，**不受窗口上限约束**——
        // 先消费它（以及因此连带的已缓存后续包），再看是否超窗。
        if seq == self.next {
            out.push(payload);
            self.next = self.next.wrapping_add(1);
            while let Some(p) = self.buf.remove(&self.next) {
                out.push(p);
                self.next = self.next.wrapping_add(1);
            }
            return out;
        }
        if self.buf.len() >= KUDUS_WINDOW {
            return out; // 超窗丢新包（对端重传会补）
        }
        self.buf.insert(seq, payload);
        while let Some(p) = self.buf.remove(&self.next) {
            out.push(p);
            self.next = self.next.wrapping_add(1);
        }
        out
    }
    /// 最高连续已收 seq（ACK 累积基）。
    pub fn ack(&self) -> u32 {
        self.next.wrapping_sub(1)
    }
    /// 已缓存乱序包的 SACK bitmap（基为 ack()）。
    pub fn sack(&self) -> [u8; 32] {
        let mut s = [0u8; 32];
        let base = self.ack();
        for k in self.buf.keys() {
            sack_mark(&mut s, base, *k);
        }
        s
    }
}

/// 重传埋点（spec §15.3）。取走即归零，tick 汇总打增量。
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RetxStats {
    /// take_expired 实际重发的包数
    pub sent: u64,
    /// 重传超上限被真丢弃的包数
    pub abandoned: u64,
    /// RetxFull 拒收次数
    pub full: u64,
    /// 本窗口内未确认包峰值
    pub backlog_max: usize,
}

/// 第 `retx` 次重传应等待的 RTO（指数退避，KUDUS_RTO_MAX 封顶）。
/// 根因→修法：旧实现固定 KUDUS_RTO=200ms 线性重传，每秒 5 次，
/// 积压包越多放大越猛（256 包 ≈1.22MB/s，8192 包 ≈39MB/s）。退避后
/// 单包 10 次重传总耗时 ≈ 200+400+...+6400 ≈ 25s，期间速率被压住。
pub fn rto_for(retx: u32) -> Duration {
    // 1u32 << 6 = 64 → 200ms × 64 = 12.8s，被 min(RTO_MAX) 截到 8s。
    // retx > 6 时移位数封顶，避免 u32 左移溢出（debug 下会 panic）。
    let shift = retx.min(6);
    KUDUS_RTO
        .saturating_mul(1u32 << shift)
        .min(KUDUS_RTO_MAX)
}

/// RetxBuf 已满（达到 KUDUS_RETX_CAP）。调用方据此丢弃新包。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetxFull;

/// 单个待确认包：载荷 + 最后发送时间 + 已重传次数。
struct RetxEntry {
    payload: Vec<u8>,
    last_sent: u64,
    retx: u32,
}

/// 发送重传缓冲：on_send 记 seq→entry；on_ack 按累积+SACK 清；
/// take_expired 吐超时未确认包。
/// 根因→修法：旧实现 seqs 无容量上限，无 ACK 时无限积压（事故实测 8192 包），
/// 叠加固定 200ms 重发使流量自我放大到 39MB/s。现加硬上限 KUDUS_RETX_CAP，
/// 满了返回 Err 让调用方决定丢弃（UDP 语义允许丢）。
pub struct RetxBuf {
    next: u32,
    seqs: HashMap<u32, RetxEntry>,
    cap: usize,
    /// 重传埋点（spec §15.3），take_stats 取走即归零。
    stats: RetxStats,
    /// 快速重传限流窗口（见 FAST_RETX_PER_MIN）。
    fast_win_start: u64,
    fast_win_count: usize,
}

impl RetxBuf {
    pub fn new(start: u32) -> Self {
        Self {
            next: start,
            seqs: HashMap::new(),
            cap: KUDUS_RETX_CAP,
            stats: RetxStats::default(),
            fast_win_start: now_ms(),
            fast_win_count: 0,
        }
    }
    /// 取走本窗口统计并归零（spec §15.3）。
    /// 峰值由 on_send 维护，这里只取走与重置。
    pub fn take_stats(&mut self) -> RetxStats {
        std::mem::take(&mut self.stats)
    }
    /// 登记一次发送，返回分配的 seq；超出容量上限返回 Err（不插入）。
    pub fn on_send(&mut self, payload: Vec<u8>) -> Result<u32, RetxFull> {
        if self.seqs.len() >= self.cap {
            self.stats.full += 1; // spec §15.3
            return Err(RetxFull);
        }
        let s = self.next;
        self.next = self.next.wrapping_add(1);
        self.seqs.insert(
            s,
            RetxEntry { payload, last_sent: now_ms(), retx: 0 },
        );
        // spec §15.3：峰值唯一来源——只在插入后更新，on_ack 不抹平。
        if self.seqs.len() > self.stats.backlog_max {
            self.stats.backlog_max = self.seqs.len();
        }
        Ok(s)
    }
    /// 快速重传限流闸：滚动 60s 窗口内是否还有额度。
    ///
    /// 返回 false 表示本轮不许快速重传——调用方退回 RTO 退避路径。
    /// 窗口用 `now_ms()` 单调推进，跨窗口自动重置；时钟回拨用
    /// `saturating_sub` 保底（不会因回拨把窗口卡死）。
    fn fast_retx_budget(&mut self, now: u64) -> bool {
        if now.saturating_sub(self.fast_win_start) >= 60_000 {
            self.fast_win_start = now;
            self.fast_win_count = 0;
        }
        self.fast_win_count < FAST_RETX_PER_MIN
    }
    /// 对端 ACK：清累积确认（<=ack）+ SACK 洞外已到包，并返回**应立刻重传的洞**。
    ///
    /// 根因→修法：旧实现只清表、返回 `()`，重传时机**完全由 RTO 超时决定**
    /// （`take_expired` 只看 `last_sent`，不看 SACK）。于是对端 SACK 清楚告诉
    /// “后面的包都到了、前面有个洞”，发送方却只能白等 200ms，且重传再丢还要
    /// 指数退避翻倍。2026-10-24 现场：本机→HK 链路 15-20% 随机丢包，
    /// 1MB 下载永久卡死，而同期 TCP（有 3-dup-ACK 快速重传）仍有 28KB/s。
    ///
    /// 为什么不用数「3 个重复 ACK」：kudus 接收方每次重排推进都立即回带 SACK 的
    /// ACK，所以**一份 SACK bitmap 就等价于 TCP 的 duplicate-ACK 信号**，
    /// 不必另建状态机，也不会因纯 ACK 包丢失而误判。
    ///
    /// 只返回**最小那一个洞**（TCP 语义）：一次补一个，避免 15% 丢包下
    /// 把整窗所有洞同时重发造成流量放大（对比 2026-10-23 重传风暴事故）。
    pub fn on_ack(&mut self, ack: u32, sack: &[u8; 32]) -> Vec<(u32, Vec<u8>)> {
        self.seqs.retain(|&seq, _| {
            if seq == ack || ack.wrapping_sub(seq) < 0x8000_0000 {
                return false; // 累积确认覆盖
            }
            let d = seq.wrapping_sub(ack);
            if d >= 1 && d <= KUDUS_SACK_BITS as u32 {
                let i = (d - 1) as usize;
                if sack[i / 8] & (1 << (i % 8)) != 0 {
                    return false; // SACK 已到
                }
            }
            true
        });
        // 快速重传：SACK 窗口内「有包已到」且存在更小的洞 ⇒ 立刻补最小洞。
        // 若 SACK 全零（对端什么都没乱序收到），无从判断是丢包还是全没到，
        // 不冒进——交给 RTO。
        let sack_base = ack;
        let mut highest_sacked: Option<u32> = None;
        for d in 1..=KUDUS_SACK_BITS as u32 {
            let i = (d - 1) as usize;
            if sack[i / 8] & (1 << (i % 8)) != 0 {
                highest_sacked = Some(d);
            }
        }
        let Some(highest) = highest_sacked else {
            return Vec::new();
        };
        // 硬闸（先算，避免在 seqs 借用内再借 &mut self）：
        // 一分钟窗内快速重传超 FAST_RETX_PER_MIN 就整体退回 RTO 退避。
        let has_budget = self.fast_retx_budget(now_ms());
        if !has_budget {
            return Vec::new();
        }
        // 找 [1, highest) 中第一个仍在 seqs 里（即未被 SACK、未被累积确认）的洞。
        // 注意上界是 `highest + 1`：`highest` 是最高 SACK 位的偏移，本身也是洞候选
        // （它没被标记却在 seqs 里 ⇒ 说明是洞）。旧代码 `1..highest` 把它排除在外，
        // 导致「最后一个洞」永远补不上。
        for d in 1..=highest {
            let seq = sack_base.wrapping_add(d);
            if let Some(e) = self.seqs.get_mut(&seq) {
                // 只补「真正丢了的」：上面 retain 已把 SACK 到过的移除，能走到这里
                // 就说明它确属洞。限制：同一包不因连续 ACK 反复快速重传。
                if e.retx == 0 {
                    e.retx = 1;
                    e.last_sent = now_ms();
                    self.stats.sent += 1;
                    self.fast_win_count += 1;
                    return vec![(seq, e.payload.clone())];
                }
                // 已快速重传过（retx>0）则交给 RTO 退避，不在本轮再补，
                // 否则对端持续回同一份 SACK 会让我们每收一帧就重发一次。
                //
                // 根因→修法（2026-10-24）：旧代码这里 `return Vec::new()` 直接
                // 退出整个查找，于是**一个还在退避中的洞会永久挡住后面所有新洞**
                // 的快速重传——实测 hole=1 补过后，hole=2..N 全被挡住，
                // 快速重传形同虚设。改为继续往后找下一个可补的洞。
                continue;
            }
        }
        Vec::new()
    }
    /// 取出超时未确认包，按 seq 排序。
    ///
    /// 退避：按每包自身 `retx` 算出的 RTO 判断到期（`_rto` 参数保留仅为
    /// 签名兼容两个调用方，实际 RTO 由 `rto_for(e.retx)` 决定）。
    /// 命中即 `retx += 1` 并刷新 `last_sent`——下次到期自然延后一倍。
    /// 超过 `KUDUS_MAX_RETX` 次的包**放弃并移除**，计入 `stats.abandoned`。
    pub fn take_expired(&mut self, _rto: Duration, now: u64) -> Vec<(u32, Vec<u8>)> {
        // 先清理：重传次数已用尽的直接丢弃（不再发），计入 abandoned 埋点。
        // 根因→修法：旧实现无「放弃」概念，未 ACK 的包无限复活，
        // 既是内存泄漏（表只增不减）也是持续流量放大。
        let mut give_up = 0u64;
        self.seqs.retain(|_, e| {
            if e.retx >= KUDUS_MAX_RETX {
                give_up += 1;
                false
            } else {
                true
            }
        });
        self.stats.abandoned += give_up;

        let mut due: Vec<(u32, Vec<u8>)> = Vec::new();
        for (seq, e) in self.seqs.iter_mut() {
            if now.wrapping_sub(e.last_sent) >= rto_for(e.retx).as_millis() as u64 {
                e.retx += 1;
                e.last_sent = now;
                self.stats.sent += 1; // spec §15.3：每重发一包 +1
                due.push((*seq, e.payload.clone()));
            }
        }
        due.sort_by_key(|(s, _)| *s);
        due
    }
    pub fn is_empty(&self) -> bool {
        self.seqs.is_empty()
    }
    pub fn len(&self) -> usize {
        self.seqs.len()
    }
}

/// 单个 UDP datagram 载荷上限（防 IP 分片）。
/// server 下行单流切片上限：proto_frame 预算 ≈1140B（见 KUDUS_MAX_UDP）。
/// UDP 上行由 [`Pkt::send_udp`] 另行限长，此处只管 TCP/HTTP/egress/link 字节流。
pub const KUDUS_DATA_CHUNK: usize = 1000;
/// 单 datagram 上限：以太网 MTU 内，避免 IP 分片（分片=特征+丢包放大）。
pub const KUDUS_MAX_UDP: usize = 1232;
/// SACK bitmap 位数（乱序窗口）。
pub const KUDUS_SACK_BITS: usize = 256;

/// 控制面分片专用流 id：decode_data 首 4B 命中即走 CtrlReasm，不进数据投递。
/// 取 u32::MAX——server 偶数 sid / agent 奇数 sid 永远撞不上。
/// 根因→修法：Config/Register 一消息一帧，代理多时 3320B 级 JSON 超
/// KUDUS_MAX_UDP 被 send_pkt 整包丢（warn 后 break，写泵直接退出）。
/// 现控制 JSON 按 KUDUS_CTRL_CHUNK 切片，每片独立 DATA 帧独立 seq（走可靠重传），
/// 接收侧按 (total,offset) 重组后整条解析。分片头 8B：[total u32 BE][offset u32 BE]。
pub const KUDUS_CTRL_SID: u32 = u32::MAX;
/// 控制分片载荷上限：50(hdr)+4(sid)+8(分片头)+1000=1062B plain，
/// 线上 4+24+1062+16=1106B < 1232 上限（与 KUDUS_DATA_CHUNK=1000 对齐）。
pub const KUDUS_CTRL_CHUNK: usize = 1000;
/// 控制分片头长度：[total 4B][offset 4B]。
pub const KUDUS_CTRL_FRAG_HDR: usize = 8;

/// 控制 JSON 切片：每片 = encode_data(CTRL_SID, [total][offset][bytes])。
/// 小消息也走此道（单片 total==len），收发对称、免双路径。
pub fn split_ctrl_frame(json: &[u8]) -> Vec<Vec<u8>> {
    let total = json.len() as u32;
    let mut out = Vec::new();
    let mut off = 0usize;
    loop {
        let end = (off + KUDUS_CTRL_CHUNK).min(json.len());
        let mut frag = Vec::with_capacity(KUDUS_CTRL_FRAG_HDR + (end - off));
        frag.extend_from_slice(&total.to_be_bytes());
        frag.extend_from_slice(&(off as u32).to_be_bytes());
        frag.extend_from_slice(&json[off..end]);
        out.push(crate::common::proto::encode_data(KUDUS_CTRL_SID, &frag));
        if end >= json.len() {
            break;
        }
        off = end;
    }
    out
}

/// 控制分片重组器（单消息槽）：发送侧一消息各片连续 seq 发出，
/// 可靠重排后按序到达；乱序/重发靠 offset 去重，total 变化即旧槽作废。
pub struct CtrlReasm {
    total: Option<u32>,
    parts: HashMap<u32, Vec<u8>>,
    len: usize,
}

impl CtrlReasm {
    pub fn new() -> Self {
        Self { total: None, parts: HashMap::new(), len: 0 }
    }
    /// 喂一片 decode_data 拆出的负载（已确认为 CTRL_SID）：
    /// 集齐即返回整条 JSON，否则 None。坏片（<8B/越界）忽略。
    pub fn feed(&mut self, frag: &[u8]) -> Option<Vec<u8>> {
        if frag.len() < KUDUS_CTRL_FRAG_HDR {
            return None;
        }
        let total = u32::from_be_bytes([frag[0], frag[1], frag[2], frag[3]]);
        let off = u32::from_be_bytes([frag[4], frag[5], frag[6], frag[7]]);
        let data = &frag[KUDUS_CTRL_FRAG_HDR..];
        if off.checked_add(data.len() as u32).unwrap_or(u32::MAX) > total {
            return None;
        }
        if self.total != Some(total) {
            self.total = Some(total);
            self.parts.clear();
            self.len = 0;
        }
        if total == 0 {
            self.total = None;
            return Some(Vec::new());
        }
        if self.parts.contains_key(&off) {
            if self.len >= total as usize {
                return Some(self.assemble(total));
            }
            return None; // 重发片：已记过，不重复计
        }
        self.len += data.len();
        self.parts.insert(off, data.to_vec());
        if self.len >= total as usize {
            let msg = self.assemble(total);
            self.total = None;
            self.parts.clear();
            self.len = 0;
            return Some(msg);
        }
        None
    }
    fn assemble(&self, total: u32) -> Vec<u8> {
        let mut offs: Vec<u32> = self.parts.keys().cloned().collect();
        offs.sort_unstable();
        let mut msg = Vec::with_capacity(total as usize);
        for o in offs {
            msg.extend_from_slice(&self.parts[&o]);
        }
        msg.truncate(total as usize);
        msg
    }
}

pub const FLAG_SYN: u8 = 0x01;
pub const FLAG_ACK: u8 = 0x02;
pub const FLAG_FIN: u8 = 0x04;
pub const FLAG_DATA: u8 = 0x08;

/// UDP 下行包边界标记 sid：与 KUDUS_CTRL_SID 同理，取 u32::MAX-1，
/// server 偶数 / agent 奇数 sid 永远撞不上。
/// 根因→修法：outbox (sid,payload) 不分 TCP/UDP，写泵一律按 1000B 切片逐片
/// deliver——公网 1 个 1500B UDP 包到内网变 2 个包，无声 corrupt。
/// UDP 整包走分片+重组（见 split_udp_dgram / UdpReasm）：传输层切、交付层拼，
/// 攒齐才向上交付一次，包边界不变。
pub const KUDUS_UDP_SID: u32 = u32::MAX - 1;
/// UDP 分片载荷上限：与 KUDUS_CTRL_CHUNK 对齐（wire 1106B < 1232）。
pub const KUDUS_UDP_CHUNK: usize = 1000;
/// UDP 分片头长度：[total 4B][offset 4B]，与控制分片同形。
pub const KUDUS_UDP_FRAG_HDR: usize = 8;
/// UDP 整包直发上限：wire 预算内最大整包（50 hdr + 4 sid + 2 dgram 头 + 1132）。
/// ≤此值一律整包一帧（与旧 send_udp 语义一致）；超了走分片（见 send_udp/
/// server 写泵），8KB 以上才丢 + warn（防 64KB 包切 64 片的重传放大）。
pub const KUDUS_UDP_MAX: usize = 1132;
/// UDP 分片总长上限：8KB（8 片）。
pub const KUDUS_UDP_FRAG_MAX: usize = 8192;

/// UDP 整包切片：每片 = encode_data(UDP_SID, [sid 4B][total 4B][offset 4B][bytes])。
/// 流 id 必须跟片走（outbox 只给 (sid,payload)，写泵侧无他处可放 sid）。
pub fn split_udp_dgram(sid: u32, dg: &[u8]) -> Vec<Vec<u8>> {
    let total = dg.len() as u32;
    let mut out = Vec::new();
    let mut off = 0usize;
    loop {
        let end = (off + KUDUS_UDP_CHUNK).min(dg.len());
        let mut frag = Vec::with_capacity(4 + KUDUS_UDP_FRAG_HDR + (end - off));
        frag.extend_from_slice(&sid.to_be_bytes());
        frag.extend_from_slice(&total.to_be_bytes());
        frag.extend_from_slice(&(off as u32).to_be_bytes());
        frag.extend_from_slice(&dg[off..end]);
        out.push(crate::common::proto::encode_data(KUDUS_UDP_SID, &frag));
        if end >= dg.len() {
            break;
        }
        off = end;
    }
    out
}

/// UDP 分片重组器：按 sid 分槽（同流背靠背包互不踩，弥补 CtrlReasm 单槽短板）。
pub struct UdpReasm {
    slots: HashMap<u32, CtrlReasm>,
}

impl UdpReasm {
    pub fn new() -> Self {
        Self { slots: HashMap::new() }
    }
    /// 喂一片 UDP_SID 负载（已 strip 外层 sid）：返回 (流sid, 整包)（集齐时）。
    /// 坏片（<12B/越界/空 total/超 8KB）忽略。槽上限 1024，超了清最旧一批防内存涨。
    pub fn feed(&mut self, frag: &[u8]) -> Option<(u32, Vec<u8>)> {
        if frag.len() >= 8 {
            let total = u32::from_be_bytes([frag[4], frag[5], frag[6], frag[7]]);
            if total > KUDUS_UDP_FRAG_MAX as u32 {
                return None;
            }
        }
        if frag.len() < 4 + KUDUS_UDP_FRAG_HDR {
            return None;
        }
        let sid = u32::from_be_bytes([frag[0], frag[1], frag[2], frag[3]]);
        if self.slots.len() >= 1024 && !self.slots.contains_key(&sid) {
            self.slots.clear();
        }
        let msg = self.slots.entry(sid).or_insert_with(CtrlReasm::new).feed(&frag[4..])?;
        self.slots.remove(&sid);
        Some((sid, msg))
    }
}

/// 定长包头（密文内）：1+1+4+4+32+8 = 50B。
pub const HDR_LEN: usize = 50;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KudusHdr {
    pub ver: u8,
    pub flags: u8,
    pub seq: u32,
    pub ack: u32,
    pub sack: [u8; 32],
    pub ts_ms: u64,
}

pub fn encode_hdr(h: &KudusHdr) -> [u8; HDR_LEN] {
    let mut b = [0u8; HDR_LEN];
    b[0] = h.ver;
    b[1] = h.flags;
    b[2..6].copy_from_slice(&h.seq.to_be_bytes());
    b[6..10].copy_from_slice(&h.ack.to_be_bytes());
    b[10..42].copy_from_slice(&h.sack);
    b[42..50].copy_from_slice(&h.ts_ms.to_be_bytes());
    b
}

pub fn decode_hdr(b: &[u8]) -> Option<(KudusHdr, &[u8])> {
    if b.len() < HDR_LEN {
        return None;
    }
    let mut sack = [0u8; 32];
    sack.copy_from_slice(&b[10..42]);
    let h = KudusHdr {
        ver: b[0],
        flags: b[1],
        seq: u32::from_be_bytes([b[2], b[3], b[4], b[5]]),
        ack: u32::from_be_bytes([b[6], b[7], b[8], b[9]]),
        sack,
        ts_ms: u64::from_be_bytes([
            b[42], b[43], b[44], b[45], b[46], b[47], b[48], b[49],
        ]),
    };
    Some((h, &b[HDR_LEN..]))
}

/// key = SHA256(token)：两边事先约定，包里不传任何密钥材料。
pub fn derive_key(token: &str) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(token.as_bytes()).into()
}

pub fn seal(key: &[u8; 32], nonce24: &[u8; 24], plain: &[u8]) -> Vec<u8> {
    use chacha20poly1305::{AeadInPlace, Key, KeyInit, XChaCha20Poly1305};
    use chacha20poly1305::aead::generic_array::GenericArray;
    let c = XChaCha20Poly1305::new(Key::from_slice(key));
    let mut buf = plain.to_vec();
    c.encrypt_in_place(GenericArray::from_slice(nonce24), b"", &mut buf)
        .expect("xchacha seal");
    buf
}

/// tag 失败返回 None：调用方静默丢包（黑洞），不回包、不记 warn。
pub fn open(key: &[u8; 32], nonce24: &[u8; 24], cipher_tag: &[u8]) -> Option<Vec<u8>> {
    use chacha20poly1305::{AeadInPlace, Key, KeyInit, XChaCha20Poly1305};
    use chacha20poly1305::aead::generic_array::GenericArray;
    let c = XChaCha20Poly1305::new(Key::from_slice(key));
    let mut buf = cipher_tag.to_vec();
    c.decrypt_in_place(GenericArray::from_slice(nonce24), b"", &mut buf)
        .ok()?;
    Some(buf)
}

/// `[session 4B BE][nonce 24B][cipher...]`。调用方先 seal 得到 cipher。
pub fn encode_packet(session: u32, nonce24: &[u8; 24], cipher: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + 24 + cipher.len());
    v.extend_from_slice(&session.to_be_bytes());
    v.extend_from_slice(nonce24);
    v.extend_from_slice(cipher);
    v
}

/// 最小 28B，否则 None（短包直接丢）。
pub fn decode_packet(buf: &[u8]) -> Option<(u32, &[u8; 24], &[u8])> {
    if buf.len() < 28 {
        return None;
    }
    let session = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let nonce: &[u8; 24] = buf[4..28].try_into().ok()?;
    Some((session, nonce, &buf[28..]))
}

/// SACK：在以 base_ack 为基的 256 位 bitmap 里标 seq 已到（bit i = base_ack+1+i）。
pub fn sack_mark(sack: &mut [u8; 32], base_ack: u32, seq: u32) {
    let d = seq.wrapping_sub(base_ack);
    if d == 0 || d > KUDUS_SACK_BITS as u32 {
        return;
    }
    let i = (d - 1) as usize;
    sack[i / 8] |= 1 << (i % 8);
}

/// 上下行 seq 域隔离：server 下行 seq 从此起跳，agent 上行帧（Open/Close/Register/Ping）
/// 永远落不到下行重排窗口里。根因→修法：此前两端各从 1 自增，agent 读泵以 server
/// 下行首包为 next，上行控制帧 seq 恰好命中下行窗口被当重排序丢弃，Open 永不到。
pub const KUDUS_SEQ_GAP: u32 = 1 << 30;
/// SACK 查洞：base_ack+1..base_ack+window 内未置位的 seq 列表（需重传）。
pub fn sack_missing(sack: &[u8; 32], base_ack: u32, window: u32) -> Vec<u32> {
    let mut out = Vec::new();
    let n = window.min(KUDUS_SACK_BITS as u32);
    for i in 0..n {
        if sack[(i / 8) as usize] & (1 << (i % 8)) == 0 {
            out.push(base_ack + 1 + i);
        }
    }
    out
}

pub fn fresh_nonce() -> [u8; 24] {
    use rand::RngCore;
    let mut n = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut n);
    n
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {

#[test]
fn reorder_window_deadlocks_on_permanent_hole() {
    // 现场：15% 丢包下某个包 10 次重传全丢 → 发送方 abandoned 放弃。
    // 接收方 buf 充满 KUDUS_WINDOW 个乱序包后再也收不进新包，
    // next 永远卡在洞上 ⇒ ack() 不动 ⇒ 双向死锁，只能重连。
    let mut rb = ReorderBuf::new(1);
    // seq=1 永久丢失，2..=1+KUDUS_WINDOW 全到
    for s in 2..=(super::KUDUS_WINDOW as u32 + 1) {
        let out = rb.push(s, vec![s as u8]);
        assert!(out.is_empty(), "洞未补时不应投递");
    }
    // 窗口已满：再来新包全部被静默丢弃
    let deep = rb.push(super::KUDUS_WINDOW as u32 + 2, vec![9]);
    assert!(deep.is_empty());
    // ack 永远停在 0（洞在 1）
    assert_eq!(rb.ack(), 0, "ack 卡死在洞前");
    // 即使丢的那个包后来到了，窗口满时 buf.len()>=WINDOW 分支也不收——
    // 但 seq==next 会被 while 循环消费… 验证洞到货能否解锁
    let recovered = rb.push(1, vec![1]);
    assert!(!recovered.is_empty(), "洞补上后应能投递一大批");
}

    /// RED: 快速重传——SACK 显示"后面的包到了、但前面的洞没到"时，必须立刻补洞，
    /// 不等 RTO 超时。
    ///
    /// 现场根因（docs/incidents/2026-10-24-lossy-link-sack-gap.md）：
    /// 本机→HK 链路 15-20% 随机丢包，`take_expired` 只看"距上次发送过了多久"，
    /// 完全不看对端 SACK 说了什么。于是每个洞都要白等 200ms RTO，叠加指数退避，
    /// 1MB 下载（~1000 包 × 15% ≈ 150 个洞）理论上要 30s+ 且实际永久卡死；
    /// 同期 TCP（有 3-dup-ACK 快速重传）实测仍能跑 28KB/s。
    ///
    /// 本用例：发 seq 1..5，对端 SACK 只标了 3,4,5（说明 1,2 丢了）。
    /// 旧代码 on_ack 返回 ()，什么也不补——只能等 RTO。
    /// 新代码必须当场返回洞里的包（seq 1，最小的那个）。
    /// RED: 快速重传必须有独立速率上限，防 2026-10-23 式自激风暴。
    ///
    /// 现场依据：docs/incidents/2026-10-23-kudus-retx-storm.md（42 倍放大）。
    ///
    /// 为什么直接测闸而不是构造 200 次重传：SACK 窗只有 256 位且 ack 基不动时
    /// 窗外的洞不进 SACK，实际能触发的快速重传被窗宽限制在 ~128 次，
    /// 构造不出自然超限的场景（实测 TOTAL=128 < CAP=200）。
    /// 闸本身是纯判定逻辑，直接单测才可靠。
    #[test]
    fn fast_retx_budget_limits_per_minute() {
        let mut r = RetxBuf::new(1);
        let t0 = super::now_ms();
        r.fast_win_start = t0;
        r.fast_win_count = 0;
        // 窗口内前 CAP 次放行
        for i in 0..super::FAST_RETX_PER_MIN {
            assert!(r.fast_retx_budget(t0 + i as u64), "第 {i} 次应放行");
            r.fast_win_count += 1;
        }
        // 第 CAP+1 次必须拒绝
        assert!(!r.fast_retx_budget(t0 + 100), "超上限必须拒绝，否则会自激放大");
        // 过 60s 后窗口重置，重新放行
        assert!(r.fast_retx_budget(t0 + 60_001), "跨窗口应重置");
        assert_eq!(r.fast_win_count, 0, "重置后计数归零");
    }

    /// 闸必须真的接在 on_ack 上：额度耗尽后 on_ack 不得再返回洞。
    #[test]
    fn on_ack_respects_fast_retx_budget() {
        let mut r = RetxBuf::new(1);
        r.fast_win_start = super::now_ms(); // 用真实时间，避免被判定跨窗口
        r.fast_win_count = super::FAST_RETX_PER_MIN; // 额度已耗尽
        let _s1 = r.on_send(vec![0u8; 10]).unwrap(); // 洞
        let s2 = r.on_send(vec![1u8; 10]).unwrap(); // 到达
        let mut sack = [0u8; 32];
        super::sack_mark(&mut sack, 0, s2);
        let got = r.on_ack(0, &sack);
        assert!(got.is_empty(), "额度耗尽后 on_ack 仍返回洞 ⇒ 闸没接上");
    }

    /// 快速重传送的包不能把后面的新洞永久堵死。
    ///
    /// 根因→修法（2026-10-24）：旧代码在 `retx > 0` 时 `return Vec::new()`
    /// 直接退出查找，一个还在退避的洞会挡住所有后续新洞。
    #[test]
    fn fast_retransmit_skips_retrying_hole() {
        let mut r = RetxBuf::new(1);
        // seq=1 是洞且已被快速重传过（retx=1）
        let s1 = r.on_send(vec![0u8; 10]).unwrap();
        let _s2 = r.on_send(vec![1u8; 10]).unwrap();
        let _s3 = r.on_send(vec![2u8; 10]).unwrap();
        let _s4 = r.on_send(vec![3u8; 10]).unwrap();
        // 先让 seq=1 被快速重传一次（SACK 标 2/3/4）
        let mut sack = [0u8; 32];
        super::sack_mark(&mut sack, 0, 2);
        super::sack_mark(&mut sack, 0, 3);
        super::sack_mark(&mut sack, 0, 4);
        assert_eq!(r.on_ack(0, &sack), vec![(s1, vec![0u8; 10])]);
        // 再发一个包 seq=5，现在让 seq=4 成为新洞（SACK 标 2/3/5，不标 4），
        // seq=1 仍在退避中 —— 必须能跨过它补 seq=4
        let s4 = r.on_send(vec![3u8; 10]).unwrap();
        let s5 = r.on_send(vec![4u8; 10]).unwrap();
        let mut sack2 = [0u8; 32];
        super::sack_mark(&mut sack2, 0, 2);
        super::sack_mark(&mut sack2, 0, 3);
        super::sack_mark(&mut sack2, 0, s5);
        let got = r.on_ack(0, &sack2);
        assert_eq!(
            got.iter().map(|(s, _)| *s).collect::<Vec<_>>(),
            vec![s4],
            "被退避中的洞不能堵住后面的新洞"
        );
    }
    #[test]
    fn sack_hole_triggers_fast_retransmit() {
        let mut tx = RetxBuf::new(1);
        for i in 1..=5u8 {
            tx.on_send(vec![i]).unwrap();
        }
        // 构造 SACK：ack=0（即 next-1，什么都没连续收到），bitmap 标 d=3,4,5。
        // d = seq - base，base=ack=0 ⇒ seq 3,4,5 对应 d=3,4,5（bit 索引 d-1）。
        let mut sack = [0u8; 32];
        for d in [3u32, 4, 5] {
            let i = (d - 1) as usize;
            sack[i / 8] |= 1 << (i % 8);
        }
        let fast = tx.on_ack(0, &sack);
        assert!(
            fast.iter().any(|(s, _)| *s == 1),
            "SACK 显示 3,4,5 已到而 1,2 未到 —— 必须立刻重传 seq=1，不等 RTO；实际 {fast:?}"
        );
    }

    /// 快速重传不能变成"每次 ACK 都狂重发"：没洞时必须返回空。
    /// 否则 15% 丢包下会把流量放大成重传风暴（对比 2026-10-23 事故）。
    #[test]
    fn no_sack_hole_means_no_fast_retransmit() {
        let mut tx = RetxBuf::new(1);
        for i in 1..=5u8 {
            tx.on_send(vec![i]).unwrap();
        }
        // 连续确认到 3：SACK 标 4,5（无洞），不应有任何快速重传。
        let mut sack = [0u8; 32];
        for d in [1u32, 2] {
            let i = (d - 1) as usize;
            sack[i / 8] |= 1 << (i % 8);
        }
        let fast = tx.on_ack(3, &sack);
        assert!(fast.is_empty(), "无洞时不得快速重传；实际 {fast:?}");
    }

    /// 同一轮 ACK 里多个洞：只补最靠前的（TCP 语义），不整批重发。
    #[test]
    fn fast_retransmit_returns_only_lowest_hole() {
        let mut tx = RetxBuf::new(1);
        for i in 1..=8u8 {
            tx.on_send(vec![i]).unwrap();
        }
        // ack=0，SACK 标 3,5,7（1,2,4,6,8 是洞）。最小洞 = 1。
        let mut sack = [0u8; 32];
        for d in [3u32, 5, 7] {
            let i = (d - 1) as usize;
            sack[i / 8] |= 1 << (i % 8);
        }
        let fast = tx.on_ack(0, &sack);
        assert_eq!(fast.len(), 1, "一轮只补最小洞，实际 {fast:?}");
        assert_eq!(fast[0].0, 1);
    }

    /// 核心回归（2026-10-23 事故）：无 ACK 时，N 个包的累计发送次数必须有上界。
    ///
    /// 旧代码如何复现：take_expired 每次都刷新时间戳且无退避、无放弃、
    /// 无容量上限，所以只要一直不 ACK，调用 1200 次 take_expired
    /// 就会重发约 1200 次/包 —— 放大倍数 = 调用次数，无上界。
    ///
    /// 断言抓什么：模拟 60 秒、50ms 一拍（1200 拍），统计总重发次数。
    /// 新代码因为退避 + 最大 10 次放弃，总重发次数必须 <= 单包上限 x 包数。
    #[test]
    fn retx_storm_does_not_amplify() {
        let mut tx = super::RetxBuf::new(1);
        const PKTS: usize = 256;
        for i in 0..PKTS {
            tx.on_send(vec![i as u8]).unwrap();
        }

        // 模拟 60s，每 50ms 调一次 take_expired（与 server 重传泵 interval 一致）
        let mut sent_total = PKTS; // 首次发送也算
        let mut t = super::now_ms();
        let mut abandoned_seen = 0;
        for _ in 0..1200 {
            t += 50;
            let due = tx.take_expired(Duration::from_millis(200), t);
            sent_total += due.len();
            // take_stats 取走即归零，故累加而不是覆盖
            abandoned_seen += tx.take_stats().abandoned;
        }

        // 上界：每个包最多被重发 KUDUS_MAX_RETX 次
        let upper = PKTS * (1 + super::KUDUS_MAX_RETX as usize);
        assert!(
            sent_total <= upper,
            "重传放大失控：共发送 {sent_total} 次，上界 {upper}（每包 1 首发 + {} 重发）",
            super::KUDUS_MAX_RETX
        );
        // 且必须有包被真正放弃（否则说明还在无限复活）
        assert!(abandoned_seen > 0, "60s 无 ACK 应触发放弃，否则包永不丢弃");
    }

    /// spec §15.3：RetxFull 拒收次数必须可见。
    #[test]
    fn retx_stats_counts_full() {
        let mut b = super::RetxBuf::new(0);
        for _ in 0..super::KUDUS_RETX_CAP {
            b.on_send(vec![1u8; 10]).unwrap();
        }
        assert!(b.on_send(vec![1u8; 10]).is_err(), "满 cap 后应拒绝");
        let s = b.take_stats();
        assert_eq!(s.full, 1);
    }

    /// 超过 KUDUS_MAX_RETX 次重传后必须从上表移除（真丢弃），不能永远留着。
    /// 旧代码没有「放弃」概念，包无限复活，这是内存与流量的双重泄漏。
    #[test]
    fn retx_counts_and_abandons() {
        let mut tx = super::RetxBuf::new(1);
        tx.on_send(b"x".to_vec()).unwrap();
        let mut t = super::now_ms();
        // 每次推进足够久，保证一定到期；跑 KUDUS_MAX_RETX 次
        for i in 0..super::KUDUS_MAX_RETX {
            t += 20_000; // 20s，远超任何退避 RTO
            let due = tx.take_expired(Duration::from_millis(200), t);
            assert_eq!(due.len(), 1, "第 {i} 次重传应到期");
        }
        // 再扫一次：此时 retx 已等于 MAX_RETX，应被清除
        t += 20_000;
        let due = tx.take_expired(Duration::from_millis(200), t);
        assert!(due.is_empty(), "超限后不应再重发");
        assert!(tx.is_empty(), "超过 MAX_RETX 必须放弃并移除，否则包永不丢弃");
        let st = tx.take_stats();
        assert_eq!(st.abandoned, 1, "放弃次数要有埋点可观测");
    }

    /// 指数退避序列：200 → 400 → 800 → 1.6s → 3.2s → 6.4s → 8s(封顶)。
    /// 旧代码固定 200ms 线性重传，每秒重发 5 次，包越多放大越猛。
    #[test]
    fn retx_backoff_is_exponential() {
        assert_eq!(super::rto_for(0), Duration::from_millis(200));
        assert_eq!(super::rto_for(1), Duration::from_millis(400));
        assert_eq!(super::rto_for(2), Duration::from_millis(800));
        assert_eq!(super::rto_for(3), Duration::from_millis(1600));
        assert_eq!(super::rto_for(4), Duration::from_millis(3200));
        assert_eq!(super::rto_for(5), Duration::from_millis(6400));
        assert_eq!(super::rto_for(6), Duration::from_secs(8), "6.4s×2=12.8s 应被 RTO_MAX 封顶");
        assert_eq!(super::rto_for(9), Duration::from_secs(8), "超过也应封顶，不能溢出");
    }

    /// 重传计数必须递增，且退避生效：首次 200ms 到期，重发后下一次要等 400ms。
    /// 旧代码 take_expired 只做 *sent = now，无计数、无退避。
    #[test]
    fn retx_counts_and_backs_off() {
        let mut tx = super::RetxBuf::new(1);
        let s = tx.on_send(b"x".to_vec()).unwrap();
        let t0 = super::now_ms();
        // 首次：200ms 后到期
        let due = tx.take_expired(Duration::from_millis(200), t0 + 200);
        assert_eq!(due.len(), 1, "首次应到期");
        assert_eq!(due[0].0, s);
        // 重发后：再过 200ms 不该到期（因为退避到 400ms）
        let due = tx.take_expired(Duration::from_millis(200), t0 + 400);
        assert!(due.is_empty(), "退避后 200ms 内不应再次到期（旧代码会立刻再发）");
        // 等到 400ms 才到期
        let due = tx.take_expired(Duration::from_millis(200), t0 + 610);
        assert_eq!(due.len(), 1, "退避 400ms 后应到期");
    }

    /// 容量上限：满 4096 后 on_send 必须拒绝，不能无限增长。
    /// 旧代码：seqs 是裸 HashMap，无上限，无 ACK 时无限涨（事故 8192 包）。
    #[test]
    fn retx_buf_respects_capacity() {
        let mut tx = super::RetxBuf::new(1);
        for i in 0..super::KUDUS_RETX_CAP {
            assert!(tx.on_send(vec![i as u8]).is_ok(), "第 {i} 个应能登记");
        }
        assert_eq!(tx.len(), super::KUDUS_RETX_CAP);
        assert!(tx.on_send(vec![0]).is_err(), "超过 cap 必须拒绝，否则缓冲无界");
        assert_eq!(tx.len(), super::KUDUS_RETX_CAP, "被拒后长度不能变");
    }

    /// 背压阈值与硬容量上限是两个不同的数，不能混用。
    /// 根因→修法：旧代码把 256 硬编码在 server/kudus.rs 两处 + agent 一处，
    /// 且没有硬上限，retx 表可无限增长（事故实测积压 8192 包 → 39MB/s）。
    #[test]
    fn retx_constants_are_sane() {
        assert_eq!(super::KUDUS_RETX_BACKLOG, 256);
        assert_eq!(super::KUDUS_RETX_CAP, 4096);
        assert!(
            super::KUDUS_RETX_BACKLOG < super::KUDUS_RETX_CAP,
            "背压阈值必须小于硬上限"
        );
        assert_eq!(super::KUDUS_MAX_RETX, 10);
        assert_eq!(super::KUDUS_RTO_MAX, Duration::from_secs(8));
    }
    use super::*;

    #[test]
    fn heartbeat_slow_fast_hysteresis() {
        // 根因→修法：固定 30s 心跳多 agent 对齐惊群；丢包无加密。慢档 15~30s 随机，
        // 丢包进快档 5~8s，回慢档需 3 连好（防翻转）。
        let mut hb = super::Heartbeat::new();
        assert!(!hb.is_fast());
        for _ in 0..20 {
            let d = hb.next_interval(false);
            assert!(d >= std::time::Duration::from_secs(15) && d <= std::time::Duration::from_secs(30));
            assert!(!hb.is_fast());
        }
        let d = hb.next_interval(true); // 丢 1 包即进快档
        assert!(hb.is_fast());
        assert!(d >= std::time::Duration::from_secs(5) && d <= std::time::Duration::from_secs(8));
        hb.next_interval(false);
        hb.next_interval(false);
        assert!(hb.is_fast()); // 2 连好仍在快档
        hb.next_interval(false);
        assert!(!hb.is_fast()); // 3 连好回慢档
    }

        /// RED（2026-10-25 现场）：看门狗预算必须随「距最后活帧时间」递减，
        /// 纯 ACK 不得让预算回满。
        ///
        /// 旧实现 `timeout(75s, recv())` 在循环体内，纯 ACK 的 `continue`
        /// 会重建 timeout。现实后果：server 重启后不认旧会话（tx=0B），
        /// 但 agent 每 50ms 收到一个纯 ACK，75s 永不触发，会话卡死 7 小时。
        #[test]
        fn watchdog_budget_drains_under_pure_ack() {
            use super::watchdog_budget_ms;
            assert_eq!(watchdog_budget_ms(0), Some(75_000));
            assert_eq!(watchdog_budget_ms(50_000), Some(25_000));
            assert_eq!(watchdog_budget_ms(75_000), None);
            assert_eq!(watchdog_budget_ms(200_000), None);
        }

        /// 纯 ACK 永远不能把预算拉回满值（旧实现的核心缺陷）。
        #[test]
        fn pure_ack_never_refills_watchdog() {
            use super::{watchdog_budget_ms};
            let mut prev = 75_000u64;
            for i in 1..=900u64 {
                let elapsed = i * 50;
                let b = watchdog_budget_ms(elapsed).expect("45s 未超时");
                assert!(b < prev, "{elapsed}ms 时预算未下降: {b} >= {prev}");
                prev = b;
            }
        }

    #[test]
    fn only_data_frames_feed_watchdog() {
        // snail/workmac 2026-10-23 现场：server 会话被踢后泄漏的重传泵每 50ms
        // 发纯 ACK 探活，agent 读泵把它投进 dec 通道，主循环 75s 看门狗被
        // 假心跳复位，session 永远不 bail（本地端口活、数据面死、无任何日志）。
        // 看门狗只认 DATA 帧（含控制面分片，同样 FLAG_DATA）：纯 ACK/FIN/SYN 不算活。
        use super::{frame_feeds_watchdog, FLAG_ACK, FLAG_DATA, FLAG_FIN, FLAG_SYN};
        assert!(frame_feeds_watchdog(FLAG_DATA));
        assert!(frame_feeds_watchdog(FLAG_DATA | FLAG_ACK)); // 捎带确认的数据帧照样算活
        assert!(!frame_feeds_watchdog(FLAG_ACK)); // 泄漏泵的探活包：不清看门狗
        // FIN 不算“活”但必须穿透到关闭分支：主循环过滤条件是
        // `!feeds && !FIN`（见 kudus_session 主循环），此处只锁 feeds 判定。
        assert!(!frame_feeds_watchdog(FLAG_FIN));
        assert!(!frame_feeds_watchdog(FLAG_SYN));
        assert!(!frame_feeds_watchdog(0));
    }

    #[test]
    fn kudus_idle_kick_threshold() {
        // 看门狗 75s：容忍连丢 2 包（最坏 30s 间隔 + 1 次丢包不误踢）。
        assert!(super::kudus_idle_stale(0, 76));
        assert!(!super::kudus_idle_stale(0, 75));
        assert!(!super::kudus_idle_stale(100, 105));
    }

    #[test]
    fn seal_open_roundtrip() {
        let k = derive_key("s3cret");
        let n = fresh_nonce();
        let c = seal(&k, &n, b"hello-kudus");
        let p = open(&k, &n, &c).unwrap();
        assert_eq!(p, b"hello-kudus");
    }

    #[test]
    fn wrong_token_is_blackhole() {
        let k1 = derive_key("right");
        let k2 = derive_key("wrong");
        let n = fresh_nonce();
        let c = seal(&k1, &n, b"secret");
        assert!(open(&k2, &n, &c).is_none()); // tag fails -> drop, no reply
    }

    #[test]
    fn tampered_nonce_fails() {
        let k = derive_key("t");
        let mut n = fresh_nonce();
        let c = seal(&k, &n, b"x");
        n[0] ^= 1;
        assert!(open(&k, &n, &c).is_none());
    }

    #[test]
    fn packet_hdr_roundtrip() {
        let k = derive_key("t");
        let n = fresh_nonce();
        let h = KudusHdr {
            ver: 1,
            flags: FLAG_DATA,
            seq: 101,
            ack: 99,
            sack: [0u8; 32],
            ts_ms: 12345,
        };
        let mut plain = encode_hdr(&h).to_vec();
        plain.extend_from_slice(b"payload");
        let pkt = encode_packet(0xdead_beef, &n, &seal(&k, &n, &plain));
        let (sess, nonce, ct) = decode_packet(&pkt).unwrap();
        assert_eq!(sess, 0xdead_beef);
        let opened = open(&k, nonce, ct).unwrap();
        let (h2, body) = decode_hdr(&opened).unwrap();
        assert_eq!((h2.seq, h2.ack), (101, 99));
        assert_eq!(body, b"payload");
        assert!(decode_packet(&pkt[..10]).is_none()); // short datagram
    }

    #[test]
    fn sack_marks_only_holes() {
        let mut sack = [0u8; 32];
        sack_mark(&mut sack, 100, 102);
        sack_mark(&mut sack, 100, 104);
        let missing = sack_missing(&sack, 100, 8);
        // 101,103,105..107 missing; 100 is acked base, 102/104 present
        assert!(missing.contains(&101) && missing.contains(&103));
        assert!(!missing.contains(&102) && !missing.contains(&104));
    }

    /// RED:丢包恢复——先丢 seq=2，后补到，输出必须按 1,2,3 有序补齐。
    /// 旧代码无重排缓冲（到包即投），丢包即永久少一块（现网 avatar/blob 截断）。
    #[test]
    fn reorder_recovers_loss_in_order() {
        let mut rx = ReorderBuf::new(1);
        assert_eq!(rx.push(1, b"a".to_vec()), vec![b"a".to_vec()]);
        assert!(rx.push(3, b"c".to_vec()).is_empty()); // 2 丢了：3 先缓存不投
        assert_eq!(rx.push(2, b"b".to_vec()), vec![b"b".to_vec(), b"c".to_vec()]); // 补 2 即补齐
        assert_eq!(rx.ack(), 3);
    }

    /// RED:超时重传——发 1,2,3，只 ack 到 1，取超时即吐出 2,3；ack 到 3 后清空。
    #[test]
    fn retx_expires_and_acks() {
        let mut tx = RetxBuf::new(1);
        let s1 = tx.on_send(b"a".to_vec()).unwrap();
        let s2 = tx.on_send(b"b".to_vec()).unwrap();
        let _s3 = tx.on_send(b"c".to_vec()).unwrap();
        assert_eq!((s1, s2), (1, 2));
        tx.on_ack(1, &[0u8; 32]);
        let due = tx.take_expired(Duration::from_millis(200), now_ms() + 1000);
        assert_eq!(due.len(), 2); // 2,3 超时待重传
        tx.on_ack(3, &[0u8; 32]);
        assert!(tx.is_empty());
    }

    #[test]
    fn parse_kudus_scheme() {
        use crate::common::quic::{parse_server_url, Transport};
        assert!(matches!(
            parse_server_url("kudus://127.0.0.1:7445"),
            Transport::Kudus { .. }
        ));
        assert!(matches!(
            parse_server_url("ws://127.0.0.1:7440/ws"),
            Transport::Ws(_)
        ));
    }

    /// RED:UDP 下行分片——1500B 公网包切 2 片，乱序到达拼回整包且 sid 不变。
    /// 旧代码按 TCP 字节流逐片 deliver，内网收到 2 个残包（无声 corrupt）。
    #[test]
    fn kudus_udp_frag_roundtrip_large() {
        // 现场：公网 1500B UDP 包，旧写泵 chunks(1000) 切 2 片逐片交，边界碎。
        let dg: Vec<u8> = (0..1500u32).map(|i| (i % 251) as u8).collect();
        let pieces = super::split_udp_dgram(77, &dg);
        assert!(pieces.len() == 2);
        for p in &pieces {
            assert!(
                4 + 24 + super::HDR_LEN + p.len() + 16 <= super::KUDUS_MAX_UDP,
                "frag still oversize: {}B",
                p.len()
            );
        }
        // 乱序投递：每片 strip 外层 sid 后喂按 sid 分槽的重组器。
        let mut reasm = super::UdpReasm::new();
        let mut got = None;
        for p in pieces.iter().rev() {
            let (id, payload) = crate::common::proto::decode_data(p).unwrap();
            assert_eq!(id, super::KUDUS_UDP_SID);
            if let Some((sid, msg)) = reasm.feed(payload) {
                got = Some((sid, msg));
            }
        }
        let (sid, msg) = got.expect("reasm never completed");
        assert_eq!(sid, 77);
        assert_eq!(msg, dg);
        // 背靠背两包同流：分槽互不踩。
        let a: Vec<u8> = (0..1200u32).map(|i| (i % 251) as u8).collect();
        let b: Vec<u8> = (0..1300u32).map(|i| ((i + 7) % 251) as u8).collect();
        let pa = super::split_udp_dgram(9, &a);
        let pb = super::split_udp_dgram(9, &b);
        assert_eq!(pa.len(), 2);
        assert_eq!(pb.len(), 2);
        // 背靠背顺序投递：a0,a1,b0,b1——a 先集齐交一次，b 再集齐交一次。
        // （可靠重排保序，同 sid 各包天然顺序到达；真交错时 total 变化旧槽作废，
        // 丢的片由重传补齐后按序重到——与 CtrlReasm 同语义，不另加 msg_id。）
        let mut r2 = super::UdpReasm::new();
        let mut hits = Vec::new();
        for p in pa.iter().chain(pb.iter()) {
            let (_, payload) = crate::common::proto::decode_data(p).unwrap();
            if let Some((s, m)) = r2.feed(payload) {
                hits.push((s, m));
            }
        }
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].0, 9);
        assert_eq!(hits[0].1, a);
        assert_eq!(hits[1].0, 9);
        assert_eq!(hits[1].1, b);
    }

    /// RED:控制帧分片——3320B 级 Config/Register 必须切成装得进 datagram 的小片，
    /// 乱序/重发到达也能重组回原文。旧代码一消息一帧，超 KUDUS_MAX_UDP 整包丢。
    #[test]
    fn kudus_ctrl_frag_roundtrip_large() {
        // 3320B 现场包：50B hdr + body 超 1138B 预算即被 send_pkt 整包丢。
        let big = vec![b'x'; 3320];
        let pieces = super::split_ctrl_frame(&big);
        assert!(pieces.len() > 1);
        for p in &pieces {
            assert!(
                4 + 24 + super::HDR_LEN + p.len() + 16 <= super::KUDUS_MAX_UDP,
                "frag still oversize: {}B",
                p.len()
            );
        }
        // 乱序投递（每片经 decode_data 拆出 sid=0 负载后喂重组器）。
        let mut reasm = super::CtrlReasm::new();
        let mut got = None;
        for p in pieces.iter().rev() {
            let (id, payload) = crate::common::proto::decode_data(p).unwrap();
            assert_eq!(id, super::KUDUS_CTRL_SID);
            if let Some(m) = reasm.feed(payload) {
                got = Some(m);
            }
        }
        assert_eq!(got.unwrap(), big);
        // 小消息不分片：单片即原文（offset 0 + total == len）。
        let small = b"{\"t\":\"ping\"}".to_vec();
        let one = super::split_ctrl_frame(&small);
        assert_eq!(one.len(), 1);
        let mut r2 = super::CtrlReasm::new();
        let (_, pl) = crate::common::proto::decode_data(&one[0]).unwrap();
        assert_eq!(r2.feed(pl).unwrap(), small);
    }

    #[test]
    fn retx_stats_starts_zero() {
        let mut b = super::RetxBuf::new(0);
        let s = b.take_stats();
        assert_eq!(s.sent, 0);
        assert_eq!(s.abandoned, 0);
        assert_eq!(s.full, 0);
        assert_eq!(s.backlog_max, 0);
    }

    #[test]
    fn retx_stats_tracks_backlog_peak() {
        let mut b = super::RetxBuf::new(0);
        for _ in 0..100 {
            b.on_send(vec![1u8; 10]);
        }
        // 全部 ACK 后 backlog 归零，但峰值必须保留 100
        b.on_ack(100, &[0u8; 32]);
        let s = b.take_stats();
        assert_eq!(s.backlog_max, 100, "峰值必须保留，不能被 ACK 抹平");
    }

    #[test]
    fn retx_stats_take_resets() {
        let mut b = super::RetxBuf::new(0);
        for _ in 0..5 {
            b.on_send(vec![1u8; 10]);
        }
        let first = b.take_stats();
        assert_eq!(first.backlog_max, 5);
        let second = b.take_stats();
        assert_eq!(second, super::RetxStats::default(), "取走后必须归零");
    }

    #[test]
    fn retx_stats_counts_resends() {
        let mut b = super::RetxBuf::new(0);
        b.on_send(vec![1u8; 10]);
        let rto = std::time::Duration::from_millis(200);
        // 每次推进 now —— take_expired 会把 *sent 刷成 now，
        // 用同一个 now 再扫不会到期（这也是旧代码「包永不丢弃」的根源）。
        let mut now = super::now_ms() + 10_000;
        let due1 = b.take_expired(rto, now);
        assert_eq!(due1.len(), 1, "首轮应有 1 包到期");
        now += 10_000;
        let due2 = b.take_expired(rto, now);
        assert_eq!(due2.len(), 1, "时间推进后再次到期");
        let s = b.take_stats();
        assert_eq!(s.sent, 2, "重发 2 次应记 sent=2");
    }
}
