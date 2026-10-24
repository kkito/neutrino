# kudus 重传放大止血 + agent UDP 资源池化设计

日期：2026-10-25（§15 于 2026-10-26 追加）· 状态：brainstorming 已确认
（A~J 全部项 + 可观测性三层，只动 neutrino）。

> **2026-10-26 追加**：本文已合并「可观测性补强」（§15，含层 4a/4b/4c）。
> 起因是 2026-10-25 对 HK 线上 journal 全量排查发现：**本次事故在日志里几乎不可见**
> （`grep -icE "retx|retrans|backpressure"` = 0 条），修完也无法证明修复有效。
> 故埋点与止血同一批实施，见 §15。

## 1. 背景与目标

### 1.1 现场问题

2026-10-23 北京 19:00–21:00（UTC 12:00–13:00），HK server（cloudserver）与 snail（minipc7s）
之间发生流量风暴：

- HK 日志量从 ~60 条/分钟激增至 500–730 条/分钟
- `ratelimit stats: minipc7s/trans-bt limit=524288B/s thru=22396311B sleep=5204ms`
  —— 限速 512KB/s，实际吞吐 **22.4MB/s（超限 42 倍）**，单次 sleep 5.2s
- snail `enp1s0` rx_dropped = 3,989,268；fq_codel `new_flow_count=21,322,015`、
  `requeues=7,803,137`
- snail 侧 `too many udp streams` 从 19:35 起持续，两小时半 3608 条

### 1.2 根因（详见 `docs/incidents/`，不入库）

两个独立缺陷叠加：

**缺陷 A：kudus 重传缓冲无上限 → 流量自我放大（主因）**

- `RetxBuf` 无容量上限，可无限积压
- `take_expired` 重发时刷新 `*sent = now`，包**永不丢弃**（无限复活）
- `KUDUS_RTO = 200ms` 固定，无退避、无最大次数（每秒重发 5 次）
- 量化：256 包积压 ≈ 1.22MB/s；8192 包 ≈ **39MB/s**，与实测 22.4MB/s 同量级

**缺陷 B：背压失效 → 流量控制有洞**

- `server/kudus.rs` 背压等待 30s（3000 × 10ms）后**放弃等待继续发包**
- 等于背压完全不存在

**缺陷 C：UDP 流槽位设计缺陷（次因，不参与风暴根因）**

- `KUDUS_MAX_UDP_STREAMS = 256` 是 agent 出站 socket 的 fd 配额
- 槽位打满后**直接拒绝新流**，DHT 场景下全部新 peer 被断
- `udp` 与 `link_udp` **共用**同一个信号量，BT 可饿死 link_udp
- 每流出站接收 buffer 固定 64KB，256 流 = 16MB 纯堆内存浪费
- agent idle 30s vs server TTL 5s，两端不一致

### 1.3 目标

1. **止血**：杜绝重传放大，流量上限可预测
2. **补洞**：背压超时必须显式失败，不能静默继续
3. **优化**：UDP 出口资源池化，fd/内存大幅下降，并发 peer 数不再受 256 限制
4. **解耦**：`udp` 与 `link_udp` 配额独立，互不饿死

## 2. 范围

- 改：`src/common/kudus.rs`（RetxBuf 重构 + RetxStats）、`src/server/kudus.rs`（背压 bail + retx 汇总）、
  `src/agent/kudus_session.rs`（buffer / 池接入 / 超时 + retx 汇总）、
  `src/agent/udp_pool.rs`（**新模块**）、`src/server/state.rs`（TunnelStats）、
  `src/server/ingress.rs`（日志降级 + per-tunnel 汇总）、`src/main.rs`（`--log-file` 对 systemd 生效）,
  `deploy/*.service`（RUST_LOG 与 journald 留存）
- 不动：kudus 加密与帧格式、`ClientMsg`/`ServerMsg` 协议字段、WSS/QUIC 传输、
  限速器语义、egress 出口选择逻辑、server 侧 UDP session 表（TTL 逻辑已修）
- 新增范围（§15 可观测性）：只做**埋点/日志**，不改任何转发语义与限速行为

## 3. 架构总览

三层改动边界清晰，层 1↔层 2 是同一事故上下游（必须一起修），层 3 独立：

```
┌─────────────────────────────────────────────────────────┐
│ 层 1：kudus 可靠传输（common/kudus.rs）                 │
│   修 RetxBuf：容量上限 + 重传计数 + 指数退避 + 可放弃    │
│   ← 止血：流量自我放大                                  │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│ 层 2：kudus 发送侧（server/kudus.rs）                   │
│   修背压：30s 超时后 bail!（不再"放弃等待继续发"）      │
│   ← 止血：流量控制有洞                                  │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│ 层 3：agent UDP 流管理（agent/kudus_session.rs）        │
│   3a buffer 2048 + 截断检测                             │
│   3b 动态 socket 池 64→512（udp / link_udp 各自独立）   │
│   3c idle 超时 30s → 5s                                 │
│   ← 优化：内存 / fd / 互相饿死                          │
└─────────────────────────────────────────────────────────┘
```

## 4. 层 1：RetxBuf 重构

### 4.1 新结构

```rust
struct RetxEntry {
    bytes: Vec<u8>,
    first_sent: u64,   // 首发 ms（退避计算基准，沿用现有 now_ms()）
    last_sent: u64,    // 实际发送 ms
    retx: u32,         // 已重传次数
}

struct RetxBuf {
    next: u32,
    seqs: HashMap<u32, RetxEntry>,   // seq(u32) → entry，沿用现有 HashMap
    cap: usize,                       // 新增：容量上限
}
```

> 注：现有实现用 `HashMap<u32, (Vec<u8>, u64)>` 且用 `now_ms()`（相对 ms u64）
> 而非 `Instant`。计划保持这两个现有选择不改（避免无关重构）。

### 4.2 容量上限

```rust
pub const KUDUS_RETX_CAP: usize = 4096;

fn insert(&mut self, seq: u64, bytes: Vec<u8>) -> Result<(), RetxFull> {
    if self.map.len() >= self.cap {
        return Err(RetxFull);   // 调用方决定丢弃/阻塞
    }
    ...
}
```

`cap = 4096` 依据：

- `KUDUS_WINDOW = 512`，4096 = 窗口 8 倍（允许突发）
- 按 1232B/包算，4096 包 ≈ **5MB** 内存上限（可控）
- 最坏发送速率估算：若仍按旧 RTO=200ms 算，4096 包 × 1232B × 5次/秒 ≈ **25MB/s**；
  但新代码有指数退避，**实际速率会远低于此值**（这是上界，不是预期值）
- 对比旧行为：缓冲无上限时实测积压 8192 包且永不释放，速率实测达 **22.4MB/s 持续两小时**

### 4.3 重传计数（修复"永不丢弃"）

旧代码 `take_expired` 里 `*sent = now` 让包无限复活。新代码：

```rust
entry.retx += 1;
entry.last_sent = now;
```

### 4.4 指数退避

```rust
pub const KUDUS_RTO_MAX: Duration = Duration::from_secs(8);
pub const KUDUS_MAX_RETX: u32 = 10;

fn rto_for(retx: u32) -> Duration {
    // 200ms → 400 → 800 → 1.6s → 3.2s → 6.4s → 8s(封顶)
    KUDUS_RTO
        .saturating_mul(1u32 << retx.min(6))
        .min(KUDUS_RTO_MAX)
}
```

### 4.5 放弃机制

```rust
if entry.retx >= KUDUS_MAX_RETX {
    self.map.remove(&seq);            // 真丢弃
    stats.retx_abandoned += 1;        // 埋点
    // 通知上层：该 seq 彻底失败
}
```

### 4.6 附带常量澄清

现有代码里背压阈值是硬编码魔数 `256`（`agent/kudus_session.rs:126`、
`server/kudus.rs:301/338`）。本次抽成常量，三处共用：

```rust
/// retx 未确认包数达到此值即认为窗口积压，需退让等 ACK。
pub const KUDUS_RETX_BACKLOG: usize = 256;
/// 背压轮询间隔。
pub const BACKPRESSURE_POLL: Duration = Duration::from_millis(10);
```

**注意区分**：`KUDUS_RETX_BACKLOG = 256`（背压阈值，滞回线）与
`KUDUS_RETX_CAP = 4096`（硬容量上限）是**两个不同的数**，不要混淆。

### 4.7 效果对比

| 场景 | 旧行为 | 新行为 |
| --- | --- | --- |
| 单个包丢失 | 每 200ms 重发，无限次 | 指数退避，10 次后放弃 |
| 缓冲积压 | 无上限（实测 8192 包） | 硬上限 4096 |
| 最坏发送速率 | ≈39MB/s（无上限） | ≈25MB/s 理论上界，退避后实际远低 |
| 是否永久占用 | 是（永不释放） | 否 |

## 5. 层 2：背压修复

### 5.1 现状

`server/kudus.rs` 背压等待 30s（3000 × 10ms），超时后**照旧 send_pkt**，等于背压不存在。
后果：窗口已满仍继续发包 → 对端重排缓冲溢出 → 丢包率飙升 → 触发更多重传 →
重传又加剧拥塞，正反馈。

### 5.2 修复

**实际存在两处同样缺陷**，都要改：

| 位置 | 现状 |
| ---- | ---- |
| `src/server/kudus.rs:299` | 下行写泵，3000×10ms 后继续发 |
| `src/server/kudus.rs:336` | 另一条写泵路径，同样 |

```rust
pub const KUDUS_BACKPRESSURE_TIMEOUT: Duration = Duration::from_secs(5);

let mut waited = Duration::ZERO;
while !window_has_room() {
    if waited >= KUDUS_BACKPRESSURE_TIMEOUT {
        bail!("kudus send backpressure timeout ({sid})");   // 不再静默继续
    }
    sleep(BACKPRESSURE_POLL).await;
    waited += BACKPRESSURE_POLL;
}
```

### 5.3 bail 之后的行为

1. 错误向上传播到该会话的主循环
2. 主循环 warn 日志 + **关闭该 kudus 会话**
3. agent 的 75s 看门狗或重连逻辑重建会话

**为什么是关会话而非丢单包**：背压超时说明链路已严重恶化，该会话的窗口、重传表、
SACK 状态全部不可信，重建是唯一能干净恢复的方式。agent 侧已有成熟重连机制
（`e420bac feat(kudus): backpressure + first-chunk timeout`）。

**代价**：重建期短暂断流（1~2s），远小于持续恶化的代价。

### 5.4 超时值

从 30s 降到 **5s**。30s 已证明过于宽松（事故持续近 2 小时）；5s 足够正常抖动
（窗口 512 包排空通常远小于 5s）。

### 5.5 agent 侧上行超时（对称修复）

**与 server 侧是两个不同位置，不要混。**

| 位置 | "发不出去"的含义 | 旧行为 | 新行为 |
| ---- | ---------------- | ------ | ------ |
| **server 侧**（本层） | server → 公网 peer 窗口满 | 30s 后静默继续发 | **5s 后 `bail!` 关会话** |
| **agent 侧**（本节） | agent → HK 隧道窗口满 | **30s 后照样继续发** | **5s 后丢弃该回包** |

#### 问题

`agent/kudus_session.rs:124` 的 `wait_window` 当前是：

```rust
pub(crate) async fn wait_window(&self) {
    for _ in 0..3000 {                                  // 3000 × 10ms = 30s
        let n = self.rel.lock().map(|r| r.retx.len()).unwrap_or(0);
        if n < 256 { break; }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    // ⭐ 循环耗尽后直接返回，调用方照样继续发送
}
```

**与 server 侧完全同构的缺陷**：等待 30s 后**不报错、不丢包，照样继续发**。
所谓"背压"在超时后形同虚设。

#### 修复：超时后丢包（而非关会话）

`wait_window` 改为返回是否等到窗口：

```rust
pub const KUDUS_AGENT_SEND_TIMEOUT: Duration = Duration::from_secs(5);

/// 返回 true = 已有空间可发；false = 超时。
pub(crate) async fn wait_window(&self) -> bool {
    let mut waited = Duration::ZERO;
    while self.rel.lock().map(|r| r.retx.len()).unwrap_or(0) >= KUDUS_RETX_BACKLOG {
        if waited >= KUDUS_AGENT_SEND_TIMEOUT { return false; }
        tokio::time::sleep(BACKPRESSURE_POLL).await;
        waited += BACKPRESSURE_POLL;
    }
    true
}
```

调用方（`agent/kudus_session.rs:628` / `:643`）改为：

```rust
if !pktw.wait_window().await {
    stats.udp_send_dropped += 1;
    warn_sampled("kudus agent send timeout, dropping (sid={sid})");
    return;   // 丢弃本次数据，不再发
}
```

#### 为何两侧策略不同

| 侧 | 策略 | 理由 |
| -- | ---- | ---- |
| server | `bail!` 关会话 | server 是流量**入口**，卡住会积压大量数据（事故中 22.4MB/s 持续两小时） |
| agent | 丢包 | agent 只是转发**回包**，丢一个 UDP 包是合法语义，且不会放大流量 |

**关键对比（回答"现在发不出去怎么办"）**：

- 旧代码：发不出去就**无限重发/无限等待** → 缓冲积压 → 内存膨胀 → 仍继续发
- 新代码：server 侧**关会话重置状态**，agent 侧**丢包不再积压**
- 两侧都保证：**任何情况下都不会无限堆积**

## 6. 层 3a：接收 buffer 改 2048 + 截断检测

### 6.1 改动

```rust
pub(crate) const UDP_RECV_BUF: usize = 2048;

let mut b = vec![0u8; UDP_RECV_BUF];
loop {
    match r.recv(&mut b).await {
        Ok(0) | Err(_) => break,
        Ok(n) => {
            if n == UDP_RECV_BUF {
                // UDP recv 静默截断，不报错，只能近似判断
                warn_sampled("kudus udp recv possibly truncated: n={n} (buf={UDP_RECV_BUF})");
                stats.udp_truncated += 1;
            }
            send_data(&pkt3, sid, &b[..n], true);
        }
    }
}
```

### 6.2 数值依据

| 约束 | 值 |
| --- | --- |
| 隧道单片上限 `KUDUS_UDP_MAX` | 1232B |
| 标准 MTU 不分片 | ~1500B |
| 选定值 | 2048（覆盖 1500 + 33% 余量） |

**2048 是下限，不能再小**：小于 1500 时正常 MTU 包会被截断。

### 6.3 截断检测语义

`recv()` 拿不到原始包长，只能判断 `n == buf.len()` → **可能**被截断。
因此日志用 `possibly truncated` 措辞、采样上报。这是已知的近似做法，
但足以发现静默丢数据（符合现有 `kudus 4 drop points count + sampled warn` 风格）。

### 6.4 收益

| 流数 | 65535 | 2048 |
| --- | --- | --- |
| 512（池上限） | 32 MB | **1 MB** |
| 256（旧上限） | 16 MB | 0.5 MB |

## 7. 层 3b：动态 socket 池

### 7.1 问题

现在每个 sid 独占一个 socket，生命周期与 sid 绑定。要解耦。

### 7.2 新模块 `agent/udp_pool.rs`（纯逻辑，无 IO）

```rust
pub struct UdpPool {
    idle: VecDeque<PooledSock>,        // 可借的空闲 socket
    in_use: HashMap<u32, PooledSock>,  // sid → socket
    lru: VecDeque<u32>,                // 最久未活跃的 sid 在队首
    cap: usize,                        // 动态扩容上限
    kind: PoolKind,                    // Udp / LinkUdp
}

impl UdpPool {
    async fn acquire(&mut self, sid: u32) -> AcquireOutcome;
    fn release(&mut self, sid: u32);
    fn touch(&mut self, sid: u32);
}
```

### 7.3 三个核心机制

**① 动态扩容 64 → 512**

```rust
const POOL_INIT: usize = 64;
const POOL_MAX: usize = 512;

// acquire：idle 非空 → 复用
//          idle 空 && in_use < cap → 新建 socket（扩容，debug 日志）
//          idle 空 && in_use == cap → 踢 LRU
```

**② LRU 踢流**

```rust
if in_use.len() >= cap {
    let victim = lru.pop_front();
    // 通知该 sid：Close { reason: "pool evicted" }
    // 其 socket 归还 idle 复用
    stats.pool_evicted += 1;
}
```

**③ 两个独立池**

```rust
// KCtx 中
udp_pool: Arc<Mutex<UdpPool>>,       // PoolKind::Udp，     cap = 512
link_udp_pool: Arc<Mutex<UdpPool>>,  // PoolKind::LinkUdp， cap = 512
```

各自 64 起步、各自扩到 512，`udp` 打满占不到 `link_udp` 的槽位。

### 7.4 目标地址处理：`send_to` 替代 `connect`

不同 sid 目标可能不同（不同端口），故：

- 池内 socket **不 `connect` 到具体目标**，改用 `send_to(target)`
- 回包仍从该 socket 的端口返回，记录「sid → (socket, target)」即可正确回发
- 这样同一 socket 可被不同目标的 sid 复用

### 7.5 与现有代码的差异

| 项 | 现状 | 改动后 |
| --- | --- | --- |
| 并发上限 | 256（信号量） | 64 起步 / 512 上限，按需扩容 |
| 超限行为 | **直接拒绝新流** | 踢 LRU 最久未活跃流 |
| `udp`/`link_udp` | 共用一个信号量 | 两个独立池 |
| 每流内存 | 64KB buffer | 2KB buffer |
| socket 生命周期 | 与 sid 绑定 | 池内复用 |

## 8. 层 3c：idle 超时统一 5s

```rust
// agent/kudus_session.rs
const UDP_STREAM_IDLE_SECS: u64 = 5;   // 30 → 5
```

与 server 侧 `UDP_SESSION_TTL_SECS_DEFAULT = 5` 对齐。

**两端同为 5s 的风险评估**：两侧计时起点不同（server 收到 peer 包时启动，agent 收到
隧道包时启动）。若 Close 帧丢失/延迟，agent 可能先自行到期并 Close——双方都发 Close 是
幂等操作，只多一帧，**不会产生错误**。真正需要担心的「agent 先关、server 仍认为活跃」
在流活跃时 server 一直在续期，只有「包间隔 ≥ 5s」的边界情况可能触发，而这本身就等价于
会话已死。**结论：5s 可用，不引入实际风险。**

## 9. 错误处理与观测

沿用现有 `drop_stats` 模式（`4c4366d`）：

| 场景 | 行为 | 埋点 |
| --- | --- | --- |
| RetxBuf 满 | 拒绝新包，返回 `RetxFull` | `retx_full` |
| 重传超上限 | 丢弃 + 通知上层 | `retx_abandoned` |
| 背压超时 | `bail!` 关会话 | `backpressure_timeout` |
| agent 上行超时 | 丢弃该回包（UDP 合法语义） | `udp_send_dropped` |
| UDP 可能截断 | 限频 warn | `udp_truncated` |
| 池满踢流 | Close + 归还 socket | `pool_evicted` |
| 池扩容 | debug 日志 | `pool_grown` |

## 10. 测试计划（TDD，先红后绿）

### 10.1 单测：`common/kudus.rs`

| 测试名 | 断言 |
| --- | --- |
| `retx_buf_respects_capacity` | 满 4096 后 `insert` 返回 `Err(RetxFull)` |
| `retx_counts_and_abandons` | 重传 10 次后条目被移除，`retx_abandoned` +1 |
| `retx_backoff_is_exponential` | `rto_for(0..=6)` = 200/400/800/1600/3200/6400/8000ms |
| `retx_does_not_live_forever` | **回归**：同 seq 包不会无限复活 |
| `retx_entry_removed_on_ack` | 现有测试保持通过（不回归） |

### 10.2 单测：`agent/udp_pool.rs`

| 测试名 | 断言 |
| --- | --- |
| `pool_reuses_idle_socket` | 归还后再借得到同一 socket |
| `pool_grows_up_to_max` | 从 64 扩到 512 |
| `pool_evicts_lru_when_full` | 池满时踢最久未用，新 sid 能进 |
| `pool_kinds_are_isolated` | `udp` 池打满不影响 `link_udp` 池 |

### 10.3 单测：`agent/kudus_session.rs`

| 测试名 | 断言 |
| --- | --- |
| `udp_recv_buf_is_small` | `UDP_RECV_BUF <= 2048` |
| `udp_idle_timeout_is_5s` | `UDP_STREAM_IDLE_SECS == 5` |
| `agent_send_timeout_drops_without_hang` | 窗口堵死时发送 5s 后丢弃并计数，不永久阻塞 |

### 10.4 e2e：`tests/e2e.rs`

> **可观测性相关测试见 §15.6**（`e2e_tunnel_stats_line_emitted` 等），
> 与本节测试同批实施。

| 测试名 | 验证 |
| --- | --- |
| `e2e_udp_pool_survives_many_peers` | 1000 个不同源端口 UDP 流全部能通（旧代码 256 起拒绝） |
| `e2e_udp_pool_evicts_and_recovers` | 超 512 并发，被踢流关闭、新流能进 |

### 10.5 回归：核心

| 测试名 | 验证 |
| --- | --- |
| `retx_storm_does_not_amplify` | 模拟丢包，断言总发送字节 ≤ 原始量 × N（约束放大倍数） |

`retx_storm_does_not_amplify` 是本次事故的**核心回归用例**：旧代码同场景下发几十倍
数据，新代码必须被限制住。

## 11. 实施顺序

| 阶段 | 内容 | 依赖 |
| --- | --- | --- |
| 0a | **§15.3 RetxStats 结构 + 埋点**（先有计数器） | 无 |
| 0b | **§15.4 accept/close 降 DEBUG + per-tunnel 汇总** | 无 |
| 0c | **§15.5 journald 留存配置** | 无 |
| 1 | `RetxBuf` 重构（cap/退避/放弃） | **阶段 0a** |
| 2 | 背压 `bail!` + agent 上行超时丢包 | 阶段 1 |
| 3 | buffer 2048 + 截断检测 | 无 |
| 4 | `udp_pool.rs` 新模块 | 无 |
| 5 | 池接入 + 超时 5s | 阶段 4 |
| 6 | e2e + 回归 | 阶段 1-5 |
| 7 | **§15.3 汇总日志接入 tick**（验证放大是否被封住） | 阶段 1, 0a |

> **阶段 0a 必须先于阶段 1**：先有 `RetxStats` 计数器，阶段 1 改完才能直接用真实
> 计数验证“放大被封住”，而不是只靠单测。这是两个层合并同一个 spec 的核心收益。

每阶段独立 TDD 红→绿、独立提交，每次 `make build` + `make test` 全绿。

## 12. 关键决策记录

| 决策项 | 结论 | 理由 |
| --- | --- | --- |
| 范围 | A~J 全部一起做 | 用户决定：一次做到底 |
| RetxBuf 重构粒度 | 一次改到位，测试分开写 | 三项都在同一结构上，分开会反复改同一处 |
| 池容量策略 | 动态 64→512 | 尽量少踢活跃流；踢流是唯一丢用户数据的行为 |
| `udp`/`link_udp` | 两个独立池 | 用户决定：简单直接，互不干扰 |
| 池目标地址 | `send_to` 而非 `connect` | 同一 socket 可服务不同目标的 sid |
| buffer 大小 | 2048 + 截断检测 | 覆盖 MTU 1500，静默丢数据需可发现 |
| idle 超时 | 两端统一 5s | 用户决定 |
| 背压超时 | 30s → 5s 且 `bail!` | 30s 已证明过宽；静默继续是根本问题 |
| agent 上行超时 | 5s 后丢包（非关会话） | agent 只转发回包，丢 UDP 包是合法语义；两侧策略差异已在 §5.5 论证 |

## 13. 预期效果

| 指标 | 事故时 | 修复后 |
| --- | --- | --- |
| 重传放大倍数 | 5~40 倍 | 受 cap + 退避 + 放弃三重约束 |
| 最坏发送速率 | ≈39MB/s（无上限） | ≈25MB/s 理论上界，退避后实际远低 |
| 永不丢弃的包 | 存在 | 不存在（10 次后放弃） |
| 背压失效 | 30s 后静默继续 | 5s 后 `bail!` |
| agent 上行堆积 | 无限等待 | 5s 后丢包，不积压 |
| UDP 并发 peer | 256（超限全拒） | 512（超限踢 LRU） |
| 每流 buffer | 64KB | 2KB |
| 512 流总堆内存 | 32MB | 1MB |
| `udp`/`link_udp` | 互相饿死 | 独立池 |
| **重传放大可见性** | **零（日志查不到）** | 见 §15.10 |
| **INFO 日志量** | 800 条/分 | ~50 条/分（§15.10） |
| **日志留存** | 2 天 | 30 天（§15.5） |

> 本表只列本节（§4–§8）的效果；可观测性三层的预期效果见 **§15.10**。

## 14. 风险与未决项

1. **池满踢流对长连接的影响**：若目标服务有 >512 并发 uTP 长连接，踢 LRU 会中断活跃流。
   缓解：踢流已发 Close 且计数可观测；若实际验证并发超过 512，后续可再拆更细的分类池
   （本次已按「两个独立池」预留了按类型分池的结构）。
2. **截断检测的近似性**：只能判断 `n == buf.len()`，无法区分「恰好等于」与「真截断」。
   措辞已用 `possibly`，可接受。
3. **背压 bail 导致会话重建**：重建期 1~2s 断流。相比持续恶化，这是更优取舍，但需在
   上线后观察重建频率是否异常（埋点 `backpressure_timeout`）。
4. **agent 丢包可能影响 BT 回包送达率**：隧道拥堵时会丢 UDP 回包。对 DHT 无影响
   （本来就可丢），对 uTP 会触发对端重传。若上线后 `udp_send_dropped` 计数上升明显，
   说明限速/窗口需要重新调，需纳入观查。

---

## 15. 层 4：可观测性补强（2026-10-26 追加）

### 15.1 动机：为什么必须和止血一起做

2026-10-25 对 HK 线上（`ssh hk`，机器 `cloudserver`）154,132 行 journal 全量排查，
结论是**本次事故在日志里几乎不可见**，且日志本身有三个独立问题：

**① 核心盲区：整个重传风暴，日志里一条都没有**

```
$ journalctl -u neutrino-server | grep -icE "retx|retrans|backpressure|window"
0
```

`src/common/kudus.rs` —— kudus 可靠传输核心（`RetxBuf`/`ReorderBuf`/SACK）**零日志、
零计数器**。事后唯一线索是：

```
ratelimit stats: minipc7s/trans-bt limit=524288B/s thru=22396311B sleep=5204ms
```

而 `thru` 是 `RateLimiter::take()` 累加的**限速器经手字节**（`ratelimit.rs:71`），
重传包走 `send_pkt` **绕过限速器**，因此**重传放大在限速统计里根本不可见**。
`thru=22396311B` 只能说"限速器放行了 22MB"，无法回答"其中多少是被放大出来的"。

**② 噪音淹没：800 条/分钟里 99% 是无意义 INFO**

事故窗口逐分钟日志量：`12:00 452 条/分 → 13:30 824 条/分`（+82%），
其中几乎全是 `tcp accept` / `tcp close` **每连接各一行 INFO**（BT 短连接）。

**③ 留存不足：journal 只保 2 天**

`journalctl --disk-usage` = 4.0G，最早一条 `2026-10-21T06:05`。
`/etc/systemd/journald.conf` 未配 `SystemMaxUse`/`MaxRetentionSec`。
事故 10-23，再跑一天日志就没了。

**④ 附带发现：`Error: Address not available (os error 99)` 崩溃循环 1505 次**
（`Started` 1527 次）—— 独立问题，见 §15.6 遗留项。

**结论**：§4 的 RetxBuf 重构**必须配套埋点**，否则修完也无法证明"放大被封住了"，
下次再出问题依然查不出来。这正是本层与 §4 合并同一个 spec 的原因。

### 15.2 范围与边界

| 层 | 内容 | 是否改代码 |
| -- | ---- | ---------- |
| 4a | `RetxBuf` 加 `RetxStats` 计数器 + per-session 汇总 | Rust |
| 4b | `tcp accept/close` 降 DEBUG + per-tunnel 汇总行 | Rust |
| 4c | journald 留存配置 + `--log-file` 对 systemd 生效 | 配置 + 少量 Rust |

**不改**：任何转发语义、限速行为、协议字段、`RetxBuf` 的算法逻辑
（4a 只**加计数**，不改变重传/放弃的判定）。

### 15.3 层 4a：RetxStats 埋点

#### 数据结构

```rust
// src/common/kudus.rs
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RetxStats {
    pub sent: u64,          // take_expired 实际重发的包数
    pub abandoned: u64,     // 重传超上限被真丢弃的包数（§4.5）
    pub full: u64,          // RetxFull 拒收次数（§4.2）
    pub backlog_max: usize, // 本窗口内未确认包峰值
}

pub struct RetxBuf {
    next: u32,
    seqs: HashMap<u32, RetxEntry>,
    stats: RetxStats,       // 新增
}
```

#### 采集与归零

```rust
/// 取走本窗口统计并归零。
/// 峰值由 on_send 维护，这里只负责取走与重置。
pub fn take_stats(&mut self) -> RetxStats {
    std::mem::take(&mut self.stats)
}
// 注：len() 已存在（kudus.rs:159），不重复定义，埋点直接用它。
```

**峰值维护职责单一**：`backlog_max` 只在**会改变 `seqs.len()` 的三处**更新
（`on_send` 插入后、`take_expired` 放弃删除后保持不降、`on_ack` 不更新）。
`take_stats` 不参与峰值计算，避免两处重复跟踪导致语义歧义。

**为什么打增量而非累计**：累计值单调爬升没有诊断价值——事故里的 `thru` 就是累计值，
爬到 22.4MB 仍看不出"这一分钟发生了什么"。归零后每行日志都是**本分钟真实发生的事**。

**为什么 `backlog_max` 用峰值**：事故中积压达 8192 包，只有峰值记录才能回答
"积压到多严重"。当前瞬时值在 tick 采样时刻可能恰好是低点，会漏掉峰值。

#### 埋点位置

| 位置 | 计数 | 说明 |
| ---- | ---- | ---- |
| `on_send` 满 cap 拒绝 | `full += 1` | 对应 §4.2 的 `RetxFull` |
| `on_send` 成功插入后 | `backlog_max = max(backlog_max, seqs.len())` | 峰值唯一来源 |
| `take_expired` 每重发一包 | `sent += 1` | §4.3 的 `retx += 1` 同处 |
| 超过 `KUDUS_MAX_RETX` 丢弃 | `abandoned += 1` | §4.5 |

#### 汇总日志

挂在**现有 `traffic` tick（60s）**上，不新开 tick（`server/mod.rs:285` 附近）。
**per-session** 采集，格式：

```
kudus retx session=3f2a1b8c hostname=minipc7s sent=4821 abandoned=0 full=0 backlog_max=1024
```

**只在非零时打**（`sent+abandoned+full+backlog_max > 0`），空闲 session 零噪音。

**为什么 per-session 而非进程级全局**：破案时要回答"**哪条隧道在放大**"。
全局计数只能说"整机在放大"，依然定位不到具体隧道——而 §1.1 现场恰恰需要
区分 `trans-bt`（风暴源）与其它 19 条隧道。

### 15.4 层 4b：降噪 + per-tunnel 汇总

#### ① accept/close 降级

```rust
// src/server/ingress.rs:583 / :717
tracing::info!("tcp accept ...") → tracing::debug!("tcp accept ...")
tracing::info!("tcp close ...")  → tracing::debug!("tcp close ...")
```

单连接细节保留在 DEBUG，需要时 `RUST_LOG=neutrino=debug` 临时开。

#### ② per-tunnel 汇总（新增）

**关键设计：累加必须在"关闭时刻"做，不能 tick 扫表。**
`conns` 表在连接 close 时即 `remove`（`ingress.rs:715`），tick 时扫表只能看到
仍存活的连接。BT 短连接大量快开快关，扫表统计会**严重偏低**。

```rust
// src/server/state.rs
#[derive(Default)]
pub(crate) struct TunnelStats {
    pub accepts: u64,
    pub closes: u64,
    pub rx: u64,
    pub tx: u64,
    pub stick: u64,   // first-chunk timeout 次数
}

// Shared 新增字段：key = tunnel name
pub(crate) tunnel_stats: RwLock<HashMap<String, TunnelStats>>,
```

埋点：

| 位置 | 动作 |
| ---- | ---- |
| `ingress.rs:583` accept | `accepts += 1` |
| `ingress.rs:717` close | `closes += 1; rx += c.rx; tx += c.tx` |
| `ingress.rs:675` first-chunk timeout | `stick += 1` |

tick 时取走归零，打一行：

```
tunnel stats minipc7s/trans-bt accepts=523 closes=521 stick=2 rx=12.3MB tx=88.1MB
```

- `stick` = first-chunk timeout 次数：现场那条 `first-chunk timeout (reorder hole?)`
  高频告警，汇总成计数比刷屏更有用。
- `rx`/`tx` 用人类可读单位（`12.3MB`），日志是给人看的。
- 同样只在该隧道本窗口有活动时打。

#### ③ 预期效果

| 指标 | 事故时 | 改后 |
| ---- | ------ | ---- |
| INFO 日志量 | 800 条/分 | ~50 条/分 |
| 单连接明细 | INFO 刷屏 | DEBUG 按需 |
| 隧道级吞吐 | 无 | 每分一行 |
| 重传放大 | **不可见** | `sent`/`abandoned`/`backlog_max` 直接可读 |

### 15.5 层 4c：日志留存

#### ① journald 配置（运维，不改代码）

`/etc/systemd/journald.conf`：

```ini
[Journal]
SystemMaxUse=500M
MaxRetentionSec=30day
```

**为什么不引入 `tracing-appender` 写文件**：日志"只剩 2 天"的根因是
journald 未配上限，而非没有文件。journald 本身就是成熟的滚动+保留方案，
配好即解决。引新依赖会带来"stdout 与文件双写重复"的新问题，反而更复杂。

#### ② `--log-file` 对 systemd 生效（**本次不实现**）

现状：`--log-file` **只在 `--detach` 时被使用**（`main.rs:200` / `:219`），
systemd 下传 `--log-file` 会**静默忽略**。

**决定：本次不实现，仅修复“静默”问题**——在 systemd 模式（非 `--detach`）下
传了 `--log-file` 时打一条 `warn!` 告知“未启用，请用 journald”，避免误解。

理由：journald 已能满足留存需求（①），而真正按需写文件需要滚动/保留/双写去重，
不是 30 行内能干净做完的事。**不为假需求引复杂度。**

若将来确实需要文件日志，单独立项（引入 `tracing-appender` + 明确双写策略）。

### 15.6 测试计划（TDD，先红后绿）

#### 单测 `common/kudus.rs`

| 测试名 | 断言 |
| ------ | ---- |
| `retx_stats_counts_resends` | 连续 `take_expired` N 次，`take_stats().sent == N` |
| `retx_stats_tracks_backlog_peak` | 灌 100 包后全 ACK，`backlog_max == 100` 而非 0 |
| `retx_stats_take_resets` | 第二次 `take_stats()` 全零（含 `backlog_max`） |
| `retx_stats_counts_full` | cap 满后 `on_send` 失败，`full == 1` |
| `retx_stats_counts_abandoned` | 超 `KUDUS_MAX_RETX` 丢弃，`abandoned == 1` |

#### 单测 `server/state.rs`

| 测试名 | 断言 |
| ------ | ---- |
| `tunnel_stats_accumulate_and_drain` | 累加后 `drain` 取走得值且归零 |
| `tunnel_stats_absent_tunnel_not_emitted` | 无活动隧道不产生行 |

#### 单测 `ingress` 日志级别（纯判定）

将"该不该打 accept 日志"抽成无 IO 纯函数再测（沿用项目既有风格）：

| 测试名 | 断言 |
| ------ | ---- |
| `accept_log_level_is_debug` | 级别常量 == DEBUG（防回归被改回 INFO） |
| `log_file_warns_when_ignored` | 非 detach + 非空 log_file ⇒ 打 warn（纯判定函数 `should_warn_log_file_ignored`） |

#### e2e

| 测试名 | 验证 |
| ------ | ---- |
| `e2e_tunnel_stats_line_emitted` | 建一条隧道跑若干连接，tick 后 journal/stdout 出现 `tunnel stats <name> accepts=>0` |
| `e2e_retx_stats_visible_in_log` | 制造丢包场景，日志出现 `kudus retx ... sent=>0` |
| `e2e_no_per_conn_info_flood` | 100 次短连接，INFO 行数 < 阈值（旧代码 200 行，新代码 ~1 行汇总） |

**注意**：e2e 断言日志需读子进程 stdout，沿用现有 e2e 的子进程捕获方式；
tick 用 `boot_with_desired` 的 50ms 参数化，不盲目 `sleep`。

### 15.7 实施顺序（本层内）

| 阶段 | 内容 | 依赖 |
| ---- | ---- | ---- |
| 4a-1 | `RetxStats` 结构 + `take_stats` + 单测 | 无 |
| 4a-2 | 四处埋点接入 + 单测 | 4a-1 |
| 4a-3 | server/agent tick 汇总日志 | 4a-2, §4 完成 |
| 4b-1 | accept/close 降 DEBUG | 无 |
| 4b-2 | `TunnelStats` + 累加 + tick 汇总 | 4b-1 |
| 4c | journald 配置 + deploy 文件注释 | 无 |

**与 §11 的关系**：4a-1/4a-2 **必须在 §4（RetxBuf 重构）之前**完成，
这样 §4 改完后能**直接用真实计数器验证**放大是否被封住，而非只靠单测。
4b/4c 与本层之外无依赖，可并行。

### 15.8 关键决策记录（本层）

| 决策项 | 结论 | 理由 |
| ------ | ---- | ---- |
| 范围 | 三层全做（A+B+C） | 用户决定 |
| 与主 spec 关系 | **合并进本 spec**，一起做 | 用户决定：原 spec 尚未实施，一次做完 |
| 计数器归属 | `RetxBuf` 内部（方案 A） | per-session 精确，能定位"哪条隧道"；避免全局状态污染单测 |
| 统计语义 | 取走即归零，打增量 | 累计值无诊断价值（`thru` 即反例） |
| `backlog_max` | 记峰值不记当前值 | tick 采样可能落在低点，峰值才反映真实严重程度 |
| accept/close | 降 DEBUG + per-tunnel 汇总 | 保留可见性（汇总）又去掉刷屏（明细） |
| 汇总累加点 | **关闭时刻累加**，非 tick 扫表 | close 即 remove，扫表会严重偏低 |
| 汇总挂载点 | 现有 `traffic` tick（60s） | 不新开 tick，与 retx 汇总同一落点 |
| 留存方案 | 只配 journald，不引 `tracing-appender` | 根因是配置缺失，非缺文件；避免双写与依赖 |
| `--log-file` systemd 生效 | 可选低优先级，>30 行则放弃 | journald 已满足留存 |

### 15.9 遗留项（不在本 spec 范围）

1. **`Error: Address not available (os error 99)` 崩溃循环 1505 次**
   （`Started` 1527 次）。独立问题，需单独排查（疑似端口未释放/绑定冲突）。
   **建议作为下一个独立 spec。**
2. **`kudus drop unknown_session` 采样日志**频率偏高，是否降级待观察。

### 15.10 预期效果（本层）

| 问题 | 现状 | 改后 |
| ---- | ---- | ---- |
| 重传放大可见性 | **零** | `sent/abandoned/full/backlog_max` per-session |
| 隧道级吞吐 | 无 | 每分一行 `accepts/closes/stick/rx/tx` |
| INFO 日志量 | 800 条/分 | ~50 条/分 |
| 日志留存 | 2 天 | 30 天 |
| 下次事故破案 | 几乎不可能 | 可定位到具体隧道与放大倍数 |

---

## 16. 层 5：UDP 流生命周期可观测 + 闭环补盲（2026-10-24 追加）

### 16.1 动机

§15.4 规划了「降噪 + per-tunnel 汇总」，但实施时暴露两个更基本的问题：

1. **§15.4 的 UDP 部分未落地**。TCP/HTTP 的 `tunnel_stats` 已埋（`ec97bee`），
   UDP ingress 一处都没有——而 BT 的 UDP tracker / DHT / uTP **全走 UDP**，
   等于最重的流量在日志里不存在。
2. **「5 秒够不够」无法回答**。2026-10-24 现场追问 agent 侧
   `UDP_STREAM_IDLE_SECS=5` 是否过激，翻遍日志只能看到每分钟一行全局
   `kudus retx sent=N abandoned=N`，不知道**哪条流活了多久、为什么断**。

第 2 点揭示一个更普遍的缺陷：两个 UDP 泵的失败分支全是**静默**的
（`Ok(0) | Err(_) => break`、`.is_err() { return; }`），
socket 出错、对端拒绝、池满踢流在日志里完全不可见。

详见 [2026-10-24-udp-stream-lifecycle-blind.md](../../incidents/2026-10-24-udp-stream-lifecycle-blind.md)
与 [2026-10-24-tunnel-stats-udp-gap.md](../../incidents/2026-10-24-tunnel-stats-udp-gap.md)。

### 16.2 范围

| # | 项 | 归属 | 状态 |
| - | -- | ---- | ---- |
| 1 | agent 侧流级统计 `UdpStreamStat` + 收尾日志 | 层 5a | 已实现 |
| 2 | 两个泵的失败分支补 warn（去静默） | 层 5a | 已实现 |
| 3 | `UdpPool::summary()` 池状态可见 | 层 5a | 已实现 |
| 4 | `--udp-idle-secs` 启动参数（替代硬编码常量） | 层 5a | 已实现 |
| 5 | UDP ingress `tunnel_stats` 埋点（§15.4 补漏） | 层 5b | **待实现** |
| 6 | accept/close/udp session 全量降 DEBUG | 层 5b | tcp 已完成（`258330e`）；**udp session 待降** |
| 7 | journald 留存落地（§15.5 ①） | 运维 | **待执行** |

**不在范围**：server 侧 UDP 会话数上限（当前无上限、靠 TTL 回收，
风险见 §16.7）。

### 16.3 层 5a：agent 侧流级可观测（已实现）

#### ① `UdpStreamStat`

```rust
pub(crate) struct UdpStreamStat {
    started: Instant,
    rx_pkts: AtomicU64, rx_bytes: AtomicU64,   // ws→local 方向
    tx_pkts: AtomicU64, tx_bytes: AtomicU64,   // local→ws 方向
    truncated: AtomicU64,                       // n == UDP_RECV_BUF 的次数
    end: AtomicU8,                              // 结束原因
}
```

两侧泵各写一半（原子计数，无锁），流收尾统一汇总。

#### ② 收尾日志（DEBUG）

```
kudus udp stream closed sid=123 lived=5.02s reason=idle-timeout
  rx_pkts=3 rx_bytes=180 tx_pkts=0 tx_bytes=0 truncated=0 pool=12/64 evicted=0
```

**判读表**（直接回答「5 秒够不够」）：

| `lived` | `reason` | 含义 |
| ------- | -------- | ---- |
| ≈ idle 秒数 | `idle-timeout` | **卡在 idle 边界 → 超时太短**，应放宽 |
| 远小于 idle | `recv-err` / `send-err` | 本地目标/内核出错，与 idle 无关 |
| 任意 | `server-close` | server 主动关（正常 TTL 回收） |
| 任意 | `local-eof` | 本地 transmission 关了 socket |

`reason` 取值：`idle-timeout` / `server-close` / `send-err` / `recv-err` /
`local-eof` / `running`。

#### ③ 去静默

```rust
// local→ws
Err(e) => {
    stat.end.store(END_RECV_ERR, ..);
    tracing::warn!("kudus udp local->ws recv failed: sid={sid} err={e}");
    break;
}
// ws→local
if let Err(e) = w.send(&dg).await {
    stat.end.store(END_SEND_ERR, ..);
    tracing::warn!("kudus udp ws->local send failed: sid={sid} err={e} (rx_pkts={n})");
    return;
}
```

**关键决策：`Ok(0)` 与 `Err` 必须分开**。旧代码合并成 `Ok(0) | Err(_)`，
把「对端正常关闭」和「`ECONNREFUSED`/`ENOBUFS` 真错误」混为一谈，
事后无法区分——这是静默事故的标准写法。

#### ④ `UdpPool::summary()`

```rust
pub fn summary(&self) -> String {
    format!("{}/{} evicted={}", self.in_use.len(), self.created, self.evicted_total)
}
```

判读：`in_use` 涨到 100+ 就该警惕（**真实硬顶是内核 `SO_RCVBUF`
钳 64KB，实测并发 ≈137**，不是 `POOL_MAX=512`）；`evicted` 涨 = 已在踢 LRU。

#### ⑤ `--udp-idle-secs`

```bash
neutrino agent --server kudus://hk:36182 --config agent.toml --udp-idle-secs 60
```

```rust
pub(crate) fn resolve_udp_idle_secs(cli: u64) -> u64 {
    if cli == 0 { UDP_STREAM_IDLE_SECS } else { cli }
}
```

**为什么 `0` 回退默认而非当真**：`Duration::from_secs(0)` 在超时语义下是灾难值
——要么瞬杀全部 UDP 流，要么永不超时泄 fd（正是
[retx-storm 事故](../../incidents/2026-10-23-kudus-retx-storm.md) 的旧病根）。
误配代价太高，`0` 一律当「没传」。

server 侧早有 `--udp-session-ttl`，agent 侧却没有对应开关——**不对称本身就是缺陷信号**。

### 16.4 层 5b：UDP `tunnel_stats` 埋点（待实现）

#### ① 为什么不能 tick 扫表

`conns` 表在会话关闭时即 `remove`，tick 时扫表只能看到仍存活的连接。
BT 短连接大量快开快关，扫表统计会**严重偏低**（§15.4 ② 已论证）。
**累加必须在「关闭时刻」做。**

#### ② 旁挂表 + 对齐回收

`sessions` 元组已有 5 个字段，再塞 `stats_key` 要动所有解构模式
（`ingress.rs:899` / `:976` 等）。改用旁挂小表：

```rust
// 与 sessions 同生命周期：sid -> "hostname/proxyname"
let mut sid_stats: HashMap<u32, String> = HashMap::new();
```

**清理必须与 `sessions` 对齐**（关键决策 C）：`TTL 路径`显式删，
另外在 `sessions.retain(...)` 之后同步 `sid_stats.retain(|sid, _| live.contains(sid))`，
覆盖 agent 主动 Close（池满踢流、断线）这些不走 TTL 的路径，否则长期运行泄漏。

#### ③ 三个埋点

| 位置 | 动作 | 说明 |
| ---- | ---- | ---- |
| 新建 session（`ingress.rs:976` 插 `sessions` 前） | `accepts += 1` + 写 `sid_stats` | 语义 = **新建会话数** |
| TTL 回收（`:872` `expired_sids` 后） | **先**累加 `closes += 1` **再**删 `sid_stats` | 顺序反了查不到 key |
| `conns` 行累加点（`:930` 附近） | `rx += payload.len()` / `tx += chunk.len()` | 按 `sid_stats` 找 key |

**`accepts` 语义决策（A）**：= 新建 session 数，不是收包数。
与 TCP 的「建立连接」对等，`accepts/closes` 配对才有意义；包量由 `rx`/`tx` 字节体现。

#### ④ 降噪范围（决策 B）

| 位置 | 现状 | 动作 |
| ---- | ---- | ---- |
| `ingress.rs:624` tcp accept | 已 `debug!`（`258330e`） | 无 |
| `ingress.rs:762` tcp close | 已 `debug!`（`258330e`） | 无 |
| `ingress.rs:975` udp session | **`info!`** | → `debug!` |
| HTTP accept/close | 本就无单连接日志 | 无 |

**注意：源码降噪早已提交（`258330e`），但 HK 跑的是旧二进制**，
journald 里仍是每分钟 541 条 `tcp accept`/`tcp close` 的 INFO。
**部署新二进制即自动生效**——这次降噪的价值一半在「把已改的代码发上去」。

**为什么还要降 `udp session`**：同类日志只降一处会留下「tcp 在 debug、
udp 在 info」的不一致；`tunnel stats` 汇总行（每分一次、per-tunnel 明细）
已在 INFO 保留可见性，单连接明细本就该在 DEBUG 按需开（`RUST_LOG=neutrino=debug`）。

### 16.5 层 5c：journald 留存（运维，不改代码）

`/etc/systemd/journald.conf`：

```ini
[Journal]
SystemMaxUse=500M
MaxRetentionSec=30day
```

「日志只剩 2 天」的根因是 journald 未配上限，不是没有文件。
**不引入 `tracing-appender`**：journald 本身是成熟的滚动+保留方案，
引新依赖会带来「stdout 与文件双写重复」的新问题。

### 16.6 测试计划（TDD，先红后绿）

| # | 用例 | 类型 | 抓什么 |
| - | ---- | ---- | ------ |
| 1 | `udp_stream_stat_reason_names` | 单测 | 6 个结束原因的名字映射 |
| 2 | `udp_pool_summary_counts_in_use_and_evicted` | 单测 | `summary()` 的 in_use/created/evicted |
| 3 | `udp_idle_secs_resolves_cli_override` | 单测 | `0 → 默认`、显式值原样、两端常量相等 |
| 4 | `e2e_udp_tunnel_stats_line_emitted` | e2e | UDP 打流后 `tunnel stats <host>/<proxy> accepts>=1` |
| 5 | `ingress_accumulates_tunnel_stats` | 单测 | 现有源码字面量断言（**不可信**，见 §16.8） |

**e2e 4 的坑**：server UDP ingress 把 `SO_RCVBUF` 钳到 64KB，突发灌包在
ingress 之前就被内核丢掉，实测恒定只进 ≈137 个。用例必须**少量包或错峰发**。

**回退验证**：注释掉 UDP 的 `accepts += 1`，用例 4 必须变红。

### 16.7 关键决策记录（本层）

| # | 决策 | 理由 |
| - | ---- | ---- |
| A | `accepts` = 新建会话数，非收包数 | 与 TCP 语义对等，配对才有意义 |
| B | tcp/http/udp 三处 accept/close 全降 DEBUG | 避免同类日志级别不一致 |
| C | 旁挂表 + `sessions.retain` 后同步 retain | 覆盖 agent 主动 Close 路径，零泄漏 |
| D | `--udp-idle-secs` 的 `0` 回退默认 | `from_secs(0)` 是灾难值（瞬杀/泄 fd） |
| E | `Ok(0)` 与 `Err` 分支必须分开 | 合并即放弃区分「正常关闭 vs 真错误」 |

### 16.8 教训

1. **「能不能回答运维的追问」是日志的验收标准。** 这次不是不知道要打什么，
   而是「每分钟一行全局数字」看起来已经够了——直到有人问「5 秒够不够」
   才发现答不上来。好的日志应让**下一个问题**也能被回答。
2. **源码字面量断言会给出虚假的安全感。** `ingress_accumulates_tunnel_stats`
   在 UDP 完全空白时依然全绿（它只查 `.accepts += 1` 是否存在，不区分路径）。
   行为断言（e2e 真打流看日志行）才是唯一可信的证据。
3. **凡是运维可能要调的阈值，都别写死成常量。**
4. **池里的账要有人读。** `evicted_total` 一直在累加却从不输出，等于没埋。

### 16.9 已知风险（不在本层解决）

**server 无会话数上限 vs agent 池 512 上限的不对称**：
server `sessions` 无数量上限（只按 TTL 时间清），agent 池满 512 才踢 LRU。
若 BT 洪峰把并发推过 512，会出现「agent 踢掉 → server 还在 → peer 再发包
→ 又建」的**踢建抖动**。

当前实测 107 条，离 512 很远。层 5a 的 `pool=.../... evicted=` 日志上线后，
`evicted` 一旦开始涨即可确认。届时再评估是否加 server 侧上限。

> 另注：§15.9 遗留项 1（`Address not available` 崩溃循环 1505 次）仍未排查。
