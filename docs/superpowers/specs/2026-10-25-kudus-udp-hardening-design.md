# kudus 重传放大止血 + agent UDP 资源池化设计

日期：2026-10-25 · 状态：brainstorming 已确认（A~J 全部项，只动 neutrino）。

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

- 改：`src/common/kudus.rs`（RetxBuf 重构）、`src/server/kudus.rs`（背压 bail）、
  `src/agent/kudus_session.rs`（buffer / 池接入 / 超时）、
  `src/agent/udp_pool.rs`（**新模块**）
- 不动：kudus 加密与帧格式、`ClientMsg`/`ServerMsg` 协议字段、WSS/QUIC 传输、
  限速器语义、egress 出口选择逻辑、server 侧 UDP session 表（TTL 逻辑已修）

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
    first_sent: Instant,   // 首发时刻，退避计算基准
    last_sent: Instant,    // 实际发送时刻
    retx: u32,             // 已重传次数
}

struct RetxBuf {
    map: BTreeMap<u64, RetxEntry>,   // seq → entry
    cap: usize,                       // 新增：容量上限
    next_expiry: Option<Instant>,
}
```

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

### 4.6 效果对比

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
| **agent 侧**（本节） | agent → HK 隧道窗口满 | **无限等待**（`wait_window` 无超时） | **5s 后丢弃该回包** |

#### 问题

`agent/kudus_session.rs:124` 的 `wait_window` 当前无超时：窗口满就 sleep 后重试，
永远等下去。上行数据的来源是 transmission 的回包，虽然量小于下行，
但若 HK 长期不腾窗口，回包会在内存里**持续积压**。

#### 修复：超时后丢包（而非关会话）

```rust
pub const KUDUS_AGENT_SEND_TIMEOUT: Duration = Duration::from_secs(5);

match tokio::time::timeout(KUDUS_AGENT_SEND_TIMEOUT, wait_window()).await {
    Ok(()) => { /* 正常发送 */ }
    Err(_) => {
        // 隧道拥堵：丢弃这个 UDP 回包。UDP 语义允许丢包，
        // 对端会重传或放弃，不会造成协议错误。
        stats.udp_send_dropped += 1;
        warn_sampled("kudus agent send timeout, dropping udp reply (sid={sid})");
    }
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
| 1 | `RetxBuf` 重构（cap/退避/放弃） | 无 |
| 2 | 背压 `bail!` + agent 上行超时丢包 | 阶段 1 |
| 3 | buffer 2048 + 截断检测 | 无 |
| 4 | `udp_pool.rs` 新模块 | 无 |
| 5 | 池接入 + 超时 5s | 阶段 4 |
| 6 | e2e + 回归 | 阶段 1-5 |

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
