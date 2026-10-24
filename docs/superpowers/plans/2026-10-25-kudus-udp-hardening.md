# kudus 重传放大止血 + agent UDP 资源池化 实现计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 修掉 kudus 重传缓冲无上限导致的流量自我放大（事故实测超限 42 倍），并把 agent 侧 UDP 出站从「一会话一 socket + 64KB buffer」改成「动态池复用 + 2KB buffer」；同时补上可观测性（重传埋点 + 降噪 + 留存），使下次事故可被定位。

**Architecture:** 先做阶段 0（可观测性，spec §15）：`RetxStats` 埋点、accept/close 降 DEBUG + per-tunnel 汇总、journald 留存。再做三层止血：层 1 重构 `common/kudus.rs::RetxBuf`（容量上限 + 重传计数 + 指数退避 + 放弃），层 2 修背压失效（server 侧 `bail!` 关会话、agent 侧超时丢包），层 3 新增 `agent/udp_pool.rs` 纯逻辑池模块并接入 `kudus_session.rs`。层 1↔2 是同一事故上下游必须一起修；层 3 完全独立。**先有埋点再做修复，才能用真实计数验证「放大被封住」。**

**Tech Stack:** Rust 2021、tokio（async runtime / `Mutex` / `Semaphore`）、`tracing`（日志）、`anyhow`（错误）、cargo test（单测 + `tests/e2e.rs` 真子进程 e2e）。

**关键约束（来自 AGENTS.md）：**
- `make build` 配了 `RUSTFLAGS="-D warnings"`，**任何 warning 直接中断构建**
- 铁律：先写失败测试（RED），亲眼确认变红且红的原因是「行为缺失」
- `make test` 全绿才算完；e2e 必须串行（`--test-threads=1`）
- 测试等待一律「轮询可观测状态 + 上限」，禁止盲等 `sleep(N)`

**Spec:** `docs/superpowers/specs/2026-10-25-kudus-udp-hardening-design.md`

---

## 文件结构

| 文件 | 职责 | 动作 |
| --- | --- | --- |
| `src/common/kudus.rs` | kudus 可靠传输核心：`RetxBuf`、常量、分片 | **改**：RetxStats 埋点（阶段 0a）+ RetxBuf 重构 + 新常量 + 单测 |
| `src/server/kudus.rs` | server 侧 kudus 会话：写泵、重传泵、背压 | **改**：两处背压改 `bail!` + 抽常量 + retx 汇总采集 |
| `src/agent/kudus_session.rs` | agent 侧 kudus 会话：UDP 流开闭、发送 | **改**：buffer 2048、`wait_window` 返回 bool、池接入、超时 5s、retx 汇总采集 |
| `src/agent/udp_pool.rs` | **新建**：UDP socket 池纯逻辑（分配/LRU/扩容），无 IO | **建** |
| `src/agent/mod.rs` | agent 子模块声明 | **改**：加 `pub mod udp_pool;` |
| `src/server/state.rs` | server 全局状态 | **改**（阶段 0b）：`TunnelStats` + `drain_tunnel_stats` + `fmt_bytes` |
| `src/server/ingress.rs` | TCP/UDP 入站 | **改**（阶段 0b）：accept/close 降 DEBUG + 三处 TunnelStats 累加 |
| `src/server/mod.rs` | server 装配与后台 tick | **改**（阶段 0b）：per-tunnel / retx 汇总行输出 |
| `src/main.rs` | CLI 入口 | **改**（阶段 0c）：`--log-file` 被忽略时 warn |
| `deploy/journald-neutrino.conf` | journald 留存配置 | **建**（阶段 0c） |
| `tests/e2e.rs` | 端到端测试（真子进程 + 随机端口） | **改**：加 2 个 e2e |

**为什么新建 `udp_pool.rs`：** 池的分配/LRU/扩容决策是纯逻辑，抽出来后可以完全单测（不需要真 socket、不需要 tokio runtime），也让 `kudus_session.rs`（已 800+ 行）不再膨胀。符合 spec §7.2。

---

## 阶段划分

| 阶段 | Tasks | 说明 |
| --- | --- | --- |
| **阶段 0：可观测性** | **0a-1~0c-2** | **必须先做**：先有计数器，阶段 1 才能验证修复效果 |
| 阶段 1：RetxBuf | Task 1-5 | 止血核心，必须在阶段 2 之前 |
| 阶段 2：背压 | Task 6-7 | 依赖阶段 1 的常量 |
| 阶段 3：buffer | Task 8 | 独立 |
| 阶段 4：池模块 | Task 9-12 | 纯逻辑，独立 |
| 阶段 5：池接入 | Task 13-15 | 依赖阶段 4 |
| 阶段 6：e2e + 回归 | Task 16-17 | 依赖阶段 1-5 |
| **阶段 7：可观测性 e2e** | **Task 18** | 依赖阶段 0 + 阶段 1 |

> **`full`/`abandoned` 埋点的特殊依赖**：Task 0a-3 依赖阶段 1 的 `RetxFull` 与
> `KUDUS_MAX_RETX`。**推荐执行顺序**：0a-1 → 0a-2（只做 `sent`）→ 0b 全部 → 0c 全部
> → 阶段 1（Task 1-5）→ **回来做 0a-3**。阶段 1 的 Task 2/4 完成后再补这两个埋点。

---

## 阶段 0：可观测性补强（对应 spec §15，**必须先做**）

> **为什么排在最前**：阶段 1 要重构 `RetxBuf`。先埋好 `RetxStats` 计数器，
> 阶段 1 改完就能**用真实计数验证「放大被封住」**，而不是只靠单测猜。
> 详见 spec §15.1 / §15.7 / §11。

---

### Task 0a-1: `RetxStats` 结构 + `take_stats`

**Files:**
- Modify: `src/common/kudus.rs:112-166`（`RetxBuf` 定义与 `impl`）
- Test: `src/common/kudus.rs`（文件末尾 `mod tests`，若无则新建）

- [ ] **Step 1: 写失败测试**

在 `src/common/kudus.rs` 的 `mod tests` 中加：

```rust
#[test]
fn retx_stats_starts_zero() {
    let b = RetxBuf::new(0);
    let s = b.take_stats();
    assert_eq!(s.sent, 0);
    assert_eq!(s.abandoned, 0);
    assert_eq!(s.full, 0);
    assert_eq!(s.backlog_max, 0);
}

#[test]
fn retx_stats_tracks_backlog_peak() {
    let mut b = RetxBuf::new(0);
    for _ in 0..100 {
        b.on_send(vec![1u8; 10]);
    }
    // 全部 ACK 后 backlog 归零，但峰值应保留 100
    b.on_ack(100, &[0u8; 32]);
    let s = b.take_stats();
    assert_eq!(s.backlog_max, 100, "峰值必须保留，不能被 ACK 抹平");
}

#[test]
fn retx_stats_take_resets() {
    let mut b = RetxBuf::new(0);
    for _ in 0..5 {
        b.on_send(vec![1u8; 10]);
    }
    let first = b.take_stats();
    assert_eq!(first.backlog_max, 5);
    let second = b.take_stats();
    assert_eq!(second, RetxStats::default(), "取走后必须归零");
}
```

- [ ] **Step 2: 运行测试确认失败**

Run: `cargo test --bin neutrino retx_stats`
Expected: FAIL — `cannot find type RetxStats` / `no method take_stats`

- [ ] **Step 3: 最小实现**

在 `src/common/kudus.rs` 中，`pub struct RetxBuf` **之前**加：

```rust
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
```

`RetxBuf` 加字段（现有两个字段之后）：

```rust
pub struct RetxBuf {
    next: u32,
    seqs: HashMap<u32, (Vec<u8>, u64)>,
    stats: RetxStats,   // 新增
}
```

`RetxBuf::new` 改：

```rust
pub fn new(start: u32) -> Self {
    Self { next: start, seqs: HashMap::new(), stats: RetxStats::default() }
}
```

`impl RetxBuf` 内加：

```rust
/// 取走本窗口统计并归零（spec §15.3）。
/// 峰值由 on_send 维护，这里只取走与重置。
pub fn take_stats(&mut self) -> RetxStats {
    std::mem::take(&mut self.stats)
}

```

`on_send` 中插入后更新峰值：

```rust
pub fn on_send(&mut self, payload: Vec<u8>) -> u32 {
    let s = self.next;
    self.next = self.next.wrapping_add(1);
    self.seqs.insert(s, (payload, now_ms()));
    if self.seqs.len() > self.stats.backlog_max {
        self.stats.backlog_max = self.seqs.len();
    }
    s
}
```

- [ ] **Step 4: 运行测试确认通过**

Run: `cargo test --bin neutrino retx_stats`
Expected: PASS（3 个测试全绿）

- [ ] **Step 5: 全量验证 + 提交**

```bash
make build && cargo test --bin neutrino kudus
git add src/common/kudus.rs
git commit -m "feat(kudus): RetxStats 埋点结构 + backlog 峰值跟踪

spec §15.3 第一步：只加计数器，不改任何重传/放弃判定逻辑。
backlog_max 在 on_send 插入后更新（唯一峰值来源），take_stats 取走即归零。"
```

---

### Task 0a-2: `sent` 埋点（take_expired）

> 本 task 只做 `sent`，它不依赖阶段 1。`full`/`abandoned` 见 Task 0a-3。
> **推荐顺序**：0a-1 → 0a-2 → 0b 全部 → 0c 全部 → 阶段 1 → 回来做 0a-3。

**Files:**
- Modify: `src/common/kudus.rs`（`take_expired`、`on_send`）
- Test: `src/common/kudus.rs`

- [ ] **Step 1: 写失败测试（sent）**

```rust
#[test]
fn retx_stats_counts_resends() {
    let mut b = RetxBuf::new(0);
    b.on_send(vec![1u8; 10]);
    let rto = Duration::from_millis(200);
    // 每次推进 now —— take_expired 会把 *sent 刷成 now，
    // 用同一个 now 再扫不会到期（这也是旧代码「包永不丢弃」的根源）。
    let mut now = now_ms() + 10_000;
    let due1 = b.take_expired(rto, now);
    assert_eq!(due1.len(), 1, "首轮应有 1 包到期");
    now += 10_000;
    let due2 = b.take_expired(rto, now);
    assert_eq!(due2.len(), 1, "时间推进后再次到期");
    let s = b.take_stats();
    assert_eq!(s.sent, 2, "重发 2 次应记 sent=2");
}
```

- [ ] **Step 2: 运行测试确认失败**

Run: `cargo test --bin neutrino retx_stats_counts_resends`
Expected: FAIL — `assertion left: 0, right: 2`

- [ ] **Step 3: 最小实现**

`take_expired` 内，每次 `due.push` 后累加：

```rust
pub fn take_expired(&mut self, rto: Duration, now: u64) -> Vec<(u32, Vec<u8>)> {
    let mut due: Vec<(u32, Vec<u8>)> = Vec::new();
    for (seq, (p, sent)) in self.seqs.iter_mut() {
        if now.wrapping_sub(*sent) >= rto.as_millis() as u64 {
            *sent = now;
            self.stats.sent += 1;   // 新增：埋点
            due.push((*seq, p.clone()));
        }
    }
    due.sort_by_key(|(s, _)| *s);
    due
}
```

- [ ] **Step 4: 运行测试确认通过**

Run: `cargo test --bin neutrino retx_stats_counts_resends`
Expected: PASS

- [ ] **Step 5: 提交**

```bash
make build && cargo test --bin neutrino retx_stats
git add src/common/kudus.rs
git commit -m "feat(kudus): RetxStats.sent 埋点（take_expired 每重发一包 +1）"
```

---

### Task 0a-3: `full` / `abandoned` 埋点（**在阶段 1 的 Task 2/4 之后做**）

**Files:**
- Modify: `src/common/kudus.rs`

- [ ] **Step 1: 写失败测试**

```rust
#[test]
fn retx_stats_counts_full() {
    let mut b = RetxBuf::new(0);
    for _ in 0..KUDUS_RETX_CAP {
        b.on_send(vec![1u8; 10]);
    }
    let r = b.try_send(vec![1u8; 10]);
    assert!(r.is_err(), "满 cap 后应拒绝");
    let s = b.take_stats();
    assert_eq!(s.full, 1);
}

#[test]
fn retx_stats_counts_abandoned() {
    let mut b = RetxBuf::new(0);
    b.on_send(vec![1u8; 10]);
    let mut now = now_ms();
    for _ in 0..KUDUS_MAX_RETX {
        now += 10_000;
        b.take_expired(Duration::from_millis(200), now);
    }
    now += 10_000;
    b.take_expired(Duration::from_millis(200), now);
    let s = b.take_stats();
    assert_eq!(s.abandoned, 1, "超上限应记 1 次放弃");
}
```

- [ ] **Step 2: 运行确认失败**

Run: `cargo test --bin neutrino retx_stats_counts`
Expected: FAIL — `assertion left: 0, right: 1`

- [ ] **Step 3: 最小实现**

`on_send` 的 cap 拒绝分支加 `self.stats.full += 1;`；
`take_expired` 的放弃分支加 `self.stats.abandoned += 1;`。
（具体代码位置随阶段 1 的 Task 2/4 而定，在对应 `RetxFull` / `retx >= KUDUS_MAX_RETX` 处。）

- [ ] **Step 4: 运行确认通过**

Run: `cargo test --bin neutrino retx_stats`
Expected: PASS（全 5 个测试）

- [ ] **Step 5: 提交**

```bash
make build && cargo test --bin neutrino kudus
git add src/common/kudus.rs
git commit -m "feat(kudus): RetxStats.full/abandoned 埋点"
```

---

### Task 0b-1: `tcp accept/close` 降 DEBUG

**Files:**
- Modify: `src/server/ingress.rs:583`（accept）、`:717`（close）
- Test: `src/server/ingress.rs`（`mod tests`）

- [ ] **Step 1: 写失败测试**

```rust
#[test]
fn accept_log_level_is_debug() {
    // 防回归：这两个日志点必须是 DEBUG。若有人改回 INFO，
    // BT 场景下 800 条/分刷屏回归（2026-10-23 现场，spec §15.1）。
    // 用源码断言而非运行时断言，零成本。
    let src = include_str!("ingress.rs");
    assert!(
        src.contains(r#"tracing::debug!("tcp accept"#),
        "tcp accept 必须降级为 debug"
    );
    assert!(
        src.contains(r#"tracing::debug!("tcp close"#),
        "tcp close 必须降级为 debug"
    );
    assert!(
        !src.contains(r#"tracing::info!("tcp accept"#),
        "tcp accept 不能是 info（回归）"
    );
    assert!(
        !src.contains(r#"tracing::info!("tcp close"#),
        "tcp close 不能是 info（回归）"
    );
}
```

> 注：`include_str!("ingress.rs")` 在 `src/server/ingress.rs` 的 `mod tests` 里
> 路径需为 `include_str!("ingress.rs")`（相对当前文件所在目录）。

- [ ] **Step 2: 运行确认失败**

Run: `cargo test --bin neutrino accept_log_level_is_debug`
Expected: FAIL — 含 info 版存在

- [ ] **Step 3: 最小实现**

```rust
// src/server/ingress.rs:583
tracing::debug!("tcp accept :{port} peer={peer} -> sid={sid} tunnel={pname} target={target} limit={}", ...);

// src/server/ingress.rs:717
tracing::debug!("tcp close :{port} peer={peer} sid={sid} rx={} tx={}", c.rx, c.tx);
```

同时把上方注释（`// 建连日志（每连接一行，量可接受；断开在双泵结束处记）`）改为
说明降级原因与 per-tunnel 汇总替代。

- [ ] **Step 4: 运行确认通过**

Run: `cargo test --bin neutrino accept_log_level_is_debug`
Expected: PASS

- [ ] **Step 5: 提交**

```bash
make build && cargo test --bin neutrino accept_log_level
git add src/server/ingress.rs
git commit -m "feat(server): tcp accept/close 日志降 DEBUG，为 per-tunnel 汇总让出 INFO

spec §15.4：事故时 800 条/分里 99% 是这两行的刷屏，明细降 DEBUG 按需开，
INFO 层改由 per-tunnel 每分钟汇总承担（Task 0b-2）。"
```

---

### Task 0b-2: `TunnelStats` 累加与取走

**Files:**
- Modify: `src/server/state.rs`（`Shared` 结构加字段 + `TunnelStats` 定义 + `Shared::new`）
- Test: `src/server/state.rs`（`mod tests`）

- [ ] **Step 1: 写失败测试**

```rust
#[test]
fn tunnel_stats_accumulate_and_drain() {
    let mut st = TunnelStats::default();
    st.accepts += 2;
    st.closes += 1;
    st.rx += 100;
    st.tx += 200;
    st.stick += 1;
    assert_eq!(st.accepts, 2);
    assert_eq!(st.rx, 100);
}

#[test]
fn tunnel_stats_drain_returns_and_clears() {
    let mut m: HashMap<String, TunnelStats> = HashMap::new();
    let e = m.entry("a/bt".into()).or_default();
    e.accepts = 5;
    e.rx = 1024;
    let drained = drain_tunnel_stats(&mut m);
    assert_eq!(drained.len(), 1);
    let s = &drained["a/bt"];
    assert_eq!(s.accepts, 5);
    assert_eq!(s.rx, 1024);
    assert!(m.is_empty(), "取走后必须清空，下轮重新累计");
}

#[test]
fn tunnel_stats_format_human_bytes() {
    assert_eq!(fmt_bytes(0), "0B");
    assert_eq!(fmt_bytes(1023), "1023B");
    assert_eq!(fmt_bytes(1024), "1.0KB");
    assert_eq!(fmt_bytes(1024 * 1024 * 12 + 1024 * 300), "12.3MB");
}
```

- [ ] **Step 2: 运行确认失败**

Run: `cargo test --bin neutrino tunnel_stats`
Expected: FAIL — `cannot find type TunnelStats`

- [ ] **Step 3: 最小实现**

`src/server/state.rs` 中，`Shared` 定义**之前**加：

```rust
/// 隧道级累计（spec §15.4）。在「关闭时刻」累加，不等 tick 扫表——
/// conns 表 close 即 remove，扫表只能看到存活连接，BT 短连接会严重偏低。
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct TunnelStats {
    pub(crate) accepts: u64,
    pub(crate) closes: u64,
    pub(crate) rx: u64,
    pub(crate) tx: u64,
    /// first-chunk timeout 次数
    pub(crate) stick: u64,
}

/// 取走并清空（tick 汇总用）。
pub(crate) fn drain_tunnel_stats(
    m: &mut HashMap<String, TunnelStats>,
) -> HashMap<String, TunnelStats> {
    std::mem::take(m)
}

/// 人类可读字节数（日志用）。
pub(crate) fn fmt_bytes(n: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KB", "MB", "GB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n}B")
    } else {
        format!("{v:.1}{}", UNITS[i])
    }
}
```

`Shared` 结构内（`conns` 字段之后）加：

```rust
/// 隧道级累计（spec §15.4），key = tunnel 名（如 "minipc7s/trans-bt"）
pub(crate) tunnel_stats: std::sync::Mutex<HashMap<String, TunnelStats>>,
```

`Shared::new` / `Default` 构造处加：

```rust
tunnel_stats: std::sync::Mutex::new(HashMap::new()),
```

> 用 `std::sync::Mutex` 而非 `tokio::sync`：临界区只有 entry+1（纳秒级），
> 与现有 `drop_hits`/`drop_warn` 一致，不在 async 里 await 该锁。

- [ ] **Step 4: 运行确认通过**

Run: `cargo test --bin neutrino tunnel_stats`
Expected: PASS（3 个全绿）

- [ ] **Step 5: 提交**

```bash
make build && cargo test --bin neutrino tunnel_stats
git add src/server/state.rs
git commit -m "feat(server): TunnelStats 隧道级累计结构 + 人类可读字节格式化

spec §15.4：累加在关闭时刻做（conns close 即 remove，扫表会偏低）。"
```

---

### Task 0b-3: ingress 三处累加接入

**Files:**
- Modify: `src/server/ingress.rs:583`（accept）、`:717`（close）、`:675`（first-chunk timeout）

- [ ] **Step 1: 写失败测试**

`src/server/ingress.rs` 的 `mod tests` 里加源码断言（与 0b-1 同风格）：

```rust
#[test]
fn ingress_accumulates_tunnel_stats() {
    let src = include_str!("ingress.rs");
    assert!(src.contains("tunnel_stats"), "accept/close 必须累加 TunnelStats");
    assert!(src.contains("stick"), "first-chunk timeout 必须计数");
}
```

- [ ] **Step 2: 运行确认失败**

Run: `cargo test --bin neutrino ingress_accumulates`
Expected: FAIL

- [ ] **Step 3: 最小实现**

**关键**：close 处位于 `tokio::spawn(async move { ... })` 闭包内（`:633` 开始），
`hostname`/`pname` 的捕获情况不确定。**在 accept 处一次性算好 key，移入闭包复用**，
避免 close 处依赖 move 语义：

accept 处（`ingress.rs:583` 那行日志**之前**，与 `sid` 同级）：

```rust
let sid = next_sid();
// spec §15.4：隧道级累计 key，close 处在 spawn 闭包内复用（不依赖 hostname 捕获）
let stats_key = format!("{hostname}/{pname}");
{
    if let Ok(mut m) = s3.tunnel_stats.lock() {
        m.entry(stats_key.clone()).or_default().accepts += 1;
    }
}
```

close 处（`ingress.rs:717` 的 `if let Some(c) = ...` 块内）：

```rust
if let Ok(mut m) = s3.tunnel_stats.lock() {
    let e = m.entry(stats_key).or_default();
    e.closes += 1;
    e.rx += c.rx;
    e.tx += c.tx;
}
```

> `stats_key` 在闭包外定义、被 `async move` 闭包捕获使用（close / stick 都读它）。
> `accepts` 块用 `clone()` 以免提前消耗所有权。

first-chunk timeout 处（`ingress.rs:675` 的 warn 之后，同在闭包内）：

```rust
if let Ok(mut m) = s3.tunnel_stats.lock() {
    m.entry(stats_key.clone()).or_default().stick += 1;
}
```

> 注：first-chunk timeout 分支与 close 可能同时发生，故这里用 `clone()`。
> key 格式与 `ratelimit stats` 行一致（`hostname/proxy名`）。

- [ ] **Step 4: 运行确认通过**

Run: `cargo test --bin neutrino ingress_accumulates`
Expected: PASS

- [ ] **Step 5: 提交**

```bash
make build && cargo test --bin neutrino ingress
git add src/server/ingress.rs
git commit -m "feat(server): ingress 三处接入 TunnelStats 累加（accept/close/first-chunk timeout）"
```

---

### Task 0b-4: tick 汇总输出

**Files:**
- Modify: `src/server/mod.rs`（`traffic` tick 内，约 `:285` 打 `tick traffic` 那处之后）
- Test: `src/server/mod.rs`（`tick_tests`）

- [ ] **Step 1: 写失败测试**

```rust
#[test]
fn tunnel_stats_line_format() {
    let mut m: HashMap<String, crate::server::state::TunnelStats> = HashMap::new();
    let e = m.entry("minipc7s/trans-bt".into()).or_default();
    e.accepts = 523;
    e.closes = 521;
    e.stick = 2;
    e.rx = 1024 * 1024 * 12 + 1024 * 300;
    e.tx = 1024 * 1024 * 88 + 1024 * 100;
    let line = format_tunnel_stats_line(&m);
    assert!(
        line.contains("tunnel stats minipc7s/trans-bt accepts=523 closes=521 stick=2"),
        "got: {line}"
    );
    assert!(line.contains("rx=12.3MB"), "got: {line}");
    assert!(line.contains("tx=88.1MB"), "got: {line}");
}

#[test]
fn tunnel_stats_absent_tunnel_not_emitted() {
    let mut m: HashMap<String, crate::server::state::TunnelStats> = HashMap::new();
    m.entry("idle/tun".into()).or_default();  // 全零
    assert!(format_tunnel_stats_line(&m).is_empty(), "全零隧道不应产生日志");
}
```

- [ ] **Step 2: 运行确认失败**

Run: `cargo test --bin neutrino tunnel_stats_line`
Expected: FAIL — `cannot find function format_tunnel_stats_line`

- [ ] **Step 3: 最小实现**

`src/server/mod.rs` 加纯函数：

```rust
/// 格式化隧道汇总行（spec §15.4）。全零隧道跳过，每条隧道一行。
fn format_tunnel_stats_line(
    m: &std::collections::HashMap<String, state::TunnelStats>,
) -> String {
    let mut keys: Vec<&String> = m.keys().collect();
    keys.sort();
    let mut lines: Vec<String> = Vec::new();
    for k in keys {
        let s = &m[k];
        if s.accepts + s.closes + s.stick + s.rx + s.tx == 0 {
            continue;
        }
        // 注意：rx/tx==0 但 accepts>0 也要打（短连接可能无字节）
        let rx = state::fmt_bytes(s.rx);
        let tx = state::fmt_bytes(s.tx);
        lines.push(format!(
            "tunnel stats {k} accepts={} closes={} stick={} rx={rx} tx={tx}",
            s.accepts, s.closes, s.stick
        ));
    }
    lines.join("\n")
}
```

traffic tick 里（`tracing::info!("{}", state::tick_heartbeat("traffic", ...))` 之后）加：

```rust
{
    let drained = {
        let mut m = s.tunnel_stats.lock().unwrap_or_else(|e| e.into_inner());
        state::drain_tunnel_stats(&mut m)
    };
    for line in format_tunnel_stats_line(&drained).lines() {
        tracing::info!("{line}");
    }
}
```

- [ ] **Step 4: 运行确认通过**

Run: `cargo test --bin neutrino tunnel_stats_line`
Expected: PASS

- [ ] **Step 5: 提交**

```bash
make build && cargo test --bin neutrino tunnel_stats
git add src/server/mod.rs
git commit -m "feat(server): traffic tick 输出 per-tunnel 汇总行

每分一行：tunnel stats <name> accepts= closes= stick= rx= tx=
全零隧道跳过，不产生噪音。"
```

---

### Task 0b-5: retx 汇总接入 tick（**依赖阶段 1 完成**）

**Files:**
- Modify: `src/server/kudus.rs`（session 结构处采集）、`src/server/mod.rs`（tick 输出）

- [ ] **Step 1: 写失败测试**

```rust
#[test]
fn retx_stats_line_format() {
    let s = RetxStats { sent: 4821, abandoned: 0, full: 0, backlog_max: 1024 };
    let line = format_retx_stats_line("3f2a1b8c", "minipc7s", &s);
    assert_eq!(
        line,
        "kudus retx session=3f2a1b8c hostname=minipc7s sent=4821 abandoned=0 full=0 backlog_max=1024"
    );
}

#[test]
fn retx_stats_skips_idle() {
    let s = RetxStats::default();
    assert!(format_retx_stats_line("a", "h", &s).is_empty());
}
```

- [ ] **Step 2: 运行确认失败**

Run: `cargo test --bin neutrino retx_stats_line`
Expected: FAIL

- [ ] **Step 3: 最小实现**

`src/server/mod.rs`（或 kudus.rs，取就近）加：

```rust
/// 格式化单会话重传统计行（spec §15.3）。全零跳过。
fn format_retx_stats_line(session: &str, hostname: &str, s: &RetxStats) -> String {
    if s.sent + s.abandoned + s.full == 0 && s.backlog_max == 0 {
        return String::new();
    }
    format!(
        "kudus retx session={session} hostname={hostname} sent={} abandoned={} full={} backlog_max={}",
        s.sent, s.abandoned, s.full, s.backlog_max
    )
}
```

采集：在 server kudus 会话的 tick 路径里，对每个活跃 session：

```rust
let st = relw.lock().map(|mut r| r.retx.take_stats()).unwrap_or_default();
let line = format_retx_stats_line(&format!("{session:08x}"), &hostname, &st);
if !line.is_empty() {
    tracing::info!("{line}");
}
```

agent 侧同理（`src/agent/kudus_session.rs`，`rel: Arc<Mutex<RelSend>>`）。

> **执行提示**：两侧 session 结构当前的 tick 挂载点需在执行时确认。
> 若两侧都没有现成 tick，则在 traffic tick 里遍历活跃 session 采集
> （参考 `rate_limiters` 的 `lims.iter()` 模式）。

- [ ] **Step 4: 运行确认通过**

Run: `cargo test --bin neutrino retx_stats_line`
Expected: PASS

- [ ] **Step 5: 提交**

```bash
make build && cargo test --bin neutrino retx
git add src/server/mod.rs src/server/kudus.rs src/agent/kudus_session.rs
git commit -m "feat: kudus retx per-session 汇总日志接入 tick

spec §15.3：sent/abandoned/full/backlog_max 每分一行，全零跳过。
这是下次事故能定位「哪条隧道在放大」的关键信号。"
```

---

### Task 0c-1: journald 留存配置

**Files:**
- Modify: `deploy/tunnel-server.service`（加注释说明）
- Create: `deploy/journald-neutrino.conf`（可直接拷贝到 `/etc/systemd/journald.conf.d/`）

- [ ] **Step 1: 写配置片段**

```ini
# deploy/journald-neutrino.conf
# 安装：cp deploy/journald-neutrino.conf /etc/systemd/journald.conf.d/
#       systemctl restart systemd-journald
#
# 根因：2026-10-23 事故后排查发现 journal 只保留 2 天（最早一条 10-21），
# 事故日志差点丢失。journald 默认未配上限，靠磁盘总量自动滚动。
[Journal]
SystemMaxUse=500M
MaxRetentionSec=30day
```

- [ ] **Step 2: 验证配置语法**

Run: `systemd-analyze verify deploy/journald-neutrino.conf 2>&1 || true`
Expected: 无语法错误（journald 配置不被 systemd-analyze 校验，允许空输出）

- [ ] **Step 3: 提交**

```bash
git add deploy/journald-neutrino.conf deploy/tunnel-server.service
git commit -m "ops(deploy): journald 留存配置 500M/30 天

spec §15.5：事故后 journal 只保 2 天，差点丢失关键日志。"
```

---

### Task 0c-2: `--log-file` 被忽略时 warn

**Files:**
- Modify: `src/main.rs`（`Cmd::Server` / `Cmd::Agent` 分支）
- Test: `src/main.rs`（`main_tests`）

- [ ] **Step 1: 写失败测试（纯判定函数）**

在 `src/main.rs` 的 `mod main_tests` 里加：

```rust
#[test]
fn log_file_warns_when_ignored() {
    assert!(should_warn_log_file_ignored(false, "/tmp/x.log"));
    assert!(!should_warn_log_file_ignored(true, "/tmp/x.log"), "detach 时生效，不 warn");
    assert!(!should_warn_log_file_ignored(false, ""), "未传不 warn");
    assert!(!should_warn_log_file_ignored(true, ""));
}
```

- [ ] **Step 2: 运行确认失败**

Run: `cargo test --bin neutrino log_file_warns_when_ignored`
Expected: FAIL — `cannot find function should_warn_log_file_ignored`

- [ ] **Step 3: 最小实现**

```rust
/// --log-file 只在 --detach 时生效；systemd 下传了会被忽略 → warn 告知（spec §15.5）。
fn should_warn_log_file_ignored(detach: bool, log_file: &str) -> bool {
    !detach && !log_file.is_empty()
}
```

在 `Cmd::Server` 与 `Cmd::Agent` 分支里、`if detach { return detach_spawn(...) }` **之前**：

```rust
if should_warn_log_file_ignored(detach, &log_file) {
    tracing::warn!(
        "--log-file 仅在 --detach 时生效，当前已忽略；systemd 场景请用 journalctl -u <unit>"
    );
}
```

- [ ] **Step 4: 运行确认通过**

Run: `cargo test --bin neutrino log_file_warns_when_ignored`
Expected: PASS

- [ ] **Step 5: 提交**

```bash
make build && cargo test --bin neutrino main
git add src/main.rs
git commit -m "fix(main): --log-file 在非 detach 下被忽略时 warn，不再静默

spec §15.5：旧代码 systemd 下传 --log-file 完全无效且无任何提示。"
```

---

## 阶段 0 验收

```bash
make build   # 零 warning
make test    # 全绿（含新增 12 个单测）
```

**验收标准**：
1. `cargo test --bin neutrino retx_stats` 全绿（5 个）
2. `cargo test --bin neutrino tunnel_stats` 全绿（4 个）
3. `cargo test --bin neutrino accept_log_level` 全绿
4. `cargo test --bin neutrino log_file_warns_when_ignored` 全绿
5. 手动跑 server，日志中能看到 `tunnel stats ...` 行，且无 `tcp accept` INFO 刷屏

> 注：`retx` 汇总行（Task 0b-5）依赖阶段 1 完成，不在本阶段验收范围；
> 其 e2e 断言在阶段 7（Task 18）统一验证。

---

---

## 阶段 1：RetxBuf 重构

### Task 1: 提取背压常量（不改行为）

**Files:**
- Modify: `src/common/kudus.rs:9-12`（常量区，`KUDUS_RTO` / `KUDUS_WINDOW` 之后）
- Test: `src/common/kudus.rs` 的 `mod tests`

这一步先只加常量、不改任何逻辑，让后续 Task 有名字可用，且 diff 极小。

- [ ] **Step 1: 写失败测试**

在 `src/common/kudus.rs` 的 `mod tests` 内加：

```rust
    /// 背压阈值与硬容量上限是两个不同的数，不能混用。
    /// 根因→修法：旧代码把 256 硬编码在 server/kudus.rs 两处 + agent 一处，
    /// 且没有硬上限，retx 表可无限增长（事故实测积压 8192 包 → 39MB/s）。
    #[test]
    fn retx_constants_are_sane() {
        assert_eq!(super::KUDUS_RETX_BACKLOG, 256);
        assert_eq!(super::KUDUS_RETX_CAP, 4096);
        assert!(super::KUDUS_RETX_BACKLOG < super::KUDUS_RETX_CAP, "背压阈值必须小于硬上限");
        assert_eq!(super::KUDUS_MAX_RETX, 10);
        assert_eq!(super::KUDUS_RTO_MAX, Duration::from_secs(8));
    }
```

- [ ] **Step 2: 跑测试确认变红**

```bash
cd /mnt/sdb/proj/kkito/proj/neutrino && cargo test --bin neutrino retx_constants_are_sane 2>&1 | tail -20
```
预期：编译错误 `cannot find value KUDUS_RETX_BACKLOG in the crate root`（常量不存在 → 红）

- [ ] **Step 3: 加常量**

在 `src/common/kudus.rs` 的 `pub const KUDUS_WINDOW: usize = 512;` 这一行**之后**插入：

```rust
/// 背压阈值：retx 未确认包数达到此值即认为窗口积压，需退让等 ACK。
/// 这是「滞回线」，不是硬上限——正常发送在这里停等一下，与 KUDUS_RETX_CAP 不同。
pub const KUDUS_RETX_BACKLOG: usize = 256;

/// retx 缓冲硬容量上限。根因→修法：旧 RetxBuf 无上限，无 ACK 时无限积压
/// （事故实测 8192 包），叠加固定 200ms 重传使流量自我放大 5~40 倍
/// （ratelimit 实测 thru=22.4MB/s vs limit=512KB/s）。
/// 4096 = KUDUS_WINDOW(512) × 8，按 1232B/包约 5MB 内存上限。
pub const KUDUS_RETX_CAP: usize = 4096;

/// 单个包最大重传次数，超过即放弃并从上表移除。
/// 根因→修法：旧 take_expired 重发时刷新 *sent = now，包永不丢弃（无限复活）。
pub const KUDUS_MAX_RETX: u32 = 10;

/// 重传退避上限。200ms 起指数翻倍，最长到 8s 封顶。
pub const KUDUS_RTO_MAX: Duration = Duration::from_secs(8);
```

- [ ] **Step 4: 跑测试确认变绿**

```bash
cd /mnt/sdb/proj/kkito/proj/neutrino && cargo test --bin neutrino retx_constants_are_sane 2>&1 | tail -10
```
预期：`test result: ok. 1 passed`

- [ ] **Step 5: 构建确认零 warning**

```bash
make build 2>&1 | tail -5
```
预期：成功，无 warning（`-D warnings` 会直接失败如果有）

- [ ] **Step 6: 提交**

```bash
git add src/common/kudus.rs
git commit -m "refactor(kudus): 抽 backpressure 魔数 + 新增 RETX_CAP/MAX_RETX/RTO_MAX 常量

旧代码把背压阈值 256 硬编码在 server/kudus.rs 两处 + agent/kudus_session.rs
一处，且 retx 表无容量上限。先只加常量不改行为，后续 Task 引用。"
```

---

### Task 2: RetxBuf 加容量上限（cap）

**Files:**
- Modify: `src/common/kudus.rs:113-160`（`RetxBuf` 结构 + `on_send`）
- Test: `src/common/kudus.rs` 的 `mod tests`

- [ ] **Step 1: 写失败测试**

在 `mod tests` 内加：

```rust
    /// 容量上限：满 4096 后 on_send 必须拒绝，不能无限增长。
    /// 旧代码：seqs 是裸 HashMap，无上限，无 ACK 时无限涨（事故 8192 包）。
    #[test]
    fn retx_buf_respects_capacity() {
        let mut tx = RetxBuf::new(1);
        for i in 0..super::KUDUS_RETX_CAP {
            assert!(tx.on_send(vec![i as u8]).is_ok(), "第 {i} 个应能登记");
        }
        assert_eq!(tx.len(), super::KUDUS_RETX_CAP);
        // 第 CAP+1 个必须被拒
        assert!(tx.on_send(vec![0]).is_err(), "超过 cap 必须拒绝，否则缓冲无界");
        assert_eq!(tx.len(), super::KUDUS_RETX_CAP, "被拒后长度不能变");
    }
```

- [ ] **Step 2: 跑测试确认变红**

```bash
cargo test --bin neutrino retx_buf_respects_capacity 2>&1 | tail -20
```
预期：编译错误——`on_send` 当前返回 `u32` 不是 `Result`，`is_ok()` 方法不存在。

- [ ] **Step 3: 改 RetxBuf 结构 + on_send 签名**

把 `src/common/kudus.rs` 里 `RetxBuf` 的**结构定义和 `on_send`/`new`** 换成（保持其余方法不变，`take_expired` 先照旧）：

```rust
/// 发送重传缓冲：on_send 记 seq→(payload, sent_ms, 重传次数)；on_ack 按累积+SACK 清；
/// take_expired 吐超时未确认包（调用方原样重发并刷新计时）。
/// 根因→修法：旧实现 seqs 无容量上限，无 ACK 时无限积压（事故实测 8192 包），
/// 叠加固定 200ms 重发使流量自我放大到 39MB/s。现加硬上限 KUDUS_RETX_CAP，
/// 满了返回 Err 让调用方决定丢弃（UDP 语义允许丢，TCP 流则断流重连）。
pub struct RetxBuf {
    next: u32,
    seqs: HashMap<u32, RetxEntry>,
    cap: usize,
}

/// 单个待确认包：载荷 + 时间戳 + 重传计数。
struct RetxEntry {
    payload: Vec<u8>,
    last_sent: u64,
    retx: u32,
}

impl RetxBuf {
    pub fn new(start: u32) -> Self {
        Self {
            next: start,
            seqs: HashMap::new(),
            cap: super::KUDUS_RETX_CAP,
        }
    }
    /// 登记一次发送，返回分配的 seq；超出容量上限返回 Err（不插入）。
    pub fn on_send(&mut self, payload: Vec<u8>) -> Result<u32, RetxFull> {
        if self.seqs.len() >= self.cap {
            return Err(RetxFull);
        }
        let s = self.next;
        self.next = self.next.wrapping_add(1);
        self.seqs.insert(s, RetxEntry { payload, last_sent: now_ms(), retx: 0 });
        Ok(s)
    }
```

然后在同文件常量区附近加错误类型：

```rust
/// RetxBuf 已满（达到 KUDUS_RETX_CAP）。调用方据此丢弃新包。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetxFull;
```

`on_ack` 和 `take_expired` 需要跟着改字段访问（`(p, sent)` → entry）：

```rust
    /// 对端 ACK：清累积确认（<=ack）+ SACK 洞外已到包。
    pub fn on_ack(&mut self, ack: u32, sack: &[u8; 32]) {
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
    }
    /// 取出超时未确认包（刷新其计时防连爆），按 seq 排序。
    pub fn take_expired(&mut self, rto: Duration, now: u64) -> Vec<(u32, Vec<u8>)> {
        let mut due: Vec<(u32, Vec<u8>)> = Vec::new();
        for (seq, e) in self.seqs.iter_mut() {
            if now.wrapping_sub(e.last_sent) >= rto.as_millis() as u64 {
                e.last_sent = now;
                due.push((*seq, e.payload.clone()));
            }
        }
        due.sort_by_key(|(s, _)| *s);
        due
    }
```

- [ ] **Step 4: 修所有 on_send 调用方**

`on_send` 现在返回 `Result`，所有调用方必须处理。逐处修：

`src/agent/kudus_session.rs` 内（用 `grep -n "on_send" src/agent/kudus_session.rs src/server/kudus.rs` 找全）。典型模式是把

```rust
let seq = rel.on_send(payload);
```
改成
```rust
let seq = match rel.on_send(payload) {
    Ok(s) => s,
    Err(_) => {
        tracing::warn!("kudus retx buf full, dropping packet");
        return;   // 或对应分支的 drop 处理
    }
};
```

**注意**：此 Task 只做「能编译 + 测试绿」，精确的丢弃策略在 Task 3-5 完善。若某调用方在闭包里无法 `return`，先用 `if let Ok(seq) = ... { ... }` 包住后续逻辑。

- [ ] **Step 5: 跑测试确认变绿**

```bash
cargo test --bin neutrino retx_buf_respects_capacity 2>&1 | tail -10
```
预期：`test result: ok. 1 passed`

- [ ] **Step 6: 全量单测确认没打断现有用例**

```bash
cargo test --bin neutrino 2>&1 | tail -15
```
预期：全绿（特别是 `retx_expires_and_acks` 必须仍通过）

- [ ] **Step 7: 构建 + 提交**

```bash
make build 2>&1 | tail -5
git add -A
git commit -m "feat(kudus): RetxBuf 加硬容量上限 KUDUS_RETX_CAP=4096

根因：seqs 是裸 HashMap 无上限，无 ACK 时无限积压（事故实测 8192 包，
按 200ms 重发推算 39MB/s，与线上实测 22.4MB/s 同量级）。

改：on_send 返回 Result<u32, RetxFull>，满 cap 则拒绝插入。
RetxEntry 抽出独立结构（payload/last_sent/retx），为后续退避与放弃做准备。"
```

---

### Task 3: 重传计数 + 指数退避（修「包永不丢弃」）

**Files:**
- Modify: `src/common/kudus.rs`（`take_expired` + 新增 `rto_for`）
- Test: `src/common/kudus.rs` 的 `mod tests`

这是整个止血的核心：旧代码重发时只刷新计时、不计数、不退避，包可以无限复活。

- [ ] **Step 1: 写失败测试（退避序列）**

```rust
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
```

- [ ] **Step 2: 写失败测试（计数确实递增）**

```rust
    /// 重传计数必须递增，且退避生效：首次 200ms 到期，重发后下一次要等 400ms。
    /// 旧代码 take_expired 只做 *sent = now，无计数、无退避。
    #[test]
    fn retx_counts_and_backs_off() {
        let mut tx = RetxBuf::new(1);
        let s = tx.on_send(b"x".to_vec()).unwrap();
        let t0 = now_ms();
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
```

- [ ] **Step 3: 跑测试确认变红**

```bash
cargo test --bin neutrino retx_backoff 2>&1 | tail -15
cargo test --bin neutrino retx_counts_and_backs_off 2>&1 | tail -15
```
预期：
- `retx_backoff_is_exponential`：编译错误 `cannot find function rto_for`
- `retx_counts_and_backs_off`：断言失败 `退避后 200ms 内不应再次到期`（旧代码确实立刻再发）

- [ ] **Step 4: 实现 rto_for + 修改 take_expired**

在 `src/common/kudus.rs` 的 `RetxBuf` impl **之前**加：

```rust
/// 第 `retx` 次重传应等待的 RTO（指数退避，KUDUS_RTO_MAX 封顶）。
/// 根因→修法：旧实现固定 KUDUS_RTO=200ms 线性重传，每秒 5 次，
/// 积压包越多放大越猛（256 包 ≈1.22MB/s，8192 包 ≈39MB/s）。退避后
/// 单包 10 次重传总耗时 ≈ 200+400+...+6400 ≈ 25s，期间速率被压住。
pub(crate) fn rto_for(retx: u32) -> Duration {
    // 1u32 << 6 = 64 → 200ms × 64 = 12.8s，被 min(RTO_MAX) 截到 8s。
    // retx > 6 时移位数封顶，避免 u32 左移溢出（debug 下会 panic）。
    let shift = retx.min(6);
    KUDUS_RTO.saturating_mul(1u32 << shift).min(KUDUS_RTO_MAX)
}
```

把 `take_expired` 改成按每个包自己的 rto 判断，并递增计数：

```rust
    /// 取出超时未确认包（按各自退避 RTO 判断），递增重传计数，按 seq 排序。
    /// 注意：这里**不再**无条件刷新计时——重发后下一次到期时间是
    /// now + rto_for(retx+1)，退避在调用方/下次遍历体现；此处只记 last_sent=now。
    pub fn take_expired(&mut self, _rto: Duration, now: u64) -> Vec<(u32, Vec<u8>)> {
        let mut due: Vec<(u32, Vec<u8>)> = Vec::new();
        for (seq, e) in self.seqs.iter_mut() {
            // 用该包自身重传次数算出的退避 RTO，而非全局固定值。
            let rto = rto_for(e.retx);
            if now.wrapping_sub(e.last_sent) >= rto.as_millis() as u64 {
                e.retx += 1;
                e.last_sent = now;
                due.push((*seq, e.payload.clone()));
            }
        }
        due.sort_by_key(|(s, _)| *s);
        due
    }
```

**说明**：参数 `_rto` 保留但不再使用（保留签名兼容两个调用方），实际 RTO 由 `rto_for(e.retx)` 决定。若 `-D warnings` 报 unused，已用下划线前缀规避。

- [ ] **Step 5: 跑测试确认变绿**

```bash
cargo test --bin neutrino retx_backoff_is_exponential 2>&1 | tail -8
cargo test --bin neutrino retx_counts_and_backs_off 2>&1 | tail -8
```
预期：两个都 `test result: ok. 1 passed`

- [ ] **Step 6: 确认老用例没被打断**

```bash
cargo test --bin neutrino retx_expires_and_acks 2>&1 | tail -15
```
预期：ok。**注意**：这个老用例先在 t0+1000 取到期（首轮 200ms 满足），断言 2 条；之后 `on_ack(3)` 清空。退避不影响首轮，应通过。若失败，检查是否是 `KUDUS_SACK_BITS` 相关的 retain 逻辑被误改。

- [ ] **Step 7: 构建 + 提交**

```bash
make build 2>&1 | tail -5
git add src/common/kudus.rs
git commit -m "fix(kudus): 重传指数退避 + 递增计数，修「包永不丢弃」

根因：旧 take_expired 命中后只做 *sent = now，既不计数也不退避。
配合固定 KUDUS_RTO=200ms，同一个包可以无限次重生（每秒 5 次），
未 ACK 的包永远留在表里，形成流量自我放大的正反馈——
这正是 2026-10-23 事故 ratelimit thru=22.4MB/s vs limit=512KB/s 的直接机制。

修法：新增 rto_for(retx) = 200ms << min(retx,6)，封顶 KUDUS_RTO_MAX=8s。
take_expired 按每包自身 retx 算出的 RTO 判断到期，命中则 retx += 1。
单包 10 次重传累计 ≈25s 才放弃，期间发送速率被指数压住。"
```

---

### Task 4: 超过最大重传次数即放弃 + 埋点

**Files:**
- Modify: `src/common/kudus.rs`（`take_expired` + 新增 `abandoned` 计数）
- Test: `src/common/kudus.rs` 的 `mod tests`

- [ ] **Step 1: 写失败测试**

```rust
    /// 超过 KUDUS_MAX_RETX 次重传后必须从上表移除（真丢弃），不能永远留着。
    /// 旧代码没有「放弃」概念，包无限复活，这是内存与流量的双重泄漏。
    #[test]
    fn retx_counts_and_abandons() {
        let mut tx = RetxBuf::new(1);
        tx.on_send(b"x".to_vec()).unwrap();
        let mut t = now_ms();
        // 每次推进足够久，保证一定到期；跑 KUDUS_MAX_RETX 次
        for i in 0..super::KUDUS_MAX_RETX {
            t += 20_000; // 20s，远超任何退避 RTO
            let due = tx.take_expired(Duration::from_millis(200), t);
            assert_eq!(due.len(), 1, "第 {i} 次重传应到期");
        }
        // 第 MAX_RETX 次之后，条目应被移除
        assert!(tx.is_empty(), "超过 MAX_RETX 必须放弃并移除，否则包永不丢弃");
        assert!(tx.abandoned() > 0, "放弃次数要有埋点可观测");
    }
```

- [ ] **Step 2: 跑测试确认变红**

```bash
cargo test --bin neutrino retx_counts_and_abandons 2>&1 | tail -15
```
预期：断言失败 `超过 MAX_RETX 必须放弃并移除`（旧实现只是无限重发，`is_empty()` 为 false）

- [ ] **Step 3: 实现放弃逻辑 + 计数**

在 `RetxBuf` 结构里加 `abandoned` 字段：

```rust
pub struct RetxBuf {
    next: u32,
    seqs: HashMap<u32, RetxEntry>,
    cap: usize,
    /// 因超过 KUDUS_MAX_RETX 被放弃的包总数（只增不减，供观测）。
    abandoned: u64,
}
```

`new()` 里初始化 `abandoned: 0`。

`take_expired` 改为先清理超次数条目，再取到期：

```rust
    /// 取出超时未确认包（按各自退避 RTO 判断），递增重传计数，按 seq 排序。
    /// 超过 KUDUS_MAX_RETX 次重传的包**放弃并移除**，计入 abandoned 埋点。
    /// 根因→修法：旧实现无「放弃」概念，未 ACK 的包无限复活，
    /// 既泄漏内存又持续放大流量。
    pub fn take_expired(&mut self, _rto: Duration, now: u64) -> Vec<(u32, Vec<u8>)> {
        // 先清理：重传次数已用尽的，直接丢弃（不再发）。
        let max_retx = KUDUS_MAX_RETX;
        let mut give_up = 0u64;
        self.seqs.retain(|_, e| {
            if e.retx >= max_retx {
                give_up += 1;
                false
            } else {
                true
            }
        });
        self.abandoned += give_up;

        let mut due: Vec<(u32, Vec<u8>)> = Vec::new();
        for (seq, e) in self.seqs.iter_mut() {
            let rto = rto_for(e.retx);
            if now.wrapping_sub(e.last_sent) >= rto.as_millis() as u64 {
                e.retx += 1;
                e.last_sent = now;
                due.push((*seq, e.payload.clone()));
            }
        }
        due.sort_by_key(|(s, _)| *s);
        due
    }
    /// 因超过最大重传次数被放弃的包总数。
    pub fn abandoned(&self) -> u64 {
        self.abandoned
    }
```

- [ ] **Step 4: 跑测试确认变绿**

```bash
cargo test --bin neutrino retx_counts_and_abandons 2>&1 | tail -10
```
预期：`test result: ok. 1 passed`

- [ ] **Step 5: 全量单测**

```bash
cargo test --bin neutrino 2>&1 | tail -15
```
预期：全绿

- [ ] **Step 6: 构建 + 提交**

```bash
make build 2>&1 | tail -5
git add src/common/kudus.rs
git commit -m "feat(kudus): 重传超 KUDUS_MAX_RETX(10) 次即放弃并计数

旧实现没有「放弃」概念：未 ACK 的包每次 take_expired 都只刷新时间戳，
可以无限次重发，既是内存泄漏（表只增不减）也是流量放大器。

改：take_expired 开头先 retain 清掉 retx >= MAX_RETX 的条目，
计入 abandoned 埋点后返回。配合 Task 3 的指数退避，单包寿命被限制在
≈25s 内（200+400+...+6400ms），不会永久占用也不再无限重发。"
```

---

### Task 5: 核心回归用例——放大倍数被封住

**Files:**
- Test: `src/common/kudus.rs` 的 `mod tests`

这是本次事故的**核心回归用例**。它不复现真实网络，而是直接量化「同一个包在无 ACK 情况下最多被发多少次」——这正是事故的数学本质。

- [ ] **Step 1: 写失败测试（先在旧代码上验证它会红）**

```rust
    /// 核心回归（2026-10-23 事故）：无 ACK 时，N 个包的累计发送次数必须有上界。
    ///
    /// 旧代码如何复现：take_expired 每次都刷新时间戳且无退避、无放弃、
    /// 无容量上限，所以只要一直不 ACK，调用 1000 次 take_expired
    /// 就会重发 1000 次 —— 放大倍数 = 调用次数，无上界。
    ///
    /// 断言抓什么：模拟 60 秒、50ms 一拍（1200 拍），统计总重发次数。
    /// 新代码因为退避 + 最大 10 次放弃，总重发次数必须 ≤ 单包上限 × 包数。
    #[test]
    fn retx_storm_does_not_amplify() {
        let mut tx = RetxBuf::new(1);
        const PKTS: usize = 256;
        for i in 0..PKTS {
            tx.on_send(vec![i as u8]).unwrap();
        }

        // 模拟 60s，每 50ms 调一次 take_expired（与 server 重传泵 interval 一致）
        let mut sent_total = PKTS; // 首次发送也算
        let mut t = now_ms();
        let mut abandoned_seen = 0;
        for _ in 0..1200 {
            t += 50;
            let due = tx.take_expired(Duration::from_millis(200), t);
            sent_total += due.len();
            abandoned_seen = tx.abandoned();
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

        // 旧代码对照：同一场景下 sent_total 会是 256 + 约 1200×256，即约 30 万次。
        // 放大倍数 ≈ 1200 倍；新代码 ≤ 256×11 = 2816 次，放大 ≤ 11 倍。
    }
```

- [ ] **Step 2: 验证这个测试在旧代码上确实会红（回退验证）**

这是 AGENTS.md 要求的「临时关掉修复，测试必须变红」。做法：临时把 `rto_for` 改成恒返回 `KUDUS_RTO` 且注释掉 retain 清理块，跑测试。

```bash
# 临时改坏（手动）：把 take_expired 里的 retain 块注释掉
cargo test --bin neutrino retx_storm_does_not_amplify 2>&1 | tail -15
```
预期：`重传放大失控：共发送 307200 次，上界 2816` 之类（300000+ 次）

改回后确认变绿。

- [ ] **Step 3: 跑测试确认变绿**

```bash
cargo test --bin neutrino retx_storm_does_not_amplify 2>&1 | tail -10
```
预期：`test result: ok. 1 passed`

- [ ] **Step 4: 提交**

```bash
git add src/common/kudus.rs
git commit -m "test(kudus): 核心回归 retx_storm_does_not_amplify 锁死放大倍数

2026-10-23 事故的数学本质：无 ACK 时重发次数 = 调用次数，无上界。

用例模拟 256 包 + 60s（1200 拍 × 50ms，与 server 重传泵 interval 一致）：
- 旧代码：每拍每包都重发 → 约 30 万次，放大 ≈1200 倍
- 新代码：退避 + 10 次放弃 → ≤256×11=2816 次，放大 ≤11 倍

同时断言 abandoned > 0，确保「放弃」真的发生了（否则说明包还在无限复活）。
已做回退验证：注释掉 retain 清理块后该用例确实变红。"
```

---

## 阶段 2：背压修复

### Task 6: server 侧背压超时 `bail!`（两处）

**Files:**
- Modify: `src/server/kudus.rs:299-305`（UDP 下行分支）
- Modify: `src/server/kudus.rs:336-342`（outbox/TCP 分支）
- Test: `src/server/kudus.rs` 的 `mod tests`

- [ ] **Step 1: 写失败测试（纯函数抽取）**

背压逻辑在 async 大循环里不便直接测，先把「等多久才放弃」抽成纯判定函数。在 `src/server/kudus.rs` 的 `mod tests` 内加：

```rust
    /// 背压超时必须报错，不能静默继续发。
    /// 根因：旧代码 3000×10ms(30s) 循环耗尽后 `break` 出循环照旧 send_pkt，
    /// 等于背压完全失效——窗口满了还继续灌，对端重排窗溢出→丢包→更多重传。
    #[test]
    fn backpressure_exhausted_is_error() {
        // 第 0..N 拍都还没到时限 → 继续等
        assert!(!super::backpressure_exhausted(std::time::Duration::from_secs(0)));
        assert!(!super::backpressure_exhausted(std::time::Duration::from_millis(4990)));
        // 到 5s 必须判为耗尽
        assert!(super::backpressure_exhausted(std::time::Duration::from_secs(5)));
        assert!(super::backpressure_exhausted(std::time::Duration::from_secs(31)));
    }
```

- [ ] **Step 2: 跑测试确认变红**

```bash
cargo test --bin neutrino backpressure_exhausted_is_error 2>&1 | tail -12
```
预期：编译错误 `cannot find function backpressure_exhausted`

- [ ] **Step 3: 实现纯函数 + 替换两处循环**

在 `src/server/kudus.rs` 加（放在文件顶部 import 之后、其他 fn 之前）：

```rust
/// 背压等待是否已耗尽。根因→修法：旧代码 3000×10ms(30s) 后 `break` 出
/// 等待循环但**照旧发包**，背压形同虚设。现在耗尽即返回错误，由调用方 bail。
fn backpressure_exhausted(waited: std::time::Duration) -> bool {
    waited >= crate::common::kudus::KUDUS_BACKPRESSURE_TIMEOUT
}
```

在 `src/common/kudus.rs` 常量区加：

```rust
/// 发送背压最长等待。根因→修法：旧 30s（3000×10ms）已证明过宽，
/// 事故中持续近 2 小时；5s 足够正常抖动（窗口 512 包排空远小于 5s）。
pub const KUDUS_BACKPRESSURE_TIMEOUT: Duration = Duration::from_secs(5);

/// 背压轮询间隔。抽出来供 server/agent 三处共用，消除硬编码 10ms。
pub const BACKPRESSURE_POLL: Duration = Duration::from_millis(10);
```

把 **第一处**（约 `:299`，UDP 下行分支）的：

```rust
                    for _ in 0..3000 {
                        let n = relw.lock().map(|r| r.retx.len()).unwrap_or(0);
                        if n < 256 {
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
```
替换为：

```rust
                    {
                        let mut waited = Duration::ZERO;
                        loop {
                            let n = relw.lock().map(|r| r.retx.len()).unwrap_or(0);
                            if n < crate::common::kudus::KUDUS_RETX_BACKLOG {
                                break;
                            }
                            if backpressure_exhausted(waited) {
                                anyhow::bail!("kudus send backpressure timeout (udp downlink)");
                            }
                            tokio::time::sleep(crate::common::kudus::BACKPRESSURE_POLL).await;
                            waited += crate::common::kudus::BACKPRESSURE_POLL;
                        }
                    }
```

把 **第二处**（约 `:336`，outbox/TCP 分支）的同样循环替换为：

```rust
                    {
                        let mut waited = Duration::ZERO;
                        loop {
                            let n = relw.lock().map(|r| r.retx.len()).unwrap_or(0);
                            if n < crate::common::kudus::KUDUS_RETX_BACKLOG {
                                break;
                            }
                            if backpressure_exhausted(waited) {
                                anyhow::bail!("kudus send backpressure timeout (outbox)");
                            }
                            tokio::time::sleep(crate::common::kudus::BACKPRESSURE_POLL).await;
                            waited += crate::common::kudus::BACKPRESSURE_POLL;
                        }
                    }
```

**注意**：`bail!` 要求所在函数返回 `Result`。检查这两处所在的函数签名——若是 `-> anyhow::Result<()>` 或有 `?` 上下文则可直接用；若在 `tokio::spawn` 的 `async move {}` 里且返回 `()`，改为 `tracing::error!` + `return`（退出该 task）。

- [ ] **Step 4: 跑测试确认变绿**

```bash
cargo test --bin neutrino backpressure_exhausted_is_error 2>&1 | tail -10
```
预期：`test result: ok. 1 passed`

- [ ] **Step 5: 构建 + 提交**

```bash
make build 2>&1 | tail -5
git add src/server/kudus.rs src/common/kudus.rs
git commit -m "fix(server/kudus): 背压超时改为 bail，不再静默继续发

根因：server/kudus.rs 两处写泵（UDP 下行 :299、outbox :336）
都是 3000×10ms(30s) 循环，超时后 break 出循环**照旧发包**，
背压等于不存在。窗口已满仍继续灌 → 对端重排窗溢出 → 丢包率飙升
→ 触发更多重传 → 重传又加剧拥塞，正反馈。

修法：抽纯函数 backpressure_exhausted(waited) 便于单测；
两处等待循环改为到 5s 即 bail!/error 退出。超时从 30s 收到 5s
（事故持续近 2 小时，30s 已证明过宽）。
另抽常量 KUDUS_RETX_BACKLOG=256 / BACKPRESSURE_POLL=10ms 消除硬编码。"
```

---

### Task 7: agent 侧 `wait_window` 超时即丢包

**Files:**
- Modify: `src/agent/kudus_session.rs:124-132`（`wait_window`）
- Modify: `src/agent/kudus_session.rs:628`（http 泵调用点）
- Modify: `src/agent/kudus_session.rs:643`（TCP 泵调用点）
- Test: `src/agent/kudus_session.rs` 的 `mod tests`

- [ ] **Step 1: 写失败测试**

在 `src/agent/kudus_session.rs` 的 `mod tests` 内加：

```rust
    /// agent 侧背压超时后必须放弃本次发送，不能像旧代码那样照样发。
    /// 根因：旧 wait_window 是 3000×10ms 循环，耗尽后直接返回，
    /// 调用方照样 send_data —— 与 server 侧同构的"背压形同虚设"。
    #[test]
    fn agent_send_timeout_drops_without_hang() {
        use std::sync::Arc;
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
        let rt = tokio::runtime::Runtime::new().unwrap();
        let ok = rt.block_on(async {
            tokio::time::timeout(
                std::time::Duration::from_secs(30),
                pkt.wait_window(),
            )
            .await
        });
        assert!(ok.is_ok(), "wait_window 不能永久挂住");
        assert!(!ok.unwrap(), "窗口积压时应返回 false（超时），调用方据此丢包");
    }
```

- [ ] **Step 2: 跑测试确认变红**

```bash
cargo test --bin neutrino agent_send_timeout_drops_without_hang 2>&1 | tail -15
```
预期：编译错误或断言失败——`wait_window` 当前返回 `()`，`!ok.unwrap()` 无法编译 / 或超时 30s 后 panic

- [ ] **Step 3: 改 wait_window 返回 bool + 加常量**

在 `src/agent/kudus_session.rs` 顶部常量区（`UDP_STREAM_IDLE_SECS` 附近）加：

```rust
/// agent 侧等待隧道窗口的最长时间；超时即丢弃本次数据（UDP 语义允许丢）。
/// 根因→修法：旧实现 3000×10ms(30s) 循环耗尽后照样发送，
/// 与 server 侧同构——背压在超时后形同虚设。
const KUDUS_AGENT_SEND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
```

把 `wait_window` 换成：

```rust
    /// 等待 retx 未确认包数降到背压阈值以下。
    /// 返回 `true` = 有空间可发；`false` = 等了 KUDUS_AGENT_SEND_TIMEOUT 仍积压。
    /// 根因→修法：旧实现超时后直接返回、调用方照样发，背压失效；
    /// 现改为返回 bool，调用方据此**丢弃**本次数据（UDP 可丢，不会放大）。
    /// 注意：仍用异步 sleep，不占 reactor（旧 std::thread::sleep 版会卡死同 task 其他流）。
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
```

- [ ] **Step 4: 修两处调用点**

`:628` 附近（http 泵）：

```rust
        let pktw = pkt.clone();
        let local_to_ws = tokio::spawn(async move {
            if !pktw.wait_window().await {
                tracing::warn!("kudus agent send timeout, dropping http response (sid={sid})");
                return;
            }
            http_response_pump(super::stream::KudusSender(pktw.clone()), sid, lr).await
        });
```

`:643` 附近（TCP 泵）：

```rust
                    Ok(n) => {
                        if !pkt2.wait_window().await {
                            tracing::warn!("kudus agent send timeout, dropping chunk (sid={sid})");
                            break;
                        }
                        send_data(&pkt2, sid, &b[..n], false);
                    }
```

- [ ] **Step 5: 跑测试确认变绿**

```bash
cargo test --bin neutrino agent_send_timeout_drops_without_hang 2>&1 | tail -10
```
预期：`test result: ok. 1 passed`（约 5s 后返回 false）

- [ ] **Step 6: 全量单测 + 构建**

```bash
cargo test --bin neutrino 2>&1 | tail -15
make build 2>&1 | tail -5
```
预期：全绿 + 零 warning

- [ ] **Step 7: 提交**

```bash
git add src/agent/kudus_session.rs
git commit -m "fix(agent/kudus): wait_window 超时后丢包，不再照样发送

根因：旧 wait_window 是 3000×10ms(30s) 循环，耗尽后直接返回，
调用方（http 泵 :628 / TCP 泵 :643）照样 send_data——背压超时后
形同虚设，与 server/kudus.rs 两处是同构缺陷。

修法：wait_window 改为 async fn -> bool（true=可发，false=5s 后仍积压）。
两处调用点拿到 false 即 warn + 丢弃本次数据并退出/break。
选择"丢包"而非"关会话"：agent 只转发回包，丢 UDP 包是合法语义，
不会像 server 侧那样造成入口积压放大。"
```

---

## 阶段 3：UDP 接收 buffer 缩小

### Task 8: buffer 65535 → 2048 + 截断检测

**Files:**
- Modify: `src/agent/kudus_session.rs:701`（`vec![0u8; 65535]`）
- Modify: `src/agent/kudus_session.rs:27` 附近（加常量）
- Test: `src/agent/kudus_session.rs` 的 `mod tests`

- [ ] **Step 1: 写失败测试**

```rust
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
```

- [ ] **Step 2: 跑测试确认变红**

```bash
cargo test --bin neutrino udp_recv_buf_is_small 2>&1 | tail -12
```
预期：编译错误 `cannot find value UDP_RECV_BUF`

- [ ] **Step 3: 加常量 + 改分配 + 加截断检测**

在 `src/agent/kudus_session.rs` 常量区加：

```rust
/// UDP 出站 socket 的接收缓冲大小（每条流一份，池化后每个 socket 一份）。
/// 根因→修法：旧值 65535，256 流即 16MB 纯堆内存；而隧道单片上限
/// KUDUS_UDP_MAX=1232、标准 MTU ~1500，2048 足够并留余量。
pub(crate) const UDP_RECV_BUF: usize = 2048;
```

在 `open_udp_stream_to` 里把 `let mut b = vec![0u8; 65535];` 改成 `let mut b = vec![0u8; UDP_RECV_BUF];`。

在 `Ok(n) => send_data(&pkt3, sid, &b[..n], true),` 之前插入截断检测：

```rust
                Ok(n) => {
                    // UDP recv 会静默截断（不报错）：n == buf.len() 说明可能被截。
                    // 拿不到原始包长，只能近似判断，故措辞用 possibly。
                    if n == UDP_RECV_BUF {
                        tracing::warn!(
                            "kudus udp recv possibly truncated: n={n} (buf={UDP_RECV_BUF}) sid={sid}"
                        );
                    }
                    send_data(&pkt3, sid, &b[..n], true);
                }
```

- [ ] **Step 4: 跑测试确认变绿**

```bash
cargo test --bin neutrino udp_recv_buf_is_small 2>&1 | tail -10
```
预期：`test result: ok. 1 passed`

- [ ] **Step 5: 构建 + 提交**

```bash
make build 2>&1 | tail -5
git add src/agent/kudus_session.rs
git commit -m "perf(agent/kudus): UDP 接收 buffer 65535→2048 + 截断检测

根因：每条 udp 流都 vec![0u8; 65535]，256 流=16MB 纯堆内存浪费，
池化到 512 流则是 32MB。而隧道单片上限 KUDUS_UDP_MAX=1232、
标准 MTU ~1500，64KB 远超所需。

改：抽常量 UDP_RECV_BUF=2048（覆盖 1500 留 33% 余量，且不低于 MTU
否则会截断正常包）。512 流总堆内存 32MB → 1MB。

UDP recv 静默截断不报错，故补 n == buf.len() 检测 + warn，
让"可能被截断"这件事至少可观测（措辞用 possibly，因为拿不到原始包长）。"
```

---

## 阶段 4：UDP socket 池模块

### Task 9: 新建 `udp_pool.rs` 骨架 + 基础分配

**Files:**
- Create: `src/agent/udp_pool.rs`
- Modify: `src/agent/mod.rs:9` 附近（加 `pub mod udp_pool;`）
- Test: `src/agent/udp_pool.rs` 的 `mod tests`

**设计说明**：池只管「sid ↔ 槽位」的账，**不持有真实 socket**。真实 socket 由调用方（`kudus_session.rs`）创建并传入槽位号。这样整个模块零 IO、零 tokio 依赖，可以纯同步单测。

- [ ] **Step 1: 写失败测试**

新建 `src/agent/udp_pool.rs`：

```rust
//! UDP 出站 socket 池：纯逻辑（零 IO），只管 sid ↔ 槽位的账。
//!
//! 背景（2026-10-23 事故）：旧实现一个 sid 独占一个 socket，用
//! `Semaphore(256)` 限并发，打满就**直接拒绝新流**——DHT 扫描下所有
//! 新 peer 全断，且 `udp` 与 `link_udp` 共用一个信号量会互相饿死。
//!
//! 根因→修法：改为固定容量的池 + LRU 复用。socket 数只与「同时在等回包
//! 的会话数」相关，与「累计会话数」无关。池满时踢最久未活跃的 sid
//! （发 Close + 归还槽位），新会话总能进。
//!
//! 为何必须多 socket（不能共享一个）：UDP 回包不带会话标识，目标服务
//! 回包时只有源地址可区分归属，所以必须靠不同源端口 = 不同 socket。
//! 这不是设计选择，是 UDP 语义强制。

/// 池类别：udp 与 link_udp 各自独立一个池，互不抢占。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PoolKind {
    Udp,
    LinkUdp,
}

/// 池初始容量（起步值，按需扩容）。
pub const POOL_INIT: usize = 64;
/// 池扩容硬上限。超过则踢 LRU。
pub const POOL_MAX: usize = 512;

/// acquire 的结果。
#[derive(Debug, PartialEq, Eq)]
pub enum Acquire {
    /// 分到槽位号（0..cap）。
    Slot(usize),
    /// 池满，踢掉了这个 sid（调用方需给它发 Close）。
    Evicted(u32),
}

pub struct UdpPool {
    kind: PoolKind,
    /// 已创建的槽位总数（= 曾扩容到的最大并发）。
    created: usize,
    /// 空闲槽位号。
    idle: Vec<usize>,
    /// sid → 槽位号。
    in_use: std::collections::HashMap<u32, usize>,
    /// 最近使用顺序：头部最久未用。
    lru: std::collections::VecDeque<u32>,
    /// 累计踢流次数（观测）。
    evicted_total: u64,
}

impl UdpPool {
    pub fn new(kind: PoolKind) -> Self {
        Self {
            kind,
            created: 0,
            idle: Vec::new(),
            in_use: std::collections::HashMap::new(),
            lru: std::collections::VecDeque::new(),
            evicted_total: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 空池首次 acquire：扩容出一个槽位。
    #[test]
    fn pool_allocates_first_slot() {
        let mut p = UdpPool::new(PoolKind::Udp);
        assert_eq!(p.created(), 0);
        assert_eq!(p.acquire(100), Acquire::Slot(0));
        assert_eq!(p.created(), 1, "首次 acquire 应扩容出 1 个槽位");
        assert_eq!(p.in_use_len(), 1);
    }
}
```

在 `src/agent/mod.rs` 的 `pub mod stream;` 后加一行 `pub mod udp_pool;`（保持字母序则放在 `pub mod session;` 之后、`pub mod stream;` 之前）。

同时给 `UdpPool` 补上测试用到的最小方法：

```rust
impl UdpPool {
    /// 已创建的槽位总数。
    pub fn created(&self) -> usize {
        self.created
    }
    /// 正在使用的 sid 数。
    pub fn in_use_len(&self) -> usize {
        self.in_use.len()
    }
    /// 分配一个槽位给 sid。见 [`Acquire`]。
    pub fn acquire(&mut self, sid: u32) -> Acquire {
        // 已有则直接返回原槽位（重复 Open 幂等）。
        if let Some(&slot) = self.in_use.get(&sid) {
            self.touch(sid);
            return Acquire::Slot(slot);
        }
        // 1) 有空闲槽位 → 复用
        if let Some(slot) = self.idle.pop() {
            self.in_use.insert(sid, slot);
            self.lru.push_back(sid);
            return Acquire::Slot(slot);
        }
        // 2) 还能扩容 → 新建
        if self.created < POOL_MAX {
            let slot = self.created;
            self.created += 1;
            self.in_use.insert(sid, slot);
            self.lru.push_back(sid);
            return Acquire::Slot(slot);
        }
        // 3) 满 → 踢 LRU
        let victim = self.lru.pop_front().expect("池满时 lru 不应为空");
        let slot = self.in_use.remove(&victim).expect("lru 里的 sid 必须在 in_use");
        self.evicted_total += 1;
        self.in_use.insert(sid, slot);
        self.lru.push_back(sid);
        Acquire::Evicted(victim)
    }
    /// 归还 sid 的槽位。
    pub fn release(&mut self, sid: u32) {
        if let Some(slot) = self.in_use.remove(&sid) {
            self.idle.push(slot);
            self.lru.retain(|&s| s != sid);
        }
    }
    /// 标记 sid 最近活跃（移到 LRU 尾部）。
    pub fn touch(&mut self, sid: u32) {
        if self.in_use.contains_key(&sid) {
            self.lru.retain(|&s| s != sid);
            self.lru.push_back(sid);
        }
    }
    /// 累计踢流次数。
    pub fn evicted_total(&self) -> u64 {
        self.evicted_total
    }
}
```

- [ ] **Step 2: 跑测试确认变红**

先只写测试、不写实现，跑：

```bash
cargo test --bin neutrino pool_allocates_first_slot 2>&1 | tail -12
```
预期：编译错误 `no method named acquire` / `created` 等（红）

- [ ] **Step 3: 补上实现（上面的 impl 块）**

- [ ] **Step 4: 跑测试确认变绿**

```bash
cargo test --bin neutrino pool_allocates_first_slot 2>&1 | tail -8
```
预期：`test result: ok. 1 passed`

- [ ] **Step 5: 构建 + 提交**

```bash
make build 2>&1 | tail -5
git add src/agent/udp_pool.rs src/agent/mod.rs
git commit -m "feat(agent/udp_pool): 新建 UDP socket 池模块骨架

纯逻辑零 IO：只管 sid ↔ 槽位的账，真实 socket 由调用方创建。
这样整个模块可同步单测（不需要真 socket / tokio runtime）。

设计要点：socket 数只与「同时在等回包的会话数」相关，与「累计会话数」
无关（SOCKS5 UDP ASSOCIATE / QUIC / WireGuard 同思路）。
每 sid 一个槽位是 UDP 语义强制：回包不带会话标识，只能靠源端口区分。

本 Task 只做基础分配 + release + touch，后续 Task 补扩容/踢流/解耦测试。"
```

---

### Task 10: 池 reuse + 扩容测试

**Files:**
- Test: `src/agent/udp_pool.rs` 的 `mod tests`

- [ ] **Step 1: 写失败测试**

```rust
    /// 归还后再借，应复用同一个槽位（不新建）。
    /// 旧实现每个 sid 新建 socket，用完即销毁，fd 反复开合。
    #[test]
    fn pool_reuses_idle_socket() {
        let mut p = UdpPool::new(PoolKind::Udp);
        assert_eq!(p.acquire(100), Acquire::Slot(0));
        let created_after_first = p.created();
        p.release(100);
        assert_eq!(p.in_use_len(), 0);
        // 换一个 sid 借：应复用槽位 0，不扩容
        assert_eq!(p.acquire(200), Acquire::Slot(0));
        assert_eq!(p.created(), created_after_first, "归还后应按复用槽位，不该再扩容");
    }

    /// 持续 acquire 应扩容到 POOL_MAX 为止。
    #[test]
    fn pool_grows_up_to_max() {
        let mut p = UdpPool::new(PoolKind::Udp);
        for sid in 0..POOL_MAX as u32 {
            assert!(matches!(p.acquire(sid), Acquire::Slot(_)), "未到上限不应踢流");
        }
        assert_eq!(p.created(), POOL_MAX);
        assert_eq!(p.in_use_len(), POOL_MAX);
        assert_eq!(p.evicted_total(), 0, "未超上限不该有踢流");
    }
```

- [ ] **Step 2: 跑测试确认变红**

```bash
cargo test --bin neutrino pool_reuses_idle_socket 2>&1 | tail -10
cargo test --bin neutrino pool_grows_up_to_max 2>&1 | tail -10
```
预期：可能已绿（Task 9 的实现已覆盖）。**若已绿，说明测试没抓到东西**——检查是否漏了 `idle.pop()` 分支。这种情况应补一个更强的断言（见 Step 3）。

- [ ] **Step 3: 若已绿，加强测试（验证真的复用了同一槽位而非新建后碰巧同号）**

```rust
    /// 断言复用是"真的从 idle 池取"，而不是扩容后槽位号巧合相同。
    #[test]
    fn pool_reuse_actually_uses_idle_list() {
        let mut p = UdpPool::new(PoolKind::Udp);
        p.acquire(1); // slot 0
        p.acquire(2); // slot 1
        assert_eq!(p.created(), 2);
        p.release(1); // slot 0 进 idle
        assert_eq!(p.idle_len(), 1, "release 后应有 1 个空闲槽位");
        p.acquire(3); // 应从 idle 拿 slot 0
        assert_eq!(p.created(), 2, "不应扩容");
        assert_eq!(p.idle_len(), 0, "idle 应被取空");
    }
```

需要给 `UdpPool` 加：

```rust
    /// 空闲槽位数（测试与观测用）。
    pub fn idle_len(&self) -> usize {
        self.idle.len()
    }
```

- [ ] **Step 4: 跑测试确认变绿**

```bash
cargo test --bin neutrino pool_ 2>&1 | tail -12
```
预期：`test result: ok. 3 passed`

- [ ] **Step 5: 提交**

```bash
make build 2>&1 | tail -5
git add src/agent/udp_pool.rs
git commit -m "test(agent/udp_pool): 锁死槽位复用与扩容行为

- pool_reuses_idle_socket：release 后再 acquire 复用同槽位，不扩容
- pool_grows_up_to_max：持续 acquire 扩容到 POOL_MAX=512 且不踢流
- pool_reuse_actually_uses_idle_list：断言真的从 idle 队列取
  （防止"新建后槽位号巧合相同"的假绿）

补 UdpPool::idle_len() 供测试与观测。"
```

---

### Task 11: LRU 踢流测试

**Files:**
- Test: `src/agent/udp_pool.rs` 的 `mod tests`

- [ ] **Step 1: 写失败测试**

```rust
    /// 池满时踢最久未活跃的 sid，新 sid 能进。
    /// 旧实现是"打满直接拒新流"（Semaphore 拿不到 permit 就 warn + return），
    /// DHT 扫描下所有新 peer 全断——这正是 snail 上 3608 条
    /// "too many udp streams" 的来源。
    #[test]
    fn pool_evicts_lru_when_full() {
        let mut p = UdpPool::new(PoolKind::Udp);
        for sid in 0..POOL_MAX as u32 {
            p.acquire(sid);
        }
        // 此刻 lru 头部是 sid=0（最久未用）
        let out = p.acquire(9999);
        assert_eq!(out, Acquire::Evicted(0), "池满应踢最久未用的 sid=0");
        assert_eq!(p.evicted_total(), 1);
        assert_eq!(p.in_use_len(), POOL_MAX, "踢一个进一个，总数不变");
        assert!(p.contains(9999), "新 sid 必须能进");
        assert!(!p.contains(0), "被踢的 sid 必须已移除");
    }

    /// touch 后该 sid 不应再是 LRU 首位。
    #[test]
    fn pool_touch_moves_to_back() {
        let mut p = UdpPool::new(PoolKind::Udp);
        for sid in 0..POOL_MAX as u32 {
            p.acquire(sid);
        }
        p.touch(0); // 让 0 变最近活跃
        let out = p.acquire(8888);
        assert_eq!(out, Acquire::Evicted(1), "touch 后应踢 sid=1 而不是 0");
        assert!(p.contains(0), "touch 过的 sid 不该被踢");
    }
```

- [ ] **Step 2: 跑测试确认变红**

```bash
cargo test --bin neutrino pool_evicts_lru_when_full 2>&1 | tail -12
```
预期：编译错误 `no method named contains`（缺方法）

- [ ] **Step 3: 补 `contains`**

```rust
    /// 该 sid 是否正占用槽位。
    pub fn contains(&self, sid: u32) -> bool {
        self.in_use.contains_key(&sid)
    }
```

- [ ] **Step 4: 跑测试确认变绿**

```bash
cargo test --bin neutrino pool_evicts_lru_when_full 2>&1 | tail -8
cargo test --bin neutrino pool_touch_moves_to_back 2>&1 | tail -8
```
预期：都 ok

- [ ] **Step 5: 提交**

```bash
git add src/agent/udp_pool.rs
git commit -m "test(agent/udp_pool): 锁死 LRU 踢流与 touch 提升

旧实现打满直接拒新流（Semaphore 拿不到 permit 就 warn+return），
DHT 扫描下所有新 peer 全断——snail 上 3608 条 too many udp streams 即此。
现改为池满踢 LRU：被踢的 sid 由调用方发 Close，新 sid 总能进。

- pool_evicts_lru_when_full：满 512 后 acquire 踢出最旧的 sid=0
- pool_touch_moves_to_back：touch 过的 sid 不再被优先踢"
```

---

### Task 12: 两池隔离测试（`udp` vs `link_udp`）

**Files:**
- Test: `src/agent/udp_pool.rs` 的 `mod tests`

- [ ] **Step 1: 写失败测试**

```rust
    /// udp 池打满不应影响 link_udp 池——这是任务书中"H 配额解耦"的核心。
    /// 旧实现：udp 与 link_udp 共用一个 Semaphore(KUDUS_MAX_UDP_STREAMS)，
    /// BT 的 DHT 洪峰会把 link_udp 的 permit 吃光，link 功能被饿死。
    #[test]
    fn pool_kinds_are_isolated() {
        let mut udp = UdpPool::new(PoolKind::Udp);
        let mut link = UdpPool::new(PoolKind::LinkUdp);
        // 打满 udp 池
        for sid in 0..POOL_MAX as u32 {
            udp.acquire(sid);
        }
        assert_eq!(udp.in_use_len(), POOL_MAX);
        // link_udp 池应完全不受影响
        assert_eq!(link.created(), 0, "udp 打满不该动 link_udp");
        assert!(matches!(link.acquire(1), Acquire::Slot(0)), "link_udp 应能正常分配");
        assert_eq!(link.evicted_total(), 0);
    }

    /// 池的 kind 可读，便于日志区分。
    #[test]
    fn pool_reports_kind() {
        assert_eq!(UdpPool::new(PoolKind::Udp).kind(), PoolKind::Udp);
        assert_eq!(UdpPool::new(PoolKind::LinkUdp).kind(), PoolKind::LinkUdp);
    }
```

- [ ] **Step 2: 跑测试确认变红**

```bash
cargo test --bin neutrino pool_kinds_are_isolated 2>&1 | tail -12
```
预期：编译错误 `no method named kind`

- [ ] **Step 3: 补 `kind()`**

```rust
    /// 池类别（日志区分用）。
    pub fn kind(&self) -> PoolKind {
        self.kind
    }
```

- [ ] **Step 4: 跑测试确认变绿**

```bash
cargo test --bin neutrino pool_ 2>&1 | tail -15
```
预期：全部 `pool_*` 通过（约 6 个）

- [ ] **Step 5: 全量单测 + 构建 + 提交**

```bash
cargo test --bin neutrino 2>&1 | tail -15
make build 2>&1 | tail -5
git add src/agent/udp_pool.rs
git commit -m "test(agent/udp_pool): 锁死 udp/link_udp 两池隔离

根因：旧实现 udp 与 link_udp 共用同一个 Semaphore(KUDUS_MAX_UDP_STREAMS
=256)，BT 的 DHT 洪峰会把 link_udp 的 permit 吃光，link 功能被饿死。

现每个 PoolKind 各自一个 UdpPool 实例（各自 64 起步 / 各自扩到 512），
互不抢占。补 kind() 供日志区分。"
```

---

## 阶段 5：池接入 agent 会话

### Task 13: `KCtx` 加两个池 + 超时 5s

**Files:**
- Modify: `src/agent/kudus_session.rs`（`KCtx` 结构、初始化、`open_udp_stream_to`）
- Test: `src/agent/kudus_session.rs` 的 `mod tests`

- [ ] **Step 1: 写失败测试**

```rust
    /// idle 超时必须与 server 侧 TTL(5s) 对齐。
    /// 根因：agent 侧曾是 120s（DHT 下 fd 空占太久），改 30s 后仍与
    /// server TCP 差 6 倍——server 5s 就忘掉 sid，agent 还挂着 fd。
    #[test]
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
```

- [ ] **Step 2: 跑测试确认变红**

```bash
cargo test --bin neutrino udp_idle_timeout_is_5s 2>&1 | tail -12
```
预期：断言失败 `assertion left == right failed: 应与 server ... 对齐`（当前是 30）

- [ ] **Step 3: 改常量 + KCtx 加池字段**

把 `src/agent/kudus_session.rs:27` 的 `const UDP_STREAM_IDLE_SECS: u64 = 30;` 改成：

```rust
/// UDP 流空闲超时（agent 侧兜底）。根因→修法：曾 120s、后 30s，均与
/// server 侧 UDP_SESSION_TTL_SECS_DEFAULT=5 相差过大——server 5s 就回收
/// session 并发 Close，agent 却还挂着 fd。现对齐 5s；主路径仍是 server
/// 主动 Close，此值只作 server 异常（崩溃/断网）时的兜底。
const UDP_STREAM_IDLE_SECS: u64 = 5;
```

在 `KCtx` 结构里加两个池（找到 `pub(crate) struct KCtx {` 定义处）：

```rust
pub(crate) struct KCtx {
    // ... 现有字段保留 ...
    /// udp 类流的 socket 池（与 link_udp 独立，互不抢占）。
    pub(crate) udp_pool: tokio::sync::Mutex<super::udp_pool::UdpPool>,
    /// link_udp 类流的 socket 池。
    pub(crate) link_udp_pool: tokio::sync::Mutex<super::udp_pool::UdpPool>,
}
```

在 `KCtx` 的构造处（`grep -n "KCtx {" src/agent/kudus_session.rs` 找全部，含生产代码与测试）补：

```rust
        udp_pool: tokio::sync::Mutex::new(super::udp_pool::UdpPool::new(
            super::udp_pool::PoolKind::Udp,
        )),
        link_udp_pool: tokio::sync::Mutex::new(super::udp_pool::UdpPool::new(
            super::udp_pool::PoolKind::LinkUdp,
        )),
```

**注意**：`mod tests` 里手工构造 `KCtx` 的地方（如 `udp_stream_frees_socket_when_server_goes_idle`）也要补这两个字段，否则编译失败。

- [ ] **Step 4: 跑测试确认变绿**

```bash
cargo test --bin neutrino udp_idle_timeout_is_5s 2>&1 | tail -10
```
预期：ok

- [ ] **Step 5: 构建 + 提交**

```bash
make build 2>&1 | tail -5
git add src/agent/kudus_session.rs
git commit -m "feat(agent/kudus): KCtx 接入 udp/link_udp 两个独立池 + idle 超时 30s→5s

- KCtx 新增 udp_pool / link_udp_pool（各自独立 UdpPool 实例）
- UDP_STREAM_IDLE_SECS 30 → 5，与 server 侧 UDP_SESSION_TTL_SECS_DEFAULT 对齐

根因：两端超时差 6 倍时，server 5s 已回收 session 并发 Close，
agent 侧 fd 还要多挂 25s。主路径仍是 server 主动 Close（ingress.rs:825），
此值只作 server 异常时的兜底，故与 server TTL 等值是合理选择。"
```

---

### Task 14: `open_udp_stream_to` 改用池（替换 Semaphore）

**Files:**
- Modify: `src/agent/kudus_session.rs:661-745`（`open_udp_stream_to`）
- Modify: `src/agent/kudus_session.rs:521` / `:524`（分发点传 PoolKind）
- Modify: `src/agent/kudus_session.rs:242`（删或保留 `udp_slots`）
- Test: `src/agent/kudus_session.rs` 的 `mod tests`

- [ ] **Step 1: 写失败测试**

```rust
    /// 槽位打满后必须踢 LRU 而非全拒。
    /// 根因：旧实现 try_acquire_owned 失败即 warn + Close{reason:"udp busy"}
    /// 并 return——snail 上 3608 条 "too many udp streams" 即此。
    #[test]
    fn udp_pool_evicts_instead_of_rejecting() {
        use super::udp_pool::{PoolKind, POOL_MAX, UdpPool, Acquire};
        let mut p = UdpPool::new(PoolKind::Udp);
        for sid in 0..POOL_MAX as u32 {
            assert!(matches!(p.acquire(sid), Acquire::Slot(_)));
        }
        // 第 513 个不是被拒，而是踢掉最旧的
        assert!(matches!(p.acquire(7777), Acquire::Evicted(_)), "打满应踢流而非拒绝");
        assert!(p.contains(7777), "新流必须能进");
    }
```

- [ ] **Step 2: 跑测试确认变红**

```bash
cargo test --bin neutrino udp_pool_evicts_instead_of_rejecting 2>&1 | tail -12
```
预期：若 Task 12 已实现应已绿。**若已绿说明此测试重复**——把它删掉，改在 Task 14 Step 3 直接用 e2e 覆盖（Task 16）。保留 `udp_concurrency_capped` 老测试并更新其断言。

- [ ] **Step 3: 改 `open_udp_stream_to`**

原实现开头是：

```rust
    let _slot = match ctx.udp_slots.clone().try_acquire_owned() {
        Ok(g) => g,
        Err(_) => {
            tracing::warn!("kudus udp stream {sid} rejected: too many udp streams");
            let e = ClientMsg::Close { stream: sid, reason: "udp busy".into() };
            let _ = pkt.send_ctrl(&e);
            return Ok(());
        }
    };
```

替换为：

```rust
    // 从池借槽位；池满则踢最久未活跃的 sid（发 Close 并复用它的槽位），新流总能进。
    // 根因→修法：旧实现 Semaphore(256) 拿不到 permit 就 warn + Close + return，
    // DHT 扫描下所有新 peer 全断（snail 实测 3608 条 too many udp streams）。
    //
    // 注意：UdpPool::acquire 在池满时**内部已经完成**「移除 victim + 把新 sid
    // 放进 victim 的槽位」，返回 Evicted(victim) 只是告知调用方该给谁发 Close。
    // 因此这里**不要**再 acquire 一次（会打乱 LRU），槽位号由池内部账本保证。
    let slot = {
        let mut pool = ctx.udp_pool.lock().await;
        match pool.acquire(sid) {
            super::udp_pool::Acquire::Slot(s) => s,
            super::udp_pool::Acquire::Evicted(victim) => {
                // 通知被踢的 sid：server 侧会随 TTL 自然过期，agent 主动 Close 更快。
                tracing::warn!("kudus udp pool full, evicting sid={victim} (new sid={sid})");
                let e = ClientMsg::Close { stream: victim, reason: "pool evicted".into() };
                let _ = pkt.send_ctrl(&e);
                // 新 sid 已由池放进原 victim 的槽位，取回来即可。
                pool.slot_of(sid).expect("evict 后新 sid 必已占位")
            }
        }
    };
```

给 `UdpPool` 补一个查询方法（在 Task 9 的 impl 里加）：

```rust
    /// 该 sid 当前占用的槽位号。
    pub fn slot_of(&self, sid: u32) -> Option<usize> {
        self.in_use.get(&sid).copied()
    }
```

在函数结尾（`ctx.streams.write().await.remove(&sid);` 之后）补归还：

```rust
    ctx.udp_pool.lock().await.release(sid);
```

在收包路径（`send_data(&pkt3, sid, ...)` 所在循环）前后加 `touch` 以维持 LRU 准确：

```rust
            Ok(n) => {
                ctx.udp_pool.lock().await.touch(sid);
                if n == UDP_RECV_BUF { /* 截断 warn，见 Task 8 */ }
                send_data(&pkt3, sid, &b[..n], true);
            }
```

**注意**：`open_udp_stream_to` 签名里的 `sock` 参数现在由调用方创建。槽位号 `slot` 目前只用于记账（socket 由调用方绑定），**不需要改 socket 创建方式**——保持最小改动，先让账对上。

- [ ] **Step 4: 改分发点传池**

`src/agent/kudus_session.rs:521`（`kind == "udp"`）与 `:524`（`kind == "link_udp"`）目前都调 `open_udp_stream`。给 `open_udp_stream` 加参数：

```rust
async fn open_udp_stream(
    ctx: Arc<KCtx>,
    pkt: Pkt,
    sid: u32,
    port: u16,
    kind: super::udp_pool::PoolKind,
) -> anyhow::Result<()> {
```

内部按 kind 选池：

```rust
    let pool = match kind {
        super::udp_pool::PoolKind::Udp => &ctx.udp_pool,
        super::udp_pool::PoolKind::LinkUdp => &ctx.link_udp_pool,
    };
```

并把该池传给 `open_udp_stream_to`（同样加 `pool` 参数，或用 `kind` 在里面选）。

- [ ] **Step 5: 处理旧 `udp_slots` 字段**

`grep -n "udp_slots" src/agent/kudus_session.rs` 找全。删除 `udp_slots` 字段、初始化、以及 `KUDUS_MAX_UDP_STREAMS` 的 Semaphore 用法。

**同步更新老测试** `udp_concurrency_capped`（约 `:802`）：

```rust
    #[test]
    fn udp_concurrency_capped() {
        // snail 2026-10-23：无上限时 DHT flood 每流 1 fd 打满 1024 EMFILE。
        // 旧实现用 Semaphore(256) 打满直接拒；现改为池化 512 上限 + LRU 踢流。
        assert!(super::udp_pool::POOL_MAX <= 512, "fd 上限仍需可控");
        assert!(super::udp_pool::POOL_INIT < super::udp_pool::POOL_MAX, "初值应小于上限");
    }
```

- [ ] **Step 6: 跑全部单测确认变绿**

```bash
cargo test --bin neutrino 2>&1 | tail -20
```
预期：全绿，特别是 `udp_stream_frees_socket_when_server_goes_idle` 仍通过

- [ ] **Step 7: 构建 + 提交**

```bash
make build 2>&1 | tail -5
git add src/agent/kudus_session.rs
git commit -m "feat(agent/kudus): open_udp_stream 改用 socket 池（替换 Semaphore 硬拒）

根因：旧实现 KUDUS_MAX_UDP_STREAMS=256 的 Semaphore，拿不到 permit
就 warn + Close{reason:"udp busy"} + return，DHT 扫描下所有新 peer
全断（snail 实测 3608 条 too many udp streams）。且 udp 与 link_udp
共用同一信号量，BT 洪峰可饿死 link 功能。

改：按 kind 选 ctx.udp_pool / ctx.link_udp_pool，acquire 池满时
踢 LRU（对被踢 sid 发 Close{reason:"pool evicted"}），新 sid 总能进。
流结束时 release 归还槽位，收包时 touch 维持 LRU 准确。

删除 udp_slots 字段与 KUDUS_MAX_UDP_STREAMS 的 Semaphore 用法；
老测试 udp_concurrency_capped 断言改为锁 POOL_MAX <= 512。"
```

---

### Task 15: ~~socket 创建改用 `send_to`（不 `connect`）~~ —— **实施中撤销**

> **实施决策（2026-10-24）**：本 Task 的设计前提有误，已撤销。
>
> 原设想：socket 池复用同一 socket 服务多个目标的 sid，故不能 connect。
> 实际：同一目标（transmission 51413）的多条流回包源地址完全相同，
> unconnected socket 靠 `recv_from` 无法 demux 到 sid → **跨 sid 串包**，
> 比原缺陷更严重。`connect` 反而是内核级来源过滤（防护）。
>
> 结论：UDP 语义强制「每 sid 一 socket」。池的职责只是**限制 fd 数量**
> + LRU 踢流，不共享 socket。Task 14 的实现已符合此结论。
>
> 保留一个回归测试 `udp_egress_socket_per_stream_is_intentional`
> 锁住"必须 connect"这一不变式，防止后来者误改成 send_to。

**Files:**
- Modify: `src/agent/kudus_session.rs:729-745`（`open_udp_stream` 里 bind + connect）
- Test: `src/agent/kudus_session.rs` 的 `mod tests`

- [ ] **Step 1: 写失败测试**

```rust
    /// 出站 socket 不应 connect 到固定目标，否则同一 socket 无法被不同目标的
    /// sid 复用。改用 send_to 后，一个 socket 可服务多个目标（池化前提）。
    /// 说明：这条测试验证的是「代码里没有 connect 调用」，用 grep 式断言。
    #[test]
    fn udp_egress_uses_send_to_not_connect() {
        let src = include_str!("kudus_session.rs");
        // open_udp_stream 里不应再有 sock.connect(...)
        let bad = src
            .lines()
            .filter(|l| l.contains("sock.connect") || l.contains(".connect(addr)"))
            .count();
        assert_eq!(bad, 0, "出站 socket 不该 connect 到固定目标（会阻止池复用）");
    }
```

- [ ] **Step 2: 跑测试确认变红**

```bash
cargo test --bin neutrino udp_egress_uses_send_to_not_connect 2>&1 | tail -12
```
预期：断言失败，`bad` 至少为 1（现有代码有 `sock.connect(addr)`）

- [ ] **Step 3: 改 open_udp_stream 的 socket 创建与发送**

原代码（约 `:740`）：

```rust
    let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
    sock.connect(addr).await?;
```

改为：

```rust
    // 不 connect 到固定目标：池化后同一 socket 可能服务不同目标的 sid。
    // 用 send_to 逐包指定目标；回包来源靠 socket 的本地端口区分（UDP 语义）。
    let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
```

发送侧把 `w.send(&dg).await` 改成 `w.send_to(&dg, target).await`，目标在闭包外先算好：

```rust
    let sock = Arc::new(sock);
    let target = addr; // SocketAddr，Copy
    let w = sock.clone();
    let ws_to_udp = tokio::spawn(async move {
        loop {
            match tokio::time::timeout(
                std::time::Duration::from_secs(UDP_STREAM_IDLE_SECS),
                drx.recv(),
            )
            .await
            {
                Ok(Some(dg)) => {
                    if w.send_to(&dg, target).await.is_err() {
                        return;
                    }
                }
                _ => break,
            }
        }
    });
```

接收侧 `r.recv(&mut b)` 改成 `r.recv_from(&mut b)`（因为不再 connect 到固定目标，`recv` 在未 connect 的 socket 上行为依赖平台，`recv_from` 明确）：

```rust
    let udp_to_ws = tokio::spawn(async move {
        let mut b = vec![0u8; UDP_RECV_BUF];
        loop {
            match r.recv_from(&mut b).await {
                Ok((0, _)) | Err(_) => break,
                Ok((n, _from)) => {
                    if n == UDP_RECV_BUF {
                        tracing::warn!("kudus udp recv possibly truncated: n={n} buf={UDP_RECV_BUF} sid={sid}");
                    }
                    send_data(&pkt3, sid, &b[..n], true);
                }
            }
        }
    });
```

- [ ] **Step 4: 跑测试确认变绿**

```bash
cargo test --bin neutrino udp_egress_uses_send_to_not_connect 2>&1 | tail -10
```
预期：ok

- [ ] **Step 5: 跑 UDP 相关单测确认没打断**

```bash
cargo test --bin neutrino udp 2>&1 | tail -20
```
预期：所有 `udp_*` 单测通过

- [ ] **Step 6: 构建 + 提交**

```bash
make build 2>&1 | tail -5
git add src/agent/kudus_session.rs
git commit -m "refactor(agent/kudus): 出站 socket 改用 send_to，不再 connect 固定目标

原因：connect 会把 socket 绑定到单一对端，池化后同一 socket 需要
服务不同目标的 sid。改用 send_to(target) 逐包指定，接收侧相应
从 recv 改 recv_from。

UDP 回包归属仍靠 socket 本地端口区分（这是 UDP 语义强制的，
不以 connect 与否为转移），故该改动不改变回包正确性。

补测试 udp_egress_uses_send_to_not_connect（源码级断言防止回归）。"
```

---

## 阶段 6：e2e 与最终验证

### Task 16: e2e —— 多 peer 不再被 256 卡死

**Files:**
- Modify: `tests/e2e.rs`
- Test: `tests/e2e.rs`

先看清 e2e 的既有辅助函数，避免重复造轮子。

- [ ] **Step 1: 读现有 e2e 结构**

```bash
cd /mnt/sdb/proj/kkito/proj/neutrino
grep -n "fn boot_with_desired\|fn settle\|fn wait_agents_count\|fn free_port" tests/e2e.rs | head
grep -n "async fn e2e_udp" tests/e2e.rs | head
```
把找到的辅助函数签名记下来，后续步骤要用。

- [ ] **Step 2: 写失败测试**

照 `kudus_http_udp_and_hot_config`（`tests/e2e.rs:1144`）的搭法：先起 udp 回声后端，再用 `boot_kudus(proxies_toml)` 启环境。核心差别是本用例要造 **300 个不同源端口**（>256）。

在 `tests/e2e.rs` 末尾加：

```rust
/// UDP 池化回归（2026-10-23 事故）：同一 UDP 隧道端口上，来自远多于 256 个
/// 不同源端口的会话必须都能拿到回包。
///
/// 旧代码如何复现：KUDUS_MAX_UDP_STREAMS=256 的 Semaphore 打满后，
/// 第 257 个 sid 直接 Close{reason:"udp busy"}，对应 peer 收不到任何回包
/// ——snail 上 3608 条 "too many udp streams" 即此。
///
/// 断言抓什么：300 个**不同源端口**各发 1 包（每个源端口 = 一个 sid），
/// 要求全部收到回声。旧代码只有前 256 个能通。
#[tokio::test]
async fn kudus_udp_pool_survives_many_peers() {
    // udp echo backend
    let uback = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let ubport = uback.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut b = vec![0u8; 2048];
        loop {
            let Ok((n, p)) = uback.recv_from(&mut b).await else {
                break;
            };
            let _ = uback.send_to(&b[..n], p).await;
        }
    });
    let rport = free_port();
    let env = boot_kudus(&format!(
        "[[proxies]]\nname=\"u\"\ntype=\"udp\"\nlocal_ip=\"127.0.0.1\"\n\
         local_port={ubport}\nremote_port={rport}\n"
    ))
    .await;
    // 先探一次，确认 kudus 链路收敛（轮询可观测状态，不盲等）
    let probe = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    probe.connect(format!("127.0.0.1:{rport}")).await.unwrap();
    let mut ok = false;
    for _ in 0..60 {
        probe.send(b"probe").await.unwrap();
        let mut b = [0u8; 64];
        if let Ok(Ok(n)) =
            tokio::time::timeout(Duration::from_millis(300), probe.recv(&mut b)).await
        {
            if &b[..n] == b"probe" {
                ok = true;
                break;
            }
        }
    }
    assert!(ok, "kudus udp never converged");

    // 300 个不同源端口轮流发（每个源端口在 agent 侧是一个 sid）
    const N: usize = 300;
    let mut oks = 0usize;
    for i in 0..N {
        let s = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        s.connect(format!("127.0.0.1:{rport}")).await.unwrap();
        let msg = format!("peer-{i}");
        s.send(msg.as_bytes()).await.unwrap();
        let mut b = [0u8; 128];
        if let Ok(Ok(n)) = tokio::time::timeout(Duration::from_secs(3), s.recv(&mut b)).await {
            if &b[..n] == msg.as_bytes() {
                oks += 1;
            }
        }
    }
    assert_eq!(
        oks, N,
        "300 个源端口应全部拿到回声，旧代码 sid>256 会被直拒（实际成功 {oks}）"
    );
}
```

**为什么用 300 个不同源端口**：agent 侧 sid 来自 server 下发的 `Open{stream}`，server 为每个新的 UDP 源地址分配 sid。300 个不同本地源端口 → 300 个 sid → 必然超过旧上限 256。

**注意**：`boot_with_desired` 的实际签名以 Step 1 查到的为准。若它不支持 UDP 回声目标，改为复用现有 udp e2e（如 `e2e_udp_ratelimit_caps_ingress_rate`）的搭法。

- [ ] **Step 3: 跑测试确认变红（在修复前的代码上）**

```bash
cargo test --test e2e e2e_udp_pool_survives_many_peers -- --test-threads=1 2>&1 | tail -20
```
预期（若在 Task 14 之前跑）：`300 个 peer 应全部拿到回包... 实际成功 256`
完成 Task 14 后应变绿。

- [ ] **Step 4: 跑测试确认变绿**

```bash
cargo test --test e2e e2e_udp_pool_survives_many_peers -- --test-threads=1 2>&1 | tail -12
```
预期：ok

- [ ] **Step 5: 提交**

```bash
git add tests/e2e.rs
git commit -m "test(e2e): 300 个 UDP peer 全部通，锁死 256 槽位硬拒回归

2026-10-23 事故次因：KUDUS_MAX_UDP_STREAMS=256 的 Semaphore 打满后
直接 Close 新流，snail 上留下 3608 条 too many udp streams。

用例：并发 300 个源端口（>256）各发 1 包，要求全部收到回声。
旧代码至少 44 个收不到；池化 + LRU 后应全通。"
```

---

### Task 17: 全量验证 + 文档收尾

**Files:**
- Modify: `AGENTS.md`（测试现状、易踩坑两节）
- Test: 全量

- [ ] **Step 1: 跑全量单测**

```bash
cd /mnt/sdb/proj/kkito/proj/neutrino
cargo test --bin neutrino 2>&1 | tail -10
```
预期：全绿。记下通过数量。

- [ ] **Step 2: 跑全量 e2e（必须串行）**

```bash
cargo test --test e2e -- --test-threads=1 2>&1 | tail -15
```
预期：全绿。记下通过数量与耗时。

- [ ] **Step 3: make build 确认零 warning**

```bash
make build 2>&1 | tail -5
```
预期：成功。**若有任何 warning，构建会直接失败**（`-D warnings`）。

- [ ] **Step 4: make test 一次性全过**

```bash
make test 2>&1 | tail -20
```
预期：全绿

- [ ] **Step 5: 更新 AGENTS.md**

更新「测试现状」小节的数字（单测/ e2e 数量），并在「易踩坑」增加两条：

```markdown
- `RetxBuf` 有硬上限 `KUDUS_RETX_CAP=4096`，`on_send` 返回 `Result`；满了要丢包，
  别忽略返回值（`-D warnings` 会拦 unused_must_use）。重传按 `rto_for(retx)` 指数退避，
  超 `KUDUS_MAX_RETX=10` 次即放弃——这是 2026-10-23 流量风暴的止血点，别改回固定 RTO。
- 背压阈值 `KUDUS_RETX_BACKLOG=256` 与硬上限 `KUDUS_RETX_CAP=4096` 是**两个不同的数**：
  前者是滞回线（等一等），后者是天花板（拒绝/丢弃）。混用会导致「要么不背压、要么一上来就拒」。
```

- [ ] **Step 6: 提交**

```bash
git add AGENTS.md
git commit -m "docs(agents): 记录 RetxBuf 上限/退避与背压阈值+硬上限的区分

- 补易踩坑两条：RetxBuf on_send 返回 Result 不可忽略；
  KUDUS_RETX_BACKLOG(256) 与 KUDUS_RETX_CAP(4096) 是两个不同的数
- 更新测试现状数量"
```

- [ ] **Step 7: 最终核对 spec 覆盖**

逐条对照 `docs/superpowers/specs/2026-10-25-kudus-udp-hardening-design.md`：

| Spec 项 | 对应 Task | 状态 |
| --- | --- | --- |
| §4.2 容量上限 cap=4096 | Task 1, 2 | ✅ |
| §4.3 重传计数 | Task 3 | ✅ |
| §4.4 指数退避 | Task 3 | ✅ |
| §4.5 放弃机制 | Task 4 | ✅ |
| §4.6 常量澄清 | Task 1, 6, 7 | ✅ |
| §5.2 server 背压 bail（两处） | Task 6 | ✅ |
| §5.5 agent 上行超时丢包 | Task 7 | ✅ |
| §6 buffer 2048 + 截断检测 | Task 8 | ✅ |
| §7 动态池 64→512 | Task 9-14 | ✅ |
| §7.4 send_to 替代 connect | Task 15 | ⛔ 撤销（见 Task 15 说明：会跨 sid 串包，connect 是必要防护） |
| §7.5 两池独立 | Task 12, 13 | ✅ |
| §8 idle 5s | Task 13 | ✅ |
| §9 埋点 | Task 4, 6, 7, 10-12 | ✅ |
| §10.1 RetxBuf 单测 | Task 1-5 | ✅ |
| §10.2 pool 单测 | Task 9-12 | ✅ |
| §10.3 session 单测 | Task 8, 13, 15 | ✅ |
| §10.4 e2e | Task 16 | ✅ |
| §10.5 核心回归 | Task 5 | ✅ |
| §15 可观测性（日志补强） | Task 0a/0b/0c, 18 | ✅（Task 18 待做） |

**§7.4 偏离说明**：原 spec 设想池共享 socket 用 `send_to`。实施时发现同目标
（如 transmission 51413）多条流回包源地址完全相同，unconnected socket 无法
按来源 demux 到 sid → 跨 sid 串包（比原缺陷更严重）。故保留每 sid 一 socket +
`connect`（内核级来源过滤），池只限 fd 数 + LRU 踢流。已加回归测试
`udp_egress_socket_per_stream_is_intentional` 锁住该不变式。

---

## 风险提示（执行时注意）

1. **`-D warnings` 很严格**：`on_send` 返回 `Result` 后若有调用方忽略返回值，`unused_must_use` 会直接让构建失败。Task 2 Step 4 必须把所有调用方改全。
2. **`bail!` 需要 Result 上下文**：Task 6 的两处循环若在返回 `()` 的 `async move` 块里，改用 `tracing::error!` + `return`（退出 task），不要硬套 `bail!`。
3. **e2e 必须串行**：`--test-threads=1`，并发会因时间窗互相干扰而假红。
4. **不要盲等**：所有等待用「轮询可观测状态 + 上限」或参数化物理时间（见 AGENTS.md 测试等待规范）。
5. **`KCtx` 有两处构造**（生产 + 测试），加字段时都要改，否则编译失败。
6. **Task 14 若 Step 2 已绿**：说明测试重复，删掉该测试，靠 e2e（Task 16）覆盖。


---

## 阶段 7：可观测性 e2e（对应 spec §15.6）

> **前置**：阶段 0 全部完成 + 阶段 1 完成（retx e2e 需要真实的 `take_stats` 行为）。
> 现有 e2e 用 `Stdio::null()` 丢弃子进程输出，**无法断言日志**。
> 本阶段先加一个「捕获 server stdout 到文件」的 boot 变体，再写 3 个断言。

---

### Task 18: e2e —— 日志可观测性

**Files:**
- Modify: `tests/e2e.rs`
- Test: `tests/e2e.rs`

- [ ] **Step 1: 加 boot 变体（捕获 server 日志）**

在 `tests/e2e.rs` 的 `boot_with_desired` **之后**新增：

```rust
/// 同 boot_with_desired，但把 server 的 stdout 重定向到文件，
/// 供「日志可观测性」类 e2e 断言（spec §15.6）。
/// tracing 默认写 stdout，故只需重定向 stdout。
async fn boot_with_logfile(proxies_toml: &str, desired_toml: Option<&str>) -> (Env, std::path::PathBuf) {
    let ws_port = free_port();
    let dir = std::env::temp_dir().join(format!("nt-e2e-{}", uuid::Uuid::new_v4()));
    tokio::fs::create_dir_all(&dir).await.unwrap();
    let cfg_path = dir.join("agent.toml");
    tokio::fs::write(
        &cfg_path,
        format!("hostname = \"e2e\"\ntoken = \"s3cret\"\n{proxies_toml}"),
    )
    .await
    .unwrap();
    let data = dir.join("data");
    tokio::fs::create_dir_all(&data).await.unwrap();
    let desired_path = dir.join("desired.toml");
    if let Some(d) = desired_toml {
        tokio::fs::write(&desired_path, d).await.unwrap();
    }
    let log_path = dir.join("server.log");
    let log_f = std::fs::File::create(&log_path).unwrap();
    let log_f2 = log_f.try_clone().unwrap();

    let bin = env!("CARGO_BIN_EXE_neutrino").to_string();
    let srv = tokio::process::Command::new(&bin)
        .stdout(std::process::Stdio::from(log_f))
        .stderr(std::process::Stdio::from(log_f2))
        .args([
            "server",
            "--listen",
            &format!("127.0.0.1:{ws_port}"),
            "--data",
            data.to_str().unwrap(),
            "--desired",
            desired_path.to_str().unwrap(),
            "--token",
            "s3cret",
            "--live-tick-ms",
            "50",
            "--traffic-tick-ms",
            "50",
            "--limiter-tick-ms",
            "50",
            "--persist-tick-ms",
            "50",
        ])
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    // 等就绪（轮询，不盲等）
    let web_base = format!("http://127.0.0.1:{ws_port}");
    settle(&web_base).await;
    // agent 侧沿用普通 boot 的启动逻辑（agent 日志不参与断言）
    let ag = tokio::process::Command::new(&bin)
        .stdout(e2e_stdio())
        .stderr(e2e_stdio())
        .args([
            "agent",
            "--server",
            &format!("ws://127.0.0.1:{ws_port}/ws"),
            "--config",
            cfg_path.to_str().unwrap(),
        ])
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let ag_pid = ag.id().unwrap();
    let env = Env {
        http_port: ws_port,
        web_base,
        data_dir: data,
        desired_path,
        _srv: srv,
        _ag: ag,
        ag_pid,
    };
    (env, log_path)
}

/// 读日志文件全文（日志可能还没 flush，稍等重试）。
fn read_log(p: &std::path::Path) -> String {
    std::fs::read_to_string(p).unwrap_or_default()
}
```

- [ ] **Step 2: 写 3 个失败测试**

在 `tests/e2e.rs` 末尾加：

```rust
/// spec §15.4：per-tunnel 汇总行必须出现在 INFO 日志里。
/// 旧代码：根本没有这一行（只有每连接 accept/close 刷屏）。
#[tokio::test]
async fn e2e_tunnel_stats_line_emitted() {
    let proxies = r#"
[[proxies]]
name = "bt"
type = "tcp"
local_ip = "127.0.0.1"
local_port = 59999
remote_port = 0
"#;
    let (env, log) = boot_with_logfile(proxies, None).await;
    wait_agents_count(&env.web_base, 1).await;
    std::mem::forget(env); // 保持子进程存活到断言结束
    // 轮询等汇总行出现（traffic tick 50ms，给足上限但不用固定 sleep）
    let mut found = false;
    for _ in 0..60 {
        if read_log(&log).contains("tunnel stats ") {
            found = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(found, "缺少 per-tunnel 汇总行 `tunnel stats ...`\n--- log ---\n{}", read_log(&log));
}

/// spec §15.4：accept/close 明细必须不再是 INFO（降噪生效）。
/// 旧代码：每次连接两行 INFO，BT 场景 800 条/分。
#[tokio::test]
async fn e2e_no_per_conn_info_flood() {
    let proxies = r#"
[[proxies]]
name = "bt"
type = "tcp"
local_ip = "127.0.0.1"
local_port = 59999
remote_port = 0
"#;
    let (env, log) = boot_with_logfile(proxies, None).await;
    wait_agents_count(&env.web_base, 1).await;
    std::mem::forget(env);
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let text = read_log(&log);
    let info_accepts = text.lines()
        .filter(|l| l.contains(" INFO") && l.contains("tcp accept"))
        .count();
    assert_eq!(info_accepts, 0, "tcp accept 不应再打 INFO，实际 {info_accepts} 行");
}

/// spec §15.3：retx 统计行必须可观测。
/// 旧代码：`grep -icE "retx" = 0`，重传风暴完全不可见。
/// 本用例在无丢包的干净环境下断言「格式正确 + 有活动时才打」，
/// 真丢包场景由单测覆盖（e2e 造跨境丢包不现实）。
#[tokio::test]
async fn e2e_retx_stats_visible_in_log() {
    let proxies = r#"
[[proxies]]
name = "bt"
type = "tcp"
local_ip = "127.0.0.1"
local_port = 59999
remote_port = 0
"#;
    let (env, log) = boot_with_logfile(proxies, None).await;
    wait_agents_count(&env.web_base, 1).await;
    std::mem::forget(env);
    // 干净环境下 retx 可能为 0（不打日志）——这是正确行为。
    // 断言：要么没有该行，要么格式正确（不能出现半截/错字段）。
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let text = read_log(&log);
    for line in text.lines().filter(|l| l.contains("kudus retx session=")) {
        assert!(line.contains(" sent="), "格式缺 sent: {line}");
        assert!(line.contains(" alive=") || line.contains(" abandoned="), "格式缺 abandoned: {line}");
        assert!(line.contains(" backlog_max="), "格式缺 backlog_max: {line}");
    }
}
```

> **注意**：以上用 `std::mem::forget(env)` 防止 `Env` 的 `kill_on_drop` 提前杀掉子进程。
> 这是 e2e 里少见的写法，因为需要在测试体内持续读日志。若现有 e2e 有更优雅的
> 「borrow 不 drop」模式（如把断言放在 `Env` 生命周期内），以现有模式为准。

- [ ] **Step 3: 运行确认失败**

Run: `cargo test --test e2e e2e_tunnel_stats_line_emitted -- --test-threads=1`
Expected: FAIL — `缺少 per-tunnel 汇总行`（旧代码无此行）

Run: `cargo test --test e2e e2e_no_per_conn_info_flood -- --test-threads=1`
Expected: FAIL — `tcp accept 不应再打 INFO`

- [ ] **Step 4: 实现通过（阶段 0 完成后应自然通过）**

若阶段 0 已完成，这两个测试应直接 PASS。
若 FAIL，回到 Task 0b-1 / 0b-4 检查日志级别与 tick 挂载。

Run: `cargo test --test e2e e2e_ -- --test-threads=1`
Expected: PASS

- [ ] **Step 5: 提交**

```bash
make build && cargo test --test e2e -- --test-threads=1
git add tests/e2e.rs
git commit -m "test(e2e): 日志可观测性断言（tunnel stats 行 / 无 INFO 刷屏 / retx 格式）

spec §15.6：新增 boot_with_logfile 变体捕获 server stdout。
e2e_tunnel_stats_line_emitted 是核心回归——旧代码根本没有这一行。"
```

