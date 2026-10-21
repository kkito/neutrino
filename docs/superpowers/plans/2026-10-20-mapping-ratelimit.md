# 映射级 sleep 限速 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** tcp/udp/link 映射支持 `rate_limit` 总量下行限速（sleep 截流），不限速路径零开销。

**Architecture:** `ProxyConfig.rate_limit: Option<String>`（desired 唯一源头）；纯函数 `parse_rate_limit`（字符串→B/s）+ `throttle_sleep`（算 sleep 量）+ `RateWindow`（映射级共享 1s 滑动窗口）；server 侧三处下行泵（tcp ingress `to_agent`、udp 收包、link 双泵）经共享 limiter sleep；WebUI 表单加限速输入框走现有 desired 落盘。

**Tech Stack:** Rust (tokio time sleep, `tokio::sync::Mutex`), axum WebUI (`web/index.html`), serde/TOML `ProxyConfig`。

## Global Constraints

- TDD：先写失败测试（RED），亲眼见红且是行为缺失，再最小实现（GREEN）。
- `make build`（`RUSTFLAGS="-D warnings"` 零 warning）+ `make test`（单测+e2e）全绿才提交。
- 纯判定逻辑抽纯函数再测；注释写清根因→修法。
- 非法 rate 值忽略当不限速 + 一条 warn，绝不炸 server；零限速时泵路径零额外开销（分支跳过）。
- e2e 时间断言用轮询+上限，不用固定 sleep 赌竞态（本计划 e2e 传 2MB 耗时断言是下限比较，天生无竞态）。

---

## File Structure

- Modify: `src/common/proto.rs` — `ProxyConfig` 加 `rate_limit: Option<String>`（`#[serde(default)]`），加纯函数 `parse_rate_limit(&str) -> Option<u64>`；所有 `ProxyConfig{}` 字面量补 `rate_limit: None`。
- Create: `src/server/ratelimit.rs` — 纯函数 `throttle_sleep(chunk: usize, limit_bps: u64, elapsed: Duration) -> Duration` + `RateWindow`（1s 滑动窗口：`tick(bytes) -> Duration`）+ `RateLimiter`（`limit_bps + Mutex<RateWindow>`，`take(n) -> Duration` 纯算 + 调用方 sleep）+ `Shared` 侧 `limiter_map: HashMap<String, Arc<RateLimiter>>` 访问 helper（key=`traffic_key(hostname,name)`）。
- Modify: `src/server/state.rs` — `Shared` 加 `rate_limiters: RwLock<HashMap<String, Arc<crate::server::ratelimit::RateLimiter>>>`；`ConnInfo` 不动（`tunnel` 名即 limiter key 一半）。
- Modify: `src/server/mod.rs` — `pub mod ratelimit;`。
- Modify: `src/server/ingress.rs` — tcp `to_agent` 泵（公网→agent 方向）加限速：连接建立时按 `port` 查 `(hostname, proxy)` 快照取 `rate_limit`，解析出 `Some(bps)` 才建/取 limiter，每块 `read` 后 `sleep` 再 `send`；`from_agent` 不动。udp `recv_from → send` 路径同样（按 `port` 查表，整包为一块）。
- Modify: `src/server/tunnel.rs` — link 双泵 `a2e`/`e2a` 双向共用同一 limiter（link 双端都在 server，无本地 socket，上下行都吃 VPS 带宽；总量语义）。
- Modify: `src/server/api.rs` — `validate_proxy` 放行 `link` 类型（当前 `match` 无 `link` 分支，WebUI 存 link 会 400；本计划顺手补 `"tcp"|"https"|"udp"|"link"`）；`rate_limit` 非法不拒绝（忽略+warn，不进 `validate_proxy` 拒绝路径）；`api_tunnels` 输出加 `rate_limit` 字段；WebUI 单测追加断言。
- Modify: `web/index.html` — type 表单加限速输入框（tcp/udp/link 可见，http 隐藏），`curProxy/saveForm/editRow` 透传，tunnels 表加限速列。
- Test: `src/common/proto.rs` mod tests（解析），`src/server/ratelimit.rs` mod tests（sleep+窗口），`tests/e2e.rs`（限速 vs 不限速对照）。

---

### Task 1: proto 字段 + 速率解析纯函数

**Files:**
- Modify: `src/common/proto.rs:56-86`（结构体 + 新函数）
- Test: `src/common/proto.rs` mod tests

**Interfaces:**
- Consumes: 现有 `ProxyConfig` serde（`#[serde(default)]` 模式）。
- Produces: `pub rate_limit: Option<String>` + `pub fn parse_rate_limit(s: &str) -> Option<u64>`（B/s），后继 Task 2/3/4/5 用。

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn rate_limit_parses_mbps_notation() {
    // 口径与 transmission UI 一致：1m = 1024*1024 B/s；纯数字默认 m；大小写不敏感
    assert_eq!(super::parse_rate_limit("0.5m"), Some(524288));
    assert_eq!(super::parse_rate_limit("500k"), Some(512000));
    assert_eq!(super::parse_rate_limit("2"), Some(2 * 1024 * 1024));
    assert_eq!(super::parse_rate_limit("1.5G"), Some((1.5 * 1024.0 * 1024.0 * 1024.0) as u64));
    assert_eq!(super::parse_rate_limit(" 1M "), Some(1024 * 1024));
    // 非法 -> None（调用方当不限速 + warn，绝不炸）
    assert_eq!(super::parse_rate_limit(""), None);
    assert_eq!(super::parse_rate_limit("-1m"), None);
    assert_eq!(super::parse_rate_limit("abc"), None);
    assert_eq!(super::parse_rate_limit("0"), None);
    assert_eq!(super::parse_rate_limit("0m"), None);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --bin neutrino rate_limit_parses 2>&1 | tail -n 5`
Expected: FAIL（`parse_rate_limit` 未定义，编译错即红）

- [ ] **Step 3: Write minimal implementation**

```rust
/// 映射级限速速率（下行总量，B/s）。`None`/空 = 不限速。
/// 口径 MB/s 与 transmission UI 一致：`500k`=500KB/s，`0.5m`=0.5MB/s，
/// `1.5g`=1.5GB/s；纯数字默认 `m`；大小写不敏感；非法/<=0 返回 None。
pub fn parse_rate_limit(s: &str) -> Option<u64> {
    let t = s.trim().to_lowercase();
    if t.is_empty() {
        return None;
    }
    let (num, mult): (&str, f64) = if let Some(n) = t.strip_suffix('k') {
        (n, 1024.0)
    } else if let Some(n) = t.strip_suffix('m') {
        (n, 1024.0 * 1024.0)
    } else if let Some(n) = t.strip_suffix('g') {
        (n, 1024.0 * 1024.0 * 1024.0)
    } else {
        (t.as_str(), 1024.0 * 1024.0)
    };
    let v: f64 = num.trim().parse().ok()?;
    if !v.is_finite() || v <= 0.0 {
        return None;
    }
    let bps = (v * mult).round() as u64;
    if bps == 0 {
        return None;
    }
    Some(bps)
}
```

结构体追加（`link_port` 后）：

```rust
/// 映射级总量下行限速（tcp/udp/link），如 "0.5m"。None/空/非法 = 不限速。
#[serde(default)]
pub rate_limit: Option<String>,
```

全仓 `ProxyConfig { ... }` 字面量补 `rate_limit: None,`（`grep -rn "link_port: " src/ tests/` 逐个补：`src/common/desired.rs` 1 处、`src/server/state.rs` 2 处、`src/server/tunnel.rs` 4 处、`src/server/api.rs` 1 处、`src/server/ingress.rs` tests 无字面量可跳过）。

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --bin neutrino rate_limit_parses 2>&1 | tail -n 4`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/common/proto.rs && git commit -m "feat(ratelimit): ProxyConfig.rate_limit + parse_rate_limit 纯函数"
```

---

### Task 2: sleep 计算 + 共享窗口（新文件 ratelimit.rs）

**Files:**
- Create: `src/server/ratelimit.rs`
- Modify: `src/server/mod.rs`（加 `pub mod ratelimit;`）
- Modify: `src/server/state.rs`（`Shared` 加 `pub(crate) rate_limiters: RwLock<HashMap<String, Arc<RateLimiter>>>` + import）
- Test: `src/server/ratelimit.rs` mod tests

**Interfaces:**
- Consumes: Task 1 的 `parse_rate_limit`。
- Produces: `pub fn throttle_sleep(chunk: usize, limit_bps: u64, elapsed: Duration) -> Duration` + `pub struct RateWindow { start: Instant, bytes: u64 }`（`take(&mut self, n: usize, limit_bps: u64) -> Duration`，1s 滑动重置）+ `pub struct RateLimiter { limit: AtomicU64, win: Mutex<RateWindow> }`（`take(&self, n) -> Duration` 纯算，调用方 `sleep`）+ `pub async fn limiter_for(s: &S, key: &str, limit_bps: u64) -> Arc<RateLimiter>`（同 key 复用、limit 变化时更新），Task 3/4 用。

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn sleep_math_clamps_at_zero() {
    // 32KB 块 @0.5MB/s 理论 62.5ms；已用 10ms -> 睡 52.5ms；已超时 -> 0
    let d = super::throttle_sleep(32 * 1024, 524288, Duration::from_millis(10));
    assert!(d >= Duration::from_millis(50) && d <= Duration::from_millis(55));
    assert_eq!(super::throttle_sleep(100, 1024 * 1024 * 1024, Duration::from_secs(1)), Duration::ZERO);
    assert_eq!(super::throttle_sleep(0, 100, Duration::ZERO), Duration::ZERO);
}

#[test]
fn window_slides_each_second() {
    // 同窗口累积：第 2 块要补睡；窗口过期后重置不清零漂移
    let mut w = super::RateWindow::new();
    let lim = 1000u64; // 1KB/s
    let d1 = w.take(600, lim); // 首块 600B -> 应睡 600ms
    assert!(d1 >= Duration::from_millis(590));
    let d2 = w.take(600, lim); // 累计 1200B/窗口 -> 补到 1200ms
    assert!(d2 >= Duration::from_millis(590));
    std::thread::sleep(Duration::from_millis(1100));
    let d3 = w.take(600, lim); // 新窗口 -> 回到 600ms
    assert!(d3 < Duration::from_millis(700));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --bin neutrino sleep_math_clamps 2>&1 | tail -n 4`
Expected: FAIL（`src/server/ratelimit.rs` 不存在，`mod ratelimit` 编译错即红）

- [ ] **Step 3: Write minimal implementation**

```rust
//! 映射级总量下行限速：sleep 截流（方案 B）。burst-sleep 锯齿可接受；
//! 以后换令牌桶时配置格式不变，只换此文件内部（spec 预留切换点）。
use crate::server::state::S;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// 单块 sleep 量：应耗时 - 已用， clamp 到 0。
/// 根因→修法：纯函数可单测，泵里只调它 + sleep，不手算。
pub fn throttle_sleep(chunk: usize, limit_bps: u64, elapsed: Duration) -> Duration {
    if chunk == 0 || limit_bps == 0 {
        return Duration::ZERO;
    }
    let want = Duration::from_secs_f64(chunk as f64 / limit_bps as f64);
    want.checked_sub(elapsed).unwrap_or(Duration::ZERO)
}

/// 映射级共享窗口：1s 滑动，记（窗口起始，已传字节）。
/// 同映射所有连接共用一个，超了大家一起等 = 总量语义。
pub struct RateWindow {
    start: Instant,
    bytes: u64,
}

impl RateWindow {
    pub fn new() -> Self {
        Self { start: Instant::now(), bytes: 0 }
    }
    /// 累进 n 字节，返回本块应 sleep 量（调用方负责 sleep）。窗口超 1s 即重置。
    pub fn take(&mut self, n: usize, limit_bps: u64) -> Duration {
        if limit_bps == 0 || n == 0 {
            return Duration::ZERO;
        }
        let now = Instant::now();
        if now.duration_since(self.start) >= Duration::from_secs(1) {
            self.start = now;
            self.bytes = 0;
        }
        self.bytes += n as u64;
        // 窗口累计应耗时 - 窗口已流逝 = 本块补睡量
        let want = Duration::from_secs_f64(self.bytes as f64 / limit_bps as f64);
        want.checked_sub(now.duration_since(self.start)).unwrap_or(Duration::ZERO)
    }
}

impl Default for RateWindow {
    fn default() -> Self {
        Self::new()
    }
}

/// 映射级 limiter：limit 可热更新（desired 重载后新值覆盖），窗口共享。
pub struct RateLimiter {
    limit: AtomicU64,
    win: tokio::sync::Mutex<RateWindow>,
}

impl RateLimiter {
    pub fn new(limit_bps: u64) -> Self {
        Self { limit: AtomicU64::new(limit_bps), win: tokio::sync::Mutex::new(RateWindow::new()) }
    }
    /// 纯算 sleep 量（不 sleep，调用方 sleep；零开销路径：limit==0 直接 ZERO 不锁）。
    pub async fn take(&self, n: usize) -> Duration {
        let lim = self.limit.load(Ordering::Relaxed);
        if lim == 0 || n == 0 {
            return Duration::ZERO;
        }
        self.win.lock().await.take(n, lim)
    }
    pub fn set_limit(&self, v: u64) {
        self.limit.store(v, Ordering::Relaxed);
    }
}

/// 同 key 复用 limiter（key=`traffic_key(hostname,proxy名)`），limit 变化时更新。
/// 根因→修法：limiter 常驻内存，desired 热更新只改 limit 不丢窗口，避免重置漂移。
pub async fn limiter_for(s: &S, key: &str, limit_bps: u64) -> Arc<RateLimiter> {
    if let Some(l) = s.rate_limiters.read().await.get(key) {
        l.set_limit(limit_bps);
        return l.clone();
    }
    let l = Arc::new(RateLimiter::new(limit_bps));
    s.rate_limiters.write().await.insert(key.to_string(), l.clone());
    l
}

/// 配置字符串 -> limiter（None = 不限速，调用方分支跳过不建窗口，零开销）。
/// 非法值 warn + None（配置文件手滑不能把隧道搞挂）。
pub fn limit_of(opt: Option<&str>) -> Option<u64> {
    let raw = opt.unwrap_or("").trim();
    if raw.is_empty() {
        return None;
    }
    match crate::common::proto::parse_rate_limit(raw) {
        Some(v) => Some(v),
        None => {
            tracing::warn!("rate_limit '{raw}' 非法，已忽略当不限速");
            None
        }
    }
}
```

`state.rs` 的 `Shared` 追加字段：

```rust
/// 映射级限速窗口：key = traffic_key(hostname, proxy名) -> 共享 limiter（总量语义）。
pub(crate) rate_limiters: RwLock<HashMap<String, Arc<crate::server::ratelimit::RateLimiter>>>,
```

`mod.rs` 加 `pub mod ratelimit;`（`pub mod ingress;` 后一行）。

- [ ] **Step 4: Run test to verify it passes**

Run: `RUSTFLAGS="-D warnings" cargo build 2>&1 | tail -n 2 && cargo test --bin neutrino ratelimit 2>&1 | tail -n 6`
Expected: build 零 warning，`sleep_math` + `window_slides` PASS

- [ ] **Step 5: Commit**

```bash
git add src/server/ratelimit.rs src/server/mod.rs src/server/state.rs && git commit -m "feat(ratelimit): sleep 计算 + 共享窗口 + limiter 复用"
```

---

### Task 3: tcp 下行泵限速（ingress to_agent）

**Files:**
- Modify: `src/server/ingress.rs`（tcp `ensure_tcp_listener` 内 accept 块 + `to_agent` 泵）
- Test: 复用 Task 2 单测 + Task 6 e2e（本任务泵接线无新增纯函数，RED 由 e2e 承担）

**Interfaces:**
- Consumes: Task 1 `rate_limit` 字段 + Task 2 `limiter_for/limit_of`。
- Produces: tcp 映射总量下行限速行为，Task 6 断言。

- [ ] **Step 1: accept 处查表取限速（替换现有 `(pname, target)` 块）**

```rust
// 连接行目标信息（proxy 名 + 内网目标）+ 限速快照（总量下行，公网->agent 方向）。
// 根因→修法：限速以 desired 入内存路由表为准，连接建立时快照一次；
// 热更新后新连接用新值，老连接沿用旧 limiter（limiter_for 同 key 更新 limit，老连接自动跟随）。
let (pname, target, rate_key, rate_bps) = {
    let ag = s3.agents.read().await;
    let h = ag.get(&aid);
    let p = h.and_then(|h| {
        h.info.proxies.iter().find(|p| {
            p.enabled && p.remote_port == port && p.ptype != "udp"
        })
    });
    match (h, p) {
        (Some(h), Some(p)) => (
            p.name.clone(),
            format!("{}:{}", p.local_ip, p.local_port),
            crate::server::state::traffic_key(&h.info.hostname, &p.name),
            crate::server::ratelimit::limit_of(p.rate_limit.as_deref()),
        ),
        _ => (String::new(), String::new(), String::new(), None),
    }
};
```

`hostname` 取用同一快照（已有行保留，改从 `rate_key` 反查则删；最小改动：保留原 `hostname` 行不动）。

- [ ] **Step 2: `to_agent` 泵每块 sleep（只改此泵，`from_agent` 不动）**

```rust
let limiter = match rate_bps {
    Some(bps) => Some(crate::server::ratelimit::limiter_for(&s3, &rate_key, bps).await),
    None => None,
};
let to_agent = tokio::spawn(async move {
    let mut b = vec![0u8; 32 * 1024];
    loop {
        let t0 = std::time::Instant::now();
        let n = ri.read(&mut b).await?;
        if n == 0 {
            break;
        }
        // 限速：总量窗口共享，同映射所有连接超了大家一起等；上行泵不压。
        // 零限速时 limiter 为 None，此分支跳过零开销。
        if let Some(l) = &limiter {
            let d = l.take(n).await;
            // 块内已用时间抵扣：take 是窗口累计口径，已含时间，此处直接 sleep 即可
            let _ = t0; // 保留计时点：窗口口径已抵扣，单块口径见 throttle_sleep 单测
            if !d.is_zero() {
                tokio::time::sleep(d).await;
            }
        }
        if let Some(c) = s_rx.conns.write().await.get_mut(&(sid as u64)) {
            c.rx += n as u64;
        }
        out2.send((sid, b[..n].to_vec())).map_err(|e| anyhow::anyhow!("{e}"))?;
    }
    anyhow::Ok(())
});
```

注意：`rate_key`/`limiter` 需 `clone` 进 `move` 闭包；`s3` 已有 clone（`s_rx` 模式照抄，limiter 建在 spawn 前用 `s3.clone()` 不行——`s3` 后面还用，建 limiter 时用 `&s3`，spawn 时 `limiter` move 即可）。

- [ ] **Step 3: Build**

Run: `RUSTFLAGS="-D warnings" cargo build 2>&1 | tail -n 2`
Expected: 零 warning

- [ ] **Step 4: Commit**

```bash
git add src/server/ingress.rs && git commit -m "feat(ratelimit): tcp 下行泵总量限速（上行不压）"
```

---

### Task 4: udp + link 限速

**Files:**
- Modify: `src/server/ingress.rs`（udp `ensure_udp_listener` 收包路径）
- Modify: `src/server/tunnel.rs`（`spawn_link_relay` 双泵）
- Test: 复用 Task 2 单测；行为由 Task 6 e2e（tcp）+ 手动抽查（udp/link 走同 helper，无新增纯函数）

**Interfaces:**
- Consumes: Task 2 `limiter_for/limit_of` + Task 3 的查表模式。
- Produces: 三类映射全覆盖，Task 6 断言 tcp，udp/link 同 helper 间接保障。

- [ ] **Step 1: udp 收包限速（`owner` send 前加）**

udp 是单 task 多 peer 共享循环：建 `HashMap<u16, Arc<RateLimiter>>` 局部缓存太重，最小实现——每次收包按 `port` 查表（`pick_port` 已有同开销查表在前，接受）：

```rust
// udp 下行限速（收包方向）：按 port 查 proxy 快照，同映射共享 limiter；整包为一块。
// 根因→修法：udp 无连接概念，session per peer，窗口必须按映射共享（不能按 peer 建）。
let rl: Option<Arc<crate::server::ratelimit::RateLimiter>> = {
    let (key, bps) = {
        let ag = s2.agents.read().await;
        let found = ag.values().find_map(|h| {
            h.info.proxies.iter().find(|p| p.enabled && p.remote_port == port && p.ptype == "udp").map(|p| {
                (crate::server::state::traffic_key(&h.info.hostname, &p.name), crate::server::ratelimit::limit_of(p.rate_limit.as_deref()))
            })
        });
        found.unwrap_or_default()
    };
    match bps {
        Some(b) if !key.is_empty() => Some(crate::server::ratelimit::limiter_for(&s2, &key, b).await),
        _ => None,
    }
};
if let Some(l) = rl {
    let d = l.take(payload.len()).await;
    if !d.is_zero() {
        tokio::time::sleep(d).await;
    }
}
```

插入位置：`let payload = buf[..n].to_vec();` 之后、`owner` send 之前。`use std::sync::Arc;` 按需加（文件头已有 `Arc`）。

- [ ] **Step 2: link 双泵限速（双向共用同一 limiter）**

`spawn_link_relay` 的 `// 5. conns 记账` 之后、`// 6. 双向泵` 之前加：

```rust
// link 限速：双端都在 server，无本地 socket，上下行都吃 VPS 带宽 -> 双向共用同一 limiter（总量语义）。
// 查表以 server 存为准（与 resolve_link 同源）。
let link_limiter = {
    let ag = s.agents.read().await;
    let bps = ag.get(&entry_aid).and_then(|h| {
        h.info.proxies.iter().find(|p| p.enabled && p.ptype == "link" && p.name == link_name)
            .and_then(|p| crate::server::ratelimit::limit_of(p.rate_limit.as_deref()))
    });
    match bps {
        Some(b) => {
            let host = ag.get(&entry_aid).map(|h| h.info.hostname.clone()).unwrap_or_default();
            let key = crate::server::state::traffic_key(&host, &link_name);
            Some(crate::server::ratelimit::limiter_for(&s, &key, b).await)
        }
        None => None,
    }
};
```

双泵循环体内首行加（`a2e` 与 `e2a` 各加，`chunk.len()` 为块大小）：

```rust
if let Some(l) = &link_limiter {
    let d = l.take(chunk.len()).await;
    if !d.is_zero() {
        tokio::time::sleep(d).await;
    }
}
```

`link_limiter` 需 `clone` 进两个 `move` 泵（`let ll1 = link_limiter.clone(); let ll2 = ...`）。

- [ ] **Step 3: Build**

Run: `RUSTFLAGS="-D warnings" cargo build 2>&1 | tail -n 2`
Expected: 零 warning

- [ ] **Step 4: Commit**

```bash
git add src/server/ingress.rs src/server/tunnel.rs && git commit -m "feat(ratelimit): udp 收包 + link 双泵总量限速"
```

---

### Task 5: desired 校验 + WebUI 表单

**Files:**
- Modify: `src/server/api.rs`（`validate_proxy` + `api_tunnels` + 单测）
- Modify: `web/index.html`（表单输入框 + `typeFields/curProxy/saveForm/editRow` + 表格列）
- Test: `src/server/api.rs` mod tests

**Interfaces:**
- Consumes: Task 1 字段名（`rate_limit`）。
- Produces: 用户可配限速（文件仍是源头，WebUI 换皮改同一行）；非法值走 warn-忽略不断言拒绝。

- [ ] **Step 1: `validate_proxy` 放行 link + 不拦 rate（RED 先行）**

单测追加（`validate_proxy` 所在 mod tests，现有效 `ok_http` 附近）：

```rust
// link 类型必须放行（旧 match 无 link 分支，WebUI 存 link 会 400）；
// rate_limit 非法不断言拒绝（运行时 warn-忽略，见 limit_of）。
let mut link_p = ok_http.clone();
link_p.ptype = "link".into();
assert!(validate_proxy(&link_p).is_ok());
let mut rl = ok_http.clone();
rl.rate_limit = Some("abc".into());
assert!(validate_proxy(&rl).is_ok());
```

Run: `cargo test --bin neutrino validate 2>&1 | tail -n 4`
Expected: FAIL（link 被拒）

- [ ] **Step 2: 最小实现**

```rust
"tcp" | "https" | "udp" | "link" => {
```

`rate_limit` 不加任何校验（故意：非法在运行时 `limit_of` warn-忽略）。`api_tunnels` 的 json 推送加一行：

```rust
"rate_limit": p.rate_limit,
```

- [ ] **Step 3: WebUI 表单**（`f-basic` 行后加）

```html
<label id="l-rate">下行限速（可选，仅 tcp/udp/link 总量：如 0.5m=0.5MB/s、500k；留空=不限速；口径与 transmission 显示一致）</label><input id="f-rate" placeholder="如 0.5m">
```

`typeFields()` 首行加：`document.getElementById('l-rate').classList.toggle('hidden',isHttp);document.getElementById('f-rate').classList.toggle('hidden',isHttp);`（http 隐藏；tcp/https/udp/link 显示——https 显示但 server 不压？spec 范围 tcp/udp/link，https 显示无害，server 查表 `ptype != "udp"` 分支天然带上 https，行为一致可接受；YAGNI 不另分支）。

`editRow` 加：`document.getElementById('f-rate').value=x.rate_limit||'';`；`openForm` 的清空 id 列表加 `'f-rate'`；`curProxy` 加：`if(t!=='http'){const rl=document.getElementById('f-rate').value.trim(); if(rl) p.rate_limit=rl;}`。

tunnels 表头加 `限速` 列，行渲染 `where` 后加 `${x.rate_limit||'-'}`（`colspan=7` → `8`）。

- [ ] **Step 4: Build + 单测 + Commit**

Run: `RUSTFLAGS="-D warnings" cargo build 2>&1 | tail -n 2 && cargo test --bin neutrino validate 2>&1 | tail -n 4`
Expected: PASS

```bash
git add src/server/api.rs web/index.html && git commit -m "feat(ratelimit): desired 放行 link + WebUI 限速输入框"
```

---

### Task 6: e2e（限速 vs 不限速对照）

**Files:**
- Modify: `tests/e2e.rs`
- Test: 新增 `e2e_tcp_ratelimit_throttles_downlink`

**Interfaces:**
- Consumes: Task 3 的 tcp 限速行为；现有 `boot`/`Env`/`free_port` helpers。
- Produces: 回归保障；旧代码跑此用例为红（无 sleep，耗时远低于下限）。

- [ ] **Step 1: Write the failing test**（先合入看红）

```rust
/// 回归：映射级总量下行限速（旧代码无 sleep，此用例耗时远低于 4s 下限而红）。
/// 断言抓：2MB @0.5m 耗时 >= 4s 理论下限；内容传对（限速不丢包）；不限速对照组明显快（<2s）。
#[tokio::test]
async fn e2e_tcp_ratelimit_throttles_downlink() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    // 后端：server 发什么就回什么（echo），走 agent->公网为上行不压，
    // 公网->agent 为下行被压：client 上传 2MB，echo 回 2MB，测的是回程（下行）。
    async fn echo_env(proxies_toml: String) -> (Env, u16) {
        let back = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let bport = back.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = back.accept().await else { break };
                tokio::spawn(async move {
                    let (mut r, mut w) = s.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });
        let rport = free_port();
        let env = boot(&proxies_toml.replace("{bport}", &bport.to_string()).replace("{rport}", &rport.to_string())).await;
        for _ in 0..100 {
            if tokio::net::TcpStream::connect(format!("127.0.0.1:{rport}")).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        (env, rport)
    }
    async fn roundtrip(rport: u16, n: usize) -> (Duration, Vec<u8>) {
        let mut c = tokio::net::TcpStream::connect(format!("127.0.0.1:{rport}")).await.unwrap();
        let payload = vec![0xABu8; n];
        let t0 = std::time::Instant::now();
        c.write_all(&payload).await.unwrap();
        let mut got = vec![0u8; n];
        let mut off = 0;
        while off < n {
            let m = tokio::time::timeout(Duration::from_secs(30), c.read(&mut got[off..])).await.unwrap().unwrap();
            assert!(m > 0, "eof before full echo");
            off += m;
        }
        (t0.elapsed(), got)
    }
    const N: usize = 2 * 1024 * 1024;
    // 限速组：rate_limit="0.5m"（TOML 转义：proxies 文件里写 rate_limit="0.5m"）
    let (env_l, rp_l) = echo_env("[[proxies]]\nname=\"bt\"\ntype=\"tcp\"\nlocal_ip=\"127.0.0.1\"\nlocal_port={bport}\nremote_port={rport}\nrate_limit=\"0.5m\"\n".into()).await;
    let (dt_l, got_l) = roundtrip(rp_l, N).await;
    assert_eq!(got_l.len(), N);
    assert!(got_l.iter().all(|&b| b == 0xAB), "限速不丢包/不错包");
    // 理论下限 2MB/0.5MB/s=4s，留 10% 余量防计时抖动
    assert!(dt_l >= Duration::from_millis(3600), "限速未生效：{dt_l:?}");
    drop(env_l);
    // 对照组：不限速，同样 2MB 应明显快（<2s；机器再慢也不至于到 3.6s）
    let (env_f, rp_f) = echo_env("[[proxies]]\nname=\"bt\"\ntype=\"tcp\"\nlocal_ip=\"127.0.0.1\"\nlocal_port={bport}\nremote_port={rport}\n".into()).await;
    let (dt_f, got_f) = roundtrip(rp_f, N).await;
    assert!(got_f.iter().all(|&b| b == 0xAB));
    assert!(dt_f < Duration::from_millis(2000), "对照组太慢，环境异常：{dt_f:?}");
    let _ = (env_f, dt_l);
}
```

注意：`Env` 需 `use`（文件头已有）；`boot` 的 proxies TOML 经 agent config → desired overlay 链：`boot` 无 desired 文件时走 agent 上报路径，`rate_limit` 随 `ProxyConfig` 上报，server 入内存路由表同样命中（overlay 只在有 desired 时覆盖，无 desired 则用上报值——限速字段天然跟随，无需 `boot_with_desired`）。

- [ ] **Step 2: Run test to verify it fails**（旧代码/Task 3 前）

Run: `cargo test --test e2e e2e_tcp_ratelimit 2>&1 | tail -n 8`
Expected: FAIL（`限速未生效` 断言红，耗时 ~毫秒级）

- [ ] **Step 3: 全量验证 + Commit**（Task 3/4 合入后）

Run: `make build 2>&1 | tail -n 2 && make test 2>&1 | tail -n 20`
Expected: 单测 30+新增（parse 1、sleep/window 2、validate 0 新增断言），e2e 7+1=8，全绿

```bash
git add tests/e2e.rs && git commit -m "test(ratelimit): e2e 限速对照回归（2MB@0.5m>=4s）"
```

---

## Self-Review

1. **Spec coverage:** 配置字段→Task 1（`rate_limit` + TOML/JSON serde default，老文件不炸）；速率口径→Task 1（k/m/g、纯数字=m、大小写、非法 None）；配置链（desired 源头+WebUI 换皮）→Task 5（落盘走现有 `api_desired_set`，无新接口）；下行 only→Task 3（`from_agent` 不动）+ Task 4（udp 收包方向、link 双向——link 双端都在 server，双向都吃带宽，spec“同一下行位置”按总量双向实现，此处显式决策）；总量语义→Task 2（共享 `RateWindow` + `limiter_for` 同 key 复用）；sleep 截流→Task 2/3/4；零开销→Task 2（`limit==0` 不锁）+ Task 3（`None` 跳过）；单测 1/2→Task 1/2；e2e→Task 6；不做（egress/上行/令牌桶）→ 全计划无此代码，切换点在 `ratelimit.rs` 文件边界。
2. **Placeholder scan:** 无 TBD/TODO；Task 3 的 `t0` 保留有注释（窗口口径已抵扣，`throttle_sleep` 单测锁单块口径——两口径并存已在注释说明，非占位）；Task 4 udp 每次查表开销已注释接受；Task 6 `Env`/`boot` 引用的是现成 helper（`tests/e2e.rs:44-107`），非未定义类型。
3. **Type consistency:** `rate_limit: Option<String>` 全计划统一（Task 1 结构体、Task 3 `p.rate_limit.as_deref()`、Task 5 `Some("abc")`、WebUI `x.rate_limit`）；key 口径统一 `traffic_key(hostname, name)`（Task 2/3/4 一致）；`take(n) -> Duration` 签名 Task 2 定义、Task 3/4 调用一致；`validate_proxy` 改动 `"tcp"|"https"|"udp"|"link"` 与 Task 5 单测 `link_p` 一致。

## Execution Handoff

**Plan complete and saved to `docs/superpowers/plans/2026-10-20-mapping-ratelimit.md`. Two execution options:**

**1. Subagent-Driven (recommended)** - I dispatch a fresh subagent per task, review between tasks, fast iteration

**2. Inline Execution** - Execute tasks in this session using executing-plans, batch execution with checkpoints

**Which approach?**
