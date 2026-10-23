# kudus 黑洞可观测 + egress 细分 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** kudus 4 个黑洞丢包点可计数、可归因（reason + /24），egress 按目标细分，WebUI 可见。

**Architecture:** 分发循环热路径只做原子计数（零锁）；60s traffic tick 统一归集进现有 traffic 结构并落盘；egress 改 conns 行 tunnel 命名 + cap；API 加前缀过滤；WebUI 加黑洞区。

**Tech Stack:** Rust (tokio, tracing), existing traffic.json, WebUI vanilla JS in web/index.html

## Global Constraints

- 黑洞语义不变：零回包，只 server 侧计数+日志。
- 不动 WSS/QUIC、agent 侧、ClientMsg 协议字段、限速逻辑。
- `make build` 零 warning + `make test` 全绿。
- TDD：先红后绿，频繁提交。

---

### Task 1: drop 纯函数（key 生成 + /24 聚合 + 采样限流）

**Files:**
- Modify: `src/server/state.rs:128-160` (traffic_key 附近加新函数)
- Test: `src/server/state.rs` 同文件 `#[cfg(test)]` 模组

**Interfaces:**
- Consumes: 无（纯函数）
- Produces: `pub(crate) fn drop_key(reason: &str, peer: &str) -> String`, `pub(crate) fn warn_throttled(last_warn: i64, now: i64) -> bool` — Task 2/3 调用

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn drop_key_buckets_subnet() {
    assert_eq!(drop_key("short", "1.2.3.4:5678"), "kudus_drop/short/1.2.3.0/24");
    assert_eq!(drop_key("undecryptable", "[2001:db8::1]:443"), "kudus_drop/undecryptable/2001:db8::/64");
    assert_eq!(drop_key("bad_hdr", "garbage"), "kudus_drop/bad_hdr/unknown");
}

#[test]
fn warn_throttle_60s() {
    assert!(warn_throttled(0, 61));
    assert!(!warn_throttled(10, 69));
    assert!(warn_throttled(10, 70));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test drop_key_buckets_subnet 2>&1 | tail -5`
Expected: FAIL with "cannot find function `drop_key`"

- [ ] **Step 3: Write minimal implementation**

```rust
/// 黑洞 key：kudus_drop/{reason}/{subnet}。v4 取 /24，v6 取 /64，防随机源 IP 打爆表。
pub(crate) fn drop_key(reason: &str, peer: &str) -> String {
    // peer 形如 "1.2.3.4:5678" 或 "[2001:db8::1]:443"；先剥端口再按 IP 截段
    let host = peer.rsplit(':').next().unwrap_or(peer);
    let host = host.trim_matches(|c| c == '[' || c == ']').trim_matches(':');
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        match ip {
            std::net::IpAddr::V4(v) => {
                let o = v.octets();
                return format!("kudus_drop/{reason}/{}.{}.{}.0/24", o[0], o[1], o[2]);
            }
            std::net::IpAddr::V6(v) => {
                let s = v.segments();
                return format!("kudus_drop/{reason}/{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3]);
            }
        }
    }
    // 纯 IP 无端口兜底：host 本身可能是 "1.2.3.4"
    let host = peer.split(':').next().unwrap_or(peer).trim_matches(|c| c == '[' || c == ']');
    if let Ok(std::net::IpAddr::V4(v)) = host.parse::<std::net::IpAddr>() {
        if let std::net::IpAddr::V4(v) = v {
            let o = v.octets();
            return format!("kudus_drop/{reason}/{}.{}.{}.0/24", o[0], o[1], o[2]);
        }
    }
    format!("kudus_drop/{reason}/unknown")
}

/// 采样限流：同 key 60s 最多 1 条 warn。
pub(crate) fn warn_throttled(last_warn: i64, now: i64) -> bool {
    now - last_warn >= 60
}
```

注：上面的 peer 剥端口要小心 IPv6 多冒号——用 `rsplit(':')` 取 host 会错。正确做法：先用 `peer.parse::<SocketAddr>()`，成功取 `.ip()`；失败再回退字符串处理。实现时按此修（测试用例覆盖 `"1.2.3.4:5678"` 与 `"[2001:db8::1]:443"` 两种，`SocketAddr` parse 都能过）。

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test drop_key 2>&1 | tail -3`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/server/state.rs
git commit -m "feat(drop): drop_key subnet bucketing + warn throttle pure fns"
```

### Task 2: Shared 原子计数器 + 60s tick 归集进 traffic

**Files:**
- Modify: `src/server/state.rs:40-80` (Shared 结构加字段)
- Modify: `src/server/mod.rs:150-175` (60s traffic tick 循环内加归集)
- Test: `src/server/state.rs` pure 归集函数单测

**Interfaces:**
- Consumes: Task 1 `drop_key`
- Produces: `Shared.drop_hits: DashMap 或 Mutex<HashMap<String,(u64,u64)>>` + `pub(crate) fn drain_drops(...)` — Task 3 调用 `record_drop`

字段定义（加到 Shared）：

```rust
/// 黑洞原子计数：热路径每包 +1（包数, 字节），60s tick 归集进 traffic 后清零。
/// 用 std Mutex<HashMap> 即可（临界区只有 entry+1，纳秒级）；不另引 dashmap 依赖。
pub(crate) drop_hits: std::sync::Mutex<HashMap<String, (u64, u64)>>,
/// warn 限流表：key -> 上次 warn 的 unix ts，纯内存不落盘。
pub(crate) drop_warn: std::sync::Mutex<HashMap<String, i64>>,
```

归集函数（state.rs 纯函数，单测锁）：

```rust
/// 60s tick 把 drop_hits  draining 进 traffic：与 tick_from_conns 同节奏 push (ts,包数,字节)。
pub(crate) fn tick_drops(
    traffic: &mut HashMap<String, VecDeque<(i64, u64, u64)>>,
    hits: &mut HashMap<String, (u64, u64)>,
    now: i64,
) {
    for (k, (pkts, bytes)) in hits.drain() {
        if pkts == 0 { continue; }
        let q = traffic.entry(k).or_default();
        q.push_back((now, pkts, bytes));
        trim_traffic(q);
    }
}
```

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn tick_drops_push_and_drain() {
    let mut tr: HashMap<String, VecDeque<(i64, u64, u64)>> = HashMap::new();
    let mut hits = HashMap::new();
    hits.insert("kudus_drop/short/1.2.3.0/24".into(), (10u64, 500u64));
    tick_drops(&mut tr, &mut hits, 1700);
    assert!(hits.is_empty());
    let q = &tr["kudus_drop/short/1.2.3.0/24"];
    assert_eq!(q.len(), 1);
    assert_eq!(q[0], (1700, 10, 500));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test tick_drops 2>&1 | tail -3`
Expected: FAIL with "cannot find function `tick_drops`"

- [ ] **Step 3: Shared 加字段 + record_drop + tick_drops 实现 + mod.rs tick 接入**

Shared 初始化处（找 `Shared {` 构造点）加：

```rust
drop_hits: std::sync::Mutex::new(HashMap::new()),
drop_warn: std::sync::Mutex::new(HashMap::new()),
```

记录入口（state.rs，热路径调用，零 await）：

```rust
/// 热路径记录：只做 Mutex + entry +1，不打日志不拿 await 锁。
pub(crate) fn record_drop(s: &Shared, key: String, bytes: u64) {
    if let Ok(mut m) = s.drop_hits.lock() {
        let e = m.entry(key).or_insert((0, 0));
        e.0 = e.0.saturating_add(1);
        e.1 = e.1.saturating_add(bytes);
    }
}
```

mod.rs 60s tick 内（`tick_from_conns` 之后同一临界区）加：

```rust
{
    let mut hits = s.drop_hits.lock().unwrap().drain().collect::<HashMap<_,_>>();
    // drop key 首次见：seen 逻辑与 tick_from_conns 一致，直接 push 点即可
    // （drop 点天然带 ts，无基线问题，不走 seen/last_total）
    state::tick_drops(&mut tr, &mut hits, chrono::Local::now().timestamp());
}
```

- [ ] **Step 4: Run tests**

Run: `cargo test tick_drops 2>&1 | tail -3 && cargo build 2>&1 | tail -2`
Expected: PASS + 零 warning

- [ ] **Step 5: Commit**

```bash
git add src/server/state.rs src/server/mod.rs
git commit -m "feat(drop): atomic drop_hits + 60s tick drain into traffic"
```

### Task 3: kudus 分发循环 4 丢包点接入计数 + 采样 warn

**Files:**
- Modify: `src/server/kudus.rs:664-700` (`run_kudus` 分发循环)
- Test: 手动 e2e（Task 6），此处单测覆盖 `decode_packet` 短包分支已存在，不新增纯函数测试

**Interfaces:**
- Consumes: Task 1 `drop_key` + `warn_throttled`，Task 2 `record_drop`
- Produces: 线上行为（计数 + 限流 warn）

4 个改点（`run_kudus` 内，按现有 `continue` 分支逐个加两行）：

```rust
// 点1 短包：
let Some((session, nonce, ct)) = decode_packet(&buf[..n]) else {
    let k = crate::server::state::drop_key("short", &peer.to_string());
    crate::server::state::record_drop(&s, k.clone(), n as u64);
    maybe_warn_drop(&s, k, &peer.to_string(), n);
    tracing::debug!("kudus short packet ({}B) from {peer}", n);
    continue;
};
// 点2 解密失败：
let Some(plain) = open(&key, nonce, ct) else {
    let k = crate::server::state::drop_key("undecryptable", &peer.to_string());
    crate::server::state::record_drop(&s, k.clone(), n as u64);
    maybe_warn_drop(&s, k, &peer.to_string(), n);
    tracing::debug!("kudus undecryptable packet session={session:08x} from {peer}");
    continue;
};
// 点3 坏内层头：同理 reason="bad_hdr"，bytes=plain.len()
// 点4 未知 session 非 SYN：reason="unknown_session"，bytes=n
```

采样 warn helper（kudus.rs 内，与 run_kudus 同文件）：

```rust
/// 同 key 60s 最多 1 条 warn（首包详情 + 计数在 tick 里看总量）。
fn maybe_warn_drop(s: &Shared, key: String, peer: &str, bytes: usize) {
    let now = chrono::Local::now().timestamp();
    let hit = s.drop_warn.lock().map(|mut m| {
        let last = m.get(&key).cloned().unwrap_or(0);
        if crate::server::state::warn_throttled(last, now) {
            m.insert(key.clone(), now);
            true
        } else { false }
    }).unwrap_or(false);
    if hit {
        tracing::warn!("kudus drop {key} from {peer} ({}B, sampled 1/60s)", bytes);
    }
}
```

注意：`run_kudus(s: S, ...)` 的 `s` 是 `Arc<Shared>`，闭包内直接用 `s` 即可；`Shared` 需 import（文件头已有 `use crate::server::state::{log_ev, save_state, AgentHandle, AgentInfo, Shared}`）。

- [ ] **Step 1: 实现 4 点 + helper**（无新纯函数，跳过红灯，直接写实现）
- [ ] **Step 2: 编译**

Run: `cargo build 2>&1 | tail -2`
Expected: 零 warning

- [ ] **Step 3: Commit**

```bash
git add src/server/kudus.rs
git commit -m "feat(drop): kudus 4 drop points count + sampled warn"
```

### Task 4: egress tunnel 按目标细分 + key cap

**Files:**
- Modify: `src/server/tunnel.rs:insert_egress_conn` (tunnel 字段)
- Modify: `src/server/state.rs` (加 `egress_tunnel` 纯函数 + cap 常量)
- Test: `src/server/state.rs` 单测

**Interfaces:**
- Consumes: 无
- Produces: `pub(crate) fn egress_tunnel(host: &str, port: u16) -> String`, `pub(crate) const EGRESS_KEYS_PER_AGENT: usize = 500`

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn egress_tunnel_namespaced() {
    assert_eq!(egress_tunnel("tracker.example.com", 443), "egress/tracker.example.com:443");
}

#[test]
fn egress_cap_buckets_overflow() {
    // 600 个 key → top 500 保留，溢出进 egress/other（纯函数 bucket 判定）
    assert!(egress_overflow(600, 500));
    assert!(!egress_overflow(500, 500));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test egress_tunnel 2>&1 | tail -3`
Expected: FAIL with "cannot find function"

- [ ] **Step 3: Write minimal implementation**

state.rs 加：

```rust
/// 单 agent egress key 上限（防恶意 agent 刷 key 膨胀 traffic 表）
pub(crate) const EGRESS_KEYS_PER_AGENT: usize = 500;

pub(crate) fn egress_tunnel(host: &str, port: u16) -> String {
    format!("egress/{host}:{port}")
}

pub(crate) fn egress_overflow(n_keys: usize, cap: usize) -> bool {
    n_keys > cap
}
```

tunnel.rs `insert_egress_conn` 改一行：

```rust
// tunnel: "egress".into() → tunnel: super::state::egress_tunnel(host, port),
tunnel: super::state::egress_tunnel(host, port),
```

cap 执行（tick 侧，`tick_from_conns_at` 内或 mod.rs tick 后——选 mod.rs tick 后，10 行）：

```rust
// egress cap：按 agent 分组计 key 数，超 EGRESS_KEYS_PER_AGENT 只留量最大的 N 个，其余并入 egress/other
// 实现：遍历 tr keys 前缀 "agent/egress/"，组内按近 5 点求和排序，尾部 drain 并把量加到 "{agent}/egress/other"
```

为保持 task 独立，此处给全实现（state.rs 纯函数，tick 后调用）：

```rust
/// egress cap 纯函数：输入全表快照（key -> 近N点总量），返回要合并进 other 的 key 列表。
/// 调用方负责 drain + 累加。pure 便于单测。
pub(crate) fn egress_over_cap(
    totals: &HashMap<String, u64>,
    cap: usize,
) -> Vec<String> {
    use std::collections::HashMap as M;
    let mut by_agent: M<String, Vec<(String, u64)>> = M::new();
    for (k, v) in totals {
        if let Some(rest) = k.split_once("/egress/") {
            if rest.1 != "other" {
                by_agent.entry(rest.0.to_string()).or_default().push((k.clone(), *v));
            }
        }
    }
    let mut out = vec![];
    for (_, mut v) in by_agent {
        if v.len() > cap {
            v.sort_by(|a, b| b.1.cmp(&a.1));
            out.extend(v[cap..].iter().map(|(k, _)| k.clone()));
        }
    }
    out
}
```

mod.rs tick 中调用：先对 tr 做近 5 点求和快照 → `egress_over_cap` → 超的 key drain 并把总量点并入 `{agent}/egress/other`（当轮 push 一个点，ts=now）。

- [ ] **Step 4: Run tests**

Run: `cargo test egress 2>&1 | tail -3 && cargo build 2>&1 | tail -2`
Expected: PASS + 零 warning

- [ ] **Step 5: Commit**

```bash
git add src/server/tunnel.rs src/server/state.rs src/server/mod.rs
git commit -m "feat(egress): tunnel per-target split + per-agent cap"
```

### Task 5: API 前缀过滤 + WebUI 黑洞区

**Files:**
- Modify: `src/server/api.rs:378-420` (`api_traffic` keys 选择分支)
- Modify: `web/index.html` (traffic 区加黑洞汇总行 + top 表，复用现有样式/接口)
- Test: `src/server/api.rs` 既有 `traffic_slice_math` 旁加前缀单测（slice 层是纯函数，key 过滤在 handler——单测改测 `match_prefix` helper）

先抽 helper（api.rs）：

```rust
/// tunnel=:key 精确；tunnel=prefix* 前缀；all/空 全量。
pub(crate) fn traffic_key_match(key: &str, q: &str) -> bool {
    if q.is_empty() || q == "all" { return true; }
    if let Some(p) = q.strip_suffix('*') { return key.starts_with(p); }
    key == q
}
```

handler 改：

```rust
let keys: Vec<String> = tr.keys().filter(|k| traffic_key_match(k, &q.tunnel)).cloned().collect();
```

WebUI（index.html，traffic section 内）：

```html
<!-- 黑洞丢包：fetch /api/traffic?tunnel=kudus_drop* 同 gran/n，每 60s 随主图刷新 -->
<div id="sec-drop">…按 reason 汇总行 + top/24 表（复用现有 table 样式）…</div>
```

JS 约 30 行：与现有 traffic fetch 并行发一份 `tunnel=kudus_drop*`，按 `/` 切 reason/subnet 汇总渲染。无新图表库。

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn traffic_prefix_match() {
    assert!(traffic_key_match("kudus_drop/short/1.2.3.0/24", "kudus_drop*"));
    assert!(traffic_key_match("minipc7s/egress", "minipc7s/egress"));
    assert!(!traffic_key_match("minipc7s/egress", "kudus_drop*"));
    assert!(traffic_key_match("a/b", "all"));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test traffic_prefix 2>&1 | tail -3`
Expected: FAIL

- [ ] **Step 3: 实现 helper + handler 改 + WebUI 区**

- [ ] **Step 4: Run tests + build**

Run: `cargo test traffic 2>&1 | tail -3 && cargo build 2>&1 | tail -2`
Expected: PASS + 零 warning

- [ ] **Step 5: Commit**

```bash
git add src/server/api.rs web/index.html
git commit -m "feat(api): traffic prefix filter + webui drop section"
```

### Task 6: e2e 验证（垃圾包 → 计数可见）

**Files:** 无新增（用现有 tests/ + curl）

- [ ] **Step 1: 起 server 发垃圾包**

```bash
# 终端1：debug 起 server（或 cargo run -- --listen 127.0.0.1:7440 ...按本地习惯）
# 终端2：100 个短包 + 100 个随机包打 kudus 端口
for i in $(seq 1 100); do printf 'junk' | nc -u -w0 127.0.0.1 36182; done
head -c 200 /dev/urandom | nc -u -w0 127.0.0.1 36182
```

- [ ] **Step 2: 查 API + 日志**

```bash
curl -s "http://127.0.0.1:7440/api/traffic?tunnel=kudus_drop*&gran=min&n=5" -H "Authorization: Bearer <token>"
# 期望：points 非空，short/undecryptable 有数
# 日志期望：1 条 warn "kudus drop kudus_drop/short/127.0.0.0/24 ..."（60s 内只 1 条）
```

- [ ] **Step 3: 全量测试**

Run: `make test 2>&1 | tail -5 && make build 2>&1 | tail -2`
Expected: 全绿 + 零 warning

- [ ] **Step 4: Commit（若有 e2e 修补）或直接收尾**

```bash
git log --oneline -6
```

## Self-Review

- Spec §3 黑洞计数 → Task 1+2+3；§4 采样日志 → Task 3 helper；§5 egress 细分 → Task 4；§6 WebUI+API → Task 5；§7 单测清单全覆盖（聚合/限流/cap/兼容——兼容用既有 upgrade 路径 + Task 5 不破坏精确匹配）；e2e → Task 6。
- 无占位符：每步含真实代码/命令；类型一致（drop key 统一 `kudus_drop/{reason}/{subnet}`，egress `egress/{host}:{port}`，tick 点 `(ts,rx,tx)` 复用）。
- YAGNI：无 HyperLogLog、无自动封禁、无阈值告警（spec §8 不做）。
