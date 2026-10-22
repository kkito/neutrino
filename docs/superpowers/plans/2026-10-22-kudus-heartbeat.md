# kudus 心跳重整 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** kudus 心跳加 jitter + 丢包自适应、砍 server 反向 Ping、双端 75s 看门狗（只动 kudus，WSS/QUIC 不动）。

**Architecture:** `common/kudus.rs` 新增纯函数式 `Heartbeat`（间隔计算 + 迟滞状态机）与 `KUDUS_IDLE_KICK_SECS` 常量；agent/server 两端各改 ping 发送与 recv 超时，复用现有 `RelSend.retx` / `ServerRel` 非空判断丢包、复用现有 `cleanup` 退出路径。

**Tech Stack:** Rust, tokio (`timeout`, `sleep`), rand 0.8 (`gen_range`)。

## Global Constraints

- 只改 kudus：`src/common/kudus.rs`、`src/agent/kudus_session.rs`、`src/server/kudus.rs`；WSS/QUIC 文件不动，`IDLE_KICK_SECS`(45s) 不动。
- TDD：纯判定逻辑先写失败单测（RED），亲眼见红再实现。
- `make build`（`RUSTFLAGS="-D warnings"` 零 warning）+ `make test` 全绿才提交。
- 注释写清"根因→修法"。

---

### Task 1: `Heartbeat` + 常量 + idle 判定（common）

**Files:**
- Modify: `src/common/kudus.rs`（`KUDUS_RTO` 常量区后加新常量与结构体；`mod tests` 加单测）

**Interfaces:**
- Consumes: 无（`rand::Rng::gen_range`，rand 0.8 已在 Cargo.toml）。
- Produces: `pub const KUDUS_IDLE_KICK_SECS: i64 = 75`；`pub struct Heartbeat` + `Heartbeat::new()` + `next_interval(&mut self, lossy: bool) -> Duration` + `is_fast(&self) -> bool`；`pub fn kudus_idle_stale(last_seen_unix: i64, now_unix: i64) -> bool`。Task 2/3 引用这些名字和签名。

- [ ] **Step 1: Write the failing test**

在 `src/common/kudus.rs` 的 `mod tests` 末尾加：

```rust
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

#[test]
fn kudus_idle_kick_threshold() {
    // 看门狗 75s：容忍连丢 2 包（最坏 30s 间隔 + 1 次丢包不误踢）。
    assert!(super::kudus_idle_stale(0, 76));
    assert!(!super::kudus_idle_stale(0, 75));
    assert!(!super::kudus_idle_stale(100, 105));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --bin neutrino common::kudus::tests::heartbeat 2>&1 | tail -5`
Expected: FAIL（`Heartbeat` 不存在，编译错即红——行为缺失型红）。

Run: `cargo test --bin neutrino common::kudus::tests::kudus_idle 2>&1 | tail -5`
Expected: FAIL（同上）。

- [ ] **Step 3: Write minimal implementation**

在 `src/common/kudus.rs` 的 `KUDUS_WINDOW` 常量后加：

```rust
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

/// 纯判定：now-last_seen 超 75s 即僵尸（kudus 版；WSS 用 state::is_idle_stale 45s，不动）。
pub fn kudus_idle_stale(last_seen_unix: i64, now_unix: i64) -> bool {
    now_unix - last_seen_unix > KUDUS_IDLE_KICK_SECS
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --bin neutrino common::kudus 2>&1 | tail -5`
Expected: PASS（全部 common::kudus 单测绿）。

- [ ] **Step 5: Commit**

```bash
git add src/common/kudus.rs
git commit -m "feat(kudus): Heartbeat 自适应间隔 + 75s idle 判定（纯函数+单测）"
```

---

### Task 2: agent 侧 ping loop + 主循环看门狗

**Files:**
- Modify: `src/agent/kudus_session.rs`（ping loop 段约 302~315 行；主分发循环 `dec_rx.recv()` 处）

**Interfaces:**
- Consumes: Task 1 的 `Heartbeat::new/next_interval`、`KUDUS_IDLE_KICK_SECS`；`Pkt.rel`（`Arc<Mutex<RelSend>>`，`retx.len()` 判丢包）。
- Produces: 无新接口（行为变更：ping 间隔自适应；75s 无帧 bail，外层 backoff 重连复用现有）。

- [ ] **Step 1: Write the failing test**

agent session 是 IO 型，无纯函数可测。此 Task 的"测试" = Task 1 已锁语义 + Step 4 的真连验证。补一条编译期契约单测（防签名漂移），加在 `src/agent/kudus_session.rs` 末尾 `mod tests`（若无则新建）：

```rust
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --bin neutrino agent::kudus_session 2>&1 | tail -5`
Expected: FAIL（`mod tests` 不存在则编译错；若已存在则此断言缺 `Heartbeat`——Task 1 已合入则直接绿，跳过 RED，以 Step 4 真连为验证）。

- [ ] **Step 3: Write minimal implementation**

(a) ping loop 替换（旧代码是 `interval(30s.max(5))` 固定 tick）：

```rust
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
```

注意：`interval` 变量（Welcome 下发的 30）此后不再使用——删 `let interval = loop` 的绑定改为 `let _interval` 或直接丢弃，避免 warning（`RUSTFLAGS="-D warnings"` 会炸）。最小改法：`let _interval = loop { ... }` 改成 `loop { ... break interval }` 后的使用处……实际旧代码 `tracing::info!("kudus welcomed, heartbeat {interval}s")` 用了一次，保留该行，把 ping loop 内 `interval.max(5)` 删掉即可，无多余 warning（`interval` 仍被 info 行消费）。

(b) 主分发循环加看门狗（旧 `let Some((h, body)) = dec_rx.recv().await else { break; };`）：

```rust
// 看门狗：75s 无 server 任何帧即判死，bail 走外层 backoff 重连。
// 根因→修法：旧裸 recv 永等，server OOM 重启后 agent 卡旧会话无感知
// （macmini 2026-10-21 现场）。握手完成后的主循环才计时。
let (h, body) = match tokio::time::timeout(
    std::time::Duration::from_secs(crate::common::kudus::KUDUS_IDLE_KICK_SECS as u64),
    dec_rx.recv(),
).await {
    Ok(Some(v)) => v,
    _ => anyhow::bail!("kudus heartbeat timeout: no server frame"),
};
```

- [ ] **Step 4: Run test + 真连验证**

Run: `cargo test --bin neutrino agent::kudus_session common::kudus 2>&1 | tail -3`
Expected: PASS。

Run: `RUSTFLAGS="-D warnings" cargo build 2>&1 | tail -2`
Expected: 零 warning 构建成功。

真连：`./target/debug/neutrino agent --server kudus://127.0.0.1:<本地server端口>` 起本地对测，或连 hk（需 token），看日志 ping 间隔为 15~30s 随机（多等几个周期）且 `welcomed` 正常。

- [ ] **Step 5: Commit**

```bash
git add src/agent/kudus_session.rs
git commit -m "feat(kudus-agent): ping 自适应间隔 + 75s 看门狗重连"
```

---

### Task 3: server 侧砍反向 Ping + RTT 上报 + 看门狗

**Files:**
- Modify: `src/server/kudus.rs`：
  - (a) 删 server Ping task（约 240~260 行 `last_ping` + spawn 段）；
  - (b) `ClientMsg::Ping` 分支改 RTT 上报，删 `ClientMsg::Pong` 分支（读循环约 403~413 行 + `dispatch_body` 约 475~484 行两处）；
  - (c) 读循环 `rx.recv().await` 包 75s timeout，超时走 `cleanup + log_ev + FIN 200ms×3`；
  - (d) `dispatch_body` 签名去 `last_ping` 参数（两处调用点同步改：约 376 行 + 定义 468 行）。

**Interfaces:**
- Consumes: Task 1 的 `KUDUS_IDLE_KICK_SECS`；现有 `cleanup(&s, &agent_id, &hostname)`、`log_ev`、`tx.send_pkt`。
- Produces: 无新接口（`agents[].rtt_ms` 改由 agent Ping 的 `ts` 秒级计算）。

- [ ] **Step 1: Write the failing test**

server handle 是 IO 型，补契约单测锁常量（加在 `src/server/kudus.rs` 的 `mod tests` 末尾）：

```rust
#[test]
fn kudus_watchdog_contract() {
    // Task 3 看门狗与 Task 1 同阈值；server 不再自发 Ping（rtt 由 agent 上报）。
    assert_eq!(crate::common::kudus::KUDUS_IDLE_KICK_SECS, 75);
    assert!(crate::common::kudus::kudus_idle_stale(0, 76));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --bin neutrino server::kudus::tests::kudus_watchdog 2>&1 | tail -3`
Expected: FAIL（函数不存在）。Task 1 已合入则直接绿，跳过，以 Step 4 为验证。

- [ ] **Step 3: Write minimal implementation**

(a) 删 server Ping task 整段（含 `last_ping` 定义）：

```rust
// server 心跳：每 15s Ping（与 WSS/QUIC 同周期）。
let last_ping = Arc::new(RwLock::new(None::<std::time::Instant>));
{ ... spawn ... }
```

整段删除。注意 `RwLock` import 若只被它用则一并清理（先 build 看 warning）。

(b) 两处 `ClientMsg::Ping/Pong` 分支（读循环内 + `dispatch_body` 内，形状相同）改成：

```rust
ClientMsg::Ping { ts } => {
    // 根因→修法：server 反向 Ping 已砍（唯一作用是量 RTT）；rtt 改由
    // agent 上报的 ts 秒级计算，展示够用，省每会话每 15s 一包。
    let _ = ctl_tx.send(ServerMsg::Pong { ts });
    let ms = (chrono::Utc::now().timestamp() - ts).max(0) * 1000;
    if let Some(hh) = s.agents.write().await.get_mut(&agent_id) {
        hh.info.rtt_ms = ms;
    }
}
```

并删掉紧随的 `ClientMsg::Pong { .. } => { ... }` 分支（server 不再发 Ping，不会再收到 Pong）。

(c) `dispatch_body` 签名删 `last_ping: &Arc<RwLock<Option<std::time::Instant>>>` 参数，两处调用点（读循环 `dispatch_body(&s, &agent_id, &hostname, &ctl_tx, &last_ping, &tx, ob)` 与重放处）同步删实参。

(d) 读循环加看门狗（旧 `let (p, h, body) = rx.recv().await.ok_or_else(...)?;`）：

```rust
let (p, h, body) = match tokio::time::timeout(
    Duration::from_secs(crate::common::kudus::KUDUS_IDLE_KICK_SECS as u64),
    rx.recv(),
).await {
    Ok(Some(v)) => v,
    Ok(None) => break, // channel 关：对端已走，对齐旧语义
    Err(_) => {
        // 根因→修法：kudus 读循环裸等，agent 断网即僵尸会话永久占路由。
        // 75s 无声 → cleanup + log + FIN 200ms×3 尽力通知（UDP 可能丢，
        // agent 侧 75s 看门狗兜底重连）。
        log_ev(&s, format!("kudus agent '{hostname}' heartbeat timeout, kicking stale session {agent_id}"));
        for _ in 0..3 {
            let fh = KudusHdr { ver: 1, flags: FLAG_FIN, seq: 0, ack: 0, sack: [0u8; 32], ts_ms: now_ms() };
            tx.send_pkt(&fh, b"bye");
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        break;
    }
};
```

`break` 后沿用现有尾巴：`write_task.abort()` → FIN（`fin_acked=false` 会再发 3 次——与看门狗 FIN 重复，可接受；或置 `fin_acked=true` 省一次，想省就加一行）→ `cleanup` → `disconnected` 事件。推荐置 `fin_acked = true`（break 前加一行），省 3 包。

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --bin neutrino server::kudus common::kudus 2>&1 | tail -3`
Expected: PASS。

Run: `RUSTFLAGS="-D warnings" cargo build 2>&1 | tail -2`
Expected: 零 warning（重点看 `RwLock`/`Instant` 未使用 warning）。

- [ ] **Step 5: Commit**

```bash
git add src/server/kudus.rs
git commit -m "feat(kudus-server): 砍反向Ping + agent上报RTT + 75s看门狗踢僵尸"
```

---

### Task 4: 全量验证 + e2e 回归确认

**Files:** 无代码改动（验证 + 修偶发失败）。

- [ ] **Step 1: 全量测试**

Run: `make build && make test 2>&1 | grep -E "test result|FAILED|error"`
Expected: `105+` 单测 PASS；e2e 全绿。若 `e2e_udp_and_hot_config` 再红（此前一次偶发 FAILED），单独重跑：

Run: `cargo test --test e2e e2e_udp_and_hot_config 2>&1 | tail -3`
Expected: PASS（连跑 3 次确认非必现）。

- [ ] **Step 2: 真机验证（hk + macmini）**

1. 本机 debug 起 agent 连 hk：`kudus://hk.kkito.cn:36182`（域名解析已修），确认 `welcomed`。
2. 观察 hk journal：`agent '<host>' registered` 且无 `heartbeat timeout` 误踢（至少等 2~3 个心跳周期）。
3. link 回声（本机 13000→macmini 4000）再 curl 一次，确认数据面未被心跳改动影响。

- [ ] **Step 3: 提交版本号（可选）**

若验证通过且要发 0.7.4：`Cargo.toml` version → `0.7.4`，commit + 打 tag（需用户确认，默认不发版）。

---

## Self-Review

1. **Spec 覆盖**：§3 Heartbeat→Task 1/2；§4 砍反向 Ping+RTT 上报→Task 3(b)；§5 双向看门狗+mermaid→Task 2(b)/3(d)；§6 单测→Task 1 步骤；§7 不做（WSS/QUIC/毫秒 RTT/错峰）→Global Constraints 锁死。`ServerMsg::Ping→Pong` agent 分支保留（spec §4 已定，Task 2 不动它）。看门狗从 Register 后计时：实现上主循环/读循环本就在握手之后，无需额外代码。✅
2. **Placeholder 扫描**：无 TBD/TODO；所有代码块完整，函数签名与现有代码一致（`cleanup(&s,&agent_id,&hostname)`、`log_ev(&s, String)`、`tx.send_pkt(&hdr,&[u8])` 均沿用 kudus.rs 现有调用形状）。✅
3. **类型一致**：`Heartbeat::new()->Self`、`next_interval(bool)->Duration`、`is_fast()->bool`、`KUDUS_IDLE_KICK_SECS: i64`、`kudus_idle_stale(i64,i64)->bool`，Task 2/3 引用与 Task 1 定义一致；`Duration` 在 common/kudus.rs 已 `use std::time::{Duration,...}`。✅
