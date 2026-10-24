# 层 5：UDP 可观测性收尾 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 补齐 spec §16 的 5b（UDP `tunnel_stats` 埋点 + 降噪）、5d（SIGUSR1/2 动态日志级别 + 启动 banner）、5c（journald 留存），并把已实现但未提交的 5a 一并落地。

**Architecture:** 三个独立改动面。(1) `src/server/ingress.rs` 的 UDP 会话循环加旁挂 `sid_stats` 表，与 `sessions` 同步 retain，在 accept/close 两个时刻累加 `Shared::tunnel_stats`；(2) 新建 `src/log_level.rs`，用 `tracing_subscriber::reload` 包一层可换的 `EnvFilter`，`main.rs` 注册 `SIGUSR1/2` 并调用 `print_log_level_hint()`；(3) journald 是纯运维配置，落到 `deploy/` 并照做。

**Tech Stack:** Rust, axum, tokio（已含 `full` feature，`signal` 直接可用）, `tracing-subscriber` 需新增 `reload` feature。

---

## 前置说明

- 工作树当前有**未提交**的 5a 改动：`src/agent/kudus_session.rs`、`src/agent/udp_pool.rs`、`src/agent/mod.rs`、`src/agent/link.rs`、`src/main.rs`。Task 1 先把它们提交掉，避免与后续改动混在一起。
- 所有 `cargo test --bin neutrino` 单测；e2e 必须加 `-- --test-threads=1`。
- 编译用 `make build`（带 `RUSTFLAGS="-D warnings"`）。
- **禁止盲等 `sleep(N)`**：等待一律轮询可观测状态（见 `settle()` / `wait_agents_count()` / `wait_log_contains()`）。

---

### Task 1: 提交已有的层 5a 改动

**Files:**
- Modify（已改，待提交）: `src/agent/kudus_session.rs`, `src/agent/udp_pool.rs`, `src/agent/mod.rs`, `src/agent/link.rs`, `src/main.rs`

- [ ] **Step 1: 确认工作树只有这 5 个文件被改**

```bash
cd /mnt/sdb/proj/kkito/proj/neutrino
git status --porcelain
```

Expected: 恰好 5 行 ` M src/...`，无其他意外文件。

- [ ] **Step 2: 跑全量测试确认基线绿**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
make build
cargo test --bin neutrino 2>&1 | tail -3
cargo test --test e2e -- --test-threads=1 2>&1 | tail -3
```

Expected: `make build` 零 warning；`180 passed`；`40 passed`。

- [ ] **Step 3: 提交**

```bash
git add src/agent/kudus_session.rs src/agent/udp_pool.rs src/agent/mod.rs src/agent/link.rs src/main.rs
git commit -m "$(cat <<'EOF'
feat(agent): UDP 流生命周期可观测 + --udp-idle-secs（spec §16.3）

根因：两个 UDP 泵的失败分支全是静默的——`Ok(0) | Err(_) => break`
把「对端正常关闭」和 `ECONNREFUSED`/`ENOBUFS` 混为一谈，
`.is_err() { return; }` 连日志都不打。2026-10-24 现场追问「agent 侧
UDP_STREAM_IDLE_SECS=5 够不够」，翻遍日志只能看到每分钟一行全局
`kudus retx sent=N abandoned=N`，答不出「哪条流活了多久、为什么断」。

修法：
- 新增 UdpStreamStat（started + 6 个 AtomicU64 + AtomicU8 end），
  两个泵各写一半方向计数，收尾统一汇总打一行 debug：
  `kudus udp stream closed sid=.. lived=..s reason=.. rx_pkts=.. pool=../..`
- 结束原因区分 idle-timeout / server-close / send-err / recv-err /
  local-eof / running，Ok(None) 与 Err 分开处理
- 送包/收包失败改 warn!，带 sid 与已收包数，不再静默
- UdpPool::summary() 暴露 `in_use/created evicted=`，池满踢流有账可查
- --udp-idle-secs 启动参数，resolve_udp_idle_secs() 里 0 回退默认常量
  （Duration::from_secs(0) 会瞬杀全部流或永不超时泄 fd，误配代价太高）

测试：udp_stream_stat_reason_names / udp_pool_summary_counts_in_use_and_evicted /
udp_idle_secs_resolves_cli_override；回退验证：去掉 0 回退逻辑后
断言 left:0 right:5 变红。
EOF
)"
```

Expected: commit 成功。

---

### Task 2: UDP tunnel_stats —— 先写失败的 e2e（RED）

**Files:**
- Modify: `tests/e2e.rs`（在 `e2e_tunnel_stats_line_emitted` 之后追加新用例）

- [ ] **Step 1: 在 `tests/e2e.rs` 末尾追加失败测试**

在文件末尾（最后一个 `}` 之后）追加：

```rust
/// spec §16.4：UDP ingress 必须累计 tunnel_stats。
/// 旧代码只有 TCP/HTTP 埋点，UDP 路径一处都没有——而 BT 的 tracker/DHT/uTP
/// 全走 UDP，等于最重的流量在汇总行里不存在。
///
/// 断言抓什么：打一次 UDP 包后，`tunnel stats <host>/<proxy> accepts=` 必须 >=1。
/// 回退验证：注释掉 udp 分支的 accepts += 1，本用例必须变红。
///
/// 注意：server 把 UDP ingress socket 的 SO_RCVBUF 钳到 64KB（故意限速设计），
/// 突发灌包会在 ingress 之前被内核丢掉，实测恒定只进 ~137 个。所以这里只发
/// 少量包并错峰，不做洪泛。
#[tokio::test]
async fn e2e_udp_tunnel_stats_line_emitted() {
    // 一个回显的 UDP 后端
    let back = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let bport = back.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut b = [0u8; 2048];
        loop {
            let Ok((n, peer)) = back.recv_from(&mut b).await else {
                return;
            };
            let _ = back.send_to(&b[..n], peer).await;
        }
    });
    // 隧道配在 server 的 desired.toml（desired 是唯一源头）
    let desired = format!(
        "[[agents.e2e]]\nname=\"udpstats\"\ntype=\"udp\"\nlocal_ip=\"127.0.0.1\"\nlocal_port={bport}\n\
         remote_port={bport}\n"
    );
    let (env, log) = boot_with_logfile("", Some(&desired)).await;
    let n = wait_agents_count(env.http_port, 1, 40).await;
    assert_eq!(n, 1, "agent 没上线，日志类断言无意义");
    // 少量错峰发包（不做洪泛，见函数注释）
    let cli = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for i in 0..5u8 {
        let _ = cli
            .send_to(&[b'x'; 32], ("127.0.0.1", bport))
            .await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        let _ = i;
    }
    // 等汇总行出现（traffic tick 50ms；上限 3s 兜底）
    assert!(
        wait_log_contains(&log, "tunnel stats ", 60),
        "缺少 per-tunnel 汇总行\n--- log ---\n{}",
        read_log(&log)
    );
    let text = read_log(&log);
    let line = text
        .lines()
        .filter(|l| l.contains("tunnel stats e2e/udpstats"))
        .next_back()
        .unwrap_or_else(|| panic!("没有 udpstats 的汇总行\n--- log ---\n{text}"));
    let accepts: u64 = line
        .split("accepts=")
        .nth(1)
        .and_then(|s| s.split_whitespace().next())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    assert!(
        accepts >= 1,
        "UDP 隧道必须累计 accepts（旧代码 UDP 路径完全没有 tunnel_stats 埋点）: {line}"
    );
}
```

- [ ] **Step 2: 跑该用例，确认它**因为「UDP 未埋点」而红**

```bash
cd /mnt/sdb/proj/kkito/proj/neutrino
export PATH="$HOME/.cargo/bin:$PATH"
cargo test --test e2e e2e_udp_tunnel_stats_line_emitted -- --test-threads=1 2>&1 | tail -20
```

Expected: FAIL。失败信息应是「没有 udpstats 的汇总行」或 `accepts` 为 0——
**不是**编译错误、不是「agent 没上线」。

如果失败原因是「agent 没上线」，属于用例构造问题，先修用例再继续。

---

### Task 3: 实现 UDP tunnel_stats 埋点（GREEN）

**Files:**
- Modify: `src/server/ingress.rs:850-1040`（UDP 会话循环）

- [ ] **Step 1: 在 `sessions` 声明旁加旁挂表**

找到 `ingress.rs` 中这一行（约 `:855`）：

```rust
        let mut sessions: HashMap<std::net::SocketAddr, (u32, Instant, mpsc::UnboundedSender<(u32, Vec<u8>)>, Option<std::sync::Arc<RateLimiter>>, mpsc::UnboundedSender<ServerMsg>)> = HashMap::new();
```

在它**后面**插入：

```rust
        // spec §16.4：sid -> "hostname/proxyname"，供 tunnel_stats 累加用。
        // 为什么旁挂而不塞进 sessions 元组：元组已有 5 个字段，再塞一个要动
        // 所有解构模式（:899 get_mut / :881 retain / :958 等）。旁挂表代价更低。
        // 必须与 sessions 同步回收（见下方两处 retain），否则 agent 主动 Close
        // （池满踢流、断线）这些不走 TTL 的路径会让它无限增长。
        let mut sid_stats: HashMap<u32, String> = HashMap::new();
```

- [ ] **Step 2: TTL 回收处先累加 closes 再删旁挂表**

找到这段（约 `:866-884`，含 `expired_sids` 到 `retain` 的完整块）：

```rust
            let dead = expired_sids(&snapshot, now, ttl);
            let n_exp = dead.len();
            if n_exp > 0 {
                // Close 让 agent 删 streams 表项 + abort 双向泵 + drop socket。
                // send 失败（agent 已断）忽略：表项照样删。
                let dead_set: std::collections::HashSet<u32> = dead.into_iter().collect();
                for (id, _, _, _, ctl) in sessions.values() {
                    if dead_set.contains(id) {
                        let _ = ctl.send(ServerMsg::Close { stream: *id, reason: "udp idle".into() });
                    }
                }
            }
            sessions.retain(|_, (_, t, _, _, _)| t.elapsed() < ttl);
            if n_exp > 0 {
                tracing::debug!("udp :{port} expired {n_exp} sessions ({} alive)", sessions.len());
            }
```

替换为（**复用已有的 `dead_set`，不要另造列表**）：

```rust
            let dead = expired_sids(&snapshot, now, ttl);
            let n_exp = dead.len();
            if n_exp > 0 {
                // Close 让 agent 删 streams 表项 + abort 双向泵 + drop socket。
                // send 失败（agent 已断）忽略：表项照样删。
                let dead_set: std::collections::HashSet<u32> = dead.into_iter().collect();
                for (id, _, _, _, ctl) in sessions.values() {
                    if dead_set.contains(id) {
                        let _ = ctl.send(ServerMsg::Close { stream: *id, reason: "udp idle".into() });
                    }
                }
                // spec §16.4：先累加 closes 再删旁挂表——顺序反了 sid_stats 里
                // 已经查不到 key，closes 会永远是 0。
                if let Ok(mut m) = s2.tunnel_stats.lock() {
                    for sid_d in dead_set.iter() {
                        if let Some(key) = sid_stats.get(sid_d) {
                            m.entry(key.clone()).or_default().closes += 1;
                        }
                    }
                }
                for sid_d in dead_set.iter() {
                    sid_stats.remove(sid_d);
                }
            }
            sessions.retain(|_, (_, t, _, _, _)| t.elapsed() < ttl);
            // agent 主动 Close（池满踢流/断线）不走 TTL 路径，用同一次 retain 对齐清理，
            // 否则这些 sid 会永久留在旁挂表里。
            {
                let live: std::collections::HashSet<u32> =
                    sessions.values().map(|(id, _, _, _, _)| *id).collect();
                sid_stats.retain(|sid_d, _| live.contains(sid_d));
            }
            if n_exp > 0 {
                tracing::debug!("udp :{port} expired {n_exp} sessions ({} alive)", sessions.len());
            }
```

- [ ] **Step 3: 新建 session 处累加 accepts 并写旁挂表**

先改解构处的变量名（约 `:938`）——`_sess_host` / `_sess_pname` 带下划线是因为
原先只在日志里用一次，现在要真正参与 key 拼接，改为不带下划线：

```rust
                    let (sess_host, sess_key, sess_pname, sess_bps) = {
```

（把该行原来的 `let (_sess_host, sess_key, _sess_pname, sess_bps) = {` 整行替换掉。）

然后找到（约 `:975`）：

```rust
                    tracing::info!("udp session {peer} -> sid={id} tunnel={_sess_pname} host={_sess_host}");
                    sessions.insert(peer, (id, Instant::now(), out_cached, sess_limiter, ctl.clone()));
```

替换为：

```rust
                    // spec §16.4 ④：udp session 单连接明细降 DEBUG（同类日志
                    // tcp accept/close 已在 258330e 降级，只留 udp 在 INFO 会不一致）。
                    tracing::debug!("udp session {peer} -> sid={id} tunnel={sess_pname} host={sess_host}");
                    // spec §16.4 ③：accepts 语义 = 新建会话数（非收包数），与 TCP 的
                    // 「建立连接」对等，accepts/closes 配对才有意义；包量由 rx/tx 字节体现。
                    {
                        let key = format!("{sess_host}/{sess_pname}");
                        if let Ok(mut m) = s2.tunnel_stats.lock() {
                            m.entry(key.clone()).or_default().accepts += 1;
                        }
                        sid_stats.insert(id, key);
                    }
                    sessions.insert(peer, (id, Instant::now(), out_cached, sess_limiter, ctl.clone()));
```

- [ ] **Step 4: rx / tx 累加点顺手记隧道级流量**

找到 rx 累加处（约 `:1021-1031`）：

```rust
            // UDP 连接行 rx 累计 + since 刷新（peer 行线性查找）
            {
                let peer_s = peer.to_string();
                let mut m = s2.conns.write().await;
                if let Some(c) = m.values_mut().find(|c| c.proto == "udp" && c.peer == peer_s) {
                    c.rx += payload.len() as u64;
                    c.since = chrono::Local::now().timestamp();
                }
            }
```

替换为：

```rust
            // UDP 连接行 rx 累计 + since 刷新（peer 行线性查找）
            {
                let peer_s = peer.to_string();
                let mut m = s2.conns.write().await;
                if let Some(c) = m.values_mut().find(|c| c.proto == "udp" && c.peer == peer_s) {
                    c.rx += payload.len() as u64;
                    c.since = chrono::Local::now().timestamp();
                }
            }
            // spec §16.4 ③：隧道级 rx 同样在包路径累加（不是 tick 扫表——
            // UDP 会话关得快，扫表会严重偏低）。
            if let Some(key) = sid_stats.get(&sid) {
                if let Ok(mut m) = s2.tunnel_stats.lock() {
                    m.entry(key.clone()).or_default().rx += payload.len() as u64;
                }
            }
```

tx 累加在 agent→peer 的 spawn 里，那里拿不到 `sid_stats`（已经 move 进闭包了）。改为在 spawn 前把 key 克隆进去：

找到（约 `:943`）：

```rust
                    let up_limiter = sess_limiter.clone();
                    tokio::spawn(async move {
                        while let Some(chunk) = drx.recv().await {
```

替换为：

```rust
                    let up_limiter = sess_limiter.clone();
                    // spec §16.4：隧道级 tx 在回包路径累加。key 必须在 spawn 前
                    // 克隆进去——sid_stats 是循环局部变量，闭包捕获会与主循环的
                    // 借用冲突。
                    let tx_key = format!("{sess_host}/{sess_pname}");
                    let s_tx = s3.clone();
                    tokio::spawn(async move {
                        while let Some(chunk) = drx.recv().await {
```

并在同一 spawn 内、`let _ = sock2.send_to(&chunk, peer).await;` **之前**插入：

```rust
                            if let Ok(mut m) = s_tx.tunnel_stats.lock() {
                                m.entry(tx_key.clone()).or_default().tx += chunk.len() as u64;
                            }
```

- [ ] **Step 5: 跑 Task 2 的 e2e，确认变绿**

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cargo test --test e2e e2e_udp_tunnel_stats_line_emitted -- --test-threads=1 2>&1 | tail -20
```

Expected: PASS。

- [ ] **Step 6: 回退验证（必做）**

注释掉 Step 3 里的 `m.entry(key.clone()).or_default().accepts += 1;`，重跑：

```bash
cargo test --test e2e e2e_udp_tunnel_stats_line_emitted -- --test-threads=1 2>&1 | tail -10
```

Expected: **FAIL**（`accepts` 为 0 或汇总行不出现）。确认后恢复该行。

- [ ] **Step 7: 跑全量测试 + build**

```bash
make build
cargo test --bin neutrino 2>&1 | tail -3
cargo test --test e2e -- --test-threads=1 2>&1 | tail -3
```

Expected: 零 warning；单测全绿；e2e `41 passed`（新增 1 个）。

- [ ] **Step 8: Commit**

```bash
git add src/server/ingress.rs tests/e2e.rs
git commit -m "$(cat <<'EOF'
feat(server): UDP ingress 补 tunnel_stats 埋点 + udp session 降噪（spec §16.4）

根因：§15.4 规划的 per-tunnel 汇总只落了 TCP/HTTP（ec97bee），UDP 路径
一处都没有——而 BT 的 tracker/DHT/uTP 全走 UDP，等于最重的流量在汇总行
里不存在，查流量只能靠 agent 级累计数推算。

修法：
- 旁挂 sid_stats 表（sid -> "host/代理名"），不塞 sessions 元组，
  避免动 5 处解构模式
- accepts 语义 = 新建会话数（非收包数），与 TCP 的「建立连接」对等
- TTL 回收处先累加 closes 再删旁挂表（顺序反了查不到 key，closes 恒 0）
- 旁挂表在 sessions.retain 后同步 retain，覆盖 agent 主动 Close
  （池满踢流/断线）这些不走 TTL 的路径，否则长期运行泄漏
- rx/tx 在包路径累加（不是 tick 扫表：UDP 会话关得快，扫表严重偏低）
- udp session 日志 INFO -> DEBUG，与 258330e 的 tcp accept/close 保持一致

测试：新增 e2e_udp_tunnel_stats_line_emitted（打 5 个错峰包后断言
accepts>=1）；回退验证：注释掉 accepts += 1 后该用例变红。
注意 e2e 只发少量包——UDP ingress SO_RCVBUF 钳 64KB，灌包会在内核前置丢弃。
EOF
)"
```

---

### Task 4: 动态日志级别 —— 先写失败单测（RED）

**Files:**
- Create: `src/log_level.rs`
- Modify: `src/main.rs`（加 `mod log_level;`）

- [ ] **Step 1: 新建 `src/log_level.rs`，只放类型与常量，函数留空实现**

创建 `src/log_level.rs`：

```rust
//! 动态日志级别（spec §16.5）。
//!
//! 为什么需要：流收尾等排查日志是 DEBUG 级，默认 `RUST_LOG=info` 看不到；
//! 但生产上为了开 debug 去改 systemd Environment 再 restart，会掐掉所有正在
//! 进行的 UDP 会话，等于把要观测的现象消灭掉。
//!
//! 为什么用信号不用 HTTP：agent 当前无 WebUI（`--server` 直连），HTTP 对它
//! 不可用；信号两端对称、零配置、无需认证。

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// DEBUG 窗口时长（spec §16.5 ⑦：不限时会让 DEBUG 撑爆 journald）。
pub(crate) const DEBUG_WINDOW: Duration = Duration::from_secs(60);

/// 启动时的级别（= RUST_LOG 解析后的基准）。恢复目标必须是它而不是硬编码
/// "info"——用户若用 `RUST_LOG=neutrino::agent=debug` 启动，USR2 应回到那个值。
static BASE_LEVEL: std::sync::OnceLock<String> = std::sync::OnceLock::new();
/// 当前窗口的代际计数：每次 USR1 自增，旧的 restore 任务看到代际不符就退出。
static GENERATION: AtomicU64 = AtomicU64::new(0);

/// 记录启动时的基准级别（main 里 init 后调用一次）。
pub(crate) fn set_base(level: &str) {
    let _ = BASE_LEVEL.set(level.to_string());
}

/// 恢复目标：基准级别；未初始化时回退 "info"。
pub(crate) fn restore_target() -> &'static str {
    BASE_LEVEL.get().map(|s| s.as_str()).unwrap_or("info")
}

/// 启动 banner 的那行提示（spec §16.5 ⑤：信号开关最大的问题是没人知道它存在）。
/// 抽成纯函数便于单测——banner 文本里少写一个信号，运维就永远只会用一半功能。
pub(crate) fn hint_line(available: bool, level: &str) -> String {
    if available {
        format!(
            "  log level    : {level}  →  kill -USR1 <pid> 临时开 DEBUG {}s；kill -USR2 <pid> 提前恢复",
            DEBUG_WINDOW.as_secs()
        )
    } else {
        "  log level    : 信号开关不可用（signal() 注册失败），请用 RUST_LOG 环境变量".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 恢复目标必须是启动值，不能是硬编码 "info"（spec §16.5 ④ 要点 2）。
    #[test]
    fn log_level_restore_target_is_startup_value() {
        set_base("neutrino=debug");
        assert_eq!(
            restore_target(),
            "neutrino=debug",
            "restore_target 必须返回 set_base 传入的值，硬编码 info 会把用户自己开的模块级 debug 也关掉"
        );
    }

    /// banner 必须同时提到两个信号，否则运维只会用一半功能（spec §16.5 ⑤）。
    #[test]
    fn log_level_hint_line_names_both_signals() {
        let h = hint_line(true, "info");
        assert!(h.contains("-USR1"), "banner 缺 SIGUSR1: {h}");
        assert!(h.contains("-USR2"), "banner 缺 SIGUSR2: {h}");
        assert!(h.contains("60"), "banner 必须写明窗口秒数: {h}");
    }

    /// 注册失败时必须明说不可用，而不是照打一句"能用"（否则运维 kill 一下进程就死了）。
    #[test]
    fn log_level_hint_line_warns_when_unavailable() {
        let h = hint_line(false, "info");
        assert!(h.contains("不可用"), "注册失败必须提示不可用: {h}");
        assert!(!h.contains("-USR1"), "不可用时不该教用户发信号: {h}");
    }
}
```

- [ ] **Step 2: `src/main.rs` 顶部注册模块**

在 `src/main.rs` 已有的 `mod` 声明块（找 `mod agent;` 或 `mod server;`）旁边加一行：

```rust
mod log_level;
```

- [ ] **Step 3: 跑单测，确认**因编译失败/断言失败**而红**

```bash
cd /mnt/sdb/proj/kkito/proj/neutrino
export PATH="$HOME/.cargo/bin:$PATH"
cargo test --bin neutrino log_level 2>&1 | tail -20
```

Expected: 3 个测试中至少 `log_level_restore_target_is_startup_value` FAIL。
（若因 `GENERATION` 未使用而 warning，属正常，Task 5 会用到。）

- [ ] **Step 4: 让测试变绿（当前实现其实已足够，只差 unused 处理）**

确认 3 个测试全过：

```bash
cargo test --bin neutrino log_level 2>&1 | tail -10
```

Expected: `3 passed`。

若有 `GENERATION` unused warning，先临时加 `#[allow(dead_code)]` 到该 static 上，Task 5 移除。

---

### Task 5: 接入 reload layer + SIGUSR1/2 注册

**Files:**
- Modify: `Cargo.toml`（加 `reload` feature）
- Modify: `src/log_level.rs`（加 `install` / `spawn_signal_handler`）
- Modify: `src/main.rs`（改造 tracing 初始化）

- [ ] **Step 1: Cargo.toml 加 reload feature**

把

```toml
tracing-subscriber = { version = "0.3", features = ["env-filter", "chrono"] }
```

改为

```toml
tracing-subscriber = { version = "0.3", features = ["env-filter", "chrono", "reload"] }
```

- [ ] **Step 2: `src/log_level.rs` 加 reload 与信号处理**

在文件顶部 `use` 之后插入：

```rust
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::reload;

/// 可换 filter 的句柄。init 后存进这里，信号处理与运行期调级共用。
static HANDLE: std::sync::OnceLock<reload::Handle<EnvFilter, tracing_subscriber::Registry>> =
    std::sync::OnceLock::new();

/// 初始化日志：默认只有 info（未设 RUST_LOG 时），返回可 reload 的句柄。
/// 与旧的 `tracing_subscriber::fmt().with_env_filter(...).init()` 行为一致，
/// 额外多一个能换 filter 的把手。
pub(crate) fn install() {
    let env = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());
    let filter = EnvFilter::try_new(&env).unwrap_or_else(|_| EnvFilter::new("info"));
    let (layer, handle) = reload::Layer::new(filter);
    let timer = tracing_subscriber::fmt::time::ChronoLocal::new(
        "%Y-%m-%dT%H:%M:%S%.3f%:z".to_string(),
    );
    tracing_subscriber::registry()
        .with(layer)
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(std::io::stdout)
                .with_timer(timer),
        )
        .init();
    let _ = HANDLE.set(handle);
    set_base(&env);
}

/// 换级别。失败（句柄未初始化）返回 false，调用方应 warn。
pub(crate) fn set_level(spec: &str) -> bool {
    match HANDLE.get() {
        Some(h) => h.reload(EnvFilter::try_new(spec).unwrap_or_else(|_| EnvFilter::new("info"))).is_ok(),
        None => false,
    }
}

/// 注册 SIGUSR1 / SIGUSR2。返回 false = 注册失败，调用方必须 warn，
/// 并把 banner 改成「不可用」——**失败时绝不能假装能发信号**：
/// SIGUSR1 的默认行为是终止进程，运维照着 banner 发一下就把服务打死了。
#[cfg(unix)]
pub(crate) fn spawn_signal_handler() -> bool {
    use tokio::signal::unix::{signal, SignalKind};
    let (mut usr1, mut usr2) = match (
        signal(SignalKind::user_defined1()),
        signal(SignalKind::user_defined2()),
    ) {
        (Ok(a), Ok(b)) => (a, b),
        _ => return false,
    };
    tokio::spawn(async move {
        let mut restore: Option<tokio::task::JoinHandle<()>> = None;
        loop {
            tokio::select! {
                _ = usr1.recv() => {
                    // 重复 USR1 要覆盖旧计时器：不 abort 会积累 N 个 restore 任务，
                    // 第一个到期就把级别打回去，窗口远短于 60s。
                    if let Some(h) = restore.take() { h.abort(); }
                    let gen = GENERATION.fetch_add(1, Ordering::SeqCst) + 1;
                    if set_level("debug") {
                        tracing::info!(
                            "log level -> debug for {}s (SIGUSR1)",
                            DEBUG_WINDOW.as_secs()
                        );
                    } else {
                        tracing::warn!("log level reload failed (SIGUSR1)");
                    }
                    let target = restore_target().to_string();
                    restore = Some(tokio::spawn(async move {
                        tokio::time::sleep(DEBUG_WINDOW).await;
                        // 代际不符 = 期间又按过 USR1 或 USR2，让位给更新的任务
                        if GENERATION.load(Ordering::SeqCst) != gen {
                            return;
                        }
                        if set_level(&target) {
                            tracing::info!("log level restored to {target} after {}s", DEBUG_WINDOW.as_secs());
                        }
                    }));
                }
                _ = usr2.recv() => {
                    if let Some(h) = restore.take() { h.abort(); }
                    GENERATION.fetch_add(1, Ordering::SeqCst);
                    let target = restore_target().to_string();
                    if set_level(&target) {
                        tracing::info!("log level restored to {target} early (SIGUSR2)");
                    }
                }
            }
        }
    });
    true
}

/// 非 unix：没有 SIGUSR1/2，直接不可用。
#[cfg(not(unix))]
pub(crate) fn spawn_signal_handler() -> bool {
    false
}
```

- [ ] **Step 3: 改造 `src/main.rs` 的 tracing 初始化**

找到（约 `:192-204`）：

```rust
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info");
    }
    // stdout 时间戳用本地 wall clock（默认 SystemTime 打 UTC，如 HKT 机器 18:00 打成 10:00Z）。
    let timer = tracing_subscriber::fmt::time::ChronoLocal::new("%Y-%m-%dT%H:%M:%S%.3f%:z".to_string());
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stdout)
        .with_timer(timer)
        .init();
    let cli = Cli::parse();
```

替换为：

```rust
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info");
    }
    // spec §16.5：可 reload 的日志层（SIGUSR1 临时开 debug 60s 用）。
    // 内部仍读 RUST_LOG，行为与非 reload 版一致。
    log_level::install();
    let cli = Cli::parse();
    // 信号开关：注册失败绝不能假装可用（SIGUSR1 默认行为是杀进程）。
    let sig_ok = log_level::spawn_signal_handler();
    if !sig_ok {
        tracing::warn!(
            "signal-based log level unavailable; use RUST_LOG env var instead"
        );
    }
    println!("{}", log_level::hint_line(sig_ok, log_level::restore_target()));
```

注意：`log_level::install()` 必须在 `Cli::parse()` **之前**，否则解析失败时没有日志输出。

- [ ] **Step 4: 编译并跑单测**

```bash
make build
cargo test --bin neutrino log_level 2>&1 | tail -10
```

Expected: 零 warning；3 passed。

- [ ] **Step 5: 手工验证信号真的生效（本机 agent 上做）**

先起一个测试版 agent（不要动现网那个）：

```bash
# 用随机高端口 + 临时配置，纯本地冒烟
./target/debug/neutrino agent --server ws://127.0.0.1:1/ws --config /tmp/sigtest.toml &
AG=$!
sleep 1
kill -USR1 $AG
sleep 1
kill -USR2 $AG
kill $AG
```

Expected: 输出里出现 `log level -> debug for 60s (SIGUSR1)` 与
`log level restored ... (SIGUSR2)`，且**进程没有被杀**（`kill $AG` 才是我们主动结束的）。

如果进程被 SIGUSR1 打死，说明 `signal()` 没注册成功——回去查 Step 2。

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml Cargo.lock src/log_level.rs src/main.rs
git commit -m "$(cat <<'EOF'
feat: SIGUSR1/SIGUSR2 动态日志级别 + 启动 banner 自曝用法（spec §16.5）

背景：流收尾等排查日志是 DEBUG 级，默认 RUST_LOG=info 看不到；但生产上
为开 debug 去改 systemd Environment 再 daemon-reload+restart，会掐掉所有
正在进行的 UDP 会话，等于把要观测的现象消灭掉。

方案：
- tracing-subscriber 加 reload feature，EnvFilter 包 reload::Layer，
  handle 存 OnceLock，运行期随时换 filter（立即生效、不重启）
- SIGUSR1 提级 debug 60s 自动恢复；SIGUSR2 提前恢复
- 不用 HTTP API：agent 当前无 WebUI（--server 直连），HTTP 对它不可用
- 不用 SIGURG/SIGWINCH：默认忽略虽更安全，但语义与日志无关

四条红线：
1. signal() 注册失败必须返回 false 并 warn——SIGUSR1 默认行为是终止进程，
   失败还教用户发信号就是把人往坑里带
2. 恢复目标是启动时的级别（OnceLock 存 RUST_LOG 原值），不是硬编码 info
3. 重复 USR1 要 abort 旧计时器 + 比对代际，否则第一个到期就把级别打回去
4. 启动 banner 打印用法（hint_line 纯函数，可单测）：信号开关最大的问题
   是没人知道它存在

测试：3 个单测（恢复目标=启动值、banner 含两个信号、注册失败时警示）。
不发真信号测——与测试运行器自身信号处理冲突；改为手工冒烟验证。
EOF
)"
```

---

### Task 6: journald 留存（运维配置落地）

**Files:**
- Create: `deploy/journald-neutrino.conf`
- Modify: `docs/architecture.md`（运维章节加一段）

- [ ] **Step 1: 创建 `deploy/journald-neutrino.conf`**

```ini
# neutron 日志留存（spec §16.6）
#
# 部署位置二选一：
#   A. 全局：/etc/systemd/journald.conf.d/neutrino.conf（推荐，不动全局配置）
#   B. 服务级：只用 systemd 的 LogRateLimit 之类不够——留存上限是 journald 全局的，
#      所以必须落在 journald 配置里，不能写在 service 单元里。
#
# 应用：
#   sudo mkdir -p /etc/systemd/journald.conf.d
#   sudo cp deploy/journald-neutrino.conf /etc/systemd/journald.conf.d/neutrino.conf
#   sudo systemctl restart systemd-journald
#
# 验证：
#   journalctl --disk-usage          # 应 <= 500M
#   journalctl -u neutrino-server --since "-30 days" --no-pager | head -1   # 能取到 30 天前

[Journal]
# 为什么要有上限：2026-10-23 事故时 journal 只剩 2 天，根因不是没有文件，
# 而是 journald 未配上限导致滚动过快。
SystemMaxUse=500M
MaxRetentionSec=30day
# 单条日志长度上限（UDP 流收尾行带多个计数，默认 8K 够用，显式写清便于调整）
MaxLineLen=16K
```

- [ ] **Step 2: 在 `docs/architecture.md` 末尾加运维小节**

在文件末尾追加：

```markdown
## 日志留存与动态调级

### 留存

日志「只剩 2 天」的根因是 journald 未配上限，不是没有文件。用
`deploy/journald-neutrino.conf` 落到 `/etc/systemd/journald.conf.d/`：

```bash
sudo mkdir -p /etc/systemd/journald.conf.d
sudo cp deploy/journald-neutrino.conf /etc/systemd/journald.conf.d/neutrino.conf
sudo systemctl restart systemd-journald
journalctl --disk-usage      # 应 <= 500M
```

**为什么不引入 `tracing-appender` 写文件**：引新依赖会带来「stdout 与文件
双写重复」的新问题，而 journald 本身就是成熟的滚动+保留方案。

### 动态调级（不用重启）

单连接明细、UDP 流收尾等排查日志是 DEBUG 级，默认看不到。开 60 秒：

```bash
kill -USR1 $(pgrep -x neutrino)    # DEBUG 60s，到点自动恢复
kill -USR2 $(pgrep -x neutrino)    # 立即恢复
```

启动 banner 里会打印当前级别和这两条命令（`log level : ...`）。

**为什么不改 `RUST_LOG` 重启**：重启会掐掉所有正在进行的 UDP 会话，
等于把要观测的现象消灭掉。

**注意**：`SIGUSR1` 的默认行为是**终止进程**。若启动日志里有
`signal-based log level unavailable`，说明 `signal()` 注册失败，
此时发 `SIGUSR1` 会打死服务——只能改用环境变量。
```

- [ ] **Step 3: Commit**

```bash
git add deploy/journald-neutrino.conf docs/architecture.md
git commit -m "$(cat <<'EOF'
docs(deploy): journald 留存配置 + 动态调级运维说明（spec §16.6）

日志「只剩 2 天」的根因是 journald 未配上限导致滚动过快，不是没有文件。
配置落 /etc/systemd/journald.conf.d/（不动全局 journald.conf）：
SystemMaxUse=500M / MaxRetentionSec=30day / MaxLineLen=16K。

不引 tracing-appender：journald 本身是成熟的滚动+保留方案，引新依赖会带来
「stdout 与文件双写重复」的新问题。

architecture.md 补两节：留存部署步骤、SIGUSR1/2 动态调级及「注册失败时
发信号会打死服务」的警告。
EOF
)"
```

---

### Task 7: 全量验证 + 两端部署

**Files:** 无代码改动

- [ ] **Step 1: 全量测试**

```bash
cd /mnt/sdb/proj/kkito/proj/neutrino
export PATH="$HOME/.cargo/bin:$PATH"
make build
cargo test --bin neutrino 2>&1 | tail -3
cargo test --test e2e -- --test-threads=1 2>&1 | tail -3
```

Expected: 零 warning；单测 **183 passed**（180 + 3 个 log_level）；e2e **41 passed**。

- [ ] **Step 2: 打 tag 触发 CI 出 musl 静态二进制**

**不要** `scp` 本机 `target/release/neutrino`（macOS/arm64 在 server 上 203/EXEC；
2026-10-20 已踩过一次把线上二进制覆盖掉）。

```bash
git tag v0.0.0-layer5 && git push origin feat/kudus-hardening --tags
# 等 GitHub Actions release.yml 完成，下载
# neutrino-<version>-x86_64-unknown-linux-musl.tar.gz
```

- [ ] **Step 3: HK 部署**

```bash
scp neutrino-*-x86_64-unknown-linux-musl.tar.gz hk:/root/nastools/neutrino/
ssh hk 'cd /root/nastools/neutrino && tar xzf neutrino-*.tar.gz && systemctl restart neutrino-server'
ssh hk 'journalctl -u neutrino-server -n 30 --no-pager | grep "log level"'
```

Expected: banner 里出现 `log level    : info  →  kill -USR1 ...`。

- [ ] **Step 4: HK 落 journald 配置**

```bash
scp deploy/journald-neutrino.conf hk:/tmp/
ssh hk 'mkdir -p /etc/systemd/journald.conf.d && cp /tmp/journald-neutrino.conf /etc/systemd/journald.conf.d/neutrino.conf && systemctl restart systemd-journald && journalctl --disk-usage'
```

Expected: `Archived and active journals take up ... ` 且不超过 500M。

- [ ] **Step 5: 端到端验证 SIGUSR1 在 HK 生效**

```bash
ssh hk 'kill -USR1 $(pgrep -x neutrino) && sleep 2 && journalctl -u neutrino-server -n 200 --no-pager | grep -c "log level -> debug"'
ssh hk 'journalctl -u neutrino-server --no-pager -n 30 | grep -c "udp stream closed"'
ssh hk 'kill -USR2 $(pgrep -x neutrino)'
```

Expected: 第一条 >= 1；第二条 >= 1（说明流收尾日志真的出来了）；
第三条后日志出现 `log level restored ... early (SIGUSR2)`。

- [ ] **Step 6: 本机 agent 加 `--udp-idle-secs 60` 重启**

```bash
pkill -f 'neutrino agent' ; sleep 1
# 用你现有的启动方式，加参数：--udp-idle-secs 60
# 与 HK 的 --udp-session-ttl 60 对齐
```

然后 `kill -USR1 $(pgrep -x neutrino)`，观察
`kudus udp stream closed ... lived=..s reason=..`，收集 `lived` 分布回答
「5 秒够不够」（spec §16.3 ② 判读表）。

---

## 附：自检清单

| spec 要求 | 对应 Task |
| --------- | --------- |
| §16.2 #5 UDP tunnel_stats 埋点 | Task 2（RED）+ Task 3（GREEN） |
| §16.2 #6 udp session 降 DEBUG | Task 3 Step 3 |
| §16.2 #7 journald 留存 | Task 6 |
| §16.2 #8 SIGUSR1 提级 60s | Task 4 + Task 5 |
| §16.2 #9 SIGUSR2 提前恢复 | Task 5 Step 2 |
| §16.5 ⑤ 启动 banner 自曝 | Task 4 Step 1（`hint_line`）+ Task 5 Step 3 |
| §16.7 用例 1-3（5a 单测） | Task 1（已实现，随提交带入） |
| §16.7 用例 4（UDP e2e） | Task 2 |
| §16.7 用例 6-8（log_level） | Task 4 |
| §16.10 已知风险（会话数上限） | 不在本计划，见 spec |
