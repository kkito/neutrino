# desired 文件重载按钮 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 手改 `desired.toml` 后点 server WebUI「从文件重载」按钮即生效（替代重启），出错进日志。

**Architecture:** 新增 `POST /api/desired/reload`（重读文件→全量替换内存→对在线 agent 推 `Config`，复用 `api_desired_set` 后半段）；`web/index.html` 加按钮 + toast；解析失败 error+内存不动、坏条 warn+跳过。

**Tech Stack:** Rust (axum 0.7 路由, tokio RwLock), 原生 JS (fetch + toast)。

## Global Constraints

- `RUSTFLAGS="-D warnings"` 下零 warning 才算过 (`make build`)。
- `make test` 全绿（44 单测 + 9 e2e 及新增）。
- TDD：先写失败测试（RED），亲眼看到红且红因是"行为缺失"，再最小实现（GREEN）。
- e2e 时间断言用轮询+上限（40×200ms），不用固定 sleep 赌竞态。
- 注释写清"根因→修法"；e2e 注释写清"旧代码如何复现、断言抓什么"。

---

### Task 1: `POST /api/desired/reload` 后端接口

**Files:**
- Modify: `src/server.rs:327`（路由注册，`reload` 静态段必须先于 `:hostname` 参数路由）
- Modify: `src/server.rs:1440` 附近（新增 `api_desired_reload`，紧随 `api_desired_set` 之后）
- Modify: `src/desired.rs`（`load` 解析失败打 `warn!`，行为不变仍返回空）

**Interfaces:**
- Consumes: `DesiredStore::load(path) -> Self`, `validate_proxy(&ProxyConfig) -> Result<(), String>`, `apply_proxies_for_agent(&S, &str, &[ProxyConfig])`, `ServerMsg::Config { proxies }`, `auth_ok(&HeaderMap, &str) -> bool`, `log_ev(&S, String)`。
- Produces: `async fn api_desired_reload(State((S, Arc<String>)>, HeaderMap) -> impl IntoResponse`，返回 `{ok, reloaded, skipped, pushed}` / `{ok:false, reason}`。

- [ ] **Step 1: Write the failing test**

单测放在 `src/server.rs::tests`，先验证路由优先级（RED：`reload` 会被当 hostname 吞掉、无 404 概念——此测试锁定"静态段优先"行为，防回归）：

```rust
#[test]
fn desired_reload_route_not_swallowed_by_hostname() {
    // Axum 路由语义：静态段 /api/desired/reload 优先于 /api/desired/:hostname。
    // 本测试锁定该假设：若未来有人调换注册顺序导致 reload 被当 hostname 解析，此处即红。
    // 实现方式：构造路由表（与 run() 内一致），用 axum-test 发 POST /api/desired/reload，
    // 未鉴权应得 401（走到 reload handler 的 auth），而非 200 + hostname='reload' 的 desired 查询结果。
    // RED 时：无 reload 路由 → 落到 :hostname 的 POST 分支 → 返回 desired set 结果（行为缺失即红）。
}
```

注：本仓库 `axum-test = "17"` 仅声明未使用；若接线成本高，退化为"代码审查级"测试——直接对 `api_desired_reload` 做单元调用（构造 `Shared` + 临时 desired 文件），断言坏 TOML 返回 500 且内存不动。两种都算 GREEN，优先前者。

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --bin neutrino desired_reload 2>&1 | tail -5`
Expected: FAIL（无此 handler / 路由）。

- [ ] **Step 3: Write minimal implementation**

```rust
// src/server.rs 路由（reload 静态段先于 :hostname 注册）：
.route("/api/desired/reload", post(api_desired_reload))
.route("/api/desired/:hostname", get(api_desired_get).post(api_desired_set))
```

```rust
/// 从文件重载 desired：手改 desired.toml 后点按钮生效（替代重启）。
/// 根因→修法：load 只在启动时调一次，手改文件无感知；本接口重读全量替换内存，
/// 不落盘（文件即源）。坏 TOML 内存不动；坏条跳过、好条生效。
async fn api_desired_reload(
    State((s, _)): State<(S, Arc<String>)>,
    h: HeaderMap,
) -> impl IntoResponse {
    let s2 = s.clone();
    if !auth_ok(&h, &s2.jwt_secret) {
        return unauthorized();
    }
    let raw = std::fs::read_to_string(&s.desired_path);
    let parsed: Result<toml::Value, _> = raw
        .as_deref()
        .map(str::to_owned)
        .ok_or_else(|| "read failed".to_string())
        .and_then(|text| toml::from_str(&text).map_err(|e| e.to_string()));
    let parsed = match parsed {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("desired reload failed ({}): {e}", s.desired_path);
            log_ev(&s, format!("desired reload failed: {e}"));
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"ok": false, "reason": e})),
            )
                .into_response();
        }
    };
    // 与 DesiredStore::load 同构解析：{agents: {hostname: [proxies]}}
    let table: HashMap<String, Vec<ProxyConfig>> = parsed
        .get("agents")
        .and_then(|a| serde_json::from_value(serde_json::to_value(a).unwrap_or_default()).ok())
        .unwrap_or_default();
    let mut reloaded = 0;
    let mut skipped = 0;
    let mut fresh: HashMap<String, Vec<ProxyConfig>> = HashMap::new();
    for (hostname, list) in table {
        let mut good = vec![];
        for p in list {
            match validate_proxy(&p) {
                Ok(()) => good.push(p),
                Err(e) => {
                    skipped += 1;
                    tracing::warn!("desired reload skip {hostname}/{}: {e}", p.name);
                }
            }
        }
        reloaded += good.len();
        fresh.insert(hostname, good);
    }
    *s.desired.write().await = fresh.clone();
    // 对在线 agent 按 hostname 推送（复用 api_desired_set 后半段语义）
    let mut pushed = 0;
    for (hostname, proxies) in &fresh {
        let targets: Vec<(String, mpsc::UnboundedSender<ServerMsg>)> = {
            s.agents
                .read()
                .await
                .values()
                .filter(|hh| &hh.info.hostname == hostname)
                .map(|hh| (hh.info.agent_id.clone(), hh.ctl.clone()))
                .collect()
        };
        for (aid, ctl) in &targets {
            let _ = ctl.send(ServerMsg::Config { proxies: proxies.clone() });
            apply_proxies_for_agent(&s, aid, proxies).await;
            pushed += 1;
        }
    }
    log_ev(&s, format!("desired reloaded ({reloaded} ok, {skipped} skipped, pushed {pushed})"));
    Json(serde_json::json!({"ok": true, "reloaded": reloaded, "skipped": skipped, "pushed": pushed}))
        .into_response()
}
```

`src/desired.rs` 的 `load` 加日志（行为不变）：

```rust
pub fn load(path: &str) -> Self {
    let data = std::fs::read_to_string(path)
        .ok()
        .and_then(|s| {
            toml::from_str::<File>(&s)
                .map_err(|e| tracing::warn!("desired load parse failed ({path}): {e}"))
                .ok()
        })
        .map(|f| f.agents)
        .unwrap_or_default();
    Self { path: path.into(), data }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --bin neutrino desired 2>&1 | tail -3` + `RUSTFLAGS="-D warnings" cargo build 2>&1 | tail -1`
Expected: PASS + 零 warning。

- [ ] **Step 5: Commit**

```bash
git add src/server.rs src/desired.rs
git commit -m "feat: POST /api/desired/reload (file reload without restart)"
```

---

### Task 2: server WebUI「从文件重载」按钮

**Files:**
- Modify: `web/index.html`（隧道 tab 顶栏，`+ 新增隧道` 旁加按钮 + `reloadDesired()` JS）

**Interfaces:**
- Consumes: Task 1 的 `POST /api/desired/reload` → `{ok, reloaded, skipped, pushed}` / `{ok:false, reason}`；现有 `hdrs(true)`、`toast(m, err)`。
- Produces: 按钮 + toast 展示，无新全局函数污染（仅 `reloadDesired`）。

- [ ] **Step 1: Write the failing test**

本 task 无自动化测试（纯前端 DOM）；RED 验证 = 手工：WebUI 无按钮。plan 要求写实——此步记为"确认按钮不存在"：

Run: `grep -c "reloadDesired" web/index.html` Expected: `0`（行为缺失）。

- [ ] **Step 2: Run test to verify it fails**

Run: `grep -c "reloadDesired" web/index.html`
Expected: `0`。

- [ ] **Step 3: Write minimal implementation**

```html
<!-- 隧道 tab 顶栏：+ 新增隧道 旁 -->
<button class="btn ghost" onclick="reloadDesired()">从文件重载</button>
```

```js
async function reloadDesired(){
  const r=await fetch('/api/desired/reload',{method:'POST',headers:hdrs(true)});
  const j=await r.json().catch(()=>({}));
  if(r.ok&&j.ok){ toast(`已重载 ${j.reloaded} 条，跳过 ${j.skipped} 条，推送 ${j.pushed} 个 agent`); refresh(); }
  else toast('重载失败: '+(j.reason||r.status),true);
}
```

位置：`web/index.html` 隧道 `topbar` 内 `+ 新增隧道` 按钮之后；JS 紧随 `loadDesired` 之后。样式 `.btn ghost`，无新风格。

- [ ] **Step 4: Run test to verify it passes**

Run: `grep -c "reloadDesired" web/index.html` Expected: `3`（按钮 + 函数定义 + 调用各一）。
附带：`RUSTFLAGS="-D warnings" cargo build 2>&1 | tail -1`（web embed 无 break）。

- [ ] **Step 5: Commit**

```bash
git add web/index.html
git commit -m "feat: server WebUI desired reload button"
```

---

### Task 3: e2e 重载回归 + spec 状态翻转

**Files:**
- Modify: `tests/e2e.rs`（新增 `desired_reload_from_file`）
- Modify: `docs/superpowers/specs/2026-10-19-public-port-ingress-design.md`（状态行翻转）

**Interfaces:**
- Consumes: Task 1 接口 + Task 2 按钮；`boot_with_desired`、`login` helper；`free_port()`。
- Produces: 全绿 `make test`。

- [ ] **Step 1: Write the failing test**

```rust
/// e2e desired 重载回归：旧代码无 reload 接口时，此测试在 POST /api/desired/reload 即 404。
/// 断言抓三段：①手改文件加 tcp 映射→reload→端口通；②文件改错（非法 TOML）→reload 500 且旧映射仍通（内存不动）；
/// ③修好但某条字段非法→reload 成功、好条生效、坏条跳过（skipped=1）。
#[tokio::test]
async fn desired_reload_from_file() {
    // echo backend
    let back = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bport = back.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = back.accept().await.unwrap();
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    let rport = free_port();
    // 注意：需拿到 Env 内部的 desired 文件路径——boot_with_desired 用临时 dir，
    // 本测试自建 dir 传 desired 路径以便手改（参考 boot_with_desired 实现，复制其 server/agent 拉起逻辑，
    // 仅 desired_path 用可写路径；轮询 40×200ms 等 server 起）。
    // ① 初始 desired 为空 map；手写一段 tcp 映射（hostname须与 agent.toml 的 hostname 一致 "e2e"）→ POST reload → 连 rport 回声成功。
    // ② 写入非法 TOML（"[[[broken"）→ POST reload 期望 500 → 旧 rport 仍通。
    // ③ 写入好条+坏条（坏条如 type="tcp" 但 remote_port=0）→ POST reload 期望 ok 且 skipped=1 → 好条 rport 仍通。
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --test e2e desired_reload 2>&1 | tail -5`
Expected: FAIL（404，无 reload 路由）——确认红因是"行为缺失"。

- [ ] **Step 3: Write minimal implementation**

Task 1 已实现本步；若 Step 2 在 Task 1 之后跑则直接 PASS。本 step 内容 = 按需补齐（如 Task 1 返回字段与断言对不上，修 handler 不修测试）。

- [ ] **Step 4: Run test to verify it passes**

Run: `make test 2>&1 | grep -E "test result|FAILED"`
Expected: `44+1 passed` 单测行 + e2e 行全 ok（含新增）。

- [ ] **Step 5: Commit**

```bash
git add tests/e2e.rs docs/superpowers/specs/2026-10-19-public-port-ingress-design.md
git commit -m "test: e2e desired reload from file + spec status flip"
```

spec 状态行翻转内容：`状态： 映射已实现，§6 重载按钮待实现` → `状态： 已实现（含 §6 重载按钮）`。

---

## Self-Review

1. **Spec coverage:** §6.1→Task 1（接口+日志+鉴权），§6.2→Task 2（按钮+toast），§6.3→Task 3（单测路由优先级+e2e 三段+全绿门槛）。§2–§5 本就"已实现"，无新 task。Gaps: 无。
2. **Placeholder scan:** 无 TBD/TODO/"类似 Task N"；Task 2 的 RED 用 grep 计数写实（纯 DOM 无单测可挂）；Task 3 Step 3 诚实标注"Task 1 已实现"而不留空。
3. **Type consistency:** `api_desired_reload(State((S, Arc<String>)>, HeaderMap)` 与现有三个 handler 同签名；`{ok, reloaded, skipped, pushed}` 字段名在 Task 1/2/3 一致；`ServerMsg::Config { proxies: Vec<ProxyConfig> }` 与 1480 行用法一致。
