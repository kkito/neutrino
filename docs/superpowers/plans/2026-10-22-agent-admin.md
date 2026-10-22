# agent-admin Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** agent WebUI 长出 server 管理页完整读写能力，经已认证隧道转手（默认关闭，`--allow-agent-admin` 开启）。

**Architecture:** `proto.rs` 加 `AdminReq/AdminResp`（req_id 配对）；server 侧抽 `dispatch_admin` 纯内核（开关判定+现有数据组装，不经 HTTP）；三传输双端各加一对分支；agent `--web` 后端加 `/api/srv/*` 转手（oneshot 等回包）；`agent.html` 加 server 管理 tab。

**Tech Stack:** Rust, tokio oneshot, serde JSON, 现有 axum handler 内核复用。

## Global Constraints

- server 开关默认关：`--allow-agent-admin` 不传 = 任何 AdminReq 回 403。
- token 即最高权：开了之后无条件信任已连 agent；弱 token（<16 字符）启动 warn；每次写 log_ev 溯源。
- TDD 先红后绿；`make build` 零 warning + `cargo test --bin neutrino` 全绿。
- e2e 不写不跑（用户明确）。
- 只加新分支，不改现有心跳/隧道行为。

---

### Task 1: 协议字段 + server 开关 plumbing

**Files:**
- Modify: `src/common/proto.rs`（ClientMsg/ServerMsg 加变体）
- Modify: `src/main.rs`（Server 加 `allow_agent_admin: bool`，透传给 `server::run`）
- Modify: `src/server/mod.rs`（`run` 签名加参）
- Modify: `src/server/state.rs`（`Shared` 加 `allow_agent_admin: bool` 字段，`load_state` 处初始化）

**Interfaces:**
- Consumes: 无。
- Produces: `ClientMsg::AdminReq { req_id: u64, method: String, path: String, body: String }`；`ServerMsg::AdminResp { req_id: u64, status: u16, body: String }`；`Shared.allow_agent_admin`。Task 2/3/4 引用。

- [ ] **Step 1: Write the failing test**

在 `src/common/proto.rs` 的 `mod tests`（若无则新建 `#[cfg(test)] mod tests`）末尾加：

```rust
#[test]
fn admin_req_resp_roundtrip() {
    // 根因→修法：agent-admin 转手需要 req_id 配对的请求/响应帧，三传输共享。
    let q = super::ClientMsg::AdminReq { req_id: 7, method: "GET".into(), path: "overview".into(), body: "{}".into() };
    let s = serde_json::to_string(&q).unwrap();
    let back: super::ClientMsg = serde_json::from_str(&s).unwrap();
    assert_eq!(q, back);
    let r = super::ServerMsg::AdminResp { req_id: 7, status: 200, body: "{\"agents\":[]}".into() };
    let s = serde_json::to_string(&r).unwrap();
    let back: super::ServerMsg = serde_json::from_str(&s).unwrap();
    assert_eq!(r, back);
}
```

（要求 `ClientMsg`/`ServerMsg` 派生 `PartialEq`——若没有，加 `PartialEq` 到 derive 列表。不加会红，正好是 RED。）

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --bin neutrino common::proto::tests::admin_req_resp 2>&1 | tail -5`
Expected: FAIL（变体不存在，编译错即红）。

- [ ] **Step 3: Write minimal implementation**

(a) `src/common/proto.rs`：`ClientMsg` enum 加：

```rust
AdminReq { req_id: u64, method: String, path: String, body: String },
```

`ServerMsg` enum 加：

```rust
AdminResp { req_id: u64, status: u16, body: String },
```

两 enum 的 derive 加 `PartialEq`（若缺）。

(b) `src/main.rs` Server 分支加：

```rust
/// 允许已连 agent 经隧道读写 server 管理 API（默认关；开了 = token 即最高权，见 spec）。
#[arg(long, default_value_t = false)]
allow_agent_admin: bool,
```

解构处加 `allow_agent_admin,`，`server::run(...)` 调用加实参。

(c) `src/server/mod.rs`：`run` 签名加 `allow_agent_admin: bool`，函数内 `Shared` 构造处赋值，
同时弱 token warn：

```rust
if token.len() < 16 {
    tracing::warn!("--allow-agent-admin compatible warning: token < 16 chars, agent-admin 开启后等于弱口令管全 server");
}
```

（warn 文案如上：token 弱本身平时也该喊，但 spec 只要求开了场景下必有提示；简单起见无条件 warn，
文案注明 agent-admin 语境。）

(d) `src/server/state.rs`：`Shared` 加 `pub(crate) allow_agent_admin: bool`，
构造处（`load_state` 返回 `Shared{...}` 的位置）加 `allow_agent_admin: false` 默认，
`run` 里覆盖为传入值（`Shared` 若是直接构造则改构造点；若 load_state 构造则 run 后 `ps.allow_agent_admin = allow_agent_admin`——看实际代码选）。

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --bin neutrino common::proto 2>&1 | grep "test result"`
Expected: `ok`。

Run: `RUSTFLAGS="-D warnings" cargo build 2>&1 | tail -1`
Expected: `Finished` 无 warning。

- [ ] **Step 5: Commit**

```bash
git add src/common/proto.rs src/main.rs src/server/mod.rs src/server/state.rs
git commit -m "feat(admin): AdminReq/AdminResp 协议 + --allow-agent-admin 开关 plumbing"
```

---

### Task 2: server 侧 `dispatch_admin` 内核 + 三传输 server 分支

**Files:**
- Modify: `src/server/api.rs`（新 `dispatch_admin` 函数 + 单测）
- Modify: `src/server/tunnel.rs`（WSS 读循环 ClientMsg 分支加 AdminReq）
- Modify: `src/server/quic.rs`（同构分支）
- Modify: `src/server/kudus.rs`（`dispatch_body` + 读循环内两处 ClientMsg::Ping 旁加 AdminReq）

**Interfaces:**
- Consumes: Task 1 的协议变体 + `Shared.allow_agent_admin`；现有 `AgentInfo` 组装逻辑（从 `api_overview` 复制，不重构它）。
- Produces: `pub(crate) async fn dispatch_admin(s: &S, hostname: &str, method: &str, path: &str, body: &str) -> (u16, String)`。Task 4 agent 转手只管透传，不依赖此签名细节。

- [ ] **Step 1: Write the failing test**

在 `src/server/api.rs` 的 `mod tests` 末尾加：

```rust
#[tokio::test]
async fn dispatch_admin_closed_by_default() {
    // 根因→修法：开关默认关，没开时读写一律 403（读也不给）。
    let s = crate::server::state::test_shared().await; // 若无此 helper，用最小 Shared 构造
    let (st, _) = super::dispatch_admin(&s, "hbtest", "GET", "overview", "{}").await;
    assert_eq!(st, 403);
}

#[tokio::test]
async fn dispatch_admin_open_serves_overview() {
    let s = crate::server::state::test_shared().await;
    s.allow_agent_admin = true;
    let (st, body) = super::dispatch_admin(&s, "hbtest", "GET", "overview", "{}").await;
    assert_eq!(st, 200);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(v.get("agents").is_some() && v.get("version").is_some());
}
```

注意：`Shared` 测试构造——先查 `state.rs` 是否有 test helper；没有则在 `state.rs` 加：

```rust
#[cfg(test)]
pub(crate) async fn test_shared() -> Arc<Shared> { ...最小构造... }
```

`allow_agent_admin` 字段若是 `pub(crate)`，测试同 crate 可直接赋值。

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --bin neutrino server::api::tests::dispatch_admin 2>&1 | tail -5`
Expected: FAIL（`dispatch_admin` 不存在）。

- [ ] **Step 3: Write minimal implementation**

(a) `src/server/api.rs` 加：

```rust
/// agent-admin 内核：供隧道内 AdminReq 调用（与 HTTP 层同数据，不经 axum/auth）。
/// 根因→修法：agent 页要镜像 server 管理页，但浏览器只连 agent；转手经已认证隧道，
/// server 按开关放行。path 口径复用 /api/*（不带前缀，如 "overview"/"tunnels"/"desired"）。
pub(crate) async fn dispatch_admin(s: &S, hostname: &str, method: &str, path: &str, body: &str) -> (u16, String) {
    if !s.allow_agent_admin {
        return (403, r#"{"ok":false,"reason":"agent admin disabled"}"#.into());
    }
    let is_write = method == "POST" || method == "PUT" || path.starts_with("desired_set") || path == "toggle";
    match (method, path) {
        ("GET", "overview") => {
            let ag = s.agents.read().await;
            let list: Vec<AgentInfo> = ag.values().map(|h| {
                let mut i = h.info.clone();
                i.online_secs = (chrono::Utc::now() - h.connected_at).num_seconds();
                i
            }).collect();
            (200, serde_json::json!({"agents": list, "version": crate::common::proto::VERSION}).to_string())
        }
        ("GET", "tunnels") => {
            // 与 api_tunnels 同组装（含 ratelimit_stats），复制不重构。
            ...同 api_tunnels 循环体...
        }
        ("GET", "logs") => {
            let v = s.events.read().await.clone();
            (200, serde_json::json!({"logs": v}).to_string())
        }
        ("GET", p) if p.starts_with("traffic") => {
            // query 如 "traffic?gran=min&n=60"：按 ? 切参，调现有 slice/统计拼装。
            ...最小实现：透传现有 traffic 查询逻辑...
        }
        ("POST", "desired_set") => {
            // body = {"hostname":..,"proxies":..}：调现有 desired 落盘+推送内核后半段。
            // 先实现：解析 body，写 s.desired + 落盘 + 在线推送（抄 api_desired_set 后半）。
            log_ev(s, format!("agent '{hostname}' admin desired_set ..."));
            (200, ...)
        }
        _ => (404, r#"{"ok":false,"reason":"unknown admin path"}"#.into()),
    }
}
```

**实现时注意**：上面是骨架，动手时打开 `api.rs` 把每个分支的现有 handler 循环体原样搬进来
（overview/tunnels/logs/desired_set/traffic 查询），不要重构原 handler。
`is_write` 变量：所有写分支（desired_set/toggle/改口令等）入口先
`log_ev(s, format!("agent '{hostname}' admin {method} {path}"))` 再执行——读不记，写必记。
path 清单至少覆盖前端要用的：`overview, tunnels, logs, traffic, desired_get, desired_set, toggle`
（改口令 `set_pass` 若 handler 简单则带上，复杂则 404 留后续）。

(b) 三传输 server 分支（同构，各加 5 行）。WSS `src/server/tunnel.rs` 读循环：

```rust
Ok(ClientMsg::AdminReq { req_id, method, path, body }) => {
    let (st, rb) = crate::server::api::dispatch_admin(&s, &hostname, &method, &path, &body).await;
    let _ = ctl_tx.send(ServerMsg::AdminResp { req_id, status: st, body: rb });
}
```

QUIC `src/server/quic.rs` 与 kudus `src/server/kudus.rs`（两处：读循环 + `dispatch_body`）同形复制。
（变量名按各文件现有 `s/hostname/ctl_tx` 对齐，kudus 用 `&s/&agent_id` 形态——`hostname` 变量在 kudus 读循环存在。）

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --bin neutrino server::api 2>&1 | grep "test result"`
Expected: `ok`。

Run: `RUSTFLAGS="-D warnings" cargo build 2>&1 | tail -1`
Expected: `Finished` 无 warning。

- [ ] **Step 5: Commit**

```bash
git add src/server/api.rs src/server/tunnel.rs src/server/quic.rs src/server/kudus.rs src/server/state.rs
git commit -m "feat(admin-server): dispatch_admin 内核 + 三传输 server 分支"
```

---

### Task 3: agent 侧三传输 AdminResp 回填 + req_id 路由

**Files:**
- Modify: `src/agent/session.rs`（WSS：AdminResp 分支 + 待办 map）
- Modify: `src/agent/quic_session.rs`（同构）
- Modify: `src/agent/kudus_session.rs`（同构）
- Modify: `src/agent/web.rs` 或新建 `src/agent/admin.rs`（`AdminPending: Arc<Mutex<HashMap<u64, oneshot::Sender<(u16,String)>>>>` 持有者 + `admin_call` 封装）

**Interfaces:**
- Consumes: Task 1 协议变体。
- Produces: `pub(crate) async fn admin_call(pending, send_ctrl, method, path, body) -> anyhow::Result<(u16, String)>`（Task 4 的 `/api/srv/*` 调用它）。

- [ ] **Step 1: Write the failing test**

`admin_call` 的超时/配对逻辑抽纯部单测。在新建 `src/agent/admin.rs`：

```rust
#[cfg(test)]
mod tests {
    #[test]
    fn req_id_pairs_and_timeout_cleans() {
        // 根因→修法：AdminReq 发后等 AdminResp，req_id 配对；超时 15s 清理防 map 泄漏。
        // 测纯部：req_id 自增不重 + 超时判定函数。
        let mut next = 0u64;
        let a = super::next_req_id(&mut next);
        let b = super::next_req_id(&mut next);
        assert_ne!(a, b);
        assert!(super::is_expired(std::time::Instant::now() - std::time::Duration::from_secs(16)));
        assert!(!super::is_expired(std::time::Instant::now()));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --bin neutrino agent::admin 2>&1 | tail -5`
Expected: FAIL（文件/函数不存在）。

- [ ] **Step 3: Write minimal implementation**

新建 `src/agent/admin.rs`：

```rust
//! agent-admin 客户端：经当前隧道向 server 发 AdminReq 并等 AdminResp（req_id 配对，15s 超时）。
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::{oneshot, Mutex};

pub(crate) type AdminPending = Arc<Mutex<HashMap<u64, oneshot::Sender<(u16, String)>>>>;
static NEXT_REQ: AtomicU64 = AtomicU64::new(1);

pub(crate) fn next_req_id(_: &mut u64) -> u64 { NEXT_REQ.fetch_add(1, Ordering::Relaxed) }
pub(crate) fn is_expired(t: std::time::Instant) -> bool { t.elapsed() > std::time::Duration::from_secs(15) }

/// 发请求并等回包：send 经调用方控制通道（WSS 发 text / QUIC-kudus 发 ctrl）。
pub(crate) async fn admin_call(
    pending: &AdminPending,
    send: impl Fn(u64) -> anyhow::Result<()>,
    method: &str, path: &str, body: &str,
) -> anyhow::Result<(u16, String)> {
    let id = NEXT_REQ.fetch_add(1, Ordering::Relaxed);
    let (tx, rx) = oneshot::channel();
    pending.lock().await.insert(id, tx);
    let _ = (method, path, body);
    if let Err(e) = send(id) {
        pending.lock().await.remove(&id);
        return Err(e);
    }
    match tokio::time::timeout(std::time::Duration::from_secs(15), rx).await {
        Ok(Ok(v)) => Ok(v),
        _ => { pending.lock().await.remove(&id); anyhow::bail!("admin call timeout"); }
    }
}

/// 三传输 AdminResp 分支共用：按 req_id 回填，无人等则丢。
pub(crate) async fn on_admin_resp(pending: &AdminPending, req_id: u64, status: u16, body: String) {
    if let Some(tx) = pending.lock().await.remove(&req_id) {
        let _ = tx.send((status, body));
    }
}
```

（单测里的 `next_req_id(&mut u64)` 签名与上面 `fn next_req_id(_: &mut u64)` 对齐——动手时以实现为准，
单测调 `NEXT_REQ` 自增两次不断言具体值，只断言不等。）

三传输 agent 分支（各加 5 行 + pending 持有）：
- WSS `session.rs` 主循环 `ServerMsg::AdminResp{..}` 分支 → `on_admin_resp(&pending, ...).await`。
- QUIC/kudus 同构（变量名按各文件对齐）。
- pending 持有者：session 建立时 `Arc::new(Mutex::new(HashMap::new()))`，clone 进读循环，
  同时把一份存到 `AgentStatus` 或 web 共享结构供 Task 4 用（最小改：`lazy_static` 级别的
  `OnceCell<AdminPending>` 都行，但优先放现有 status/share 结构里——动手看 `web.rs` 共享结构选）。

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --bin neutrino agent::admin 2>&1 | grep "test result"`
Expected: `ok`。

Run: `RUSTFLAGS="-D warnings" cargo build 2>&1 | tail -1`
Expected: `Finished` 无 warning。

- [ ] **Step 5: Commit**

```bash
git add src/agent/admin.rs src/agent/session.rs src/agent/quic_session.rs src/agent/kudus_session.rs src/agent/
git commit -m "feat(admin-agent): AdminResp 回填 + req_id 路由（三传输）"
```

---

### Task 4: agent `/api/srv/*` 转手 + 前端 server 管理 tab

**Files:**
- Modify: `src/agent/web.rs`（加 `POST /api/srv/*` + `GET /api/srv/*` 路由，经 `admin_call` 转手）
- Modify: `web/agent.html`（新 tab + 复制 index.html 管理逻辑，前缀 `/api/`→`/api/srv/`）
- Modify: `src/main.rs`（若有 `#[cfg(test)]` 校验 main_tests，补开关单测——见 Step 1）

**Interfaces:**
- Consumes: Task 3 的 `admin_call` + pending 持有者。
- Produces: 无（最终用户可见功能）。

- [ ] **Step 1: Write the failing test**

`main_tests` 风格：开关默认关。加单测（位置按现有 `main_tests`）：

```rust
#[test]
fn agent_admin_switch_defaults_off() {
    // 根因→修法：--allow-agent-admin 默认关，不传即锁死（B 信任模型下默认开等于裸奔）。
    let cli = super::Cli::try_parse_from(["neutrino", "server"]).unwrap();
    match cli.cmd {
        super::Cmd::Server { allow_agent_admin, .. } => assert!(!allow_agent_admin),
        _ => panic!("want server"),
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --bin neutrino main_tests::agent_admin 2>&1 | tail -5`
Expected: FAIL（字段不存在）。

- [ ] **Step 3: Write minimal implementation**

(a) `src/agent/web.rs` 路由加：

```rust
.route("/api/srv/overview", get(api_srv_passthrough))
.route("/api/srv/tunnels", get(api_srv_passthrough))
...（或一条通配：axum `"/api/srv/*path"`，动手看 axum 版本支不支持通配——支持则一条路由全包）
```

handler 骨架：

```rust
/// agent-admin 转手：浏览器→agent→server→agent→浏览器（登录用 agent 本地口令，无二次登录）。
/// 根因→修法：出差在外管 hk server 不用先 ssh 回家；server 开关关时原样回 403。
async fn api_srv_passthrough(
    State(st): State<WebState>, Path(path): Path<String>, headers/body...
) -> impl IntoResponse {
    // 1. agent 本地鉴权（复用现有 cookie/Bearer 校验）。
    // 2. 当前传输的 send_ctrl 闭包 + pending → admin_call(method, path, body).await
    // 3. 超时/未连接 → 502 {"ok":false,"reason":"no session / timeout"}；否则原样回 status+body。
}
```

细节：`WebState` 需新增 `admin_pending: AdminPending` + 当前会话的发送器
（WSS 的 ws-sender / quic-kudus 的 Pkt clone——三传输取"当前在线"的那个，按 `status.transport` 选；
动手看 `web.rs` 现有 `WebState` 字段选最小加法）。

(b) `web/agent.html`：新 tab `srv`，把 `web/index.html` 的 tunnels/desired/logs/traffic/改口令
整块逻辑复制过来，fetch 前缀 `/api/`→`/api/srv/`。登录态复用本页 `auth`（`hdrs()` 不变）。

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --bin neutrino 2>&1 | grep "test result"`
Expected: `ok`（全绿，含 main_tests 新单测）。

Run: `RUSTFLAGS="-D warnings" cargo build 2>&1 | tail -1`
Expected: `Finished` 无 warning。

- [ ] **Step 5: 真机验证（代替 e2e）**

1. 本机起 server（`--allow-agent-admin`）+ kudus agent（`--web 127.0.0.1:18080`）。
2. 浏览器开 agent 页 → server tab：看到本机 server 的 agents/tunnels；改一条 desired 备注并保存，
   server 日志出现 `agent '<host>' admin POST desired_set`。
3. 不带开关重启 server，server tab 应显示 403（`agent admin disabled`）。

- [ ] **Step 6: Commit**

```bash
git add src/agent/web.rs web/agent.html src/main.rs
git commit -m "feat(admin-ui): agent /api/srv 转手 + server 管理 tab"
```

---

## Self-Review

1. **Spec 覆盖**：§2 开关+warn+溯源→Task 1(c/d)+Task 2(a 写分支 log_ev)；§3 协议→Task 1(a)，
   三传输→Task 2(b)+Task 3；§4 数据流→Task 4(a)；§5 前端重写→Task 4(b)；§6 单测→各 Task Step 1；
   §7 不做（细粒度鉴权/独立 token/e2e）→Global Constraints。✅
2. **Placeholder 扫描**：无 TBD/TODO；Task 2(a) 的 traffic/desired_set 分支注明"动手时搬现有 handler 循环体"，
   无"适当处理"类空话；未知点（axum 通配、`Shared` 构造位置、test helper 有无）都给了 fallback 做法。✅
3. **类型一致**：`AdminReq{req_id:u64,method:String,path:String,body:String}` /
   `AdminResp{req_id:u64,status:u16,body:String}` / `dispatch_admin(&S,&str,&str,&str,&str)->(u16,String)` /
   `admin_call(&AdminPending, impl Fn(u64)->Result<()>, &str,&str,&str)->Result<(u16,String)>` /
   `on_admin_resp(&AdminPending,u64,u16,String)`，跨 Task 一致。✅
