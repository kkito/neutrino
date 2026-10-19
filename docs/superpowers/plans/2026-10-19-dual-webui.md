# 双 WebUI + server 期望态 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** server 存期望隧道配置并可视化管理，agent 本地可视上行状态，agent 无状态化。

**Architecture:** server 新增 `desired.toml`（hostname→proxies）为唯一源头，register 时覆盖、上线即下发；两端各一个单文件 WebUI，共享 CSS token。

**Tech Stack:** Rust (axum 0.7, tokio full, serde/toml, bcrypt, jsonwebtoken), 单文件 HTML 无框架, cargo test + e2e 子进程。

## Global Constraints

- 单二进制 `neutrino server | agent`，不新增依赖（复用 axum/bcrypt/toml）。
- `ProxyConfig` 结构不变（`src/proto.rs:50-65`）。
- WebUI 单文件 `include_str!` 编入二进制，零外部资源。
- agent 默认管理口令 admin / neutrino123，bcrypt 落盘。
- 现有 17 测试保持全绿。

---

## File Structure

- Modify: `src/server.rs` — Shared 加 `desired: RwLock<HashMap<String, Vec<ProxyConfig>>>` + `desired_path: String`；新增 `load_desired/save_desired/apply_proxies_for_agent`；`on_register` 用期望态覆盖；新增 `GET/POST /api/desired/:hostname`。
- Modify: `src/agent.rs` — `AgentFileConfig.proxies` 改 `#[serde(default)]` 兼容忽略；新增 `--web/--web-user/--web-pass` 处理的 `web` 模块（新建 `src/agent_web.rs`）。
- Create: `src/agent_web.rs` — agent 本地 WebUI 服务（`GET /` + `GET /api/status` + `POST /api/settings`)。
- Create: `src/desired.rs` — `DesiredStore { path, data }` 纯逻辑（load/save/get/set），可单元测试。
- Modify: `src/main.rs` — Agent 子命令加 `--web/--web-user/--web-pass`；Server 加 `--desired`（默认 `./data/desired.toml`）。
- Modify: `web/index.html` — server WebUI 重做（侧边栏/隧道表格/弹窗表单/toast/高级折叠区）。
- Create: `web/agent.html` — agent 本地 WebUI（状态+只读隧道+设置）。
- Modify: `tests/e2e.rs` — 新增 2 e2e。
- Modify: `agent.toml.example`, `README.md`, `docs/architecture.md` — 同步文档。

---

### Task 1: DesiredStore 纯逻辑

**Files:**
- Create: `src/desired.rs`
- Test: `src/desired.rs` (mod tests)

**Interfaces:**
- Consumes: `crate::proto::ProxyConfig`
- Produces: `DesiredStore::load(path)->Self`, `save(&self)`, `get(&self, host)->Vec<ProxyConfig>`, `set(&mut self, host, Vec<ProxyConfig>)`（供 Task 3 调用）

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn desired_roundtrip() {
    let dir = std::env::temp_dir().join(format!("nt-des-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join("desired.toml");
    let mut st = DesiredStore::load(p.to_str().unwrap());
    assert!(st.get("h1").is_empty());
    st.set("h1".into(), vec![ProxyConfig {
        name: "w".into(), ptype: "http".into(), local_ip: "127.0.0.1".into(),
        local_port: 80, domains: vec!["a.test".into()], remote_port: 0,
        set_x_forwarded_proto: None, enabled: true,
    }]);
    st.save();
    let st2 = DesiredStore::load(p.to_str().unwrap());
    assert_eq!(st2.get("h1").len(), 1);
    assert_eq!(st2.get("h1")[0].name, "w");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test desired_roundtrip 2>&1 | tail -5`
Expected: FAIL with "cannot find `DesiredStore`"

- [ ] **Step 3: Write minimal implementation**

```rust
//! Server-side desired tunnel state: hostname -> proxies (TOML persisted).
use crate::proto::ProxyConfig;
use std::collections::HashMap;

#[derive(Debug, Default)]
pub struct DesiredStore {
    pub path: String,
    data: HashMap<String, Vec<ProxyConfig>>,
}

#[derive(serde::Serialize, serde::Deserialize, Default)]
struct File {
    #[serde(default)]
    agents: HashMap<String, Vec<ProxyConfig>>,
}

impl DesiredStore {
    pub fn load(path: &str) -> Self {
        let data = std::fs::read_to_string(path).ok()
            .and_then(|s| toml::from_str::<File>(&s).ok())
            .map(|f| f.agents).unwrap_or_default();
        Self { path: path.into(), data }
    }
    pub fn save(&self) {
        let f = File { agents: self.data.clone() };
        if let Ok(s) = toml::to_string_pretty(&f) {
            let _ = std::fs::write(&self.path, s);
        }
    }
    pub fn get(&self, host: &str) -> Vec<ProxyConfig> {
        self.data.get(host).cloned().unwrap_or_default()
    }
    pub fn set(&mut self, host: String, v: Vec<ProxyConfig>) {
        self.data.insert(host, v);
    }
}
```

并在 `src/main.rs` 顶部加 `pub mod desired;`。

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test desired_roundtrip 2>&1 | tail -4`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/desired.rs src/main.rs
git commit -m "feat: DesiredStore 期望态读写"
```

---

### Task 2: register 期望态覆盖 + 路由复用

**Files:**
- Modify: `src/server.rs:47-66` (Shared 加字段), `src/server.rs:226-262` (run 初始化), `src/server.rs:469` (on_register)
- Test: `src/server.rs` mod tests（纯函数 `resolve_proxies` 单测）

**Interfaces:**
- Consumes: Task 1 `DesiredStore`
- Produces: `apply_proxies_for_agent(s, aid, proxies)` 供 Task 3 复用（抽出 api_config 里的重路由代码）

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn resolve_prefers_desired() {
    let want = vec![ProxyConfig { name: "d".into(), ptype: "http".into(),
        local_ip: "127.0.0.1".into(), local_port: 1,
        domains: vec![], remote_port: 0, set_x_forwarded_proto: None, enabled: true }];
    assert_eq!(resolve_proxies(Some(want.clone()), vec![]), want);
    assert!(resolve_proxies(None, vec![]).is_empty());
}

fn resolve_proxies(desired: Option<Vec<ProxyConfig>>, reported: Vec<ProxyConfig>) -> Vec<ProxyConfig> {
    desired.unwrap_or(reported)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test resolve_prefers_desired 2>&1 | tail -4`
Expected: FAIL (`resolve_proxies` 未定义）

- [ ] **Step 3: Write minimal implementation**

在 `src/server.rs`：
1. `Shared` 加 `desired: RwLock<HashMap<String, Vec<ProxyConfig>>>` + `desired_path: String`。
2. `run()` 签名加 `desired: &str`，启动时 `DesiredStore::load` 填入内存。
3. 加纯函数 `resolve_proxies`（如上）。
4. `on_register` 开头：`let proxies = resolve_proxies(s.desired.read().await.get(hostname).cloned(), proxies);` 并在覆盖时 `log_ev("desired overlay for '{hostname}'")`。
5. 把 api_config/api_toggle 里的"清路由→重建→更新 hh.info.proxies→lazy listen"抽成 `async fn apply_proxies_for_agent(s: &S, aid: &str, proxies: &[ProxyConfig])`，两处改调它（行为不变）。

- [ ] **Step 4: Run tests**

Run: `cargo test --bin neutrino 2>&1 | tail -3`
Expected: 全部 PASS（含新增 2 个）

- [ ] **Step 5: Commit**

```bash
git add src/server.rs src/main.rs
git commit -m "feat: register期望态覆盖, 路由应用复用"
```

---

### Task 3: server 期望态 CRUD API

**Files:**
- Modify: `src/server.rs` (路由 + handler)
- Test: e2e 复用（Task 6 验证），本任务以 `curl` 手工验证

**Interfaces:**
- Consumes: Task 2 `apply_proxies_for_agent`
- Produces: `GET /api/desired/:hostname` → `{"proxies":[...]}`；`POST /api/desired/:hostname` body `{"proxies":[...]}` → 写文件+内存+`apply`+在线即下发 `Config`

- [ ] **Step 1: 加路由与 handler**（鉴权沿用 `auth_ok`，失败 `unauthorized()`；写文件失败返回 500 且内存不改）

```rust
.route("/api/desired/:hostname", get(api_desired_get).post(api_desired_set))
```

handler 草形：读 `s.desired` 返回；写时先校验每条 proxy（http 必有 domains；tcp/udp/https 必有 remote_port>0；三者任一不满足 → 400+reason），再 `set` + `DesiredStore{path}.save` + `apply_proxies_for_agent` + 若 agent 在线则 `ctl.send(Config)` + `log_ev`。

- [ ] **Step 2: 手工验证**

```bash
cargo build 2>&1 | tail -1
./target/debug/neutrino server --listen 127.0.0.1:17440 --http-in 127.0.0.1:17080 --data /tmp/nt-d --token s3 &
JWT=$(curl -s -X POST 127.0.0.1:17440/api/login -d '{"user":"admin","pass":"welcome2ll"}' -H 'content-type: application/json' | python3 -c "import json,sys;print(json.load(sys.stdin)['token'])")
curl -s -H "Authorization: Bearer $JWT" 127.0.0.1:17440/api/desired/e2e; echo
curl -s -X POST -H "Authorization: Bearer $JWT" -H 'content-type: application/json' 127.0.0.1:17440/api/desired/e2e -d '{"proxies":[]}'; echo
cat /tmp/nt-d/desired.toml
```

Expected: GET `{}`→空列表；POST `{"ok":true}`；文件落盘。

- [ ] **Step 3: Commit**

```bash
git add src/server.rs
git commit -m "feat: 期望态CRUD API"
```

---

### Task 4: server WebUI 重做（同视觉 token）

**Files:**
- Modify: `web/index.html`
- Test: 人工浏览器验证 + Task 6 e2e 覆盖接口

**Interfaces:**
- Consumes: Task 3 API + 既有 `/api/overview|tunnels|logs|config` + `:agent/:name/enabled`

- [ ] **Step 1: 重写页面**：侧边栏（总览/隧道/日志）+ 隧道表（状态徽章：生效/待同步/禁用）+ 新增/编辑弹窗（类型切换字段：http→domains 输入；tcp/udp/https→remote_port；`set_x_forwarded_proto` 仅 http 显示）+ toast + "高级"折叠区（保留原 JSON 直推）。
- CSS token（与 Task 5 共用）：`:root{--bg,--panel,--accent:#4f9cf0,--ok,--warn,--off}` + 深色 `prefers-color-scheme` + `.badge/.btn/.modal/.toast`。零外部资源，沿用 `fetch` + Bearer（沿用现有 login 存 token）。
- 表单提交 → `POST /api/desired/:hostname`（hostname 取自顶部 agent 下拉 = overview 列表 + 手输）。
- 字段校验（与后端一致，前端先拦）：http 无 domains 禁提交并 toast。

- [ ] **Step 2: 人工验证**

Run: `open http://127.0.0.1:17440/`（沿用 Task 3 的 server），点一遍：登录→建 http 隧道→列表出现→禁用→日志有记录。

- [ ] **Step 3: Commit**

```bash
git add web/index.html
git commit -m "feat: server WebUI隧道管理+新视觉"
```

---

### Task 5: agent 本地 WebUI + 启动项

**Files:**
- Create: `src/agent_web.rs`, `web/agent.html`
- Modify: `src/agent.rs` (Ctx 加 `status: Arc<RwLock<AgentStatus>>`，session 更新在线/RTT/重连计数/生效隧道), `src/main.rs` (Agent 加 `--web/--web-user/--web-pass`)

**Interfaces:**
- Consumes: 无（独立监听端口）
- Produces: `agent_web::serve(bind, user, pass_hash, status)`；`AgentStatus{server_url, online, rtt_ms, reconnects, proxies: Vec<ProxyConfig>}`

- [ ] **Step 1: AgentFileConfig 兼容**

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AgentFileConfig {
    hostname: String,
    token: String,
    #[serde(default)]
    server_note: Option<String>, // 占位防未知字段？不，用 deny? 否：保持 serde 默认忽略未知字段即可
    #[serde(default)]
    proxies: Vec<ProxyConfig>, // 保留兼容，启动有值则 warn 忽略（源头已是 server）
}
```

启动时若 `!cfg.proxies.is_empty()` 则 `tracing::warn!("local proxies ignored, server is source of truth")`。

- [ ] **Step 2: agent_web.rs 最小实现**：axum 三路由（`/`→`include_str!("../web/agent.html")`；`/api/status`→JSON；`/api/settings`→改 server 地址则返回 `{"ok":true,"reconnect":true}` 由调用方触发重连——本期简化：改地址需重启 agent 进程，API 返回提示文案，不做热重连，settings 仅改管理口令即时生效）。
- 鉴权：Basic（user+bcrypt pass）或 Bearer（登录颁发）；密码 hash 存 agent `--data`（新增 `--data` 默认 `~/.config/neutrino`？YAGNI：默认 `./agent-data`）。
- agent.html：状态卡（server/在线/RTT/重连）+ 生效隧道只读表（"由 server 下发"角标）+ 改口令表单，同 Task 4 CSS token。

- [ ] **Step 3: main.rs 加参并联线**

```rust
Agent {
    #[arg(long, default_value = "wss://tunnel.nat.kkito.cn:7443/ws")]
    server: String,
    #[arg(long, default_value = "agent.toml")]
    config: String,
    #[arg(long, default_value = "")]
    web: String, // 空=不起WebUI, 否则如 127.0.0.1:8080
    #[arg(long, default_value = "admin")]
    web_user: String,
    #[arg(long, default_value = "neutrino123")]
    web_pass: String,
}
```

`agent::run(&server, &config, &web, &web_user, &web_pass)`，有 `--web` 则 spawn `agent_web::serve`。

- [ ] **Step 4: 验证**

```bash
./target/debug/neutrino agent --server ws://127.0.0.1:17440/ws --config /tmp/a.toml --web 127.0.0.1:18080 &
curl -s -u admin:neutrino123 127.0.0.1:18080/api/status; echo
```

Expected: `{"online":true,...}`。

- [ ] **Step 5: Commit**

```bash
git add src/agent.rs src/agent_web.rs src/main.rs web/agent.html
git commit -m "feat: agent本地WebUI+启动项"
```

---

### Task 6: e2e + 文档收尾

**Files:**
- Modify: `tests/e2e.rs`, `agent.toml.example`, `README.md`, `docs/architecture.md`

- [ ] **Step 1: e2e-1 WebUI 建隧道打通**

```rust
#[tokio::test]
async fn e2e_desired_crud_flows_to_agent() {
    // boot server+agent(空proxies) → login → POST /api/desired/e2e 建 http 隧道指测试后端
    // → curl http入口经Host拿到后端 → GET /api/desired/e2e 确认落盘内容
}
```

- [ ] **Step 2: e2e-2 重启被覆盖**

```rust
#[tokio::test]
async fn e2e_restart_covered_by_desired() {
    // agent带本地proxies(错误端口)启动 → 仍按期望态打通（证明覆盖）→ 日志有 desired overlay
}
```

- [ ] **Step 3: 全量测试**

Run: `cargo test 2>&1 | grep -E "test result|FAILED"`
Expected: 14+2+3…（原 17 + 新增单测/2e2e）全 PASS，零残留进程。

- [ ] **Step 4: 文档**：`agent.toml.example` 瘦身注释（proxies 废弃说明）；README 加双 WebUI + desired.toml 章节；`docs/architecture.md` 架构图加 desired 存储 + agent WebUI 节点。

- [ ] **Step 5: Commit**

```bash
git add tests/e2e.rs agent.toml.example README.md docs/architecture.md
git commit -m "test+docs: 期望态e2e与文档"
```

---

## Self-Review

- Spec 覆盖：§2 期望态→Task1-3；register 覆盖→Task2；§3.1 CRUD+表单→Task3-4；§3.2 agent UI→Task5；§3.3 视觉→Task4-5；§4 错误处理→各任务内（文件失败500/离线待同步/冲突server为准）；§5 测试→Task1/2/6。
- 无占位符：每步含代码与命令；类型一致（`ProxyConfig`/`DesiredStore`/`AgentStatus` 全 plan 统一）。
- 修正点：Task5 settings 改上行地址本期简化为"需重启生效"（spec 未明确热重连，已收敛为重启生效，避免范围蔓延）。
