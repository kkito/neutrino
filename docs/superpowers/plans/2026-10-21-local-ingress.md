# Local Ingress Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** agent 自带内网 HTTP 入口：`http://<name><suffix>` 直访名下 http 隧道（basic_auth/XFP/热配与 server 对齐）。

**Architecture:** 新文件 `src/agent/local_ingress.rs`（裸 TCP accept → 读头 → 抽 host → 剥后缀 → 查 `status.proxies` 快照 → basic_auth → XFP → dial 本地 → `copy_bidirectional`）；`mod.rs` 起独立 task＋复用 `egress_reload` watcher 双重启；`web.rs` 加 4 设置项＋状态行。会话零改动（读 `status.proxies` 快照，三传输 Config 处已更新）。

**Tech Stack:** tokio TcpListener/copy_bidirectional，复用 `crate::server::http_util::{extract_host, inject_xfp}`、`crate::common::proto::check_basic_auth`。

## Global Constraints

- `RUSTFLAGS="-D warnings"` 下 `make build` 零 warning 才算过。
- `make test`（单元＋e2e）全绿才提交；e2e 时间断言用轮询（40×200ms）不用固定 sleep 赌竞态。
- TDD：先写失败测试（RED），亲眼见红且红因是"行为缺失"，再最小实现（GREEN）。
- `ProxyConfig` 零字段新增；`status.proxies` 是唯一隧道数据源（不读文件、不读 session 上下文）。
- miss/auth 失败只 `debug` 日志＋客户端 4xx，默认 info 无噪音；目录页只列隧道名，不泄露 token/上行地址。
- bind 失败只 warn＋`status.local_ingress_err`，不 abort 主循环；`suffix` 为空或无前导 `.` 即不启动＋`err` 写明原因。

---

### Task 1: 纯函数＋配置＋状态字段（单测锁定行为）

**Files:**
- Modify: `src/agent/mod.rs`（`LocalIngress` 结构体＋`AgentFileConfig.local_ingress`＋`read_local_ingress_file2`）
- Modify: `src/agent/web.rs`（`AgentStatus` 加 `local_ingress_listen/on/err`＋`LocalSettings` 4 字段＋`merge_local_ingress_toml`＋`read_local_ingress_file`）
- Modify: `agent.toml.example`（`[local_ingress]` 注释样例）
- Test: 上述两文件的 `mod tests`

**Interfaces:**
- Consumes: `EgressHttp`/`read_egress_file2`/`merge_egress_toml` 模式（同文件内照抄）；`AgentStatus` 既有字段。
- Produces: `LocalIngress { enabled: bool, listen_ip: String, listen_port: u16, suffix: String }`；`pub(crate) fn strip_ingress_name(host: &str, suffix: &str) -> Option<String>`（放 `local_ingress.rs`，本任务先建文件只含此函数＋单测）；`merge_local_ingress_toml(v, enabled, ip, port, suffix)`；`directory_page(names: &[String]) -> (u16, Vec<u8>)` 返回 `(404, body)`。

- [ ] **Step 1: 建 `src/agent/local_ingress.rs` 纯函数＋失败单测**

```rust
//! agent 本地 HTTP 入口：内网 `http://<name><suffix>` 直访名下 http 隧道。
//! 转发面见 Task 2；本文件先落纯函数（单测锁定）。

/// 剥泛域名：host 已小写去端口；suffix 须小写且以 '.' 开头。
/// 单 label 才接受（`a.b.suffix` 拒绝防越权）；miss 返回 None（调用方回 404 目录页）。
pub(crate) fn strip_ingress_name(host: &str, suffix: &str) -> Option<String> {
    if suffix.is_empty() || !suffix.starts_with('.') {
        return None;
    }
    let label = host.strip_suffix(suffix)?;
    if label.is_empty() || label.contains('.') {
        return None;
    }
    Some(label.to_string())
}

/// 404 目录页：只列隧道名（不泄露 token/上行地址）。返回 (status, body)。
pub(crate) fn directory_page(names: &[String]) -> (u16, Vec<u8>) {
    let mut body = String::from("no such tunnel\navailable:");
    for n in names {
        body.push(' ');
        body.push_str(n);
    }
    body.push('\n');
    (404, body.into_bytes())
}
```

单测（同文件 `mod tests`）：大小写（`WEB.LOCAL.E2E`＋小写 suffix 命中 `web`）、多 label 拒绝（`evil.deep.local.e2e`→None）、空 label 拒绝（`.local.e2e`→None）、suffix 无前导点（`local.e2e`→None）、空 suffix→None、目录页含名不含 token。

- [ ] **Step 2: 运行确认失败**

Run: `cargo test --bin neutrino local_ingress 2>&1 | tail -5`
Expected: FAIL（`local_ingress.rs` 不存在／`mod.rs` 未声明模块）。

- [ ] **Step 3: 最小实现——建文件＋`mod.rs` 接线＋配置/状态字段**

`mod.rs` 加：
```rust
pub mod local_ingress;
```
`AgentFileConfig` 加：
```rust
    #[serde(default)]
    pub local_ingress: LocalIngress;
```
`LocalIngress`（仿 `EgressHttp`，默认 `false/"0.0.0.0"/80/""`）＋ `read_local_ingress_file2`（仿 `read_egress_file2`，返回 `(bool, String, u16, String)`）。
`web.rs`：`AgentStatus` 加 `local_ingress_listen: String`／`local_ingress_on: bool`／`local_ingress_err: Option<String>`（全 `#[serde(default)]`）；`LocalSettings` 加 `local_enabled: Option<bool>`／`local_ip: Option<String>`／`local_port: Option<u16>`／`local_suffix: Option<String>`；`merge_local_ingress_toml`（仿 `merge_egress_toml` 写 `[local_ingress]` 四键）；`read_local_ingress_file`。
`agent.toml.example` 追加注释样例：
```toml
# 内网 HTTP 入口（可选）：内网经 http://<隧道名><suffix> 直访本地隧道，不走公网。
# [local_ingress]
# enabled = false
# listen_ip = "0.0.0.0"
# listen_port = 80
# suffix = ".local.xxx.com"
```

- [ ] **Step 4: 运行确认通过**

Run: `cargo test --bin neutrino local_ingress 2>&1 | tail -3` → ok；`RUSTFLAGS="-D warnings" cargo build 2>&1 | tail -1` 无 warning。
Expected: 单测全绿（含新增 8＋）。

- [ ] **Step 5: Commit**

```bash
git add src/agent/local_ingress.rs src/agent/mod.rs src/agent/web.rs agent.toml.example
git commit -m "feat(local-ingress): pure fns + config + status fields (strip/domain page/toml merge)"
```

### Task 2: 转发面＋生命周期＋WebUI（e2e 前本地可手动验证）

**Files:**
- Modify: `src/agent/local_ingress.rs`（`serve_local_ingress`＋`handle_conn`）
- Modify: `src/agent/mod.rs`（启动 task＋reload watcher 双重启）
- Modify: `src/agent/web.rs`（`api_settings` 接 4 字段＋状态页行＋`write_settings_toml` 透传）
- Test: `src/agent/local_ingress.rs::tests`（handle 级用 `TcpListener` 回环：命中/basic_auth/dial 失败三分支走真 socket 测）

**Interfaces:**
- Consumes: Task 1 的 `strip_ingress_name/directory_page/LocalIngress`；`AgentStatus.proxies` 快照；`extract_host/inject_xfp/check_basic_auth`；`DualOut` 不需要（本地直连 `TcpStream::connect`，不断言上行）。
- Produces: `pub(crate) async fn serve_local_ingress(cfg: LocalIngress, status: Arc<RwLock<AgentStatus>>)`；`status.local_ingress_*` 三字段由本 task 维护。

- [ ] **Step 1: 写失败测试（回环真 socket 三分支）**

```rust
#[tokio::test]
async fn handle_conn_routes_by_suffix() {
    // backend 固定回 "BACKEND"
    let back = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bport = back.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = back.accept().await.unwrap();
            tokio::spawn(async move {
                let mut b = vec![0u8; 4096];
                let _ = s.read(&mut b).await;
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 7\r\nconnection: close\r\n\r\nBACKEND").await;
            });
        }
    });
    // status.proxies 快照挂一条 http 隧道 name=web local_port=bport
    // serve_local_ingress 起在 127.0.0.1:0（取实际端口），suffix=".local.e2e"
    // ① Host: web.local.e2e → 含 BACKEND；② Host: nope.local.e2e → 404 含 web；
    // ③ 多 label → 404。同时测 suffix 为空时 serve 直接返回（起后 status.err 非空且端口无监听）。
}
```

basic_auth 分支：隧道配 `basic_auth="u:p"`，无头→401 且有 `WWW-Authenticate`，对头→200。

- [ ] **Step 2: 运行确认失败**

Run: `cargo test --bin neutrino local_ingress 2>&1 | tail -5`
Expected: FAIL（`serve_local_ingress` 未定义）。

- [ ] **Step 3: 最小实现转发面**

```rust
pub(crate) async fn serve_local_ingress(cfg: LocalIngress, status: Arc<RwLock<AgentStatus>>) {
    {
        let mut st = status.write().await;
        st.local_ingress_listen = format!("{}:{}", cfg.listen_ip, cfg.listen_port);
        st.local_ingress_on = cfg.enabled;
        st.local_ingress_err = None;
    }
    if !cfg.enabled {
        return;
    }
    let suffix = cfg.suffix.to_lowercase();
    if suffix.is_empty() || !suffix.starts_with('.') {
        status.write().await.local_ingress_err =
            Some("suffix empty or missing leading dot (e.g. .local.xxx.com)".into());
        return;
    }
    let lis = match tokio::net::TcpListener::bind(format!("{}:{}", cfg.listen_ip, cfg.listen_port)).await {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!("local ingress bind failed: {e:#}");
            status.write().await.local_ingress_err = Some(format!("bind failed: {e:#}"));
            return;
        }
    };
    tracing::info!("local ingress on {}:{}", cfg.listen_ip, cfg.listen_port);
    loop {
        let Ok((inbound, _)) = lis.accept().await else { continue; };
        let (st, sf) = (status.clone(), suffix.clone());
        tokio::spawn(async move {
            if let Err(e) = handle_conn(inbound, st, &sf).await {
                tracing::debug!("local ingress conn ended: {e:#}");
            }
        });
    }
}
```

`handle_conn`：读到 `\r\n\r\n`（64K 上限）→ `extract_host(unsafe str)` → `strip_ingress_name` → 快照找
`p.ptype=="http" && p.enabled && p.name==label` → miss 回 `directory_page(names)`（names 取自快照 http 隧道名）；
basic_auth 校验（`check_basic_auth(&headers, p.basic_auth.as_deref())`，需把头收集成 `http::HeaderMap`，
失败回 401＋realm）；`inject_xfp(head, p.set_x_forwarded_proto)`（配了才注入）→
`TcpStream::connect((local_ip, local_port))` 失败回 `502` → `copy_bidirectional`。
头解析：用 `httparse`？——零新依赖：手动按 `\r\n` 切首行＋`k: v` 行（沿用 server ingress 手拼风格，不引入解析器）。

- [ ] **Step 4: mod.rs 接线＋web.rs 表单＋运行验证**

`mod.rs run()`：egress 启动块之后并列起 `serve_local_ingress(cfg.local_ingress.clone(), status.clone())`
（独立 `AbortHandle` 复用 `egress_cur`？——不，单开 `local_cur`＋同一 `egress_rx` watcher 内双重启：
watcher 收到 bump 后依次重起 egress 与 local ingress，读各自 `read_*_file2`）。
`web.rs`：`LocalSettings` 4 字段进 `api_settings`（`write_settings_toml` 加参透传 `merge_local_ingress_toml`），
状态页加一行 `local ingress: on/off listen suffix err`。
Run: `cargo test --bin neutrino 2>&1 | tail -2` 全绿＋`RUSTFLAGS="-D warnings" cargo build` 零 warning。

- [ ] **Step 5: Commit**

```bash
git add src/agent/local_ingress.rs src/agent/mod.rs src/agent/web.rs
git commit -m "feat(local-ingress): suffix routing + basic_auth/XFP + dual-restart wiring + webui"
```

### Task 3: e2e 全链路＋README（收尾）

**Files:**
- Modify: `tests/e2e.rs`（`local_ingress_http_names`）
- Modify: `README.md`（agent 本地入口一节＋agent.toml.example 联动说明）
- Test: `cargo test` 全量

**Interfaces:**
- Consumes: Task 2 的 `serve_local_ingress`（e2e 经真 agent 子进程间接触发，不直调）。
- Produces: e2e 覆盖 6 断言；README 文档。

- [ ] **Step 1: 写失败 e2e**

```rust
#[tokio::test]
async fn local_ingress_http_names() {
    // backend http 固定 body "local-ok"；backend2 配 basic_auth "u:p" 回 "secret-ok"
    // agent.toml 追加 [local_ingress] enabled=true listen 127.0.0.1:0?——端口须确定：
    // 取 free_port() 写入文件（e2e 已有 free_port helper）。
    // suffix=".local.e2e"；proxies 走 boot() 的 server desired（server 为准，agent 本地 proxies 忽略——
    // 注意：local ingress 读 status.proxies（server 下发），所以 desired 里要有这两条 http 隧道）。
    // 断言：① web.local.e2e→local-ok；② nope.local.e2e→404含web；③ evil.deep.local.e2e→404；
    // ④ sec.local.e2e 无头→401，有头→secret-ok；⑤ /api/config 清空→404（轮询，上限8s）；
    // ⑥ 64KB body 一致。backend 用裸 TcpListener 回固定 HTTP（仿 kudus e2e 写法）。
}
```

注意：`boot()` 不写 `[local_ingress]`——e2e 内拼 agent.toml 时追加段落（读 boot 源码确认拼接点；必要时加 `boot_with_local_ingress` helper）。

- [ ] **Step 2: 运行确认失败**

Run: `cargo test --test e2e local_ingress 2>&1 | tail -5`
Expected: FAIL（agent 无本地入口 → 全 4xx/连接拒）。

- [ ] **Step 3: 最小实现让 e2e 变绿**

本任务一般零产品代码（Task 2 已实现）；若红因是 e2e helper 拼接问题，修 helper（`boot` 追加 `[local_ingress]` 段）。
热配清空断言：调 server `/api/config` 空 proxies（仿 kudus e2e），轮询 `gone` 上限 40×200ms。

- [ ] **Step 4: 全量验证＋README**

Run: `make build`＋`make test` 全绿（93＋28 基础上 ＋1 e2e，单测 ＋N）。
README 在"双 WebUI"行附近加一节：内网入口配置/URL 格式/断网上行仍可用/目录页说明。

- [ ] **Step 5: Commit**

```bash
git add tests/e2e.rs README.md
git commit -m "feat(local-ingress): e2e names/auth/hot-clear/big-body + docs"
```

## Self-Review

- Spec 覆盖：§1 配置→Task1＋Task2 接线；§2 匹配→Task1 纯函数＋单测；§3 转发→Task2；§4 生命周期/可观测→Task2；§5 测试→Task1/2/3；§6 非目标无任务（正确）。
- 占位扫描：无 TBD；端口 `127.0.0.1:0` 疑问已在 Task3 注明用 `free_port()` 确定端口（agent 监听须已知端口，`:0` 取实际端口方案在单测 Task2-step3 用 `local_addr()`，e2e 用 `free_port`，两处写法都已给出）。
- 类型一致：`LocalIngress` 字段名四处统一（enabled/listen_ip/listen_port/suffix）；`AgentStatus` 新增三字段名统一（local_ingress_listen/on/err）；`merge_local_ingress_toml(v, enabled, ip, port, suffix)` 签名在 Task1 定义、Task2 调用一致。
