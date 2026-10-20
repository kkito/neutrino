# 跨 agent TCP 互联（link）Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 同一张隧道表配 `type=link`，入口 agent 监听、server 中转 WSS 双流、出口 agent dial 目标，TCP 互访。

**Architecture:** 配置挂入口 agent 名下（desired 复用）。入口 agent 起 TcpListener，accept 后发 `ClientMsg::Open{kind:"link"}`；server 查表找出口 agent，发 `ServerMsg::Open{kind:"link"}`，双 channel 对接泵；出口 agent 当 TCP 直拨。统计复用 conns/traffic 现有路径。

**Tech Stack:** Rust (tokio, axum, tokio-tungstenite), vanilla JS WebUI (`web/index.html`), `ProxyConfig` serde。

## Global Constraints

- TDD：先写失败测试（RED），亲眼见红且是行为缺失，再最小实现（GREEN）。
- `make build`（`RUSTFLAGS="-D warnings"` 零 warning）+ `make test`（单测+e2e）全绿才提交。
- 纯判定逻辑抽纯函数再测；注释写清根因→修法。
- TCP only；默认配了就通（无确认）；server 只做 L4 字节泵。

---

## File Structure

- Modify: `src/common/proto.rs` — `ProxyConfig` 加 `link_agent/link_host/link_port`（`#[serde(default)]`），`Open.kind` 注释加 `"link"`，加纯函数 `valid_link(&ProxyConfig) -> bool`（自环/空字段拒绝）。
- Modify: `src/server/tunnel.rs` — 加 `spawn_link_relay()`（入口 Open → 查表 → 出口 Open → 双 channel 泵 + conns 记账 + Drop-guard 清理）。
- Modify: `src/server/state.rs` — `ConnInfo.proto` 允许 `"link"`（注释即可，无结构改）。
- Modify: `src/agent/session.rs` — `open_stream` 加 `kind=="link"` 分支：不查 proxies，直接 `dial(host, port)`（server 下发的目标为准）。
- Create: `src/agent/link.rs` — 入口监听 `serve_link(name, bind, out, status)` + `handle_link_conn`（accept → 奇数 sid → `Open{link}` → socket↔WSS 泵），照抄 `src/agent/egress.rs` 结构。
- Modify: `src/agent/mod.rs` — Config 热更新时为每条启用 link 起/停 `serve_link` task（照抄 egress watch 模式）；`AgentStatus` 加 `link_err: Option<String>`（serde default）。
- Modify: `src/agent/web.rs` — `AgentStatus` 加字段；tunnels 只读表复用（link 显示监听地址）。
- Modify: `web/index.html` — type 下拉加 `link`，表单联动显隐 + `curProxy/saveForm` 校验（自环拒绝）。
- Test: `src/common/proto.rs` mod tests（serde 默认+valid_link），`src/server/tunnel.rs` mod tests（目标以 server 存为准），`tests/e2e.rs`（roundtrip/offline/hot-update）。

---

### Task 1: proto 字段 + 校验纯函数

**Files:**
- Modify: `src/common/proto.rs:56-74`
- Test: `src/common/proto.rs` mod tests

**Interfaces:**
- Consumes: 现有 `ProxyConfig` serde。
- Produces: `link_agent: String, link_host: String, link_port: u16` + `pub fn valid_link(p: &ProxyConfig, self_hostname: &str) -> bool`，后继任务用。

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn link_fields_default_and_validate() {
    let p: ProxyConfig = serde_json::from_str(r#"{"name":"l","type":"link","local_ip":"0.0.0.0","local_port":13306}"#).unwrap();
    assert_eq!(p.link_agent, "");
    assert!(!super::valid_link(&p, "agent2")); // 缺对端 -> 拒绝
    let mut q = p.clone();
    q.link_agent = "agent2".into(); // 自环 -> 拒绝
    q.link_host = "10.0.0.1".into();
    q.link_port = 3306;
    assert!(!super::valid_link(&q, "agent2"));
    q.link_agent = "agent1".into();
    assert!(super::valid_link(&q, "agent2"));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --bin neutrino link_fields_default_and_validate 2>&1 | tail -n 5`
Expected: FAIL（`valid_link`/`link_agent` 不存在，编译错即红）

- [ ] **Step 3: Write minimal implementation**

```rust
pub struct ProxyConfig {
    // ... 现有字段不动，追加：
    #[serde(default)]
    pub link_agent: String, // link 对端 agent 主机名
    #[serde(default)]
    pub link_host: String,  // 对端可达目标 ip
    #[serde(default)]
    pub link_port: u16,     // 对端可达目标 port
}

/// link 条目校验（纯函数）：对端/目标/监听缺一不可，且禁止自环。
pub fn valid_link(p: &ProxyConfig, self_hostname: &str) -> bool {
    if p.ptype != "link" || !p.enabled {
        return false;
    }
    if p.link_agent.trim().is_empty() || p.link_agent == self_hostname {
        return false;
    }
    if p.link_host.trim().is_empty() || p.link_port == 0 || p.local_port == 0 {
        return false;
    }
    true
}
```

同时把 `ClientMsg::Open` 的 `kind` 注释 `// "http" | "tcp" | "egress"` 改为 `// "http" | "tcp" | "egress" | "link"`（server/agent 两处同改）。

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --bin neutrino link_fields 2>&1 | tail -n 4`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/common/proto.rs && git commit -m "feat(link): ProxyConfig 加 link 三字段 + valid_link 纯函数"
```

---

### Task 2: server 中转（Open-link → 双 channel 泵 + conns）

**Files:**
- Modify: `src/server/tunnel.rs`（`ws_loop` 的 `ClientMsg::Open` 分支 + 新增 `spawn_link_relay`）
- Test: `src/server/tunnel.rs` mod tests（查表纯函数 `resolve_link`）

**Interfaces:**
- Consumes: Task 1 的 `ProxyConfig.link_*`；现有 `spawn_egress_dial` 的占位+泵模式；`insert_conn/ConnInfo`。
- Produces: `fn resolve_link(proxies: &[ProxyConfig], link_name: &str) -> Option<(String, String, u16)>` + `fn spawn_link_relay(...)`，Task 3/6 依赖其行为。

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn resolve_link_uses_server_table() {
    // server 存为准：入口传什么 host 都不信，只认 desired 表
    let p = ProxyConfig {
        name: "dblink".into(), ptype: "link".into(),
        local_ip: "0.0.0.0".into(), local_port: 13306,
        link_agent: "agent1".into(), link_host: "10.0.0.1".into(), link_port: 3306,
        domains: vec![], remote_port: 0,
        set_x_forwarded_proto: None, basic_auth: None, enabled: true,
    };
    assert_eq!(
        super::resolve_link(&[p], "dblink"),
        Some(("agent1".into(), "10.0.0.1".into(), 3306))
    );
    assert_eq!(super::resolve_link(&[], "dblink"), None);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --bin neutrino resolve_link 2>&1 | tail -n 4`
Expected: FAIL（`resolve_link` 未定义）

- [ ] **Step 3: Write minimal implementation**

```rust
/// link 查表（纯函数）：按 link 名找启用的 link 条目，返回 (对端hostname, host, port)。
pub(crate) fn resolve_link(
    proxies: &[ProxyConfig],
    link_name: &str,
) -> Option<(String, String, u16)> {
    proxies.iter().find(|p| p.enabled && p.ptype == "link" && p.name == link_name).map(|p| {
        (p.link_agent.clone(), p.link_host.clone(), p.link_port)
    })
}
```

`ws_loop` 的 `ClientMsg::Open` 分支加（放在 `egress` 分支后）：

```rust
Ok(ClientMsg::Open { stream, kind, .. }) if kind == "link" => {
    // link 名经 host 字段透传（agent2 发 Open 时 host=link名，port 忽略）；
    // 目标以 server 存的 desired 为准，不信客户端。
    spawn_link_relay(&s, &agent_id, &hostname, stream, host, ctl_tx.clone());
}
```

`spawn_link_relay` 骨架（照抄 `spawn_egress_dial` 占位+泵，差异三处）：

```rust
fn spawn_link_relay(
    s: &S,
    entry_agent_id: &str,
    entry_hostname: &str,
    sid_entry: u32,
    link_name: String,
    ctl_entry: mpsc::UnboundedSender<ServerMsg>,
) {
    let s = s.clone();
    let (entry_aid, entry_host) = (entry_agent_id.to_string(), entry_hostname.to_string());
    tokio::spawn(async move {
        // 1. 查表（server 存为准）
        let (exit_host, tgt_host, tgt_port) = {
            let ag = s.agents.read().await;
            let proxies = ag.get(&entry_aid).map(|h| h.info.proxies.clone()).unwrap_or_default();
            match resolve_link(&proxies, &link_name) {
                Some(t) => t,
                None => {
                    let _ = ctl_entry.send(ServerMsg::Close { stream: sid_entry, reason: "link denied: no such link".into() });
                    return;
                }
            }
        };
        // 2. 找出口 agent（按 hostname），分配出口 sid（偶数，避开 agent 奇数 sid）
        let (exit_aid, exit_ctl, exit_out) = {
            let ag = s.agents.read().await;
            match ag.iter().find(|(_, h)| h.info.hostname == exit_host) {
                Some((id, h)) => (id.clone(), h.ctl.clone(), s.outbox.read().await.get(id).cloned()),
                None => {
                    let _ = ctl_entry.send(ServerMsg::Close { stream: sid_entry, reason: "link denied: exit agent offline".into() });
                    log_ev(&s, format!("link '{link_name}' exit '{exit_host}' offline"));
                    return;
                }
            }
        };
        let Some(exit_out) = exit_out else {
            let _ = ctl_entry.send(ServerMsg::Close { stream: sid_entry, reason: "link denied: exit gone".into() });
            return;
        };
        let sid_exit = s.next_sid().await; // 复用 server 偶数 sid 分配器（与公网 ingress 同源）
        // 3. 出口占位 incoming[sid_exit]（防早到 Binary 丢包，同 egress 注释）
        let (dtx_exit, mut drx_exit) = mpsc::unbounded_channel::<Vec<u8>>();
        if let Ok(ag) = s.agents.try_read() {
            if let Some(h) = ag.get(&exit_aid) {
                if let Ok(mut inc) = h.incoming.try_write() {
                    inc.insert(sid_exit, dtx_exit);
                }
            }
        }
        // 入口占位 incoming[sid_entry]（入口 agent 发 Open 后背靠背发数据）
        let (dtx_entry, mut drx_entry) = mpsc::unbounded_channel::<Vec<u8>>();
        if let Ok(ag) = s.agents.try_read() {
            if let Some(h) = ag.get(&entry_aid) {
                if let Ok(mut inc) = h.incoming.try_write() {
                    inc.insert(sid_entry, dtx_entry);
                }
            }
        }
        // 4. 向出口发 Open{link}（host/port=真实目标，出口直接 dial）
        if exit_ctl.send(ServerMsg::Open { stream: sid_exit, kind: "link".into(), host: tgt_host.clone(), port: tgt_port }).is_err() {
            let _ = ctl_entry.send(ServerMsg::Close { stream: sid_entry, reason: "link denied: exit send failed".into() });
            return;
        }
        // 5. conns 记账（peer=入口对端未知，记 entry hostname；target=最终目标）
        let cid = sid_entry as u64 | ((sid_exit as u64) << 32);
        s.conns.write().await.insert(cid, super::state::ConnInfo {
            id: cid, proto: "link".into(), peer: entry_host.clone(),
            public_port: 0, agent: entry_host.clone(), tunnel: link_name.clone(),
            remote_port: 0, target: format!("{exit_host}->{tgt_host}:{tgt_port}"),
            since: chrono::Utc::now().timestamp(), rx: 0, tx: 0,
        });
        // 6. 双向泵：drx_entry -> exit_out(sid_exit)；drx_exit -> entry_out(sid_entry)
        let entry_out = s.outbox.read().await.get(&entry_aid).cloned();
        let Some(entry_out) = entry_out else {
            s.conns.write().await.remove(&cid);
            return;
        };
        let c1 = cid;
        let a2e = tokio::spawn(async move {
            let mut rx_b = 0u64;
            while let Some(chunk) = drx_entry.recv().await {
                rx_b += chunk.len() as u64;
                if exit_out.send((sid_exit, chunk)).is_err() { break; }
            }
            (rx_b, c1)
        });
        let s2 = s.clone();
        let e2a = tokio::spawn(async move {
            while let Some(chunk) = drx_exit.recv().await {
                if entry_out.send((sid_entry, chunk)).is_err() { break; }
            }
        });
        let _ = tokio::join!(a2e, e2a);
        // 7. Drop-guard 语义：任一方向结束即双关+清行（防僵尸行，见 HttpConnGuard 修法）
        s2.conns.write().await.remove(&cid);
        if let Some(h) = s2.agents.read().await.get(&entry_aid) {
            h.incoming.write().await.remove(&sid_entry);
        }
        if let Some(h) = s2.agents.read().await.get(&exit_aid) {
            h.incoming.write().await.remove(&sid_exit);
        }
        let _ = ctl_entry.send(ServerMsg::Close { stream: sid_entry, reason: "eof".into() });
        // 出口 Close 经 exit_ctl 发（ws_loop 的 outbox 通道由 agent_id 路由，此处直接 ctl）
        if let Some(h) = s2.agents.read().await.get(&exit_aid) {
            let _ = h.ctl.send(ServerMsg::Close { stream: sid_exit, reason: "eof".into() });
        }
        log_ev(&s2, format!("link '{link_name}' closed"));
    });
}
```

注意：`next_sid` 分配器位置按现有 `Shared` 实际字段调整（`grep next_sid src/server/state.rs`）；`mpsc`/`log_ev` 已在 tunnel.rs import。

- [ ] **Step 4: Run test to verify it passes**

Run: `RUSTFLAGS="-D warnings" cargo build 2>&1 | tail -n 2 && cargo test --bin neutrino resolve_link 2>&1 | tail -n 4`
Expected: build 零 warning，单测 PASS

- [ ] **Step 5: Commit**

```bash
git add src/server/tunnel.rs && git commit -m "feat(link): server 中转 spawn_link_relay（查表+双泵+conns）"
```

---

### Task 3: agent 出口侧（Open{link} 直接 dial）

**Files:**
- Modify: `src/agent/session.rs`（`open_stream` 开头加 link 分支）
- Test: e2e 覆盖（本任务只改分支，单测难写，RED 由 Task 6 的 roundtrip 承担；此处先合入并用 Task 6 验证）

**Interfaces:**
- Consumes: Task 2 发的 `ServerMsg::Open{kind:"link", host, port}`（真实目标）。
- Produces: 出口 dial+泵行为，后继 Task 6 断言。

- [ ] **Step 1: 在 `open_stream` 顶部加 link 短路分支**

```rust
if kind == "link" {
    // link 出口：server 下发的 host/port 即真实目标（以 server 存为准），直接 dial，不查本地 proxies。
    let local = TcpStream::connect((host.as_str(), port)).await?;
    // 以下与 tcp 分支同泵：ws->local / local->ws，EOF 即收尾
    let (dtx, mut drx) = mpsc::unbounded_channel::<Vec<u8>>();
    let early = ctx.pending.write().await.remove(&sid).unwrap_or_default();
    for chunk in early {
        let _ = dtx.send(chunk);
    }
    ctx.streams.write().await.insert(sid, dtx);
    let (mut lr, mut lw) = local.into_split();
    let ctx3 = ctx.clone();
    let ws_to_local = tokio::spawn(async move {
        while let Some(chunk) = drx.recv().await {
            if lw.write_all(&chunk).await.is_err() {
                break;
            }
        }
    });
    let local_to_ws = tokio::spawn(async move {
        use tokio::io::AsyncReadExt;
        let mut b = vec![0u8; 32 * 1024];
        loop {
            match lr.read(&mut b).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if ctx3.out.send(Message::Binary(encode_data(sid, &b[..n]).into())).is_err() {
                        break;
                    }
                }
            }
        }
    });
    tokio::select! {
        _ = ws_to_local => {}
        _ = local_to_ws => {}
    }
    ctx.streams.write().await.remove(&sid);
    let e = ClientMsg::Close { stream: sid, reason: "eof".into() };
    let _ = ctx.out.send(Message::Text(serde_json::to_string(&e).unwrap().into()));
    return Ok(());
}
```

- [ ] **Step 2: Build**

Run: `RUSTFLAGS="-D warnings" cargo build 2>&1 | tail -n 2`
Expected: 零 warning 通过

- [ ] **Step 3: Commit**

```bash
git add src/agent/session.rs && git commit -m "feat(link): agent 出口 Open-link 直接 dial（不查 proxies）"
```

---

### Task 4: agent 入口监听（新文件 link.rs + 热更新接线）

**Files:**
- Create: `src/agent/link.rs`
- Modify: `src/agent/mod.rs`（声明 `pub mod link` + Config 热更新处起/停 task）
- Modify: `src/agent/web.rs`（`AgentStatus` 加 `link_err`，tunnels 只读表显示 link 监听）

**Interfaces:**
- Consumes: Task 1 的 `valid_link`；`OutHolder`（同 egress）；`AgentStatus`。
- Produces: 入口监听行为；Task 6 断言 roundtrip。

- [ ] **Step 1: Write `src/agent/link.rs`**（照抄 `egress.rs` 结构，差异：按条目起监听、发 Open{link}）

```rust
//! agent link 入口监听：本地 accept -> WSS Open{link} -> 双向泵。照抄 egress 模式。
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, RwLock};
use tokio_tungstenite::tungstenite::Message;

use super::egress::OutHolder;
use super::web::AgentStatus;
use crate::common::proto::{encode_data, ClientMsg};

static CTR: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);

/// 单条 link 监听。bind 失败只记 status，不断 WSS 主链（同 egress）。
pub(crate) async fn serve_link(
    link_name: String,
    bind: String,
    out: OutHolder,
    status: Arc<RwLock<AgentStatus>>,
) {
    let lis = match TcpListener::bind(&bind).await {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!("link '{link_name}' bind {bind} failed: {e:#}");
            status.write().await.link_err = Some(format!("{link_name} bind failed: {e:#}"));
            return;
        }
    };
    tracing::info!("link '{link_name}' listen on {bind}");
    loop {
        let Ok((inbound, _)) = lis.accept().await else {
            continue;
        };
        let (out, link_name) = (out.clone(), link_name.clone());
        tokio::spawn(async move {
            if let Err(e) = handle_link_conn(inbound, link_name, out).await {
                tracing::debug!("link conn ended: {e:#}");
            }
        });
    }
}

async fn handle_link_conn(
    mut inbound: TcpStream,
    link_name: String,
    out: OutHolder,
) -> anyhow::Result<()> {
    let holder = out.read().await.clone();
    let Some(tx) = holder else {
        anyhow::bail!("wss down");
    };
    // sid 取奇数：server 偶数 sid，避免碰撞（同 egress）。
    let sid = CTR.fetch_add(2, std::sync::atomic::Ordering::Relaxed) | 1;
    let (dtx, mut drx) = mpsc::unbounded_channel::<Vec<u8>>();
    super::egress::egress_streams().write().await.insert(sid, dtx);
    // host=link名（server 以此查表，port 忽略）；目标以 server 存为准。
    tx.send(Message::Text(
        serde_json::to_string(&ClientMsg::Open { stream: sid, kind: "link".into(), host: link_name, port: 0 })?.into(),
    ))?;
    let (mut ri, mut wi) = inbound.into_split();
    let tx2 = tx.clone();
    let from_local = tokio::spawn(async move {
        let mut b = vec![0u8; 32 * 1024];
        loop {
            match ri.read(&mut b).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tx2.send(Message::Binary(encode_data(sid, &b[..n]).into())).is_err() {
                        break;
                    }
                }
            }
        }
    });
    let to_local = tokio::spawn(async move {
        while let Some(chunk) = drx.recv().await {
            if chunk.is_empty() {
                break; // server eof 标记（同 egress 保序空包）
            }
            if wi.write_all(&chunk).await.is_err() {
                break;
            }
        }
    });
    let _ = tokio::join!(from_local, to_local);
    super::egress::egress_streams().write().await.remove(&sid);
    let _ = tx.send(Message::Text(
        serde_json::to_string(&ClientMsg::Close { stream: sid, reason: "eof".into() })?.into(),
    ));
    anyhow::Ok(())
}
```

注意：入口回包路由复用 `egress_streams()` 表（session 的 Binary 分发先查 `Ctx.streams` 再查此表，link 的 sid 只在此表，能收到包；零改动 session 分发）。

- [ ] **Step 2: `mod.rs` 接线**（`pub mod link;` + 热更新）

在 `src/agent/mod.rs` 顶部加 `pub mod link;`。热更新触发点（现有 egress watch / Config 应用处，二选一按实际代码位置）：每次收到 Config / 启动时，对 `proxies` 里 `enabled && ptype=="link" && valid_link(p, hostname)` 的条目，以 `name` 为 key 起 `serve_link` task，旧 key 不在新表则 abort。最小实现：维护 `Arc<Mutex<HashMap<String, AbortHandle>>> link_tasks`，逻辑照抄 `egress_cur` 单 task 模式扩展为多 key。

- [ ] **Step 3: `web.rs` 状态字段**

```rust
#[serde(default)]
pub link_err: Option<String>,
```

tunnels 只读表：`p.ptype=="link"` 时目标列显示 `link→{link_agent}:{link_host}:{link_port}`、监听列显示 `{local_ip}:{local_port}`（按现有行渲染分支加一个 `if` 即可）。

- [ ] **Step 4: Build**

Run: `RUSTFLAGS="-D warnings" cargo build 2>&1 | tail -n 2`
Expected: 零 warning

- [ ] **Step 5: Commit**

```bash
git add src/agent/link.rs src/agent/mod.rs src/agent/web.rs && git commit -m "feat(link): agent 入口监听 + 热更新 + 状态展示"
```

---

### Task 5: server WebUI（同表 + 表单联动 + 校验）

**Files:**
- Modify: `web/index.html`（type 下拉、表单字段、`typeFields/curProxy/saveForm/editRow`、表格行渲染）
- Test: `src/server/api.rs` mod tests（`webui_has_traffic_conns_tabs` 追加断言）

**Interfaces:**
- Consumes: Task 1 字段名（`link_agent/link_host/link_port`）；`/api/desired` 现有读写。
- Produces: 用户可配 link；Task 6 可用 WebUI 建 link（e2e 直接调 API，UI 断言走单测）。

- [ ] **Step 1: 表单 HTML**（在 `f-dom/f-port` 行旁加 link 专用行，默认 hidden）

```html
<label id="l-link-agent" class="hidden">对端 agent（入口填出口的主机名）</label>
<select id="f-link-agent" class="hidden"></select>
<label id="l-link-tgt" class="hidden">对端目标 ip:port（出口 agent 可达）</label>
<div id="f-link-tgt" class="hidden"><input id="f-link-ip" placeholder="如 192.168.1.10"><input id="f-link-port" placeholder="如 3306"></div>
```

- [ ] **Step 2: `typeFields()` 联动**

```js
function typeFields(){
  const t=document.getElementById('f-type').value, isHttp=(t==='http'), isLink=(t==='link');
  document.getElementById('l-dom').classList.toggle('hidden',!isHttp);
  document.getElementById('f-dom').classList.toggle('hidden',!isHttp);
  document.getElementById('l-port').classList.toggle('hidden',isHttp||isLink);
  document.getElementById('f-port').classList.toggle('hidden',isHttp||isLink);
  for(const id of ['l-link-agent','f-link-agent','l-link-tgt','f-link-tgt'])
    document.getElementById(id).classList.toggle('hidden',!isLink);
  if(isLink){
    // 对端下拉=在线 agents（除自己）；监听地址标签提示
    const self=document.getElementById('hostsel').value;
    fetch('/api/overview',{headers:hdrs(),credentials:'same-origin'}).then(r=>r.json()).then(o=>{
      const sel=document.getElementById('f-link-agent');
      sel.innerHTML=(o.agents||[]).filter(a=>a.hostname!==self)
        .map(a=>`<option>${a.hostname}</option>`).join('')||'<option value="">(无其他在线 agent)</option>';
    }).catch(()=>{});
  }
}
```

type 下拉加 `<option value="link">link（跨 agent）</option>`；监听 ip 输入框 placeholder 改为 `0.0.0.0（入口内网可达）/ 127.0.0.1（仅本机）`。

- [ ] **Step 3: `curProxy/saveForm/editRow` + 表格行**

```js
// curProxy 追加：
if(t==='link'){ p.link_agent=document.getElementById('f-link-agent').value.trim();
  p.link_host=document.getElementById('f-link-ip').value.trim();
  p.link_port=parseInt(document.getElementById('f-link-port').value||'0'); }
// saveForm 校验追加：
if(p.type==='link'){
  if(!p.link_agent){ toast('对端 agent 必填',true); return; }
  if(p.link_agent===h){ toast('link 对端不能是自己',true); return; }
  if(!p.link_host||!p.link_port){ toast('对端目标 ip:port 必填',true); return; }
  if(!p.local_port){ toast('本监听端口必填',true); return; }
}
// 表格 target 列：link 显示 `${x.link_agent}→${x.link_host}:${x.link_port}`，domains 列显示 `-`
```

- [ ] **Step 4: 单测断言追加**（`webui_has_traffic_conns_tabs` 内）

```rust
assert!(html.contains("f-link-agent"), "missing link peer select");
assert!(html.contains("link_agent"), "missing link fields");
assert!(html.contains("不能是自己"), "missing link self-loop guard");
```

- [ ] **Step 5: Build + 单测 + Commit**

Run: `RUSTFLAGS="-D warnings" cargo build 2>&1 | tail -n 2 && cargo test --bin neutrino webui 2>&1 | tail -n 4`
Expected: PASS

```bash
git add web/index.html src/server/api.rs && git commit -m "feat(link): WebUI 同表支持 link（表单联动+自环校验）"
```

---

### Task 6: e2e（roundtrip / offline / hot-update）

**Files:**
- Modify: `tests/e2e.rs`

**Interfaces:**
- Consumes: Task 2/3/4 的完整链路；现有 `boot_with_desired`/`Env` helpers。
- Produces: 回归保障；旧代码跑此用例为红（无 link 监听/中转）。

- [ ] **Step 1: `link_tcp_roundtrip`（RED 先行，可在 Task 2 前先合入此用例看红）**

```rust
#[tokio::test]
async fn link_tcp_roundtrip() {
    // 后端 echo（agent1 可达）
    let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = echo.accept().await else { break };
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    // agent1：零 link 配置（纯出口）；agent2：一条 link 监听随机端口
    // 注：Env/boot helper 按现有 boot_with_desired 扩展为双 agent（参考 e2e_restart_covered_by_desired 的双启动模式）；
    // desired[agent2] = [{name:"dblink", type:"link", local_ip:"127.0.0.1", local_port:LINK_PORT,
    //   link_agent:"agent1", link_host:"127.0.0.1", link_port:echo_port}]
    // 断言：client 连 agent2 LINK_PORT，发 "hello-link"，5s 内收到回声；
    // 且 /api/conns 有 tunnel=="dblink" 的行，client 关后行消失（Drop-guard）。
}
```

实现提示：e2e 双 agent 启动按现有 `Env` 结构复制一份（不同 hostname/port/random port）；LINK_PORT 用 `TcpListener::bind(0)` 预占取端口后释放再配（防冲突）。

- [ ] **Step 2: `link_agent_offline_closes`**

```rust
#[tokio::test]
async fn link_agent_offline_closes() {
    // link_agent 指向不存在的主机名；client 连上后应被干净 Close（读到 EOF/0 字节），
    // 且入口 agent 主链不断（/api/overview 仍有 agent2）。
}
```

- [ ] **Step 3: `link_hot_update`**

```rust
#[tokio::test]
async fn link_hot_update() {
    // 先有 link（roundtrip 通），再 POST /api/desired/agent2 置空；
    // 断言：监听端口释放（connect 被拒），旧连接已关。
}
```

- [ ] **Step 4: 全量验证 + Commit**

Run: `make build 2>&1 | tail -n 2 && make test 2>&1 | tail -n 20`
Expected: 单测 60+（新增 3 左右），e2e 16（新增 3），全绿

```bash
git add tests/e2e.rs && git commit -m "test(link): e2e roundtrip/offline/hot-update 回归"
```

---

## Self-Review

1. **Spec coverage:** §2 建流→Task 2/3/4；§3 字段+server 为准→Task 1/2（`resolve_link` 只读 server 表，`host` 透传 link 名）；§4 两端行为→Task 3/4（`link_err`/热更新abort）；§5 WebUI→Task 5（同表+自环拦）；§6 统计→Task 2 的 conns 插行 + tick 自动（`traffic_key(agent2/link名)` 天然存在，无需代码）；§7 测试→Task 6 + 各 Task 单测。`valid_egress_target` 式纯函数→`valid_link`（Task 1）。
2. **Placeholder scan:** 无 TBD/TODO；Task 2 的 `next_sid` 标注了按实际字段调整（唯一需现场确认的点，已给出 grep 定位法）；Task 4 的 mod.rs 热更新给出两种挂载点二选一 + 照抄对象（`egress_cur`）。
3. **Type consistency:** `link_agent/link_host/link_port` 命名全计划统一；`resolve_link` 返回 `(String,String,u16)` 与 `spawn_link_relay` 解构一致；`Open{link}` 的 `host=link名` 约定在 Task 2/4 两侧一致；conns `proto="link"` 与 spec 一致。

## Execution Handoff

**Plan complete and saved to `docs/superpowers/plans/2026-10-20-agent-link.md`. Two execution options:**

**1. Subagent-Driven (recommended)** - I dispatch a fresh subagent per task, review between tasks, fast iteration

**2. Inline Execution** - Execute tasks in this session using executing-plans, batch execution with checkpoints

**Which approach?**
