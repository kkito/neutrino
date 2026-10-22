# link_udp + egress_exit Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 实现跨机 UDP 中继（link_udp）与 egress 出口路由（按发起方定出口），三传输对称。

**Architecture:** server 中心化中继复用 resolve_link/spawn_link_relay 双泵结构；UDP 用 per-peer session（照抄 ensure_udp_listener 60s 超时）；egress_exit 在 spawn_egress_dial 前查表，命中则发反向 egress_dial 给出口 agent 拨号。

**Tech Stack:** Rust (tokio: TcpListener/UdpSocket/mpsc), kudus/QUIC/WSS 三传输 Open/Data/Close, 现有 split_udp_dgram 分片, link_limiter 限速, conns 记账。

## Global Constraints

- 三传输对称：WSS session.rs / QUIC quic_session.rs / kudus kudus_session.rs 同语义分支。
- YAGNI：不做按目标分流，不做单 agent 多 egress 监听，不做 SOCKS5。
- TDD：先红后绿，每任务独立可测，频繁提交。
- remote_port 对 link/link_udp 恒 0，非 0 拒绝。

---

### Task 1: valid_link 扩展 link_udp

**Files:**
- Modify: `src/common/proto.rs:125-136`
- Test: `src/common/proto.rs` 内 `#[cfg(test)]`（已有 valid_link 单测旁）

**Interfaces:**
- Consumes: `ProxyConfig { ptype, enabled, local_port, link_agent, link_host, link_port }`
- Produces: `pub fn valid_link(p: &ProxyConfig, self_hostname: &str) -> bool`（link 与 link_udp 同函数放行）

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn valid_link_udp_ok_and_bad() {
    let mut p = ProxyConfig {
        name: "u".into(), ptype: "link_udp".into(),
        local_ip: "0.0.0.0".into(), local_port: 51413,
        domains: vec![], remote_port: 0, enabled: true,
        link_agent: "exit".into(), link_host: "10.0.0.1".into(),
        link_port: 51413, rate_limit: None,
    };
    assert!(super::valid_link(&p, "entry"));
    p.link_agent = "entry".into();
    assert!(!super::valid_link(&p, "entry")); // 自环拒绝
    p.link_agent = "exit".into(); p.link_port = 0;
    assert!(!super::valid_link(&p, "entry")); // 零目标端口拒绝
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test valid_link_udp_ok_and_bad 2>&1 | tail -5`
Expected: FAIL（`ptype != "link"` 直接 false，第一行 assert 失败）

- [ ] **Step 3: Write minimal implementation**

```rust
pub fn valid_link(p: &ProxyConfig, self_hostname: &str) -> bool {
    if !(p.ptype == "link" || p.ptype == "link_udp") || !p.enabled {
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

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test valid_link 2>&1 | tail -3`
Expected: PASS（新旧单测全过）

- [ ] **Step 5: Commit**

```bash
git add src/common/proto.rs
git commit -m "feat(link_udp): valid_link 放行 link_udp（自环/空目标/零端口拒绝）"
```

### Task 2: validate_proxy 放行 link_udp

**Files:**
- Modify: `src/server/api.rs:549-575`（validate_proxy 的 link 分支）
- Test: `src/server/api.rs` 内单测（link_p 旁加 link_udp_p）

**Interfaces:**
- Consumes: Task 1 的 ptype 字符串 `"link_udp"`
- Produces: `validate_proxy` 对 link_udp 与 link 同规则（要求 local_port != 0）

- [ ] **Step 1: Write the failing test**

```rust
let mut udp_p = ok_http.clone();
udp_p.ptype = "link_udp".into();
udp_p.domains.clear();
udp_p.local_port = 51413;
udp_p.remote_port = 0;
assert!(validate_proxy(&udp_p).is_ok());
udp_p.local_port = 0;
assert!(validate_proxy(&udp_p).is_err());
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test validate_proxy 2>&1 | tail -5`
Expected: FAIL（`unknown type 'link_udp'`）

- [ ] **Step 3: Write minimal implementation**

```rust
"link" | "link_udp" => {
    if p.local_port == 0 {
        return Err("link proxy requires local_port".into());
    }
    // remote_port 必须为 0：link 语义复用 local_port 做入口，不占 server 端口
    if p.remote_port != 0 {
        return Err("link proxy requires remote_port=0".into());
    }
    Ok(())
}
```

注意：此改动同时给旧 `link` 加了 remote_port=0 约束，旧单测 `link_p` 的 remote_port 若非 0 需同步改为 0（desired 里 link 本来恒 0，无生产影响）。

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test validate_proxy 2>&1 | tail -3`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/server/api.rs
git commit -m "feat(link_udp): validate_proxy 放行 link_udp（remote_port 恒 0）"
```

### Task 3: server 侧 UDP 中继（link_udp relay）

**Files:**
- Modify: `src/server/tunnel.rs:274-300`（resolve_link，已通用，补单测）
- Modify: `src/server/tunnel.rs:288-500`（新增 spawn_link_udp_relay，照抄 spawn_link_relay 双泵 + per-peer session）
- Modify: `src/server/kudus.rs:507-512` + WSS `src/server/tunnel.rs:201-204` + QUIC 对应分支（`kind == "link_udp"` → relay）
- Test: `src/server/tunnel.rs` 内单测 + e2e（Task 6）

**Interfaces:**
- Consumes: Task 1/2 的 link_udp 配置；`resolve_link(&[ProxyConfig], &str) -> Option<(String,String,u16)>`
- Produces: `pub(crate) fn spawn_link_udp_relay(s, entry_agent_id, entry_hostname, sid_entry, peer_addr: String, link_name, ctl_entry)`

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn resolve_link_udp_uses_server_table() {
    let p = ProxyConfig {
        name: "u".into(), ptype: "link_udp".into(),
        local_ip: "0.0.0.0".into(), local_port: 51413,
        domains: vec![], remote_port: 0, enabled: true,
        link_agent: "exit".into(), link_host: "10.0.0.1".into(),
        link_port: 51413, rate_limit: Some("1m".into()),
    };
    assert_eq!(
        super::resolve_link(&[p], "u"),
        Some(("exit".into(), "10.0.0.1".into(), 51413))
    );
    let q = ProxyConfig {
        name: "u".into(), ptype: "link_udp".into(),
        local_ip: String::new(), local_port: 0, domains: vec![],
        remote_port: 0, enabled: false, link_agent: String::new(),
        link_host: String::new(), link_port: 0, rate_limit: None,
    };
    assert_eq!(super::resolve_link(&[q], "u"), None);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test resolve_link_udp 2>&1 | tail -5`
Expected: 视 resolve_link 现状——若已通用则 PASS（此步转为回归锁），若按 ptype 过滤则 FAIL；FAIL 时修 resolve_link 去掉 ptype 硬编码为 `"link"`（改为同时接受 link/link_udp 或不判 ptype 只判 enabled+name）。

- [ ] **Step 3: Write minimal implementation**

在 `tunnel.rs` 新增（结构照抄 spawn_link_relay，差异只列关键处）：

```rust
pub(crate) fn spawn_link_udp_relay(
    s: &S,
    entry_agent_id: &str,
    entry_hostname: &str,
    sid_entry: u32,
    peer_addr: String,          // 入口 peer 地址（UDP 回包用）
    link_name: String,
    ctl_entry: mpsc::UnboundedSender<ServerMsg>,
) {
    // 1. resolve_link 查表（与 TCP 同源）；查不到 → Close{link denied: no such link}
    // 2. 按 hostname 找出口 agent + 出向通道；离线 → Close{link denied: exit agent offline}
    // 3. session key = format!("{entry_aid}/{peer_addr}/{link_name}")：
    //    若已存在则复用出口 sid（同 peer 后续包不再重建）；否则分配 sid_exit = next_sid_pub()
    //    + 双端占位 incoming + drain_early（照抄 relay 3/3.5 步）
    // 4. 发 Open{kind:"link_udp", host:真实tgt_host, port:真实tgt_port} 给出口
    // 5. conns 行：proto="link_udp", peer=entry_host, target="exit->host:port"
    //    + link_limiter（traffic_key 同 TCP）
    // 6. 双向泵（照抄 a2e/e2a，chunk 按 payload 计 rx/tx）
    // 7. 任一端结束 → abort 对端 + 清 conns/incoming + 双发 Close{eof} + log "link_udp '{name}' closed"
    // 8. session 表 60s 无包由后台 sweep 清（复用 ensure_udp_listener 的 expired 模式，
    //    sweep 间隔 30s，key 粒度 peer+link）
}
```

入口分发三处各加一行（WSS tunnel.rs / kudus.rs 两处 / quic.rs 对应处）：

```rust
ClientMsg::Open { stream, kind, host, .. } if kind == "link_udp" => {
    // host 首包格式 "link名|peer地址"（agent 入口拼；见 Task 4），server 拆出 peer_addr
    let (name, peer) = host.split_once('|').map(|(a,b)|(a.to_string(),b.to_string()))
        .unwrap_or((host.clone(), String::new()));
    spawn_link_udp_relay(&s, &agent_id, &hostname, stream, peer, name, ctl_tx.clone());
}
```

- [ ] **Step 4: Run tests**

Run: `cargo test link_udp 2>&1 | tail -3` + `cargo test resolve_link 2>&1 | tail -3`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/server/tunnel.rs src/server/kudus.rs
git commit -m "feat(link_udp): server UDP 中继（per-peer session + 双泵 + conns）"
```

### Task 4: agent 侧 link_udp 收发（三传输）

**Files:**
- Modify: `src/agent/link.rs`（新增 serve_link_udp + sync 复用 valid_link；入口 per-peer sid 表）
- Modify: `src/agent/kudus_session.rs:488-494`（kind=="link_udp" 出口 dial 泵；入口回包 deliver 已有 streams 表复用）
- Modify: `src/agent/session.rs` + `src/agent/quic_session.rs`（同语义分支）
- Test: e2e（Task 6）+ 单测 bind 失败不炸

**Interfaces:**
- Consumes: Task 3 的 server relay；`egress_streams()` sid→tx 表（复用）
- Produces: 入口 `UdpSocket::bind(local)` 常驻监听（link_tasks 表，LinkGuard 同命）；出口 `UdpSocket::connect(目标)` 伪连接泵

- [ ] **Step 1: Write the failing test**

```rust
#[tokio::test]
async fn link_udp_entry_binds_and_forwards() {
    // 本机回显 UDP server 127.0.0.1:0 → 取端口
    // 起 serve_link_udp（mock Tx 记录 Open host 格式 "名|peer"）
    // 发 datagram → 断言 mock 收到 Open{kind:"link_udp"} 且 host 含 '|'
}
```

（mock Tx：link.rs 内 Tx 为私有 enum，测试放在 link.rs 内部模块，直接调字符串拼接函数 `udp_open_host(name, peer) -> String`；先写该纯函数测试，再实现。）

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test link_udp_entry 2>&1 | tail -5`
Expected: FAIL（函数不存在）

- [ ] **Step 3: Write minimal implementation**

```rust
// link.rs
pub(crate) fn udp_open_host(link_name: &str, peer: &str) -> String {
    format!("{link_name}|{peer}")
}

pub(crate) async fn serve_link_udp(
    link_name: String, bind: String, out: OutHolder, status: Arc<RwLock<AgentStatus>>,
) {
    let sock = match UdpSocket::bind(&bind).await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            status.write().await.link_err = Some(format!("{link_name} udp bind {bind} failed: {e:#}"));
            return;
        }
    };
    let mut peer_sid: HashMap<String, u32> = HashMap::new();
    let mut buf = vec![0u8; 65535];
    loop {
        let Ok((n, peer)) = sock.recv_from(&mut buf).await else { continue; };
        // peer → sid（无则奇数分配，kudus 用 CTR_KUDUS 基址）；首包 Open{link_udp, host=udp_open_host}，每包 Data
    }
}
```

kudus 出口分支（kudus_session.rs open_stream 处，照抄 link TCP 段，TcpStream::connect 换 UdpSocket::connect + 泵）：

```rust
if kind == "link_udp" {
    let sock = match UdpSocket::connect((host.as_str(), port)).await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            tracing::warn!("kudus link_udp egress dial {host}:{port} failed: {e:#}");
            let c = ClientMsg::Close { stream: sid, reason: "link denied".into() };
            let _ = pkt.send_ctrl(&c);
            return Ok(());
        }
    };
    // 双向泵：tunnel Data → sock.send；sock.recv → send_data(sid)；各 120s idle 超时结束
    return pump_udp(ctx, pkt, sid, sock).await;
}
```

WSS/QUIC 出口同构（session.rs open_tcp_stream 旁 / quic_session.rs 同位置）。

- [ ] **Step 4: Run tests**

Run: `cargo test link_udp 2>&1 | tail -3`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/agent/link.rs src/agent/kudus_session.rs src/agent/session.rs src/agent/quic_session.rs
git commit -m "feat(link_udp): agent 三传输入口监听 + 出口 dial 泵"
```

### Task 5: e2e udp_link_roundtrip

**Files:**
- Create/Modify: e2e 测试文件（沿用现有 link e2e 位置，查 `link_tcp_roundtrip` 所在文件）
- Test: 全链路回显

**Interfaces:**
- Consumes: Task 3+4
- Produces: `udp_link_roundtrip` e2e 通过

- [ ] **Step 1: Write the failing test**

```rust
#[tokio::test]
async fn udp_link_roundtrip() {
    // 1. 本机 UDP 回显 server（recv→sendto 原样返回），端口 P1
    // 2. 起 server（desired 含 link_udp：entry agent 名 E，link_agent=X host=127.0.0.1 port=P1）
    // 3. 起入口 agent（bind 127.0.0.1:P0）+ 出口 agent（X）
    // 4. udp client 发 b"hello-udp" → P0 → 断言回包相等
    // 5. 断言 conns 有 proto=="link_udp" 行
}
```

按仓库现有 e2e 脚手架写（参考 link_tcp_roundtrip 的起 server/agent helper，不自创框架）。

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test udp_link_roundtrip 2>&1 | tail -8`
Expected: FAIL（端到端不通/超时）

- [ ] **Step 3-4: 联调至 PASS**

Run: `cargo test udp_link_roundtrip 2>&1 | tail -3` + 全量 `cargo test 2>&1 | tail -3`
Expected: PASS（若超时先查 drain_early/占位是否抄全，再查 sid 奇偶碰撞）

- [ ] **Step 5: Commit**

```bash
git add <e2e文件>
git commit -m "test(link_udp): e2e 回显往返 + conns 建行断言"
```

### Task 6: egress_exit 路由 + 反向 dial

**Files:**
- Modify: `src/common/proto.rs` 或 `src/server/state.rs`（Desired 结构加 `egress_exit: HashMap<String,String>`，默认空）
- Modify: `src/server/tunnel.rs:556 spawn_egress_dial`（查表→反向 dial 中转泵）
- Modify: 三传输 agent（`egress_dial` 出口分支，照抄 Task 4 出口 dial 段，kind 换成 egress 数据泵语义=TCP 字节流）
- Modify: `src/server/api.rs`（desired 解析/校验放行 egress_exit；admin UI 可选 scept——YAGNI 先只做文件+API 存取，不做 UI）
- Test: 路由查表单测 + e2e egress_exit_roundtrip（含回退）

**Interfaces:**
- Consumes: 现有 spawn_egress_dial / open_tcp_stream 出口 dial
- Produces: `fn egress_exit_for(desired: &HashMap<String,String>, initiator: &str) -> Option<String>`；新 kind `"egress_dial"`

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn egress_exit_routing() {
    let m: HashMap<String, String> =
        [("minipc7s".into(), "kr".into())].into_iter().collect();
    assert_eq!(super::egress_exit_for(&m, "minipc7s"), Some("kr".into()));
    assert_eq!(super::egress_exit_for(&m, "macmini"), None); // 未列出→本机拨
    let empty: HashMap<String, String> = HashMap::new();
    assert_eq!(super::egress_exit_for(&empty, "minipc7s"), None);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test egress_exit_routing 2>&1 | tail -4`
Expected: FAIL（函数不存在）

- [ ] **Step 3: Write minimal implementation**

```rust
pub(crate) fn egress_exit_for(
    table: &std::collections::HashMap<String, String>,
    initiator: &str,
) -> Option<String> {
    let e = table.get(initiator)?.trim().to_string();
    if e.is_empty() || e == initiator {
        return None; // 空/自指 → 本机拨（fail-open）
    }
    Some(e)
}
```

spawn_egress_dial 头部加：

```rust
if let Some(exit_host) = egress_exit_for(&s.desired.read().await.egress_exit, &hostname) {
    // 按 hostname 找出口 agent 出向通道；找不到 → 回退本机拨号 + warn（fail-open）
    // 找到 → 发 Open{kind:"egress_dial", host, port} + 中转双泵（照抄 relay 3-7 步，
    // conns proto="egress", target="exit->host:port"）
    // return;
}
// 原有本机 connect() 路径不变
```

agent 三传输 `egress_dial` 分支 = TCP connect + 双向泵（与 link TCP 出口段逐行同构，只是 kind 名不同；回包走同一 sid）。

- [ ] **Step 4: Run tests**

Run: `cargo test egress_exit 2>&1 | tail -3` + e2e（发起 agent→server→出口 dial 回显 TCP→回包；再测出口离线回退本机拨仍通）
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/server/tunnel.rs src/agent/kudus_session.rs src/agent/session.rs src/agent/quic_session.rs src/common/proto.rs src/server/api.rs
git commit -m "feat(egress): 按发起方路由出口（egress_dial 反向拨号 + 离线回退）"
```

### Task 7: 版本 + 文档 + 发布

**Files:**
- Modify: `Cargo.toml`（0.7.5 → 0.7.6）、两个 spec 文件状态行、README（如有代理类型表）
- Test: `cargo test 2>&1 | tail -3` + `cargo build --release`

- [ ] **Step 1: 全量测试**

Run: `cargo test 2>&1 | tail -3`
Expected: 全部 PASS（含新增 4 组 + 旧 e2e）

- [ ] **Step 2: 发版构建**

Run: `cargo build --release 2>&1 | tail -2`
Expected: 成功，`target/release/neutrino --version` 显示 0.7.6

- [ ] **Step 3: Commit**

```bash
git add Cargo.toml Cargo.lock docs README.md
git commit -m "chore(release): bump 0.7.5 -> 0.7.6 (link_udp + egress_exit)"
```

## Self-Review

- spec 覆盖：§1→Task1/2；§2→Task3；§3→Task4；§4 限速记账→Task3/4 内复用 limiter/conns（无独立任务，因零新代码）；§5→Task1/5；egress spec §1→Task6 查表，§2→Task6 信令泵，§3→配置层（KR 另起监听，不写代码，由部署时配 agent.toml），§4→Task6。
- 无占位符：每步含代码/命令/断言。
- 类型一致：`spawn_link_udp_relay(s, entry_agent_id, entry_hostname, sid_entry, peer_addr: String, link_name, ctl_entry)`；`udp_open_host(&str,&str)->String`；`egress_exit_for(&HashMap<String,String>, &str)->Option<String>`；新 kind 仅 `"link_udp"` 与 `"egress_dial"` 两个字符串。
