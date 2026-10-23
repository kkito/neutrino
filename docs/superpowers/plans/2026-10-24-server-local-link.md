# server-local link 直拨 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `link_agent = "server-local"` 时 server 自己 dial 目标，workmac 本机 10123 直达 HK `127.0.0.1:22`。

**Architecture:** `spawn_link_relay` 查表后插分支：保留字命中即 server 本机 `TcpStream::connect` + 双泵（照抄 `spawn_egress_dial_local` 的占位/drain/记账/泵模式）；`valid_link` 加白名单让入口 agent 起监听。

**Tech Stack:** Rust (tokio: TcpStream, mpsc, RwLock), neutrino 现有 server tunnel 模块。

## Global Constraints

- kudus/QUIC 双通道共用 `spawn_link_relay`，一次改全通，不另分支。
- dial 失败即 Close（fail-closed），同 link 出口 dial 失败语义。
- conns 记账 proto 仍为 `link`，`/api/conns`、traffic 口径零改动。
- `link_udp` + server-local 不做；`api.rs` 校验不动；WebUI 不动。

---

## File Structure

- Modify: `src/common/proto.rs` — `valid_link` 白名单放行 `server-local`（约 3 行）。
- Modify: `src/server/tunnel.rs` — `spawn_link_relay` 加 server-local 分支（约 80 行，照抄 `spawn_egress_dial_local` 的 dial+drain+双泵+记账）。
- Test: 现有 `#[cfg(test)] mod tests` 内联单测（两处各加 1-2 个 test fn，跟随现有 `resolve_link_uses_server_table` 风格）。

---

### Task 1: valid_link 白名单 + 单测

**Files:**
- Modify: `src/common/proto.rs:124-135` (`valid_link`)
- Test: `src/common/proto.rs` 同文件 `#[cfg(test)]`（若无则新建 mod tests）

**Interfaces:**
- Consumes: 无（纯函数）。
- Produces: `valid_link(p, self_hostname)` 对 `link_agent == "server-local"` 返回 true（其他条件不变）。

- [ ] **Step 1: 查看现有 valid_link 与单测风格**

Run: `sed -n '120,140p' src/common/proto.rs && grep -n "mod tests" src/common/proto.rs`
Expected: 看到 `valid_link` 函数体 + tests 模块位置。

- [ ] **Step 2: 写 failing test**

在 `src/common/proto.rs` 的 tests 模块追加：

```rust
#[test]
fn valid_link_allows_server_local() {
    let p = ProxyConfig {
        name: "s-hk".into(),
        ptype: "link".into(),
        local_ip: "127.0.0.1".into(),
        local_port: 10123,
        link_agent: "server-local".into(),
        link_host: "127.0.0.1".into(),
        link_port: 22,
        ..Default::default()
    };
    assert!(valid_link(&p, "workmac"));
}
```

注意：先确认 `ProxyConfig` 字段全（`rate_limit/domains/remote_port/set_x_forwarded_proto/enabled` 等），`..Default::default()` 要求 `ProxyConfig: Default`；若无 Default 实现则显式写全字段。`enabled` 必须 true（valid_link 首行即查）。

- [ ] **Step 3: 运行确认失败**

Run: `cargo test -p neutrino valid_link_allows_server_local 2>&1 | tail -5`
Expected: FAIL（`valid_link` 现把 `server-local` 当普通对端名放行？不——现逻辑 `link_agent == self_hostname` 才拦，非空即过，所以此 test 现已 PASS。改为断言非法空值仍拦 + 保留字显式分支，见 Step 4）。

修正说明：现 `valid_link` 对任意非空非自环 link_agent 都返回 true，`server-local` 其实已放行。本 task 真正要做的是**显式化**：加具名常量 + 单测锁定语义，防止未来收紧校验时误杀。

- [ ] **Step 4: 最小实现——具名常量 + 显式分支**

```rust
/// link_agent 保留字：server 自己 dial，不走任何 agent（见 spec 2026-10-24）。
pub const LINK_EXIT_SERVER_LOCAL: &str = "server-local";
```

`valid_link` 内自环检查改为：

```rust
if p.link_agent.trim().is_empty() {
    return false;
}
if p.link_agent == self_hostname && p.link_agent != LINK_EXIT_SERVER_LOCAL {
    return false;
}
```

（语义：保留字永不判自环；真有 agent 叫 server-local，server 侧分支优先，见 Task 2。）

- [ ] **Step 5: 运行通过**

Run: `cargo test -p neutrino valid_link 2>&1 | tail -5`
Expected: PASS（含既有 valid_link 单测）。

- [ ] **Step 6: Commit**

```bash
git add src/common/proto.rs
git commit -m "feat(link): server-local 保留字常量 + valid_link 显式放行"
```

---

### Task 2: spawn_link_relay server-local 分支

**Files:**
- Modify: `src/server/tunnel.rs` (`spawn_link_relay`，查表后/找出口前插分支，约 line 340 附近 `// 2. 找出口 agent` 之前)
- Test: `src/server/tunnel.rs` `mod tests` 追加单测

**Interfaces:**
- Consumes: Task 1 的 `LINK_EXIT_SERVER_LOCAL`；复用 `super::ingress::next_sid_pub`（仅 conns 记账用）、`log_ev`、`insert_conn`/`ConnInfo`（link 现有记账）、`ServerMsg::Close`。
- Produces: server-local link 建流走 server 本机 dial；失败回 `Close{reason: "link denied: server-local dial failed"}`。

分支伪代码（照抄 `spawn_egress_dial_local` 的 dial+drain+双泵模式，连接行复用 link 格式）：

```rust
// 1.5 server-local：server 自己 dial，不找出口 agent
if exit_host == crate::common::proto::LINK_EXIT_SERVER_LOCAL {
    // 入口占位（dtx_entry 已在第 3 步注册，此处直接用）
    let up = match tokio::time::timeout(
        std::time::Duration::from_secs(30),
        tokio::net::TcpStream::connect((tgt_host.as_str(), tgt_port)),
    )
    .await
    {
        Ok(Ok(u)) => u,
        Ok(Err(e)) | Err(_) => {
            let _ = ctl_entry.send(ServerMsg::Close {
                stream: sid_entry,
                reason: "link denied: server-local dial failed".into(),
            });
            log_ev(&s, format!("link '{link_name}' server-local dial {tgt_host}:{tgt_port} failed: {e:?}"));
            // 清入口占位（照抄函数尾的 remove 逻辑，只清 entry 侧）
            if let Some(h) = s.agents.read().await.get(&entry_aid) {
                h.incoming.write().await.remove(&sid_entry);
            }
            return;
        }
    };
    // conns 记账（link 口径，target 前缀 server-local）
    let cid = (sid_entry as u64) | ((super::ingress::next_sid_pub() as u64) << 32);
    s.conns.write().await.insert(cid, super::state::ConnInfo {
        id: cid,
        proto: "link".into(),
        peer: entry_host.clone(),
        public_port: 0,
        agent: entry_host.clone(),
        tunnel: link_name.clone(),
        remote_port: 0,
        target: format!("server-local->{tgt_host}:{tgt_port}"),
        since: chrono::Utc::now().timestamp(),
        rx: 0, tx: 0,
    });
    // 双泵：drx_entry（入口 client 发来）-> up 写；up 读 -> entry_out 发回
    // 照抄 spawn_egress_dial_local 的 to_public/from_agent（含 rx/tx 累计 key 为 cid，
    // key 类型注意：egress 用 sid as u64，link 用 cid——此处跟 link 走，用 cid）
    // 结束：双关 + 清 conns 行 + 清入口 incoming + Close{ eof }（只清 entry 侧，无 exit 侧）
    return;
}
```

注意点（实现时必读）：
- `tgt_host/tgt_port/exit_host/link_name/entry_aid/entry_host/sid_entry/ctl_entry/dtx_entry/drx_entry` 在分支点是否还活着：查表块返回的 `(exit_host, tgt_host, tgt_port)` 是 clone 出来的；`dtx_entry/drx_entry` 在第 3 步已建——分支插在"第 2 步找出口"之前即第 3 步占位之前，**占位尚未发生**。两种摆法：(a) 分支放第 3 步占位之后（复用占位+drain_early），(b) 分支内自己占位。选 (a)：把分支插在 drain_early 之后、conns 记账之前，入口占位/drain 全复用，只需 dial + 自己的 conns 行 + 双泵（泵的对端是本地 socket 不是 exit_out）。
- link 现有双泵是 channel↔channel（a2e/e2a 经 `exit_out`/`entry_out` 发 `(sid, chunk)`）；server-local 是 channel↔socket：一端 `drx_entry.recv() → wu.write_all`，另一端 `ru.read → entry_out.send((sid_entry, chunk))`。照抄 `spawn_egress_dial_local` 的 `to_public`/`from_agent` 两段即可（它正是 socket↔channel，变量名 `aid/sid/out/drx` 对号入座：`aid=entry_aid, sid=sid_entry, out=entry_out`）。
- 限速：link 现有 `link_limiter` 按 `traffic_key(host, link_name)` 双向共用；server-local 分支同样包一层（`p.rate_limit` 取自查表时的 proxy——查表只返回了三元组，需把 `rate_limit` 也带出来，或复用现有 `link_limiter` 构造块。最省事：分支插在 `link_limiter` 构造**之后**，直接 `ll1/ll2.clone()` 用）。
- 最终插点：`// 6. 双向泵` 之前、`link_limiter` 块之后。分支内 dial 成功则走自己的 socket 泵 + `return`，跳过原 channel 双泵。

- [ ] **Step 1: 读透插点上下文**

Run: `sed -n '340,440p' src/server/tunnel.rs`
Expected: 确认查表块、第 2 步、第 3 步占位、3.5 drain、link_limiter 块、`// 6. 双向泵` 的行号。

- [ ] **Step 2: 写 failing 单测（纯函数层）**

`resolve_link` 已透出 `(link_agent, host, port)` 三元组，分支条件是 `exit_host == LINK_EXIT_SERVER_LOCAL` ——纯字符串比较，无需单测。改为给 `spawn_egress_dial_local` 风格补集成锚点：单测 dial 失败路径-semantics：`TcpStream::connect("127.0.0.1:1")` 必拒。

在 `src/server/tunnel.rs` tests 追加：

```rust
#[tokio::test]
async fn server_local_dial_refused_is_closed() {
    // 关端口必拒：server-local fail-closed 语义锚点
    let r = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::net::TcpStream::connect("127.0.0.1:1"),
    )
    .await;
    assert!(matches!(r, Ok(Err(_))), "closed port must refuse, got {r:?}");
}
```

- [ ] **Step 3: 运行确认通过（锚点 test 本来就过）**

Run: `cargo test -p neutrino server_local_dial_refused 2>&1 | tail -3`
Expected: PASS（锚点先立，实现后靠 e2e 验证）。

- [ ] **Step 4: 实现分支**（按上面伪代码 + 插点说明，完整写出）

- [ ] **Step 5: 编译 + 全量测试**

Run: `cargo build 2>&1 | tail -2 && cargo test 2>&1 | tail -3`
Expected: 零 warning，全部 PASS。

- [ ] **Step 6: Commit**

```bash
git add src/server/tunnel.rs
git commit -m "feat(link): server-local 分支，server 本机直拨"
```

---

### Task 3: e2e 验证（本机 10123 → HK 22）+ 部署

**Files:**
- Modify: `hknas/neutrino/data/desired.toml`（machines 仓库：`link_agent = "hk"` → `"server-local"`）——注意 machines 与 neutrino 是两个仓库，别混。

**Interfaces:**
- Consumes: Task 2 的二进制。
- Produces: `ssh -p 10123 kkito@127.0.0.1`（本机）直达 HK shell。

- [ ] **Step 1: 编 neutrino 发版二进制（musl 静态，HK 用）**

Run: `cargo build --release --target x86_64-unknown-linux-musl 2>&1 | tail -2`
Expected: 产物 `target/x86_64-unknown-linux-musl/release/neutrino`。

- [ ] **Step 2: 发 HK + 重启 server**

```bash
scp target/x86_64-unknown-linux-musl/release/neutrino root@hk.kkito.cn:/tmp/
ssh root@hk.kkito.cn 'tar xzf /tmp/neutrino-*.tar.gz -C /root/nastools/neutrino/ 2>/dev/null || cp /tmp/neutrino /root/nastools/neutrino/neutrino; systemctl restart neutrino-server; sleep 3; systemctl is-active neutrino-server'
```

Expected: `active`。（以 hknas restart-neutrino.sh 流程为准，先读它再动手。）

- [ ] **Step 3: machines 仓库改 desired + reload**

`s-hk` 条 `link_agent = "server-local"`（已加的是 `"hk"`，改字面量），scp 到 HK 后 `/api/desired/reload`（流程同上次 trans-bt-udp：login 取 JWT → POST reload，期望 `reloaded:16`）。

- [ ] **Step 4: 本机验证**

Run: `ssh -p 10123 root@127.0.0.1 'hostname; uptime'`
Expected: 回 `cloudserver` + uptime（首次连 host key 告警正常，确认指纹后 yes）。

- [ ] **Step 5: 两仓库 commit**

neutrino 仓库：Task 1+2 已各 commit；machines 仓库：desired 改动 commit。

---

## Self-Review

- Spec coverage: 语义节（保留字/空值非法/link_udp不做/conns口径）→ Task 1（常量+valid_link）+ Task 2（分支+记账）；实现节（3处）→ Task 1/2 全覆盖；不做节 → 无 task，正确。
- Placeholder scan: 无 TBD/TODO；伪代码中 `{e:?}` 等均为合法 Rust；`ConnInfo` 字段照抄现有 link 记账块（实现时以 `sed -n` 实测为准，plan 已注明必读行号）。
- Type consistency: `LINK_EXIT_SERVER_LOCAL: &str` 两处引用一致；`cid` 组装照抄 link 现有 `(sid_entry as u64) | ((sid_exit as u64) << 32)`，分支内用 `next_sid_pub()` 替代 `sid_exit`（无 exit 侧），类型 u64 一致。
