# 跨机 UDP 中继（link_udp）设计 spec

- 日期：2026-10-22
- 状态：brainstorming 通过，待 review
- 范围：通用 UDP 跨 agent 中转（server 中心化中继，方案 A）。不绑定任何具体应用；BT/transmission 只是首个用例。
- 非范围：TUN/L3 劫持（另立项）；egress 指定出口（用“远端 egress + TCP link 承载”现成组合代替，不写代码）；SOCKS5 egress（另起 spec）。

## 背景

- `link`（TCP）已支持跨 agent 中转：入口 agent 监听 → server `resolve_link` 查表 → `spawn_link_relay` 双泵 → 出口 agent dial 真实目标。三传输（WSS/QUIC/kudus）全通。
- `type="udp"` 只能终结在所属 agent 本机（server `ensure_udp_listener` + agent `open_udp_stream`），无跨机语义。
- 缺口：入口与出口不在同一 agent 的 UDP 流量（如公网 UDP 端口要打到内网主机）无解。本 spec 补齐。

## §1 配置语义

```toml
[[agents.kr]]
name = "bt-udp"
type = "link_udp"
local_ip = "0.0.0.0"
local_port = 51413
link_agent = "minipc7s"
link_host = "172.28.0.10"
link_port = 51413
remote_port = 0
rate_limit = "1m"
enabled = true
```

- 校验（`valid_link` 同源扩展）：`ptype=="link_udp"` + `enabled` + `link_agent` 非空且 ≠ 自己 + `link_host` 非空 + `link_port != 0` + `local_port != 0`；`remote_port` 必须为 0（非 0 拒绝，防止误占 server 公网端口，与 TCP link 一致）。
- `local_port`（入口）与 `link_port`（出口目标）独立解耦，允许不同；`domains` 忽略（UDP 无域名路由）。
- API 校验：`validate_proxy` 放行 `link_udp`（要求 `local_port != 0`，与 link 同）。

## §2 中继链路（server 侧）

- 入口 agent 收 UDP 包 → `ClientMsg::Open{kind:"link_udp", host:link名}`（首包）+ `Data` 经隧道发 server。
- server `resolve_link` 复用（以 desired 为准，入口传参不信）：`link名 → (link_agent, link_host, link_port)`。
- session 表：key=`(入口agent, 入口peer地址, link名)`，value=出口 sid + 最后活跃。照抄 `ensure_udp_listener` 的 session/60s 超时清表；来源从“本机 socket”换成“入口 agent 上行 Data”，去向从“本机 dial”换成“Open 出口 agent”。
- 回包按 session 表原路返回入口 agent，由入口 `sendto` 原 peer。server 不建本地 socket，纯内存转发。
- 任一端 `Close` / session 超时 → 清行 + `conns` 移除（Drop-guard 语义，复用 TCP link）。

## §3 agent 侧收发

- 入口：`UdpSocket::bind(local_ip:local_port)` 常驻监听，task 挂 `link_tasks` 与 session 同命（LinkGuard 语义，重连重建）。按 peer 地址分配奇数 sid（kudus 用独立 `CTR_KUDUS` 基址，防碰撞），首包发 `Open`，后续发 `Data`；回包按 sid 查表 `sendto`。
- 出口：收 `Open{kind:"link_udp"}`（server 已换成真实 `link_host:link_port`，照搬 TCP link 做法）→ `UdpSocket::connect(目标)` 伪连接 → 双向泵。`connect` 天然按对端过滤，多 peer 隔离。
- 三传输对称：`session.rs` / `quic_session.rs` / `kudus_session.rs` 各加 `kind=="link_udp"` 分支（`udp` 分支 + link 查表）；UDP 包走现有 `split_udp_dgram` 分片/重组，零改动；<1200B 包整包直发。
- bind 失败只记 `status.link_err` 不断主链；出口 dial 失败回 `Close{link denied}`；UDP 不可达（ICMP）不等，靠超时自然清。

## §4 限速 / 记账 / 超时

- 限速：复用 `link_limiter` 双泵总量语义，key=`traffic_key(hostname, link名)`，按 payload 计字节。
- 记账：`conns` 行 `proto="link_udp"`，`peer=入口agent`，`target="出口agent->host:port"`，5s tick 归集，WebUI 零改动。
- 超时：session 60s 无包清表；agent 伪连接同寿命。

## §5 测试（TDD）

1. `valid_link_udp` 纯函数单测（6 组合法/非法）。
2. `resolve_link` 复用单测（`link_udp` 同表可查）。
3. e2e `udp_link_roundtrip`：回显 UDP server → 入口发包 → server 中继 → 出口 dial → 回包原路；断言 payload + `conns` 建行 + 超时清行。
4. 超大包分片已有单测覆盖，不新增。

## 后续

- P0（配置，不写代码）：KR `bt-tcp` 加 `rate_limit="1m"`；tracker 走“KR egress 监听 + snail TCP link 承载”现成组合。
- SOCKS5 egress、egress 出口路由各另起 spec。
