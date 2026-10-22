# egress 出口路由（按发起 agent 指定出口）设计 spec

- 日期：2026-10-22
- 状态：brainstorming 通过，待 review
- 范围：server 侧 egress 出口路由（方案 A：按发起 agent 定出口；A1 路由表放 desired.toml；B1 独立监听端口即选择）。通用能力，不绑定任何具体应用。
- 非范围：按目标分流（B，不要）；TUN（另立项）；SOCKS5 egress（另起 spec）。

## 背景

- 现状：agent 发 `Open{egress}` → server 本机 `TcpStream::connect(目标)`（`spawn_egress_dial`），出口 IP 恒为 server 本机。其他 agent 无法充当出口。
- 目标：server 按发起 agent 查路由表，把拨号任务派给指定出口 agent；调用方（transmission `proxy_url` 等）零变化，只换端口。

## §1 配置语义

server `desired.toml` 新增顶层表（agent 粒度）：

```toml
[egress_exit]
minipc7s = "kr"   # 该 agent 发起的 egress，一律由 kr 拨号
# 未列出的 agent → server 本机拨号（现状，不变）
```

- key=发起方 hostname，value=出口方 hostname；value 为空/出口 agent 离线 → 回退 server 本机拨号（fail-open，不断链）+ warn 日志。
- 出口方不可自指、无需校验目标可达（拨号失败走正常 Close 透传）。

## §2 信令与泵

- server `spawn_egress_dial` 前查表：命中 → 发反向 dial 指令给出口 agent（新 `kind="egress_dial"`，host/port=真实目标，sid=server 分配偶数），自己只做中转泵（照抄 `spawn_link_relay` 双泵结构 + `conns` 行，`proto="egress"`，`target="出口->host:port"`）。
- 出口 agent 收 `egress_dial` → `TcpStream::connect(host:port)`（30s 超时，照抄现有拨号段）→ 建泵：tunnel 下行 → socket；socket 回包 → tunnel 上行。失败回 `Close{link denied}`（复用原因串），server 清行。
- 三传输对称：WSS（`session.rs`）/ QUIC（`quic_session.rs`）/ kudus（`kudus_session.rs`）各加 `egress_dial` 分支（拨号+泵，与 `open_tcp_stream` 出口段同构）。
- 全链路 Close/超时透传；限速/记账走现有 egress 口径（总量，不新增 key）。

## §3 监听形态（B1）

- 端口即选择：snail `:18080` 走 HK（现状），KR `:18081` 另起 egress 监听专供“经 KR 出”流量。transmission 切代理只需改 `proxy_url` 端口。
- agent `agent.toml` 的 `[egress.http]` 保持单监听语义；多出口 = 多 agent 各起监听，不扩展单 agent 多监听（YAGNI）。

## §4 测试（TDD）

1. 路由查表单测：命中/未命中回退/出口自指/空表 4 组。
2. e2e `egress_exit_roundtrip`：发起 agent → server → 出口 agent dial 回显 TCP server → 回包原路；断言 payload + 回退路径（出口离线时 server 本机拨号仍通）。
3. 现有 egress e2e 全过（回退路径即现状）。
