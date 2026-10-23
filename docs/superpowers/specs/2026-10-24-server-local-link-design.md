# server-local link 设计（2026-10-24，A 方案）

## 背景

workmac 本机 link 映射已 9 条（tm/git/llm/ssh×3/代理×3），全经对端 agent 出口 dial。
现需把 HK server 本机 `127.0.0.1:22` 映射到本机 10123（`s-hk`），
但 HK 上无 agent（只有 server），link 语义"入口 agent → 出口 agent dial"走不通。

## 决策

- 方案 A（本 spec）：`link_agent = "server-local"` 保留字，server 自己 dial。
  备选 B（新增 `local` type）改动面大一倍（proto/api/desired/WebUI 全动），YAGNI 不取；
  备选 C（HK 起 agent 回连自己）多进程+多一跳回环，不取。
- 字面量用 `server-local` 而不用空值：明确意图，不与"忘填"混淆；空值仍按非法拦掉。
- `link_udp` 暂不支持 server-local（UDP 无连接 session 另套逻辑，ssh 用不上）。

## 语义

```toml
[[agents.workmac]]
name = "s-hk"
type = "link"
local_ip = "127.0.0.1"
local_port = 10123
link_agent = "server-local"   # 保留字：server 自己 dial，不走任何 agent
link_host = "127.0.0.1"
link_port = 22
```

- 目标地址 server 本机可达即可（127/内网段）；dial 失败即 Close（fail-closed，
  同 link 出口 dial 失败语义）。
- 保留字冲突：agent hostname 禁止叫 `server-local`（分支优先，真撞了改名）。
- conns 记账：`target = "server-local->127.0.0.1:22"`，proto 仍为 `link`，
  `/api/conns`、traffic 口径零改动。

## 实现（3 处）

1. `src/server/tunnel.rs::spawn_link_relay`：第 1 步查表后、第 2 步找出口 agent 前插分支。
   `exit_host == "server-local"` 即 `TcpStream::connect(tgt_host, tgt_port)`（30s 超时，
   同 `egress_dial`），成功后入口 incoming/outbox ↔ 本地 socket 双泵
  （照抄 `spawn_egress_dial` 的泵+Drain+Drop-guard）；失败回
   `Close{link denied: server-local dial failed}`。
   kudus/QUIC 双通道共用此函数，一次改全通。
2. `src/common/proto.rs::valid_link`：`link_agent == "server-local"` 白名单放行
   （入口 agent 的 link 监听要能起；自环检查保留）。
3. 单测 2 个：`resolve_link` 透出保留字 + server-local dial 成功/失败路径
   （失败路径可用 `127.0.0.1:1` 关端口 dial 必拒）。

## 不做

- `api.rs` link 校验不动（只查 local_port/remote_port，不查 link_agent）。
- WebUI 类型下拉不动（仍是 `link`）。
- `link_udp` + server-local 不做；egress 口径不动。
