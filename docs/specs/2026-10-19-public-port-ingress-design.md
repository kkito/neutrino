# neutrino 公网端口 ingress（通用端口映射）设计

日期： 2026-10-19 ｜ 状态： 已实现（零开发，纯配置） ｜ 需求来源： 内网端口经 server 出口对外提供服务

## 1. 背景与目标

- 目标：把 agent 内网里的一个 TCP/UDP 端口，映射到 server 网络里对外提供服务。外部客户端访问 `server 公网地址:remote_port`，流量经隧道落地到内网 `local_ip:local_port`。
- 结论先行：**代码侧现成，零开发**。本需求是通用做法说明（配法 + 前置条件 + 验证），不是开发需求。
- 与 egress（出网代理）正交：一个管进（server listen → agent 拨内网），一个管出（agent listen → server 拨公网），复用同一套 stream 泵。

## 2. 做法（纯配置）

### 2.1 server desired（`tunnel/data/desired.toml`，唯一来源）

```toml
[[agents.<hostname>]]
name = "svc-tcp"
type = "tcp"
local_ip = "172.28.0.10"
local_port = 51413
remote_port = 51413
enabled = true

[[agents.<hostname>]]
name = "svc-udp"
type = "udp"
local_ip = "172.28.0.10"
local_port = 51413
remote_port = 51413
enabled = true
```

- 字段含义：`type` 取 `tcp`/`udp`；`remote_port` 是 server 侧监听的公网端口；`local_ip:local_port` 是 agent 侧要拨的内网目标；`enabled` 控制开关。
- `local_port` 与 `remote_port` 可以不同（如内网 8080 对外 9000），按需填写。
- TCP/UDP 各配一段；只需要 TCP 时只配 `type="tcp"` 那段即可。

### 2.2 生效机制（代码现状）

- server 启动/热加载后，对每个 `enabled` 且 `remote_port > 0` 的条目自动 `bind 0.0.0.0:remote_port`（见 `src/server.rs::ensure_tcp_listener` / `ensure_udp_listener`）。
- 外部连接进来 → 按 `remote_port` 选 agent → agent 拨内网 `local_ip:local_port`，双向透传。
- TCP 是纯字节透传，无应用层语义干扰；UDP 按 peer session 转发。
- 回滚：desired 里对应条目 `enabled = false`，秒级摘除。

## 3. 前置条件（基础设施层面，与代码无关）

- server 必须能在公网 `listen` 到 `remote_port`：若 server 跑在 NAT/面板之后，需要在上游加 `remote_port → server 内网` 的端口映射，否则公网流量到不了 server，配了也不通。
- 不满足时：先补映射，再按 §2 配置；不要改代码，改了也没用。

## 4. 灰度建议

- 先加 TCP 验证连通性，再加 UDP（或反之），分步确认。
- 关注 server 出口带宽：大流量服务经 server 中转，中转带宽可能成为瓶颈，先灰度观察再全切。

## 5. 测试

- TCP：外部 `nc -v <server公网地址> <remote_port>` 能连上，业务握手正常。
- UDP：`nc -u` 探活 + 实际业务有来回包即算过。
- 回归（已有，无需新写）：`tests/e2e.rs::e2e_tcp_passthrough`（TCP 回声）、`e2e_udp_and_hot_config`（UDP 回声 + 热配摘路由）。

## 6. 自检

- 无代码变更，无 TBD；前置条件明确（上游端口映射），不满足则配了也不通。
- 后续增强（另开需求，不在本篇）：按 agent 授权、按端口白名单。
