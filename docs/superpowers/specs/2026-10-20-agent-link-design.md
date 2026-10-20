# 跨 agent TCP 互联（link）设计

日期：2026-10-20 · 状态：brainstorming 已确认，待实现计划（writing-plans）。

## 1. 背景与目标

- 现状：每条隧道都是 `公网 → server → 某一个 agent → 内网目标`，
  `ProxyConfig.ptype` 只有 `http/tcp/udp`（公网入口语义）。
- 目标：任意两个 agent 之间 TCP 互访，server 只做 L4 中转。
  例：agent2 监听 `0.0.0.0:13306`，agent2 内网机器连它，
  流量 `client → agent2 → server → agent1 → 192.168.1.10:3306`。
- 非目标：UDP（会话机制复杂，留后续）；访问确认（默认配了就通）；
  server 不解析 L7（link 里跑 http 也是透字节，不注入 XFP）。

## 2. 架构与数据面

- 配置归属：link 条目配在**入口 agent**名下（`desired[agent2]` 里一条
  `type=link`），server 存、agent2 执行监听、agent1 被动 dial。
- 建流（全走现有 WSS，不开新端口）：
  1. agent2 `accept(监听)` → `ClientMsg::Open{kind:"link", link=name, stream=sid2}`。
  2. server 查 `agent2/link名 → (agent1, 目标)`，
     向 agent1 发 `ServerMsg::Open{kind:"link", stream=sid1, host, port}`。
  3. agent1 `dial(目标)`，server 把 `sid2 channel ↔ sid1 channel` 对接泵
     （与现有 `tcp socket ↔ agent流` 泵同一份逻辑，双 channel 版）。
- 拆链：任一侧 Close/EOF/超时，server 同时 Close 另一侧，
  复用 `ConnInfo` 记账（`tunnel=link名`，`peer=agent2侧对端`），流量进 traffic。
- 与公网隧道零耦合：link 不占 `remote_port`，不进 nginx。

## 3. 协议与配置字段

- `ProxyConfig`：`ptype` 加 `"link"`；新增（全 `#[serde(default)]`，老配置零迁移）：
  `link_agent: String`（对端主机名）、`link_host: String`、`link_port: u16`。
- `local_ip/local_port` 在 link 下含义切换为**入口监听地址**
  （`0.0.0.0`=入口 agent 内网可达，`127.0.0.1`=仅本机）。
- `ClientMsg::Open.kind` / `ServerMsg::Open.kind` 加 `"link"`；
  server 收到 link Open 时**以 server 存的 desired 为准**，
  忽略客户端传的 host/port（防入口 agent 伪造目标扫对端内网，
  默认全开策略下唯一的校验点）。
- 失败语义：`link_agent` 不在线 / agent1 dial 失败 →
  server 给入口侧发 `Close{reason}` + `log_ev`（手感同公网 tcp 打不通）。

## 4. 两端行为

- agent1（出口）：零新逻辑，`Open{kind:"link"}` 当 tcp 打；
  收敛比较（`PartialEq`）已覆盖新字段，开箱即用。
- agent2（入口）：新增监听 task，照抄 `egress` 本地监听模式
  （bind 失败只影响本监听，不断 WSS 主链；Config 更新时 abort 旧监听；
  错误进 `AgentStatus.last_error`，agent WebUI 可见）。
- server：`Open(link)` 处理 = 查表 + 向对端发 Open + 建双 channel 泵；
  `desired.toml` 格式不变（link 即 proxies 数组里多一种 type）。

## 5. WebUI（同一张隧道表）

- 表格：`type` 列加 `link` badge；`target` 列显示 `agent1→host:port`；
  domains/ports 列显示 `-`。
- 表单：`type` 下拉加 `link`；选中隐藏域名/公网端口/basic_auth，
  显示对端 agent 下拉（在线 agents）+ 对端目标 ip/port；
  监听地址标签切换，默认 `0.0.0.0`（提示 `127.0.0.1`=仅本机）。
- 校验：link 必填对端三件套+监听端口；`link_agent` 禁止等于自己（自环）；
  `name` 在该 agent 下唯一（复用现有逻辑）。
- conns/traffic 零改动（自动按 `tunnel=link名` 统计）。
- agent 侧 WebUI 只读显示 link 监听，不可改（源头在 server desired）。

## 6. 流量统计与连接（复用，无额外工作量）

- **conns**：link 中转泵建流时 `insert_conn`（`tunnel=link名`，`peer`=连到
  agent2 监听的对端），每泵一块累加该行 `rx/tx`，双关时删除。
  实现时注意走 `HttpConnGuard` 同款 Drop-guard 语义，任一侧断都清行，
  不引入新僵尸行（`conns` 上限 5000 复用）。
- **traffic**：60s tick 按 `traffic_key(hostname, name)`（即 `agent2/link名`）
  记增量，link 字节天然经过两端 agent 的 `rx/tx_bytes` 累加路径
  （`tunnel.rs` 的 Binary/out_rx 分支不分 kind），所以 link 自动进
  `/api/traffic`，流量 tab 下拉直接多出 `agent2/link名` 选项，落盘
  `traffic.json` 复用。
- 注意：当前 tick 取的是 agent 级累计（同 agent 多条目均摊口径已有近似），
  link 沿用同一口径，不单独立精确到流的计数——与现有隧道一致，不加复杂度。

## 7. 测试与边界

- 单测：link 字段 serde 默认（老 desired 不炸）；自环校验；
  Open(link) 目标以 server 存为准（伪造被忽略）。
- e2e：
  1. `link_tcp_roundtrip`（agent1 挂 echo，client 经 agent2 监听回声；旧代码红）；
  2. `link_agent_offline_closes`（对端不在线，client 被干净 Close，主链不断）；
  3. `link_hot_update`（删 link 后监听端口释放）。
- 实现顺序：`proto.rs` → server 中转 → agent 监听 → WebUI → 单测+e2e（约 5 提交）。
