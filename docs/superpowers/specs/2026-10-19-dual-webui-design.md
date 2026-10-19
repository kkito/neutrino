# neutrino 双 WebUI + server 期望态设计

日期： 2026-10-19 ｜ 状态： 已通过用户评审（Q1–Q5 全 ok，方案一）

## 1. 背景

- client 配置现状： 纯 `agent.toml` 文件（`hostname/token/[[proxies]]`），启动读一次；
  之后只能靠 server 下发 `Config` 热更新内存副本，文件不改写，agent 重启配置丢失。
- server WebUI 现状： 单文件 `web/index.html`（`include_str!` 编入二进制），仅总览/隧道开关/裸 JSON 推送，
  无表单化隧道管理，样式为裸 table。
- 目标： server 与 agent 各有一个 WebUI；server 为唯一配置源头（期望态），agent 无状态；
  两端页面同一视觉语言。

## 2. 架构与数据流

- server 新增 `desired.toml`：`[agents.<hostname>] proxies = [...]`，复用 `ProxyConfig` 结构不变，
  为将来"按服务"维度（多 agent 同业务）预留位置（本期只实现按 agent）。
- server 启动加载到内存 `desired: hostname -> proxies`；WebUI CRUD 写文件＋更新内存＋即时生效路由。
- 在线 agent：修改后立即发送 `ServerMsg::Config`；离线 agent：`register` 时 server 用期望态覆盖
  agent 上报的 proxies（上报份仅记日志比对）。
- agent 启动新增 `--web/--web-user/--web-pass`（默认 admin / neutrino123，bcrypt 落 agent data dir）；
  `agent.toml` 瘦身为 `hostname/token/server`，`proxies` 保留解析兼容但不再作为源头（有值则 warn 忽略）。
- agent 本地 WebUI：单文件 `web/agent.html`，`include_str!` 编入二进制。

## 3. 组件与接口

### 3.1 server 侧

- `GET/POST /api/desired/:hostname`：隧道 CRUD（表单用）；原 `POST /api/config` 保留为高级直推。
- `web/index.html` 重做：侧边栏（总览/隧道/日志）＋隧道表格＋新增/编辑弹窗表单
  （按类型切换字段：http 必填 domains，tcp/udp 必填 remote_port）＋toast 提示；
  原裸 JSON 推送框保留为"高级"折叠区。
- 隧道行状态：在线生效 / 待同步（agent 离线）/ 已禁用。

### 3.2 agent 侧

- `GET /api/status`：上行状态（server 地址/在线/RTT/重连次数）＋生效中隧道（只读，标"由 server 下发"）。
- `POST /api/settings`：改上行 server 地址 / 管理口令（改地址后重启 session）。
- 鉴权：启动口令 bcrypt 校验，简 Basic/Bearer。

### 3.3 共享视觉

- 同一套 CSS token：深色模式、徽章（在线/离线/启用/禁用）、表单、弹窗、toast；
  两个 HTML 同色系同组件，零依赖单文件。

## 4. 错误处理

- 期望态写文件失败 → API 500，内存不改，toast 报错。
- 下发 Config 时 agent 离线 → 跳过，register 时覆盖；WebUI 显示"待同步"。
- agent 改上行地址失败（连不上）→ 保留旧 session，状态页标"连接失败，重试中"，不丢生效隧道。
- 冲突一律以 server 期望态为准。

## 5. 测试

- 单元：`desired.toml` 读写 roundtrip、register 覆盖逻辑、表单字段校验。
- e2e 新增 2 个：WebUI 建隧道→agent 生效打通；agent 重启后被期望态覆盖。
- 现有 17 个测试保持全绿。

## 6. 自检

- 无 TBD/占位；各节一致（按 agent 存储，B 维度仅预留未实现已注明）。
- 范围单轮可交付：不含多 agent 同业务展开（B）、不含 agent WebUI 经 server 穿透访问（Q2 选 A，SSH 转发）。
