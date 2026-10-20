# 映射级 sleep 限速设计（2026-10-20）

## 背景

snail-kkito 的 transmission 经 51413 端口映射跑 BT，VPS（natproxy，43.226.62.230）
带宽被下载吃满（trans-bt-tcp 每分钟 40~67MB rx，约 5~9MB/s 持续）。
当时的解法是方案 2：直接下线 trans-bt-tcp/udp，转纯出向。但纯出向抢不到
被动 peer，速度受限。更好的解法：映射回来，但加个总量限速——VPS 出带宽
换速度，上限可控。

## 目标

只针对端口映射类（tcp/udp/link）加**映射级总量下行限速**，sleep 截流实现。
egress 代理（HTTP 形态）不在 scope。

## 配置

`desired.toml` 每个 tcp/udp/link 映射可加：

```toml
[[agents.snail-kkito]]
name = "trans-bt-tcp"
type = "tcp"
local_ip = "172.28.0.10"
local_port = 51413
remote_port = 51413
rate_limit = "0.5m"
enabled = true
```

### 速率字符串口径（MB/s，大小写不敏感）

- `500k` = 500KB/s，`0.5m` = 0.5MB/s（=524288 B/s），`1.5g` = 1.5GB/s
- 纯数字不写单位默认按 `m`（MB/s）
- 口径与 transmission UI 显示的下载速度一致，所见即所得
- 不配字段 = 不限速；非法值（负数、无法解析）忽略当不限速 + 一条 warn 日志，
  绝不炸 server（配置文件手滑不能把隧道搞挂）

### 配置链

- `desired.toml` 是唯一源头，server 启动 + 热更新（desired overlay）时读入内存路由表
- WebUI 每行映射加限速输入框，保存走现有 Config 落盘逻辑写回文件
  （文件永远是源头，WebUI 只是换皮改同一行）

## 限速语义

- **双向总量**（2026-10-20 修正：旧版只压下行）：公网→agent 与
  agent→公网共用**同一个**映射级 limiter，`rate_limit` = 双向字节总和上限。
  端口映射是裸字节透传，两个方向都吃 VPS 带宽，单压一边没有意义。
- **总量语义**：每个映射一个共享计数窗口，同映射所有连接的转发字节累加，
  超了大家一起 sleep——映射总上限，不是单连接上限
- udp 收包/回包同压（共用映射级 limiter）；link 双泵已双向共用同一 limiter
  （双端都在 server，两方向都吃 VPS 带宽）

## 实现（sleep 截流，方案 B）

泵每次转发一块（32KB）后：

```
应耗时 = 本块字节 / 上限(B/s) - 本块实际已用时间
if 应耗时 > 0 { tokio::time::sleep(应耗时) }
```

- 总量语义靠映射级共享 `Mutex<窗口>` 实现：窗口记（窗口起始 instant，已传字节）；
  每块先把字节累进窗口，再按窗口累计算 sleep——同映射所有连接共用一个窗口，
  超了大家一起等；窗口按 1s 滑动重置（防长期累积漂移）
- 效果是 burst-sleep 循环（锯齿），对端可能降 peer 评分——接受，
  简单直接优先；以后觉得伤再换令牌桶（本设计预留切换点：把 sleep 点
  换成桶消耗即可，配置格式不用变）
- 零限速（字段缺失/非法）时泵路径零额外开销（分支跳过，不建窗口）

## 测试（TDD）

- 单测 1：速率字符串解析（`0.5m`→524288、`500k`→512000、`2`→2MB/s、
  非法→None、大小写、`1.5g`）
- 单测 2：sleep 时长计算（给定块大小+上限+已用时间，算出 sleep 量；
  不超限时为 0）
- e2e：起个限速映射（如 `0.5m`）传固定大小（如 2MB），耗时 ≥ 理论下限
  （2MB/0.5MB/s=4s），且不限速对照组明显快；两者都传对内容（限速不丢包）

## 不做的

- egress 代理限速（HTTP 形态，CONNECT/Forward 两条路，另议）
- 令牌桶（预留以后，配置格式兼容，内部实现可换）

## 现场证伪记录（2026-10-20）

- spec 初版背景称"压住 VPS 下行带宽"治 BT 吃满——已证伪：transmission
  所在 snail 机有公网直连能力，主动 outbound 的 peer 流量根本不经过 VPS，
  隧道只承载 incoming。VPS 侧限速只能压住经隧道的那部分，不能压 BT 总量。
- 结论：本功能是**端口映射通用限速**（经此端口的流量双向总量上限），
  不是 BT 总量治理。BT 总量得在装 transmission 的机器侧动手
  （transmission 自带 speed-limit 或主机层 tc）。
