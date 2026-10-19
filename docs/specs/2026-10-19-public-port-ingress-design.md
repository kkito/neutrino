# neutrino 公网端口 ingress（以 51413 BT 端口为例）设计

日期： 2026-10-19 ｜ 状态： 草稿待评审 ｜ 需求来源： snail transmission 51413 被动 incoming 切 neutrino

## 1. 背景与目标

- 现状：51413 TCP+UDP 走 frp → hknas（`103.215.83.104:51413`），外面 peer 靠 `announce-ip` 连回来。跑得好好的。
- 目标：论证 51413 能否切到 neutrino（natproxy），并给出通用做法——**任意 TCP/UDP 公网端口经 server listen → agent → 内网**。
- 结论先行：**代码侧现成，卡在机房端口映射**（§2）。本文是"条件满足后怎么做"，不是"现在就切"。

## 2. 前置条件（与代码无关，机房层面）

- neutrino 的 tcp/udp ingress 要求 server **先在公网 listen 到端口**（`ensure_tcp_listener` / `ensure_udp_listener` 绑 `0.0.0.0:remote_port`）。
- natproxy 现只有 `8080→80`、`7443→443` 两个映射，公网流量到不了 51413——不满足条件，写再多代码也没用。
- 行动项：去 natproxy 面板加 `51413 TCP+UDP → 内网` 映射。能加 → §3 直接配；不能加 → 继续 frp+hknas，本需求关闭。

## 3. 切流做法（条件满足后，零开发，纯配置）

### 3.1 server desired（natproxy `tunnel/data/desired.toml`）

```toml
[[agents.snail-kkito]]
name = "transmission-bt-tcp"
type = "tcp"
local_ip = "172.28.0.10"
local_port = 51413
remote_port = 51413
enabled = true

[[agents.snail-kkito]]
name = "transmission-bt-udp"
type = "udp"
local_ip = "172.28.0.10"
local_port = 51413
remote_port = 51413
enabled = true
```

- server 启动/热加载后自动 `bind 0.0.0.0:51413`（tcp+udp 各一），公网 peer 进来 → 按 `remote_port` 选 agent → agent 拨 snail 内网 transmission。
- UDP 是按 peer session 转发的（现有 `ensure_udp_listener` 逻辑），BT 的 uTP/UDP 打洞包能过；TCP 是纯字节透传，无 HTTP 语义干扰。

### 3.2 transmission 侧

- `announce-ip` 改成 natproxy 公网 IP（`43.226.62.230`），或保持 hknas IP 做灰度（部分 peer 走老路）。
- `peer-port` 还是 51413，不用动。

### 3.3 灰度与回滚

- 灰度：先加 tcp 不加 udp（或反之），看 tracker peer 数/上传量变化。
- 回滚：desired 里 `enabled = false` + frp 那路保持 online（frpc 的 51413 配置别删），秒级切回。

## 4. 通用含义（为什么说"通用"）

- 本需求不写代码：`type=tcp/udp + remote_port` 就是通用端口映射，51413 只是第一个用例。
- 以后任何"公网端口 → 内网端口"（如游戏服、SSH 备用口）都按 §3.1 加一段 desired 即可。
- 与 egress（出网代理）正交：一个管进（listen），一个管出（connect），复用同一套 stream 泵。

## 5. 与 frp 的对比（做决策用）

|  | frp + hknas（现状） | neutrino + natproxy（本方案） |
|---|---|---|
| 公网端口 | hknas 原生开放 51413 | 需面板加映射（前置条件） |
| 出口带宽 | hknas IDC 大 | natproxy 小 VPS，peer 大流量可能吃紧 |
| UDP | 支持（51413/udp 已映射） | 支持（session 转发） |
| 运维 | 多一套 frps | 少一套组件，desired 统一管 |

- 即使条件满足，带宽也是隐忧：做种上传大流量经 natproxy 中转，不如 hknas。建议：能加映射也先灰度看上传量，再决定切不切。

## 6. 测试（条件满足后）

- 公网 `nc -v 43.226.62.230 51413` 通；tracker 后台 peer 列表出现 natproxy IP；上传量对比 frp 时期。
- UDP：`nc -u` 探活 + 实际做种有上传即算过。

## 7. 自检

- 无代码变更，无 TBD；前置条件明确（面板加映射），不满足则本需求关闭、frp 续跑。
- 待评审：要不要去加映射？灰度策略同意？
