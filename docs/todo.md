# TODO

## egress（出网代理）

- [x] HTTP forward proxy / CONNECT（一期，已实现 commit 076a3c9）
  - [x] agent 本地监听 + 解析 CONNECT / 普通 HTTP 请求目标
  - [x] `ClientMsg::Open{kind:"egress"}` + server 侧 `TcpStream::connect` 拨公网
  - [x] stream 泵复用、Close 收尾、错误透出
  - [x] agent 本地 WebUI 开关/端口显示
  - [ ] server WebUI agent 行 egress 状态（只读，二期，需扩展 Register 上报）
  - [x] 单元 + e2e（`curl -x` 模拟通用客户端）
- [ ] SOCKS5 CONNECT（二期）
  - [ ] agent 本地 SOCKS5 握手 + CONNECT 解析
  - [ ] 与 HTTP 共用同一 `egress` 通道
- [ ] Mixed / 双协议同端口（三期，可选）
  - [ ] 同一监听端口 sniff HTTP vs SOCKS5
- [ ] 安全增强（待评审，另开 spec）
  - [ ] server 目标白名单（按 host:port 匹配）
  - [ ] 按 agent 授权（`allow_egress`）
- [ ] 认证（待定）
  - [ ] 本地代理是否需要用户名/密码（默认 127.0.0.1 可免）
  - [ ] WSS 侧复用现有 token，不新增
