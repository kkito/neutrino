# QUIC 传输底座（agent↔server 双传输）设计

日期：2026-10-21 · 状态：brainstorming 已确认（A 监听形态 + A' 帧映射），待实现计划。

## 1. 背景与目标

- 现状：agent↔server 只有一条 WSS 长连（`src/agent/session.rs::session` ↔
  `src/server/tunnel.rs::ws_loop`），控制帧走 Text JSON，数据走 Binary
  `[stream_id:u32 BE][payload]`。UDP 访客包是 `UDP-over-TCP`，丢包即全队头阻塞。
- 目标：新增 QUIC 传输与 WSS 共存。server 可开 QUIC 监听，agent 启动时按
  `--server` scheme 选路：`ws://,wss://` 走老路，`quic://host:port` 走 QUIC。
  各隧道 `ProxyConfig`（http/tcp/https/udp/link/egress）零改动。
- 非目标：DATAGRAM 跑数据（二期优化）；0-RTT；多路径；WSS 摘除。

## 2. 架构与监听形态（方案 A）

- `server --quic-listen 0.0.0.0:7444`（默认空=不开），与 `--listen` TCP 端口独立。
  nginx/证书不动；公网防火墙需另放行该 UDP 端口。
- 证书：server 启动时 `rcgen` 自签（SAN=listen host，落盘 `data/quic-cert.der` 供运维核对
  指纹，`data/quic-key.der` 0600 落盘复用，重启不漂移）。agent 侧自定义
  `ServerCertVerifier` 跳过链校验（只防被动窃听），真认证靠 token（见 §4）。
- 依赖：`quinn 0.11 + rustls 0.23 + rcgen 0.13`（与现有 rustls 栈同系，不引入 openssl）。
- 代码落点：新增 `src/common/quic.rs`（endpoint 构造+帧编解码纯函数），
  `src/server/quic.rs`（监听+accept→复用会话语义），`src/agent/quic_session.rs`
  （拨号+建流）。`session.rs`/`tunnel.rs` 现有 WSS 路径一行不改。

## 3. QUIC 上的帧映射（方案 A'，拒绝换行分隔）

- Control stream：agent 建连后 open 一条双向 stream，命名 control。
  帧格式 `[len:u32 BE][JSON bytes]`，`len ≤ 1MiB`，超限判恶意并 `connection.close()`。
  JSON 即现有 `ClientMsg/ServerMsg` serde 复用（`src/common/proto.rs` 零改动）。
  半包用 `read_exact(len)` 解决，粘包用 len 切分；QUIC stream 本身可靠有序。
- 隧道数据：每个隧道一条独立 QUIC 双向 stream。首帧为 length-prefixed
  `Open{stream, kind, host, port}`（`stream` 沿用现有 sid 分配：agent 奇数/server 偶数，
  与 WSS 互不干扰），之后即纯字节流（TCP/HTTP/link/egress 照搬现有泵）。
  UDP 访客包在 stream 内再套 `[dlen:u16 BE][payload]` 保 datagram 边界
  （`dlen ≤ 65527`，超限丢包+计数，不关流）。
- Close 语义：`[len][Close{stream, reason}]` 走 control + 对应数据 stream `finish()` 关写端；
  对端读到 FIN 即收尾。server `conns`/`traffic` 记账点与 WSS 版同一位置，
  双关清理复用 Drop-guard 语义，不引入新僵尸行。

## 4. 会话语义（与 WSS 一字不差，纯函数复用）

- 时序：`Hello{hostname,version,token}` → `Welcome{interval}` → `Register{proxies}` →
  期望态覆盖（`resolve_proxies`/`needs_config_push`，收敛跳过 Config 防 ping-pong）→
  `Config/ConfigAck/Register` 热更新 → `Ping/Pong` 双向心跳（server 15s 测 RTT，
  agent 按 welcome interval 发 Ping）。token 不对 server 直接 `close(401)` + `log_ev`。
- agent 重连：指数退避 `[1,2,5,10,30,60]s` + WebUI redial generation 打断，
  复用 `src/agent/mod.rs::sleep_backoff_or_redial` 同一函数，不另写一套。
- agent 本地 WebUI 状态（online/rtt/reconnects）写入点不变，只是多一个
  `transport: "quic"|"wss"` 字段展示。

## 5. 两端 CLI 与配置

- server：`--quic-listen ""` 默认不开；传值即绑 UDP + 打印 `quic listening on …` +
  证书指纹（sha256 前 16 hex，运维核对用）。
- agent：`--server quic://host:port` 走 QUIC（`DEFAULT_AGENT_SERVER` 不变仍是 wss；
  以 `quic://` 前缀判定，无需新增 `--transport` flag，少一个互斥校验）。
  `agent.toml` 的 `server = "quic://…"` 同理生效；WebUI 上行地址改后红拨链路复用。
- 失败语义：QUIC 握手/建连失败进同一重连循环（`last_error` 写 `quic: …` 前缀，
  与 `ws: …` 区分，WebUI 可见）。

## 6. 测试与边界

- 单测（`src/common/quic.rs::tests`）：len-prefixed 编解码（半包/粘包/超限拒收）；
  udp `[dlen]` 打包拆包（空包/超大丢弃）；`quic://` URL 解析（缺端口/错 scheme 拒绝）。
- e2e（`tests/e2e.rs`，真子进程+随机端口）：`quic_basic`（QUIC 建连→HTTP 透隧道→
  UDP 回声→WebUI 热下发 Config 生效）；`quic_bad_token_closes`（错 token 被关，
  主监听不倒）；`wss_still_works`（现有 7 个 e2e 即回归，不另写）。
- 铁律：先写失败测试（关掉 QUIC 实现，`quic_basic` 必须红，且红在"建连失败"不是笔误）；
  `make build`（零 warning）+ `make test`（30+7+新增）全绿才提交。

## 7. 实现顺序（约 5 提交，不含文档）

1. `common/quic.rs` 纯函数（帧编解码+URL 解析）+ 单测；
2. `server/quic.rs` 监听+accept+hello 鉴权（先只做到 Welcome/Close）+ 单测；
3. 会话语义移植（Register/Config/心跳/pump 复用，UDP dlen 边界）；
4. agent `quic_session.rs` + `--server quic://` 选路 + WebUI transport 展示；
5. e2e + README/architecture 文档更新。
