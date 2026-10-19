# neutrino — stealth WSS tunnel (Rust, server|agent 单二进制)

对照 `natproxy/docs/tunnel-requirements.md` + `tunnel-design.md` 实现，M1–M5 全量。

## 协议（src/proto.rs）

- 控制帧 WSS Text JSON：
  - C→S: `hello/register/ping/pong/open/close/configack`
  - S→C: `welcome/ping/pong/open/close/config/error`
- 数据帧 WSS Binary：`[stream_id:u32 BE][payload]`，server 偶数 id。
  TCP/HTTP 每连接一个 stream 全双工；UDP 每个 peer 一个 stream，每帧即一个 datagram。
- `ProxyConfig`：`name/type(local http|tcp|https|udp)/local_ip/local_port/domains/remote_port/set_x_forwarded_proto/enabled`（`enabled` 缺省 true，老配置兼容）。

## 功能对照

| 需求 | 实现 |
|---|---|
| WSS 单长连接+token+重连+双向心跳+RTT | agent 指数退避重连；双方 ping/pong；server 侧 `rtt_ms` 进 overview |
| http Host 路由 | `http_ingress` 按 `Host` 查多 agent 轮询；`set_x_forwarded_proto` 改写请求头（owncloud 用） |
| https 透传 | `type=https` + `remote_port`：server TCP listen，agent 按 `remote_port` 匹配本地 TLS 端口透传（不解密） |
| tcp 透传 | 同上 `type=tcp`（如 51413），lazy listen |
| udp | 每 `remote_port` 一个 UDP socket，peer→stream 会话 120s 过期；agent 用 connected UDP 透本地 |
| WebUI 登录 | bcrypt（`genhash` 生成，存 `state.json`；空=初装 admin/welcome2ll）+ HS256 JWT（HttpOnly cookie `nt_session` + Bearer 双通道），未登录 `/api/*` 401 |
| 双 WebUI | server `web/index.html`（总览/隧道表单/日志）+ agent `--web` 本地页（上行状态/只读隧道/改口令），同视觉 token，深色模式 |
| 期望态（server 为准）| `desired.toml`（`[[agents.<hostname]]]`，结构同 ProxyConfig）→ WebUI `GET/POST /api/desired/:hostname` 增删改 → 在线即下发 `Config`，离线 register 时覆盖+回推同步；agent 本地 proxies 忽略 |
| 多 agent | domain/port → agent 列表轮询；`state.json` 落盘 totals+password_hash（30s + 断线时） |

## 测试

```bash
cargo test            # 17 单元（帧/路由/XFP/JWT/state/期望态/校验） + 5 e2e
```

e2e 用 `CARGO_BIN_EXE_neutrino` 起真 server/agent 子进程（`kill_on_drop`，无残留），随机端口，
覆盖：Host 路由、未知域名 404、XFP 注入、401 门禁、cookie 颁发、tcp 回声、udp 回声、
`POST /api/config` 清空推送、`toggle` 不存在隧道 404、WebUI 建隧道即时打通+落盘、
agent 本地错误配置被期望态覆盖（含回推同步本地路由表）。

## 本地验证

```bash
cargo build
./target/debug/neutrino server --listen 127.0.0.1:7440 --http-in 127.0.0.1:7080 --token welcome2ll --desired ./data/desired.toml &
./target/debug/neutrino agent --server ws://127.0.0.1:7440/ws --config agent.toml.example --web 127.0.0.1:8080 &
# 隧道在 server WebUI 里建（/ → 隧道 → +新增隧道），agent 无需配 proxies
curl -H 'Host: git.nat.kkito.cn' http://127.0.0.1:7080/   # 透到 agent 本地
open http://127.0.0.1:7440/                                # server WebUI
open http://127.0.0.1:8080/                                # agent 本地 WebUI（默认 admin/neutrino123）
```

## 部署到 natproxy（server）

```bash
cargo build --release
scp target/release/neutrino root@natproxy:/root/nastools/tunnel/
NEUTRINO_TOKEN=welcome2ll ./neutrino server --listen 127.0.0.1:7440 --http-in 127.0.0.1:7080 --data ./data
```

nginx 用 `deploy/tunnel-nginx.conf`：`tunnel.nat.kkito.cn/ws`→7440（Upgrade 头+1d 超时），
WebUI `/`→7440，业务域→7080；tcp/udp 端口 podman `-p 51413:51413[/udp]`。

## 部署到 snail（agent）

```bash
scp target/release/neutrino agent.toml snail:/home/kkito/.config/tunnel/
sudo cp deploy/tunnel-agent.service /etc/systemd/system/ && sudo systemctl enable --now tunnel-agent
```
