# agent 本地 HTTP 入口（local ingress）设计

日期：2026-10-21。目标：agent 自带内网 HTTP 入口，内网经 `*.<suffix>`（如 `*.local.xxx.com`）
直访 agent 名下各 http 隧道，不走公网 server。范围 A（仅 http）＋ B（`local_suffix` 泛域名）
＋ C（监听可配，默认 80）＋ Q4-A（ miss 列名 404）。

## 1. 配置（`agent.toml`）

```toml
[local_ingress]
enabled = false            # 默认关：避免无 root 时 :80 bind 失败刷 warn，也避免用户无感知暴露内网
listen_ip = "0.0.0.0"
listen_port = 80           # 默认 80：内网 URL 无端口；被占/无权限则 warn + status 标红，不影响主链
suffix = ""                # 如 ".local.xxx.com"；为空 = 未配置，入口不启动（与 enabled 双保险）
```

- 新增 `LocalIngress` 结构体（`src/agent/mod.rs`，仿 `EgressHttp`：`enabled/listen_ip/listen_port/suffix`，
  默认 `false/"0.0.0.0"/80/""`），`AgentFileConfig` 加 `local_ingress: LocalIngress`（`#[serde(default)]`，老文件兼容）。
- agent 本地 WebUI 可改四项（仿 egress 表单：`local_enabled/local_ip/local_port/local_suffix`），
  保存回写 toml（`merge_local_ingress_toml` 纯函数单测）＋ bump 已有 `egress_reload` 通道，watcher 同时重起
  egress 与 local ingress 两个监听（主链不动）。
- `read_local_ingress_file2` 供 watcher 热重启读最新值（仿 `read_egress_file2`）。

## 2. 匹配（纯函数 `strip_ingress_name(host, suffix) -> Option<String>`，单测）

- `host` 已是 `extract_host` 小写去端口结果；`suffix` 归一化小写，必须以 `.` 开头（否则配置无效→入口不启动＋status 标错）。
- `host.strip_suffix(suffix)` 余下 `label`：非空且不含 `.`（单 label，防 `a.b.suffix` 越权）→ `Some(label)`；
  否则 `None`（→ 404 目录页）。大小写不敏感。
- 查表：`status.proxies` 快照（**三传输会话已在 Config/ConfigAck 处更新此字段，无需改 session/quic/kudus 会话**），
  找 `ptype=="http" && enabled && name==label` 的第一条；无 → 404。

## 3. 转发（`src/agent/local_ingress.rs`，仿 `egress.rs::serve_egress` 结构）

每 inbound 连接（裸 TCP，agent 自己就是 HTTP server）：

1. 读到 `\r\n\r\n`（上限 64K，同 egress 防慢连接）。
2. `extract_host` → `strip_ingress_name` → 查表；miss → `404`＋`text/plain` 目录页
   `available: <name1> <name2>...`（内网排错，Q4-A；授意：只列 http 隧道名，不泄露 token/上行地址）。
3. `check_basic_auth`（`common::proto`，与 server 入口同语义）：配了 `basic_auth` 才校验，
   失败 → `401`＋`WWW-Authenticate: Basic realm="<name>"`（浏览器弹框，agent/内网服务无感知）。
4. `inject_xfp(head, set_x_forwarded_proto)`（复用 `crate::server::http_util::inject_xfp`，同 crate 可见）；
   未配则原样。
5. `TcpStream::connect(local_ip:local_port)` → 失败 `502 agent dial refused\n`（对齐 server `egress denied` 文案风格）。
6. 写 head 后 `copy_bidirectional` 透明透传（keep-alive/chunked/upgrade 全透，无需解析 body；
   关闭任一方向即收尾，同 link 泵语义）。

并发/限流：每连接一 task，无全局限流（内网可信；server 侧 ratelimit 不适用，agent 本地直连本机服务）。
`conns`/`traffic` 不记（server 侧流量口径不变，避免双算；WebUI 只显示在线状态＋隧道表）。

## 4. 生命周期与可观测

- 与 session 解耦：`run()` 里与 egress 并列起 task，读 `status.proxies` 实时快照 → **Config 热更新即时生效**，
  无需 sync；session 重连不影响本地监听（反而是优点：内网入口在断线重拨期仍接受连接，拨通即恢复）。
  注意：断线期 inbound 会 dial 本地成功但无处可去——不，dial 的是**本地服务**，直接透传，
  本地入口根本不依赖上行！断网时内网照常用（这是附带优点，写进 README）。
- 状态：`AgentStatus` 加 `local_ingress_listen/on/err/names`（names=当前 http 隧道名，供 WebUI/目录页复用同一快照源）。
  bind 失败：`warn!`＋`err=Some(...)`，task 退出（同 egress，不 abort 主循环）；reload watcher 下次重起。
- 日志：`info!("local ingress on {bind} suffix {suffix}")`；每连接只 `debug`（防刷屏，对齐 egress `handle_conn`）；
  miss/auth 失败 `debug`（内网扫描不刷屏）；dial 失败 `debug`＋客户端 `502`。
- agent WebUI：状态行显示 `local ingress: on 0.0.0.0:80 (.local.xxx.com)` 或 err；设置表单四项＋保存即重载。

## 5. 测试（TDD，先红后绿）

- 单测（`local_ingress.rs::tests`）：`strip_ingress_name`（大小写/带点 label 拒绝/空 label/后缀无点前缀/空后缀）；
  404 目录页包含 names 且不含 token；`merge_local_ingress_toml` 保留 proxies/upstream；`read_*` 默认值。
- e2e（`tests/e2e.rs::local_ingress_http_names`）：真子进程；backend http 固定 body；agent 开
  `local_ingress(enabled, 127.0.0.1:高位端口, suffix=".local.e2e")`；断言：
  ① `Host: web.local.e2e` → 200 body；② `Host: nope.local.e2e` → 404 且含 `web`；
  ③ `Host: evil.deep.local.e2e` → 404（多 label 越权拒绝）；
  ④ basic_auth 隧道无头 → 401，有头 → 200；
  ⑤ `/api/config` 清空后 → 404（热配即时，无需 reload）；
  ⑥ 64KB body 往返一致（透明透传无损）。
- 回归：`make build`（`-D warnings`）＋ `make test` 全绿（含既有 93＋28）。

## 6. 非目标

- https/tcp/udp 本地入口（各自直连即可，无需经 agent；后续需要再议）。
- 本地入口走 server 计费/traffic（口径不变，内网流量不上报）。
- SNI/按端口分流、TLS 终结（纯 http 明文，内网可信假设；要加密走 server 公网 https 隧道）。

## 自检

- 无 TBD；`strip_ingress_name` 与 `route_fallback` 无冲突（不同进程不同端口）；
  `status.proxies` 三会话更新已确认（session.rs:177 / quic_session / kudus_session 同模式）；
- 范围单计划可装下：1 新文件＋mod.rs 接线＋web.rs 表单＋proto 无改（`ProxyConfig` 零字段新增）；
- `suffix` 为空 vs `enabled=false` 双保险：任一即不启动，watcher 重启前校验并写 `err` 说明原因。
