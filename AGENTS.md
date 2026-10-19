# AGENTS.md — neutrino 协作规范

## 项目速览
- Rust 单二进制：`neutrino server | agent`（`src/main.rs` 分发）。
- server 公网单端口 `--listen`（默认 `127.0.0.1:7440`）：`/ws`（agent 信令）+ `/api/*` + `/`（WebUI）+ 隧道域名 Host 透传，三路按 Host 分流（`src/server.rs::route_fallback`）。`--http-in` 已废弃（传了 warn 忽略）。
- agent 内网出站 WSS 长连，无公网入站。隧道以 server `desired.toml` 为唯一源头，agent 本地 proxies 忽略；agent WebUI（`--web`）只管上行地址/hostname/token。
- 协议见 `README.md` + `docs/architecture.md` + `docs/specs/`。

## 文档索引
- `README.md`：协议/功能对照/本地验证/部署。
- `docs/architecture.md`：架构与典型流程（含 mermaid 图）。
- `docs/nginx.md`：natproxy 侧 nginx 接入（管理域/业务域/tcp-udp/验证）。
- `docs/specs/2026-10-19-dual-webui-design.md`：双 WebUI + 期望态设计。

## 常用命令
```bash
make build      # debug 构建，零 warning 才算过
make test       # = cargo test（单元 + e2e），全绿才提交
cargo test --bin neutrino <name>   # 跑单个单测
cargo test --test e2e <name>       # 跑单个 e2e
```

## 测试现状（2026-10-19）
- 单测 30（`src/server.rs::tests`、`src/agent.rs::tests`、`src/agent_web.rs::tests`、`src/main.rs::main_tests`）。
- e2e 7（`tests/e2e.rs`）：真子进程 + 随机端口，覆盖 Host 路由/404/WebUI 分流/XFP/tcp 回声/udp/期望态 CRUD/重启覆盖/防 Register 循环/agent WebUI 改上行。

## 铁律：TDD 修 bug / 加功能
1. **先写失败测试（RED）**：单测放对应模块 `mod tests`，回归放 `tests/e2e.rs`。必须亲眼看到它红，且红的原因是"行为缺失"（不是笔误）。修复前回退验证：临时关掉修复，测试必须变红（如 `overlay log count 250: Register/Config loop!`）。
2. **最小实现（GREEN）**：只让测试变绿，不顺手重构、不加功能。纯判定逻辑抽成无 IO 纯函数（如 `route_fallback`、`needs_config_push`、`merge_upstream_toml`、`parse_response_head`）再测。
3. **改完必须验证**：`make build`（已配 `RUSTFLAGS="-D warnings"`，任何 warning 直接变 error 中断）+ `make test`（30+7）全过才算完。e2e 允许重试的时间断言用轮询+上限（如 40×200ms），不用固定 sleep 赌竞态。
4. **再提交**：注释写清"根因→修法"（参考 `Register -> Config -> Register ping-pong` 那次），e2e 注释写清"旧代码如何复现、断言抓什么"。

## 易踩坑（已有回归用例，别再犯）
- `/` 不能注册精确路由：`GET / + Host: 隧道域名` 会被 WebUI 抢走，统一走 fallback 按 Host 分流。
- 裸 IP/`localhost`/空 Host 走 WebUI（`127.0.0.1` 带点，不能按"有点=隧道"判），未知点分域名才 404。
- `on_register` 收敛时跳过 `Config` push，否则 `Register→Config` 死循环刷屏。
- agent `Config` 回 `Register` 确认；WebUI 改上行走 redial generation 比对，睡眠间隙的 bump 不能丢。
- agent `--web-pass` 只在首次生成 hash 时生效，已有 `{config}.webpass` 时传参 warn 忽略；删文件才重置。
- `ProxyConfig` 比较依赖 `PartialEq`；加字段记得检查收敛比较与单测。
