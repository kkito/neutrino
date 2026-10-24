# AGENTS.md — neutrino 协作规范

## 项目速览
- Rust 单二进制：`neutrino server | agent`（`src/main.rs` 分发）。
- server 公网单端口 `--listen`（默认 `127.0.0.1:7440`）：`/ws`（agent 信令）+ `/api/*` + `/`（WebUI）+ 隧道域名 Host 透传，三路按 Host 分流（`src/server.rs::route_fallback`）。`--http-in` 已废弃（传了 warn 忽略）。
- agent 内网出站 WSS 长连，无公网入站。隧道以 server `desired.toml` 为唯一源头，agent 本地 proxies 忽略；agent WebUI（`--web`）只管上行地址/hostname/token。
- 协议见 `README.md` + `docs/architecture.md` + `docs/superpowers/specs/`。

## 文档索引
- `README.md`：协议/功能对照/本地验证/部署。
- `docs/architecture.md`：架构与典型流程（含 mermaid 图）。
- `docs/nginx.md`：natproxy 侧 nginx 接入（管理域/业务域/tcp-udp/验证）。
- `docs/superpowers/specs/2026-10-19-dual-webui-design.md`：双 WebUI + 期望态设计。

## 常用命令
```bash
make build      # debug 构建，零 warning 才算过
make test       # = cargo test（单元 + e2e），全绿才提交
cargo test --bin neutrino <name>   # 跑单个单测
cargo test --test e2e <name>       # 跑单个 e2e
```

## 测试现状（2026-10-19）
- 单测 139（`src/server/*::tests`、`src/agent*::tests`、`src/main.rs::main_tests`）。
- e2e 35（`tests/e2e.rs`）：真子进程 + 随机端口，覆盖 Host 路由/404/WebUI 分流/XFP/tcp 回声/udp/期望态 CRUD/重启覆盖/防 Register 循环/agent WebUI 改上行/限速/kudus/quic/link。
- 全量串行：单测 ~2s + e2e ~39s（`--test-threads=1`，e2e 必须串行，并发会因时间窗互相干扰而假红）。

### 测试等待规范（必读，已优化过一轮）
禁止盲等 `sleep(Ns)` 来“等某状态就绪”。两类正确做法：
1. **轮询可观测状态**：boot 后就绪看 `/api/tunnels` 或 `/api/overview`（参 `settle()` / `wait_agents_count()`），
   命中即返回（~20ms），未命中才耗尽上限。boot 变体内的粗同步已统一为 `settle()`（3×20ms）。
2. **参数化物理时间**：限速类用例是“字节/秒”，等比缩小限速值与灌包/排空窗口即等价
   （如 `e2e_udp_ratelimit_caps_ingress_rate`：64k/1s/2s → 512k/250ms/300ms，判据从“包数<300”改为“<400”）。
3. **观察窗类判据**：`e2e_register_does_not_loop_config_push` 原来是“死等 3s 再数条数”，
   改为“先等首条出现，再观察 400ms 看是否还涨”——死循环的特征是持续增长，此判据更强且更快（3.4s→0.6s）。

**后台 tick 可配**：`server` 新增 `--live-tick-ms/--traffic-tick-ms/--limiter-tick-ms/--persist-tick-ms`，
0=默认（5000/60000/300000/30000，与旧硬编码一致，`server::tick_tests` 锁死）。
`tests/e2e.rs::boot_with_desired` 统一传 50ms——`/api/live` 需两个 live tick 才出增量，
这也使 `e2e_live_snapshot_within_10s` 从 10.2s 降到 0.3s。

**不能动的物理时间**：mock 后端故意慢响应（`e2e_http_conns_cleaned_on_client_abort` 的 5s）、
限速窗口 1s（`ratelimit.rs`）、kudus RTO 200ms、负向“黑洞”观察窗（`kudus_bad_token_blackhole`）。

## 铁律：TDD 修 bug / 加功能
1. **先写失败测试（RED）**：单测放对应模块 `mod tests`，回归放 `tests/e2e.rs`。必须亲眼看到它红，且红的原因是"行为缺失"（不是笔误）。修复前回退验证：临时关掉修复，测试必须变红（如 `overlay log count 250: Register/Config loop!`）。
2. **最小实现（GREEN）**：只让测试变绿，不顺手重构、不加功能。纯判定逻辑抽成无 IO 纯函数（如 `route_fallback`、`needs_config_push`、`merge_upstream_toml`、`parse_response_head`）再测。
3. **改完必须验证**：`make build`（已配 `RUSTFLAGS="-D warnings"`，任何 warning 直接变 error 中断）+ `make test`（30+7）全过才算完。e2e 允许重试的时间断言用轮询+上限（如 40×200ms），不用固定 sleep 赌竞态。
4. **再提交**：注释写清"根因→修法"（参考 `Register -> Config -> Register ping-pong` 那次），e2e 注释写清"旧代码如何复现、断言抓什么"。

## 部署（natproxy server 二进制）
- linux 二进制只走 GitHub Actions：打 tag `v*` 触发 `.github/workflows/release.yml`
  （musl static，产物 `neutrino-<version>-x86_64-unknown-linux-musl.tar.gz`，见 GitHub Release），
  下载解压到 `/root/nastools/tunnel/neutrino` 再 `systemctl restart tunnel-server`。
- 别 `scp` 本机 `target/release/neutrino`（macOS arm64，server 上 203/EXEC 起不来；
  2026-10-20 已踩过一次把线上二进制覆盖掉）；本地也别折腾 musl cross（缺 musl-gcc，ring 编不过）。
- 本地 `make build` + `make test` 全绿即可，部署等 CI 产物。

## 易踩坑（已有回归用例，别再犯）
- `/` 不能注册精确路由：`GET / + Host: 隧道域名` 会被 WebUI 抢走，统一走 fallback 按 Host 分流。
- 裸 IP/`localhost`/空 Host 走 WebUI（`127.0.0.1` 带点，不能按"有点=隧道"判），未知点分域名才 404。
- `on_register` 收敛时跳过 `Config` push，否则 `Register→Config` 死循环刷屏。
- agent `Config` 回 `Register` 确认；WebUI 改上行走 redial generation 比对，睡眠间隙的 bump 不能丢。
- agent `--web-pass` 只在首次生成 hash 时生效，已有 `{config}.webpass` 时传参 warn 忽略；删文件才重置。
- `ProxyConfig` 比较依赖 `PartialEq`；加字段记得检查收敛比较与单测。
