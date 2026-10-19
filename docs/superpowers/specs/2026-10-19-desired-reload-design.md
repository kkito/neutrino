# desired 文件重载按钮设计

日期： 2026-10-19 ｜ 状态： 待实现 ｜ 需求来源： public-port-ingress 通用化后续（server 侧配置生效方式）

## 1. 背景

- server 期望态 `desired.toml` 是唯一来源（`--desired` 指定路径，默认 `./data/desired.toml`）。
- 现状两条写入路径不对称：WebUI 改（`POST /api/desired/:hostname`）即时生效；**手改文件只在 server 启动时加载一次**，改完要么重启，要么进 WebUI 随便保存一次间接触发。
- 本需求：**要么重启生效，要么点按钮**。不做文件监听（无新依赖、无跨平台事件坑），不做门禁/审批（超出范围）。

## 2. 后端：`POST /api/desired/reload`

- 路由：`src/server.rs` 加 `.route("/api/desired/reload", post(api_desired_reload))`，注意 Axum 路由优先级——`/api/desired/reload` 必须先于 `/api/desired/:hostname` 注册（或确认 Axum 静态段优先，单测覆盖）。
- 行为：
  1. `DesiredStore::load(&s.desired_path)` 重读文件，全量替换内存 `s.desired`。
  2. 对在线 agent 按 hostname 推 `ServerMsg::Config` + 调 `apply_proxies_for_agent`（复用 `api_desired_set` 后半段，不落盘——文件本身就是源）。
  3. 返回 `{ok, reloaded, skipped, pushed}`。
- 出错进日志（核心诉求）：
  - 文件读不到 / TOML 解析失败 → `error!`（含 path），接口返回 500 + reason，内存保持不动。
  - 解析成功但某条 `validate_proxy` 不过 → 逐条 `warn!`（含 hostname/name/原因），**跳过坏条、好条照常生效**，`skipped` 计数返回。
  - 现状 `DesiredStore::load` 解析失败静默 `unwrap_or_default()`，本次顺手让 load 侧也打 warn（保持行为兼容，只加日志）。
- 鉴权：沿用现有 `auth_ok` + JWT，与其它 `/api/*` 一致。

## 3. 前端：server WebUI「从文件重载」按钮

- 文件：`web/index.html`，期望态编辑区按钮排（`loadDesired`/`saveForm` 处）新增「从文件重载」按钮，样式 `.btn ghost`。
- JS：`fetch('/api/desired/reload', {method:'POST', headers:hdrs(true)})` → toast 显示 `已重载 N 条，跳过 M 条，推送 K 个 agent`；失败 toast 红字显示 reason。沿用现有 `toast(m,err)`，无新风格。

## 4. 测试

- 单测（`src/server.rs::tests`）：路由优先级——`POST /api/desired/reload` 不被 `:hostname` 吞掉（`reload` 当 hostname 查应无此行为）。
- e2e（`tests/e2e.rs`）：手改 desired 文件加一条 tcp 映射 → 调 reload → 端口通；再把文件改错（非法 TOML）→ 调 reload 返回 500 且旧映射仍通（内存不动）；修好文件但某条字段非法 → reload 成功、好条生效、坏条跳过（看返回 `skipped=1`）。
- 全绿门槛：`make build` 零 warning + `make test`（44+9 及新增）。

## 5. 非目标

- 文件监听/自动热加载（notify/mtime 轮询都不做）。
- 门禁、审批、白名单、按 agent 授权（另开需求）。
- server WebUI agent 行 egress 只读状态（egress 二期，已在 todo）。

## 自检

- 无 TBD；路由优先级、坏条跳过语义、内存不动保证均已明确，无双解。
- 范围单计划可装下：server.rs 一接口 + index.html 一按钮 + 单测一则 + e2e 一则。
