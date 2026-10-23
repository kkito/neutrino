# kudus 黑洞可观测性 + egress 细分设计（B 方案）

日期：2026-10-23 · 状态：brainstorming 已确认（只动 neutrino，不动机房/宿主机）。

## 1. 背景与目标

- 现场问题（2026-10-22/23 HK 事件）：eth0 下行持续 2~10MB/s、6 万包/秒，最后整机断网 4 小时；机房确认为外部攻击。neutrino 侧全程无感知：kudus 黑洞丢包零计数、零日志（默认级别 debug 看不见），流量统计只有 728KB/s 正常转发量，事后只能靠 sar 猜。
- 目标：下次被打时，WebUI + 日志一眼回答"被打了、谁在打、打哪"；egress 流量按目标细分，知道代理流量去了哪。

## 2. 范围（只改 neutrino server 侧）

- 改：`src/server/kudus.rs`（分发循环 4 个丢包点计数 + 采样日志）、`src/server/state.rs`（drop 计数结构 + 落盘/裁剪复用 traffic 机制）、`src/server/tunnel.rs`（egress conns 行 tunnel 细分）、`src/server/api.rs`（`/api/traffic` 前缀过滤 + WebUI 黑洞区）。
- 不动：黑洞语义（零回包）、WSS/QUIC、agent 侧、`ClientMsg` 协议字段、限速逻辑。

## 3. 黑洞计数器

- key：`kudus_drop/{reason}/{/24}`，reason 四类正好对应 `run_kudus` 分发循环 4 个丢包点：
  - `short`：包太短连 session 头都没有（典型 flood 垃圾）
  - `undecryptable`：解密失败（错 token / 扫描器乱发）
  - `bad_hdr`：解密成功但内层头非法（版本不对/损坏）
  - `unknown_session`：能解密但 session 不存在且非 SYN（重放/过期包）
- /24 聚合：IPv4 取 /24，IPv6 取 /64；防随机源 IP 打爆 HashMap。另记 `distinct_ips` 粗略数：capped HashSet 上限 1000，超了只记总数不记明细。
- 存储：复用现有 `traffic: RwLock<HashMap<String, VecDeque<(ts,rx,tx)>>>` 结构——drop 点记 rx=包数、tx=字节数，语义复用（包数/字节双通道）。落盘进同一 `traffic.json`，`TRAFFIC_CAP=43200`、空闲不 push、重启读回，全部复用不另起机制。
- 性能：分发循环是热路径，计数只做 HashMap entry +1（无锁化：沿用现有 conns/tick 的 60s 聚合模式——分发循环只做原子计数器累加，60s tick 再归集进结构，避免每包拿写锁）。

## 4. 采样日志（保持黑洞语义）

- 零回包不变，只在 server 侧记日志。
- 每 key 每 60s 最多 1 条 `warn!`（首包详情 + 本轮计数），平时保持 `debug!` 不变。正常 agent 误发几乎为 0，被打时日志自然刷屏告警，无需调日志级别。
- 实现：`HashMap<key, (last_warn_ts, count_since_warn)>`，纯内存不落盘，重启清零可接受。

## 5. egress 按目标细分

- `spawn_egress_dial` 处 conns 行 tunnel 从固定 `"egress"` 改成 `"egress/{host}:{port}"`（host/port 现成有，直接拼）。
- `traffic_key(hostname, tunnel)` 不动（拼的是 `agent/tunnel`），tick 聚合、落盘、裁剪全链路自动生效。
- 存量 `"egress"` 老 key 兼容读回（`upgrade_legacy_points` 不动，老点照样画线）；WebUI traffic 页天然按新 key 分开展示，零前端改动。
- 基数控制：host:port 组合来自 agent 请求，恶意 agent 可刷 key 膨胀——tick 侧加 cap：单 agent egress key 超 500 只保留 top（按量排序），超的归 `egress/other`。单测锁定。

## 6. WebUI + API

- `/api/traffic?tunnel=kudus_drop` 前缀过滤（现有 `tunnel=all` 旁加前缀匹配分支，10 行以内）。
- traffic 页加"黑洞丢包"区：按 reason 汇总（包数/秒 + 字节）+ top /24 表。复用现有 canvas/表格样式，不引入新图表库。
- egress 细分 key 自动出现在现有隧道下拉/图表中，无需额外 UI。

## 7. 测试

- 单测（纯函数，先红后绿）：
  1. /24 聚合：`v4 1.2.3.4 → 1.2.3.0/24`，`v6 → /64`，非法 addr 回退 `unknown`。
  2. 采样限流：同 key 60s 内第 2 包不打 warn，第 61s 打且计数正确。
  3. egress key cap：单 agent 600 个 key → 保留 top 500 + `egress/other` 有数。
  4. 老 key 兼容：`"egress"` 旧点读回不断崖（沿用现有 upgrade 路径加一条用例）。
- e2e：起 server + 发 100 个垃圾 UDP 包 → `/api/traffic?tunnel=kudus_drop` 能查到 `short` 计数。
- 验证：`make build` 零 warning + `make test` 全绿。

## 8. 不做

- 告警线/阈值（C 方案内容）：第一次被打无数据定阈值，跑一轮看数再定。
- 自动封 IP（iptables 联动）：误封风险，人工先看一轮再说。
- HyperLogLog 精确去重：capped HashSet 够用。
- 空闲补 0（图表断崖）：独立小改，不塞进本次。
