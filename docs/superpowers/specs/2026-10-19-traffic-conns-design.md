# WebUI 流量统计 + 当前连接列表 — 设计

日期：2026-10-19｜状态：设计已确认，待评审

## 1. 背景与目标

server WebUI 现只有总量（`rx/tx_bytes`）和事件日志，看不到“这分钟用了多少”、
“现在谁连着”。本设计加两块：

1. 流量统计：按 tunnel 明细 + agent 汇总（现有总量口径保留），分钟原始点，
   小时/天现算加总。
2. 当前连接列表：外部 ip:port → 公网端口 → tunnel/agent → 内网目标，外加时长与 rx/tx。

## 2. 数据结构（`Shared` 新增）

```rust
traffic: RwLock<HashMap<String, VecDeque<(u64,u64)>>>, // key = "hostname/proxy名"
conns: RwLock<HashMap<u64, ConnInfo>>,
public_port: u16, // --listen 解析出的端口，供 HTTP fallback 连接行使用
```

```rust
struct ConnInfo {
    id: u64, proto: ConnProto, // http | tcp | https | udp
    peer: SocketAddr,          // 外部 ip:port
    public_port: u16,          // 公网侧端口（http=listen 端口，其余=remote_port）
    agent: String,             // hostname
    tunnel: String,            // proxy name
    remote_port: u16,          // 独立端口；http 为 0
    target: String,            // "local_ip:local_port"
    since: i64,                // 本地 wall clock 秒
    rx: u64, tx: u64,
}
```

- agent 汇总不单独存：前端把所选 tunnel 相加（省一半存储）。
- `conns` 纯内存，断开即删，不落盘；上限 5000 条，超了挤掉最老的（单测锁死）。

## 3. 流量累计 / 切片 / 落盘

- 累计口径沿用现有 4 处 `h.info.rx/tx_bytes +=`（公网侧字节），不动。
- 新增 60s tick：每分钟读各 tunnel 累计值，增量 = 本次 − 上次，push 进
  `VecDeque`（tunnel 下线/空闲也记 `(0,0)`，不断点）。上限 43200 点（30 天）。
- 切片：分钟点按本地分钟对齐；`hour` 按 60 点求和，`day` 按 1440 点求和；
  `n` 限点数（默认 min 180 / hour 168 / day 31）。
- 落盘：独立 `traffic.json`（`{key: [[rx,tx],...]}` 裸数组），随 tick 每 60s 全量写；
  启动读回，无文件/坏文件从空开始 + `log_ev_err` 一条。`state.json` 不动。
- 进程 crash 最多丢 1 分钟；tunnel 删/改名后旧 key 自然滑出（30 天）。
- 体积：10 tunnel × 43200 点 × 16B ≈ 7MB 内存，JSON 约 10MB。

## 4. 连接列表采集

| 入口 | 连接键 | peer 来源 | 目标信息 | 移除时机 |
|---|---|---|---|---|
| HTTP fallback | `sid` | 加 `ConnectInfo<SocketAddr>` | aid + proxy.name + 内网目标 | 响应流结束/超时/断开 |
| TCP 独立端口 | `sid` | `accept()` 保留 peer（现为 `_`） | aid + proxy.name + remote_port | 双泵任一结束 |
| HTTPS 独立端口 | 同上 | 同上 | 同上（+SNI 如有） | 同上 |
| UDP session | `peer` 映射行 | `recv_from` 的 peer | aid + proxy.name + remote_port | 120s 无包过期（现有 `retain` 处删） |

- id 与现有 `next_sid()` 同源自增；UDP 用 peer 映射成一行，不每包一行。
- 每连接 rx/tx 在透传泵旁顺手 `+=`（现有累计点旁加 3 行，不改逻辑）。
- 速率前端算：两次 5s 轮询差分。后端只给快照。
- HTTP 短连接如实反映（每请求一行），表格按 `since` 倒序。

## 5. API

- `GET /api/traffic?tunnel=<key|all>&gran=min|hour|day&n=<N>` → `{"points": [[ts,rx,tx],...]}`，
  `tunnel=all` 即 agent 汇总由前端相加（或后端加总，二选一，默认前端）。
- `GET /api/conns` → `{"conns": [ConnInfo…]}` 快照。
- 均走现有 `auth_ok` 鉴权；失败语义与 `/api/logs` 一致。

## 6. 前端（`web/index.html`）

- 流量页：tunnel 下拉 + 分/时/天切换，纯 canvas 折线（不引入图表库）。
- 连接页：表格（外部 ip:port → 公网端口 → tunnel/agent → 内网目标 → 时长 → rx/tx），5s 轮询。
- 现有 overview/tunnels/logs 不动。

## 7. 测试（TDD）

- 单测：增量计算、hour/day 加总、`VecDeque` 裁剪 43200、坏 `traffic.json` 兜底、
  conns 上限 5000 挤占。
- e2e：打真实流量后查 `/api/traffic` 有点；建连后查 `/api/conns` 有行，
  断开后行消失。
- 回退验证：关掉累计/采集，上述测试必须变红。
- 完工标准：`make build`（零 warning）+ `make test`（单测+e2e）全绿。

## 8. 不做

- 速率后端计算、连接 kill 按钮、按天自动导出、WAL 增量落盘。
