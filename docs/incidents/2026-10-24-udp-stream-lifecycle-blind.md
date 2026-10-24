# 专题：UDP 流生命周期 / 丢包全静默 + idle 超时硬编码

- **状态**：日志已修（本 PR）；`--udp-idle-secs` 已可配（本 PR）
- **关联**：
  - [2026-10-23-kudus-retx-storm.md](./2026-10-23-kudus-retx-storm.md)（主事故）
  - [2026-10-23-kudus-udp-stream-slots.md](./2026-10-23-kudus-udp-stream-slots.md)（UDP fd 槽位）
  - [2026-10-24-tunnel-stats-udp-gap.md](./2026-10-24-tunnel-stats-udp-gap.md)（tunnel_stats 埋点盲区）
- **发现途径**：2026-10-24 部署验证中用户追问"5 秒够不够"——想回答时发现**根本无数据可查**
- **性质**：可观测性盲区 + 运维不可调；不直接致命，但让"5 秒够不够"这类问题只能靠猜

## 结论速览（TL;DR）

用户问"agent 侧 5s idle 够不够"，我去查数据，发现**回答不了**：

| 想知道的事 | 有没有日志 | 结论 |
| --- | --- | --- |
| 每条流活了多久 | ❌ 无 | 无法判断是否 5s 卡点断开 |
| 每条流双向收发了多少包 | ❌ 无 | 无法区分"空跑"和"真传数据" |
| 流为什么结束（idle/对端关/出错） | ❌ 无 | 只有笼统 `Close{reason:"eof"}` |
| 本地 socket 收包出错 | ❌ 静默 | `Ok(0) \| Err(_) => break` |
| 送包给本地目标失败 | ❌ 静默 | `.is_err() { return; }` |
| 池实时占用 / 踢流次数 | ❌ 无 | `evicted_total` 有累加但从不输出 |
| 除了"每分钟全局 sent/abandoned" | ✅ 有 | 但只有总数，无流向、无原因 |

而且 `UDP_STREAM_IDLE_SECS` 是**编译期常量**：运维在现场发现 5s 不合适，
除了重新发一版二进制没有别的办法。

---

## 1. 现场：能看见"丢了 8 个包"，看不见"谁的、为什么"

2026-10-24 本机 agent（`minipc7s`）→ HK server 真实 BT 隧道打流，agent 日志每分钟一行：

```
kudus retx session=a9ed89ca hostname=minipc7s sent=90~156 abandoned=8~16 full=0 backlog_max=8~14
```

同时 `ss` 观察：

```
HK 侧:      56 条 trans-bt-udp 会话
agent 侧:   仅 5 条 UDP socket 连到 172.28.0.10:51413
链路:       200 包 ping → 11% loss, rtt avg 37ms
```

**能得到的推论只有"有丢包"**，但下面这些全都不知道：

- 是链路丢的，还是本地 socket 收不下（`UDP_RECV_BUF=2048`）丢的？
- 是 DHT 短查询断的，还是 uTP 长连接被 5s idle 掐的？
- 56 条会话里，有多少条**根本没活到建 socket**？
- `abandoned=8~16` 是集中在某几条流，还是均匀分布？

**这就是为什么"5 秒够不够"回答不了**——缺的不是推理能力，是数据。

---

## 2. 根因：两个泵的失败分支全静默

`src/agent/kudus_session.rs::open_udp_stream_to` 里，ws→udp 与 udp→ws 两个泵：

```rust
// ws → udp（下行）
match tokio::time::timeout(Duration::from_secs(UDP_STREAM_IDLE_SECS), drx.recv()).await {
    Ok(Some(dg)) => {
        if w.send(&dg).await.is_err() {
            return;                      // ← 静默返回，一行日志都没有
        }
    }
    _ => break,                          // ← idle 超时 / 通道关闭 混在一起，不可区分
}

// udp → ws（上行）
match r.recv(&mut b).await {
    Ok(0) | Err(_) => break,             // ← 对端关闭 与 真错误 混在一起，静默
    Ok(n) => { /* ... */ }
}
```

三个问题叠加：

1. **`Err(_)` 被吞**：`ECONNREFUSED`（本地 transmission 没监听）、`ENOBUFS`（内核缓冲满，
   正是 `SO_RCVBUF` 钳 64KB 的后果）都表现为"流莫名其妙没了"。
2. **原因不可区分**：`_ => break` 同时覆盖 idle 超时和 `drx` 关闭，事后无法判断是哪条路径。
3. **无存活时长/包数**：`UdpStreamStat` 之类的东西完全不存在，收尾时没有任何输出。

池侧同样有账不报：

```rust
pub struct UdpPool {
    evicted_total: u64,   // 累加了，但从来没有地方读它
    // ...
}
```

---

## 3. 连带问题：`UDP_STREAM_IDLE_SECS` 是编译期常量

```rust
const UDP_STREAM_IDLE_SECS: u64 = 5;   // 想改？重编两端。
```

而"5s 够不够"的答案**取决于现场**：跨境 11% 丢包 + BT uTP 的静默期，与内网 0% 丢包
的 HTTP 隧道完全是两回事。把它写死意味着运维每次都得：

1. 改代码 → 2. 编译 → 3. 两端一起部署 → 4. 观测 → 5. 不合适再回到 1

server 侧早有 `--udp-session-ttl` 可配，**agent 侧却没有对应开关**，是纯粹的不对称。

---

## 4. 修法（本 PR 已实现）

### 4.1 流级日志：一行说清"活了多久、传了多少、为什么断"

新增 `UdpStreamStat`（原子计数，两泵各写一半），流结束统一打一行：

```
kudus udp stream closed sid=123 lived=5.02s reason=idle-timeout
  rx_pkts=3 rx_bytes=180 tx_pkts=0 tx_bytes=0 truncated=0 pool=12/64 evicted=0
```

**这行的判读方式**（直接回答"5s 够不够"）：

| `lived` | `reason` | 含义 |
| --- | --- | --- |
| ≈ idle 秒数（如 5.00s） | `idle-timeout` | **卡在 idle 边界 → 5s 确实太短**，应放宽 |
| 远小于 idle（<1s） | `recv-err` / `send-err` | 本地目标/内核出错，与 idle 无关 |
| 任意 | `server-close` | server 主动关（正常 TTL 回收） |
| 任意 | `local-eof` | 本地 transmission 关了 socket |

`reason` 取值：`idle-timeout` / `server-close` / `send-err` / `recv-err` / `local-eof` / `running`。

同时补齐两处静默失败：

```rust
Err(e) => {                                    // udp→ws
    stat.end.store(END_RECV_ERR, ..);
    tracing::warn!("kudus udp local->ws recv failed: sid={sid} err={e}");
    break;
}
if let Err(e) = w.send(&dg).await {            // ws→udp
    stat.end.store(END_SEND_ERR, ..);
    tracing::warn!("kudus udp ws->local send failed: sid={sid} err={e} (rx_pkts={n})");
    return;
}
```

截断计数也进了统计（`truncated=`），不再只靠 warn 的频次猜。

### 4.2 池状态进日志

```rust
impl UdpPool {
    pub fn summary(&self) -> String {
        format!("{}/{} evicted={}", self.in_use.len(), self.created, self.evicted_total)
    }
}
```

`pool=12/64 evicted=0` 的判读：

- `in_use/created`：当前占用 / 历史最大并发。
- **真正的硬顶不是 `POOL_MAX=512`，而是内核 `SO_RCVBUF`（实测并发 ≈137）**，
  所以 `in_use` 涨到 100+ 就该警惕，不必等到 512。
- `evicted` 涨 = 已在踢 LRU，说明并发超顶、有流被牺牲。

### 4.3 `--udp-idle-secs` 可配（默认 5，0=默认）

```bash
neutrino agent --server kudus://hk:36182 --config agent.toml --udp-idle-secs 60
```

解析抽成无 IO 纯函数便于单测：

```rust
pub(crate) fn resolve_udp_idle_secs(cli: u64) -> u64 {
    if cli == 0 { UDP_STREAM_IDLE_SECS } else { cli }
}
```

**为什么 0 要回退默认而不是当真**：`Duration::from_secs(0)` 会让所有流立刻超时（瞬杀全部 UDP）
或永不超时（泄 fd，正是 [retx-storm 事故](./2026-10-23-kudus-retx-storm.md) 的旧病根）。
误配的代价太高，`0` 一律当"没传"。

---

## 5. 验证

| 项 | 结果 |
| --- | --- |
| `make build`（`-D warnings`） | ✅ 零 warning |
| `cargo test --bin neutrino` | ✅ **180 passed**（新增 2：`udp_stream_stat_reason_names`、`udp_pool_summary_counts_in_use_and_evicted`、`udp_idle_secs_resolves_cli_override`） |
| `cargo test --test e2e -- --test-threads=1` | ✅ 40 passed |
| 回退验证（`resolve_udp_idle_secs` 去掉 0 回退） | ✅ 变红：`left: 0, right: 5` |

> 注：`cargo test` 带 `RUSTFLAGS="-D warnings"` 会在 `src/common/kudus.rs` 报既存
> `unused Result`（3 处，与本次改动无关）；`make build`/`make test` 不受影响。

---

## 6. 待办：用真实数据回答"5s 够不够"

日志上线后需要**实测一轮**，把 `lived` 分布统计出来：

```bash
# 1) agent 开 debug（流级日志是 debug 级，量大）
RUST_LOG=neutrino=debug ./neutrino agent ... --udp-idle-secs 60

# 2) 跑一段真实 BT 流量，抓流收尾行
grep "udp stream closed" /tmp/agent.log \
  | sed -n 's/.*lived=\([0-9.]*\)s reason=\([a-z-]*\).*/\2 \1/p' \
  | awk '{sum[$1]++; if ($2 > max[$1]) max[$1]=$2} END {for (r in sum) print r, "n="sum[r], "max_lived="max[r]"s"}'
```

**判据**：

- 若 `idle-timeout` 的 `lived` 大量落在 5.0~5.1s 且 `rx_pkts` 很小 → 会话是"建了没用就超时"，
  说明 5s 只是回收垃圾，**不必放宽**（放宽反而多占 fd）。
- 若 `idle-timeout` 的 `lived` 卡在 5.0s 但 `rx_pkts` 有量、且之后同一对端反复建流 →
  **真长连接被掐**，应放宽到 30~60s。
- 若 `recv-err` 占比高 → 与 idle 无关，去查本地 transmission / `SO_RCVBUF`。

---

## 7. 教训

1. **"能不能回答运维的追问"是日志的验收标准。** 这次不是不知道要打什么，而是
   "每分钟一行全局数字"看起来已经够了——直到有人问"5 秒够不够"才发现答不上来。
   好的日志应该让**下一个问题**也能被回答。
2. **`match ... { Ok(0) | Err(_) => break }` 是静默事故的标准写法。**
   把"对端正常关闭"和"真错误"合并到一个分支，等于主动放弃了区分能力。
   收包/发包失败至少 warn + 带 sid。
3. **凡是运维可能要调的阈值，都别写死成常量。** server 侧早有 `--udp-session-ttl`，
   agent 侧没有 `--udp-idle-secs` —— 不对称本身就是缺陷信号。
4. **`0` 含义必须明确定义。** `Duration::from_secs(0)` 在超时语义下是灾难值
   （瞬杀 / 永不超时），把它定义为"未传 → 回退默认"并用单测锁死。
5. **池里的账要有人读。** `evicted_total` 一直在累加却从不输出，等于没埋。
