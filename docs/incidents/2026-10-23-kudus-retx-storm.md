# 事故复盘：kudus 重传风暴（HK ↔ snail 互发数兆流量）

- **状态**：✅ 已修复（指数退避 + `KUDUS_RETX_CAP` + `KUDUS_MAX_RETX`；
  2026-10-25 `10fa13b` 又给快速重传加了每分钟硬闸 `FAST_RETX_PER_MIN`）
- **发生时间**：北京时间 2026-10-23 约 19:00 ~ 21:00（UTC 11:00 ~ 13:00；HK 为 UTC）
- **影响范围**：HK server + snail(minipc7s) agent 两端；不涉及公网对端
- **是否首次**：**不是**。同类事故已发生两次（前次症状为 HK 端内存失控，见 §5）
- **严重级别**：高（链路被打满，连带 frpc 无法建连，整机网络质量下降）

---

## 1. 现象

用户观感："HK 和 snail 两台机器互相在大量发数据，每秒几兆"。
但 transmission 面板的下载量远没有这么大 —— **下载量对不上总流量**，这是本次定位的关键线索。

### 1.1 HK server 侧日志（UTC，`journalctl -u neutrino-server`）

```
12:00 UTC 之后日志量从 ~60 条/分钟 暴涨到 500~730 条/分钟
```

限速统计单调爬升，**实测吞吐远超配置限速**：

```
concept: minipc7s/trans-bt  limit=524288B/s（=512KiB/s）
10:52Z thru=  899485B  sleep=  164ms
11:02Z thru= 1185012B  sleep=  632ms
11:37Z thru= 1273242B  sleep=  127ms
11:47Z thru= 2881564B  sleep=  259ms
11:52Z thru= 3727547B  sleep=  348ms
...    （单调爬升，无回落）
13:47Z thru=22396311B  sleep= 5204ms   ← 超限 42 倍，单次 sleep 5.2 秒
```

> `thru` 是 `RateLimiter::throttled_bytes` 累计值，`sleep` 是累计 sleep 毫秒。
> `sleep` 涨到 5204ms 是决定性异常：限速器要求的单块休眠已达数秒级，说明到达速率远超限速值。

### 1.2 snail 侧日志（CST，`journalctl _PID=<agent>`）

```
19:35:12  WARN kudus udp stream 2936 rejected: too many udp streams
19:00~21:30 期间共 3608 条 "too many udp streams"
```

> 这条告警涉及的 `KUDUS_MAX_UDP_STREAMS = 256` 槽位机制，
> 已单独成篇讨论：[2026-10-23-kudus-udp-stream-slots.md](./2026-10-23-kudus-udp-stream-slots.md)。
> （注：那个 256 是**流数**上限，与本文 §2 的背压阈值 256 **包**无关）

会话反复掉线重连（正反馈）：

```
19:08:39  WARN session ended; retry in 1s
19:09:12  WARN session ended; retry in 5s
19:10:42  WARN session ended; retry in 60s
...       （一直退避到 60s）
19:27:57  INFO kudus welcomed      ← 20 分钟后才恢复
```

### 1.3 连带伤害：整机网络质量

snail 网卡 `enp1s0`：

```
rx_dropped = 3,989,268      （近 400 万丢包，errors=0 → 纯队列满）
fq_codel: new_flow_count = 21,322,015  （2132 万个 flow）
          requeues       = 7,803,137
qdisc:  limit 10240p, drop_overlimit 0, maxpacket 68130
```

同时段 `frpc` **全程无法建连**（上行被占满）：

```
18:30:08  [W] connect to server error: connection write timeout
18:30:28  [I] try to connect to server...
18:30:38  [W] connect to server error: connection write timeout
...       （每 20s 一轮，持续数小时）
```

HK 侧 `kudus drop unknown_session` 来自 `116.236.246.0/24`、`120.204.103.0/24`
—— 正是 snail 的家庭出口 IP，证明 agent↔server 的 kudus 会话也在不停抖动。

---

## 2. 根因

**`RetxBuf`（kudus 重传缓冲）没有容量上限，配合固定 200ms 线性重传，产生自我放大。**
业务流量只有几百 KB/s，链路上跑的却是它的 5~40 倍，且**全是同一个包的重复拷贝**。

### 2.0 定性：三个独立缺陷叠加，不是单一 bug

> 注：本节及后文的 256 指「未确认数据包」阈值；
> 「UDP 流槽位 256」是另一个概念，见专题 [2026-10-23-kudus-udp-stream-slots.md](./2026-10-23-kudus-udp-stream-slots.md)。

直觉上容易归为"流量控制没做好"，但严格讲是**三层机制各自失效**，必须分开修：

| #   | 层次           | 缺陷                                      | 代码位置                                    |
| --- | -------------- | ----------------------------------------- | ------------------------------------------- |
| A   | **拥塞控制**   | **完全缺失**：固定 RTO、无退避、不响应丢包 | `kudus.rs:9` + `server/kudus.rs:363-395`    |
| B   | 流量控制       | **有机制但失效**：背压 30s 后放弃等待      | `server/kudus.rs:299-305` / `:336-342`      |
| C   | 资源管理       | **无界增长**：缓冲无上限、包永不丢弃       | `common/kudus.rs:112-127` / `:145-155`      |

#### A. 拥塞控制缺失（最根本）

流量控制与拥塞控制是两件事，这次缺的是后者：

|          | 解决什么           | 依赖信号               |
| -------- | ------------------ | ---------------------- |
| 流量控制 | 接收方处理不过来   | 接收方通告窗口         |
| 拥塞控制 | **网络本身传不动** | 丢包 / RTT 上升        |

本次场景正是拥塞：跨境 UDP 丢包 = 网络堵了。而实现是**固定 200ms 线性重传、无退避**：

```rust
pub const KUDUS_RTO: Duration = Duration::from_millis(200);  // 固定值，不随 RTT 调整
// 每个未确认包每 200ms 恒发一次 = 每秒 5 次，无指数退避、无最大重传次数
```

对比 TCP：丢包时 `RTO` 指数退避（200→400→800→1600…）+ 慢启动/快速重传。这里全没有。

结果：网络越堵 → 丢包越多 → 重传越多 → 网络更堵。
这是教科书级的 **拥塞崩溃（congestion collapse）**——1986 年互联网因此差点瘫掉，
才催生了 TCP 拥塞控制。

> kudus 是自研 UDP 可靠传输层（QUIC 简化版）。既然自己做可靠传输，
> 拥塞控制就是绕不开的成本——QUIC 的复杂度正来源于把 TCP 拥塞控制重做了一遍
> （CUBIC/BBR）。这里只做了"固定 RTO 重传"，**没有拥塞控制**。

#### B. 流量控制实现有洞

背压阈值 256 是对的，但 30 秒超时后**自己放弃**（详见 §2.3）：
不 drop、不 bail、不告警，继续灌入。流量控制在最需要时失效。

#### C. 资源无界增长

即使流量控制正确，`RetxBuf` 不设上限也致命（§5 的 929MB 内存峰值即此）。
属纯数据结构缺陷。

### 2.1 缺陷代码

`src/common/kudus.rs:112-127` —— 重传缓冲无界：

```rust
pub struct RetxBuf {
    next: u32,
    seqs: HashMap<u32, (Vec<u8>, u64)>,   // ← 无容量上限
}

impl RetxBuf {
    pub fn on_send(&mut self, payload: Vec<u8>) -> u32 {
        let s = self.next;
        self.next = self.next.wrapping_add(1);
        self.seqs.insert(s, (payload, now_ms()));   // ← 无条件插入，从不拒绝
        s
    }
```

`src/common/kudus.rs:145-155` —— 超时重传刷新计时，包永不死亡：

```rust
pub fn take_expired(&mut self, rto: Duration, now: u64) -> Vec<(u32, Vec<u8>)> {
    for (seq, (p, sent)) in self.seqs.iter_mut() {
        if now.wrapping_sub(*sent) >= rto.as_millis() as u64 {
            *sent = now;            // ← 刷新计时：包永远复活，永不被丢弃
            due.push((*seq, p.clone()));
        }
    }
```

`src/server/kudus.rs:363-395` —— 重传泵，RTO=200ms、50ms 扫一次：

```rust
let KUDUS_RTO = Duration::from_millis(200);     // src/common/kudus.rs:9
let mut iv = tokio::time::interval(Duration::from_millis(50));
loop {
    iv.tick().await;
    let due = guard.retx.take_expired(KUDUS_RTO, now_ms());
    for (seq, body) in due {
        txr.send_pkt(&h, &body);   // 原样重发，无次数上限
    }
}
```

### 2.2 放大倍数

每个未确认包 **每 200ms 重发一次 = 每秒重发 5 次**（KUDUS_DATA_CHUNK = 1000B）：

| retx 积压 | 纯重传流量 |
| --------- | ---------- |
| 256 包    | 1.22 MB/s  |
| 512 包    | 2.44 MB/s  |
| 2048 包   | 9.77 MB/s  |
| 8192 包   | 39.06 MB/s |

跨境 HK↔snail RTT 数十毫秒，ACK 一旦丢包或延迟，200ms 内就判定超时 → 重传 → 继续积压。
**实测 `thru=22396311B` 与 2048~4096 包积压的量级吻合。**

> **一个常被误会的点：不是"每轮翻倍"。**
> 重传不是把数量 10→20→40 翻倍，而是**同样的包每 200ms 被复制一次**（固定 5 次/秒）。
> 涨的是「缓冲里的包数」（新包不断进、清不掉），不是「单次发送量」。详见 §2.5。

### 2.3 为什么积压只增不减：背压有洞

`src/server/kudus.rs:299-305`（UDP 分支）与 `:336-342`（TCP 分支）同款缺陷：

```rust
for _ in 0..3000 {
    let n = relw.lock().map(|r| r.retx.len()).unwrap_or(0);
    if n < 256 { break; }
    tokio::time::sleep(Duration::from_millis(10)).await;
}
// ← 30 秒（3000 × 10ms）后退出，不 drop、不 bail、不告警，
//    继续 on_send 灌入重传缓冲
```

背压阈值 256，但 **30 秒超时后彻底失效**。写泵继续注入新包，
重传泵每 200ms 发 5 倍 → **积压单调增长 → 放大单调增长**，
正是日志里 `thru` 一路爬升、`sleep` 从 484ms 爬到 5204ms 的成因。

### 2.4 为什么"下载量对不上"

那几兆里绝大部分是**同一个包的反复重发**，不是新数据。
用户从 transmission 看到的下载量是真实业务量（几百 KB/s 级），
而 kudus 链路上跑的是业务量的 5~40 倍冗余。用户的直觉是正确的。

### 2.5 直白机制：“只进不出的仓库”

把 `RetxBuf` 想成一个仓库，数据进出如下：

- **写入侧（写泵）**：每来一块业务数据 → `on_send()` 塞进仓库，等 ACK 清出
- **重传侧（重传泵）**：每 200ms 扫一次 → 找出所有“超时未 ACK 的” → **全部原样重发**

平时仓库能正常清空（业务 ~几百 KB/s，清得掉）。一旦链路丢 ACK，仓库清不掉：

| 时刻 | 仓库积压 | 每 200ms 重发量 | 链路实际流量 |
| ---- | -------- | --------------- | ------------ |
| 0s   | 10 包    | 10 包           | 业务 100KB/s + 少量重传 |
| 1s   | 100 包   | 100 包          | 放大 5 倍    |
| 2s   | 200 包   | 200 包          | 放大 10 倍   |
| 5s   | 500 包   | 500 包          | 放大 25 倍   |

**放大倍数 ≈ 积压包数 × 每秒重发次数（5）**。
业务几百 KB/s × 几十倍 = 十几到二十几 MB/s，即实测的 `thru=22.4MB`。

两个让它**无法自愈**的致命点：

1. **仓库无容量上限**：`on_send` 从不检查有多满，无条件插入
   （本应的背压 §2.3 在 30s 后失效）。
2. **包永不丢弃**：`take_expired` 里 `*sent = now` 重发时刷新计时，
   包永远只是“再等 200ms”，从不会因“重传次数过多”被扔掉。

> 正常 TCP 的重传缓冲有窗口上限，满了就**停止接收新数据**等 ACK。
> 这里是“仓库无限大、货只进不出、每 5 秒把整个仓库搬一遍”。

### 2.6 准确的一句话定性

> 发出去的包没被确认就留在缓冲里；新包还在不停进来；缓冲没有上限；
> 重传又不知退避、还会刷新计时永不死；于是每 200ms 把整个越堆越大的缓冲全发一遍。

这正好解释了为什么 `thru` **单调爬升不回落** —— 缓冲只增不减。

---

## 3. 触发路径（为什么 BT 流量会走这条链路）

不是公网打爆。公网侧日志绝大多数是 `rx=68 tx=171`（68 字节 = BT 握手）就断开，
单 peer 流量极小。真正的放大器是 snail 上的配置：

transmission 容器 (`/config/settings.json`)：

```json
"proxy-url": "http://172.28.0.1:18080"
"peer-limit-global": 200
"dht-enabled": true, "pex-enabled": true, "utp-enabled": true
"port-forwarding-enabled": true
```

`172.28.0.1:18080` 即 neutrino agent 的 **egress HTTP 代理**
（日志：`egress http proxy on 172.28.0.1:18080`）。

于是每个 BT peer 连接都被拉成跨机往返：

```
transmission(172.28.0.10) → agent egress(172.28.0.1:18080)
  → kudus(跨境 UDP) → HK server → 拨号公网 peer
  → 回程同路径返回
```

`desired.toml` 同时开了两条 BT 隧道，进一步放大连接数：

```toml
[[agents.minipc7s]] name="trans-bt"      type="tcp" remote_port=51413 rate_limit="512k"
[[agents.minipc7s]] name="trans-bt-udp"  type="udp" remote_port=51413 rate_limit="512k"
```

叠加 DHT/PEX 持续发现新 peer（`KUDUS_MAX_UDP_STREAMS = 256` 被 DHT 扫描瞬间打满，
即 §1.2 那 3608 条 `too many udp streams`），连接数一多，
上述重传放大就被彻底点燃。

> 注意：`rate_limit="512k"` 本身没能拦住，因为限速作用在**限速器统计口径**上，
> 而重传放大发生在限速器**之后**的 `send_pkt` 路径 —— 重传包不过 `limiter.take()`。

---

## 4. 时间线（北京时间 CST）

| 时刻            | 事件                                                                 |
| --------------- | -------------------------------------------------------------------- |
| 18:30           | frpc 开始持续 `connection write timeout`，每 20s 重连                |
| 19:08:39        | snail agent `session ended; retry in 1s`，进入退避                    |
| 19:27:57        | `kudus welcomed`，会话短暂恢复                                        |
| 19:35:12        | 首次 `too many udp streams`，此后持续刷屏（至 21:30 共 3608 条）      |
| 20:00 左右      | HK 日志量跃升：~60/min → 500~730/min（UTC 12:00）                     |
| 全天            | HK 限速统计 `thru` 从 0.9MB 单调爬到 22.4MB，`sleep` 爬到 5204ms      |
| 21:53（UTC 13:53）| HK `systemctl stop neutrino-server`，服务停止（至今 inactive）       |

---

## 5. 这不是第一次：前次事故证据

HK 上 `neutrino-server` 在 7 天内 **重启 1527 次**（正常服务不应如此）。
其中一次的内存峰值暴露了同一 bug 的另一个症状：

```
Oct 22 01:32:56  Consumed 1h 13min 23.236s CPU time,
                 929.4M memory peak, 921.2M memory swap peak
```

`RetxBuf.seqs` 是 `HashMap<u32, (Vec<u8>, u64)>`，**无界增长，每个未确认包一份 payload 拷贝**。
积压到几十万包时内存就是几百 MB —— 这就是 929MB 峰值的来源。

**同一 bug 的两个症状：流量放大（本次）+ 内存爆炸（上次）。**

---

## 6. 待修复项（按 TDD，先写红用例）

按 §2.0 的三层缺陷分组，**三项都应修**（只修一项无法止血）。

### A. 拥塞控制缺失（最根本）

| #   | 修复项                                        | 优先级 |
| --- | --------------------------------------------- | ------ |
| A1  | RTO 指数退避：200→400→800→…，封顶（如 2s）    | 高     |
| A2  | 最大重传次数（如 10 次）后拆流并 `warn!`       | 高     |
| A3  | （后续）RTT 自适应 RTO（Jacobson/Karels）     | 中     |
| A4  | （远期）真实现拥塞控制（CUBIC/BBR），非一行改 | 低     |

> A1+A2 是止血级；A3/A4 是协议层完善，可另开任务。

### B. 流量控制实现有洞

| #   | 修复项                                                     |
| --- | ---------------------------------------------------------- |
| B1  | 背压等 30s 等不到 ACK：`bail!` 拆会话 + `warn!`，不继续发 |
| B2  | 背压超时改为可配，且必须有可观测告警（现在静默放弃）       |

### C. 资源无界增长

| #   | 修复项                                                                         |
| --- | ------------------------------------------------------------------------------ |
| C1  | `RetxBuf` 加容量上限，超限拒绝 `on_send`（返回 `Option<u32>`）或丢最老包      |
| C2  | `take_expired` 累计重传次数，超阈值丢弃该包（不再刷新计时无限复活）            |

### D. 可观测性（防止下次靠事后复盘才能发现）

| #   | 修复项                                                                 |
| --- | ---------------------------------------------------------------------- |
| D1  | `thru > limit * N` 时 `warn!`（本次若有此告警，第一分钟就能发现）      |
| D2  | `ratelimit stats` 区分「首次发送字节」与「重传字节」                  |
| D3  | `retx` 积压深度（`RetxBuf::len()`）纳入周期日得                         |
| D4  | `too many udp streams` 采样限流（3608 条同质 warn 洗了日志）           |

### 对应单测（先写红）

- **C1**：连续 `on_send` N 次（N >> 上限）断言 `len() <= 上限`；当前代码必红。
- **C2**：同一包反复 `take_expired` 超 N 次后应不再返回；当前代码必红（`*sent = now` 永不死）。
- **A1**：模拟持续未 ACK，断言相邻两次重传间隔递增；当前固定 200ms 必红。
- **B1**：模拟 retx 恒定不降，断言有限时间内返回错误而非继续 `on_send`；当前必红。

> 验证：`make build`（`-D warnings`）+ `make test` 全绿；
> 修复前临时回退，对应测试必须变红。

---

## 7. 复现与验证要点

- 单测可完全覆盖 §2.1/2.2/2.3 的纯函数部分（`RetxBuf::on_send` / `take_expired`），无需网络。
- e2e 复现放大：故意让 agent 侧不 ACK（如丢弃下行 ACK），
  断言 server 侧重传速率有上界（`<= limit * k`），当前代码会远超。
- 验证修复：`make build`（`-D warnings`）+ `make test` 全绿；
  修复前临时回退，测试必须变红。

---

## 8. 临时止血（若再次发生）

1. `desired.toml` 里 `trans-bt-udp` 设 `enabled=false`（文件内注释已预留此预案）
2. 必要时 `trans-bt` 也关掉，切断 BT → egress → kudus 的放大路径
3. 移除 transmission 的 `proxy-url`，让 BT 走家庭直连，不再经 kudus
4. 观察指标：HK `ratelimit stats` 的 `thru`/`sleep` 是否回落、snail `rx_dropped` 是否停止增长

---

## 附：证据采集命令

```bash
# HK 侧（UTC）：限速统计
journalctl -u neutrino-server --since "<T>" --until "<T>" | grep "ratelimit stats"

# HK 侧：日志量按分钟分布，定位跃升点
journalctl -u neutrino-server --since "<T>" --until "<T>" -o short-iso | cut -c1-16 | sort | uniq -c | sort -rn

# snail 侧：udp 槽位打满
journalctl _PID=<agent_pid> --since "<T>" --until "<T>" | grep -c "too many udp streams"

# snail 侧：网卡丢包 / fq_codel flow 数
cat /sys/class/net/enp1s0/statistics/rx_dropped
tc -s qdisc show dev enp1s0
```
