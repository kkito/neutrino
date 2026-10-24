# 专题：kudus UDP 流槽位（`KUDUS_MAX_UDP_STREAMS = 256`）

- **状态**：机制已澄清，设计方案已论证可行（待实现）
- **关联**：[2026-10-23-kudus-retx-storm.md](./2026-10-23-kudus-retx-storm.md)
- **起因**：复盘主事故时的疑问 —— "我只起了一个 UDP 端口，接收 UDP 只要一个 socket 就够，
  为什么会有 256 个？是不是 TCP/UDP 没分开？"

## 结论速览（TL;DR）

**三层模型可行**（详见 §4.5）：

| 环节 | 目标 | 现状 | 结论 |
| ---- | ---- | ---- | ---- |
| ① 入口端口 | 1 个 socket | ✅ 已是 1 个 | 可行 |
| ② 隧道 | 1 条连接 + 会话 ID | ✅ 已是 1 条 | 可行 |
| ③ 出口到目标 | 多个但廉价 | ⚠️ 256 × 64KB，不廉价 | 池化可做 |

关键认知：

- **256 不是 buffer、不是集合，是 agent 侧出站 socket 的 fd 配额**（信号量）
- **kudus 隧道只有 1 条连接**，不是每 peer 一条（`udp_outbox` 按 hostname 复用）
- **出口必须多 socket 是 UDP 语义强制**：回包不带会话 ID，只能靠源端口区分
- **推荐模型 B**：固定 socket 池（如 64）+ LRU 复用 + 端口反查 sid
- 代价：池满时长连接会被踢——固定池的固有取舍

---

## 1. 先把三个"256"分清楚

代码里有 **三个不同**的 256，极易看混：

| 常量 / 字面量                | 值  | 是什么                        | 类型        | 位置                                  |
| ---------------------------- | --- | ----------------------------- | ----------- | ------------------------------------- |
| `KUDUS_MAX_UDP_STREAMS`      | 256 | **并发 UDP 流条数**上限       | `Semaphore` | `agent/kudus_session.rs:25`           |
| 背压阈值（裸字面量）         | 256 | **未确认数据包个数**上限      | 数字比较    | `server/kudus.rs:301` / `:338`        |
| `KUDUS_SACK_BITS`            | 256 | SACK bitmap **位数**          | 位宽        | `common/kudus.rs:171`                 |

本文只讨论第一个：`KUDUS_MAX_UDP_STREAMS`。

### 它是什么：信号量，不是缓冲区、不是集合

```rust
// agent/kudus_session.rs:24-25
/// 单 agent UDP egress 最大并发（udp + link_udp 共用）。256 fd 预留给 TCP/控制面。
pub(crate) const KUDUS_MAX_UDP_STREAMS: usize = 256;

// :242
udp_slots: Arc::new(tokio::sync::Semaphore::new(KUDUS_MAX_UDP_STREAMS)),
```

所以它既不是 buffer 也不是 collection，**是并发许可（permit）计数器**。
它本身不存数据，只回答"现在还能不能开新流"。

---

## 2. "一个 UDP 端口" vs "256 条流"

### 2.0 先分清三张网（讨论后澄清的关键）

“agent 和 HK 之间是不是建了多条连接” —— **不是。** 三层资源完全不同：

| 层次 | 资源 | 数量 | 依据 |
| ---- | ---- | ---- | ---- |
| ① HK 监听接收 | `UdpSocket` on `0.0.0.0:{port}` | **1 个** | `server/ingress.rs` `udp ingress on` |
| ② HK↔agent 隧道 | kudus UDP 连接 | **1 条** | `server/kudus.rs:700` 1 个 bind；agent `kudus_session.rs:185-186` 1 次 connect |
| ③ agent→内网目标 | 出站 `UdpSocket` | **每 sid 1 个（上限 256）** | `kudus_session.rs:740-741` |

**决定性证据：kudus 隧道本来就是复用的。** 下行通道的 key 是 **hostname**，不是 sid：

```rust
// server/state.rs:55
udp_outbox: RwLock<HashMap<String, mpsc::UnboundedSender<(u32, Vec<u8>)>>>,
//                            ↑ hostname           ↑ 帧里带 sid
```

所有 sid 的 UDP 数据都塞进同一个 sender，走同一条 kudus 连接。

于是完整数据路径：

```
公网 peer                HK server           ← kudus 1 条 →          agent          transmission
   │                        │                                       │                  │
   ├─ UDP 包 ──────────────→│ bind 51413（1 个 socket）            │                  │
   │                        │ 查 sessions 表（peer→sid）            │                  │
   │                        ├─ (sid, 数据) ───────────────────────→│                  │
   │                        │                                       ├─ socket#1 ──────→│ ← 256 个之一是它
   │                        │←──────── (sid, 回包) ─────────────────┤←───── 回包 ─────┤
   │←────── 发回 peer ──────┤ 查 sid→peer                           │                  │
```

**结论：256 管的是 ③，不是 ①也不是 ②。**
`KUDUS_MAX_UDP_STREAMS` 注释中的 "UDP egress" 也确认了它是出站侧。

> 一个常见误解：以为每条流在 kudus 里占一个连接，于是 DHT 几千 peer
> 就会建几千条隧道连接——**实际不会**，隧道只有 1 条，复用得很好。
> 真正爆掉的是 agent 内网侧的出站 socket 配额。

### 2.1 澄清：接收端口确实只有一个

疑问的出发点完全正确。`server` 侧对每个 `remote_port` 只 bind 一个 socket，
且读包 buf 也全进程只一份（`let mut buf = vec![0u8; 65535]`，`recv_from` 反复复用）：

```rust
// server/ingress.rs
tracing::info!("udp ingress on 0.0.0.0:{port}");
```

**所以“256 个 64KB buffer”并不存在。** 256 与接收端无关。

### 2.2 256 是 agent 侧的**出站 socket** 数量

关键在 `agent/kudus_session.rs:729-743`：

```rust
async fn open_udp_stream(ctx: Arc<KCtx>, pkt: Pkt, sid: u32, port: u16) -> Result<()> {
    let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;  // ← 每条流新 bind 一个 socket
    sock.connect((p.local_ip, p.local_port)).await?;             // ← 连到内网目标
    open_udp_stream_to(ctx, pkt, sid, sock).await
}
```

**每来一条新的 UDP 流（新 `sid`），agent 就新 bind 一个 socket**，
并有 `open_udp_stream_to` 里成对的 2 个 tokio task（上行泵 + 下行泵）。

所以开销单位是：**1 条流 = 1 个 socket(fd) + 2 个 task + 1 个信号量槽位**。

> **注意：256 不是“256 个 64KB buffer”。**
> 真正成本是 **fd** 与内核 skb 缓冲（每个 `UdpSocket` 默认 rmem/wmem 约 208KB，256 个约 52MB），
> 而非应用层 buffer。所以“调大到 4096”不可行（≈800MB 内核缓冲 + 4096 fd），
> 想支持更多 peer 必须换模型（见 §4），不是改大常量。

### 2.3 为什么现在的实现要为每个 sid 建 socket

UDP 无连接，但隧道多路复用，必须能区分“这个包属于哪个请求者”。
于是引入 `sid`（stream id）作为逻辑通道标识：

```
公网 BT peer X 发来 UDP 包
  → server sessions 表查 peer X 的 SocketAddr 是否已有 sid
  → 无 → next_sid() 分配新 sid，发 ServerMsg::Open { stream: sid, kind: "udp", port }
  → 隧道发给 agent
  → agent 为 sid 新建 socket → 转发给内网 transmission
  → 该 peer 后续包全走同一条流
  → TTL 到期 → server 发 Close → agent 回收 socket + 槽位
```

server 侧 session 表的 key 是 **peer 的 `SocketAddr`**（`server/ingress.rs:802`）：

```rust
// peer -> (stream_id, last_seen, 下行 sender, limiter, ctl)
let mut sessions: HashMap<SocketAddr, (u32, Instant, ...)> = HashMap::new();
```

**换句话说：一个公网 peer = 一条流 = agent 侧一个 socket。**

**为何必须一 sid 一 socket（而不是共用）：** agent 向 transmission 发完包后，
transmission 的回包源地址永远是同一个（`172.28.0.10:51413`），
若所有 peer 共用 socket，agent 收到回包时无法判断该回给哪个 sid。
`connect()` 后 socket 只收该目标回包，但**仍靠各自的本地源端口**让 transmission 区分上下文——
这就是“一 sid 一 socket”的真实动机：**用源端口给 UDP 回包做归属标记**。

> 这是 UDP 本身的限制：回包不带会话标识，只能靠源端口区分。
> 所以想省掉这 256 个 socket，必须解决“回包归属”问题（见 §4）。

### 2.4 所以“256 个”从哪来

因为 **peer 多**，不是因为端口多。

BT 的 DHT 扫描特征：**大量不同源端口/IP，每个只发一两个 UDP 包就走**。
每个新 `SocketAddr` 都开一条新流，于是：

```
短时间 3000+ 个 peer → 256 个槽位瞬间占满
→ 后续全部 try_acquire_owned() 失败
→ WARN kudus udp stream 2936 rejected: too many udp streams
```

这正是主事故里 3608 条该 warn 的来源（`sid=2936` 说明流 id 已涨到近 3000）。

---

## 3. TCP / UDP 到底分开了没有

分两个层面回答，结论不同 —— 这也是原疑问的核心。

### 3.1 传输路径：已完全分开（正确）

|              | TCP                       | UDP                              |
| ------------ | ------------------------- | -------------------------------- |
| 函数         | `open_tcp_stream`         | `open_udp_stream`                |
| 流的语义     | 一个 TCP 连接 = 一条流    | 一个 sid = 一条流                |
| socket 时机  | 连接时 1 个，全程复用     | 每条流 1 个                      |
| 回收依据     | 连接关闭                  | `UDP_STREAM_IDLE_SECS = 30` 空闲 |
| 下行通道     | `outbox`                  | `udp_outbox`（整包分片，保边界） |

分离是**必要且正确**的：TCP 有连接语义，UDP 没有，混在一起无法保证包边界
（`ingress.rs:858-859` 注释已记录这个坑：旧代码一律走 `outbox`，被 kudus 写泵按 TCP 切片拆碎，
1500B 包变 2 个残包 → 无声 corrupt）。

> "因为 TCP 的原因才需要分开" —— 这个直觉是对的。

### 3.2 资源配额：**没分开**（缺陷）

```rust
/// 单 agent UDP egress 最大并发（udp + link_udp 共用）。256 fd 预留给 TCP/控制面。
```

**`udp`（BT 隧道）与 `link_udp`（link 通道）共用同一个 256 信号量。**

后果：BT 的 DHT 扫描打满槽位 → `link_udp` 也拿不到许可 → **一个业务把另一个业务饿死**。
这是**资源池耦合**问题：两条优先级、用途、流量特征完全不同的通道抢同一配额。

---

## 4. 更深一层的设计质疑：DHT 该不该建持久流

即使修好配额解耦，仍有更根本的问题：

**DHT 扫描产出几千条一次性流，每条只为转发一两个 UDP 包，
却要付出「新建 socket + 2 个 task + 1 个槽位 + 会话表项 + TTL 管理」的全套成本。**

对比正常做法：UDP NAT 网关通常是**无状态转发** —— 收包、查表、转发、走人，不建流。

当前实现在“UDP 也要可靠传输/保序/多路复用”的模型里套一次性流量，
等于用租约模型处理短工单，成本与流量特征严重错配。

代价可量化：

| 观察点                       | 数值                      |
| ---------------------------- | ------------------------- |
| 单流资源                     | 1 fd + 2 task + 1 permit  |
| DHT 期间流创建速率           | 分钟级数百条              |
| 打满后行为                   | 全部拒绝（`too many udp streams`） |
| 连带                         | `link_udp` 共用配额被饿死 |

### 4.1 讨论结论：理想模型（NAT 表 + 一条管道）

讨论中提出一个更自然的模型：**sid 只标识“公网 peer”，不标识“socket”**。

```
① 公网 peer(1.2.3.4:5678) 发包到 HK:51413
   → 查 NAT 表：(1.2.3.4:5678) 有吗？
     无 → 分配 sid=100，记下 sid ↔ (1.2.3.4:5678)
   → 隧道只传 (sid, 数据)

② agent 收 (sid=100, 数据) → 经一条管道发给 transmission:51413

③ transmission 回包 → agent 打上 sid=100 传回隧道

④ HK 收 (sid=100, 回包) → 查 NAT 表得 (1.2.3.4:5678) → 发回公网
```

这个模型下：

- **kudus 层不需改动**（本来就只用 1 条连接，`udp_outbox` 按 hostname 复用）
- agent 侧变成 **1 个 socket**，而不是 256 个
- `KUDUS_MAX_UDP_STREAMS` 限的不再是 socket，而是 **NAT 表条目**——
  每条只是内存里几十字节，上限可提到 4096 甚至几万，不再是 fd 瓶颈

### 4.2 唯一的卡点：UDP 回包归属

上述③里“agent 打上 sid=100”—— **这个 sid 从何而来，是全部难点所在。**

transmission 是标准 BT 客户端，不知道 neutrino 的 sid，**不可能在回包里带 sid**。
而 UDP 回包的源地址永远是同一个（`172.28.0.10:51413`），
所以 agent 收到回包时，**仅凭包内容无法判断它属于哪个 peer**。

现有实现用“一 sid 一 socket”绕开：不同源端口 → transmission 区分上下文 → 回到不同端口。
这也是 NAT 设备的经典做法，**代价就是 fd**。

| 方案 | 做法 | 结果 |
| ---- | ---- | ---- |
| A. 一 sid 一 socket（现状） | 靠源端口区分回包 | 正确，但 256 fd 上限 |
| B. 共享 socket + 时序匹配 | 记“最近转发给目标的 sid”，回包归它 | DHT（一问一答）可行；uTP 并发多 peer 会串包 |
| C. 共享 socket + 内容关联 | 用 DHT transaction ID 等协议层字段关联 | 依赖具体协议，不通用 |

**结论：这不是“设计者没想到”，而是 UDP 无连接语义下的真实约束。**
想省 fd，只能在 B/C 里选，且需先确认流量特征。

### 4.3 待确认前提

51413 上到底跑什么，决定 B 是否成立：

- **主要是 DHT**（一问一答、时序严格）→ 方案 B 可行，能大幅简化
- **有 uTP 并发多 peer** → 必须能区分回包归属，绕不开 A

> 本节仅记录设计分析，**未改任何代码**。

---

### 4.4 具体优化项（讨论产出，待实现）

聚焦「agent ↔ 内网目标」这一层，三个独立可做的优化。
两两正交，可分开实施。

### 优化 1：接收 buffer 65535 → 2048（零风险）

**现状**（`agent/kudus_session.rs:701`）：

```rust
let udp_to_ws = tokio::spawn(async move {
    let mut b = vec![0u8; 65535];   // ← 每条 udp 流一个 64KB 堆缓冲
    loop {
        match r.recv(&mut b).await { ... }
    }
});
```

**问题**：每条流 64KB，256 流 = **16 MB 堆内存**（与内核 skb 是两笔账）。

**为何没必要这么大**：

- 上行数据来自隧道，隧道有硬上限 `KUDUS_UDP_MAX = 1232`（`common/kudus.rs:169`）
- 回包实际受 MTU 约束，BT/DHT 包 ≤ 1500
- 2048 留足余量

| buffer | 256 流总堆内存 |
| ------ | -------------- |
| 65535  | **16 MB**      |
| 2048   | **0.5 MB**     |

与优化 2 叠加后（64 socket）：64 × 2048 = **128 KB**。

**风险**：无。改动为抽常量 + 改数值。

### 优化 2：socket 池 + LRU 复用（fd 封顶）

**核心思路**：不要求「1 sid = 1 socket 生命周期」，只要求
「回包到达时有一个源端口能反查 sid」。于是 socket 可做成固定大小池子轮转复用：

```
池内 64 个 socket，各绑不同源端口（40001~40064）
sid=100 用 socket#1  → 映射表：40001 → sid 100
sid=101 用 socket#2  → 映射表：40002 → sid 101
...
sid=164 用 socket#1  → 40001 → sid 164   ← 复用，踢掉最久未用

回包到 40001 → 查表 → 当前持有者 sid 164
```

**效果对比**：

| 维度           | 现状                  | 池化后               |
| -------------- | --------------------- | -------------------- |
| fd 数量        | 撞 256 就全拒         | 固定 64，永不爆      |
| 支持并发 peer  | ≤256                  | 无上限（受 NAT 表条目） |
| 回包归属正确性 | ✅ 靠源端口           | ✅ 不变              |
| 打满行为       | **新 peer 全断**      | 踢最久未用，新 peer 总能进 |
| task 数        | 2×256 = 512           | 64（每池 socket 1 个常驻 recv） |

**实现要点**：

```
1. SocketPool：预建 N 个 socket，各自 bind(0.0.0.0:0) + connect(目标)
   记录本地端口
2. sid 分配时从池取 LRU 最久未用的一个
   更新映射：local_port → sid；被踢的旧 sid 发 Close
3. 每个池 socket 只需 1 个常驻 recv 任务
   收包 → 查 local_port → sid → 回传隧道
4. 上行：隧道来 (sid, 数据) → 查 sid → 对应池 socket → send
```

**参数建议**：池大小 64，可配（`--udp-socket-pool 64`）。

**已知限制**：池满时被踢的 sid 会断。对 DHT 无感（一问一答早已结束），
对 uTP 长连接会重连——若要彻底避免，需按流量类型分独立配额（依赖 4.3 结论）。

> 注意：不能靠 `SO_REUSEPORT` 多 socket 共享一个端口——内核对 UDP 是哈希分流，
> 不按 sid 分，做不到回包归属。

### 优化 3：DHT 收完即关（降低平均存活时间）

**现状是「TTL 计时」，不是「收完就关」。**

代码不知道何时算「收完」，因为：

- **DHT** 是一问一答：发 1 包 → 回 1 包 → 完了 → **收了回包就可以关**
- **uTP** 是长连接：持续来回 → 不能关

所以可引入「收到回包后短期宽限即关」策略，大幅降低 DHT 场景的平均存活时间。

**风险**：中。对 uTP 会误杀，**需先分清 DHT/uTP 占比**（依赖 4.3）。

### 优先级建议

| # | 优化项              | 收益                 | 风险 | 建议 |
| - | ------------------- | -------------------- | ---- | ---- |
| 1 | buffer → 2048       | 256 流省 15.5MB 堆   | 无   | **可立即做** |
| 2 | socket 池 + LRU     | fd 封顶 64，peer 无上限 | 低 | 优先做 |
| 3 | DHT 收完即关        | 降低平均存活时间     | 中   | 待 4.3 结论 |

> 注：优化 1 与主事故修复完全独立，无任何副作用，可随时落地。

### 4.5 最终结论：三层模型可行（不依赖具体业务）

抛开具体业务（不纠结 51413 跑什么），**在 UDP/TCP 代理的一般场景下**，
“入口 1 个 / 隧道 1 条 / 出口多个但廉价”这个模型是否成立？

**结论：成立。三层判断均正确，其中①②**已实现**，仅③需改造。**

#### 三层基线

| 环节 | 资源 | 目标 | 现状 | 协议依据 |
| ---- | ---- | ---- | ---- | -------- |
| ① 入口端口 | 1 个 socket | 1 个 | ✅ **已是 1 个** | UDP 无连接，`recv_from` 自带源地址 |
| ② 隧道 | 1 条连接 + 会话 ID | 1 条 | ✅ **已是 1 条**（`udp_outbox` 按 hostname 复用） | 两端均自控，QUIC/WireGuard/SOCKS5 UDP 均如此 |
| ③ 出口到目标 | 多个 socket | 多个但廉价 | ⚠️ 256 × 64KB，**不廉价** | 见下 |

#### ③ 为何必须“多个”：UDP 语义强制，不是设计选择

**关键约束：UDP 回包不带会话标识。** 目标服务（任何标准 UDP 应用）回包时
只有源地址，不会带“这是给会话 X 的”。因此回包归属只能靠下列手段之一区分：

| 手段 | 需要多 socket？ | 通用性 |
| ---- | --------------- | ------ |
| **不同源端口** | 需要 | ✅ **通用**，任何 UDP 应用都认 |
| 应用层字段关联 | 不需要 | ❌ 仅特定协议（DNS txid / DHT transaction ID） |
| 时序匹配 | 不需要 | ❌ 并发时必然串包 |

**所以“多个出口”不是选择，是 UDP 语义的必然。**
除非限定只支持一问一答协议（会在 §4.5.3 模型 C）。

#### “消耗低”怎么做到：让数量与「并发」而非「累计」相关

```
socket 数 = 同时在等回包的会话数（并发）
          ≠ 累计会话数
```

DHT 类流量累计几千 peer，但**同时**在等回包的往往只有几十个（一问一答很快结束）。
所以固定池就能服务无上限的累计会话。

#### 三种出口模型对比

| 模型 | socket 数 | 累计会话上限 | 通用性 | 结论 |
| ---- | --------- | ------------ | ------ | ---- |
| A. 一会话一 socket | = 累计数 | 撞 fd 上限（256） | ✅ 完全通用 | 现状 |
| **B. 固定池 + LRU** | 固定 N（如 64） | **无上限**（受 NAT 表） | ✅ **完全通用** | **推荐** |
| C. 单 socket + 时序匹配 | 1 | 无上限 | ❌ 仅一问一答 | 有适用条件 |

**“多个但廉价” = 模型 B。该模型通用可行，不依赖具体业务。**

#### 必须接受的固有代价

池满时踢掉最久未用的会话，**被踢会话会断**：

- 短会话（一问一答）：无影响
- 长会话（持续双向流）：会断开重连

> **能通用，但“便宜”与“不打断长连接”之间有取舍。**
> 池越大越不打断，但 fd/内存越多。这是固定池的固有代价，无法消除。

若连这个取舍也不想接受，只剩一条路：**把会话 ID 下沉到应用层**
（要求目标协议自带可关联 ID，如 SOCKS5 UDP ASSOCIATE、WireGuard peer key）。
但标准做法仍以端口为主要手段，因为不能假设目标应用配合。

#### TCP 同样适用（且更简单）

| 维度 | TCP | UDP |
| ---- | --- | --- |
| 入口 | 1 个 `TcpListener` | 1 个 `UdpSocket` |
| 隧道 | 1 条 + 会话 ID | 同 |
| 出口 | 每连接 1 个（**必须**） | 池化可复用 |
| 回包归属 | **TCP 天然有**（连接绑定） | ❌ 只能靠端口 |

TCP 的“一连接一 socket”是必需的，因为 TCP 四元组本身就是会话标识。
**反过来说：UDP 的多 socket 是在用端口模拟 TCP 的会话标识——本质是在补 UDP 缺失的那部分。**

#### 一句话结论

> **模型可行。** 入口 1 个、隧道 1 条已经实现且正确；出口的“多个”是 UDP 语义强制，
> 但可用“固定 socket 池 + LRU 复用 + 端口反查 sid”做到廉价且通用。
> 代价仅在于池满时长连接会被踢——这是固定池的固有取舍，非设计缺陷。

---

## 5. 两端超时不一致（附带的配置缺陷）

| 侧   | 常量                     | 值      | 含义                       |
| ---- | ------------------------ | ------- | -------------------------- |
| server | `UDP_SESSION_TTL_SECS_DEFAULT` | **5s**  | peer 静默 5s 即回收 session |
| agent  | `UDP_STREAM_IDLE_SECS`         | **30s** | 流空闲 30s 才自回收        |

两端差 6 倍。好在 `ingress.rs:825` 已修：server 过期时**主动发 `Close`**，
agent 立即关 socket 还槽位，不必等满 30s：

```rust
// 根因→修法：旧代码只 retain 删本地表就不管了，agent 侧那条 udp 流的 socket
// 只能等它自己的 idle 超时（30s/120s）回收，而 server TTL 只有 5s——
// 中间整段时间 server 已忘掉 sid、agent 还挂着 fd。
```

但 agent 侧 30s 作为**兜底**仍偏长（server 若异常没发 Close，fd 会多挂 30s）。
建议两端常量统一，或让 agent 的 idle 略大于 server TTL 但明显小于 30s。

### 5.1 流的关闭机制：三条触发路径

常见误解：以为流要等 30s/120s 才关。**实际有三条路，主力是第一条（5s）：**

| # | 触发条件 | 位置 | 说明 |
| - | -------- | ---- | ---- |
| ① | **server TTL 到期（5s）→ 主动发 Close** | `ingress.rs:825` | **主力路径**。agent 收到后立即 abort 双泵、drop socket、还槽位 |
| ② | agent 侧空闲 30s → 自己 break | `kudus_session.rs:688` | **兜底**。仅当 server 没发 Close（server 崩/网络断）时生效 |
| ③ | 任一侧结束 → `select!` 干掉另一侧 | `kudus_session.rs:719-722` | 旧 `join!` 是 bug（回包侧永等），已修 |

所以 **实际回收时间约 5s，不是 30s/120s**。历史：agent 侧曾是 120s，
已因"DHT 下 fd 空占太久"改成 30s（见 `kudus_session.rs:26` 注释）。

```rust
// ① server 侧：5s 无包即回收
let _ = ctl.send(ServerMsg::Close { stream: *id, reason: "udp idle".into() });

// ② agent 侧：30s 空闲兜底
match tokio::time::timeout(Duration::from_secs(UDP_STREAM_IDLE_SECS), drx.recv()).await {
    Ok(Some(dg)) => { ... }
    _ => break,
}
```

> 为何是「TTL 计时」而不是「收完就关」：代码不知道何时算「收完」——
> DHT 一问一答可以收完即关，uTP 长连接不行。见优化 3（§4.4）。

---

## 6. 待决事项

### 6.1 已澄清的误区（避免重复讨论）

| 常见误解                                   | 事实                                                      |
| ------------------------------------------ | --------------------------------------------------------- |
| agent↔HK 会为每个 peer 建多条连接          | **不会**。kudus 只有 1 条连接，按 hostname 复用           |
| 256 是 256 个 64KB buffer                  | **不是**。接收侧只 1 个 buffer；256 是 fd/流数             |
| 把 256 调大到 4096 就能解决                | **不行**。4096 fd + ≈800MB 内核缓冲，反而更糟             |
| TCP/UDP 没分开                     | **路径已分开**；只是配额池共用（见 §3.2）            |
| 可以简单地用共享 socket 省掉 256 个        | **有卡点**：UDP 回包不带会话标识，需靠源端口（见 §4.2）  |

### 6.2 可选修复方向

| # | 议题                                          | 倾向与说明                                      |
| - | --------------------------------------------- | ----------------------------------------------- |
| 1 | **接收 buffer 65535 → 2048**                  | **零风险，可立即做**（§4.4 优化 1）            |
| 2 | **socket 池 + LRU 复用**                      | fd 封顶 64，peer 无上限（§4.4 优化 2）         |
| 3 | 配额解耦：`udp` 与 `link_udp` 拆独立信号量    | 建议做，成本低，直击“一个业务饿死另一个”      |
| 4 | 先确认 51413 跑 DHT 还是 uTP                  | **前置**，决定优化 3 与方案 B 是否可行        |
| 5 | DHT 收完即关（短期宽限）                      | 收益大但需先分清流量类型（§4.4 优化 3）       |
| 6 | agent `UDP_STREAM_IDLE_SECS` 30s 是否收短     | 建议收短，与 server TTL（5s）对齐              |
| 7 | DHT 类流量单独限速/限流（防打满）              | 建议做                                          |

> 注：本节仅记录分析结论，**未做任何代码改动**。
> 修任何一项都必须按项目铁律先写红用例（`KUDUS_MAX_UDP_STREAMS` 相关单测目前只断言
> `<= 512` 与信号量初值，见 `agent/kudus_session.rs:805-807`）。
>
> 另：本专题与主事故的重传放大（[2026-10-23-kudus-retx-storm.md](./2026-10-23-kudus-retx-storm.md)）
> 是**两个独立缺陷**，槽位问题不是流量风暴的根因，应分开修。

---

## 附：相关代码索引

```
agent/kudus_session.rs:24-25   KUDUS_MAX_UDP_STREAMS 定义（egress 并发上限）
agent/kudus_session.rs:27      UDP_STREAM_IDLE_SECS = 30
agent/kudus_session.rs:185-186 agent ↔ HK kudus 连接（仅 1 次 bind+connect）
agent/kudus_session.rs:242     udp_slots 初始化
agent/kudus_session.rs:669     try_acquire_owned + 拒绝 warn
agent/kudus_session.rs:729     open_udp_stream（每 sid 新建出站 socket）
agent/kudus_session.rs:740-741 UdpSocket::bind(0) + connect(内网目标)
agent/kudus_session.rs:661     open_udp_stream_to（双泵 + select! 收尾）
agent/kudus_session.rs:521     kind == "udp" 分发
agent/kudus_session.rs:524     kind == "link_udp" 分发（共用配额）
server/kudus.rs:700            kudus listen UdpSocket::bind（仅 1 个）
server/state.rs:55             udp_outbox: HashMap<hostname, Sender<(sid, bytes)>>（按 hostname 复用）
server/ingress.rs:802          sessions: HashMap<SocketAddr, (sid, last_seen, ...)>
server/ingress.rs:806          ttl = udp_session_ttl_secs.max(1)
server/ingress.rs:875-880      ServerMsg::Open（host 为空，只传 port）
server/ingress.rs:825          过期主动发 Close（reason: "udp idle"）
server/ingress.rs:858          udp_outbox 注释（保包边界的根因）
server/state.rs:103            UDP_SESSION_TTL_SECS_DEFAULT = 5
```
