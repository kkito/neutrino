# 专题：`tunnel_stats` 埋点盲区（HTTP 已补、UDP 仍缺）

- **状态**：HTTP 缺口已修（`ec97bee`）；**UDP 缺口未修**（本文记录现场与修法，待排期）
- **关联**：
  - [2026-10-23-kudus-retx-storm.md](./2026-10-23-kudus-retx-storm.md)（主事故）
  - [2026-10-23-kudus-udp-stream-slots.md](./2026-10-23-kudus-udp-stream-slots.md)（UDP fd 槽位）
  - spec §15.4：`docs/superpowers/specs/2026-10-25-kudus-udp-hardening-design.md`
- **发现途径**：2026-10-24 部署验证（HK server + 本机 agent，51413 UDP/TCP 真实隧道打流）
- **性质**：**可观测性盲区**，不影响功能；但会让"补上来的可观测性"在主流量上失效

## 结论速览（TL;DR）

`tunnel_stats`（per-tunnel 每分钟汇总行）当前只埋在 **3 个位置**，覆盖 TCP 与 HTTP，**UDP 一条都没有**：

| 路径 | 埋点位置 | 状态 |
| ---- | -------- | ---- |
| TCP（`remote_port`） | `ensure_tcp_listener` @ `ingress.rs:616/718/764` | ✅ 有 |
| HTTP（按 Host 路由） | `fallback_http_ingress` @ `:323` + `HttpConnGuard::drop` @ `:156` | ✅ 有（2026-10-24 补） |
| **UDP（`remote_port`）** | `ensure_udp_listener`（`:807` 起） | ❌ **完全没有** |

后果：BT 的 **UDP tracker / DHT / uTP 全走 UDP ingress**，等于本项目里流量最重的一块在日志中完全不可见——
而"补可观测性"的初衷正是为了在下次事故里能看见 UDP 侧发生了什么。

---

## 1. 现场：同一个部署，TCP 有汇总行、UDP 没有

2026-10-24 在 HK（`<HK_SERVER>`）起 server `0.7.9`，本机 `minipc7s` 起 agent，
`desired.toml` 配两条隧道指向同一个实现：

```toml
[[agents.minipc7s]]
name = "bt-udp"
type = "udp"
local_ip = "127.0.0.1"
local_port = 51413
remote_port = 51413

[[agents.minipc7s]]
name = "bt-tcp"
type = "tcp"
local_ip = "127.0.0.1"
local_port = 51413
remote_port = 51414
```

两条隧道各打一次真实往返（HK 侧主动连 ingress 端口），均成功：

- UDP：HK `sendto 51413` → 收到 `b'echo:hello-from-hk'`
- TCP：HK `connect 51414` → 收到 `b'tcp-echo:tcp-hi-from-hk'`

等一个 traffic tick（默认 60s）后，server 日志里**只有 TCP 那一行**：

```
INFO neutrino::server: tunnel stats minipc7s/bt-tcp accepts=1 closes=1 stick=0 rx=14B tx=23B
```

`minipc7s/bt-udp` 一行都没有。反复抓多次确认非偶发：

```bash
grep -cE "tunnel stats" server.log        # 有
grep -cE "tunnel stats minipc7s/bt-udp"  # 0
```

同时可见 UDP 路径其实**跑过**（证明不是隧道没通）：

```
INFO neutrino::server::ingress: udp session 127.0.0.1:56978 -> sid=2 tunnel=bt-udp host=minipc7s
```

## 2. 根因：埋点写在 per-connection 的地方，UDP 没有"per-connection"概念

`TunnelStats` 的设计是**在"关闭时刻"累加**（`state.rs:38-40` 注释写明：不等 tick 扫表，
因为 conns 表 close 即 remove，扫表只能看到存活连接，BT 短连接会严重偏低）。

TCP 有明确的 accept/close 时刻，所以埋点自然落在 `ensure_tcp_listener`：

```rust
// ingress.rs:614（accept 侧）
let stats_key = format!("{hostname}/{pname}");
m.entry(stats_key).or_default().accepts += 1;
// :718 首包超时 stick += 1、:764 close 侧 closes += 1
```

HTTP 同理，`fallback_http_ingress` 建连时 `accepts += 1`，`HttpConnGuard::drop`（挂在
响应 Body 流上，正常走完/中途断开都会 drop）`closes += 1`——这是 2026-10-24 补的，
补之前 HTTP **也是完全空白**，而 HTTP 才是本项目的主流量（详见 §4）。

UDP ingress 的结构完全不同：

```rust
// ingress.rs:854 —— sessions 表（peer -> (sid, last_seen, sender, limiter, ctl)）
let mut sessions: HashMap<std::net::SocketAddr, (u32, Instant, ...)> = HashMap::new();

// :869/:881 —— 过期回收靠 TTL 扫描，不是靠 close 事件
let dead = expired_sids(&snapshot, now, ttl);
sessions.retain(|_, (_, t, _, _, _)| t.elapsed() < ttl);
```

"accept" 对应"新 peer 建 session"、"close" 对应"TTL 到期回收"——两者都是**现成的钩子**，
但当初埋点只做了 TCP，UDP 侧漏掉了。这不是设计冲突，纯属**遗漏**。

## 3. 附带发现：`_sess_host` / `_sess_pname` 已经是"半成品"

UDP ingress 里其实早就算出了建 stats_key 所需的全部素材，只是没用：

```rust
// ingress.rs:938（host/pname 只被 :975 那行日志用；sess_key 算出来却没用）
let (_sess_host, sess_key, _sess_pname, sess_bps) = {
    let ag = s2.agents.read().await;
    let snap: Vec<(&str, Vec<ProxyConfig>)> = ...;
    match resolve_udp_session(&snap, port) { Some(v) => v, None => continue }
};
```

`sess_key` 来自 `state::traffic_key(host, &p.name)`，实现在 `state.rs:187`：

```rust
pub(crate) fn traffic_key(hostname: &str, name: &str) -> String {
    format!("{hostname}/{name}")
}
```

与 TCP 路径 `format!("{hostname}/{pname}")`（`ingress.rs:614`）、HTTP 路径
`format!("{hostname}/{}", proxy.name)`（`:321`）**字节级一致**。
也就是说补 UDP 埋点不需要新算任何东西，直接把 `sess_key` 当 stats_key 用即可
（它本来是为限速器造的 key，恰好同构）。单测 `resolve_udp_session` @ `:1114`
已断言该值形如 `"h/u"`。
（`_sess_host` / `_sess_pname` 两个并未真闲置：`ingress.rs:975` 的 `udp session ...`
日志就消费它们；加下划线是因为只在那一行用，编译器不会报 unused。真正白算的只有 `sess_key`。）

## 4. 为什么这个缺口值得单独记一笔

2026-10-24 修 HTTP 缺口时的原始判断是对的：**"主流量在日志里不可见"** 就等于没补可观测性。
HTTP 修完（commit `ec97bee`）之后，同一句话对 UDP 依然成立，而且 UDP 侧更严重：

- 事故当时（2026-10-23）打爆的正是 **UDP**（`too many udp streams` 3608 条、DHT 扫描器造 session）
- 事故复盘时 `grep -icE "retx|retrans|backpressure|window"` = **0**，UDP 侧连"有会话"都看不见
- 现在 tcp 与 http 都有了 `accepts/closes/stick/rx/tx` 汇总，唯独出事的那个协议没有

换句话说：**下次同类事故发生，日志里依然看不到 UDP 隧道的 accept/close/流量**，
只能看到零星的 `udp session ... -> sid=N`（建 session 时一次）和 TTL 到期的 `debug` 行。

## 5. 修法（已验证可行，未提交）

2026-10-24 曾实现过一版并确认 `cargo build` 零 warning，为保持本次提交范围干净已回退
（`git checkout src/server/ingress.rs`）。核心思路：

1. `sessions` 元组已有 5 个字段，再塞 stats_key 要动所有解构模式 → 用**旁挂小表**
   `sid_stats: HashMap<u32, String>`（session 数受 TTL 约束，表很小）。
2. 建 session 处（插 `sessions` 前）：

   ```rust
   if !sess_key.is_empty() {
       sid_stats.insert(id, sess_key.clone());
       if let Ok(mut m) = s2.tunnel_stats.lock() {
           m.entry(sess_key).or_default().accepts += 1;
       }
   }
   ```

3. TTL 回收处，**先**累加 closes **再**删旁挂表（顺序反了查不到 key）：

   ```rust
   if n_exp > 0 {
       // ... 发 Close（原有逻辑）...
       if let Ok(mut m) = s2.tunnel_stats.lock() {
           for k in dead_set.iter().filter_map(|id| sid_stats.get(id)) {
               m.entry(k.clone()).or_default().closes += 1;
           }
       }
       for id in &dead_set { sid_stats.remove(id); }
   }
   ```

4. `rx` / `tx` 可在已有的 conns 行累加点顺手加（`udp` 下行 `c.rx += payload.len()`、
   上行 `c.tx += chunk.len()`），按 `sid_stats` 找到 key 累加。

### 实施前必须注意的三点

- **必须 TDD**：先写 RED 的 e2e（UDP 隧道打流后断言 `tunnel stats <host>/<proxy> accepts>=1`），
  再实现。参考 `tests/e2e.rs::e2e_tunnel_stats_line_emitted`（HTTP 版），把 `type` 换成 `udp`
  并灌几个包。**注意服务端 UDP ingress 把 `SO_RCVBUF` 钳到 64KB**，突发灌包会在
  ingress 之前被内核丢掉，实测恒定只进 137 个——所以要么少量包、要么错峰发。
- **回退验证**：注释掉 `accepts += 1`，用例必须变红（HTTP 那次就是这么验的，见 `ec97bee`）。
- 现有单测 `ingress_accumulates_tunnel_stats`（`:1217` 函数体）是**源码字面量断言**，
  只查 `.accepts += 1` 是否存在，**不区分路径**——补 UDP 后它照样过，不能当作"UDP 有了"的证据。

## 6. 教训

1. **"补盲区"要按协议盘点，不能按函数盘点。** 当时对着"accept/close 在哪"找埋点，
   TCP 一眼就能找到，HTTP 找了一圈才发现走的是 fallback，UDP 的等价物叫"建 session / TTL 回收"，
   名字对不上就漏了。正确做法：先列出**所有隧道路径**（tcp / http / udp / link_udp / quic），
   逐条确认有没有统计，而不是从代码里搜 `accept`。
2. **源码字面量断言会给出虚假的安全感。** `ingress_accumulates_tunnel_stats` 在 UDP 完全
   空白时依然全绿。行为断言（e2e 真打流看日志行）才是唯一可信的证据。
3. **真实部署验证能抓到单测和 e2e 都抓不到的东西。** 这个缺口是在 HK 上真起一套、
   真打 UDP/TCP 各一发、再 `grep` 日志才发现的——单测 178 + e2e 40 全绿时它一直在。
