# 事故复盘：看门狗被纯 ACK 无限喂饱，会话卡死 7 小时

- **状态**：已修复（TDD，含回退验证）
- **发现时间**：2026-10-25 06:00（准备给 18080 测速时发现代理完全不通）
- **影响**：egress HTTP 代理 18080 完全不可用，持续约 7 小时
- **是否首次**：**不是**。2026-10-23 workmac 现场同症状（记为"泄漏重传泵探活"），
  当时的修法只做了「纯 ACK 不算活」，**漏了计时器被 continue 重置这一层**

---

## 1. 现象

准备测速时 `curl -x http://127.0.0.1:18080` 全部超时（`000`，无响应）：

| 观测点 | 数值 | 说明 |
| --- | --- | --- |
| 链路 | **0% 丢包**，RTT 35ms | 网络完全正常 |
| agent 进程 | 活着，CPU 0.9% | 没崩、没忙等 |
| 18080 | `LISTEN` | 端口在听 |
| agent 日志 | `welcomed` @ 22:58，之后 **7 小时零重连** | 不知道自己死了 |
| server `tx` | **0B** | 一个字节没送出去 |
| server 日志 | 无该会话任何记录 | server 不认这个会话 |
| agent `abandoned` | 8~13/分钟 | 有包重传 10 次全失败 |
| 抓包 | `In=27`（94B 纯 ACK）/ `Out=3` | server 在发，agent 基本不回 |

**core contradiction**：server 认为会话已死，agent 认为会话还活着，双方都不重连。

94 字节 = 50B 帧头 + 封装开销 ⇒ 纯 ACK 帧（`send_pkt(&h, &[])`）。

---

## 2. 根因

agent 主循环的看门狗：

```rust
loop {
    let (h, body) = match tokio::time::timeout(
        Duration::from_secs(KUDUS_IDLE_KICK_SECS as u64),  // 75s，**在循环体内**
        dec_rx.recv(),
    ).await {
        Ok(Some((h, body))) => {
            if !frame_feeds_watchdog(h.flags) && h.flags & FLAG_FIN == 0 {
                continue;   // ← 回到循环顶部，**重建一个全新的 75s timeout**
            }
            (h, body)
        }
        _ => anyhow::bail!("kudus heartbeat timeout: no server frame"),
    };
    ...
}
```

`torque::time::timeout` 是**相对**计时：每次进入循环都新建一个 75s 定时器。
server 重传泵每 50ms 发一个纯 ACK ⇒ `recv()` 每 50ms 就返回 ⇒ `continue`
⇒ 新 75s 定时器 ⇒ **永远跑不到 75s**。

```rust
/// 旧注释（错的）
// 纯 ACK 只清重传（读泵已做），此处直接等下一帧，看门狗照常计时。
```

「看门狗照常计时」并不成立——计时器被 `continue` 重置了。

### 2.1 与 2026-10-23 的关系

那次现场同样是「本地端口活、数据面死、无日志」，修法是加了
`frame_feeds_watchdog()` 让纯 ACK 不算"活"。**但只改了"什么算活帧"，
没改"计时器怎么计"** —— `continue` 重置这个洞原封不动留着。

结果：只要 server 侧一直有纯 ACK 流出（重传泵空转/旧会话残留），
agent 就永远不会 bail。修了一半比没修更难查，因为日志里看起来"有处理逻辑"。

---

## 3. 修法

计时基准改成**绝对时刻**，存循环外；每轮只给 `timeout` **剩余预算**：

```rust
let mut last_alive = std::time::Instant::now();   // 循环外
loop {
    let budget = Duration::from_secs(KUDUS_IDLE_KICK_SECS as u64)
        .saturating_sub(last_alive.elapsed());    // 剩余预算，不是固定 75s
    let (h, body) = match tokio::time::timeout(budget, dec_rx.recv()).await {
        Ok(Some((h, body))) => {
            if !frame_feeds_watchdog(h.flags) && h.flags & FLAG_FIN == 0 {
                continue;                          // 不刷新 last_alive
            }
            last_alive = Instant::now();           // 只有 DATA/FIN 刷新
            (h, body)
        }
        _ => anyhow::bail!("kudus heartbeat timeout: no server frame"),
    };
```

关键：`saturating_sub` 保证预算耗尽后是 `0`，`timeout(0, ...)` 立即返回
`Elapsed` ⇒ 正确 bail ⇒ 外层 backoff 重连。

判定逻辑抽成纯函数 `common::kudus::watchdog_budget_ms(elapsed_ms)` 便于单测。

---

## 4. 验证

单测（`cargo test --bin neutrino watchdog`，4 passed）：
- `watchdog_budget_drains_under_pure_ack`：预算随 elapsed 递减，75s 起返回 None
- `pure_ack_never_refills_watchdog`：900 个纯 ACK × 50ms 内预算**单调下降**
- `only_data_frames_feed_watchdog` / `kudus_watchdog_contract`：既有契约不破

**回退验证**：把 `watchdog_budget_ms` 改回「永远返回满值 75000」（等价旧
`continue` 重建 timeout 的语义）⇒ 两个用例变红 ✅

全量 203 passed，e2e 41 passed，`make build` 零 warning。

线上：部署后 18080 立即恢复（`generate_204` 0.34s），后续测速全部正常。
