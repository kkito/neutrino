# 事故索引与分诊表

本目录记录 neutrino 的线上事故复盘。**先看分诊表**定位症状，
再跳对应文档看根因与修法。

---

## 分诊表：同一症状、不同根因

2026-10-24 / 25 连续挖出三个 bug，**现场抓包形态完全一样**：

```
In=27~288 个包，且入站全是 94 字节     ← server 在发，几乎全是纯 ACK
Out=极少                               ← agent 基本不回
```

94 字节 = 50B 帧头 + 4B 前缀 + 24B nonce + 16B tag ⇒ **纯 ACK 帧**
（`send_pkt(&h, &[])`，无载荷）。

**看到这个形态不要直接下结论**，按下表分诊：

| 判据 | 根因 | 文档 |
| --- | --- | --- |
| server `tx=0B` **且 server 日志查无此会话**<br>agent 日志 `welcomed` 后长时间无重连 | **看门狗被纯 ACK 喂饱**，会话永不 bail | [2026-10-25-watchdog-fed-by-pure-ack](./2026-10-25-watchdog-fed-by-pure-ack.md) |
| server `tx=0B` 但**日志有该会话** + `sent` 很大 + `backlog_max` 高 | **接收重排窗永久死锁**（窗满连 `seq==next` 都拒收） | [2026-10-24-lossy-link-sack-gap §6](./2026-10-24-lossy-link-sack-gap.md) |
| `tx` 有数但很小 + `ping -i 1` 丢包 10-20% | **公网链路丢包**，重传恢复太慢（缺快速重传） | [2026-10-24-lossy-link-sack-gap](./2026-10-24-lossy-link-sack-gap.md) |
| `thru` 远超 `limit` 且**单调爬升**，`sleep` 涨到秒级 | **重传风暴**（无退避 + 无上限自激） | [2026-10-23-kudus-retx-storm](./2026-10-23-kudus-retx-storm.md) |
| `abandoned` 持续增长，`WARN too many udp streams` | UDP 流槽位打满 | [2026-10-23-kudus-udp-stream-slots](./2026-10-23-kudus-udp-stream-slots.md) |
| UDP 流无声消失，日志里没有任何 close 记录 | UDP 流生命周期全静默 | [2026-10-24-udp-stream-lifecycle-blind](./2026-10-24-udp-stream-lifecycle-blind.md) |
| 隧道 **online**、端口**在听**、`/dev/tcp` 可连<br>但 `/api/live` 恒 0 且公网 `tcpdump` 抓不到包 | **应用层没产生流量**（任务暂停 / 配置未重启生效），<br>**不是隧道问题** | [2026-10-25-bt-51413-no-traffic](./2026-10-25-bt-51413-no-traffic.md) |
| `/api/overview` 里 UDP 隧道 `rx/tx` 恒 0 但实际有流量 | `tunnel_stats` UDP 埋点缺失 | [2026-10-24-tunnel-stats-udp-gap](./2026-10-24-tunnel-stats-udp-gap.md) |

### 分诊决策树

```
代理/隧道不通或极慢
├─ ping -i 1 <server> 有丢包？
│  ├─ 有（10-20%）─────────────────── 链路丢包
│  │   └─ 且 1MB 下载永久卡死 ─────── 快速重传缺失（已修）
│  └─ 无（0%）
│      ├─ server tx=0B
│      │   ├─ 日志查无此会话 ─────── 看门狗喂饱（已修）
│      │   └─ 日志有会话、sent 大 ── 重排窗死锁（已修）
│      └─ server tx 有数
│          ├─ thru 单调爬升 ──────── 重传风暴
│          └─ 正常
│              ├─ /api/live 恒 0 且公网抓不到包
│              │   └─ 应用层没发流量 ──── 查任务状态 / 配置是否重启生效
│              └─ 有流量但 overview 显示 0 ── tunnel_stats 埋点缺失
└─ 进程/端口本身异常？
    ├─ 进程不在 ───────────────────── 看门狗脚本 / systemd
    └─ 端口不听 ───────────────────── 启动失败，看启动日志
```

---

## 必备取证命令

抓包看方向（**这是最快的分诊入口**）：

```bash
# 统计双向包数与大小分布；In 全 94B ⇒ 纯 ACK 风暴
sudo tcpdump -i any -n "udp and port 36182" -c 300 2>/dev/null > /tmp/p.txt
echo "In=$(grep -c ' In ' /tmp/p.txt) Out=$(grep -c ' Out ' /tmp/p.txt)"
grep ' In ' /tmp/p.txt | awk '{print $NF}' | sort -n | uniq -c | sort -rn | head
```

丢包率（**必须 `-i 1`**，`-i 0.05` 会触发 ICMP 限速产生 `6667%` 假数据）：

```bash
ping -c 100 -i 1 <HK_SERVER> | tail -2
```

server 侧三个关键计数（`journalctl -u neutrino-server | grep -E 'kudus retx|tunnel stats|ratelimit'`）：

| 字段 | 含义 | 异常特征 |
| --- | --- | --- |
| `tx` | server 发出的字节 | `0B` ⇒ 数据面死了 |
| `sent` | 一分钟重传包数 | 单调爬升 ⇒ 风暴；稳定几百 ⇒ 正常 |
| `backlog_max` | 未确认包峰值 | 持续接近 `KUDUS_WINDOW`(512) ⇒ 卡洞 |
| `abandoned` | 重传超上限被弃 | 持续增长 ⇒ 链路太差或丢包簇 |
| `thru` / `sleep` | 限速器累计吞吐/休眠 | `thru` 远超 `limit` 且 `sleep` 到秒级 ⇒ 风暴 |
| `send_fail` | 本地发送失败数 | 恒 0 可**排除**本地写泵故障 |

`sent` / `abandoned` / `full` / `backlog_max` / `send_fail` 都在 agent 与
server 两侧的每分钟 `kudus retx` 汇总行里，**对比两侧数值**能立刻判断方向：

- 两侧都几百、`backlog_max` 十几 ⇒ 正常
- 只一侧几千且 `backlog_max` 数百 ⇒ 那一侧在单向丢
- 两侧都 0 但流量还在 ⇒ 数据走的是别的会话（可能旧会话残留）

开 DEBUG（信号方式，默认 `info`）：

```bash
kill -USR1 <pid>   # 开启 60s debug
kill -USR2 <pid>   # 立即恢复 info
```

---

## 事故列表（按时间）

| 日期 | 事故 | 状态 |
| --- | --- | --- |
| 2026-10-23 | [kudus 重传风暴](./2026-10-23-kudus-retx-storm.md)（42 倍放大，整机瘫痪） | ✅ 已修（`d694bf0` 等，`10fa13b` 加硬闸） |
| 2026-10-23 | [kudus UDP 流槽位](./2026-10-23-kudus-udp-stream-slots.md)（256 上限打满） | ✅ 已修（池化 + LRU） |
| 2026-10-24 | [公网链路丢包下吞吐塌陷](./2026-10-24-lossy-link-sack-gap.md)（SACK 有、快速重传无） | ✅ 已修（`9af1edd` + `6b2c0bb`） |
| 2026-10-24 | [tunnel_stats UDP 埋点盲区](./2026-10-24-tunnel-stats-udp-gap.md) | ⚠️ HTTP 已补，UDP 待排期 |
| 2026-10-24 | [UDP 流生命周期全静默](./2026-10-24-udp-stream-lifecycle-blind.md) | ✅ 已修 |
| 2026-10-25 | [看门狗被纯 ACK 无限喂饱](./2026-10-25-watchdog-fed-by-pure-ack.md)（会话卡死 7h） | ✅ 已修（`aa68ee3`） |
| 2026-10-25 | [BT 隧道 51413 无流量](./2026-10-25-bt-51413-no-traffic.md)（任务全暂停 + 配置未重启） | ✅ 已通（非代码问题） |

---

## 反复踩过的坑（跨事故共性）

1. **静默失败最难查**：`let _ = send(...)`、`Ok(0) | Err(_) => break` 这类
   合并分支会把"没发出去"变成"看起来正常"。落日志至少 warn 并带 sid。
2. **修一半比没修更难查**：2026-10-23 只修了"纯 ACK 不算活"，
   没修"计时器被 `continue` 重置"——日志里看着有处理逻辑，实际永不触发。
3. **两边指标都健康 ≠ 链路通**：重排窗死锁时 agent `send_fail=0`、
   `backlog_max=16`，server `abandoned=0`，一切看着正常但完全不通。
   **必看 `tx`（对端实际收到多少）**。
4. **不要盲等 `sleep(N)` 判断状态**：轮询可观测状态（`/api/tunnels`、
   `/api/live`、`kudus retx` 行），命中即返回。
5. **全局静态原子计数器在并行测试里会污染**：断言必须用**增量**而非绝对值。
6. **测试的回退验证必须亲眼看到红**：本轮写限流闸的测试，
   前两版都没能触发（被 `KUDUS_SACK_BITS` 窗宽和 `now_ms()` 跨窗重置挡住），
   **没有回退验证就会把无效测试当成保护**。
7. **"隧道 online + 端口在听" ≠ "有流量"**：排 BT 问题时从隧道侧查起绕了一大圈，
   实际是 transmission 33 个任务全暂停 + 改了 `settings.json` 没重启容器。
   正确顺序是 **`/api/live` 有无字节 → 公网 `tcpdump` 有无包 → 最后才查隧道**。
8. **别凭旧版本印象猜配置字段名**：transmission 4.1.1 的代理只有 `proxy_url`
   一个字段（`proxy-enabled`/`proxy-type` 在 4.x 已被合并掉），
   一度误判"缺开关所以没启用"。`--dump-settings` 才是权威，5 秒能确认。
