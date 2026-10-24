//! server 全局状态：Shared/AgentInfo/路由表/持久化 + 小纯函数。
use crate::common::proto::*;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

#[derive(Debug, Clone, Serialize)]
pub(crate) struct AgentInfo {
    pub(crate) agent_id: String,
    pub(crate) hostname: String,
    pub(crate) version: String,
    pub(crate) online_secs: i64,
    pub(crate) rtt_ms: i64,
    pub(crate) rx_bytes: u64,
    pub(crate) tx_bytes: u64,
    pub(crate) proxies: Vec<ProxyConfig>,
}

pub(crate) struct AgentHandle {
    pub(crate) info: AgentInfo,
    pub(crate) connected_at: chrono::DateTime<chrono::Utc>,
    /// 热路径原子计数：deliver/写泵/Ping 每包累加 rx/tx/rtt，零 agents 锁。
    /// 根因→修法：旧代码每包 agents.write() 改 info.rx/tx/rtt，BT flood 高 pps
    /// 下写者排队、/api/overview+tunnels 的 agents.read() 饿死 10s+ 超时
    /// （2026-10-23 HK 现场）。现只在 5s live tick 批量合进 info（单次 write），
    /// overview 读 info 快照 + 原子 load，永不饿死。
    pub(crate) ctr_rx: std::sync::Arc<std::sync::atomic::AtomicU64>,
    pub(crate) ctr_tx: std::sync::Arc<std::sync::atomic::AtomicU64>,
    pub(crate) ctr_rtt: std::sync::Arc<std::sync::atomic::AtomicI64>,
    pub(crate) ctl: mpsc::UnboundedSender<ServerMsg>,
    pub(crate) incoming: Arc<RwLock<HashMap<u32, mpsc::UnboundedSender<Vec<u8>>>>>,
    /// Binary 早到缓存：egress Open 与首包背靠背时，占位注册前的包先存此表，
    /// 拨号泵启动后 drain 写给公网（与 agent 侧 Ctx.pending 对称）。
    pub(crate) pending: Arc<RwLock<HashMap<u32, Vec<Vec<u8>>>>>,
}

/// 隧道级累计（spec §15.4）。在「关闭时刻」累加，不等 tick 扫表——
/// conns 表 close 即 remove，扫表只能看到存活连接，BT 短连接会严重偏低。
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct TunnelStats {
    pub(crate) accepts: u64,
    pub(crate) closes: u64,
    pub(crate) rx: u64,
    pub(crate) tx: u64,
    /// first-chunk timeout 次数
    pub(crate) stick: u64,
}

/// 取走并清空（tick 汇总用）。取走即归零，下轮重新累计。
#[allow(dead_code)] // 使用者：Task 0b-4（traffic tick 汇总）
pub(crate) fn drain_tunnel_stats(
    m: &mut HashMap<String, TunnelStats>,
) -> HashMap<String, TunnelStats> {
    std::mem::take(m)
}

/// 人类可读字节数（日志用）。
#[allow(dead_code)] // 使用者：Task 0b-4（traffic tick 汇总）
pub(crate) fn fmt_bytes(n: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KB", "MB", "GB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n}B")
    } else {
        format!("{v:.1}{}", UNITS[i])
    }
}

#[derive(Default)]
pub(crate) struct Shared {
    pub(crate) agents: RwLock<HashMap<String, AgentHandle>>,
    /// domain(lower) -> agent_ids (multi-agent LB via round-robin)
    pub(crate) domains: RwLock<HashMap<String, Vec<String>>>,
    /// remote_port -> agent_ids (tcp/https/udp)
    pub(crate) tcp_ports: RwLock<HashMap<u16, Vec<String>>>,
    pub(crate) tcp_listening: RwLock<HashSet<u16>>,
    pub(crate) udp_listening: RwLock<HashSet<u16>>,
    pub(crate) events: RwLock<Vec<String>>,
    pub(crate) password_hash: RwLock<String>,
    pub(crate) jwt_secret: String,
    pub(crate) outbox: RwLock<HashMap<String, mpsc::UnboundedSender<(u32, Vec<u8>)>>>,
    /// kudus UDP 下行专用：(sid, 整包 datagram)。TCP 与 UDP 在 outbox (sid,payload)
    /// 里都是裸字节无法区分——UDP 下行走此独立通道，写泵按整包分片+重组语义发
    /// （包边界不变）；WSS/QUIC 不用此表（整帧直达）。kudus 建连时注册、断开时清。
    /// 根因→修法：旧共用 outbox 被按 1000B 切片逐片 deliver，1500B 包变 2 个残包。
    pub(crate) udp_outbox: RwLock<HashMap<String, mpsc::UnboundedSender<(u32, Vec<u8>)>>>,
    pub(crate) totals: RwLock<HashMap<String, (u64, u64)>>, // hostname -> (rx,tx) persisted
    pub(crate) data_dir: String,
    pub(crate) desired: RwLock<HashMap<String, Vec<ProxyConfig>>>,
    pub(crate) desired_path: String,
    /// egress 出口路由表：发起 agent hostname -> 出口 agent hostname。
    /// [egress_exit] 顶层表，未列出/空值/自指 → 回退 server 本机拨号（fail-open）。
    pub(crate) egress_exit: RwLock<HashMap<String, String>>,
    /// 分钟流量点：key = "hostname/proxy名" -> VecDeque<(ts, rx增量, tx增量)>，cap 43200（30天）
    /// 根因→修法：点必须带落盘时的 wall clock ts，否则 api 用 now-len*60 反推，
    /// 重启/断流后旧点画到错误时间（18:12 高峰实为 17 点旧账错位）。
    pub(crate) traffic: RwLock<HashMap<String, VecDeque<(i64, u64, u64)>>>,
    /// 5s 实时快照：key 同 traffic -> (rx_5s, tx_5s)，纯内存不落盘（秒级监控用）
    pub(crate) live: RwLock<HashMap<String, (u64, u64)>>,
    /// 5s tick 上轮累计：key 同 traffic，用于算 5s 增量（纯内存，重启丢了下轮重建基线）
    pub(crate) live_last: RwLock<HashMap<String, (u64, u64)>>,
    /// agent 总量 5s 批量刷基线：hostname -> 上轮 per-host 累计（conns 行汇总）。
    /// 根因→修法：包循环零 agents 写锁后，info.rx/tx 只在 live tick 里 5s 刷一次，
    /// 基线存此表（与 live_last 的 per-tunnel 基线分开）。
    pub(crate) live_last_host: RwLock<HashMap<String, (u64, u64)>>,
    /// 上分钟累计快照：key 同 traffic，用于算增量
    pub(crate) last_total: RwLock<HashMap<String, (u64, u64)>>,
    /// 已见 tunnel：随 traffic.json 落盘，重启后读回，已知 key 首轮只建基线不 push
    ///（不断崖、不吞量）。key 同 traffic。
    pub(crate) seen_tunnels: RwLock<std::collections::HashSet<String>>,
    /// 黑洞原子计数：热路径每包 +1（包数, 字节），60s tick 归集进 traffic 后清零。
    /// std Mutex（临界区只有 entry+1，纳秒级），不另引依赖。纯内存不落盘。
    pub(crate) drop_hits: std::sync::Mutex<HashMap<String, (u64, u64)>>,
    /// warn 限流表：key -> 上次 warn 的 unix ts，纯内存不落盘。
    pub(crate) drop_warn: std::sync::Mutex<HashMap<String, i64>>,
    /// 隧道级累计（spec §15.4），key = tunnel 名（如 "minipc7s/trans-bt"）。
    /// 在 accept/close/first-chunk timeout 三处累加，traffic tick 取走即归零。
    pub(crate) tunnel_stats: std::sync::Mutex<HashMap<String, TunnelStats>>,
    /// 当前连接快照：key = conn id
    pub(crate) conns: RwLock<HashMap<u64, ConnInfo>>,
    /// --listen 解析出的公网端口（HTTP fallback 连接行用）
    pub(crate) public_port: u16,
    /// 映射级限速窗口：key = traffic_key(hostname, proxy名) -> 共享 limiter（总量语义）。
    pub(crate) rate_limiters: RwLock<HashMap<String, Arc<crate::server::ratelimit::RateLimiter>>>,
    /// agent-admin 开关：开 = 已连 agent 可经隧道读写 server 管理 API（token 即最高权）。
    /// 根因→修法：默认关，不传开关即锁死（B 信任模型下默认开等于裸奔）。
    pub(crate) allow_agent_admin: bool,
    /// UDP ingress session 空闲回收秒数（默认 5，--udp-session-ttl 可配）。
    /// 语义是「上次收到该 peer 的包之后静默多久就回收」：每包刷新 t，所以
    /// 活跃 uTP 长连接永不回收、扫描器一问一答 5s 即清。
    /// 根因→修法：旧值写死 120s（照抄 conntrack stream 超时），DHT 扫描器
    /// 每个新源端口建一条 session，120s 内堆积几十条/IP → 256 槽位瞬间打满。
    pub(crate) udp_session_ttl_secs: u64,
}

/// UDP session 空闲回收默认秒数（--udp-session-ttl 未传时）。
pub(crate) const UDP_SESSION_TTL_SECS_DEFAULT: u64 = 5;
/// 30天分钟点上限
pub(crate) const TRAFFIC_CAP: usize = 43_200;
/// 当前连接表上限（超了挤掉 id 最小的）
pub(crate) const CONNS_CAP: usize = 5_000;

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ConnInfo {
    pub(crate) id: u64,
    pub(crate) proto: String, // "http"|"tcp"|"https"|"udp"
    pub(crate) peer: String,  // 外部 ip:port
    pub(crate) public_port: u16,
    pub(crate) agent: String,
    pub(crate) tunnel: String,
    pub(crate) remote_port: u16,
    pub(crate) target: String, // local_ip:local_port
    pub(crate) since: i64,
    pub(crate) rx: u64,
    pub(crate) tx: u64,
}

/// 心跳空闲上限（双向共用）：server 每 15s 下发 Ping，agent 侧任何帧都算活；
/// 超过此秒数无任何帧即判半开（server 重启/nginx 不掐下游时 reader 永 pend）。
/// 现场：server 11:29 重启，agent 60s+ 无感知，tm hang。取 45s（3×Ping 周期）。
pub(crate) const IDLE_KICK_SECS: i64 = 45;

/// 纯判定：now-last_seen 超限即僵尸（单测覆盖心跳语义；真实看门狗在 tunnel.rs 主循环用 timeout 实现）。
/// RED 现场：last=0, now=60 -> true；刚活跃 -> false。
#[allow(dead_code)] // 看门狗逻辑在 tunnel.rs 用 timeout 内联实现，此函数只锁语义防回归
pub(crate) fn is_idle_stale(last_seen_unix: i64, now_unix: i64) -> bool {
    now_unix - last_seen_unix > IDLE_KICK_SECS
}

/// 同 hostname 旧会话 id（单 flight 踢人用）：新 Hello 到达即抢路由，旧行必须清，
/// 否则两会话抢流、404/502 来回跳。纯函数单测覆盖。
pub(crate) fn stale_ids_for_hostname(
    agents: &HashMap<String, String>,
    hostname: &str,
) -> Vec<String> {
    agents
        .iter()
        .filter(|(_, h)| h.as_str() == hostname)
        .map(|(id, _)| id.clone())
        .collect()
}

pub(crate) fn traffic_key(hostname: &str, name: &str) -> String {
    format!("{hostname}/{name}")
}

/// 黑洞 key：kudus_drop/{reason}/{subnet}。v4 取 /24，v6 取 /64，防随机源 IP 打爆表。
pub(crate) fn drop_key(reason: &str, peer: &str) -> String {
    // 先按 SocketAddr 解析（"1.2.3.4:5678" / "[2001:db8::1]:443" 都能过）；
    // 失败回退裸 IP / unknown（热路径外，60s tick 才调一次可忽略，但分发循环每包调——保持无分配以外的零开销）。
    if let Ok(sa) = peer.parse::<std::net::SocketAddr>() {
        return match sa.ip() {
            std::net::IpAddr::V4(v) => {
                let o = v.octets();
                format!("kudus_drop/{reason}/{}.{}.{}.0/24", o[0], o[1], o[2])
            }
            std::net::IpAddr::V6(v) => {
                let s = v.segments();
                format!("kudus_drop/{reason}/{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
            }
        };
    }
    if let Ok(std::net::IpAddr::V4(v)) = peer.parse::<std::net::IpAddr>() {
        let o = v.octets();
        return format!("kudus_drop/{reason}/{}.{}.{}.0/24", o[0], o[1], o[2]);
    }
    format!("kudus_drop/{reason}/unknown")
}

/// 采样限流：同 key 60s 最多 1 条 warn。
pub(crate) fn warn_throttled(last_warn: i64, now: i64) -> bool {
    now - last_warn >= 60
}

/// 单 agent egress key 上限（防恶意 agent 刷 key 膨胀 traffic 表）
pub(crate) const EGRESS_KEYS_PER_AGENT: usize = 500;

/// egress tunnel 命名：egress/{host}:{port}，按目标细分。
pub(crate) fn egress_tunnel(host: &str, port: u16) -> String {
    format!("egress/{host}:{port}")
}

/// egress cap 纯函数：输入全表快照（key -> 近N点总量），返回要合并进 other 的 key 列表。
/// 调用方负责 drain + 累加。pure 便于单测。
pub(crate) fn egress_over_cap(totals: &HashMap<String, u64>, cap: usize) -> Vec<String> {
    use std::collections::HashMap as M;
    let mut by_agent: M<String, Vec<(String, u64)>> = M::new();
    for (k, v) in totals {
        if let Some((agent, rest)) = k.split_once("/egress/") {
            if rest != "other" {
                by_agent.entry(agent.to_string()).or_default().push((k.clone(), *v));
            }
        }
    }
    let mut out = vec![];
    for (_, mut v) in by_agent {
        if v.len() > cap {
            v.sort_by(|a, b| b.1.cmp(&a.1));
            out.extend(v[cap..].iter().map(|(k, _)| k.clone()));
        }
    }
    out
}

/// 热路径记录：只做 Mutex + entry +1，不打日志不拿 await 锁。
pub(crate) fn record_drop(s: &Shared, key: String, bytes: u64) {
    if let Ok(mut m) = s.drop_hits.lock() {
        let e = m.entry(key).or_insert((0, 0));
        e.0 = e.0.saturating_add(1);
        e.1 = e.1.saturating_add(bytes);
    }
}

/// 60s tick 把 drop_hits draining 进 traffic：与 tick_from_conns 同节奏 push (ts,包数,字节)。
/// drop 点天然带 ts、无基线问题，不走 seen/last_total，直接 push。
pub(crate) fn tick_drops(
    traffic: &mut HashMap<String, VecDeque<(i64, u64, u64)>>,
    hits: &mut HashMap<String, (u64, u64)>,
    now: i64,
) {
    for (k, (pkts, bytes)) in hits.drain() {
        if pkts == 0 {
            continue;
        }
        let q = traffic.entry(k).or_default();
        q.push_back((now, pkts, bytes));
        trim_traffic(q);
    }
}

/// 增量（饱和减，防累计回绕/重置）
pub(crate) fn minute_delta(prev: (u64, u64), cur: (u64, u64)) -> (u64, u64) {
    (cur.0.saturating_sub(prev.0), cur.1.saturating_sub(prev.1))
}

/// 后 n 个点求和（聚合口径备用；slice_points 内 rchunks 求和是同口径实现）
#[allow(dead_code)]
pub(crate) fn rollup(points: &VecDeque<(i64, u64, u64)>, n: usize) -> (u64, u64) {
    points.iter().rev().take(n).fold((0, 0), |(a, b), (_, x, y)| (a + x, b + y))
}

/// conns 表插入（满 5000 挤掉 id 最小的防 OOM）
pub(crate) fn insert_conn(m: &mut HashMap<u64, ConnInfo>, c: ConnInfo) {
    if m.len() >= CONNS_CAP {
        if let Some(min) = m.keys().min().cloned() {
            m.remove(&min);
        }
    }
    m.insert(c.id, c);
}

pub(crate) fn trim_traffic(v: &mut VecDeque<(i64, u64, u64)>) {
    while v.len() > TRAFFIC_CAP {
        v.pop_front();
    }
}

pub(crate) fn log_ev(s: &S, e: String) {
    tracing::info!("{e}");
    push_ev(s, e);
}

/// 失败路径专用：单次 ERROR + 入 events，避免 log_ev(info) + error 双行刷屏。
pub(crate) fn log_ev_err(s: &S, e: String) {
    tracing::error!("{e}");
    push_ev(s, e);
}

/// WebUI 日志前缀：用 server 本地 wall clock（不用 Utc，否则 HKT 机器上早 8h）。
pub(crate) fn format_ev<Tz: chrono::TimeZone>(t: chrono::DateTime<Tz>, e: &str) -> String
where
    Tz::Offset: std::fmt::Display,
{
    format!("{} {e}", t.format("%m-%d %H:%M:%S"))
}

/// 慢请求判定（纯函数，单测覆盖）：elapsed_ms > threshold_ms 才返回告警行。
/// 根因→修法：/api/tunnels pending 6s 全靠猜——无请求日志、无慢告警、无锁等待可见性。
/// 新语义：所有 /api 请求打耗时日志（中间件），超阈值 warn + 入 events，线上不再靠猜。
pub(crate) fn slow_msg(api: &str, elapsed_ms: u64, threshold_ms: u64) -> Option<String> {
    if elapsed_ms > threshold_ms {
        Some(format!("slow api /api/{api}: {elapsed_ms}ms > {threshold_ms}ms"))
    } else {
        None
    }
}

/// 后台 tick 心跳行（纯函数，单测锁格式）：`tick <name> k=v k=v`。
/// 根因→修法：5s live/60s traffic/30s persist 三个后台循环死掉外面看不出来
/// （无日志、无指标）。新语义：每轮打一行心跳（含关键计数），停摆/卡住一眼可见。
/// debug 级（量大：5s 一行），排查时 `RUST_LOG=debug` 开。
pub(crate) fn tick_heartbeat(name: &str, kvs: &[(&str, usize)]) -> String {
    let parts: Vec<String> = kvs.iter().map(|(k, v)| format!("{k}={v}")).collect();
    format!("tick {name} {}", parts.join(" "))
}

fn push_ev(s: &S, e: String) {
    if let Ok(mut v) = s.events.try_write() {
        v.push(format_ev(chrono::Local::now(), &e));
        if v.len() > 500 {
            let n = v.len() - 500;
            v.drain(..n);
        }
    }
}

/// If server holds desired proxies for this hostname, they win over what the
/// agent reported; otherwise fall back to the reported list.
pub(crate) fn resolve_proxies(desired: Option<Vec<ProxyConfig>>, reported: Vec<ProxyConfig>) -> Vec<ProxyConfig> {
    desired.unwrap_or(reported)
}

/// Replace one agent's routes (domains + ports + info) with `proxies`.
pub(crate) async fn apply_proxies_for_agent(s: &S, aid: &str, proxies: &[ProxyConfig]) {
    {
        let mut dom = s.domains.write().await;
        dom.retain(|_, v| !v.contains(&aid.to_string()));
        for p in proxies.iter().filter(|p| p.enabled) {
            for d in &p.domains {
                let e = dom.entry(d.to_lowercase()).or_default();
                if !e.contains(&aid.to_string()) {
                    e.push(aid.to_string());
                }
            }
        }
    }
    {
        let mut tp = s.tcp_ports.write().await;
        tp.retain(|_, v| !v.contains(&aid.to_string()));
        for p in proxies.iter().filter(|p| p.enabled && p.remote_port > 0) {
            let e = tp.entry(p.remote_port).or_default();
            if !e.contains(&aid.to_string()) {
                e.push(aid.to_string());
            }
        }
    }
    if let Some(h) = s.agents.write().await.get_mut(aid) {
        h.info.proxies = proxies.to_vec();
    }
    for p in proxies.iter().filter(|p| p.enabled && p.remote_port > 0) {
        if p.ptype == "udp" {
            super::ingress::ensure_udp_listener(s, p.remote_port).await;
        } else {
            super::ingress::ensure_tcp_listener(s, p.remote_port).await;
        }
    }
}

pub(crate) type S = Arc<Shared>;

#[derive(Debug, Default, Serialize, Deserialize)]
pub(crate) struct Persisted {
    #[serde(default)]
    pub(crate) totals: HashMap<String, (u64, u64)>,
    #[serde(default)]
    pub(crate) password_hash: String,
    #[serde(default)]
    pub(crate) jwt_secret: String,
}

pub(crate) async fn load_state(data_dir: &str) -> Persisted {
    let p = format!("{data_dir}/state.json");
    match tokio::fs::read_to_string(&p).await {
        Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
        Err(_) => Persisted::default(),
    }
}

pub(crate) fn traffic_path(data_dir: &str) -> String {
    format!("{data_dir}/traffic.json")
}

/// traffic.json 落盘格式：{points: {key: [[rx,tx],...]}, seen: [key,...]}。
/// 旧格式（裸 {key: [...]}）兼容读回：seen 为空，已经有点的 key 重启后首轮
/// 只建基线不 push（不断崖）；全新 key 同样首轮建基线。
#[derive(Default, serde::Serialize, serde::Deserialize)]
struct TrafficFile {
    #[serde(default)]
    points: HashMap<String, Vec<(i64, u64, u64)>>,
    #[serde(default)]
    seen: Vec<String>,
}

/// 旧点（2 元 [rx,tx]，无 ts）-> 新点（ts=0，后续 api 回退估算）
fn upgrade_legacy_points(v: serde_json::Value) -> Option<Vec<(i64, u64, u64)>> {
    let arr = v.as_array()?;
    let mut out = vec![];
    for p in arr {
        let a = p.as_array()?;
        match a.len() {
            2 => out.push((0, a[0].as_u64()?, a[1].as_u64()?)),
            3 => out.push((a[0].as_i64()?, a[1].as_u64()?, a[2].as_u64()?)),
            _ => return None,
        }
    }
    Some(out)
}

/// 启动读回 traffic.json：无文件直接从空开始；坏 json 记一条日志、内存不动。
pub(crate) async fn load_traffic(s: &S, path: &str) {
    let Ok(txt) = tokio::fs::read_to_string(path).await else {
        return;
    };
    // 新格式含 "points" 顶层键；旧格式是裸 {tunnel: [[..]]}。
    // 根因→修法：TrafficFile 全字段 #[serde(default)]，旧文件也能“成功”解析成
    // 空 points——先判键再解析，否则线上旧 traffic.json 重启即丢全部历史点。
    let file: TrafficFile = match serde_json::from_str::<serde_json::Value>(&txt) {
        Ok(v) if v.get("points").is_some() => {
            let pts = v.get("points").cloned().unwrap_or_default();
            let mut points: HashMap<String, Vec<(i64, u64, u64)>> = HashMap::new();
            let mut bad = false;
            if let Some(m) = pts.as_object() {
                for (k, arr) in m {
                    match upgrade_legacy_points(arr.clone()) {
                        Some(p) => { points.insert(k.clone(), p); }
                        None => { bad = true; break; }
                    }
                }
            } else {
                bad = true;
            }
            let seen: Vec<String> = v.get("seen").and_then(|x| serde_json::from_value(x.clone()).ok()).unwrap_or_default();
            if bad {
                log_ev_err(s, "traffic load failed: bad json".into());
                return;
            }
            TrafficFile { points, seen }
        }
        Ok(v) => match v.as_object() {
            Some(m) => {
                let mut points: HashMap<String, Vec<(i64, u64, u64)>> = HashMap::new();
                for (k, arr) in m {
                    match upgrade_legacy_points(arr.clone()) {
                        Some(p) => { points.insert(k.clone(), p); }
                        None => {
                            log_ev_err(s, "traffic load failed: bad json".into());
                            return;
                        }
                    }
                }
                TrafficFile { points, seen: vec![] }
            }
            None => {
                log_ev_err(s, "traffic load failed: bad json".into());
                return;
            }
        },
        Err(_) => {
            log_ev_err(s, "traffic load failed: bad json".into());
            return;
        }
    };
    {
        let mut t = s.traffic.write().await;
        for (k, v) in file.points {
            let mut q: VecDeque<(i64, u64, u64)> = v.into_iter().collect();
            trim_traffic(&mut q);
            t.insert(k, q);
        }
    }
    {
        let mut seen = s.seen_tunnels.write().await;
        // 有点的 key 天然已见（旧格式兼容）；seen 列表是显式补充
        for k in s.traffic.read().await.keys() {
            seen.insert(k.clone());
        }
        for k in file.seen {
            seen.insert(k);
        }
    }
}

pub(crate) async fn save_traffic(s: &S, path: &str) {
    let t = s.traffic.read().await;
    let seen = s.seen_tunnels.read().await;
    let file = TrafficFile {
        points: t.iter().map(|(k, q)| (k.clone(), q.iter().cloned().collect())).collect(),
        seen: seen.iter().cloned().collect(),
    };
    // 根因→修法：旧代码 write 失败直接吞（let _），盘满/权限问题全靠猜。
    match serde_json::to_string(&file) {
        Ok(txt) => {
            if let Err(e) = tokio::fs::write(path, txt).await {
                tracing::warn!("persist traffic.json failed: {e:#}");
            }
        }
        Err(e) => tracing::warn!("persist traffic.json encode failed: {e:#}"),
    }
}

/// tick 一步：pure 版——输入 per-tunnel 当前累计，逐 key 算增量 push。
/// 根因→修法：旧 tick 拿 agent 级累计给该 agent 下每个 proxy 各 push 一份，
/// 多隧道流量翻 N 倍；调用方必须先按 tunnel 归集好 currents 再调此函数。
///
/// currents 只含本轮有连接活动的 tunnel（调用方以 conns 表为准过滤）；
/// 空闲隧道不 push，保持旧点数（断流恢复时前端按缺失点补 0 画线）。
/// pure 聚合：conns 表行 (rx,tx) 按 agent+tunnel 归集，返回每 tunnel 当前累计。
/// tick 时用它生成 currents，空闲隧道自然缺席（不 push）。
pub(crate) fn aggregate_conns(conns: &HashMap<u64, ConnInfo>) -> HashMap<String, (u64, u64)> {
    let mut out: HashMap<String, (u64, u64)> = HashMap::new();
    for c in conns.values() {
        let k = traffic_key(&c.agent, &c.tunnel);
        let e = out.entry(k).or_insert((0, 0));
        e.0 = e.0.saturating_add(c.rx);
        e.1 = e.1.saturating_add(c.tx);
    }
    out
}

/// tick 入口：conns 表行累计 -> per-tunnel 增量 push（聚合+增量一步到位）。
/// 调用方（60s tick）每轮调一次即可；e2e/单测锁死该入口，防旧 fanout 回归。
/// 重启连续性：重启后 conns 表清空、累计从 0 重建——旧逻辑以首轮值建基线后
/// push (0,0)，重启那分钟的流量直接吞掉。`seen` 标记区分“从未见过”与
/// “重启后首次见”：后者不 push，只建基线（不断崖、不吞量、不造假点）。
pub(crate) fn tick_from_conns(
    traffic: &mut HashMap<String, VecDeque<(i64, u64, u64)>>,
    last: &mut HashMap<String, (u64, u64)>,
    seen: &mut std::collections::HashSet<String>,
    conns: &HashMap<u64, ConnInfo>,
) {
    tick_from_conns_at(traffic, last, seen, &aggregate_conns(conns), chrono::Local::now().timestamp());
}

/// 可注入 now 的 tick 入口（单测锁 ts 用；线上走 tick_from_conns 即 now）。
pub(crate) fn tick_from_conns_at(
    traffic: &mut HashMap<String, VecDeque<(i64, u64, u64)>>,
    last: &mut HashMap<String, (u64, u64)>,
    seen: &mut std::collections::HashSet<String>,
    currents: &HashMap<String, (u64, u64)>,
    now: i64,
) {
    tick_traffic(traffic, last, seen, currents, now);
}

pub(crate) fn tick_traffic(
    traffic: &mut HashMap<String, VecDeque<(i64, u64, u64)>>,
    last: &mut HashMap<String, (u64, u64)>,
    seen: &mut std::collections::HashSet<String>,
    currents: &HashMap<String, (u64, u64)>,
    now: i64,
) {
    for (k, cur) in currents {
        // 基线缺失即只建基线不 push，两种情况：
        // 1. 全新 key（seen 无）；2. 重启后（seen 落盘读回但 last_total 是纯内存、已丢）。
        // 根因→修法：旧代码 unwrap_or(*cur) 在情况 2 下 push (0,0) 假点，图表重启处断崖。
        if !seen.contains(k.as_str()) || !last.contains_key(k.as_str()) {
            seen.insert(k.clone());
            last.insert(k.clone(), *cur);
            traffic.entry(k.clone()).or_default();
            continue;
        }
        let prev = last.get(k).cloned().unwrap_or(*cur);
        tick_one(traffic.entry(k.clone()).or_default(), prev, *cur, now);
        last.insert(k.clone(), *cur);
    }
}

/// tick 一步：算增量、push (ts,rx,tx) 队尾、裁剪。返回本分钟增量。
pub(crate) fn tick_one(
    q: &mut VecDeque<(i64, u64, u64)>,
    prev: (u64, u64),
    cur: (u64, u64),
    now: i64,
) -> (u64, u64) {
    let d = minute_delta(prev, cur);
    q.push_back((now, d.0, d.1));
    trim_traffic(q);
    d
}

pub(crate) async fn save_state(s: &S) {
    let totals = s.totals.read().await.clone();
    let password_hash = s.password_hash.read().await.clone();
    let p = Persisted {
        totals,
        password_hash,
        jwt_secret: s.jwt_secret.clone(),
    };
    let path = format!("{}/state.json", s.data_dir);
    match serde_json::to_string_pretty(&p) {
        Ok(txt) => {
            if let Err(e) = tokio::fs::write(&path, txt).await {
                tracing::warn!("persist state.json failed: {e:#}");
            }
        }
        Err(e) => tracing::warn!("persist state.json encode failed: {e:#}"),
    }
}

// ================= run =================

#[cfg(test)]
pub(crate) async fn test_shared() -> std::sync::Arc<Shared> {
    // agent-admin 单测用最小 Shared（allow_agent_admin 默认关）。
    std::sync::Arc::new(Shared { allow_agent_admin: false, ..Default::default() })
}

#[cfg(test)]
pub(crate) async fn test_shared_admin() -> std::sync::Arc<Shared> {
    // 开关打开版（构造时即开，Arc 内字段不可事后改）。
    std::sync::Arc::new(Shared { allow_agent_admin: true, ..Default::default() })
}

/// overview 快照组装（纯函数，可单测）：agents 快照 + 原子计数合并。
/// 根因→修法：旧 api_overview 在 agents.read() 临界区内调 chrono::Utc::now()
/// 且 info.rx/tx 靠每包 write 更新，flood 下读饿死。现快照只 clone，
/// rx/tx = info 基线 + ctr 原子当前值（swap 不抢，load 即走）。
pub(crate) fn snapshot_agents(
    agents: &HashMap<String, AgentHandle>,
    now: chrono::DateTime<chrono::Utc>,
) -> Vec<AgentInfo> {
    agents
        .values()
        .map(|h| {
            let mut i = h.info.clone();
            i.online_secs = (now - h.connected_at).num_seconds();
            i.rx_bytes += h.ctr_rx.load(std::sync::atomic::Ordering::Relaxed);
            i.tx_bytes += h.ctr_tx.load(std::sync::atomic::Ordering::Relaxed);
            let rtt = h.ctr_rtt.load(std::sync::atomic::Ordering::Relaxed);
            if rtt >= 0 {
                i.rtt_ms = rtt;
            }
            i
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    /// desired 清空（hostname 不在表里）必须推出空表，而不是“不推”。
    /// 旧实现只遍历 fresh，空表时连循环都不进 -> 在线 agent 的隧道永远留着。
    #[test]
    fn proxies_to_push_clears_when_hostname_absent() {
        let mut desired: HashMap<String, Vec<ProxyConfig>> = HashMap::new();
        let old = ProxyConfig {
            name: "web".into(), ptype: "http".into(), local_ip: "127.0.0.1".into(),
            local_port: 80, remote_port: 0, domains: vec!["w.e2e.test".into()],
            set_x_forwarded_proto: None, basic_auth: None, enabled: true,
            link_agent: String::new(), link_host: String::new(), link_port: 0,
            rate_limit: None,
        };
        // 有该 hostname：推它自己的表
        desired.insert("e2e".into(), vec![old.clone()]);
        assert_eq!(proxies_to_push(&desired, "e2e"), vec![old.clone()]);
        // 清空 desired：必须推空（显式清空），否则 agent 侧路由残留
        desired.clear();
        assert!(proxies_to_push(&desired, "e2e").is_empty(), "清空 desired 必须推空表");
        // 完全没列出的 hostname 同样推空
        assert!(proxies_to_push(&desired, "other").is_empty());
    }
    #[test]
    fn snapshot_agents_merges_atomic_counters() {
        // HK 2026-10-23：deliver/写泵的每包增量只落 ctr_*，5s tick 才合进 info。
        // overview 必须 info 基线 + ctr 实时值，否则 5s 窗内流量不可见、rtt 旧值。
        let mut agents: HashMap<String, AgentHandle> = HashMap::new();
        agents.insert("a1".into(), AgentHandle {
            info: AgentInfo {
                agent_id: "a1".into(), hostname: "h".into(), version: "v".into(),
                online_secs: 0, rtt_ms: -1, rx_bytes: 100, tx_bytes: 200, proxies: vec![],
            },
            connected_at: chrono::Utc::now(),
            ctr_rx: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(50)),
            ctr_tx: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(70)),
            ctr_rtt: std::sync::Arc::new(std::sync::atomic::AtomicI64::new(3000)),
            ctl: tokio::sync::mpsc::unbounded_channel().0,
            incoming: Default::default(),
            pending: Default::default(),
        });
        let list = super::snapshot_agents(&agents, chrono::Utc::now());
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].rx_bytes, 150); // 100 基线 + 50 未合账
        assert_eq!(list[0].tx_bytes, 270);
        assert_eq!(list[0].rtt_ms, 3000); // ctr 新值覆盖 info 旧值
    }
    fn seen_for_test() -> std::collections::HashSet<String> { Default::default() }
    fn seen_with(keys: &[&str]) -> std::collections::HashSet<String> { keys.iter().map(|k| k.to_string()).collect() }
    #[test]
    fn egress_tunnel_namespaced() {
        assert_eq!(egress_tunnel("tracker.example.com", 443), "egress/tracker.example.com:443");
    }

    #[test]
    fn egress_cap_overflow() {
        // 600 个 key → 超 cap，溢出 100 个；量最小的被挤掉，量最大的保留
        let mut totals: HashMap<String, u64> = HashMap::new();
        for i in 0..600 {
            totals.insert(format!("minipc7s/egress/10.0.0.1:{i}"), i as u64);
        }
        let over = egress_over_cap(&totals, EGRESS_KEYS_PER_AGENT);
        assert_eq!(over.len(), 100);
        assert!(over.contains(&"minipc7s/egress/10.0.0.1:0".to_string()));
        assert!(!over.contains(&"minipc7s/egress/10.0.0.1:599".to_string()));
        // 非 egress key 不参与
        totals.insert("minipc7s/trans-bt".into(), 999999);
        assert_eq!(egress_over_cap(&totals, EGRESS_KEYS_PER_AGENT).len(), 100);
        // egress/other 本身不计入 cap
        totals.insert("minipc7s/egress/other".into(), 1);
        assert_eq!(egress_over_cap(&totals, EGRESS_KEYS_PER_AGENT).len(), 100);
    }

    #[test]
    fn tick_drops_push_and_drain() {
        let mut tr: HashMap<String, VecDeque<(i64, u64, u64)>> = HashMap::new();
        let mut hits = HashMap::new();
        hits.insert("kudus_drop/short/1.2.3.0/24".into(), (10u64, 500u64));
        tick_drops(&mut tr, &mut hits, 1700);
        assert!(hits.is_empty());
        let q = &tr["kudus_drop/short/1.2.3.0/24"];
        assert_eq!(q.len(), 1);
        assert_eq!(q[0], (1700, 10, 500));
    }

    #[test]
    fn drop_key_buckets_subnet() {
        assert_eq!(drop_key("short", "1.2.3.4:5678"), "kudus_drop/short/1.2.3.0/24");
        assert_eq!(drop_key("undecryptable", "[2001:db8::1]:443"), "kudus_drop/undecryptable/2001:db8:0:0::/64");
        assert_eq!(drop_key("bad_hdr", "garbage"), "kudus_drop/bad_hdr/unknown");
    }

    #[test]
    fn warn_throttle_60s() {
        assert!(warn_throttled(0, 61));
        assert!(!warn_throttled(10, 69));
        assert!(warn_throttled(10, 70));
    }

    #[test]
    fn state_serde_compat() {
        let p: Persisted = serde_json::from_str(r#"{"totals":{"h":[1,2]}}"#).unwrap();
        assert_eq!(p.totals["h"], (1, 2));
        assert!(p.password_hash.is_empty());
        assert!(p.jwt_secret.is_empty());
    }

    #[tokio::test]
    async fn jwt_secret_persists_across_restart() {
        // 根因→修法：jwt_secret 曾每次启动 new_v4，重启后旧 cookie/token 全作废。
        // 必须落盘复用：旧 state.json 无此字段时为空（兼容），运行时生成后 save/load 回来不变。
        let dir = std::env::temp_dir().join(format!("nt-test-{}", uuid::Uuid::new_v4()));
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let s: S = Arc::new(Shared {
            data_dir: dir.to_str().unwrap().into(),
            jwt_secret: "sec-abc".into(),
            ..Default::default()
        });
        save_state(&s).await;
        let back = load_state(dir.to_str().unwrap()).await;
        assert_eq!(back.jwt_secret, "sec-abc");
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn save_load_state_roundtrip() {
        let dir = std::env::temp_dir().join(format!("nt-test-{}", uuid::Uuid::new_v4()));
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let s: S = Arc::new(Shared {
            data_dir: dir.to_str().unwrap().into(),
            ..Default::default()
        });
        s.totals.write().await.insert("h".into(), (10, 20));
        *s.password_hash.write().await = "hash".into();
        save_state(&s).await;
        let back = load_state(dir.to_str().unwrap()).await;
        assert_eq!(back.totals["h"], (10, 20));
        assert_eq!(back.password_hash, "hash");
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }
    #[test]
    fn tick_from_conns_end_to_end_no_fanout() {
        // tick 入口：conns 表 -> per-tunnel 增量，一步到位。
        // snail 7 隧道只有 trans-bt-tcp 有 2 条连接跑量，其余 0：
        // 有量只记一条，无量不 push（旧代码 7 条各记一份）。
        let mut m: HashMap<u64, ConnInfo> = HashMap::new();
        let row = |id, tunnel: &str, rx, tx| ConnInfo {
            id,
            proto: "tcp".into(),
            peer: "1.2.3.4:5".into(),
            public_port: 51413,
            agent: "snail-kkito".into(),
            tunnel: tunnel.into(),
            remote_port: 51413,
            target: "172.28.0.10:51413".into(),
            since: 0,
            rx,
            tx,
        };
        m.insert(1, row(1, "trans-bt-tcp", 1000, 2000));
        m.insert(2, row(2, "trans-bt-tcp", 500, 500));
        let mut traffic: HashMap<String, VecDeque<(i64, u64, u64)>> = HashMap::new();
        let mut last: HashMap<String, (u64, u64)> = HashMap::new();
        let mut seen = seen_for_test();
        // 首轮建基线：只记 last，不 push 假点（根因→修法：旧代码 push (0,0)，
        // 重启后图表多个 0 点断崖；新语义首轮序列为空）
        super::tick_from_conns(&mut traffic, &mut last, &mut seen, &m);
        assert!(traffic["snail-kkito/trans-bt-tcp"].is_empty());
        m.get_mut(&1).unwrap().rx += 100;
        m.get_mut(&1).unwrap().tx += 200;
        super::tick_from_conns(&mut traffic, &mut last, &mut seen, &m);
        let last_pt = *traffic["snail-kkito/trans-bt-tcp"].back().unwrap();
        assert_eq!((last_pt.1, last_pt.2), (100, 200));
        assert!(last_pt.0 > 0, "线上 tick 点必须带真实 ts");
        // 其他 6 条隧道一行都没有
        assert_eq!(traffic.len(), 1);
    }
    #[test]
    fn aggregate_conns_sums_per_tunnel() {
        // conns 行按 agent+tunnel 归集：同 tunnel 多连接求和，不同 tunnel 分开。
        // link 行 rx/tx 为 0（双 pump 未记连接行），归集后为 0 点，不污染。
        let mut m: HashMap<u64, ConnInfo> = HashMap::new();
        let row = |id, agent: &str, tunnel: &str, rx, tx| ConnInfo {
            id,
            proto: "tcp".into(),
            peer: "1.2.3.4:5".into(),
            public_port: 80,
            agent: agent.into(),
            tunnel: tunnel.into(),
            remote_port: 80,
            target: "127.0.0.1:80".into(),
            since: 0,
            rx,
            tx,
        };
        m.insert(1, row(1, "h", "web", 10, 20));
        m.insert(2, row(2, "h", "web", 5, 5));
        m.insert(3, row(3, "h", "db", 7, 7));
        m.insert(4, row(4, "h", "dblink", 0, 0)); // link 未记行
        let out = super::aggregate_conns(&m);
        assert_eq!(out["h/web"], (15, 25));
        assert_eq!(out["h/db"], (7, 7));
        assert_eq!(out["h/dblink"], (0, 0));
    }
    #[test]
    fn tick_skips_idle_tunnels_and_zero_fills_on_return() {
        // 空闲隧道（无流量、conns 表无该 tunnel 行）本轮不 push，保持旧点数；
        // 断流后恢复时补 0 点对齐，避免 WebUI 折线断裂。
        // 此单测定 tick 入口的过滤语义：只 push 有增量或有连接的行。
        let mut traffic: HashMap<String, VecDeque<(i64, u64, u64)>> = HashMap::new();
        traffic.insert("h/idle".into(), [(1700000000i64, 1u64, 1u64)].into_iter().collect());
        let mut last: HashMap<String, (u64, u64)> = HashMap::new();
        last.insert("h/idle".into(), (100, 100));
        // idle 无增量且本轮 conns 无此 tunnel：跳过，不 push
        let currents: HashMap<String, (u64, u64)> = HashMap::new();
        let mut seen = seen_with(&["h/idle"]);
        super::tick_traffic(&mut traffic, &mut last, &mut seen, &currents, 0);
        assert_eq!(traffic["h/idle"].len(), 1);
    }
    #[test]
    fn tick_first_seen_builds_baseline_without_fake_point() {
        // 回归：重启后 conns 累计从 0 重建，已见 key 首轮只建基线不 push。
        // 旧代码首轮 push (0,0) 假点，图表重启处多个 0 断崖；新语义序列保持为空，
        // 次轮才 push 真增量。
        let mut traffic: HashMap<String, VecDeque<(i64, u64, u64)>> = HashMap::new();
        let mut last: HashMap<String, (u64, u64)> = HashMap::new();
        let mut seen = seen_with(&["h/w"]);
        let currents: HashMap<String, (u64, u64)> = [("h/w".into(), (5000, 9000))].into();
        // 模拟重启：last 丢了但 seen 还在（随 traffic.json 读回）
        super::tick_traffic(&mut traffic, &mut last, &mut seen, &currents, 0);
        assert!(traffic["h/w"].is_empty(), "首轮不应 push 假点");
        // 全新 key：同样只建基线
        let mut traffic2: HashMap<String, VecDeque<(i64, u64, u64)>> = HashMap::new();
        let mut last2: HashMap<String, (u64, u64)> = HashMap::new();
        let mut seen2 = seen_for_test();
        super::tick_traffic(&mut traffic2, &mut last2, &mut seen2, &currents, 0);
        assert!(traffic2["h/w"].is_empty());
        assert!(seen2.contains("h/w"));
    }
    #[test]
    fn tick_records_per_tunnel_delta_without_fanout() {
        // 根因→修法：60s tick 曾拿 agent 级累计 (rx,tx) 给该 agent 下每个
        // proxy 各 push 一份相同增量——snail 7 隧道 traffic.json 数组完全相同。
        // tick 输入必须是 per-tunnel 当前累计，各记各的增量。
        let mut traffic: HashMap<String, VecDeque<(i64, u64, u64)>> = HashMap::new();
        let mut last: HashMap<String, (u64, u64)> = HashMap::new();
        last.insert("h/A".into(), (100, 200));
        last.insert("h/B".into(), (100, 200));
        let mut seen = seen_with(&["h/A", "h/B"]);
        let currents: HashMap<String, (u64, u64)> =
            [("h/A".into(), (150, 260)), ("h/B".into(), (100, 200))].into();
        super::tick_traffic(&mut traffic, &mut last, &mut seen, &currents, 0);
        // A 只记自己的 50/60；B 无流量记 0（旧代码会给 B 也记 50/60）
        assert_eq!((traffic["h/A"].back().unwrap().1, traffic["h/A"].back().unwrap().2), (50, 60));
        assert_eq!((traffic["h/B"].back().unwrap().1, traffic["h/B"].back().unwrap().2), (0, 0));
    }
    #[test]
    fn traffic_points_carry_wallclock_ts() {
        // 根因→修法：流量点只存增量不存时间，api_traffic 用 now-len*60 反推，
        // 重启/断流后旧点被画到错误时间（18:12 高峰实为 17 点旧账错位）。
        // 新语义：每点带落盘时的 wall clock ts，重启读回后时间不错位。
        let mut traffic: HashMap<String, VecDeque<(i64, u64, u64)>> = HashMap::new();
        let mut last: HashMap<String, (u64, u64)> = HashMap::new();
        let mut seen = seen_for_test();
        let t0: i64 = 1_760_933_880; // 2026-10-20 18:00:00 HKT 前后
        super::tick_from_conns_at(&mut traffic, &mut last, &mut seen, &HashMap::from([("h/w".into(), (5000u64, 9000u64))]), t0);
        super::tick_from_conns_at(&mut traffic, &mut last, &mut seen, &HashMap::from([("h/w".into(), (5100u64, 9200u64))]), t0 + 60);
        let q = &traffic["h/w"];
        assert_eq!(q.len(), 1);
        assert_eq!(q[0].0, t0 + 60, "点必须带 tick 的 wall clock ts");
        assert_eq!((q[0].1, q[0].2), (100, 200));
    }
    #[test]
    fn tick_heartbeat_line_has_expected_shape() {
        // 根因→修法：后台 tick（5s live/60s traffic/30s persist）死掉外面看不出来
        // （比如 conns 锁卡住，tick 停摆，无任何日志）。新语义：每个 tick 打一行
        // 心跳（含关键计数），停摆一眼可见。此单测锁死心跳行格式函数。
        let line = super::tick_heartbeat("live", &[("conns", 12), ("agents", 2)]);
        assert!(line.contains("tick live"), "{line}");
        assert!(line.contains("conns=12"), "{line}");
        assert!(line.contains("agents=2"), "{line}");
    }
    #[test]
    fn slow_msg_fires_only_over_threshold() {
        // 根因→修法：/api/tunnels pending 6s 全靠猜（无请求日志、无慢告警）。
        // 新语义：纯函数判定慢请求，handler 统一打慢日志，线上不再靠猜。
        assert!(super::slow_msg("tunnels", 600, 500).is_some());
        assert!(super::slow_msg("tunnels", 100, 500).is_none());
        assert!(super::slow_msg("tunnels", 500, 500).is_none());
    }
    #[test]
    fn traffic_pure_fns() {
        // Task1 基座：key/增量/加总/裁剪纯函数
        assert_eq!(super::traffic_key("h", "web"), "h/web");
        assert_eq!(super::minute_delta((100, 200), (150, 250)), (50, 50));
        assert_eq!(super::minute_delta((100, 200), (90, 250)), (0, 50)); // 回绕饱和
        let v: VecDeque<(i64, u64, u64)> = (0..10).map(|i| (0, i, i * 2)).collect();
        assert_eq!(super::rollup(&v, 3), (7 + 8 + 9, 14 + 16 + 18));
        let mut big: VecDeque<(i64, u64, u64)> = (0..43_300).map(|i| (0, i as u64, 0)).collect();
        super::trim_traffic(&mut big);
        assert_eq!(big.len(), 43_200);
    }
    #[test]
    fn ev_stamp_keeps_wall_clock_offset() {
        // 根因→修法：push_ev 曾用 chrono::Utc::now()，WebUI 日志时间比系统本地慢 8h
        //（如 natproxy HKT 18:00 打成 10:00）。format_ev 取本地 wall clock，
        // 此例用 +08:00 固定时区锁定行为：旧代码传 Utc 时间会打出 10:00:45 而变红。
        let hk = chrono::FixedOffset::east_opt(8 * 3600).unwrap();
        let t = hk.with_ymd_and_hms(2026, 10, 19, 18, 0, 45).unwrap();
        assert_eq!(format_ev(t, "x"), "10-19 18:00:45 x");
    }

    #[tokio::test]
    async fn push_ev_prefix_matches_local_now() {
        // 接线回归：push_ev 必须用本地时间打前缀（容忍分钟边界 60s）。
        let s: S = Arc::new(Shared::default());
        push_ev(&s, "hello".into());
        let v = s.events.read().await.clone();
        assert_eq!(v.len(), 1);
        let now = chrono::Local::now();
        let m0 = now.format("%m-%d %H:%M").to_string();
        let m1 = (now - chrono::Duration::seconds(60)).format("%m-%d %H:%M").to_string();
        assert!(v[0].starts_with(&m0) || v[0].starts_with(&m1), "got: {}", v[0]);
        assert!(v[0].ends_with("hello"));
    }

    #[tokio::test]
    async fn traffic_json_roundtrip_and_bad_file() {
        let dir = std::env::temp_dir().join(format!("nt-traf-{}", uuid::Uuid::new_v4()));
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let p = dir.join("traffic.json").to_str().unwrap().to_string();
        let s: S = Arc::new(Shared::default());
        s.traffic.write().await.insert("h/web".into(), [(1700000000i64, 1u64, 2u64)].into_iter().collect());
        super::save_traffic(&s, &p).await;
        let s2: S = Arc::new(Shared::default());
        super::load_traffic(&s2, &p).await;
        assert_eq!(s2.traffic.read().await["h/web"].len(), 1);
        // seen 随落盘：读回后已知 key 在内存
        assert!(s2.seen_tunnels.read().await.contains("h/web"));
        // 旧格式兼容：裸 {key: [[..]]} 必须读回点（根因→修法：TrafficFile 全 default
        // 会把旧文件“成功”解析成空 points，线上 traffic.json 重启即丢全部历史）
        tokio::fs::write(&p, br#"{"h/old":[[5,6],[7,8]]}"#).await.unwrap();
        let s3: S = Arc::new(Shared::default());
        super::load_traffic(&s3, &p).await;
        assert_eq!(s3.traffic.read().await["h/old"].len(), 2);
        assert!(s3.seen_tunnels.read().await.contains("h/old"));
        // 坏文件：不动内存、不 panic
        tokio::fs::write(&p, b"[[[broken").await.unwrap();
        super::load_traffic(&s3, &p).await;
        assert_eq!(s3.traffic.read().await["h/old"].len(), 2);
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }
    #[test]
    fn idle_kick_threshold() {
        // RED 现场：server 11:29 重启，agent reader 永 pend、无任何帧。
        // 60s 无声 -> 僵尸必须踢；刚活跃（5s 内有帧）-> 活着。
        assert!(super::is_idle_stale(0, 60));
        assert!(super::is_idle_stale(0, 46));
        assert!(!super::is_idle_stale(0, 45));
        assert!(!super::is_idle_stale(100, 105));
    }

    #[test]
    fn same_hostname_old_session_is_stale() {
        // 新 Hello 同 hostname 时旧 agent_id 必须清（单 flight），否则两会话抢流。
        let mut m: HashMap<String, String> = HashMap::new();
        m.insert("old-id".into(), "snail".into());
        m.insert("other".into(), "macmini".into());
        assert_eq!(super::stale_ids_for_hostname(&m, "snail"), vec!["old-id".to_string()]);
        assert!(super::stale_ids_for_hostname(&m, "nobody").is_empty());
    }

    #[test]
    fn conns_cap_evicts_oldest() {
        let mut m: HashMap<u64, super::ConnInfo> = HashMap::new();
        for i in 0..(super::CONNS_CAP + 10) {
            super::insert_conn(
                &mut m,
                super::ConnInfo {
                    id: i as u64,
                    proto: "tcp".into(),
                    peer: "1.1.1.1:2".into(),
                    public_port: 2222,
                    agent: "h".into(),
                    tunnel: "t".into(),
                    remote_port: 2222,
                    target: "127.0.0.1:80".into(),
                    since: 0,
                    rx: 0,
                    tx: 0,
                },
            );
        }
        assert_eq!(m.len(), super::CONNS_CAP);
        assert!(!m.contains_key(&0)); // 最老的被挤掉
    }
    #[test]
    fn resolve_prefers_desired() {
        let want = vec![ProxyConfig {
            name: "d".into(),
            ptype: "http".into(),
            local_ip: "127.0.0.1".into(),
            local_port: 1,
            domains: vec![],
            remote_port: 0,
            set_x_forwarded_proto: None,
            basic_auth: None,
            enabled: true,
            link_agent: String::new(),
            link_host: String::new(),
            link_port: 0,
            rate_limit: None,
        }];
        assert_eq!(resolve_proxies(Some(want.clone()), vec![]).len(), 1);
        assert_eq!(resolve_proxies(Some(want.clone()), vec![])[0].name, "d");
        assert!(resolve_proxies(None, vec![]).is_empty());
    }


    #[test]
    fn tunnel_stats_accumulate_and_drain() {
        let mut st = super::TunnelStats::default();
        st.accepts += 2;
        st.closes += 1;
        st.rx += 100;
        st.tx += 200;
        st.stick += 1;
        assert_eq!(st.accepts, 2);
        assert_eq!(st.closes, 1);
        assert_eq!(st.rx, 100);
        assert_eq!(st.tx, 200);
        assert_eq!(st.stick, 1);
    }

    #[test]
    fn tunnel_stats_drain_returns_and_clears() {
        let mut m: std::collections::HashMap<String, super::TunnelStats> =
            std::collections::HashMap::new();
        let e = m.entry("a/bt".into()).or_default();
        e.accepts = 5;
        e.rx = 1024;
        let drained = super::drain_tunnel_stats(&mut m);
        assert_eq!(drained.len(), 1);
        let s = &drained["a/bt"];
        assert_eq!(s.accepts, 5);
        assert_eq!(s.rx, 1024);
        assert!(m.is_empty(), "取走后必须清空，下轮重新累计");
    }

    #[test]
    fn tunnel_stats_format_human_bytes() {
        assert_eq!(super::fmt_bytes(0), "0B");
        assert_eq!(super::fmt_bytes(1023), "1023B");
        assert_eq!(super::fmt_bytes(1024), "1.0KB");
        assert_eq!(super::fmt_bytes(1024 * 1024 * 12 + 1024 * 300), "12.3MB");
    }
}

/// desired reload 后应推给某个在线 hostname 的代理表。
///
/// 根因→修法：原 `api_desired_reload` 只遍历 `fresh`（新 desired 里存在的 hostname），
/// 于是把 desired 改成空表（清空所有隧道）时循环一次都不走 —— 在线 agent 收不到
/// 空 Config，`s.desired` 空了但 `agents[].info.proxies` 仍是旧的，隧道照旧可访问。
/// 表现为 e2e `local_ingress_http_names` 里“清空后路由不消失”（改前偶发、全量必红）。
///
/// 语义：desired 里列出该 hostname → 用它；未列出 → 推空表（显式清空）。
pub(crate) fn proxies_to_push(desired: &HashMap<String, Vec<ProxyConfig>>, hostname: &str) -> Vec<ProxyConfig> {
    desired.get(hostname).cloned().unwrap_or_default()
}
