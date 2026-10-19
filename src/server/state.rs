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
    pub(crate) ctl: mpsc::UnboundedSender<ServerMsg>,
    pub(crate) incoming: Arc<RwLock<HashMap<u32, mpsc::UnboundedSender<Vec<u8>>>>>,
    /// Binary 早到缓存：egress Open 与首包背靠背时，占位注册前的包先存此表，
    /// 拨号泵启动后 drain 写给公网（与 agent 侧 Ctx.pending 对称）。
    pub(crate) pending: Arc<RwLock<HashMap<u32, Vec<Vec<u8>>>>>,
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
    pub(crate) totals: RwLock<HashMap<String, (u64, u64)>>, // hostname -> (rx,tx) persisted
    pub(crate) data_dir: String,
    pub(crate) desired: RwLock<HashMap<String, Vec<ProxyConfig>>>,
    pub(crate) desired_path: String,
    /// 分钟流量点：key = "hostname/proxy名" -> VecDeque<(rx增量,tx增量)>，cap 43200（30天）
    pub(crate) traffic: RwLock<HashMap<String, VecDeque<(u64, u64)>>>,
    /// 上分钟累计快照：key 同 traffic，用于算增量
    pub(crate) last_total: RwLock<HashMap<String, (u64, u64)>>,
    /// 当前连接快照：key = conn id（Task3 连接插桩消费）
    #[allow(dead_code)]
    pub(crate) conns: RwLock<HashMap<u64, ConnInfo>>,
    /// --listen 解析出的公网端口（Task3 HTTP fallback 连接行用）
    #[allow(dead_code)]
    pub(crate) public_port: u16,
}

/// 30天分钟点上限
pub(crate) const TRAFFIC_CAP: usize = 43_200;
/// 当前连接表上限（超了挤掉 id 最小的）；Task3 连接插桩消费
#[allow(dead_code)]
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

pub(crate) fn traffic_key(hostname: &str, name: &str) -> String {
    format!("{hostname}/{name}")
}

/// 增量（饱和减，防累计回绕/重置）
pub(crate) fn minute_delta(prev: (u64, u64), cur: (u64, u64)) -> (u64, u64) {
    (cur.0.saturating_sub(prev.0), cur.1.saturating_sub(prev.1))
}

/// 后 n 个点求和（Task4 /api/traffic hour/day 加总用）
#[allow(dead_code)]
pub(crate) fn rollup(points: &VecDeque<(u64, u64)>, n: usize) -> (u64, u64) {
    points.iter().rev().take(n).fold((0, 0), |(a, b), (x, y)| (a + x, b + y))
}

pub(crate) fn trim_traffic(v: &mut VecDeque<(u64, u64)>) {
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

/// 启动读回 traffic.json：无文件直接从空开始；坏 json 记一条日志、内存不动。
pub(crate) async fn load_traffic(s: &S, path: &str) {
    let Ok(txt) = tokio::fs::read_to_string(path).await else {
        return;
    };
    let Ok(m): Result<HashMap<String, Vec<(u64, u64)>>, _> = serde_json::from_str(&txt) else {
        log_ev_err(s, "traffic load failed: bad json".into());
        return;
    };
    let mut t = s.traffic.write().await;
    for (k, v) in m {
        let mut q: VecDeque<(u64, u64)> = v.into_iter().collect();
        trim_traffic(&mut q);
        t.insert(k, q);
    }
}

pub(crate) async fn save_traffic(s: &S, path: &str) {
    let t = s.traffic.read().await;
    let m: HashMap<&String, Vec<(u64, u64)>> =
        t.iter().map(|(k, q)| (k, q.iter().cloned().collect())).collect();
    if let Ok(txt) = serde_json::to_string(&m) {
        let _ = tokio::fs::write(path, txt).await;
    }
}

/// tick 一步：算增量、push 队尾、裁剪。返回本分钟增量。
pub(crate) fn tick_one(
    q: &mut VecDeque<(u64, u64)>,
    prev: (u64, u64),
    cur: (u64, u64),
) -> (u64, u64) {
    let d = minute_delta(prev, cur);
    q.push_back(d);
    trim_traffic(q);
    d
}

pub(crate) async fn save_state(s: &S) {
    let totals = s.totals.read().await.clone();
    let password_hash = s.password_hash.read().await.clone();
    let p = Persisted {
        totals,
        password_hash,
    };
    let path = format!("{}/state.json", s.data_dir);
    if let Ok(txt) = serde_json::to_string_pretty(&p) {
        let _ = tokio::fs::write(&path, txt).await;
    }
}

// ================= run =================

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    #[test]
    fn state_serde_compat() {
        let p: Persisted = serde_json::from_str(r#"{"totals":{"h":[1,2]}}"#).unwrap();
        assert_eq!(p.totals["h"], (1, 2));
        assert!(p.password_hash.is_empty());
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
    fn traffic_pure_fns() {
        // Task1 基座：key/增量/加总/裁剪纯函数
        assert_eq!(super::traffic_key("h", "web"), "h/web");
        assert_eq!(super::minute_delta((100, 200), (150, 250)), (50, 50));
        assert_eq!(super::minute_delta((100, 200), (90, 250)), (0, 50)); // 回绕饱和
        let v: VecDeque<(u64, u64)> = (0..10).map(|i| (i, i * 2)).collect();
        assert_eq!(super::rollup(&v, 3), (7 + 8 + 9, 14 + 16 + 18));
        let mut big: VecDeque<(u64, u64)> = (0..43_300).map(|i| (i as u64, 0)).collect();
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
        s.traffic.write().await.insert("h/web".into(), [(1u64, 2u64)].into_iter().collect());
        super::save_traffic(&s, &p).await;
        let s2: S = Arc::new(Shared::default());
        super::load_traffic(&s2, &p).await;
        assert_eq!(s2.traffic.read().await["h/web"].len(), 1);
        // 坏文件：不动内存、不 panic
        tokio::fs::write(&p, b"[[[broken").await.unwrap();
        super::load_traffic(&s2, &p).await;
        assert_eq!(s2.traffic.read().await["h/web"].len(), 1);
        let _ = tokio::fs::remove_dir_all(&dir).await;
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
        }];
        assert_eq!(resolve_proxies(Some(want.clone()), vec![]).len(), 1);
        assert_eq!(resolve_proxies(Some(want.clone()), vec![])[0].name, "d");
        assert!(resolve_proxies(None, vec![]).is_empty());
    }

}
