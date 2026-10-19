//! server 全局状态：Shared/AgentInfo/路由表/持久化 + 小纯函数。
use crate::common::proto::*;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
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

fn push_ev(s: &S, e: String) {
    if let Ok(mut v) = s.events.try_write() {
        v.push(format!("{} {e}", chrono::Utc::now().format("%m-%d %H:%M:%S")));
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
