//! Server-side desired tunnel state: hostname -> proxies (TOML persisted).
use super::proto::ProxyConfig;
use std::collections::HashMap;

#[derive(Debug, Default)]
pub struct DesiredStore {
    pub path: String,
    data: HashMap<String, Vec<ProxyConfig>>,
}

#[derive(serde::Serialize, serde::Deserialize, Default)]
struct File {
    #[serde(default)]
    agents: HashMap<String, Vec<ProxyConfig>>,
}

impl DesiredStore {
    pub fn load(path: &str) -> Self {
        let data = std::fs::read_to_string(path)
            .ok()
            .and_then(|s| {
                toml::from_str::<File>(&s)
                    .map_err(|e| tracing::warn!("desired load parse failed ({path}): {e}"))
                    .ok()
            })
            .map(|f| f.agents)
            .unwrap_or_default();
        Self {
            path: path.into(),
            data,
        }
    }
    pub fn save(&self) {
        let f = File {
            agents: self.data.clone(),
        };
        if let Ok(s) = toml::to_string_pretty(&f) {
            let _ = std::fs::write(&self.path, s);
        }
    }
    pub fn get(&self, host: &str) -> Vec<ProxyConfig> {
        self.data.get(host).cloned().unwrap_or_default()
    }
    pub fn all(&self) -> HashMap<String, Vec<ProxyConfig>> {
        self.data.clone()
    }
    pub fn set(&mut self, host: String, v: Vec<ProxyConfig>) {
        self.data.insert(host, v);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn desired_roundtrip() {
        let dir = std::env::temp_dir().join(format!("nt-des-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("desired.toml");
        let mut st = DesiredStore::load(p.to_str().unwrap());
        assert!(st.get("h1").is_empty());
        st.set(
            "h1".into(),
            vec![ProxyConfig {
                name: "w".into(),
                ptype: "http".into(),
                local_ip: "127.0.0.1".into(),
                local_port: 80,
                domains: vec!["a.test".into()],
                remote_port: 0,
                set_x_forwarded_proto: None,
            basic_auth: None,
                enabled: true,
            link_agent: String::new(),
            link_host: String::new(),
            link_port: 0,
            }],
        );
        st.save();
        let st2 = DesiredStore::load(p.to_str().unwrap());
        assert_eq!(st2.get("h1").len(), 1);
        assert_eq!(st2.get("h1")[0].name, "w");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
