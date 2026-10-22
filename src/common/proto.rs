//! Control + data frame protocol (JSON Text + Binary [stream:u32 BE][payload]).
use serde::{Deserialize, Serialize};
use http;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

fn enabled_default() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "lowercase")]
pub enum ClientMsg {
    Hello {
        hostname: String,
        version: String,
        token: String,
    },
    Register {
        proxies: Vec<ProxyConfig>,
    },
    Ping {
        ts: i64,
    },
    Pong {
        ts: i64,
    },
    Open {
        stream: u32,
        kind: String, // "http" | "tcp" | "egress" | "link" (agent-initiated)
        host: String,
        port: u16,
    },
    Close {
        stream: u32,
        reason: String,
    },
    ConfigAck {
        ok: bool,
    },
    AdminReq {
        req_id: u64,
        method: String,
        path: String,
        body: String,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "lowercase")]
pub enum ServerMsg {
    Welcome { agent_id: String, interval: u64 },
    Ping { ts: i64 },
    Pong { ts: i64 },
    Open { stream: u32, kind: String, host: String, port: u16 },
    Close { stream: u32, reason: String },
    Config { proxies: Vec<ProxyConfig> },
    Error { reason: String },
    AdminResp { req_id: u64, status: u16, body: String },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub name: String,
    #[serde(rename = "type")]
    pub ptype: String, // "http" | "tcp" | "udp" | "link"（跨 agent TCP 互联）
    pub local_ip: String,
    pub local_port: u16,
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub remote_port: u16,
    #[serde(default)]
    pub set_x_forwarded_proto: Option<String>,
    /// http 隧道入口 basic auth：`user:pass` 明文（仅内存+desired.toml 落盘，
    /// server 在透传前校验，agent 侧不感知）。缺省 None = 不校验。
    #[serde(default)]
    pub basic_auth: Option<String>,
    #[serde(default = "enabled_default")]
    pub enabled: bool,
    /// link 对端 agent 主机名（入口 agent 配置里填出口 agent 的 hostname）。
    #[serde(default)]
    pub link_agent: String,
    /// link 对端可达目标 ip（出口 agent 去 dial）。
    #[serde(default)]
    pub link_host: String,
    /// link 对端可达目标 port。
    #[serde(default)]
    pub link_port: u16,
    /// 映射级总量下行限速（tcp/udp/link），如 "0.5m"。None/空/非法 = 不限速。
    #[serde(default)]
    pub rate_limit: Option<String>,
}

/// 映射级限速速率解析：字符串 -> B/s。口径 MB/s 与 transmission UI 一致：
/// `500k`=500KB/s，`0.5m`=0.5MB/s，`1.5g`=1.5GB/s；纯数字默认 `m`；
/// 大小写不敏感；非法/<=0 返回 None（调用方当不限速 + warn，绝不炸 server）。
pub fn parse_rate_limit(s: &str) -> Option<u64> {
    let t = s.trim().to_lowercase();
    if t.is_empty() {
        return None;
    }
    let (num, mult): (&str, f64) = if let Some(n) = t.strip_suffix('k') {
        (n, 1024.0)
    } else if let Some(n) = t.strip_suffix('m') {
        (n, 1024.0 * 1024.0)
    } else if let Some(n) = t.strip_suffix('g') {
        (n, 1024.0 * 1024.0 * 1024.0)
    } else {
        (t.as_str(), 1024.0 * 1024.0)
    };
    let v: f64 = num.trim().parse().ok()?;
    if !v.is_finite() || v <= 0.0 {
        return None;
    }
    let bps = (v * mult).round() as u64;
    if bps == 0 {
        return None;
    }
    Some(bps)
}

/// link 条目校验（纯函数）：对端/目标/监听缺一不可，且禁止自环。
/// 根因→修法：link 配错（空对端/自环）要在配置层拦掉，别等建流时再炸。
pub fn valid_link(p: &ProxyConfig, self_hostname: &str) -> bool {
    if p.ptype != "link" || !p.enabled {
        return false;
    }
    if p.link_agent.trim().is_empty() || p.link_agent == self_hostname {
        return false;
    }
    if p.link_host.trim().is_empty() || p.link_port == 0 || p.local_port == 0 {
        return false;
    }
    true
}

/// 校验 http 入口 Authorization: Basic 头。`expected` 为 `user:pass` 明文。
/// 无 expected（None/空）= 不校验直接放行；有则必须精确匹配。
pub fn check_basic_auth(headers: &http::HeaderMap, expected: Option<&str>) -> bool {
    let exp = expected.unwrap_or("").trim();
    if exp.is_empty() {
        return true;
    }
    let got = headers
        .get(http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let b64 = match got.strip_prefix("Basic ") {
        Some(b) => b.trim(),
        None => return false,
    };
    use base64::Engine;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .ok()
        .and_then(|b| String::from_utf8(b).ok());
    decoded.as_deref() == Some(exp)
}

/// Encode binary data frame: [stream_id: u32 BE][payload]
pub fn encode_data(stream: u32, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + payload.len());
    v.extend_from_slice(&stream.to_be_bytes());
    v.extend_from_slice(payload);
    v
}

/// Decode binary data frame.
pub fn decode_data(buf: &[u8]) -> Option<(u32, &[u8])> {
    if buf.len() < 4 {
        return None;
    }
    let id = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
    Some((id, &buf[4..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_roundtrip() {
        let m = ClientMsg::Hello {
            hostname: "minipc7s".into(),
            version: "0.1.0".into(),
            token: "welcome2neutrino".into(),
        };
        let s = serde_json::to_string(&m).unwrap();
        assert!(s.contains("\"t\":\"hello\""));
        let back: ClientMsg = serde_json::from_str(&s).unwrap();
        assert!(matches!(back, ClientMsg::Hello { .. }));
    }

    #[test]
    fn link_fields_default_and_validate() {
        // 老 desired 无 link 字段：反序列化不炸，全空默认。
        let p: ProxyConfig = serde_json::from_str(
            r#"{"name":"l","type":"link","local_ip":"0.0.0.0","local_port":13306}"#,
        )
        .unwrap();
        assert_eq!(p.link_agent, "");
        assert!(!super::valid_link(&p, "agent2")); // 缺对端 -> 拒绝
        let mut q = p.clone();
        q.link_agent = "agent2".into(); // 自环 -> 拒绝
        q.link_host = "10.0.0.1".into();
        q.link_port = 3306;
        assert!(!super::valid_link(&q, "agent2"));
        q.link_agent = "agent1".into();
        assert!(super::valid_link(&q, "agent2"));
        // 非 link 类型直接拒绝
        let mut r = q.clone();
        r.ptype = "tcp".into();
        assert!(!super::valid_link(&r, "agent2"));
    }

    #[test]
    fn data_frame_roundtrip() {
        let b = encode_data(7, b"GET / HTTP/1.1\r\n");
        let (id, payload) = decode_data(&b).unwrap();
        assert_eq!(id, 7);
        assert_eq!(payload, b"GET / HTTP/1.1\r\n");
        assert!(decode_data(&b[..3]).is_none());
    }

    #[test]
    fn admin_req_resp_roundtrip() {
        // 根因→修法：agent-admin 转手需要 req_id 配对的请求/响应帧，三传输共享。
        let q = super::ClientMsg::AdminReq { req_id: 7, method: "GET".into(), path: "overview".into(), body: "{}".into() };
        let s = serde_json::to_string(&q).unwrap();
        let back: super::ClientMsg = serde_json::from_str(&s).unwrap();
        assert_eq!(q, back);
        let r = super::ServerMsg::AdminResp { req_id: 7, status: 200, body: "{\"agents\":[]}".into() };
        let s = serde_json::to_string(&r).unwrap();
        let back: super::ServerMsg = serde_json::from_str(&s).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn welcome_roundtrip() {
        let m = ServerMsg::Welcome {
            agent_id: "abc".into(),
            interval: 30,
        };
        let s = serde_json::to_string(&m).unwrap();
        let back: ServerMsg = serde_json::from_str(&s).unwrap();
        assert!(matches!(back, ServerMsg::Welcome { .. }));
    }

    #[test]
    fn ping_pong_roundtrip() {
        for (s, tag) in [
            (
                serde_json::to_string(&ClientMsg::Pong { ts: 1 }).unwrap(),
                "\"t\":\"pong\"",
            ),
            (
                serde_json::to_string(&ServerMsg::Ping { ts: 2 }).unwrap(),
                "\"t\":\"ping\"",
            ),
            (
                serde_json::to_string(&ServerMsg::Config { proxies: vec![] })
                    .unwrap(),
                "\"t\":\"config\"",
            ),
            (
                serde_json::to_string(&ClientMsg::ConfigAck { ok: true }).unwrap(),
                "\"t\":\"configack\"",
            ),
        ] {
            assert!(s.contains(tag), "{s}");
        }
        let _: ClientMsg = serde_json::from_str(r#"{"t":"pong","ts":5}"#).unwrap();
        let _: ServerMsg = serde_json::from_str(r#"{"t":"ping","ts":5}"#).unwrap();
    }

    #[test]
    fn rate_limit_parses_mbps_notation() {
        // 口径与 transmission UI 一致：1m = 1024*1024 B/s；纯数字默认 m；大小写不敏感
        assert_eq!(super::parse_rate_limit("0.5m"), Some(524288));
        assert_eq!(super::parse_rate_limit("500k"), Some(512000));
        assert_eq!(super::parse_rate_limit("2"), Some(2 * 1024 * 1024));
        assert_eq!(
            super::parse_rate_limit("1.5G"),
            Some((1.5 * 1024.0 * 1024.0 * 1024.0) as u64)
        );
        assert_eq!(super::parse_rate_limit(" 1M "), Some(1024 * 1024));
        // 非法 -> None（调用方当不限速 + warn，绝不炸）
        assert_eq!(super::parse_rate_limit(""), None);
        assert_eq!(super::parse_rate_limit("-1m"), None);
        assert_eq!(super::parse_rate_limit("abc"), None);
        assert_eq!(super::parse_rate_limit("0"), None);
        assert_eq!(super::parse_rate_limit("0m"), None);
    }

    #[test]
    fn proxy_enabled_defaults_true() {
        // old configs without `enabled` must stay active
        let p: ProxyConfig = toml::from_str(
            "name = \"x\"\ntype = \"http\"\nlocal_ip = \"127.0.0.1\"\nlocal_port = 80\ndomains = [\"a\"]\n",
        )
        .unwrap();
        assert!(p.enabled);
        assert_eq!(p.remote_port, 0);
        let p2: ProxyConfig = serde_json::from_str(
            r#"{"name":"y","type":"tcp","local_ip":"127.0.0.1","local_port":1,"remote_port":2,"enabled":false}"#,
        )
        .unwrap();
        assert!(!p2.enabled);
    }
}
