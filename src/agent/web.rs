//! Agent-local WebUI: status + upstream dial config + password change.
//! Served on --web bind (e.g. 127.0.0.1:8080). Upstream server/hostname/token
//! edits apply immediately (next redial) and persist to agent.toml.
use super::Upstream;
use crate::common::proto::ProxyConfig;
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use std::sync::Arc;
use tokio::{net::TcpListener, sync::RwLock};

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct AgentStatus {
    #[serde(default)]
    pub version: String,
    pub server_url: String,
    pub hostname: String,
    pub online: bool,
    pub rtt_ms: Option<u64>,
    pub reconnects: u64,
    pub last_error: Option<String>,
    pub proxies: Vec<ProxyConfig>,
    #[serde(default)]
    pub egress_listen: String,
    #[serde(default)]
    pub egress_on: bool,
    #[serde(default)]
    pub egress_err: Option<String>,
    #[serde(default)]
    pub link_err: Option<String>,
}

#[derive(Clone)]
pub struct WebState {
    pub status: Arc<RwLock<AgentStatus>>,
    pub upstream: Arc<RwLock<Upstream>>,
    pub config_path: String,
    pub redial: tokio::sync::watch::Sender<u64>,
    pub user: String,
    pub pass_hash: Arc<RwLock<String>>,
    pub data_path: String,
    pub secret: String,
    pub egress_reload: tokio::sync::watch::Sender<u64>,
}

pub struct ServeArgs {
    pub bind: String,
    pub user: String,
    pub pass_hash: Arc<RwLock<String>>,
    pub data_path: String,
    pub status: Arc<RwLock<AgentStatus>>,
    pub upstream: Arc<RwLock<Upstream>>,
    pub config_path: String,
    pub redial: tokio::sync::watch::Sender<u64>,
    pub egress_reload: tokio::sync::watch::Sender<u64>,
}

fn auth_ok(h: &HeaderMap, secret: &str) -> bool {
    if let Some(v) = h.get("authorization") {
        if let Ok(s) = v.to_str() {
            if let Some(t) = s.strip_prefix("Bearer ") {
                return crate::server_auth_verify(secret, t);
            }
        }
    }
    if let Some(c) = h.get("cookie") {
        if let Ok(s) = c.to_str() {
            for part in s.split(';') {
                let part = part.trim();
                if let Some(t) = part.strip_prefix("as_session=") {
                    if crate::server_auth_verify(secret, t) {
                        return true;
                    }
                }
            }
        }
    }
    false
}

fn unauthorized() -> axum::response::Response {
    (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"ok": false}))).into_response()
}

async fn index_page() -> Html<&'static str> {
    Html(include_str!("../../web/agent.html"))
}

#[derive(Deserialize)]
struct LoginReq {
    user: String,
    pass: String,
}

async fn api_login(State(w): State<WebState>, Json(r): Json<LoginReq>) -> impl IntoResponse {
    let h = w.pass_hash.read().await.clone();
    let ok = r.user == w.user && bcrypt::verify(&r.pass, &h).unwrap_or(false);
    if !ok {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"ok":false}))).into_response();
    }
    let jwt = crate::server_mint_jwt(&w.secret);
    let mut resp = Json(serde_json::json!({"ok": true, "token": jwt.clone()})).into_response();
    use axum::http::header;
    resp.headers_mut().insert(
        header::SET_COOKIE,
        format!("as_session={jwt}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400")
            .parse()
            .unwrap(),
    );
    resp
}

async fn api_status(State(w): State<WebState>, h: HeaderMap) -> impl IntoResponse {
    if !auth_ok(&h, &w.secret) {
        return unauthorized();
    }
    // merge hot upstream so UI always shows the pending target
    let mut st = w.status.read().await.clone();
    let up = w.upstream.read().await;
    st.server_url = up.server_url.clone();
    st.hostname = up.hostname.clone();
    Json(st).into_response()
}

async fn api_upstream(State(w): State<WebState>, h: HeaderMap) -> impl IntoResponse {
    if !auth_ok(&h, &w.secret) {
        return unauthorized();
    }
    let up = w.upstream.read().await;
    Json(serde_json::json!({
        "server_url": up.server_url,
        "hostname": up.hostname,
        "has_token": !up.token.is_empty(),
    }))
    .into_response()
}

#[derive(Deserialize, Default)]
struct SettingsReq {
    #[serde(default)]
    new_pass: Option<String>,
    #[serde(default)]
    server_url: Option<String>,
    #[serde(default)]
    hostname: Option<String>,
    #[serde(default)]
    token: Option<String>,
    #[serde(default)]
    egress_enabled: Option<bool>,
    #[serde(default)]
    egress_ip: Option<String>,
    #[serde(default)]
    egress_port: Option<u16>,
}



/// pure merge step (unit-testable): keep existing [[proxies]] etc, refresh
/// hostname/token/server only. Proxies are server-owned (desired), never
/// written from the agent WebUI.
fn merge_upstream_toml(raw: &str, up: &Upstream) -> toml::Value {
    let mut v: toml::Value =
        toml::from_str(raw).unwrap_or(toml::Value::Table(Default::default()));
    // 非 table（数组/标量脏文件）时丢弃重建，避免 as_table_mut panic
    if !v.is_table() {
        v = toml::Value::Table(Default::default());
    }
    let t = v.as_table_mut().unwrap();
    t.insert("hostname".into(), toml::Value::String(up.hostname.clone()));
    t.insert("token".into(), toml::Value::String(up.token.clone()));
    t.insert("server".into(), toml::Value::String(up.server_url.clone()));
    v
}

/// validate upstream fields the same way api_settings does.
fn validate_server_url(s: &str) -> bool {
    s.starts_with("ws://") || s.starts_with("wss://")
}



/// pure merge step (unit-testable): write [egress.http] without touching
/// upstream/proxies. Called after merge_upstream_toml on the same value.
fn merge_egress_toml(mut v: toml::Value, enabled: bool, ip: &str, port: u16) -> toml::Value {
    if !v.is_table() {
        v = toml::Value::Table(Default::default());
    }
    let t = v.as_table_mut().unwrap();
    let eg = t
        .entry("egress".to_string())
        .or_insert(toml::Value::Table(Default::default()));
    if !eg.is_table() {
        *eg = toml::Value::Table(Default::default());
    }
    let eht = eg
        .as_table_mut()
        .unwrap()
        .entry("http".to_string())
        .or_insert(toml::Value::Table(Default::default()));
    if !eht.is_table() {
        *eht = toml::Value::Table(Default::default());
    }
    let h = eht.as_table_mut().unwrap();
    h.insert("enabled".into(), toml::Value::Boolean(enabled));
    h.insert("listen_ip".into(), toml::Value::String(ip.to_string()));
    h.insert(
        "listen_port".into(),
        toml::Value::Integer(port as i64),
    );
    v
}

/// 从 agent.toml 读当前 [egress.http]（缺失给默认值），供 WebUI 部分更新合并。
async fn read_egress_file(path: &str) -> (bool, String, u16) {
    let raw = tokio::fs::read_to_string(path).await.unwrap_or_default();
    let v: toml::Value = toml::from_str(&raw).unwrap_or(toml::Value::Table(Default::default()));
    let h = v.get("egress").and_then(|e| e.get("http"));
    (
        h.and_then(|x| x.get("enabled")).and_then(|x| x.as_bool()).unwrap_or(false),
        h.and_then(|x| x.get("listen_ip"))
            .and_then(|x| x.as_str())
            .unwrap_or("0.0.0.0")
            .to_string(),
        h.and_then(|x| x.get("listen_port")).and_then(|x| x.as_integer()).unwrap_or(18080) as u16,
    )
}

async fn write_settings_toml(
    path: &str,
    up: &Upstream,
    eg: Option<(bool, String, u16)>,
) -> anyhow::Result<()> {
    let raw = tokio::fs::read_to_string(path).await.unwrap_or_default();
    let mut v = merge_upstream_toml(&raw, up);
    if let Some((en, ip, port)) = eg {
        v = merge_egress_toml(v, en, &ip, port);
    }
    tokio::fs::write(path, toml::to_string_pretty(&v)?).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_url_accepts_ws_variants_only() {
        assert!(validate_server_url("ws://127.0.0.1:7440/ws"));
        assert!(validate_server_url("wss://tunnel.nat.kkito.cn:7443/ws"));
        assert!(!validate_server_url("http://127.0.0.1:7440/"));
        assert!(!validate_server_url("127.0.0.1:7440"));
        assert!(!validate_server_url(""));
        // 大小写/首尾空格由调用方 trim+原样判断，这里保持严格前缀
        assert!(!validate_server_url("WS://x/ws"));
    }

    #[test]
    fn merge_upstream_preserves_proxies_and_refreshes_upstream() {
        let raw = "hostname = \"old\"\ntoken = \"t0\"\nserver = \"ws://old/ws\"\n\
                   [[proxies]]\nname = \"web\"\ntype = \"http\"\n";
        let up = Upstream {
            server_url: "ws://new:7440/ws".into(),
            hostname: "newhost".into(),
            token: "newtok".into(),
        };
        let v = merge_upstream_toml(raw, &up);
        assert_eq!(v["hostname"].as_str().unwrap(), "newhost");
        assert_eq!(v["token"].as_str().unwrap(), "newtok");
        assert_eq!(v["server"].as_str().unwrap(), "ws://new:7440/ws");
        // 保留的 proxies 不被清空（server 期望态覆盖的是内存，不是文件）
        assert_eq!(v["proxies"][0]["name"].as_str().unwrap(), "web");
    }

    #[test]
    fn merge_egress_preserves_and_updates() {
        let raw = "hostname = \"h\"\ntoken = \"t\"\nserver = \"ws://x/ws\"\n[egress.http]\nlisten_ip = \"127.0.0.1\"\nlisten_port = 18080\nenabled = false\n";
        let v: toml::Value = toml::from_str(raw).unwrap();
        let v = merge_egress_toml(v, true, "0.0.0.0", 18080);
        assert_eq!(v["egress"]["http"]["listen_ip"].as_str().unwrap(), "0.0.0.0");
        assert!(v["egress"]["http"]["enabled"].as_bool().unwrap());
        // 上行字段不受影响
        assert_eq!(v["hostname"].as_str().unwrap(), "h");
    }

    #[test]
    fn merge_upstream_tolerates_dirty_file() {
        let up = Upstream {
            server_url: "ws://n/ws".into(),
            hostname: "h".into(),
            token: "t".into(),
        };
        // 空文件 / 损坏 TOML / 非 table 顶层都不 panic，且上行字段正确
        for raw in ["", "[[[", "42", "\"str\""] {
            let v = merge_upstream_toml(raw, &up);
            assert_eq!(v["hostname"].as_str().unwrap(), "h");
            assert_eq!(v["server"].as_str().unwrap(), "ws://n/ws");
        }
    }
}

async fn api_settings(
    State(w): State<WebState>,
    h: HeaderMap,
    Json(r): Json<SettingsReq>,
) -> impl IntoResponse {
    if !auth_ok(&h, &w.secret) {
        return unauthorized();
    }
    let mut notes: Vec<String> = vec![];
    if let Some(p) = r.new_pass {
        if !p.is_empty() {
            let hash = bcrypt::hash(&p, bcrypt::DEFAULT_COST).unwrap_or_default();
            *w.pass_hash.write().await = hash.clone();
            let _ = tokio::fs::write(&w.data_path, &hash).await;
            notes.push("口令已更新".into());
        }
    }
    let mut changed = false;
    {
        let mut up = w.upstream.write().await;
        if let Some(s) = r.server_url {
            let s = s.trim().to_string();
            if !s.is_empty() && s != up.server_url {
                if !validate_server_url(&s) {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({"ok": false, "reason": "server 须以 ws(s):// 开头"})),
                    )
                        .into_response();
                }
                up.server_url = s;
                changed = true;
            }
        }
        if let Some(hn) = r.hostname {
            let hn = hn.trim().to_string();
            if !hn.is_empty() && hn != up.hostname {
                up.hostname = hn;
                changed = true;
            }
        }
        // empty token = keep old (avoids wiping by accident)
        if let Some(t) = r.token {
            if !t.is_empty() && t != up.token {
                up.token = t;
                changed = true;
            }
        }
        // egress 热更新：只写 [egress.http] + bump reload，不断 WSS 主链
        let eg = match (r.egress_enabled, r.egress_ip, r.egress_port) {
            (None, None, None) => None,
            (en, ip, port) => {
                let cur = read_egress_file(&w.config_path).await;
                let enabled = en.unwrap_or(cur.0);
                let lip = ip.map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).unwrap_or(cur.1);
                let lport = port.unwrap_or(cur.2);
                if lport == 0 {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({"ok": false, "reason": "egress 端口非法"})),
                    )
                        .into_response();
                }
                // 借用结束后再落盘：先 clone 出需要的写回去
                Some((enabled, lip, lport))
            }
        };
        let need_write = changed || eg.is_some();
        if need_write {
            let egv = eg.clone();
            if let Err(e) = write_settings_toml(&w.config_path, &up, egv).await {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"ok": false, "reason": format!("落盘失败: {e:#}")})),
                )
                    .into_response();
            }
            // reflect target immediately in status + force a redial
            let mut st = w.status.write().await;
            st.server_url = up.server_url.clone();
            st.hostname = up.hostname.clone();
            st.online = false;
            if changed {
                let n = w.redial.borrow().wrapping_add(1);
                w.redial.send_replace(n);
                notes.push("上行已更新，正在重连".into());
            }
            if eg.is_some() {
                let n = w.egress_reload.borrow().wrapping_add(1);
                w.egress_reload.send_replace(n);
                notes.push("出网代理已更新，监听重启中".into());
            }
        }
    }
    Json(serde_json::json!({"ok": true, "note": notes.join("；")})).into_response()
}

async fn api_reconnect(State(w): State<WebState>, h: HeaderMap) -> impl IntoResponse {
    if !auth_ok(&h, &w.secret) {
        return unauthorized();
    }
    let n = w.redial.borrow().wrapping_add(1);
    // send_replace: never blocks even with no subscribers yet
    w.redial.send_replace(n);
    Json(serde_json::json!({"ok": true, "note": "正在重连"})).into_response()
}

pub async fn serve(args: ServeArgs) {
    let app = Router::new()
        .route("/", get(index_page))
        .route("/api/login", post(api_login))
        .route("/api/status", get(api_status))
        .route("/api/upstream", get(api_upstream))
        .route("/api/settings", post(api_settings))
        .route("/api/reconnect", post(api_reconnect))
        .with_state(WebState {
            status: args.status,
            upstream: args.upstream,
            config_path: args.config_path,
            redial: args.redial,
            user: args.user,
            pass_hash: args.pass_hash,
            data_path: args.data_path,
            secret: uuid::Uuid::new_v4().to_string(),
            egress_reload: args.egress_reload,
        });
    match TcpListener::bind(&args.bind).await {
        Ok(lis) => {
            tracing::info!("agent webui on {}", args.bind);
            if let Err(e) = axum::serve(lis, app).await {
                tracing::error!("agent webui died: {e:#}");
            }
        }
        Err(e) => tracing::error!("agent webui bind {} failed: {e:#}", args.bind),
    }
}
