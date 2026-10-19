//! Agent-local WebUI: status + upstream dial config + password change.
//! Served on --web bind (e.g. 127.0.0.1:8080). Upstream server/hostname/token
//! edits apply immediately (next redial) and persist to agent.toml.
use crate::agent::Upstream;
use crate::proto::ProxyConfig;
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
    pub server_url: String,
    pub hostname: String,
    pub online: bool,
    pub rtt_ms: Option<u64>,
    pub reconnects: u64,
    pub last_error: Option<String>,
    pub proxies: Vec<ProxyConfig>,
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
    Html(include_str!("../web/agent.html"))
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
}

async fn write_upstream_toml(path: &str, up: &Upstream) -> anyhow::Result<()> {
    let raw = tokio::fs::read_to_string(path).await.unwrap_or_default();
    let mut v: toml::Value = toml::from_str(&raw).unwrap_or(toml::Value::Table(Default::default()));
    let t = v.as_table_mut().unwrap();
    t.insert("hostname".into(), toml::Value::String(up.hostname.clone()));
    t.insert("token".into(), toml::Value::String(up.token.clone()));
    t.insert("server".into(), toml::Value::String(up.server_url.clone()));
    tokio::fs::write(path, toml::to_string_pretty(&v)?).await?;
    Ok(())
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
                if !s.starts_with("ws://") && !s.starts_with("wss://") {
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
        if changed {
            if let Err(e) = write_upstream_toml(&w.config_path, &up).await {
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
            let n = w.redial.borrow().wrapping_add(1);
            w.redial.send_replace(n);
            notes.push("上行已更新，正在重连".into());
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
