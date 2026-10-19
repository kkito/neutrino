//! Agent-local WebUI: read-only status + effective tunnels, password change.
//! Served on --web bind (e.g. 127.0.0.1:8080). Changing the upstream server
//! address requires an agent restart; only the management password is hot.
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
    pub online: bool,
    pub rtt_ms: Option<u64>,
    pub reconnects: u64,
    pub proxies: Vec<ProxyConfig>,
}

#[derive(Clone)]
pub struct WebState {
    pub status: Arc<RwLock<AgentStatus>>,
    pub user: String,
    pub pass_hash: Arc<RwLock<String>>,
    pub data_path: String,
    pub secret: String,
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
    Json(w.status.read().await.clone()).into_response()
}

#[derive(Deserialize)]
struct SettingsReq {
    #[serde(default)]
    new_pass: Option<String>,
}

async fn api_settings(
    State(w): State<WebState>,
    h: HeaderMap,
    Json(r): Json<SettingsReq>,
) -> impl IntoResponse {
    if !auth_ok(&h, &w.secret) {
        return unauthorized();
    }
    let mut note = String::new();
    if let Some(p) = r.new_pass {
        if !p.is_empty() {
            let hash = bcrypt::hash(&p, bcrypt::DEFAULT_COST).unwrap_or_default();
            *w.pass_hash.write().await = hash.clone();
            let _ = tokio::fs::write(&w.data_path, &hash).await;
            note = "，口令已更新".to_string();
        }
    }
    // upstream server address change needs a process restart (documented in UI)
    Json(serde_json::json!({"ok": true, "note": format!("{note}（改上行地址请重启 agent）")})).into_response()
}

pub async fn serve(
    bind: &str,
    user: String,
    pass_hash: Arc<RwLock<String>>,
    data_path: String,
    status: Arc<RwLock<AgentStatus>>,
) -> anyhow::Result<()> {
    let app = Router::new()
        .route("/", get(index_page))
        .route("/api/login", post(api_login))
        .route("/api/status", get(api_status))
        .route("/api/settings", post(api_settings))
        .with_state(WebState {
            status,
            user,
            pass_hash,
            data_path,
            secret: uuid::Uuid::new_v4().to_string(),
        });
    let lis = TcpListener::bind(bind).await?;
    tracing::info!("agent webui on {bind}");
    axum::serve(lis, app).await?;
    Ok(())
}
