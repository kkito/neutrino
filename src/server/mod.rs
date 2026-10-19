//! server：公网单端口（/ws + /api + WebUI + fallback 隧道分流）。
pub mod api;
pub mod auth;
pub mod http_util;
pub mod ingress;
pub mod state;
pub mod tunnel;

pub(crate) use state::{Shared, S};
use api::{api_config, api_desired_get, api_desired_reload, api_desired_set, api_login, api_logs, api_overview, api_toggle, api_tunnels};
use ingress::fallback_http_ingress;
use tunnel::ws_handler;
use axum::{routing::{get, post}, Router};
use std::{sync::Arc, time::Duration};
use tokio::{net::TcpListener, sync::RwLock};
use std::collections::HashMap;

pub async fn run(listen: &str, _http_in: &str, data: &str, token: &str, desired: &str) -> anyhow::Result<()> {
    let _ = tokio::fs::create_dir_all(data).await;
    if !_http_in.is_empty() {
        tracing::warn!("--http-in is deprecated and ignored: HTTP ingress now shares --listen (Host routing)");
    }
    let ps = state::load_state(data).await;
    let ds = crate::common::desired::DesiredStore::load(desired);
    let shared: S = Arc::new(Shared {
        password_hash: RwLock::new(ps.password_hash),
        totals: RwLock::new(ps.totals),
        jwt_secret: uuid::Uuid::new_v4().to_string(),
        data_dir: data.to_string(),
        desired: RwLock::new(HashMap::new()),
        desired_path: desired.to_string(),
        ..Default::default()
    });
    // fill desired from store
    {
        let all = ds.all();
        *shared.desired.write().await = all;
    }
    let need_init = shared.password_hash.read().await.is_empty();
    let token = Arc::new(token.to_string());
    // periodic persist
    {
        let s = shared.clone();
        tokio::spawn(async move {
            let mut iv = tokio::time::interval(Duration::from_secs(30));
            loop {
                iv.tick().await;
                // fold live counters into totals
                {
                    let ag = s.agents.read().await;
                    let mut t = s.totals.write().await;
                    for h in ag.values() {
                        t.insert(h.info.hostname.clone(), (h.info.rx_bytes, h.info.tx_bytes));
                    }
                }
                state::save_state(&s).await;
            }
        });
    }
    let app = Router::new()
        .route("/ws", get(ws_handler))
        .route("/api/login", post(api_login))
        .route("/api/overview", get(api_overview))
        .route("/api/tunnels", get(api_tunnels))
        .route("/api/logs", get(api_logs))
        .route("/api/config", post(api_config))
        .route("/api/tunnels/:agent/:name/enabled", post(api_toggle))
        .route("/api/desired/reload", post(api_desired_reload))
        .route("/api/desired/:hostname", get(api_desired_get).post(api_desired_set))
        // 注意：`/` 不单独注册精确路由，否则带隧道 Host 访问 `/` 会被它抢走；
        // 统一走 fallback 按 Host 分流（WebUI vs 隧道）。
        .fallback(fallback_http_ingress)
        .with_state((shared, token.clone()));
    let lis = TcpListener::bind(listen).await?;
    tracing::info!("server listening ws+webui+http-ingress on {listen}");
    println!("neutrino-server running:");
    println!("  listen : http://{listen}/  (Host=业务域->隧道, /=WebUI, /ws=agent)");
    println!("  agent token  : {token}  (agent 用 --server ws://{listen}/ws + 相同 token)");
    if need_init {
        println!("  web login    : admin / welcome2neutrino (默认, 首次登录后请改口令)");
    } else {
        println!("  web login    : admin / (已设置的口令)");
    }
    axum::serve(lis, app).await?;
    Ok(())
}

