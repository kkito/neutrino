//! server：公网单端口（/ws + /api + WebUI + fallback 隧道分流）。
pub mod api;
pub mod auth;
pub mod http_util;
pub mod ratelimit;
pub mod ingress;
pub mod state;
pub mod tunnel;

pub(crate) use state::{Shared, S};
use api::{api_config, api_conns, api_desired_get, api_desired_reload, api_desired_set, api_login, api_logs, api_overview, api_toggle, api_traffic, api_tunnels};
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
    // 公网端口：--listen 尾段端口，供 HTTP fallback 连接行 public_port 用
    let public_port: u16 = listen.rsplit(':').next().and_then(|p| p.parse().ok()).unwrap_or(0);
    // jwt_secret 持久化：重启复用，登录 cookie 不掉（旧 state 无此字段则生成并落盘）。
    let fresh_secret = ps.jwt_secret.is_empty();
    let jwt_secret = if fresh_secret {
        uuid::Uuid::new_v4().to_string()
    } else {
        ps.jwt_secret
    };
    let shared: S = Arc::new(Shared {
        password_hash: RwLock::new(ps.password_hash),
        totals: RwLock::new(ps.totals),
        jwt_secret: jwt_secret.clone(),
        data_dir: data.to_string(),
        desired: RwLock::new(HashMap::new()),
        desired_path: desired.to_string(),
        public_port,
        ..Default::default()
    });
    // traffic 读回（无文件/坏文件从空开始，load_traffic 内部记日志）
    {
        let p = state::traffic_path(data);
        state::load_traffic(&shared, &p).await;
    }
    // fill desired from store
    {
        let all = ds.all();
        *shared.desired.write().await = all;
    }
    // 新生成的 secret 立刻落盘，避免首次启动崩溃后 secret 漂移。
    if fresh_secret {
        state::save_state(&shared).await;
    }
    let need_init = shared.password_hash.read().await.is_empty();
    let token = Arc::new(token.to_string());
    // 60s traffic tick：conns 表行累计 -> per-tunnel 增量 push + 落盘 traffic.json。
    // 根因→修法：旧 tick 拿 agent 级累计给该 agent 下每个 proxy 各 push 一份，
    // 多隧道流量翻 N 倍；新 tick 只读 conns 表归集，空闲隧道不 push。
    {
        let s = shared.clone();
        let data = data.to_string();
        tokio::spawn(async move {
            let mut iv = tokio::time::interval(Duration::from_secs(60));
            loop {
                iv.tick().await;
                {
                    let conns = s.conns.read().await;
                    let mut tr = s.traffic.write().await;
                    let mut lt = s.last_total.write().await;
                    state::tick_from_conns(&mut tr, &mut lt, &conns);
                }
                let p = state::traffic_path(&data);
                state::save_traffic(&s, &p).await;
            }
        });
    }
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
        .route("/api/traffic", get(api_traffic))
        .route("/api/conns", get(api_conns))
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
    // ConnectInfo 让 fallback 能取对端 ip:port（连接列表 peer 列用）
    let svc = app.into_make_service_with_connect_info::<std::net::SocketAddr>();
    axum::serve(lis, svc).await?;
    Ok(())
}

