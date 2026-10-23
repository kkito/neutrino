//! server：公网单端口（/ws + /api + WebUI + fallback 隧道分流）。
pub mod api;
pub mod auth;
pub mod http_util;
pub mod ratelimit;
pub mod ingress;
pub mod kudus;
pub mod quic;
pub mod state;
pub mod tunnel;

pub(crate) use state::{Shared, S};
use api::{api_config, api_conns, api_desired_get, api_desired_reload, api_desired_set, api_login, api_live, api_logs, api_overview, api_toggle, api_traffic, api_tunnels};
use ingress::fallback_http_ingress;
use tunnel::ws_handler;
use axum::{routing::{get, post}, Router};
use std::{sync::Arc, time::Duration};
use tokio::{net::TcpListener, sync::RwLock};
use std::collections::HashMap;

/// 请求耗时日志中间件：method path -> status + 耗时；慢请求（>500ms）warn + 入 events。
async fn api_access_log(
    axum::extract::State(s): axum::extract::State<S>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> impl axum::response::IntoResponse {
    let method = req.method().to_string();
    let path = req.uri().path().to_string();
    let t0 = std::time::Instant::now();
    let resp = next.run(req).await;
    let ms = t0.elapsed().as_millis() as u64;
    // 健康检查类高频口降噪：/api/live 5s 一次轮询，只记慢的
    if path == "/api/live" && ms <= 500 {
        return resp;
    }
    let line = format!("{method} {path} -> {} {ms}ms", resp.status().as_u16());
    if let Some(w) = state::slow_msg(&path.replace("/api/", ""), ms, 500) {
        tracing::warn!("{line} SLOW");
        state::log_ev_err(&s, w);
    } else {
        tracing::info!("{line}");
    }
    resp
}

pub async fn run(listen: &str, _http_in: &str, data: &str, token: &str, desired: &str, quic_listen: &str, kudus_listen: &str, allow_agent_admin: bool, udp_session_ttl: u64) -> anyhow::Result<()> {
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
        egress_exit: RwLock::new(crate::common::desired::DesiredStore::load_egress_exit(desired)),
        public_port,
        allow_agent_admin,
        // 0 是 --udp-session-ttl 0 的误传：回退默认，避免 session 永不回收。
        udp_session_ttl_secs: if udp_session_ttl == 0 {
            state::UDP_SESSION_TTL_SECS_DEFAULT
        } else {
            udp_session_ttl
        },
        ..Default::default()
    });
    if allow_agent_admin && token.len() < 16 {
        tracing::warn!("agent-admin enabled with weak token (<16 chars): token 即全 server 管理权，请换强 token");
    }
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
    // 5s live tick：conns 表行累计 -> per-tunnel 5s 增量快照（纯内存，供 /api/live 秒级监控）。
    // 根因→修法：分钟 tick 看毛刺太慢（60s 才一点）；5s 快照独立窗口、不落盘、不进 history。
    {
        let s = shared.clone();
        tokio::spawn(async move {
            let mut iv = tokio::time::interval(Duration::from_secs(5));
            loop {
                iv.tick().await;
                let cur = { let g = s.conns.read().await; state::aggregate_conns(&*g) };
                let mut live = s.live.write().await;
                let mut last = s.live_last.write().await;
                // 全量重算：本轮有行的算增量（无基线则 0），上轮有、本轮无的行清零
                let mut fresh: HashMap<String, (u64, u64)> = HashMap::new();
                for (k, c) in &cur {
                    let prev = last.get(k).cloned().unwrap_or(*c);
                    fresh.insert(k.clone(), state::minute_delta(prev, *c));
                }
                *live = fresh;
                *last = cur.clone();
                // agent 总量批量刷：包循环零 agents 写锁后，info.rx/tx 只在此 5s 刷一次
                // （单次 write，读锁最多等一个临界区，不饥饿）。key=`host/proxy`，按首段 host 汇总。
                {
                    drop(live);
                    drop(last);
                    let mut per_host: HashMap<String, (u64, u64)> = HashMap::new();
                    for (k, c) in &cur {
                        if let Some(host) = k.split('/').next() {
                            let e = per_host.entry(host.to_string()).or_insert((0, 0));
                            e.0 += c.0;
                            e.1 += c.1;
                        }
                    }
                    // 增量 = 本轮累计 - 上轮基线（基线存 live_last_host；无基线则 0，不跳变）
                    // 注：conns 行是累计值，agent 重连后行 id 变化会回绕，minute_delta 饱和为 0。
                    // 原子计数合账：deliver/写泵的每包增量先落 ctr_*，此处 swap 清零后
                    // 一次合进 info（每 5s 单次 write）+ per-host 增量。
                    let mut ag = s.agents.write().await;
                    for h in ag.values_mut() {
                        let drx = h.ctr_rx.swap(0, std::sync::atomic::Ordering::Relaxed);
                        let dtx = h.ctr_tx.swap(0, std::sync::atomic::Ordering::Relaxed);
                        let rtt = h.ctr_rtt.load(std::sync::atomic::Ordering::Relaxed);
                        h.info.rx_bytes += drx;
                        h.info.tx_bytes += dtx;
                        if rtt >= 0 {
                            h.info.rtt_ms = rtt;
                        }
                        if let Some((crx, ctx)) = per_host.get(&h.info.hostname) {
                            let prev = s.live_last_host.read().await.get(&h.info.hostname).cloned().unwrap_or((*crx, *ctx));
                            let d = state::minute_delta(prev, (*crx, *ctx));
                            h.info.rx_bytes += d.0;
                            h.info.tx_bytes += d.1;
                        }
                    }
                    drop(ag);
                    let mut base = s.live_last_host.write().await;
                    *base = per_host;
                }
                // 心跳：tick 停摆一眼可见（debug 级，量大默认不刷屏）。
                // 根因→修法：后台循环死掉无任何迹象；有心跳行+缺行即告警。
                {
                    let nc = s.conns.read().await.len();
                    let na = s.agents.read().await.len();
                    tracing::debug!("{}", state::tick_heartbeat("live", &[("conns", nc), ("agents", na)]));
                }
            }
        });
    }
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
                let (nconns, ntun) = {
                    let conns = s.conns.read().await;
                    let mut tr = s.traffic.write().await;
                    let mut lt = s.last_total.write().await;
                    let mut seen = s.seen_tunnels.write().await;
                    state::tick_from_conns(&mut tr, &mut lt, &mut seen, &conns);
                    // 黑洞归集：drop_hits drain 进 traffic（drop 点天然带 ts，不走 seen/last_total）。
                    {
                        let mut hits = s.drop_hits.lock().map(|mut m| std::mem::take(&mut *m)).unwrap_or_default();
                        state::tick_drops(&mut tr, &mut hits, chrono::Local::now().timestamp());
                    }
                    // egress cap：超量 key 并入 {agent}/egress/other（近 5 点求和排序）。
                    {
                        let snap: HashMap<String, u64> = tr
                            .iter()
                            .map(|(k, q)| (k.clone(), q.iter().rev().take(5).map(|(_, r, t)| r + t).sum()))
                            .collect();
                        let over = state::egress_over_cap(&snap, state::EGRESS_KEYS_PER_AGENT);
                        if !over.is_empty() {
                            let now = chrono::Local::now().timestamp();
                            let mut other_sum: HashMap<String, (u64, u64)> = HashMap::new();
                            for k in over {
                                if let Some((agent, _)) = k.split_once("/egress/") {
                                    if let Some(q) = tr.remove(&k) {
                                        let (sr, st) = q.iter().fold((0, 0), |(a, b), (_, r, t)| (a + r, b + t));
                                        let e = other_sum.entry(agent.to_string()).or_insert((0, 0));
                                        e.0 += sr;
                                        e.1 += st;
                                    }
                                }
                            }
                            for (agent, (sr, st)) in other_sum {
                                let q = tr.entry(format!("{agent}/egress/other")).or_default();
                                q.push_back((now, sr, st));
                                state::trim_traffic(q);
                            }
                        }
                    }
                    (conns.len(), tr.len())
                };
                let p = state::traffic_path(&data);
                state::save_traffic(&s, &p).await;
                tracing::info!("{}", state::tick_heartbeat("traffic", &[("conns", nconns), ("tunnels", ntun)]));
            }
        });
    }
    // 限速实况周期日志（5min）：每映射经手字节 + 累计 sleep，验证限速是否真在压。
    // 根因→修法：VPS 网卡总量监控分不清哪条路的流量，limiter 自带计数器才是实锤。
    {
        let s = shared.clone();
        tokio::spawn(async move {
            let mut iv = tokio::time::interval(Duration::from_secs(300));
            loop {
                iv.tick().await;
                let lims = s.rate_limiters.read().await;
                if lims.is_empty() {
                    continue;
                }
                let mut rows: Vec<String> = lims.iter().map(|(k, l)| {
                    let (limit, bytes, sleep_ms) = l.stats();
                    format!("{k} limit={limit}B/s thru={bytes}B sleep={sleep_ms}ms")
                }).collect();
                rows.sort();
                tracing::info!("ratelimit stats: {}", rows.join(" | "));
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
        .route("/api/live", get(api_live))
        .route("/api/conns", get(api_conns))
        .route("/api/config", post(api_config))
        .route("/api/tunnels/:agent/:name/enabled", post(api_toggle))
        .route("/api/desired/reload", post(api_desired_reload))
        .route("/api/desired/:hostname", get(api_desired_get).post(api_desired_set))
        // 注意：`/` 不单独注册精确路由，否则带隧道 Host 访问 `/` 会被它抢走；
        // 统一走 fallback 按 Host 分流（WebUI vs 隧道）。
        .fallback(fallback_http_ingress)
        .with_state((shared.clone(), token.clone()));
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
    // 请求日志中间件（main 0.6.6 合入）：所有请求打耗时 info；超 500ms warn + 入 events。
    // 根因→修法：/api/tunnels pending 6s 时无任何请求日志，只能逐段 curl 隔离。
    let app = app.layer(axum::middleware::from_fn_with_state(
        shared.clone(),
        api_access_log,
    ));
    // ConnectInfo 让 fallback 能取对端 ip:port（连接列表 peer 列用）
    let svc = app.into_make_service_with_connect_info::<std::net::SocketAddr>();
    if !quic_listen.is_empty() {
        // QUIC 独立 UDP 端口（可选，与 WSS 共存）：自签证书，token 真认证。
        let qs = shared.clone();
        let qt = token.clone();
        let qb = quic_listen.to_string();
        tokio::spawn(async move {
            if let Err(e) = quic::run_quic(qs, qt, &qb).await {
                tracing::warn!("quic listener {qb} exited: {e:#}");
            }
        });
        println!("  quic     : udp://{quic_listen} (agent 用 --server quic://{quic_listen})");
    }
    if !kudus_listen.is_empty() {
        // kudus 独立 UDP 端口（可选，与 WSS/QUIC 共存）：预共享 token，自研可靠传输。
        let ks = shared.clone();
        let kt = token.clone();
        let kb = kudus_listen.to_string();
        tokio::spawn(async move {
            if let Err(e) = kudus::run_kudus(ks, kt, &kb).await {
                tracing::warn!("kudus listener {kb} exited: {e:#}");
            }
        });
        println!("  kudus    : udp-k://{kudus_listen} (agent 用 --server kudus://{kudus_listen})");
    }
    axum::serve(lis, svc).await?;
    Ok(())
}

