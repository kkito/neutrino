/// server 监听：ws + WebUI + HTTP 入站同端口。axum Router 先匹配
/// `/ws`、`/api/*`、`/`（WebUI）；未命中的 Host 走下面的 `fallback`，
/// 按隧道域名路由到 agent（`no such tunnel` 即该域名未配置）。
/// `--http-in` 仅兼容保留（有值会被忽略并 warn）。
use crate::proto::*;
use axum::{
    body::Body,
    extract::{ws::Message as WsMsg, ws::WebSocket, Path, Request, State, WebSocketUpgrade},
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Json},
    routing::{get, post},
    Router,
};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    sync::{mpsc, RwLock},
};

// ================= state =================
#[derive(Debug, Clone, Serialize)]
struct AgentInfo {
    agent_id: String,
    hostname: String,
    version: String,
    online_secs: i64,
    rtt_ms: i64,
    rx_bytes: u64,
    tx_bytes: u64,
    proxies: Vec<ProxyConfig>,
}

struct AgentHandle {
    info: AgentInfo,
    connected_at: chrono::DateTime<chrono::Utc>,
    ctl: mpsc::UnboundedSender<ServerMsg>,
    incoming: Arc<RwLock<HashMap<u32, mpsc::UnboundedSender<Vec<u8>>>>>,
}

#[derive(Default)]
struct Shared {
    agents: RwLock<HashMap<String, AgentHandle>>,
    /// domain(lower) -> agent_ids (multi-agent LB via round-robin)
    domains: RwLock<HashMap<String, Vec<String>>>,
    /// remote_port -> agent_ids (tcp/https/udp)
    tcp_ports: RwLock<HashMap<u16, Vec<String>>>,
    tcp_listening: RwLock<HashSet<u16>>,
    udp_listening: RwLock<HashSet<u16>>,
    events: RwLock<Vec<String>>,
    password_hash: RwLock<String>,
    jwt_secret: String,
    outbox: RwLock<HashMap<String, mpsc::UnboundedSender<(u32, Vec<u8>)>>>,
    totals: RwLock<HashMap<String, (u64, u64)>>, // hostname -> (rx,tx) persisted
    data_dir: String,
    desired: RwLock<HashMap<String, Vec<ProxyConfig>>>,
    desired_path: String,
}

/// If server holds desired proxies for this hostname, they win over what the
/// agent reported; otherwise fall back to the reported list.
fn resolve_proxies(desired: Option<Vec<ProxyConfig>>, reported: Vec<ProxyConfig>) -> Vec<ProxyConfig> {
    desired.unwrap_or(reported)
}

/// Replace one agent's routes (domains + ports + info) with `proxies`.
async fn apply_proxies_for_agent(s: &S, aid: &str, proxies: &[ProxyConfig]) {
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
            ensure_udp_listener(s, p.remote_port).await;
        } else {
            ensure_tcp_listener(s, p.remote_port).await;
        }
    }
}

type S = Arc<Shared>;

fn log_ev(s: &S, e: String) {
    tracing::info!("{e}");
    if let Ok(mut v) = s.events.try_write() {
        v.push(format!("{} {e}", chrono::Utc::now().format("%m-%d %H:%M:%S")));
        if v.len() > 500 {
            let n = v.len() - 500;
            v.drain(..n);
        }
    }
}

// ---------- pure helpers (unit-tested) ----------
fn extract_host(head: &str) -> String {
    head.lines()
        .find_map(|l| {
            let t = l.trim();
            if t.len() > 5 && t[..5].eq_ignore_ascii_case("host:") {
                Some(t[5..].trim().split(':').next().unwrap_or("").to_lowercase())
            } else {
                None
            }
        })
        .unwrap_or_default()
}

/// Inject/replace `X-Forwarded-Proto: <proto>` into an HTTP request head.
/// Returns rewritten bytes; if no header terminator found, returns input as-is.
fn inject_xfp(head: &[u8], proto: &str) -> Vec<u8> {
    let pos = match head.windows(4).position(|w| w == b"\r\n\r\n") {
        Some(i) => i,
        None => return head.to_vec(),
    };
    let (hdr, rest) = head.split_at(pos + 4);
    let mut out: Vec<u8> = Vec::with_capacity(head.len() + 32);
    // hdr ends with \r\n\r\n; strip it, filter lines, re-emit
    let inner = &hdr[..pos];
    let mut first = true;
    for ln in inner.split(|&c| c == b'\n') {
        let mut t: &[u8] = ln;
        while t.last() == Some(&b'\r') { t = &t[..t.len()-1]; }
        while t.first() == Some(&b' ') || t.first() == Some(&b'\t') { t = &t[1..]; }
        if !first && t.len() >= 18 && t[..18].eq_ignore_ascii_case(b"x-forwarded-proto:") {
            continue;
        }
        if !first && t.is_empty() { continue; }
        out.extend_from_slice(t);
        out.extend_from_slice(b"\r\n");
        first = false;
    }
    out.extend_from_slice(format!("X-Forwarded-Proto: {proto}\r\n").as_bytes());
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(&rest[..]);
    out
}

#[allow(dead_code)]
fn trim_crlf(mut b: &[u8]) -> &[u8] {    while let Some((&c, rest)) = b.split_first() {
        if c == b' ' || c == b'\t' || c == b'\r' || c == b'\n' {
            b = rest;
        } else {
            break;
        }
    }
    b
}

#[allow(dead_code)]
fn pick_rr(list: &[String], ctr: &AtomicUsize) -> Option<String> {
    if list.is_empty() {
        return None;
    }
    let i = ctr.fetch_add(1, Ordering::Relaxed) % list.len();
    list.get(i).cloned()
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: i64,
}

pub(crate) fn mint_jwt(secret: &str) -> String {
    let c = Claims {
        sub: "admin".into(),
        exp: (chrono::Utc::now() + chrono::Duration::hours(24)).timestamp(),
    };
    jsonwebtoken::encode(
        &jsonwebtoken::Header::default(),
        &c,
        &jsonwebtoken::EncodingKey::from_secret(secret.as_bytes()),
    )
    .unwrap_or_default()
}

pub(crate) fn verify_jwt(secret: &str, token: &str) -> bool {
    jsonwebtoken::decode::<Claims>(
        token,
        &jsonwebtoken::DecodingKey::from_secret(secret.as_bytes()),
        &jsonwebtoken::Validation::default(),
    )
    .map(|d| d.claims.sub == "admin")
    .unwrap_or(false)
}

fn auth_ok(headers: &HeaderMap, secret: &str) -> bool {
    // Bearer takes precedence (tests/CLI), else HttpOnly cookie `nt_session`
    if let Some(a) = headers.get(header::AUTHORIZATION) {
        if let Ok(s) = a.to_str() {
            if let Some(t) = s.strip_prefix("Bearer ") {
                if verify_jwt(secret, t.trim()) {
                    return true;
                }
            }
        }
    }
    if let Some(c) = headers.get(header::COOKIE) {
        if let Ok(s) = c.to_str() {
            for part in s.split(';') {
                let part = part.trim();
                if let Some(t) = part.strip_prefix("nt_session=") {
                    if verify_jwt(secret, t.trim()) {
                        return true;
                    }
                }
            }
        }
    }
    false
}

// ---------- persisted state ----------
#[derive(Debug, Default, Serialize, Deserialize)]
struct Persisted {
    #[serde(default)]
    totals: HashMap<String, (u64, u64)>,
    #[serde(default)]
    password_hash: String,
}

async fn load_state(data_dir: &str) -> Persisted {
    let p = format!("{data_dir}/state.json");
    match tokio::fs::read_to_string(&p).await {
        Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
        Err(_) => Persisted::default(),
    }
}

async fn save_state(s: &S) {
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
pub async fn run(listen: &str, _http_in: &str, data: &str, token: &str, desired: &str) -> anyhow::Result<()> {
    let _ = tokio::fs::create_dir_all(data).await;
    if !_http_in.is_empty() {
        tracing::warn!("--http-in is deprecated and ignored: HTTP ingress now shares --listen (Host routing)");
    }
    let ps = load_state(data).await;
    let ds = crate::desired::DesiredStore::load(desired);
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
                save_state(&s).await;
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

// ================= /ws =================
async fn ws_handler(
    ws: WebSocketUpgrade,
    State((s, token)): State<(S, Arc<String>)>,
) -> impl IntoResponse {
    ws.on_upgrade(move |sock| ws_loop(sock, s, token))
}

async fn ws_loop(sock: WebSocket, s: S, token: Arc<String>) {
    let (mut ws_send, mut ws_recv) = sock.split();
    let hello: ClientMsg = match tokio::time::timeout(Duration::from_secs(15), ws_recv.next())
        .await
    {
        Ok(Some(Ok(WsMsg::Text(t)))) => match serde_json::from_str(&t) {
            Ok(h @ ClientMsg::Hello { .. }) => h,
            _ => {
                let _ = ws_send
                    .send(WsMsg::Text(
                        serde_json::to_string(&ServerMsg::Error {
                            reason: "expect hello".into(),
                        })
                        .unwrap()
                        .into(),
                    ))
                    .await;
                return;
            }
        },
        _ => return,
    };
    let (hostname, version, tok) = match hello {
        ClientMsg::Hello {
            hostname,
            version,
            token,
        } => (hostname, version, token),
        _ => return,
    };
    if tok != *token {
        let _ = ws_send
            .send(WsMsg::Text(
                serde_json::to_string(&ServerMsg::Error {
                    reason: "bad token".into(),
                })
                .unwrap()
                .into(),
            ))
            .await;
        log_ev(&s, format!("auth failed from agent '{hostname}'"));
        return;
    }
    let agent_id = uuid::Uuid::new_v4().to_string()[..8].to_string();
    let (ctl_tx, mut ctl_rx) = mpsc::unbounded_channel::<ServerMsg>();
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<(u32, Vec<u8>)>();
    let incoming: Arc<RwLock<HashMap<u32, mpsc::UnboundedSender<Vec<u8>>>>> =
        Arc::new(RwLock::new(HashMap::new()));
    // restore persisted counters
    let (prx, ptx) = s.totals.read().await.get(&hostname).cloned().unwrap_or((0, 0));
    {
        s.agents.write().await.insert(
            agent_id.clone(),
            AgentHandle {
                info: AgentInfo {
                    agent_id: agent_id.clone(),
                    hostname: hostname.clone(),
                    version,
                    online_secs: 0,
                    rtt_ms: -1,
                    rx_bytes: prx,
                    tx_bytes: ptx,
                    proxies: vec![],
                },
                connected_at: chrono::Utc::now(),
                ctl: ctl_tx.clone(),
                incoming: incoming.clone(),
            },
        );
        s.outbox.write().await.insert(agent_id.clone(), out_tx);
    }
    log_ev(&s, format!("agent '{hostname}' connected id={agent_id}"));
    let w = serde_json::to_string(&ServerMsg::Welcome {
        agent_id: agent_id.clone(),
        interval: 30,
    })
    .unwrap();
    if ws_send.send(WsMsg::Text(w.into())).await.is_err() {
        return;
    }
    // server-side heartbeat: Ping every 15s, track RTT on Pong
    let last_ping = Arc::new(RwLock::new(None::<Instant>));
    {
        let ctl = ctl_tx.clone();
        let lp = last_ping.clone();
        let s3 = s.clone();
        let aid3 = agent_id.clone();
        tokio::spawn(async move {
            let mut iv = tokio::time::interval(Duration::from_secs(15));
            loop {
                iv.tick().await;
                *lp.write().await = Some(Instant::now());
                if ctl
                    .send(ServerMsg::Ping {
                        ts: chrono::Utc::now().timestamp(),
                    })
                    .is_err()
                {
                    break;
                }
                let _ = (&s3, &aid3);
            }
        });
    }

    loop {
        tokio::select! {
            msg = ws_recv.next() => {
                let Some(Ok(m)) = msg else { break };
                match m {
                    WsMsg::Text(t) => {
                        match serde_json::from_str::<ClientMsg>(&t) {
                            Ok(ClientMsg::Register { proxies }) => {
                                on_register(&s, &agent_id, &hostname, proxies).await;
                            }
                            Ok(ClientMsg::Ping { ts }) => { let _ = ctl_tx.send(ServerMsg::Pong { ts }); }
                            Ok(ClientMsg::Pong { .. }) => {
                                if let Some(t0) = *last_ping.read().await {
                                    let ms = t0.elapsed().as_millis() as i64;
                                    if let Some(h) = s.agents.write().await.get_mut(&agent_id) {
                                        h.info.rtt_ms = ms;
                                    }
                                }
                            }
                            Ok(ClientMsg::Close { stream, .. }) => {
                                if let Some(h) = s.agents.read().await.get(&agent_id) {
                                    h.incoming.write().await.remove(&stream);
                                }
                            }
                            Ok(ClientMsg::Open { stream, kind, host, port }) if kind == "egress" => {
                                spawn_egress_dial(&s, &agent_id, stream, host, port, ctl_tx.clone());
                            }
                            Ok(_) => {}
                            Err(e) => tracing::warn!("bad client frame: {e}"),
                        }
                    }
                    WsMsg::Binary(b) => {
                        if let Some((id, payload)) = decode_data(&b) {
                            let waiter = s.agents.read().await.get(&agent_id).map(|h| h.incoming.clone());
                            if let Some(st) = waiter {
                                if let Some(tx) = st.read().await.get(&id).cloned() {
                                    let _ = tx.send(payload.to_vec());
                                    if let Some(h) = s.agents.write().await.get_mut(&agent_id) {
                                        h.info.rx_bytes += payload.len() as u64;
                                    }
                                }
                            }
                        }
                    }
                    WsMsg::Close(_) => break,
                    _ => {}
                }
            }
            Some(m) = ctl_rx.recv() => {
                let t = serde_json::to_string(&m).unwrap();
                if ws_send.send(WsMsg::Text(t.into())).await.is_err() { break; }
            }
            Some((id, payload)) = out_rx.recv() => {
                if ws_send.send(WsMsg::Binary(encode_data(id, &payload).into())).await.is_err() { break; }
                if let Some(h) = s.agents.write().await.get_mut(&agent_id) {
                    h.info.tx_bytes += payload.len() as u64;
                }
            }
        }
    }
    // cleanup: persist counters, drop routes
    {
        let mut ag = s.agents.write().await;
        if let Some(h) = ag.remove(&agent_id) {
            s.totals.write().await.insert(hostname.clone(), (h.info.rx_bytes, h.info.tx_bytes));
        }
        s.outbox.write().await.remove(&agent_id);
        for v in s.domains.write().await.values_mut() {
            v.retain(|a| *a != agent_id);
        }
        for v in s.tcp_ports.write().await.values_mut() {
            v.retain(|a| *a != agent_id);
        }
    }
    save_state(&s).await;
    log_ev(&s, format!("agent '{hostname}' disconnected"));
}

/// agent 上报已与期望态一致时无需再 push Config（否则死循环）。
/// 空==空视为收敛（双方都没隧道时不 push）。
fn needs_config_push(reported: &[ProxyConfig], want: &[ProxyConfig]) -> bool {
    reported != want
}

/// egress 目标校验（纯函数，单测覆盖）：空 host / 0 端口拒绝。
fn valid_egress_target(host: &str, port: u16) -> bool {
    !host.trim().is_empty() && port != 0
}

/// server 侧 egress 拨号：agent Open{egress} -> TcpStream::connect(30s 超时) -> 接现有泵。
/// 根因→修法：与 ingress 对称但方向相反——ingress 是 server 收连接让 agent 拨本地，
/// egress 是 agent 发 Open 让 server 拨公网；泵结构复用 tcp ingress（incoming/outbox）。
fn spawn_egress_dial(
    s: &S,
    agent_id: &str,
    sid: u32,
    host: String,
    port: u16,
    ctl: mpsc::UnboundedSender<ServerMsg>,
) {
    if !valid_egress_target(&host, port) {
        let _ = ctl.send(ServerMsg::Close {
            stream: sid,
            reason: "egress denied: bad target".into(),
        });
        return;
    }
    let s = s.clone();
    let aid = agent_id.to_string();
    tokio::spawn(async move {
        let up = match tokio::time::timeout(
            std::time::Duration::from_secs(30),
            tokio::net::TcpStream::connect((host.as_str(), port)),
        )
        .await
        {
            Ok(Ok(u)) => u,
            Ok(Err(e)) => {
                let _ = ctl.send(ServerMsg::Close {
                    stream: sid,
                    reason: format!("dial refused: {e}"),
                });
                return;
            }
            Err(_) => {
                let _ = ctl.send(ServerMsg::Close {
                    stream: sid,
                    reason: "dial timeout 30s".into(),
                });
                return;
            }
        };
        // 接泵：incoming[sid] 收 agent 发来的 Binary 写给公网；outbox 发 Binary 给 agent。
        let (dtx, mut drx) = mpsc::unbounded_channel::<Vec<u8>>();
        let out = {
            let ag = s.agents.read().await;
            let ob = s.outbox.read().await;
            match (ag.get(&aid), ob.get(&aid)) {
                (Some(_), Some(o)) => o.clone(),
                _ => {
                    let _ = ctl.send(ServerMsg::Close {
                        stream: sid,
                        reason: "agent gone".into(),
                    });
                    return;
                }
            }
        };
        if let Some(h) = s.agents.read().await.get(&aid) {
            h.incoming.write().await.insert(sid, dtx);
        }
        let (mut ru, mut wu) = up.into_split();
        let out2 = out.clone();
        let to_public = tokio::spawn(async move {
            let mut b = vec![0u8; 32 * 1024];
            loop {
                let n = ru.read(&mut b).await?;
                if n == 0 {
                    break;
                }
                out2
                    .send((sid, b[..n].to_vec()))
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
            }
            anyhow::Ok(())
        });
        let from_agent = async {
            while let Some(chunk) = drx.recv().await {
                wu.write_all(&chunk).await?;
            }
            anyhow::Ok::<()>(())
        };
        tokio::select! {
            r = to_public => { let _ = r.unwrap(); }
            r = from_agent => { let _ = r; }
        }
        if let Some(h) = s.agents.read().await.get(&aid) {
            h.incoming.write().await.remove(&sid);
        }
        let _ = ctl.send(ServerMsg::Close {
            stream: sid,
            reason: "eof".into(),
        });
    });
}

async fn on_register(s: &S, agent_id: &str, hostname: &str, reported: Vec<ProxyConfig>) {
    let want = s.desired.read().await.get(hostname).cloned();
    let proxies = resolve_proxies(want.clone(), reported.clone());
    if want.is_some() {
        log_ev(s, format!("agent '{hostname}' desired overlay applied ({} proxies)", proxies.len()));
        // sync the agent's local routing table: it dials by its own copy,
        // so push the overlaid list back (agent re-Registers on Config).
        // 已收敛则跳过：否则 Register -> Config -> Register 无限 ping-pong 刷屏。
        if !needs_config_push(&reported, &proxies) {
            tracing::debug!("agent '{hostname}' already converged, skip Config push");
        } else if let Some(ctl) = s.agents.read().await.get(agent_id).map(|h| h.ctl.clone()) {
            let _ = ctl.send(ServerMsg::Config { proxies: proxies.clone() });
        }
    }
    apply_proxies_for_agent(s, agent_id, &proxies).await;
    log_ev(
        s,
        format!("agent '{hostname}' registered {} proxies", proxies.len()),
    );
}

// route pickers (LB)
/// http 入口路由：返回 (agent_id, 隧道配置快照)。快照里带 basic_auth，
/// 调用方在透传前用 check_basic_auth 校验，不通过直接 401。
async fn pick_http(s: &S, host: &str) -> Option<(String, crate::proto::ProxyConfig)> {
    // simple round-robin: rotate the candidate vec under write lock
    let aid = {
        let mut dom = s.domains.write().await;
        let v = dom.get_mut(&host.to_lowercase())?;
        if v.is_empty() {
            return None;
        }
        let aid = v.remove(0);
        v.push(aid.clone());
        aid
    };
    // find proxy snapshot for this agent+host (xfp + basic_auth live here)
    let ag = s.agents.read().await;
    let proxy = ag.get(&aid).and_then(|h| {
        h.info
            .proxies
            .iter()
            .find(|p| {
                p.enabled && p.domains.iter().any(|d| d.eq_ignore_ascii_case(host))
            })
            .cloned()
    })?;
    // only return live agents
    if ag.contains_key(&aid) {
        Some((aid, proxy))
    } else {
        None
    }
}

async fn pick_port(s: &S, port: u16, kind: &str) -> Option<String> {
    let mut tp = s.tcp_ports.write().await;
    let v = tp.get_mut(&port)?;
    if v.is_empty() {
        return None;
    }
    // try each candidate until a live one with matching proxy type found
    for _ in 0..v.len() {
        let aid = v.remove(0);
        v.push(aid.clone());
        let ag = s.agents.read().await;
        let ok = ag.get(&aid).map(|h| {
            h.info.proxies.iter().any(|p| {
                p.enabled
                    && p.remote_port == port
                    && (p.ptype == kind
                        || (kind == "tcp" && p.ptype == "https")
                        || (kind == "https" && p.ptype == "tcp"))
            })
        });
        if ok == Some(true) {
            return Some(aid);
        }
    }
    None
}

// ================= http ingress =================
static STREAM_CTR: std::sync::LazyLock<AtomicUsize> =
    std::sync::LazyLock::new(|| AtomicUsize::new(0));

fn next_sid() -> u32 {
    // even ids from server; wrap-safe
    ((STREAM_CTR.fetch_add(1, Ordering::Relaxed) as u32).wrapping_mul(2)).wrapping_add(2)
}

/// 单端口 fallback 路由判定：tunneled=true 表示该 Host 命中某 agent 隧道。
/// - 命中隧道 -> 透传给 agent（无论路径）
/// - 未命中 + 裸 IP/localhost/空 Host -> WebUI（方便直接打开 IP:端口看管理页）
/// - 未命中 + 其他（点分域名） -> 404 `no such tunnel`
#[derive(Debug, PartialEq, Eq)]
enum FallbackRoute {
    Tunnel,
    WebUi,
    NotFound,
}

fn route_fallback(host: &str, tunneled: bool) -> FallbackRoute {
    if tunneled {
        return FallbackRoute::Tunnel;
    }
    if host.is_empty() || host == "localhost" || host.parse::<std::net::IpAddr>().is_ok() {
        return FallbackRoute::WebUi;
    }
    if host.contains('.') {
        return FallbackRoute::NotFound;
    }
    FallbackRoute::WebUi
}

/// axum fallback：已注册的 `/ws`、`/api/*` 优先匹配；
/// 其余路径按 Host 路由到隧道 agent。整包转发给 agent，响应流式回写；
/// 未知域名 404（`no such tunnel`），裸 IP/localhost 访问落到 WebUI。
async fn fallback_http_ingress(
    State((s, _)): State<(S, Arc<String>)>,
    req: Request,
) -> impl IntoResponse {
    use axum::body::to_bytes;
    let (parts, body) = req.into_parts();
    let host = parts
        .headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("")
        .to_lowercase();
    // 分流判定见 route_fallback：注意不能给 `/` 注册精确路由，否则
    // curl/e2e 常用的 `GET / + Host: 隧道域名` 会被 WebUI 抢走。
    let tunneled = pick_http(&s, &host).await;
    let (aid, proxy) = match route_fallback(&host, tunneled.is_some()) {
        FallbackRoute::Tunnel => tunneled.unwrap(),
        FallbackRoute::WebUi => return index_page().await.into_response(),
        FallbackRoute::NotFound => {
            return (StatusCode::NOT_FOUND, "no such tunnel\n").into_response()
        }
    };
    let xfp = proxy.set_x_forwarded_proto.clone();
    // http 隧道入口 basic auth：配了 basic_auth 才校验，无 Authorization/错口令直接 401。
    // 浏览器收到 WWW-Authenticate 会弹登录框；校验在 server 侧做，agent/内网服务无感知。
    if !crate::proto::check_basic_auth(&parts.headers, proxy.basic_auth.as_deref()) {
        return (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, format!("Basic realm=\"{}\"", proxy.name))],
            "auth required\n",
        )
            .into_response();
    }
    // 重建原始请求头字节流（含 XFP 注入），body 拼回去
    let version = match parts.version {
        ::axum::http::Version::HTTP_10 => "HTTP/1.0",
        _ => "HTTP/1.1",
    };
    let path = parts.uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    let mut head = format!("{} {} {version}\r\n", parts.method, path).into_bytes();
    for (k, v) in parts.headers.iter() {
        if k.as_str().eq_ignore_ascii_case("x-forwarded-proto") {
            continue;
        }
        head.extend_from_slice(format!("{}: {}\r\n", k, v.to_str().unwrap_or("")).as_bytes());
    }
    if let Some(p) = &xfp {
        head.extend_from_slice(format!("X-Forwarded-Proto: {p}\r\n").as_bytes());
    }
    head.extend_from_slice(b"\r\n");
    let body_bytes = to_bytes(body, 8 * 1024 * 1024).await.unwrap_or_default();
    head.extend_from_slice(&body_bytes);
    let sid = next_sid();
    let (dtx, mut drx) = mpsc::unbounded_channel::<Vec<u8>>();
    let (ctl, out) = {
        let ag = s.agents.read().await;
        let ob = s.outbox.read().await;
        match (ag.get(&aid), ob.get(&aid)) {
            (Some(h), Some(o)) => (h.ctl.clone(), o.clone()),
            _ => return (StatusCode::BAD_GATEWAY, "agent gone\n").into_response(),
        }
    };
    if let Some(h) = s.agents.read().await.get(&aid) {
        h.incoming.write().await.insert(sid, dtx);
    }
    let _ = ctl.send(ServerMsg::Open {
        stream: sid,
        kind: "http".into(),
        host,
        port: 0,
    });
    if out.send((sid, head)).is_err() {
        return (StatusCode::BAD_GATEWAY, "agent gone\n").into_response();
    }
    // 等 agent 回包（首个响应头），超时 30s
    let first = tokio::time::timeout(Duration::from_secs(30), drx.recv()).await;
    let first = match first {
        Ok(Some(b)) => b,
        _ => {
            if let Some(h) = s.agents.read().await.get(&aid) {
                h.incoming.write().await.remove(&sid);
            }
            let _ = ctl.send(ServerMsg::Close { stream: sid, reason: "timeout".into() });
            return (StatusCode::BAD_GATEWAY, "upstream timeout\n").into_response();
        }
    };
    // 简单解析状态行 + 头，body 用流式 Body 拼后续帧
    let (status, resp_headers, prefix) = parse_response_head(&first);
    let s2 = s.clone();
    let stream = async_stream_lite(s2, aid, sid, ctl, drx, prefix);
    let mut resp = axum::response::Response::builder().status(status);
    for (k, v) in resp_headers {
        resp = resp.header(k, v);
    }
    resp.body(Body::from_stream(stream)).unwrap().into_response()
}

/// 最小 HTTP 响应头解析：返回 (status, headers, 首包剩余 body 前缀)。
fn parse_response_head(buf: &[u8]) -> (StatusCode, Vec<(String, String)>, Vec<u8>) {
    let pos = buf.windows(4).position(|w| w == b"\r\n\r\n");
    let (hdr, rest) = match pos {
        Some(i) => (&buf[..i], buf[i + 4..].to_vec()),
        None => (buf, vec![]),
    };
    let text = String::from_utf8_lossy(hdr);
    let mut lines = text.lines();
    let status = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse::<u16>().ok())
        .and_then(|c| StatusCode::from_u16(c).ok())
        .unwrap_or(StatusCode::OK);
    let mut headers = vec![];
    for l in lines {
        if let Some((k, v)) = l.split_once(':') {
            let k = k.trim().to_lowercase();
            // hop-by-hop 头由 hyper 接管，去掉避免冲突
            if matches!(k.as_str(), "transfer-encoding" | "connection" | "keep-alive" | "upgrade") {
                continue;
            }
            headers.push((k, v.trim().to_string()));
        }
    }
    (status, headers, rest)
}

/// 后续响应帧 -> axum Body 流；流结束即发 Close 并清理 stream 注册。
fn async_stream_lite(
    s: S,
    aid: String,
    sid: u32,
    ctl: mpsc::UnboundedSender<ServerMsg>,
    drx: mpsc::UnboundedReceiver<Vec<u8>>, // async_stream_lite 内消费
    prefix: Vec<u8>,
) -> impl futures_util::Stream<Item = Result<axum::body::Bytes, std::io::Error>> {
    use futures_util::stream::{once, unfold};
    use futures_util::StreamExt;
    let pre = if prefix.is_empty() {
        futures_util::stream::empty().boxed()
    } else {
        once(async { Ok(axum::body::Bytes::from(prefix)) }).boxed()
    };
    let rest = unfold(Some((s, aid, sid, ctl, drx)), |st| async {
        let (s, aid, sid, ctl, mut drx) = st?;
        match drx.recv().await {
            Some(chunk) => Some((Ok(axum::body::Bytes::from(chunk)), Some((s, aid, sid, ctl, drx)))),
            None => {
                if let Some(h) = s.agents.read().await.get(&aid) {
                    h.incoming.write().await.remove(&sid);
                }
                let _ = ctl.send(ServerMsg::Close { stream: sid, reason: "eof".into() });
                None
            }
        }
    });
    pre.chain(rest)
}

/// 旧独立端口 http_ingress 已并入上面的 axum fallback（同端口 Host 路由）。
/// 保留此函数体作裸 TCP 透传参考，当前不再被调用。
/// 注意：basic auth 校验只在 axum fallback 生效；此旧路径若重新启用，需补同样校验。
#[allow(dead_code)]
async fn http_ingress(bind: &str, s: S) -> anyhow::Result<()> {
    let lis = TcpListener::bind(bind).await?;
    tracing::info!("http ingress on {bind}");
    loop {
        let (mut inbound, _peer) = lis.accept().await?;
        let s = s.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 16384];
            let n = match inbound.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => n,
            };
            buf.truncate(n);
            let host = extract_host(&String::from_utf8_lossy(&buf));
            let Some((aid, proxy)) = pick_http(&s, &host).await else {
                let r = "HTTP/1.1 404 Not Found\r\ncontent-length: 15\r\nconnection: close\r\n\r\nno such tunnel\n";
                let _ = inbound.write_all(r.as_bytes()).await;
                return;
            };
            let xfp = proxy.set_x_forwarded_proto.clone();
            let head = match xfp {
                Some(p) => inject_xfp(&buf, &p),
                None => buf,
            };
            // reserve stream id + register queue BEFORE Open so no race
            let sid = next_sid();
            let (dtx, mut drx) = mpsc::unbounded_channel::<Vec<u8>>();
            let (ctl, out) = {
                let ag = s.agents.read().await;
                let ob = s.outbox.read().await;
                match (ag.get(&aid), ob.get(&aid)) {
                    (Some(h), Some(o)) => (h.ctl.clone(), o.clone()),
                    _ => return,
                }
            };
            if let Some(h) = s.agents.read().await.get(&aid) {
                h.incoming.write().await.insert(sid, dtx);
            }
            let _ = ctl.send(ServerMsg::Open {
                stream: sid,
                kind: "http".into(),
                host,
                port: 0,
            });
            if out.send((sid, head)).is_err() {
                return;
            }
            let (mut ri, mut wi) = inbound.into_split();
            let out2 = out.clone();
            let to_agent = tokio::spawn(async move {
                let mut b = vec![0u8; 32 * 1024];
                loop {
                    let n = ri.read(&mut b).await?;
                    if n == 0 {
                        break;
                    }
                    out2
                        .send((sid, b[..n].to_vec()))
                        .map_err(|e| anyhow::anyhow!("{e}"))?;
                }
                anyhow::Ok(())
            });
            let from_agent = async {
                while let Some(chunk) = drx.recv().await {
                    wi.write_all(&chunk).await?;
                }
                anyhow::Ok::<()>(())
            };
            tokio::select! {
                r = to_agent => { let _ = r.unwrap(); }
                r = from_agent => { let _ = r; }
            }
            if let Some(h) = s.agents.read().await.get(&aid) {
                h.incoming.write().await.remove(&sid);
            }
            let _ = ctl.send(ServerMsg::Close {
                stream: sid,
                reason: "eof".into(),
            });
        });
    }
}

// ================= tcp ingress (per remote_port, lazy) =================
async fn ensure_tcp_listener(s: &S, port: u16) {
    if s.tcp_listening.read().await.contains(&port) {
        return;
    }
    s.tcp_listening.write().await.insert(port);
    let s2 = s.clone();
    tokio::spawn(async move {
        match TcpListener::bind(("0.0.0.0", port)).await {
            Ok(lis) => {
                tracing::info!("tcp ingress on 0.0.0.0:{port}");
                log_ev(&s2, format!("tcp listening :{port}"));
                loop {
                    let Ok((inbound, _)) = lis.accept().await else {
                        continue;
                    };
                    let s3 = s2.clone();
                    tokio::spawn(async move {
                        let Some(aid) =
                            pick_port(&s3, port, "tcp").await
                        else {
                            return;
                        };
                        let sid = next_sid();
                        let (dtx, mut drx) = mpsc::unbounded_channel::<Vec<u8>>();
                        let (ctl, out) = {
                            let ag = s3.agents.read().await;
                            let ob = s3.outbox.read().await;
                            match (ag.get(&aid), ob.get(&aid)) {
                                (Some(h), Some(o)) => (h.ctl.clone(), o.clone()),
                                _ => return,
                            }
                        };
                        if let Some(h) = s3.agents.read().await.get(&aid) {
                            h.incoming.write().await.insert(sid, dtx);
                        }
                        let _ = ctl.send(ServerMsg::Open {
                            stream: sid,
                            kind: "tcp".into(),
                            host: String::new(),
                            port,
                        });
                        let (mut ri, mut wi) = inbound.into_split();
                        let out2 = out.clone();
                        let to_agent = tokio::spawn(async move {
                            let mut b = vec![0u8; 32 * 1024];
                            loop {
                                let n = ri.read(&mut b).await?;
                                if n == 0 {
                                    break;
                                }
                                out2
                                    .send((sid, b[..n].to_vec()))
                                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                            }
                            anyhow::Ok(())
                        });
                        let from_agent = async {
                            while let Some(chunk) = drx.recv().await {
                                wi.write_all(&chunk).await?;
                            }
                            anyhow::Ok::<()>(())
                        };
                        tokio::select! {
                            r = to_agent => { let _ = r.unwrap(); }
                            r = from_agent => { let _ = r; }
                        }
                        if let Some(h) = s3.agents.read().await.get(&aid) {
                            h.incoming.write().await.remove(&sid);
                        }
                        let _ = ctl.send(ServerMsg::Close {
                            stream: sid,
                            reason: "eof".into(),
                        });
                    });
                }
            }
            Err(e) => {
                tracing::warn!("tcp bind :{port} failed: {e:#}");
                s2.tcp_listening.write().await.remove(&port);
            }
        }
    });
}

// ================= udp ingress (per remote_port, session per peer) =================
async fn ensure_udp_listener(s: &S, port: u16) {
    if s.udp_listening.read().await.contains(&port) {
        return;
    }
    s.udp_listening.write().await.insert(port);
    let s2 = s.clone();
    tokio::spawn(async move {
        let sock = match UdpSocket::bind(("0.0.0.0", port)).await {
            Ok(x) => Arc::new(x),
            Err(e) => {
                tracing::warn!("udp bind :{port} failed: {e:#}");
                s2.udp_listening.write().await.remove(&port);
                return;
            }
        };
        tracing::info!("udp ingress on 0.0.0.0:{port}");
        log_ev(&s2, format!("udp listening :{port}"));
        // peer -> (stream_id, last_seen)
        let mut sessions: HashMap<std::net::SocketAddr, (u32, Instant)> = HashMap::new();
        let mut buf = vec![0u8; 65535];
        loop {
            // expire old sessions
            sessions.retain(|_, (_, t)| t.elapsed() < Duration::from_secs(120));
            let (n, peer) = match sock.recv_from(&mut buf).await {
                Ok(x) => x,
                Err(_) => continue,
            };
            let sid = match sessions.get_mut(&peer) {
                Some((id, t)) => {
                    *t = Instant::now();
                    *id
                }
                None => {
                    let Some(aid) = pick_port(&s2, port, "udp").await else {
                        continue;
                    };
                    let id = next_sid();
                    let (dtx, mut drx) = mpsc::unbounded_channel::<Vec<u8>>();
                    let (ctl, out) = {
                        let ag = s2.agents.read().await;
                        let ob = s2.outbox.read().await;
                        match (ag.get(&aid), ob.get(&aid)) {
                            (Some(h), Some(o)) => (h.ctl.clone(), o.clone()),
                            _ => continue,
                        }
                    };
                    if let Some(h) = s2.agents.read().await.get(&aid) {
                        h.incoming.write().await.insert(id, dtx);
                    }
                    let _ = ctl.send(ServerMsg::Open {
                        stream: id,
                        kind: "udp".into(),
                        host: String::new(),
                        port,
                    });
                    // agent->internet pump for this peer
                    let sock2 = sock.clone();
                    let s3 = s2.clone();
                    let aid3 = aid.clone();
                    tokio::spawn(async move {
                        while let Some(chunk) = drx.recv().await {
                            let _ = sock2.send_to(&chunk, peer).await;
                            if let Some(h) = s3.agents.write().await.get_mut(&aid3)
                            {
                                h.info.tx_bytes += chunk.len() as u64;
                            }
                        }
                    });
                    let _ = out;
                    sessions.insert(peer, (id, Instant::now()));
                    id
                }
            };
            // internet -> agent (each datagram = one data frame)
            let payload = buf[..n].to_vec();
            // find owner agent of this stream
            let owner: Option<mpsc::UnboundedSender<(u32, Vec<u8>)>> = {
                let ag = s2.agents.read().await;
                let ob = s2.outbox.read().await;
                // stream registry: scan agents' incoming for sid
                let mut found = None;
                for (aid, h) in ag.iter() {
                    if h.incoming.read().await.contains_key(&sid) {
                        found = ob.get(aid).cloned();
                        break;
                    }
                }
                found
            };
            if let Some(o) = owner {
                let _ = o.send((sid, payload.clone()));
                // rx accounting
                let mut agm = s2.agents.write().await;
                for h in agm.values_mut() {
                    if h.incoming.try_read().map(|m| m.contains_key(&sid)).unwrap_or(false) {
                        h.info.rx_bytes += payload.len() as u64;
                        break;
                    }
                }
            }
        }
    });
}

// ================= WebUI =================
async fn index_page() -> Html<&'static str> {
    Html(include_str!("../web/index.html"))
}

#[derive(Deserialize)]
struct LoginReq {
    user: String,
    pass: String,
}

async fn api_login(
    State((s, _)): State<(S, Arc<String>)>,
    Json(r): Json<LoginReq>,
) -> impl IntoResponse {
    let h = s.password_hash.read().await.clone();
    let ok = if h.is_empty() {
        r.user == "admin" && r.pass == "welcome2neutrino"
    } else {
        r.user == "admin" && bcrypt::verify(&r.pass, &h).unwrap_or(false)
    };
    if !ok {
        log_ev(&s, format!("webui login failed user={}", r.user));
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"ok":false}))).into_response();
    }
    let jwt = mint_jwt(&s.jwt_secret);
    let mut resp = Json(serde_json::json!({"ok": true, "token": jwt.clone()})).into_response();
    resp.headers_mut().insert(
        header::SET_COOKIE,
        format!("nt_session={jwt}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400")
            .parse()
            .unwrap(),
    );
    resp
}

fn unauthorized() -> axum::response::Response {
    (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"ok": false}))).into_response()
}

async fn api_overview(
    State((s, _)): State<(S, Arc<String>)>,
    h: HeaderMap,
) -> impl IntoResponse {
    let s2 = s.clone();
    if !auth_ok(&h, &s2.jwt_secret) {
        return unauthorized();
    }
    let ag = s.agents.read().await;
    let list: Vec<AgentInfo> = ag
        .values()
        .map(|h| {
            let mut i = h.info.clone();
            i.online_secs = (chrono::Utc::now() - h.connected_at).num_seconds();
            i
        })
        .collect();
    Json(serde_json::json!({"agents": list})).into_response()
}

async fn api_tunnels(
    State((s, _)): State<(S, Arc<String>)>,
    h: HeaderMap,
) -> impl IntoResponse {
    let s2 = s.clone();
    if !auth_ok(&h, &s2.jwt_secret) {
        return unauthorized();
    }
    let ag = s.agents.read().await;
    let mut out = vec![];
    for hh in ag.values() {
        for p in &hh.info.proxies {
            out.push(serde_json::json!({
                "agent": hh.info.hostname, "agent_id": hh.info.agent_id,
                "name": p.name, "enabled": p.enabled,
                "type": p.ptype, "domains": p.domains, "remote_port": p.remote_port,
                "target": format!("{}:{}", p.local_ip, p.local_port),
                "status": if p.enabled { "online" } else { "disabled" },
            }));
        }
    }
    Json(serde_json::json!({"tunnels": out})).into_response()
}

async fn api_logs(
    State((s, _)): State<(S, Arc<String>)>,
    h: HeaderMap,
) -> impl IntoResponse {
    let s2 = s.clone();
    if !auth_ok(&h, &s2.jwt_secret) {
        return unauthorized();
    }
    let v = s.events.read().await.clone();
    Json(serde_json::json!({"logs": v})).into_response()
}

#[derive(Deserialize)]
struct ConfigReq {
    #[serde(default)]
    agent_id: String,
    #[serde(default)]
    hostname: String,
    proxies: Vec<ProxyConfig>,
}

/// Push proxy list to agent (hot update, WSS stays up).
async fn api_config(
    State((s, _)): State<(S, Arc<String>)>,
    h: HeaderMap,
    Json(r): Json<ConfigReq>,
) -> impl IntoResponse {
    let s2 = s.clone();
    if !auth_ok(&h, &s2.jwt_secret) {
        return unauthorized();
    }
    // resolve target agents
    let targets: Vec<(String, String, mpsc::UnboundedSender<ServerMsg>)> = {
        let ag = s.agents.read().await;
        ag.iter()
            .filter(|(_, hh)| {
                (!r.agent_id.is_empty() && hh.info.agent_id == r.agent_id)
                    || (!r.hostname.is_empty() && hh.info.hostname == r.hostname)
                    || (r.agent_id.is_empty() && r.hostname.is_empty())
            })
            .map(|(id, hh)| (id.clone(), hh.info.hostname.clone(), hh.ctl.clone()))
            .collect()
    };
    if targets.is_empty() {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"ok": false, "reason": "no such agent"})),
        )
            .into_response();
    }
    for (aid, hostname, ctl) in &targets {
        let _ = ctl.send(ServerMsg::Config {
            proxies: r.proxies.clone(),
        });
        apply_proxies_for_agent(&s, aid, &r.proxies).await;
        log_ev(&s, format!("config pushed to '{hostname}' ({} proxies)", r.proxies.len()));
    }
    Json(serde_json::json!({"ok": true, "pushed": targets.len()})).into_response()
}

/// Validate one proxy entry from the desired-CRUD form.
fn validate_proxy(p: &ProxyConfig) -> Result<(), String> {
    if p.name.is_empty() {
        return Err("name required".into());
    }
    match p.ptype.as_str() {
        "http" => {
            if p.domains.is_empty() {
                return Err("http proxy requires domains".into());
            }
            Ok(())
        }
        "tcp" | "https" | "udp" => {
            if p.remote_port == 0 {
                return Err(format!("{} proxy requires remote_port", p.ptype));
            }
            Ok(())
        }
        t => Err(format!("unknown type '{t}'")),
    }
}

#[derive(Deserialize)]
struct DesiredReq {
    proxies: Vec<ProxyConfig>,
}

/// Read desired proxies for one hostname.
async fn api_desired_get(
    State((s, _)): State<(S, Arc<String>)>,
    h: HeaderMap,
    Path(hostname): Path<String>,
) -> impl IntoResponse {
    let s2 = s.clone();
    if !auth_ok(&h, &s2.jwt_secret) {
        return unauthorized();
    }
    let proxies = s.desired.read().await.get(&hostname).cloned().unwrap_or_default();
    Json(serde_json::json!({"proxies": proxies})).into_response()
}

/// Replace desired proxies: persist to file, apply to routing, push if online.
async fn api_desired_set(
    State((s, _)): State<(S, Arc<String>)>,
    h: HeaderMap,
    Path(hostname): Path<String>,
    Json(r): Json<DesiredReq>,
) -> impl IntoResponse {
    let s2 = s.clone();
    if !auth_ok(&h, &s2.jwt_secret) {
        return unauthorized();
    }
    for p in &r.proxies {
        if let Err(e) = validate_proxy(p) {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"ok": false, "reason": e}))).into_response();
        }
    }
    // persist first; on write failure keep memory untouched
    {
        let mut st = crate::desired::DesiredStore::load(&s.desired_path);
        for (hh, pp) in s.desired.read().await.iter() {
            if hh != &hostname {
                st.set(hh.clone(), pp.clone());
            }
        }
        st.set(hostname.clone(), r.proxies.clone());
        let probe = format!("{}.tmp", st.path);
        if let Err(e) = std::fs::write(&probe, b"probe") {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"ok": false, "reason": e.to_string()}))).into_response();
        }
        let _ = std::fs::remove_file(&probe);
        st.save();
    }
    s.desired.write().await.insert(hostname.clone(), r.proxies.clone());
    let targets: Vec<(String, mpsc::UnboundedSender<ServerMsg>)> = {
        s.agents.read().await.values()
            .filter(|hh| hh.info.hostname == hostname)
            .map(|hh| (hh.info.agent_id.clone(), hh.ctl.clone()))
            .collect()
    };
    let mut pushed = 0;
    for (aid, ctl) in &targets {
        let _ = ctl.send(ServerMsg::Config { proxies: r.proxies.clone() });
        apply_proxies_for_agent(&s, aid, &r.proxies).await;
        pushed += 1;
    }
    log_ev(&s, format!("desired set for '{hostname}' ({} proxies, pushed {pushed})", r.proxies.len()));
    Json(serde_json::json!({"ok": true, "pushed": pushed})).into_response()
}

#[derive(Deserialize)]
struct ToggleReq {
    enabled: bool,
}

/// Enable/disable one proxy by name, then hot-push full list to that agent.
async fn api_toggle(
    State((s, _)): State<(S, Arc<String>)>,
    h: HeaderMap,
    Path((agent, name)): Path<(String, String)>,
    Json(r): Json<ToggleReq>,
) -> impl IntoResponse {
    let s2 = s.clone();
    if !auth_ok(&h, &s2.jwt_secret) {
        return unauthorized();
    }
    let (aid, ctl, proxies) = {
        let mut ag = s.agents.write().await;
        let found = ag.values_mut().find(|hh| {
            hh.info.agent_id == agent || hh.info.hostname == agent
        });
        let Some(hh) = found else {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"ok": false, "reason": "no such agent"})),
            )
                .into_response();
        };
        let mut hit = false;
        for p in hh.info.proxies.iter_mut() {
            if p.name == name {
                p.enabled = r.enabled;
                hit = true;
            }
        }
        if !hit {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"ok": false, "reason": "no such proxy"})),
            )
                .into_response();
        }
        (hh.info.agent_id.clone(), hh.ctl.clone(), hh.info.proxies.clone())
    };
    let _ = ctl.send(ServerMsg::Config {
        proxies: proxies.clone(),
    });
    apply_proxies_for_agent(&s, &aid, &proxies).await;
    log_ev(&s, format!("tunnel {agent}/{name} enabled={}", r.enabled));
    Json(serde_json::json!({"ok": true})).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn egress_target_rejects_empty_host() {
        assert!(!valid_egress_target("", 80));
        assert!(!valid_egress_target("   ", 80));
        assert!(!valid_egress_target("x", 0));
        assert!(valid_egress_target("example.com", 443));
    }

    #[test]
    fn basic_auth_gate() {
        use crate::proto::check_basic_auth;
        fn h(auth: Option<&str>) -> http::HeaderMap {
            let mut m = http::HeaderMap::new();
            if let Some(a) = auth {
                m.insert(http::header::AUTHORIZATION, a.parse().unwrap());
            }
            m
        }
        // 没配 = 直接放行
        assert!(check_basic_auth(&h(None), None));
        assert!(check_basic_auth(&h(None), Some("")));
        // 配了：无头/错 scheme/错口令都拒绝，只有精确 user:pass 放行
        let exp = Some("admin:s3cret");
        assert!(!check_basic_auth(&h(None), exp));
        assert!(!check_basic_auth(&h(Some("Bearer xxx")), exp));
        assert!(!check_basic_auth(&h(Some("Basic YWRtaW46d3Jvbmc=")), exp)); // admin:wrong
        assert!(check_basic_auth(&h(Some("Basic YWRtaW46czNjcmV0")), exp)); // admin:s3cret
        // serde 兼容：老配置没 basic_auth 字段也能解析，默认 None
        let p: crate::proto::ProxyConfig = serde_json::from_str(
            r#"{"name":"w","type":"http","local_ip":"127.0.0.1","local_port":80,"domains":["a.test"]}"#,
        )
        .unwrap();
        assert_eq!(p.basic_auth, None);
    }

    #[test]
    fn desired_validation() {
        let ok_http = ProxyConfig {
            name: "w".into(),
            ptype: "http".into(),
            local_ip: "127.0.0.1".into(),
            local_port: 80,
            domains: vec!["a.test".into()],
            remote_port: 0,
            set_x_forwarded_proto: None,
            basic_auth: None,
            enabled: true,
        };
        assert!(validate_proxy(&ok_http).is_ok());
        let mut bad = ok_http.clone();
        bad.domains.clear();
        assert!(validate_proxy(&bad).is_err());
        let mut tcp = ok_http.clone();
        tcp.ptype = "tcp".into();
        tcp.domains.clear();
        assert!(validate_proxy(&tcp).is_err());
        tcp.remote_port = 2222;
        assert!(validate_proxy(&tcp).is_ok());
        let mut unk = tcp.clone();
        unk.ptype = "socks".into();
        assert!(validate_proxy(&unk).is_err());
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

    #[test]
    fn host_extract() {
        assert_eq!(
            extract_host("GET / HTTP/1.1\r\nHost: Git.NAT.kkito.cn:7443\r\n\r\n"),
            "git.nat.kkito.cn"
        );
        assert_eq!(extract_host("GET / HTTP/1.1\r\n\r\n"), "");
    }

    #[test]
    fn xfp_inject_replaces() {
        let raw = b"GET / HTTP/1.1\r\nHost: a\r\nX-Forwarded-Proto: http\r\n\r\nbody";
        let out = inject_xfp(raw, "https");
        let s = String::from_utf8(out).unwrap();
        assert_eq!(s.matches("X-Forwarded-Proto:").count(), 1);
        assert!(s.contains("X-Forwarded-Proto: https"));
        assert!(s.ends_with("body"));
    }

    #[test]
    fn xfp_inject_adds() {
        let raw = b"GET / HTTP/1.1\r\nHost: a\r\n\r\n";
        let s = String::from_utf8(inject_xfp(raw, "https")).unwrap();
        assert!(s.contains("X-Forwarded-Proto: https\r\n\r\n"));
    }

    #[test]
    fn xfp_no_terminator_passthrough() {
        let raw = b"GET / partial";
        assert_eq!(inject_xfp(raw, "https"), raw);
    }

    #[test]
    fn jwt_roundtrip_and_reject() {
        let sec = "test-secret-123";
        let t = mint_jwt(sec);
        assert!(verify_jwt(sec, &t));
        assert!(!verify_jwt(sec, "bogus"));
        assert!(!verify_jwt("other", &t));
    }

    #[test]
    fn auth_header_and_cookie() {
        let sec = "s3cr3t";
        let t = mint_jwt(sec);
        let mut h = HeaderMap::new();
        h.insert(header::AUTHORIZATION, format!("Bearer {t}").parse().unwrap());
        assert!(auth_ok(&h, sec));
        let mut c = HeaderMap::new();
        c.insert(header::COOKIE, format!("x=1; nt_session={t}").parse().unwrap());
        assert!(auth_ok(&c, sec));
        assert!(!auth_ok(&HeaderMap::new(), sec));
    }

    #[test]
    fn rr_cycles() {
        let list = vec!["a".to_string(), "b".to_string()];
        let c = AtomicUsize::new(0);
        assert_eq!(
            vec![
                pick_rr(&list, &c),
                pick_rr(&list, &c),
                pick_rr(&list, &c)
            ],
            vec![
                Some("a".to_string()),
                Some("b".to_string()),
                Some("a".to_string())
            ]
        );
        assert_eq!(pick_rr(&[], &c), None);
    }

    #[test]
    fn state_serde_compat() {
        let p: Persisted = serde_json::from_str(r#"{"totals":{"h":[1,2]}}"#).unwrap();
        assert_eq!(p.totals["h"], (1, 2));
        assert!(p.password_hash.is_empty());
    }

    #[test]
    fn fallback_routes_tunnel_when_matched() {
        // 命中隧道：无论路径/Host 形式都透传（WebUI `/` 不抢）
        assert_eq!(route_fallback("web.e2e.test", true), FallbackRoute::Tunnel);
        assert_eq!(route_fallback("127.0.0.1", true), FallbackRoute::Tunnel);
    }

    #[test]
    fn fallback_routes_webui_for_local() {
        // 裸 IP（v4/v6，带点也不能误判成隧道域名）/localhost/空 Host -> WebUI
        assert_eq!(route_fallback("127.0.0.1", false), FallbackRoute::WebUi);
        assert_eq!(route_fallback("::1", false), FallbackRoute::WebUi);
        assert_eq!(route_fallback("10.0.0.5", false), FallbackRoute::WebUi);
        assert_eq!(route_fallback("localhost", false), FallbackRoute::WebUi);
        assert_eq!(route_fallback("", false), FallbackRoute::WebUi);
        // 无点单 label 也落 WebUI（方便局域网 hostname 直访）
        assert_eq!(route_fallback("intranet", false), FallbackRoute::WebUi);
    }

    #[test]
    fn fallback_routes_404_for_unknown_domain() {
        assert_eq!(route_fallback("nope.test", false), FallbackRoute::NotFound);
        assert_eq!(route_fallback("git.nat.kkito.cn", false), FallbackRoute::NotFound);
    }

    #[test]
    fn response_head_parses_status_headers_body() {
        let raw = b"HTTP/1.1 404 Not Found\r\nContent-Length: 3\r\nConnection: close\r\nTransfer-Encoding: chunked\r\n\r\nabc";
        let (status, headers, rest) = parse_response_head(raw);
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(rest, b"abc");
        // hop-by-hop 头被剥掉，业务头保留（小写归一）
        assert!(headers.iter().any(|(k, v)| k == "content-length" && v == "3"));
        assert!(!headers.iter().any(|(k, _)| k == "connection" || k == "transfer-encoding"));
    }

    #[test]
    fn response_head_tolerates_malformed() {
        // 无状态行数字 -> 兜底 200；无 CRLFCRLF -> 整包当头、body 为空
        let (s, _, rest) = parse_response_head(b"garbage");
        assert_eq!(s, StatusCode::OK);
        assert!(rest.is_empty());
        let (s2, _, rest2) = parse_response_head(b"HTTP/1.1 200 OK\r\nX-A: b");
        assert_eq!(s2, StatusCode::OK);
        assert!(rest2.is_empty());
    }

    #[test]
    fn config_push_stops_when_agent_converged() {
        // 复现刷屏死循环：agent 上报的 proxies 已与期望态一致时，
        // server 不应再下发 Config，否则 agent 回 Register -> Config 无限 ping-pong。
        let p = ProxyConfig {
            name: "web".into(),
            ptype: "http".into(),
            local_ip: "127.0.0.1".into(),
            local_port: 80,
            domains: vec!["a.test".into()],
            remote_port: 0,
            set_x_forwarded_proto: None,
            basic_auth: None,
            enabled: true,
        };
        // 已收敛：不再 push
        assert!(!needs_config_push(&[p.clone()], &[p.clone()]));
        // 未收敛：需要 push（server 期望态覆盖 agent 上报）
        let mut q = p.clone();
        q.local_port = 8080;
        assert!(needs_config_push(&[q], &[p]));
        // agent 空上报但期望态有隧道：需要 push
        assert!(!needs_config_push(&[], &[]));
    }

    #[test]
    fn server_webui_clarifies_agent_view_ip() {
        // server WebUI 填的是 agent 视角的目标地址，页面必须说清楚，
        // 否则用户会误填 server 本机的 127.0.0.1。
        let html = include_str!("../web/index.html");
        assert!(html.contains("agent"), "missing agent-perspective hint");
        assert!(html.contains("127.0.0.1 = agent"), "missing loopback hint");
    }

    #[test]
    fn server_webui_checkbox_not_full_width() {
        // .modal input{width:100%} 会把 checkbox 也撑满一行，
        // 必须有 checkbox 例外规则保证对齐。
        let html = include_str!("../web/index.html");
        assert!(html.contains("type=checkbox") || html.contains("type=\"checkbox\""));
        assert!(html.contains("input[type=checkbox]") || html.contains("input[type=\"checkbox\"]"));
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
}
