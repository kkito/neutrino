//! Server side: /ws (agent multiplex) + http/tcp/udp ingress + WebUI + state.
use crate::proto::*;
use axum::{
    extract::{ws::Message as WsMsg, ws::WebSocket, Path, State, WebSocketUpgrade},
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

fn trim_crlf(mut b: &[u8]) -> &[u8] {
    while let Some((&c, rest)) = b.split_first() {
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

fn mint_jwt(secret: &str) -> String {
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

fn verify_jwt(secret: &str, token: &str) -> bool {
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
pub async fn run(listen: &str, http_in: &str, data: &str, token: &str, desired: &str) -> anyhow::Result<()> {
    let _ = tokio::fs::create_dir_all(data).await;
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
    let token = Arc::new(token.to_string());
    {
        let s = shared.clone();
        let http_in = http_in.to_string();
        tokio::spawn(async move {
            if let Err(e) = http_ingress(&http_in, s).await {
                tracing::error!("http ingress died: {e:#}");
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
                save_state(&s).await;
            }
        });
    }
    let app = Router::new()
        .route("/ws", get(ws_handler))
        .route("/", get(index_page))
        .route("/api/login", post(api_login))
        .route("/api/overview", get(api_overview))
        .route("/api/tunnels", get(api_tunnels))
        .route("/api/logs", get(api_logs))
        .route("/api/config", post(api_config))
        .route("/api/tunnels/:agent/:name/enabled", post(api_toggle))
        .route("/api/desired/:hostname", get(api_desired_get).post(api_desired_set))
        .with_state((shared, token));
    let lis = TcpListener::bind(listen).await?;
    tracing::info!("server listening ws+webui on {listen}");
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

async fn on_register(s: &S, agent_id: &str, hostname: &str, reported: Vec<ProxyConfig>) {
    let want = s.desired.read().await.get(hostname).cloned();
    let proxies = resolve_proxies(want.clone(), reported);
    if want.is_some() {
        log_ev(s, format!("agent '{hostname}' desired overlay applied ({} proxies)", proxies.len()));
    }
    apply_proxies_for_agent(s, agent_id, &proxies).await;
    log_ev(
        s,
        format!("agent '{hostname}' registered {} proxies", proxies.len()),
    );
}

// route pickers (LB)
async fn pick_http(s: &S, host: &str) -> Option<(String, Option<String>)> {
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
    // find xfp for this agent+host
    let ag = s.agents.read().await;
    let xfp = ag.get(&aid).and_then(|h| {
        h.info
            .proxies
            .iter()
            .find(|p| {
                p.enabled && p.domains.iter().any(|d| d.eq_ignore_ascii_case(host))
            })
            .and_then(|p| p.set_x_forwarded_proto.clone())
    });
    // only return live agents
    if ag.contains_key(&aid) {
        Some((aid, xfp))
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
            let Some((aid, xfp)) = pick_http(&s, &host).await else {
                let r = "HTTP/1.1 404 Not Found\r\ncontent-length: 15\r\nconnection: close\r\n\r\nno such tunnel\n";
                let _ = inbound.write_all(r.as_bytes()).await;
                return;
            };
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
        r.user == "admin" && r.pass == "welcome2ll"
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
    fn desired_validation() {
        let ok_http = ProxyConfig {
            name: "w".into(),
            ptype: "http".into(),
            local_ip: "127.0.0.1".into(),
            local_port: 80,
            domains: vec!["a.test".into()],
            remote_port: 0,
            set_x_forwarded_proto: None,
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
