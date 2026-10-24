//! server 入站：fallback Host 分流 + TCP/UDP 监听 + 透传泵。
use crate::common::proto::*;
use super::http_util::{extract_host, inject_xfp};
use super::state::{log_ev, S};
use axum::{body::Body, extract::{Request, State}, http::{header, StatusCode}, response::IntoResponse};
use std::{collections::HashMap, sync::{atomic::{AtomicUsize, Ordering}, Arc}, time::{Duration, Instant}};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::{TcpListener, UdpSocket}, sync::mpsc};

/// http 入口路由：返回 (agent_id, 隧道配置快照)。快照里带 basic_auth，
/// 调用方在透传前用 check_basic_auth 校验，不通过直接 401。
async fn pick_http(s: &S, host: &str) -> Option<(String, crate::common::proto::ProxyConfig)> {
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
                        || (kind == "https" && p.ptype == "tcp")
                        || (kind == "tcp" && p.ptype == "http"))
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

/// UDP session 建时目标解析（纯函数，无锁、无 await）。
/// 根因→修法：旧代码收包循环每包 agents.read() 全表扫描找 proxy + limiter_for 写锁，
/// BT flood 高 pps 下锁排队，/api/tunnels+overview 的 agents.read() 饿死 6s+ pending。
/// 新路径：session 建立时调一次（快照来自单次 agents.read），包循环只用缓存零锁。
/// 返回 (hostname, traffic_key, proxy名, rate_bps)。
pub(crate) fn resolve_udp_session(
    snapshot: &[(&str, Vec<ProxyConfig>)],
    port: u16,
) -> Option<(String, String, String, Option<u64>)> {
    snapshot
        .iter()
        .find_map(|(host, proxies)| {
            proxies
                .iter()
                .find(|p| p.enabled && p.remote_port == port && p.ptype == "udp")
                .map(|p| {
                    (
                        host.to_string(),
                        crate::server::state::traffic_key(host, &p.name),
                        p.name.clone(),
                        crate::server::ratelimit::limit_of(p.rate_limit.as_deref()),
                    )
                })
        })
}

fn next_sid() -> u32 {
    // even ids from server; wrap-safe
    ((STREAM_CTR.fetch_add(1, Ordering::Relaxed) as u32).wrapping_mul(2)).wrapping_add(2)
}

/// link 中转复用 server 偶数 sid（tunnel.rs 用）。与 next_sid 同源。
pub(crate) fn next_sid_pub() -> u32 {
    next_sid()
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

/// HTTP 连接守卫：handler future 被取消（首包等待期下游断开）或响应 Body 被
/// drop（流式回写中途断开）时，unfold 状态/局部变量随之 drop，此处用 try_write
/// 同步清理 conns 行 + incoming 注册并补发 Close。根因→修法：旧代码 remove 只写
/// 在流尾回调/超时两处，Body 中途被丢弃则清理永不执行，conns 越积越多
///（natproxy 现场 56 行僵尸）。正常走完也经此路径，幂等重复清理无害。
struct HttpConnGuard {
    s: S,
    aid: String,
    sid: u32,
    ctl: mpsc::UnboundedSender<ServerMsg>,
}
impl Drop for HttpConnGuard {
    fn drop(&mut self) {
        let (s, aid, sid, ctl) = (self.s.clone(), self.aid.clone(), self.sid, self.ctl.clone());
        // 同步路径拿不到锁时起后台任务补删，不阻塞 drop。
        // 借用隔离：try 守卫只活在块内，先算 bool 再 spawn，避免借用跨 move。
        let bg_conns = {
            match s.conns.try_write() {
                Ok(mut m) => {
                    m.remove(&(sid as u64));
                    false
                }
                Err(_) => true,
            }
        };
        if bg_conns {
            let s2 = s.clone();
            tokio::spawn(async move {
                s2.conns.write().await.remove(&(sid as u64));
            });
        }
        let inc = {
            match s.agents.try_read() {
                Ok(ag) => ag.get(&aid).map(|h| h.incoming.clone()),
                Err(_) => None,
            }
        };
        match inc {
            Some(inc) => {
                let bg = {
                    match inc.try_write() {
                        Ok(mut m) => {
                            m.remove(&sid);
                            false
                        }
                        Err(_) => true,
                    }
                };
                if bg {
                    tokio::spawn(async move {
                        inc.write().await.remove(&sid);
                    });
                }
            }
            None => {
                // agents 锁忙：后台补删
                let s2 = s.clone();
                tokio::spawn(async move {
                    if let Some(h) = s2.agents.read().await.get(&aid) {
                        h.incoming.write().await.remove(&sid);
                    }
                });
            }
        }
        let _ = ctl.send(ServerMsg::Close { stream: sid, reason: "eof".into() });
    }
}

/// axum fallback：已注册的 `/ws`、`/api/*` 优先匹配；
/// 其余路径按 Host 路由到隧道 agent。整包转发给 agent，响应流式回写；
/// 未知域名 404（`no such tunnel`），裸 IP/localhost 访问落到 WebUI。
/// 真实外部 IP：nginx 在前时 ConnectInfo 恒为 127.0.0.1，优先读代理头。
/// 顺序：X-Real-IP（单 IP，nginx 配的）> X-Forwarded-For 首个 > 直连对端。
/// 伪造风险：公网直连 7440 时客户端可自带 X-Real-IP 冒充，仅展示用、不做鉴权依据。
fn real_peer(headers: &::axum::http::HeaderMap, peer: &std::net::SocketAddr) -> String {
    let hdr = |k: &str| {
        headers
            .get(k)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    };
    if let Some(ip) = hdr("x-real-ip") {
        return if ip.contains(':') { ip } else { format!("{ip}:{}", peer.port()) };
    }
    if let Some(xff) = hdr("x-forwarded-for") {
        if let Some(first) = xff.split(',').next().map(|s| s.trim()).filter(|s| !s.is_empty()) {
            return if first.contains(':') {
                first.to_string()
            } else {
                format!("{}:{}", first, peer.port())
            };
        }
    }
    peer.to_string()
}

pub(crate) async fn fallback_http_ingress(
    State((s, _)): State<(S, Arc<String>)>,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<std::net::SocketAddr>,
    req: Request,
) -> impl IntoResponse {
    use axum::body::to_bytes;
    let (parts, body) = req.into_parts();
    let peer_s = real_peer(&parts.headers, &peer);
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
        FallbackRoute::WebUi => return super::api::index_page().await.into_response(),
        FallbackRoute::NotFound => {
            return (StatusCode::NOT_FOUND, "no such tunnel\n").into_response()
        }
    };
    let xfp = proxy.set_x_forwarded_proto.clone();
    // http 隧道入口 basic auth：配了 basic_auth 才校验，无 Authorization/错口令直接 401。
    // 浏览器收到 WWW-Authenticate 会弹登录框；校验在 server 侧做，agent/内网服务无感知。
    if !crate::common::proto::check_basic_auth(&parts.headers, proxy.basic_auth.as_deref()) {
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
    // 连接快照行（/api/conns 用；流结束/超时处 remove）
    {
        let mut m = s.conns.write().await;
        let hostname = s.agents.read().await.get(&aid).map(|h| h.info.hostname.clone()).unwrap_or_default();
        super::state::insert_conn(
            &mut m,
            super::state::ConnInfo {
                id: sid as u64,
                proto: "http".into(),
                peer: peer_s,
                public_port: s.public_port,
                agent: hostname,
                tunnel: proxy.name.clone(),
                remote_port: 0,
                target: format!("{}:{}", proxy.local_ip, proxy.local_port),
                since: chrono::Local::now().timestamp(),
                rx: 0,
                tx: 0,
            },
        );
    }
    // 守卫活过两个阶段：①首包等待期 handler future 被取消→drop 清理；
    // ②响应建成后 move 进 Body 流，中途断开流被 drop→清理。正常走完也经此路径。
    let guard = std::sync::Arc::new(HttpConnGuard { s: s.clone(), aid: aid.clone(), sid, ctl: ctl.clone() });
    let _ = ctl.send(ServerMsg::Open {
        stream: sid,
        kind: "http".into(),
        host,
        port: 0,
    });
    if out.send((sid, head)).is_err() {
        drop(guard);
        return (StatusCode::BAD_GATEWAY, "agent gone\n").into_response();
    }
    // 等 agent 回包（首个响应头），超时 30s
    let first = tokio::time::timeout(Duration::from_secs(30), drx.recv()).await;
    let first = match first {
        Ok(Some(b)) => b,
        _ => {
            drop(guard);
            return (StatusCode::BAD_GATEWAY, "upstream timeout\n").into_response();
        }
    };
    // 简单解析状态行 + 头，body 用流式 Body 拼后续帧
    let (status, resp_headers, prefix) = parse_response_head(&first);
    let s2 = s.clone();
    let stream = async_stream_lite(s2, aid, sid, ctl, drx, prefix, guard);
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

/// 后续响应帧 -> axum Body 流；_guard 随 Body 活、断开被 drop 即清理（正常走完经 guard 的多次幂等清理）。
fn async_stream_lite(
    s: S,
    aid: String,
    sid: u32,
    ctl: mpsc::UnboundedSender<ServerMsg>,
    drx: mpsc::UnboundedReceiver<Vec<u8>>, // async_stream_lite 内消费
    prefix: Vec<u8>,
    _guard: std::sync::Arc<HttpConnGuard>,
) -> impl futures_util::Stream<Item = Result<axum::body::Bytes, std::io::Error>> {
    use futures_util::stream::{once, unfold};
    use futures_util::StreamExt;
    let pre = if prefix.is_empty() {
        futures_util::stream::empty().boxed()
    } else {
        once(async { Ok(axum::body::Bytes::from(prefix)) }).boxed()
    };
    let rest = unfold(Some((s, aid, sid, ctl, drx, _guard)), |st| async {
        let (s, aid, sid, ctl, mut drx, _guard) = st?;
        match drx.recv().await {
            Some(chunk) => {
                // 连接行 tx 累计（agent->公网字节）
                if let Some(c) = s.conns.write().await.get_mut(&(sid as u64)) {
                    c.tx += chunk.len() as u64;
                }
                Some((Ok(axum::body::Bytes::from(chunk)), Some((s, aid, sid, ctl, drx, _guard))))
            }
            None => None, // 清理由 HttpConnGuard::drop 统一做（正常走完也经此路径）
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
pub(crate) async fn ensure_tcp_listener(s: &S, port: u16) {
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
                    let Ok((inbound, peer)) = lis.accept().await else {
                        continue;
                    };
                    // TCP 收窗口钳制：限速映射的连接收缓冲 64KB（默认 ~6MB/连接）。
                    // 根因→修法：sleep 截流只压转发节奏，突发全进内核缓冲、网卡照涨；
                    // 收缓冲小 = 通告窗口小 = 对端单 RTT 在途量小 = 网卡毛刺低。
                    // 无限速映射跳过（零开销）；setsockopt 失败只 warn 不炸连接。
                    {
                        use std::os::fd::AsRawFd;
                        let need_clamp = {
                            let ag = s2.agents.read().await;
                            ag.values().any(|h| {
                                h.info.proxies.iter().any(|p| {
                                    p.enabled && p.remote_port == port && p.ptype != "udp" && p.rate_limit.as_deref().map(|r| !r.trim().is_empty()).unwrap_or(false)
                                })
                            })
                        };
                        if need_clamp {
                            let fd = inbound.as_raw_fd();
                            let small: libc::c_int = 64 * 1024;
                            let r = unsafe {
                                libc::setsockopt(
                                    fd,
                                    libc::SOL_SOCKET,
                                    libc::SO_RCVBUF,
                                    &small as *const _ as *const libc::c_void,
                                    std::mem::size_of_val(&small) as libc::socklen_t,
                                )
                            };
                            if r != 0 {
                                tracing::warn!("tcp :{port} SO_RCVBUF clamp failed for {peer}");
                            }
                        }
                    }
                    let s3 = s2.clone();
                    tokio::spawn(async move {
                        let Some(aid) =
                            pick_port(&s3, port, "tcp").await
                        else {
                            return;
                        };
                        // 连接行目标信息（proxy 名 + 内网目标）+ 限速快照（总量下行，公网->agent 方向）。
                        // 根因→修法：限速以 desired 入内存路由表为准，连接建立时快照一次；
                        // 热更新后新连接用新值，老连接沿用旧 limiter（limiter_for 同 key 更新 limit，老连接自动跟随）。
                        let (pname, target, rate_key, rate_bps) = {
                            let ag = s3.agents.read().await;
                            let h = ag.get(&aid);
                            let p = h.and_then(|h| {
                                h.info.proxies.iter().find(|p| {
                                    p.enabled && p.remote_port == port && p.ptype != "udp"
                                })
                            });
                            match (h, p) {
                                (Some(h), Some(p)) => (
                                    p.name.clone(),
                                    format!("{}:{}", p.local_ip, p.local_port),
                                    crate::server::state::traffic_key(&h.info.hostname, &p.name),
                                    crate::server::ratelimit::limit_of(p.rate_limit.as_deref()),
                                ),
                                _ => (String::new(), String::new(), String::new(), None),
                            }
                        };
                        let hostname = s3.agents.read().await.get(&aid).map(|h| h.info.hostname.clone()).unwrap_or_default();
                        let sid = next_sid();
                        // 建连日志：降 DEBUG（spec §15.4）。2026-10-23 BT flood 时
                        // 这里 800 条/分把 INFO 层刷屏，事故信号全被淹没；
                        // INFO 层改由 per-tunnel 每分钟汇总承担（Task 0b-4），
                        // 需要逐连接明细时 `RUST_LOG=debug` 按需打开。
                        tracing::debug!("tcp accept :{port} peer={peer} -> sid={sid} tunnel={pname} target={target} limit={}", rate_bps.map(|b| b.to_string()).unwrap_or_else(|| "none".into()));
                        // 连接快照行（双泵结束处 remove）
                        {
                            let mut m = s3.conns.write().await;
                            super::state::insert_conn(
                                &mut m,
                                super::state::ConnInfo {
                                    id: sid as u64,
                                    proto: "tcp".into(),
                                    peer: peer.to_string(),
                                    public_port: port,
                                    agent: hostname,
                                    tunnel: pname,
                                    remote_port: port,
                                    target,
                                    since: chrono::Local::now().timestamp(),
                                    rx: 0,
                                    tx: 0,
                                },
                            );
                        }
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
                        // tcp 入口必须 kind="tcp"（agent 按 remote_port 查表；kind="http"
                        // 走域名查表、空 host 直接 no route 关流——已现网踩坑）。
                        let _ = ctl.send(ServerMsg::Open {
                            stream: sid,
                            kind: "tcp".into(),
                            host: String::new(),
                            port,
                        });
                        let (mut ri, mut wi) = inbound.into_split();
                        let out2 = out.clone();
                        let s_rx = s3.clone();
                        // 双向总量：上下行共用同一 limiter（同映射所有连接+双向累加）。
                        let limiter = match rate_bps {
                            Some(bps) => Some(crate::server::ratelimit::limiter_for(&s3, &rate_key, bps).await),
                            None => None,
                        };
                        let limiter_up = limiter.clone();
                        let to_agent = tokio::spawn(async move {
                            let mut b = vec![0u8; 32 * 1024];
                            loop {
                                let n = ri.read(&mut b).await?;
                                if n == 0 {
                                    break;
                                }
                                // 限速：总量窗口共享，同映射所有连接超了大家一起等；上行泵不压。
                                // 零限速时 limiter 为 None，此分支跳过零开销。
                                // 窗口口径已含时间抵扣（单块口径见 throttle_sleep 单测），此处直接 sleep。
                                if let Some(l) = &limiter {
                                    let d = l.take(n).await;
                                    if !d.is_zero() {
                                        tokio::time::sleep(d).await;
                                    }
                                }
                                // 连接行 rx 累计（公网->agent 字节；tick/live 只读 conns。
                                // 根因→修法：旧代码另有 agents.write() 做 agent 级 rx 记账，
                                // 高 pps 下写锁饿死 /api/tunnels+overview 的读；agent 级总量
                                // 由 30s persist 循环批量刷（见 mod.rs），包循环零 agents 锁。）
                                if let Some(c) = s_rx.conns.write().await.get_mut(&(sid as u64)) {
                                    c.rx += n as u64;
                                }
                                out2
                                    .send((sid, b[..n].to_vec()))
                                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                            }
                            anyhow::Ok(())
                        });
                        let s_tx = s3.clone();
                        let from_agent = async {
                            // 首包门：第一个 chunk 必须 5s 内到，否则关连接（防 agent 侧重排
                            // 洞卡住时 visitor 空等 30s——微信图 tun1 30s 才回 360146 即此）。
                            let mut pending_first: Option<Vec<u8>> =
                                match tokio::time::timeout(
                                    std::time::Duration::from_secs(5),
                                    drx.recv(),
                                )
                                .await
                                {
                                    Ok(Some(c)) => Some(c),
                                    _ => {
                                        tracing::warn!("tcp :{port} sid={sid} first-chunk timeout (reorder hole?), close early");
                                        None
                                    }
                                };
                            // 首包已到则先写，后续走正常 recv；首包超时直接进 select 收尾。
                            if let Some(chunk) = pending_first.take() {
                                if let Some(l) = &limiter_up {
                                    let d = l.take(chunk.len()).await;
                                    if !d.is_zero() {
                                        tokio::time::sleep(d).await;
                                    }
                                }
                                if let Some(c) = s_tx.conns.write().await.get_mut(&(sid as u64)) {
                                    c.tx += chunk.len() as u64;
                                }
                                wi.write_all(&chunk).await?;
                            } else {
                                anyhow::bail!("first chunk timeout");
                            }
                            while let Some(chunk) = drx.recv().await {
                                if let Some(l) = &limiter_up {
                                    let d = l.take(chunk.len()).await;
                                    if !d.is_zero() {
                                        tokio::time::sleep(d).await;
                                    }
                                }
                                if let Some(c) = s_tx.conns.write().await.get_mut(&(sid as u64)) {
                                    c.tx += chunk.len() as u64;
                                }
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
                        // 断开日志：降 DEBUG（spec §15.4），汇总由 per-tunnel tick 承担。
                        if let Some(c) = s3.conns.write().await.remove(&(sid as u64)) {
                            tracing::debug!("tcp close :{port} peer={peer} sid={sid} rx={} tx={}", c.rx, c.tx);
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

/// 过期 session 的 sid 列表（纯函数，无 IO）。
///
/// 根因→修法：旧 `sessions.retain(...)` 只删 server 本地表项，从不告诉 agent。
/// agent 那条 udp 流的 socket 因此只能等它自己的 idle 超时才回收，而两边的超时
/// 时长不一致（server TTL 5s vs agent 30s/120s），中间整段时间 server 已经把 sid
/// 忘了、agent 还挂着 fd —— DHT 扫描器不停造新 session，fd 只增不减。
/// 现在把「哪些 sid 因静默过期」算出来，由调用方逐个发 Close 让 agent 立刻关 socket。
pub(crate) fn expired_sids(
    sessions: &[(std::net::SocketAddr, u32, Instant)],
    now: Instant,
    ttl: Duration,
) -> Vec<u32> {
    sessions
        .iter()
        .filter(|(_, _, t)| now.saturating_duration_since(*t) >= ttl)
        .map(|(_, sid, _)| *sid)
        .collect()
}

pub(crate) async fn ensure_udp_listener(s: &S, port: u16) {
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
        // UDP 丢包限速：socket 收缓冲钳到 64KB（默认 ~6MB）。
        // 根因→修法：UDP 无窗口无背压，sleep 只能拖转发节奏，对端照发、网卡照涨；
        // 唯一用户态能干的是让内核缓冲变小——超了内核直接丢包，对端 uTP 感知丢包
        // 后降速（类拥塞语义）。buffer 小 = 丢得早 = 对端发得少 = 网卡数字下来。
        // 失败只记 warn 不炸（钳不住就退化成旧行为）。
        {
            use std::os::fd::AsRawFd;
            let fd = sock.as_raw_fd();
            let small: libc::c_int = 64 * 1024;
            let r = unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_RCVBUF,
                    &small as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&small) as libc::socklen_t,
                )
            };
            if r != 0 {
                tracing::warn!("udp :{port} SO_RCVBUF clamp failed, unlimited buffer");
            }
        }
        tracing::info!("udp ingress on 0.0.0.0:{port}");
        log_ev(&s2, format!("udp listening :{port}"));
        // peer -> (stream_id, last_seen, 下行 sender 缓存, 下行 limiter 缓存)。
        // 根因→修法：包循环零 agents 锁 + 零 rate_limiters 锁——sender 与 limiter
        // 都在建 session 时缓存（单次 agents.read 快照 + limiter_for 一次），
        // 每包只 take（Mutex 临界区极短）+ 发包，不再全表扫描/拿写锁。
        // 注意：sender 按传输选——kudus agent 走 udp_outbox（整包分片语义，
        // 包边界不变），WSS/QUIC 沿用 outbox（整帧直达）。判定一次缓存在 session 里，
        // 包循环零分支：UDP 整包直达 outbox 会被 kudus 写泵按 TCP 切片拆碎。
        use crate::server::ratelimit::RateLimiter;
        let mut sessions: HashMap<std::net::SocketAddr, (u32, Instant, mpsc::UnboundedSender<(u32, Vec<u8>)>, Option<std::sync::Arc<RateLimiter>>, mpsc::UnboundedSender<ServerMsg>)> = HashMap::new();
        let mut buf = vec![0u8; 65535];
        // TTL 语义：该 peer 静默多久就回收。每收一包都刷新 t（见下方 get_mut 分支），
        // 所以活跃 uTP 长连接永不过期，DHT 一问一答 / 扫描器发一次就走 → 秒级清掉。
        let ttl = Duration::from_secs(s2.udp_session_ttl_secs.max(1));
        loop {
            // expire old sessions（conns 表 UDP 行同步删）
            // 根因→修法：旧代码只 `retain` 删本地表就不管了，agent 侧那条 udp 流的
            // socket 只能等它自己的 idle 超时（30s/120s）回收，而 server TTL 只有 5s——
            // 中间整段时间 server 已忘掉 sid、agent 还挂着 fd。DHT 扫描器不停造新
            // session 时 fd 只增不减（HK 2026-10-23：5min 158 个 session，snail socket
            // 一路涨到 100+）。现在过期即发 Close，agent 立刻关 socket 还槽位。
            let now = Instant::now();
            let snapshot: Vec<(std::net::SocketAddr, u32, Instant)> =
                sessions.iter().map(|(p, (id, t, _, _, _))| (*p, *id, *t)).collect();
            let dead = expired_sids(&snapshot, now, ttl);
            let n_exp = dead.len();
            if n_exp > 0 {
                // Close 让 agent 删 streams 表项 + abort 双向泵 + drop socket。
                // send 失败（agent 已断）忽略：表项照样删。
                let dead_set: std::collections::HashSet<u32> = dead.into_iter().collect();
                for (id, _, _, _, ctl) in sessions.values() {
                    if dead_set.contains(id) {
                        let _ = ctl.send(ServerMsg::Close { stream: *id, reason: "udp idle".into() });
                    }
                }
            }
            sessions.retain(|_, (_, t, _, _, _)| t.elapsed() < ttl);
            if n_exp > 0 {
                tracing::debug!("udp :{port} expired {n_exp} sessions ({} alive)", sessions.len());
            }
            {
                let live: std::collections::HashSet<u32> = sessions.values().map(|(id, _, _, _, _)| *id).collect();
                s2.conns.write().await.retain(|_, c| c.proto != "udp" || live.contains(&(c.id as u32)));
            }
            // recv_from 必须带超时：过期检查在循环顶部，旧代码不带超时就会一直
            // 阻塞在这里——只要对端不发新包，过期检查永远轮不到执行，TTL 形同虚设
            // （HK 现场：5s TTL 下 session 数依旧涨，因为回收只在“来下一个包”时发生）。
            // 超时取 min(ttl, 1s)：保证至少每秒扫一次过期表。
            let (n, peer) = match tokio::time::timeout(ttl.min(Duration::from_secs(1)), sock.recv_from(&mut buf)).await {
                Ok(Ok(x)) => x,
                Ok(Err(_)) => continue,
                // 超时 = 刚好回到循环顶部做一次过期回收，然后继续等包
                Err(_) => continue,
            };
            let sid = match sessions.get_mut(&peer) {
                Some((id, t, _, _, _)) => {
                    *t = Instant::now();
                    *id
                }
                None => {
                    let Some(aid) = pick_port(&s2, port, "udp").await else {
                        continue;
                    };
                    let id = next_sid();
                    let (dtx, mut drx) = mpsc::unbounded_channel::<Vec<u8>>();
                    // kudus agent 的 UDP 下行走独立 udp_outbox（整包分片+重组，
                    // 包边界不变）；WSS/QUIC agent 无 udp_outbox 行，沿用 outbox。
                    // 根因→修法：旧代码一律走 outbox，kudus 写泵按 TCP 字节流
                    // 切片逐片 deliver，1500B 包变 2 个残包（无声 corrupt）。
                    let (ctl, out) = {
                        let ag = s2.agents.read().await;
                        let ob = s2.outbox.read().await;
                        let uob = s2.udp_outbox.read().await;
                        match (ag.get(&aid), uob.get(&aid), ob.get(&aid)) {
                            (Some(h), Some(u), _) => (h.ctl.clone(), u.clone()),
                            (Some(h), None, Some(o)) => (h.ctl.clone(), o.clone()),
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
                    // agent->internet pump for this peer（回包方向同压：与收包共用映射级 limiter，双向总量）。
                    // 快照一次：单次 agents.read 拿全表 proxies 快照，纯函数解析出目标，
                    // 建 limiter + 缓存 outbox，后续每包零锁。
                    let sock2 = sock.clone();
                    let s3 = s2.clone();
                    let (_sess_host, sess_key, _sess_pname, sess_bps) = {
                        let ag = s2.agents.read().await;
                        let snap: Vec<(&str, Vec<ProxyConfig>)> = ag.values().map(|h| (h.info.hostname.as_str(), h.info.proxies.clone())).collect();
                        match resolve_udp_session(&snap, port) {
                            Some(v) => v,
                            None => continue,
                        }
                    };
                    let out_cached = out.clone();
                    let sess_limiter = match sess_bps {
                        Some(b) => Some(crate::server::ratelimit::limiter_for(&s2, &sess_key, b).await),
                        None => None,
                    };
                    let up_limiter = sess_limiter.clone();
                    tokio::spawn(async move {
                        while let Some(chunk) = drx.recv().await {
                            if let Some(l) = &up_limiter {
                                let d = l.take(chunk.len()).await;
                                if !d.is_zero() {
                                    tokio::time::sleep(d).await;
                                }
                            }
                            // UDP 连接行 tx 累计（peer 行线性查找；连接数小可接受）
                            let peer_s = peer.to_string();
                            {
                                let mut m = s3.conns.write().await;
                                if let Some(c) = m.values_mut().find(|c| c.proto == "udp" && c.peer == peer_s) {
                                    c.tx += chunk.len() as u64;
                                }
                            }
                            let _ = sock2.send_to(&chunk, peer).await;
                            // agent 级 tx 不在此记（包循环零 agents 锁；conns 行 tx 已记，
                            // 总量由 persist 循环批量刷）。
                        }
                    });
                    // session 级日志（建时一次，包循环不打）：UDP flood 排查看 session 数，
                    // 每包日志会把盘打爆。
                    tracing::info!("udp session {peer} -> sid={id} tunnel={_sess_pname} host={_sess_host}");
                    sessions.insert(peer, (id, Instant::now(), out_cached, sess_limiter, ctl.clone()));
                    // UDP 连接行（peer 一行；since 每次收包刷新见下）
                    {
                        let ag = s2.agents.read().await;
                        let hostname = ag.get(&aid).map(|h| h.info.hostname.clone()).unwrap_or_default();
                        let (pname, target) = ag
                            .get(&aid)
                            .and_then(|h| h.info.proxies.iter().find(|p| p.enabled && p.remote_port == port && p.ptype == "udp"))
                            .map(|p| (p.name.clone(), format!("{}:{}", p.local_ip, p.local_port)))
                            .unwrap_or_default();
                        let mut m = s2.conns.write().await;
                        super::state::insert_conn(
                            &mut m,
                            super::state::ConnInfo {
                                id: id as u64,
                                proto: "udp".into(),
                                peer: peer.to_string(),
                                public_port: port,
                                agent: hostname,
                                tunnel: pname,
                                remote_port: port,
                                target,
                                since: chrono::Local::now().timestamp(),
                                rx: 0,
                                tx: 0,
                            },
                        );
                    }
                    id
                }
            };
            // internet -> agent (each datagram = one data frame)
            let payload = buf[..n].to_vec();
            // udp 下行限速（收包方向）：session 缓存的 limiter 直接 take，整包为一块。
            // 根因→修法：旧代码每包 agents.read 全表扫描 + limiter_for 写锁，
            // BT flood 下锁排队饿死 /api/tunnels+overview。新路径 session 建时缓存，
            // 每包只 take（Mutex 临界区极短，零 agents/rate_limiters 锁）。
            // 窗口按映射共享（sess 建时同 key 同 limiter，见 limiter_for 同 key 复用）。
            {
                let lim = sessions.get(&peer).and_then(|(_, _, _, l, _)| l.clone());
                if let Some(l) = lim {
                    let d = l.take(payload.len()).await;
                    if !d.is_zero() {
                        tokio::time::sleep(d).await;
                    }
                }
            }
            // UDP 连接行 rx 累计 + since 刷新（peer 行线性查找）
            {
                let peer_s = peer.to_string();
                let mut m = s2.conns.write().await;
                if let Some(c) = m.values_mut().find(|c| c.proto == "udp" && c.peer == peer_s) {
                    c.rx += payload.len() as u64;
                    c.since = chrono::Local::now().timestamp();
                }
            }
            // 发给 session 建时缓存的 outbox sender（零 agents 锁）。
            // 根因→修法：旧代码每包全表扫描 agents 找 owner + agents.write() 记 rx，
            // BT flood 高 pps 下锁排队，/api/tunnels+overview 的 agents.read() 饿死 6s+。
            // sessions 表建时已缓存 (sid -> outbox sender)，包循环只碰 sessions+conns。
            // agent 级 rx 由 persist 循环批量刷（conns 行 rx 为准）。
            let owner: Option<mpsc::UnboundedSender<(u32, Vec<u8>)>> = {
                sessions.get(&peer).and_then(|(id, _, o, _, _)| {
                    if *id == sid {
                        Some(o.clone())
                    } else {
                        None
                    }
                })
            };
            if let Some(o) = owner {
                let _ = o.send((sid, payload));
            }
        }
    });
}

// ================= WebUI =================

#[cfg(test)]
mod tests {
    use super::*;
    /// UDP session TTL 默认 5s 且可配。根因→修法：旧值写死 120s（照抄 conntrack
    /// stream 超时），DHT 扫描器每个新源端口建一条 session，120s 内同 IP 堆几十条
    /// → snail 侧 256 槽位瞬间打满（too many udp streams）。
    /// 语义是「上次收包后静默多久回收」，每包刷 t，故活跃 uTP 不受影响。
    #[test]
    fn udp_session_ttl_defaults_to_5s() {
        assert_eq!(crate::server::state::UDP_SESSION_TTL_SECS_DEFAULT, 5);
        // 字段类型为 u64，可经 --udp-session-ttl 覆盖；0 在 run() 里回退默认值。
        let s = crate::server::state::Shared::default();
        assert_eq!(s.udp_session_ttl_secs, 0, "derive(Default) 给 0，必须在 run() 显式赋值");
    }

    /// RED：session 过期时必须产出「要通知 agent 关掉」的 sid 列表。
    /// 根因→修法：旧代码 `sessions.retain(...)` 只删本地表项，从不发 Close，
    /// 于是 agent 侧那条 udp 流的 socket 只能靠自己的 idle 超时回收——
    /// server 5s 就忘了这个 sid，agent 却还挂着 fd（HK 2026-10-23 现场：
    /// 5min 建 158 个 session，snail 侧 socket 只增不减）。
    /// 修法：过期回收时把 sid 收集出来，逐个 ctl.send(Close)，让 agent 立刻关 socket。
    /// 纯函数：只吃 (now, ttl, 表) 吐 sid 列表，无 IO 可单测。
    #[test]
    fn expired_sessions_yield_close_list() {
        use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
        use std::time::{Duration, Instant};
        let now = Instant::now();
        let mk = |p: u16| SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, p));
        // (peer, sid, 上次收包时刻)：20000 刚活跃；20001/20002 已静默超 5s。
        let sessions = vec![
            (mk(20000), 7u32, now - Duration::from_millis(100)),
            (mk(20001), 8, now - Duration::from_secs(9)),
            (mk(20002), 9, now - Duration::from_secs(6)),
        ];
        let mut got = super::expired_sids(&sessions, now, Duration::from_secs(5));
        got.sort_unstable();
        assert_eq!(got, vec![8, 9], "静默超 ttl 的都该被回收");
        // 活跃的（刚收过包）绝不能回收：否则 uTP 长连接每包重建 socket。
        assert!(!got.contains(&7));
        // 全活跃 -> 空列表（不产生任何 Close）
        let live = vec![(mk(20000), 7u32, now)];
        assert!(super::expired_sids(&live, now, Duration::from_secs(5)).is_empty());
    }

    /// RED：UDP session 目标解析必须是纯函数（不碰 agents 锁）。
    /// 根因→修法：旧收包循环每包 agents.read() 全表扫描找 proxy，
    /// BT flood 高 pps 下读锁排队，/api/tunnels+overview 的 agents.read() 饿死
    /// 6s+ pending（live/conns/traffic 不碰 agents 锁所以 1ms 正常）。
    /// 修法：session 建立时缓存 (aid,outbox,proxy名,limiter)，包循环零锁。
    #[test]
    fn red_udp_session_resolve_is_pure() {
        // 期望 API：给定 proxies 快照 + port，返回 (hostname, proxy名, rate bps)，
        // 全程无 .await、无锁。先写断言，函数不存在即红。
        let proxies = vec![crate::common::proto::ProxyConfig {
            name: "u".into(), ptype: "udp".into(), local_ip: "127.0.0.1".into(),
            local_port: 9999, link_agent: "".into(), link_host: "".into(), link_port: 0,
            rate_limit: Some("1m".into()), domains: vec![], remote_port: 51413,
            set_x_forwarded_proto: None, basic_auth: None, enabled: true,
        }];
        let r = super::resolve_udp_session(&[("h", proxies)], 51413);
        assert_eq!(r, Some(("h".to_string(), "h/u".to_string(), "u".to_string(), Some(1048576u64))));
        // 端口无映射 -> None（包直接丢，不建 session）
        assert_eq!(super::resolve_udp_session(&[("h", vec![])], 51413), None);
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
    fn real_peer_prefers_proxy_headers() {
        // 根因→修法：nginx 在前时 ConnectInfo 恒为 127.0.0.1，peer 列全是内网地址。
        // 旧代码直接 peer.to_string()，此单测锁死代理头优先顺序。
        use axum::http::HeaderMap;
        let peer: std::net::SocketAddr = "127.0.0.1:60032".parse().unwrap();
        // X-Real-IP 优先（无端口则补对端端口）
        let mut h = HeaderMap::new();
        h.insert("x-real-ip", "1.2.3.4".parse().unwrap());
        assert_eq!(real_peer(&h, &peer), "1.2.3.4:60032");
        // XFF 取首个，跳过 X-Real-IP 缺席时
        let mut h2 = HeaderMap::new();
        h2.insert("x-forwarded-for", "5.6.7.8, 10.0.0.1".parse().unwrap());
        assert_eq!(real_peer(&h2, &peer), "5.6.7.8:60032");
        // 都没有 → 直连对端
        assert_eq!(real_peer(&HeaderMap::new(), &peer), "127.0.0.1:60032");
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

    /// spec §15.4：accept/close 明细必须降 DEBUG。
    /// 2026-10-23 现场：800 条/分里 99% 是这两行，事故时 INFO 层被刷屏淹没。
    /// 用源码断言而非运行时断言，零成本防回归。
    #[test]
    fn accept_log_level_is_debug() {
        // 注意：include_str! 会把本测试自身的字符串也算进去，
        // 故断言用的 needle 必须拼接构造，不能写字面量（否则自匹配恒真）。
        let dbg = concat!("tracing::deb", "ug!(");
        let inf = concat!("tracing::inf", "o!(");
        let acc = "\"tcp accept";
        let clo = "\"tcp close";
        let src = include_str!("ingress.rs");
        assert!(
            src.contains(&format!("{dbg}{acc}")),
            "tcp accept 必须降级为 debug"
        );
        assert!(
            src.contains(&format!("{dbg}{clo}")),
            "tcp close 必须降级为 debug"
        );
        assert!(
            !src.contains(&format!("{inf}{acc}")),
            "tcp accept 不能是 info（回归）"
        );
        assert!(
            !src.contains(&format!("{inf}{clo}")),
            "tcp close 不能是 info（回归）"
        );
    }
}
