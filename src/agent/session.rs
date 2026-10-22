//! agent 会话：WSS 长连 + Register/Config + Binary 分发 + 建流。
use crate::common::proto::*;
use crate::server::state::IDLE_KICK_SECS;
use super::{AgentFileConfig, Upstream};
use super::stream::{http_response_pump, WsSender};
use futures_util::{SinkExt, StreamExt};
use std::{collections::HashMap, sync::Arc};
use tokio::{io::AsyncWriteExt, net::TcpStream, sync::{mpsc, RwLock}};
use tokio_tungstenite::{connect_async, tungstenite::Message};

pub(crate) struct Ctx {
    pub(crate) proxies: RwLock<Vec<ProxyConfig>>,
    pub(crate) link_tasks: tokio::sync::Mutex<std::collections::HashMap<String, tokio::task::AbortHandle>>,
    pub(crate) streams: RwLock<HashMap<u32, mpsc::UnboundedSender<Vec<u8>>>>,
    /// Binary arrived before Open task inserted the channel (server sends
    /// Open+head back-to-back; spawn ordering isn't guaranteed).
    pub(crate) pending: RwLock<HashMap<u32, Vec<Vec<u8>>>>,
    pub(crate) out: mpsc::UnboundedSender<Message>,
}

pub(crate) async fn session(
    up: Upstream,
    cfg: AgentFileConfig,
    status: Arc<RwLock<super::web::AgentStatus>>,
    egress_out: super::egress::OutHolder,
) -> anyhow::Result<()> {
    tracing::info!("dial {} as '{}'", up.server_url, up.hostname);
    let (ws, _) = connect_async(up.server_url.as_str()).await?;
    tracing::info!("ws connected as '{}'", up.hostname);
    let (mut sink, mut stream) = ws.split();
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Message>();
    // writer
    let writer = tokio::spawn(async move {
        while let Some(m) = out_rx.recv().await {
            if sink.send(m).await.is_err() {
                break;
            }
        }
    });
    *egress_out.write().await = Some(out_tx.clone());
    super::admin::set_sender(Some(super::admin::AdminSender::Ws(out_tx.clone()))).await;
    let ctx = Arc::new(Ctx {
        proxies: RwLock::new(cfg.proxies.clone()),
        link_tasks: tokio::sync::Mutex::new(HashMap::new()),
        streams: RwLock::new(HashMap::new()),
        pending: RwLock::new(HashMap::new()),
        out: out_tx.clone(),
    });
    // link 入口监听与 session 同命：Config 热更新时 sync，session 结束 abort 全部。
    super::link::sync_link_listeners(
        &ctx,
        &cfg.proxies,
        &up.hostname,
        &egress_out,
        &status,
    )
    .await;
    let send = |m: &ClientMsg| {
        out_tx
            .send(Message::Text(serde_json::to_string(m).unwrap().into()))
            .map_err(|e| anyhow::anyhow!("{e}"))
    };
    // hello (hot-updatable hostname/token from WebUI)
    send(&ClientMsg::Hello {
        hostname: up.hostname.clone(),
        version: VERSION.into(),
        token: up.token.clone(),
    })?;
    // welcome (15s)
    let welcome: ServerMsg = match tokio::time::timeout(
        std::time::Duration::from_secs(15),
        stream.next(),
    )
    .await
    {
        Ok(Some(Ok(Message::Text(t)))) => serde_json::from_str(&t)?,
        Ok(Some(Ok(_))) => anyhow::bail!("expect welcome text"),
        Ok(_) => anyhow::bail!("ws closed before welcome"),
        Err(_) => anyhow::bail!("welcome timeout"),
    };
    let interval = match welcome {
        ServerMsg::Welcome { interval, .. } => interval,
        ServerMsg::Error { reason } => anyhow::bail!("server rejected: {reason}"),
        _ => anyhow::bail!("expect welcome"),
    };
    tracing::info!("welcomed, heartbeat {interval}s");
    {
        let mut st = status.write().await;
        st.online = true;
        st.last_error = None;
    }
    send(&ClientMsg::Register {
        proxies: cfg.proxies.clone(),
    })?;
    tracing::info!("registered {} proxies", cfg.proxies.len());

    // ping loop
    {
        let out = out_tx.clone();
        tokio::spawn(async move {
            let mut iv = tokio::time::interval(std::time::Duration::from_secs(
                interval.max(5),
            ));
            loop {
                iv.tick().await;
                let p = ClientMsg::Ping {
                    ts: chrono::Utc::now().timestamp(),
                };
                if out
                    .send(Message::Text(serde_json::to_string(&p).unwrap().into()))
                    .is_err()
                {
                    break;
                }
            }
        });
    }

    // reader loop：带心跳超时——timeout 内无任何 server 帧即判半开
    // （server 重启/nginx 不掐下游时裸 next() 永 pend，外层重拨进不去）。
    // 根因→修法：旧代码只发 Ping 不验 Pong，这次 tm hang 60s+ 無感知就卡死在这里。
    loop {
        let msg = match tokio::time::timeout(
            std::time::Duration::from_secs(IDLE_KICK_SECS as u64),
            stream.next(),
        )
        .await
        {
            Ok(m) => m,
            Err(_) => anyhow::bail!("heartbeat timeout: no server frame for {IDLE_KICK_SECS}s"),
        };
        let Some(msg) = msg else { break };
        let msg = msg?;
        match msg {
            Message::Text(t) => match serde_json::from_str::<ServerMsg>(&t) {
                Ok(ServerMsg::Pong { ts }) => {
                    // server echoes our Ping ts (unix secs); coarse RTT is fine
                    let now = chrono::Utc::now().timestamp();
                    let ms = ((now - ts).max(0) as u64).saturating_mul(1000);
                    status.write().await.rtt_ms = Some(ms);
                }
                Ok(ServerMsg::Open {
                    stream,
                    kind,
                    host,
                    port,
                }) => {
                    let ctx = ctx.clone();
                    tokio::spawn(async move {
                        if let Err(e) =
                            open_stream(ctx, stream, kind, host, port).await
                        {
                            tracing::warn!("open stream {stream} failed: {e:#}");
                        }
                    });
                }
                Ok(ServerMsg::Ping { ts }) => {
                    let _ = out_tx.send(Message::Text(
                        serde_json::to_string(&ClientMsg::Pong { ts }).unwrap().into(),
                    ));
                }
                Ok(ServerMsg::AdminResp { req_id, status, body }) => {
                    super::admin::on_admin_resp(req_id, status, body).await;
                }
                Ok(ServerMsg::Close { stream, .. }) => {
                    ctx.streams.write().await.remove(&stream);
                    super::egress::egress_streams().write().await.remove(&stream);
                }
                Ok(ServerMsg::Config { proxies }) => {
                    *ctx.proxies.write().await = proxies.clone();
                    super::link::sync_link_listeners(
                        &ctx,
                        &proxies,
                        &up.hostname,
                        &egress_out,
                        &status,
                    )
                    .await;
                    {
                        let mut st = status.write().await;
                        st.proxies = proxies.clone();
                    }
                    let _ = out_tx.send(Message::Text(
                        serde_json::to_string(&ClientMsg::ConfigAck { ok: true })
                            .unwrap()
                            .into(),
                    ));
                    let _ = out_tx.send(Message::Text(
                        serde_json::to_string(&ClientMsg::Register { proxies })
                            .unwrap()
                            .into(),
                    ));
                    tracing::info!("hot config applied");
                }
                Ok(_) => {}
                Err(e) => tracing::warn!("bad server frame: {e}"),
            },
            Message::Binary(b) => {
                if let Some((id, payload)) = decode_data(&b) {
                    if let Some(tx) = ctx.streams.read().await.get(&id).cloned() {
                        let _ = tx.send(payload.to_vec());
                    } else if payload.is_empty()
                        && super::egress::egress_streams().read().await.contains_key(&id)
                    {
                        // server eof 标记（与数据同 outbox 通道保序）：删表即 drop 唯一
                        // sender，handle_conn 的 drx 关闭→from_server 结束→连接 teardown。
                        super::egress::egress_streams().write().await.remove(&id);
                    } else if let Some(tx) = super::egress::egress_streams().read().await.get(&id).cloned() {
                        let _ = tx.send(payload.to_vec());
                    } else {
                        // Open not processed yet — buffer for open_stream to drain.
                        ctx.pending.write().await.entry(id).or_default().push(payload.to_vec());
                    }
                }
            }
            Message::Close(_) => {
                tracing::warn!("ws closed by server");
                break;
            }
            _ => {}
        }
    }
    // 主循环退出 = 掉线（调用方负责重连退避）。之前此处静默，agent 掉线只能去 server 侧猜。
    tracing::warn!("ws session ended, will redial");
    *egress_out.write().await = None;
    super::admin::set_sender(None).await;
    writer.abort();
    anyhow::Ok(())
}

async fn open_stream(
    ctx: Arc<Ctx>,
    sid: u32,
    kind: String,
    host: String,
    port: u16,
) -> anyhow::Result<()> {
    if kind == "udp" {
        return open_udp_stream(ctx, sid, port).await;
    }
    if kind == "link_udp" {
        // UDP 出口：server 下发真实目标，直接 connect + 双泵（与 open_udp_stream 同泵）。
        let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
        if sock.connect((host.as_str(), port)).await.is_err() {
            let e = ClientMsg::Close { stream: sid, reason: "link denied".into() };
            let _ = ctx.out.send(Message::Text(serde_json::to_string(&e).unwrap().into()));
            return Ok(());
        }
        tracing::debug!("link_udp egress stream {sid} -> {host}:{port}");
        return open_udp_stream_sock(ctx, sid, sock).await;
    }
    if kind == "egress_dial" {
        return open_egress_dial(ctx, sid, host, port).await;
    }
    if kind == "link" {
        // link 出口：server 侧下发的 host/port 即真实目标（以 server 存为准），
        // 直接 dial，不查本地 proxies。泵与 tcp 同（EOF 即收尾）。
        let local = TcpStream::connect((host.as_str(), port)).await?;
        let (dtx, mut drx) = mpsc::unbounded_channel::<Vec<u8>>();
        let early = ctx.pending.write().await.remove(&sid).unwrap_or_default();
        for chunk in early {
            let _ = dtx.send(chunk);
        }
        ctx.streams.write().await.insert(sid, dtx);
        let (mut lr, mut lw) = local.into_split();
        let ctx3 = ctx.clone();
        let ctx2 = ctx.clone();
        let mut ws_to_local = tokio::spawn(async move {
            while let Some(chunk) = drx.recv().await {
                if lw.write_all(&chunk).await.is_err() {
                    break;
                }
            }
        });
        let mut local_to_ws = tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            let mut b = vec![0u8; 32 * 1024];
            loop {
                match lr.read(&mut b).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if ctx3.out.send(Message::Binary(encode_data(sid, &b[..n]).into())).is_err() {
                            break;
                        }
                    }
                }
            }
        });
        // 任一方向结束即拆：否则对端关后泵永等→不回 Close→server conns 僵尸行。
        tokio::select! {
            _ = &mut ws_to_local => { local_to_ws.abort(); }
            _ = &mut local_to_ws => { ws_to_local.abort(); }
        }
        ctx.streams.write().await.remove(&sid);
        let e = ClientMsg::Close { stream: sid, reason: "eof".into() };
        let _ = ctx2.out.send(Message::Text(serde_json::to_string(&e).unwrap().into()));
        return Ok(());
    }
    // route to local target
    let proxies = ctx.proxies.read().await.clone();
    let target = if kind == "http" {
        proxies.iter().find(|p| {
            p.enabled
                && p.domains.iter().any(|d| d.eq_ignore_ascii_case(&host))
        })
    } else {
        // tcp (incl. https passthrough): match by remote_port, fallback to first tcp/https
        proxies
            .iter()
            .find(|p| {
                p.enabled
                    && p.remote_port == port
                    && (p.ptype == "tcp" || p.ptype == "https")
            })
            .or_else(|| {
                proxies.iter().find(|p| {
                    p.enabled && (p.ptype == "tcp" || p.ptype == "https")
                })
            })
    };
    let Some(p) = target else {
        let e = ClientMsg::Close {
            stream: sid,
            reason: "no route".into(),
        };
        let _ = ctx
            .out
            .send(Message::Text(serde_json::to_string(&e).unwrap().into()));
        return Ok(());
    };
    let local = TcpStream::connect((p.local_ip.as_str(), p.local_port)).await?;
    tracing::debug!("stream {sid} -> {}:{}", p.local_ip, p.local_port);
    let (dtx, mut drx) = mpsc::unbounded_channel::<Vec<u8>>();
    let early = ctx.pending.write().await.remove(&sid).unwrap_or_default();
    for chunk in early {
        let _ = dtx.send(chunk);
    }
    ctx.streams.write().await.insert(sid, dtx);
    let (mut lr, mut lw) = local.into_split(); // owned halves, 'static
    let ctx2 = ctx.clone();
    // ws -> local
    let ws_to_local = tokio::spawn(async move {
        while let Some(chunk) = drx.recv().await {
            if lw.write_all(&chunk).await.is_err() {
                break;
            }
        }
    });
    // local -> ws：只有 http（有明确响应边界）才做“读一个响应即收尾”；
    // tcp/https/裸流按字节透传，任意一方向 EOF 即收尾（旧 select! 逻辑）。
    // 之前 http 逻辑套在 tcp 上，echo 回包无响应头，被当成“头过大兜底裸流”
    // 进了 stream_body_until_idle 的 5s 空闲等待——tcp 回声测试挂 10s 超时。
    let ctx3 = ctx.clone();
    if kind == "http" {
        let local_to_ws = tokio::spawn(http_response_pump(WsSender(ctx3.out.clone()), sid, lr));
        // keep-alive 后端不会 FIN，不能等 ws->local 的 EOF：
        // 响应读完即收尾（之前 select! 双向等，curl 挂到 keep-alive 超时约 6s）。
        let _ = local_to_ws.await;
        ws_to_local.abort();
    } else {
        let local_to_ws = tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            let mut b = vec![0u8; 32 * 1024];
            loop {
                match lr.read(&mut b).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if ctx3.out.send(Message::Binary(encode_data(sid, &b[..n]).into())).is_err() {
                            break;
                        }
                    }
                }
            }
        });
        tokio::select! {
            _ = ws_to_local => {}
            _ = local_to_ws => {}
        }
    }
    ctx.streams.write().await.remove(&sid);
    let e = ClientMsg::Close { stream: sid, reason: "eof".into() };
    let _ = ctx2.out.send(Message::Text(serde_json::to_string(&e).unwrap().into()));
    Ok(())
}

/// http 响应泵：按 Content-Length / chunked 把“一个响应”读完即收尾。
/// keep-alive 后端不会 FIN，不能等 EOF（旧代码挂 6s 就是等它）；
/// 读不到完整头/超预算则按流式透传兜底（靠 server 侧 30s 上游超时）。
/// lr 所有权移入：读完即结束，无借用问题。
async fn open_udp_stream(ctx: Arc<Ctx>, sid: u32, port: u16) -> anyhow::Result<()> {
    let proxies = ctx.proxies.read().await.clone();
    let target = proxies
        .iter()
        .find(|p| p.enabled && p.ptype == "udp" && p.remote_port == port)
        .or_else(|| proxies.iter().find(|p| p.enabled && p.ptype == "udp"));
    let Some(p) = target else {
        let e = ClientMsg::Close { stream: sid, reason: "no route".into() };
        let _ = ctx.out.send(Message::Text(serde_json::to_string(&e).unwrap().into()));
        return Ok(());
    };
    let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
    sock.connect((p.local_ip.as_str(), p.local_port)).await?;
    tracing::debug!("udp stream {sid} -> {}:{}", p.local_ip, p.local_port);
    open_udp_stream_sock(ctx, sid, sock).await
}

/// UDP 双泵（已 connect 的 socket 版）：出口 link_udp 与普通 udp 共用。
/// egress 出口反向拨号（WSS 版）：server 下发 Open{egress_dial, 真实目标} → 本机 dial → 双泵。
/// 与 open_tcp_stream 出口段同构；失败回 Close{link denied}（复用原因串，server 清行）。
async fn open_egress_dial(ctx: Arc<Ctx>, sid: u32, host: String, port: u16) -> anyhow::Result<()> {
    let local = match tokio::time::timeout(
        std::time::Duration::from_secs(30),
        TcpStream::connect((host.as_str(), port)),
    )
    .await
    {
        Ok(Ok(s)) => s,
        _ => {
            let e = ClientMsg::Close { stream: sid, reason: "link denied".into() };
            let _ = ctx.out.send(Message::Text(serde_json::to_string(&e).unwrap().into()));
            return Ok(());
        }
    };
    tracing::debug!("egress_dial stream {sid} -> {host}:{port}");
    let (dtx, mut drx) = mpsc::unbounded_channel::<Vec<u8>>();
    let early = ctx.pending.write().await.remove(&sid).unwrap_or_default();
    for chunk in early {
        let _ = dtx.send(chunk);
    }
    ctx.streams.write().await.insert(sid, dtx);
    let (mut lr, mut lw) = local.into_split();
    let ctx3 = ctx.clone();
    let ctx2 = ctx.clone();
    let mut ws_to_local = tokio::spawn(async move {
        while let Some(chunk) = drx.recv().await {
            if lw.write_all(&chunk).await.is_err() {
                break;
            }
        }
    });
    let mut local_to_ws = tokio::spawn(async move {
        use tokio::io::AsyncReadExt;
        let mut b = vec![0u8; 32 * 1024];
        loop {
            match lr.read(&mut b).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if ctx3.out.send(Message::Binary(encode_data(sid, &b[..n]).into())).is_err() {
                        break;
                    }
                }
            }
        }
    });
    tokio::select! {
        _ = &mut ws_to_local => { local_to_ws.abort(); }
        _ = &mut local_to_ws => { ws_to_local.abort(); }
    }
    ctx.streams.write().await.remove(&sid);
    let e = ClientMsg::Close { stream: sid, reason: "eof".into() };
    let _ = ctx.out.send(Message::Text(serde_json::to_string(&e).unwrap().into()));
    let _ = &ctx2;
    anyhow::Ok(())
}

async fn open_udp_stream_sock(ctx: Arc<Ctx>, sid: u32, sock: tokio::net::UdpSocket) -> anyhow::Result<()> {
    let sock = Arc::new(sock);
    let (dtx, mut drx) = mpsc::unbounded_channel::<Vec<u8>>();
    let early = ctx.pending.write().await.remove(&sid).unwrap_or_default();
    for chunk in early {
        let _ = dtx.send(chunk);
    }
    ctx.streams.write().await.insert(sid, dtx);
    // ws -> udp (each frame = one datagram), with idle timeout
    let w = sock.clone();
    let ws_to_udp = tokio::spawn(async move {
        loop {
            match tokio::time::timeout(std::time::Duration::from_secs(120), drx.recv()).await {
                Ok(Some(dg)) => {
                    if w.send(&dg).await.is_err() {
                        break;
                    }
                }
                _ => break, // closed or idle-expired
            }
        }
    });
    // udp -> ws
    let ctx3 = ctx.clone();
    let r = sock.clone();
    let udp_to_ws = tokio::spawn(async move {
        let mut b = vec![0u8; 65535];
        loop {
            match r.recv(&mut b).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if ctx3.out.send(Message::Binary(encode_data(sid, &b[..n]).into())).is_err() {
                        break;
                    }
                }
            }
        }
    });
    let _ = tokio::join!(ws_to_udp, udp_to_ws);
    ctx.streams.write().await.remove(&sid);
    let e = ClientMsg::Close { stream: sid, reason: "eof".into() };
    let _ = ctx.out.send(Message::Text(serde_json::to_string(&e).unwrap().into()));
    Ok(())
}

