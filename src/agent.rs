//! Agent side: out-bound WSS, local dial, stream pumps.
use crate::proto::*;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::{mpsc, RwLock},
};
use tokio_tungstenite::{connect_async, tungstenite::Message};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct AgentFileConfig {
    hostname: String,
    #[serde(default)]
    token: String,
    #[serde(default)]
    server: String,
    #[serde(default)]
    proxies: Vec<ProxyConfig>,
}

/// Hot-updatable upstream dial config (WebUI can change without restart).
#[derive(Debug, Clone)]
pub struct Upstream {
    pub server_url: String,
    pub hostname: String,
    pub token: String,
}

pub use crate::agent_web::AgentStatus;

struct Ctx {
    proxies: RwLock<Vec<ProxyConfig>>,
    streams: RwLock<HashMap<u32, mpsc::UnboundedSender<Vec<u8>>>>,
    /// Binary arrived before Open task inserted the channel (server sends
    /// Open+head back-to-back; spawn ordering isn't guaranteed).
    pending: RwLock<HashMap<u32, Vec<Vec<u8>>>>,
    out: mpsc::UnboundedSender<Message>,
}

async fn load_or_default(config_path: &str, url: &str) -> anyhow::Result<AgentFileConfig> {
    match tokio::fs::read_to_string(config_path).await {
        Ok(raw) => Ok(toml::from_str(&raw)?),
        // config 文件缺失也允许启动：用 CLI --server + 默认 hostname/token 先跑，
        // 用户稍后在本地 WebUI 里填上行地址，保存即落盘+重连。
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::warn!("{config_path} not found, starting unconfigured (set upstream via WebUI); see agent.toml.example");
            Ok(AgentFileConfig {
                hostname: std::env::var("HOSTNAME")
                    .ok()
                    .filter(|h| !h.trim().is_empty())
                    .unwrap_or_else(|| "agent".into()),
                token: String::new(),
                server: url.to_string(),
                proxies: vec![],
            })
        }
        Err(e) => Err(anyhow::anyhow!("read {config_path}: {e} (see agent.toml.example)")),
    }
}

/// 默认上行（与 CLI --server 默认值保持一致，单测 enforce）。
pub const DEFAULT_AGENT_SERVER: &str = "wss://tunnel.nat.kkito.cn:7443/ws";

/// 启动上行解析：显式 CLI > 文件 > CLI 默认。
/// cli_explicit 指用户是否在命令行改了 --server（与默认值不同即算显式）。
fn resolve_initial_url(cli_url: &str, cfg: &AgentFileConfig, cli_explicit: bool) -> String {
    if cli_explicit {
        cli_url.to_string()
    } else if cfg.server.trim().is_empty() {
        cli_url.to_string()
    } else {
        cfg.server.clone()
    }
}

/// backoff 睡眠，可被 redial 打断：被打断返回 true（调用方立即重拨）。
/// seen 为进入睡眠前的 generation：订阅前已到的 bump 也算打断，避免间隙丢失。
async fn sleep_backoff_or_redial(
    dur: std::time::Duration,
    mut rx: tokio::sync::watch::Receiver<u64>,
    seen: u64,
) -> bool {
    if *rx.borrow() != seen {
        return true;
    }
    tokio::select! {
        _ = tokio::time::sleep(dur) => false,
        woke = async {
            loop {
                if rx.changed().await.is_err() {
                    return false;
                }
                if *rx.borrow_and_update() != seen {
                    return true;
                }
            }
        } => woke,
    }
}

pub async fn run(url: &str, config_path: &str, web: &str, web_user: &str, web_pass: &str) -> anyhow::Result<()> {
    let cfg: AgentFileConfig = load_or_default(config_path, url).await?;
    if !cfg.proxies.is_empty() {
        tracing::warn!("local proxies in {config_path} ignored: server is source of truth");
    }
    // 启动优先级：显式 --server > 文件 server > 默认值。
    // 文件里的 server 是 WebUI 上次保存的；用户本次显式传参则覆盖它
    // （并在 WebUI 保存时回写文件，后续启动不用再传）。
    let cli_explicit = url != DEFAULT_AGENT_SERVER;
    let initial_url = resolve_initial_url(url, &cfg, cli_explicit);
    let upstream = Arc::new(RwLock::new(Upstream {
        server_url: initial_url.clone(),
        hostname: cfg.hostname.clone(),
        token: cfg.token.clone(),
    }));
    tracing::info!(
        "agent '{}' -> {initial_url} ({} proxies)",
        cfg.hostname,
        cfg.proxies.len()
    );
    // shared status for local WebUI
    let status = Arc::new(RwLock::new(crate::agent_web::AgentStatus {
        server_url: initial_url.clone(),
        hostname: cfg.hostname.clone(),
        ..Default::default()
    }));
    // bumped by WebUI to force an immediate redial (settings save / button)
    let (redial_tx, redial_rx) = tokio::sync::watch::channel(0u64);
    if web.is_empty() {
        println!("agent local webui disabled (enable with --web 127.0.0.1:8080)");
    } else {
        // persist web password hash under agent data file.
        // NOTE: --web-pass only takes effect on FIRST run (when the file
        // doesn't exist yet). Afterwards the persisted hash wins; delete
        // the file to reset to the CLI value.
        let data_path = format!("{config_path}.webpass");
        let (hash, fresh) = match tokio::fs::read_to_string(&data_path).await {
            Ok(h) if !h.trim().is_empty() => {
                if web_pass != "neutrino123" {
                    tracing::warn!("--web-pass ignored: {data_path} already exists (delete it to reset password)");
                }
                (h.trim().to_string(), false)
            }
            _ => {
                let h = bcrypt::hash(web_pass, bcrypt::DEFAULT_COST)?;
                let _ = tokio::fs::write(&data_path, &h).await;
                (h, true)
            }
        };
        if !fresh {
            println!("agent webui password: persisted ({data_path}); delete it to reset to --web-pass");
        }
        let w = web.to_string();
        let u = web_user.to_string();
        println!("agent local webui: http://{w}/ (user {u})");
        let ph = Arc::new(RwLock::new(hash));
        tokio::spawn(crate::agent_web::serve(crate::agent_web::ServeArgs {
            bind: w,
            user: u,
            pass_hash: ph,
            data_path,
            status: status.clone(),
            upstream: upstream.clone(),
            config_path: config_path.to_string(),
            redial: redial_tx.clone(),
        }));
    }
    let mut backoff = vec![1u64, 2, 5, 10, 30, 60];
    let mut reconnects = 0u64;
    // abort handle for the live session; WebUI redial aborts it so the loop
    // immediately redials with the new upstream (no waiting, no restart).
    // watch channel carries a monotonically increasing generation; the loop
    // re-checks it after every session so no bump is ever lost (no take race:
    // watcher only aborts, generation compare happens in-loop).
    let cur: Arc<tokio::sync::Mutex<Option<tokio::task::AbortHandle>>> =
        Arc::new(tokio::sync::Mutex::new(None));
    {
        let cur2 = cur.clone();
        tokio::spawn(async move {
            let mut rx = redial_rx;
            // skip the initial value; only future bumps count
            let mut seen = *rx.borrow_and_update();
            loop {
                if rx.changed().await.is_err() {
                    break;
                }
                let v = *rx.borrow_and_update();
                if v != seen {
                    seen = v;
                    if let Some(h) = cur2.lock().await.as_ref() {
                        h.abort();
                    }
                }
            }
        });
    }
    let mut redial_seen = *redial_tx.borrow();
    loop {
        // bump arrived while not in a session (backoff / debounce gap):
        // count the redial without spawning a stale session first, so no
        // user click is ever lost (the old debounce consumed them).
        {
            let gen_now = *redial_tx.borrow();
            if gen_now != redial_seen {
                redial_seen = gen_now;
                reconnects += 1;
                backoff = vec![1u64, 2, 5, 10, 30, 60];
                {
                    let mut st = status.write().await;
                    st.online = false;
                    st.reconnects = reconnects;
                    st.last_error = Some("redial requested".into());
                }
                tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                continue;
            }
        }
        // snapshot hot-updatable dial config
        let up = upstream.read().await.clone();
        {
            let mut st = status.write().await;
            st.server_url = up.server_url.clone();
            st.hostname = up.hostname.clone();
        }
        // run session in a task so the watcher can abort it on redial
        let sess = tokio::spawn(session(up, cfg.clone(), status.clone()));
        *cur.lock().await = Some(sess.abort_handle());
        let err = match sess.await {
            Ok(Ok(())) => String::from("closed"),
            Ok(Err(e)) => format!("{e:#}"),
            Err(j) if j.is_cancelled() => String::from("redial requested"),
            Err(j) => format!("task: {j}"),
        };
        *cur.lock().await = None;
        reconnects += 1;
        // a redial bump that arrived while the session was already exiting
        // (watcher had nothing/old handle to abort) still counts: compare
        // generations in-loop so the signal is never lost.
        let gen_now = *redial_tx.borrow();
        let bumped = gen_now != redial_seen;
        redial_seen = gen_now;
        let redial = err == "redial requested" || bumped;
        {
            let mut st = status.write().await;
            st.online = false;
            st.reconnects = reconnects;
            st.last_error = Some(err);
        }
        if redial {
            // user-triggered: immediate redial, reset backoff
            backoff = vec![1u64, 2, 5, 10, 30, 60];
            // small debounce so rapid double-clicks don't spin; bumps arriving
            // during the debounce coalesce (consume them so the next session
            // starts once with the latest upstream instead of redialing twice).
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            redial_seen = *redial_tx.borrow();
        } else {
            let s = backoff.first().cloned().unwrap_or(60);
            if backoff.len() > 1 {
                backoff.remove(0);
            }
            tracing::warn!("session ended; retry in {s}s (WebUI save reconnects immediately)");
            // 睡眠可被 WebUI 保存打断：打断后按 redial 走（立即重拨+重置 backoff）。
            // 传 seen=redial_seen：subscribe 间隙到达的 bump 也算打断，不丢。
            if sleep_backoff_or_redial(std::time::Duration::from_secs(s), redial_tx.subscribe(), redial_seen).await {
                reconnects += 1;
                backoff = vec![1u64, 2, 5, 10, 30, 60];
                {
                    let mut st = status.write().await;
                    st.online = false;
                    st.reconnects = reconnects;
                    st.last_error = Some("redial requested".into());
                }
                tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                redial_seen = *redial_tx.borrow();
                continue;
            }
        }
    }
}

async fn session(up: Upstream, cfg: AgentFileConfig, status: Arc<RwLock<crate::agent_web::AgentStatus>>) -> anyhow::Result<()> {
    let (ws, _) = connect_async(up.server_url.as_str()).await?;
    tracing::info!("ws connected");
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
    let ctx = Arc::new(Ctx {
        proxies: RwLock::new(cfg.proxies.clone()),
        streams: RwLock::new(HashMap::new()),
        pending: RwLock::new(HashMap::new()),
        out: out_tx.clone(),
    });
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

    // reader loop
    while let Some(msg) = stream.next().await {
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
                Ok(ServerMsg::Close { stream, .. }) => {
                    ctx.streams.write().await.remove(&stream);
                }
                Ok(ServerMsg::Config { proxies }) => {
                    *ctx.proxies.write().await = proxies.clone();
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
                    } else {
                        // Open not processed yet — buffer for open_stream to drain.
                        ctx.pending.write().await.entry(id).or_default().push(payload.to_vec());
                    }
                }
            }
            Message::Close(_) => break,
            _ => {}
        }
    }
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
        let local_to_ws = tokio::spawn(http_response_pump(ctx3, sid, lr));
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
async fn http_response_pump(ctx: Arc<Ctx>, sid: u32, mut lr: tokio::net::tcp::OwnedReadHalf) {
    use tokio::io::AsyncReadExt;
    let mut b = vec![0u8; 32 * 1024];
    // 首包：必须含完整响应头，否则按裸流透传
    let mut head = vec![];
    loop {
        match tokio::time::timeout(std::time::Duration::from_secs(10), lr.read(&mut b)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => return,
            Ok(Ok(n)) => {
                head.extend_from_slice(&b[..n]);
                if head.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
                if head.len() > 64 * 1024 {
                    break; // 头过大：兜底裸流
                }
            }
        }
    }
    let hpos = head.windows(4).position(|w| w == b"\r\n\r\n");
    let (hlen, body_prefix) = match hpos {
        Some(i) => (i + 4, head[i + 4..].to_vec()),
        None => {
            let _ = ctx.out.send(Message::Binary(encode_data(sid, &head).into()));
            stream_body_until_idle(ctx.clone(), sid, &mut lr).await;
            return;
        }
    };
    let hdr_txt = String::from_utf8_lossy(&head[..hlen]);
    let _ = ctx.out.send(Message::Binary(encode_data(sid, &head).into()));
    if hdr_txt.lines().any(|l| {
        matches!(l.split_once(':'), Some((k, v))
            if k.trim().eq_ignore_ascii_case("transfer-encoding")
                && v.to_lowercase().contains("chunked"))
    }) {
        // chunked：按块边界读到 0-chunk 即收尾，不靠超时。
        stream_chunked(ctx.clone(), sid, &mut lr, body_prefix).await;
        return;
    }
    if hdr_txt.lines().any(|l| {
        matches!(l.split_once(':'), Some((k, v))
            if k.trim().eq_ignore_ascii_case("connection")
                && v.to_lowercase().contains("close"))
    }) {
        // connection: close：靠 EOF 收尾。
        stream_body_until_idle(ctx.clone(), sid, &mut lr).await;
        return;
    }
    let want: usize = content_length(&hdr_txt).unwrap_or(0);
    let mut got = body_prefix.len();
    let mut extra = want.saturating_sub(got);
    while extra > 0 {
        match tokio::time::timeout(std::time::Duration::from_secs(10), lr.read(&mut b)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
            Ok(Ok(n)) => {
                if ctx.out.send(Message::Binary(encode_data(sid, &b[..n]).into())).is_err() {
                    break;
                }
                got += n;
                extra = want.saturating_sub(got);
            }
        }
    }
}

/// 从响应头文本提取 Content-Length（无则 None）。
fn content_length(hdr: &str) -> Option<usize> {
    hdr.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        if k.trim().eq_ignore_ascii_case("content-length") {
            v.trim().parse::<usize>().ok()
        } else {
            None
        }
    })
}

/// chunked 响应：按块边界读到 0-chunk 即收尾。
/// 关键：body_prefix 里可能已含后续块（甚至整个尾部），先消费 prefix 再读网。
/// 0-chunk 行本身（`0\r\n`）+ 其后 trailer 空行在 prefix 里齐了就直接收尾，
/// 不再读网——否则 keep-alive 连接上读网会挂到对方超时。
async fn stream_chunked(ctx: Arc<Ctx>, sid: u32, lr: &mut tokio::net::tcp::OwnedReadHalf, prefix: Vec<u8>) {
    use tokio::io::AsyncReadExt;
    let mut buf: Vec<u8> = prefix;
    loop {
        // 读到一行块头
        let line_end = loop {
            if let Some(i) = buf.windows(2).position(|w| w == b"\r\n") {
                break i;
            }
            let mut b = vec![0u8; 4096];
            match tokio::time::timeout(std::time::Duration::from_secs(10), lr.read(&mut b)).await {
                Ok(Ok(0)) | Ok(Err(_)) | Err(_) => {
                    let _ = ctx.out.send(Message::Binary(encode_data(sid, &buf).into()));
                    return;
                }
                Ok(Ok(n)) => buf.extend_from_slice(&b[..n]),
            }
        };
        let size_line = String::from_utf8_lossy(&buf[..line_end]).to_string();
        let size = usize::from_str_radix(size_line.split(';').next().unwrap_or("").trim(), 16).unwrap_or(usize::MAX);
        if size == usize::MAX {
            let _ = ctx.out.send(Message::Binary(encode_data(sid, &buf).into()));
            stream_body_until_idle(ctx.clone(), sid, lr).await; // 非法块头兜底
            return;
        }
        if size == 0 {
            // 0-chunk 行 + trailer：能从 buf 里凑够 `\r\n\r\n` 就直接收尾。
            let after = &buf[line_end + 2..];
            if after.windows(4).any(|w| w == b"\r\n\r\n") || after == b"\r\n" {
                let _ = ctx.out.send(Message::Binary(encode_data(sid, &buf).into()));
            } else {
                // prefix 里尾部不全：最多再等 1s 凑 trailer，凑不齐也收尾
                // （trailer 可丢，不能把等待算进响应）。
                let _ = ctx.out.send(Message::Binary(encode_data(sid, &buf).into()));
                let mut tail: Vec<u8> = vec![];
                let _ = tokio::time::timeout(std::time::Duration::from_secs(1), async {
                    let mut b = vec![0u8; 1024];
                    while !tail.windows(2).any(|w| w == b"\r\n") && tail.len() < 1024 {
                        match lr.read(&mut b).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => tail.extend_from_slice(&b[..n]),
                        }
                    }
                })
                .await;
            }
            return;
        }
        // 需要 size + 2（尾 CRLF）字节
        let need = line_end + 2 + size + 2;
        while buf.len() < need {
            let mut b = vec![0u8; 32 * 1024];
            match tokio::time::timeout(std::time::Duration::from_secs(10), lr.read(&mut b)).await {
                Ok(Ok(0)) | Ok(Err(_)) | Err(_) => {
                    let _ = ctx.out.send(Message::Binary(encode_data(sid, &buf).into()));
                    return;
                }
                Ok(Ok(n)) => buf.extend_from_slice(&b[..n]),
            }
        }
        // 本块完整：切出来发送，留剩余继续解析（关键：不能整 buf 一次发完就 return，
        // 否则 0-chunk 还没读到；也不能攒着不发，要边读边发）。
        let chunk = buf[..need].to_vec();
        let _ = ctx.out.send(Message::Binary(encode_data(sid, &chunk).into()));
        buf = buf[need..].to_vec();
    }
}

/// 流式透传直到后端 EOF 或 5s 读空闲（chunked/close 连接的收尾方式）。
async fn stream_body_until_idle(ctx: Arc<Ctx>, sid: u32, lr: &mut tokio::net::tcp::OwnedReadHalf) {
    let mut b = vec![0u8; 32 * 1024];
    loop {
        match tokio::time::timeout(std::time::Duration::from_secs(5), lr.read(&mut b)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
            Ok(Ok(n)) => {
                if ctx.out.send(Message::Binary(encode_data(sid, &b[..n]).into())).is_err() {
                    break;
                }
            }
        }
    }
}

/// UDP over stream: each Binary frame = one datagram. Agent dials a connected
/// UDP socket to local_ip:local_port and shuttles datagrams both ways.
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
    let sock = Arc::new(sock);
    tracing::debug!("udp stream {sid} -> {}:{}", p.local_ip, p.local_port);
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

#[cfg(test)]
mod tests {
    use super::*;

        use std::time::Duration;

    /// RED: backoff 睡眠必须可被 redial 打断。
    /// 现场：session 刚失败，主循环进 30s+ 睡眠，此时 WebUI 点保存 bump。
    /// 判定函数 sleep_backoff_or_redial：redial 到达即早返 true。
    #[tokio::test]
    async fn backoff_sleep_is_interruptible_by_redial() {
        let (tx, rx) = tokio::sync::watch::channel(0u64);
        // 无 bump：睡满（用 50ms 代表，便于测试）
        let t0 = std::time::Instant::now();
        let woke = sleep_backoff_or_redial(Duration::from_millis(50), rx.clone(), 0).await;
        assert!(!woke);
        assert!(t0.elapsed() >= Duration::from_millis(50));
        // 睡眠中到达的 bump：30s 睡眠也必须毫秒级打断
        let h = tokio::spawn(async move {
            sleep_backoff_or_redial(Duration::from_secs(30), rx, 0).await
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        tx.send_replace(1);
        let woke = tokio::time::timeout(Duration::from_secs(2), h)
            .await
            .expect("redial must interrupt backoff")
            .unwrap();
        assert!(woke, "redial during backoff must interrupt sleep");
    }

    #[tokio::test]
    async fn backoff_sleep_catches_pre_subscribe_bump() {
        // bump 发生在 subscribe 间隙（借出旧句柄后、新订阅前）：
        // 新订阅看到的 generation 已变，必须直接判打断，不能再睡。
        let (tx, rx) = tokio::sync::watch::channel(0u64);
        tx.send_replace(7);
        let woke = sleep_backoff_or_redial(Duration::from_secs(30), rx, 0).await;
        assert!(woke, "stale-observed generation must count as redial");
    }

    #[tokio::test]
    async fn cli_server_overrides_file() {
        // RED: 启动时显式传 --server，必须优先于文件里的 server。
        // 现场：文件里是旧地址，CLI 给了新地址，实际拨的应是 CLI 的。
        // 默认值不算“显式传”：只有用户改了 CLI 默认值才覆盖文件。
        let dir = std::env::temp_dir().join(format!("nt-agent-test-{}", uuid::Uuid::new_v4()));
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let p = dir.join("agent.toml");
        tokio::fs::write(&p, "hostname = \"h\"\ntoken = \"t\"\nserver = \"ws://file-old/ws\"\n").await.unwrap();
        let cfg = load_or_default(p.to_str().unwrap(), "ws://cli-new/ws").await.unwrap();
        assert_eq!(resolve_initial_url("ws://cli-new/ws", &cfg, true), "ws://cli-new/ws");
        // 没显式传（还是默认值）：文件优先
        assert_eq!(resolve_initial_url(super::DEFAULT_AGENT_SERVER, &cfg, false), "ws://file-old/ws");
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn missing_config_starts_unconfigured() {
        let cfg = load_or_default("/nonexistent-dir-xyz/agent.toml", "ws://x:7440/ws").await.unwrap();
        assert_eq!(cfg.server, "ws://x:7440/ws");
        assert!(cfg.proxies.is_empty());
        // hostname 回退：HOSTNAME 为空时用默认名而非 panic
        assert!(!cfg.hostname.trim().is_empty());
    }

    #[tokio::test]
    async fn load_or_default_reads_existing_file() {
        let dir = std::env::temp_dir().join(format!("nt-agent-test-{}", uuid::Uuid::new_v4()));
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let p = dir.join("agent.toml");
        tokio::fs::write(&p, "hostname = \"h1\"\ntoken = \"t1\"\nserver = \"ws://s1/ws\"\n").await.unwrap();
        let cfg = load_or_default(p.to_str().unwrap(), "ws://cli/ws").await.unwrap();
        assert_eq!(cfg.hostname, "h1");
        assert_eq!(cfg.token, "t1");
        assert_eq!(cfg.server, "ws://s1/ws");
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn load_or_default_rejects_broken_toml() {
        let dir = std::env::temp_dir().join(format!("nt-agent-test-{}", uuid::Uuid::new_v4()));
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let p = dir.join("agent.toml");
        tokio::fs::write(&p, "[[[").await.unwrap();
        assert!(load_or_default(p.to_str().unwrap(), "ws://cli/ws").await.is_err());
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }
}
