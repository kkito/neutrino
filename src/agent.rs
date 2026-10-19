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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AgentFileConfig {
    hostname: String,
    token: String,
    #[serde(default)]
    proxies: Vec<ProxyConfig>,
}

struct Ctx {
    proxies: RwLock<Vec<ProxyConfig>>,
    streams: RwLock<HashMap<u32, mpsc::UnboundedSender<Vec<u8>>>>,
    /// Binary arrived before Open task inserted the channel (server sends
    /// Open+head back-to-back; spawn ordering isn't guaranteed).
    pending: RwLock<HashMap<u32, Vec<Vec<u8>>>>,
    out: mpsc::UnboundedSender<Message>,
}

pub async fn run(url: &str, config_path: &str) -> anyhow::Result<()> {
    let raw = tokio::fs::read_to_string(config_path).await.map_err(|e| {
        anyhow::anyhow!("read {config_path}: {e} (see agent.toml.example)")
    })?;
    let cfg: AgentFileConfig = toml::from_str(&raw)?;
    tracing::info!(
        "agent '{}' -> {url} ({} proxies)",
        cfg.hostname,
        cfg.proxies.len()
    );
    let mut backoff = vec![1u64, 2, 5, 10, 30, 60];
    loop {
        match session(url, &cfg).await {
            Ok(_) => {
                tracing::info!("session ended, reconnect in 2s");
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
            Err(e) => {
                let s = backoff.first().cloned().unwrap_or(60);
                if backoff.len() > 1 {
                    backoff.remove(0);
                }
                tracing::warn!("session error: {e:#}; retry in {s}s");
                tokio::time::sleep(std::time::Duration::from_secs(s)).await;
            }
        }
    }
}

async fn session(url: &str, cfg: &AgentFileConfig) -> anyhow::Result<()> {
    let (ws, _) = connect_async(url).await?;
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
    // hello
    send(&ClientMsg::Hello {
        hostname: cfg.hostname.clone(),
        version: VERSION.into(),
        token: cfg.token.clone(),
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
                Ok(ServerMsg::Pong { .. }) => {}
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
                Ok(ServerMsg::Close { stream, .. }) => {
                    ctx.streams.write().await.remove(&stream);
                }
                Ok(ServerMsg::Config { proxies }) => {
                    *ctx.proxies.write().await = proxies.clone();
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
    // drain data that arrived before the Open task ran
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
    // local -> ws
    let ctx3 = ctx.clone();
    let local_to_ws = tokio::spawn(async move {
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
    // either direction EOF ends the stream (join! would wait for BOTH,
    // but ws->local only ends when server closes the stream, i.e. never
    // for keep-alive HTTP — that was the hang: curl waited for backend
    // response EOF while we waited for curl's EOF).
    tokio::select! {
        _ = ws_to_local => {}
        _ = local_to_ws => {}
    }
    ctx.streams.write().await.remove(&sid);
    let e = ClientMsg::Close { stream: sid, reason: "eof".into() };
    let _ = ctx2.out.send(Message::Text(serde_json::to_string(&e).unwrap().into()));
    Ok(())
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
