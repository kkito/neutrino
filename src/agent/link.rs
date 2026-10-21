//! agent link 入口监听：本地 accept -> WSS Open{link} -> 双向泵。照抄 egress 模式。
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, RwLock};

use super::egress::OutHolder;
use super::quic_session::QCtx;
use super::kudus_session::KCtx;
/// Config 同步 link 监听（kudus 版）：任务表挂在 KCtx 上，出站走 KudusOutHolder（Pkt）。
pub(crate) async fn sync_link_listeners_kudus(
    ctx: &KCtx,
    proxies: &[crate::common::proto::ProxyConfig],
    self_hostname: &str,
    holder: &super::egress::KudusOutHolder,
) {
    use crate::common::proto::valid_link;
    use std::collections::HashSet;
    let want: HashSet<String> = proxies
        .iter()
        .filter(|p| valid_link(p, self_hostname))
        .map(|p| p.name.clone())
        .collect();
    let mut tasks = ctx.link_tasks.lock().await;
    let gone: Vec<String> = tasks.keys().filter(|k| !want.contains(*k)).cloned().collect();
    for k in gone {
        if let Some(h) = tasks.remove(&k) { h.abort(); }
    }
    for p in proxies.iter().filter(|p| valid_link(p, self_hostname)) {
        if tasks.contains_key(&p.name) { continue; }
        let bind = format!("{}:{}", p.local_ip, p.local_port);
        let h = tokio::spawn(serve_link_kudus(p.name.clone(), bind, holder.clone()));
        tasks.insert(p.name.clone(), h.abort_handle());
    }
}

async fn serve_link_kudus(link_name: String, bind: String, holder: super::egress::KudusOutHolder) {
    let lis = match TcpListener::bind(&bind).await {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!("link '{link_name}' bind {bind} failed: {e:#}");
            return;
        }
    };
    tracing::info!("link '{link_name}' listen on {bind}");
    loop {
        let Ok((inbound, _)) = lis.accept().await else { continue; };
        let holder = holder.clone();
        let link_name = link_name.clone();
        tokio::spawn(async move {
            let hout = holder.read().await.clone();
            let Some(p) = hout else { return; };
            if let Err(e) = handle_link_conn_with(inbound, link_name, &Tx::Kudus(p)).await {
                tracing::debug!("link conn ended: {e:#}");
            }
        });
    }
}

use super::web::AgentStatus;
use crate::common::proto::{encode_data, ClientMsg};
use crate::common::quic::encode_frame;

static CTR: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);

/// Config 同步 link 监听：新 link 起 serve_link，消失的 abort，session 级持有。
/// 根因→修法：监听与 session 同命——重连即全量重建，不残留旧监听。
pub(crate) async fn sync_link_listeners(
    ctx: &super::session::Ctx,
    proxies: &[crate::common::proto::ProxyConfig],
    self_hostname: &str,
    out: &OutHolder,
    status: &Arc<RwLock<AgentStatus>>,
) {
    use crate::common::proto::valid_link;
    use std::collections::HashSet;
    let want: HashSet<String> = proxies
        .iter()
        .filter(|p| valid_link(p, self_hostname))
        .map(|p| p.name.clone())
        .collect();
    let mut tasks = ctx.link_tasks.lock().await;
    // 消失的 abort
    let gone: Vec<String> = tasks.keys().filter(|k| !want.contains(*k)).cloned().collect();
    for k in gone {
        if let Some(h) = tasks.remove(&k) {
            h.abort();
        }
    }
    // 新增的起监听
    for p in proxies.iter().filter(|p| valid_link(p, self_hostname)) {
        if tasks.contains_key(&p.name) {
            continue;
        }
        let bind = format!("{}:{}", p.local_ip, p.local_port);
        let h = tokio::spawn(serve_link(p.name.clone(), bind, out.clone(), status.clone()));
        tasks.insert(p.name.clone(), h.abort_handle());
    }
}

/// 单条 link 监听。bind 失败只记 status，不断 WSS 主链（同 egress）。
/// 根因→修法：监听 task 与 session/WSS 主链解耦，bind 失败直接返回。
pub(crate) async fn serve_link(
    link_name: String,
    bind: String,
    out: OutHolder,
    status: Arc<RwLock<AgentStatus>>,
) {
    let lis = match TcpListener::bind(&bind).await {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!("link '{link_name}' bind {bind} failed: {e:#}");
            status.write().await.link_err = Some(format!("{link_name} bind failed: {e:#}"));
            return;
        }
    };
    tracing::info!("link '{link_name}' listen on {bind}");
    loop {
        let Ok((inbound, _)) = lis.accept().await else {
            continue;
        };
        let (out, link_name) = (out.clone(), link_name.clone());
        tokio::spawn(async move {
            if let Err(e) = handle_link_conn(inbound, link_name, out).await {
                tracing::debug!("link conn ended: {e:#}");
            }
        });
    }
}

async fn handle_link_conn(
    inbound: TcpStream,
    link_name: String,
    out: OutHolder,
) -> anyhow::Result<()> {
    let holder = out.read().await.clone();
    let Some(tx) = holder else {
        anyhow::bail!("wss down");
    };
    handle_link_conn_with(inbound, link_name, &Tx::Ws(tx)).await
}

/// 发送端抽象：WSS 发 Message，QUIC 发 control 复用帧，kudus 发封包 datagram。
enum Tx {
    Ws(mpsc::UnboundedSender<tokio_tungstenite::tungstenite::Message>),
    Quic(mpsc::UnboundedSender<Vec<u8>>),
    Kudus(super::kudus_session::Pkt),
}

impl Tx {
    fn send_open(&self, sid: u32, link_name: &str) -> anyhow::Result<()> {
        let open = ClientMsg::Open {
            stream: sid,
            kind: "link".into(),
            host: link_name.to_string(),
            port: 0,
        };
        let j = serde_json::to_string(&open)?;
        match self {
            Tx::Ws(tx) => {
                tx.send(tokio_tungstenite::tungstenite::Message::Text(j.into()))?;
            }
            Tx::Quic(tx) => {
                tx.send(encode_frame(j.as_bytes()))?;
            }
            Tx::Kudus(p) => {
                p.send_ctrl(&ClientMsg::Open {
                    stream: sid,
                    kind: "link".into(),
                    host: link_name.to_string(),
                    port: 0,
                })?;
            }
        }
        Ok(())
    }
    #[allow(dead_code)]
    fn send_data(&self, _sid: u32, _chunk: &[u8]) -> anyhow::Result<()> {
        // from_local 已按分支内联（Tx 不可 Clone，进闭包需 match 重建发送器），
        // 此方法保留作 Tx 语义完备，暂未使用。
        anyhow::bail!("unused");
    }
    fn send_close(&self, sid: u32) {
        let e = ClientMsg::Close { stream: sid, reason: "eof".into() };
        if let Ok(j) = serde_json::to_string(&e) {
            match self {
                Tx::Ws(tx) => {
                    let _ = tx.send(tokio_tungstenite::tungstenite::Message::Text(j.into()));
                }
                Tx::Quic(tx) => {
                    let _ = tx.send(encode_frame(j.as_bytes()));
                }
                Tx::Kudus(p) => {
                    let _ = p.send_ctrl(&ClientMsg::Close { stream: sid, reason: "eof".into() });
                }
            }
        }
    }
}

/// Config 同步 link 监听（QUIC 版）：任务表挂在 QCtx 上，出站走 QuicOutHolder。
pub(crate) async fn sync_link_listeners_quic(
    ctx: &QCtx,
    proxies: &[crate::common::proto::ProxyConfig],
    self_hostname: &str,
    holder: &super::egress::QuicOutHolder,
) {
    use crate::common::proto::valid_link;
    use std::collections::HashSet;
    let want: HashSet<String> = proxies
        .iter()
        .filter(|p| valid_link(p, self_hostname))
        .map(|p| p.name.clone())
        .collect();
    let mut tasks = ctx.link_tasks.lock().await;
    let gone: Vec<String> = tasks.keys().filter(|k| !want.contains(*k)).cloned().collect();
    for k in gone {
        if let Some(h) = tasks.remove(&k) {
            h.abort();
        }
    }
    // QUIC 出站通道由 session 持有（与 WSS OutHolder 参数对称），监听 task 只 clone Arc。
    for p in proxies.iter().filter(|p| valid_link(p, self_hostname)) {
        if tasks.contains_key(&p.name) {
            continue;
        }
        let bind = format!("{}:{}", p.local_ip, p.local_port);
        let h = tokio::spawn(serve_link_quic(p.name.clone(), bind, holder.clone()));
        tasks.insert(p.name.clone(), h.abort_handle());
    }
}

async fn serve_link_quic(link_name: String, bind: String, holder: super::egress::QuicOutHolder) {
    let lis = match TcpListener::bind(&bind).await {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!("link '{link_name}' bind {bind} failed: {e:#}");
            return;
        }
    };
    tracing::info!("link '{link_name}' listen on {bind}");
    loop {
        let Ok((inbound, _)) = lis.accept().await else {
            continue;
        };
        let holder = holder.clone();
        let link_name = link_name.clone();
        tokio::spawn(async move {
            let hout = holder.read().await.clone();
            let Some(tx) = hout else {
                return;
            };
            if let Err(e) = handle_link_conn_with(inbound, link_name, &Tx::Quic(tx)).await {
                tracing::debug!("link conn ended: {e:#}");
            }
        });
    }
}

async fn handle_link_conn_with(inbound: TcpStream, link_name: String, tx: &Tx) -> anyhow::Result<()> {
    // sid 取奇数：server 偶数 sid，避免碰撞（同 egress）。
    let sid = CTR.fetch_add(2, std::sync::atomic::Ordering::Relaxed) | 1;
    let (dtx, mut drx) = mpsc::unbounded_channel::<Vec<u8>>();
    super::egress::egress_streams().write().await.insert(sid, dtx);
    // host=link名（server 以此查表，port 忽略）；目标以 server 存为准。
    tx.send_open(sid, &link_name)?;
    let (mut ri, mut wi) = inbound.into_split();
    // from_local 需要 &Tx 的克隆能力：Tx 不可 Clone，此处按变体重建发送闭包。
    // 简化：WSS/QUIC 两分支各自 spawn（Tx::Ws(tx) 的 tx 本身 Clone，Quic 同理）。
    let mut from_local = match tx {
        Tx::Ws(wtx) => {
            let tx2 = wtx.clone();
            tokio::spawn(async move {
                let mut b = vec![0u8; 32 * 1024];
                loop {
                    match ri.read(&mut b).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if tx2
                                .send(tokio_tungstenite::tungstenite::Message::Binary(
                                    encode_data(sid, &b[..n]).into(),
                                ))
                                .is_err()
                            {
                                break;
                            }
                        }
                    }
                }
            })
        }
        Tx::Quic(qtx) => {
            let tx2 = qtx.clone();
            tokio::spawn(async move {
                let mut b = vec![0u8; 32 * 1024];
                loop {
                    match ri.read(&mut b).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if tx2.send(encode_frame(&encode_data(sid, &b[..n]))).is_err() {
                                break;
                            }
                        }
                    }
                }
            })
        }
        Tx::Kudus(p) => {
            let p2 = p.clone();
            tokio::spawn(async move {
                let mut b = vec![0u8; 32 * 1024];
                loop {
                    match ri.read(&mut b).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            use crate::common::kudus::FLAG_DATA;
                            if p2.send(FLAG_DATA, 0, [0u8; 32], &encode_data(sid, &b[..n])).is_err() {
                                break;
                            }
                        }
                    }
                }
            })
        }
    };
    let mut to_local = tokio::spawn(async move {
        while let Some(chunk) = drx.recv().await {
            if chunk.is_empty() {
                break; // server eof 标记（同 egress 保序空包）
            }
            if wi.write_all(&chunk).await.is_err() {
                break;
            }
        }
    });
    // 任一方向结束即拆：否则 client 关后 to_local 永等→不发 Close→server conns 僵尸行。
    tokio::select! {
        _ = &mut from_local => { to_local.abort(); }
        _ = &mut to_local => { from_local.abort(); }
    }
    super::egress::egress_streams().write().await.remove(&sid);
    tx.send_close(sid);
    anyhow::Ok(())
}
