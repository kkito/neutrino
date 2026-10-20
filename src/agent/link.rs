//! agent link 入口监听：本地 accept -> WSS Open{link} -> 双向泵。照抄 egress 模式。
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, RwLock};
use tokio_tungstenite::tungstenite::Message;

use super::egress::OutHolder;
use super::web::AgentStatus;
use crate::common::proto::{encode_data, ClientMsg};

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
    // sid 取奇数：server 偶数 sid，避免碰撞（同 egress）。
    let sid = CTR.fetch_add(2, std::sync::atomic::Ordering::Relaxed) | 1;
    let (dtx, mut drx) = mpsc::unbounded_channel::<Vec<u8>>();
    super::egress::egress_streams().write().await.insert(sid, dtx);
    // host=link名（server 以此查表，port 忽略）；目标以 server 存为准。
    tx.send(Message::Text(
        serde_json::to_string(&ClientMsg::Open {
            stream: sid,
            kind: "link".into(),
            host: link_name,
            port: 0,
        })?
        .into(),
    ))?;
    let (mut ri, mut wi) = inbound.into_split();
    let tx2 = tx.clone();
    let mut from_local = tokio::spawn(async move {
        let mut b = vec![0u8; 32 * 1024];
        loop {
            match ri.read(&mut b).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tx2.send(Message::Binary(encode_data(sid, &b[..n]).into())).is_err() {
                        break;
                    }
                }
            }
        }
    });
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
    let _ = tx.send(Message::Text(
        serde_json::to_string(&ClientMsg::Close {
            stream: sid,
            reason: "eof".into(),
        })?
        .into(),
    ));
    anyhow::Ok(())
}
