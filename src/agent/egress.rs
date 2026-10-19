//! agent 出网代理 IO：本地监听 + WSS 建流 + 双向泵（解析见 common::egress_parse）。
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, RwLock};
use tokio_tungstenite::tungstenite::Message;

use super::EgressHttp;
/// egress 回包路由表：sid -> 本地连接写通道。
/// 与 Ctx.streams 分离（egress 由 agent 主动发起，session 的 Binary 分发查完 Ctx 再查此表）。
pub(crate) fn egress_streams(
) -> &'static RwLock<std::collections::HashMap<u32, mpsc::UnboundedSender<Vec<u8>>>> {
    static T: std::sync::LazyLock<
        RwLock<std::collections::HashMap<u32, mpsc::UnboundedSender<Vec<u8>>>>,
    > = std::sync::LazyLock::new(|| RwLock::new(std::collections::HashMap::new()));
    &T
}

use super::web::AgentStatus;
use crate::common::proto::ClientMsg;

/// 出站通道持有者：session 建连后注入 out_tx，断开置 None。
/// egress 连接 WSS 断开时 fail-fast（直接 502），重连后自动恢复。
pub(crate) type OutHolder = Arc<RwLock<Option<mpsc::UnboundedSender<Message>>>>;

/// agent egress 本地监听。端口被占只 warn + 状态标红，不影响 WSS 主链。
/// 根因→修法：监听 task 与 session/WSS 主链解耦，bind 失败直接返回，
/// 调用方（run/热重启）只更新 status.egress_err，不 abort 主循环。
pub(crate) async fn serve_egress(bind: String, http: EgressHttp, out: OutHolder, status: Arc<RwLock<AgentStatus>>) {
    // 状态先行：WebUI 立即可见监听目标
    {
        let mut st = status.write().await;
        st.egress_listen = bind.clone();
        st.egress_on = http.enabled;
        st.egress_err = None;
    }
    if !http.enabled {
        return;
    }
    let lis = match TcpListener::bind(&bind).await {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!("egress bind {bind} failed: {e:#}");
            status.write().await.egress_err = Some(format!("bind failed: {e:#}"));
            return;
        }
    };
    tracing::info!("egress http proxy on {bind}");
    loop {
        let Ok((inbound, _)) = lis.accept().await else {
            continue;
        };
        let out = out.clone();
        let status = status.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(inbound, out).await {
                tracing::debug!("egress conn ended: {e:#}");
                let _ = status;
            }
        });
    }
}

async fn handle_conn(
    mut inbound: tokio::net::TcpStream,
    out: OutHolder,
) -> anyhow::Result<()> {
    // 读到完整请求头（上限 64K，防慢连接撑内存）
    let mut buf = vec![];
    let mut tmp = vec![0u8; 8192];
    loop {
        let n = inbound.read(&mut tmp).await?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if buf.len() > 64 * 1024 {
            let _ = inbound
                .write_all(b"HTTP/1.1 431 Header Too Large\r\nconnection: close\r\n\r\n")
                .await;
            return Ok(());
        }
    }
    let Some((target, hlen)) = crate::common::egress_parse::parse_proxy_request(&buf) else {
        let _ = inbound
            .write_all(b"HTTP/1.1 400 Bad Request\r\nconnection: close\r\n\r\n")
            .await;
        return Ok(());
    };
    let holder = out.read().await.clone();
    let Some(tx) = holder else {
        // WSS 未连：fail-fast
        let _ = inbound
            .write_all(b"HTTP/1.1 502 Bad Gateway\r\nconnection: close\r\n\r\n")
            .await;
        return Ok(());
    };
    // sid 取奇数：server 侧 next_sid 只发偶数，避免碰撞。
    static CTR: std::sync::LazyLock<std::sync::atomic::AtomicU32> =
        std::sync::LazyLock::new(|| std::sync::atomic::AtomicU32::new(1));
    let sid = CTR.fetch_add(2, std::sync::atomic::Ordering::Relaxed) | 1;
    let (host, port, connect) = match target {
        crate::common::egress_parse::ProxyTarget::Connect { host, port } => (host, port, true),
        crate::common::egress_parse::ProxyTarget::Forward { host, port, .. } => (host, port, false),
    };
    // 在 Open 之前先把回包通道注册到全局表（server 回包+Close 靠它路由）
    let (dtx, mut drx) = mpsc::unbounded_channel::<Vec<u8>>();
    egress_streams().write().await.insert(sid, dtx);
    let open = ClientMsg::Open {
        stream: sid,
        kind: "egress".into(),
        host,
        port,
    };
    if tx
        .send(Message::Text(serde_json::to_string(&open).unwrap().into()))
        .is_err()
    {
        egress_streams().write().await.remove(&sid);
        let _ = inbound
            .write_all(b"HTTP/1.1 502 Bad Gateway\r\nconnection: close\r\n\r\n")
            .await;
        return Ok(());
    }
    if !connect {
        // Forward：原 head 经 Binary 发给 server（由 server 端泵写给公网目标）
        let head = buf[..hlen].to_vec();
        let _ = tx.send(Message::Binary(crate::common::proto::encode_data(sid, &head).into()));
        // head 之后已读的多余字节（pipeline）也一并转发
        if buf.len() > hlen {
            let _ = tx.send(Message::Binary(
                crate::common::proto::encode_data(sid, &buf[hlen..]).into(),
            ));
        }
    }
    let (mut ri, mut wi) = inbound.into_split();
    // CONNECT：等 server 侧拨通首包（或 Close）再回 200；Forward：server 回包即响应头，直接透传。
    // 为控 scope 首版统一按裸流泵：CONNECT 先回 200（server 拨失败会 Close 通道，泵结束关连接）。
    if connect {
        if wi
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .is_err()
        {
            egress_streams().write().await.remove(&sid);
            return Ok(());
        }
    }
    let tx2 = tx.clone();
    let to_server = tokio::spawn(async move {
        let mut b = vec![0u8; 32 * 1024];
        loop {
            match ri.read(&mut b).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tx2
                        .send(Message::Binary(crate::common::proto::encode_data(sid, &b[..n]).into()))
                        .is_err()
                    {
                        break;
                    }
                }
            }
        }
    });
    let from_server = async {
        loop {
            match drx.recv().await {
                Some(chunk) => {
                    if wi.write_all(&chunk).await.is_err() {
                        break;
                    }
                }
                None => {
                    // drx 关闭 = server 发了 eof 标记后删表（或 session Close 清表），正常收尾。
                    break;
                }
            }
        }
    };
    tokio::select! {
        _ = to_server => {}
        _ = from_server => {}
    }
    egress_streams().write().await.remove(&sid);
    let e = ClientMsg::Close {
        stream: sid,
        reason: "eof".into(),
    };
    let _ = tx.send(Message::Text(serde_json::to_string(&e).unwrap().into()));
    Ok(())
}

