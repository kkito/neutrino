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
use crate::common::proto::{encode_data, ClientMsg};

/// 出站通道持有者：session 建连后注入 out_tx，断开置 None。
/// egress 连接 WSS 断开时 fail-fast（直接 502），重连后自动恢复。
pub(crate) type OutHolder = Arc<RwLock<Option<mpsc::UnboundedSender<Message>>>>;

/// QUIC 出站通道持有者：发的是 control 复用帧（len+JSON 或 len+[sid+payload]）。
/// server 侧 handle_conn 读循环同时接受两种帧，无需区分。
pub(crate) type QuicOutHolder = Arc<RwLock<Option<mpsc::UnboundedSender<Vec<u8>>>>>;

/// kudus 出站通道持有者：持已建连的封包器 [`Pkt`]（内含 key/session/seq），
/// egress Open/data/close 直接封 DATA 帧经写泵发出。
pub(crate) type KudusOutHolder = Arc<RwLock<Option<crate::agent::kudus_session::Pkt>>>;

/// serve 三路：同时持 WSS + QUIC + kudus 三个 out holder，哪个连着用哪个。
/// 根因→修法：egress 监听与主链解耦、热重启不碰主链，双路 holder 只需在 handle 时
/// 选一个 Some 的；transport 切换时旧 holder 被 session 置 None，无残留。
#[derive(Clone)]
pub(crate) struct DualOut {
    pub(crate) ws: OutHolder,
    pub(crate) quic: QuicOutHolder,
    pub(crate) kudus: KudusOutHolder,
}

impl DualOut {
    /// kudus/QUIC 优先（UDP 延迟更低），回退 WSS。
    async fn pick(&self) -> Option<OutMsg> {
        if let Some(k) = self.kudus.read().await.clone() {
            return Some(OutMsg::Kudus(k));
        }
        if let Some(q) = self.quic.read().await.clone() {
            return Some(OutMsg::Quic(q));
        }
        self.ws.read().await.clone().map(OutMsg::Ws)
    }
}

/// 发包统一口：Open 走 JSON 文本语义，data 走二进制语义（QUIC 侧自动套复用帧）。
#[derive(Clone)]
enum OutMsg {
    Ws(mpsc::UnboundedSender<Message>),
    Quic(mpsc::UnboundedSender<Vec<u8>>),
    Kudus(super::kudus_session::Pkt),
}

impl OutMsg {
    fn open(&self, sid: u32, host: String, port: u16) -> anyhow::Result<()> {
        let open = ClientMsg::Open { stream: sid, kind: "egress".into(), host: host.clone(), port };
        let j = serde_json::to_string(&open)?;
        match self {
            OutMsg::Ws(tx) => tx.send(Message::Text(j.into()))?,
            OutMsg::Quic(tx) => tx.send(crate::common::quic::encode_frame(j.as_bytes()))?,
            // kudus：egress Open 是控制语义 —— DATA 帧包 proto JSON。
            OutMsg::Kudus(p) => {
                p.send_ctrl(&ClientMsg::Open { stream: sid, kind: "egress".into(), host, port })?;
            }
        }
        Ok(())
    }
    fn data(&self, sid: u32, chunk: &[u8]) -> anyhow::Result<()> {
        match self {
            OutMsg::Ws(tx) => tx.send(Message::Binary(encode_data(sid, chunk).into()))?,
            OutMsg::Quic(tx) => {
                tx.send(crate::common::quic::encode_frame(&encode_data(sid, chunk)))?
            }
            OutMsg::Kudus(p) => {
                p.send_data_stream(sid, chunk);
            }
        }
        Ok(())
    }
    fn close(&self, sid: u32) {
        if let Ok(j) = serde_json::to_string(&ClientMsg::Close { stream: sid, reason: "eof".into() }) {
            match self {
                OutMsg::Ws(tx) => {
                    let _ = tx.send(Message::Text(j.into()));
                }
                OutMsg::Quic(tx) => {
                    let _ = tx.send(crate::common::quic::encode_frame(j.as_bytes()));
                }
                OutMsg::Kudus(p) => {
                    let _ = p.send_ctrl(&ClientMsg::Close { stream: sid, reason: "eof".into() });
                }
            }
        }
    }
}

/// agent egress 本地监听。端口被占只 warn + 状态标红，不影响 WSS 主链。
/// 根因→修法：监听 task 与 session/WSS 主链解耦，bind 失败直接返回，
/// 调用方（run/热重启）只更新 status.egress_err，不 abort 主循环。
pub(crate) async fn serve_egress(bind: String, http: EgressHttp, out: DualOut, status: Arc<RwLock<AgentStatus>>) {
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
    out: DualOut,
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
    let Some(tx) = out.pick().await else {
        // 双路都断：fail-fast
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
    if tx.open(sid, host, port).is_err() {
        egress_streams().write().await.remove(&sid);
        let _ = inbound
            .write_all(b"HTTP/1.1 502 Bad Gateway\r\nconnection: close\r\n\r\n")
            .await;
        return Ok(());
    }
    if !connect {
        // Forward：原 head 经 Binary 发给 server（由 server 端泵写给公网目标）
        let head = buf[..hlen].to_vec();
        let _ = tx.data(sid, &head);
        // head 之后已读的多余字节（pipeline）也一并转发
        if buf.len() > hlen {
            let _ = tx.data(sid, &buf[hlen..]);
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
    let to_server = {
        let tx = tx.clone();
        tokio::spawn(async move {
            let mut b = vec![0u8; 32 * 1024];
            loop {
                match ri.read(&mut b).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if tx.data(sid, &b[..n]).is_err() {
                            break;
                        }
                    }
                }
            }
        })
    };
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
    tx.close(sid);
    Ok(())
}

