//! agent link 入口监听：本地 accept -> WSS Open{link} -> 双向泵。照抄 egress 模式。
//! link_udp：同语义的 UDP 版（UdpSocket 收包 → Open{link_udp, host="名|peer"} + Data）。
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, RwLock};

/// link_udp Open host 拼装："link名|peer地址"（server 侧 split_once('|') 拆，见 plan Task 4）。
pub(crate) fn udp_open_host(link_name: &str, peer: &str) -> String {
    format!("{link_name}|{peer}")
}

#[cfg(test)]
mod udp_tests {
    #[test]
    fn link_udp_entry_binds_and_forwards() {
        // 纯函数拼装：首包 Open host 格式 "名|peer"，server 侧可拆。
        assert_eq!(
            super::udp_open_host("bt-udp", "1.2.3.4:5678"),
            "bt-udp|1.2.3.4:5678"
        );
        let (name, peer) = super::udp_open_host("bt-udp", "1.2.3.4:5678")
            .split_once('|')
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .unwrap();
        assert_eq!(name, "bt-udp");
        assert_eq!(peer, "1.2.3.4:5678");
    }
}

use super::egress::OutHolder;
use super::quic_session::QCtx;
use super::kudus_session::KCtx;

// link 监听泄漏 Guard：session 退出时 abort 全部监听，释放端口给下次重连。
// 根因→修法：旧 ctx 随 session 丢弃，AbortHandle 跟着丢，监听成孤儿占端口，
// 重连 bind 必然 Address in use（控制面活、数据面全死）。Guard 持有 ctx 的引用，
// session 退出路径只要创建过它，drop 即全 abort。
pub(crate) struct LinkGuard<'a> {
    tasks: &'a tokio::sync::Mutex<std::collections::HashMap<String, tokio::task::AbortHandle>>,
}

impl<'a> LinkGuard<'a> {
    pub(crate) fn new(
        tasks: &'a tokio::sync::Mutex<std::collections::HashMap<String, tokio::task::AbortHandle>>,
    ) -> Self {
        Self { tasks }
    }
}

impl Drop for LinkGuard<'_> {
    fn drop(&mut self) {
        if let Ok(mut tasks) = self.tasks.try_lock() {
            for (_, h) in tasks.drain() {
                h.abort();
            }
        }
    }
}

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
        // link_udp 走 UDP 入口（UdpSocket），link 走 TCP 入口（TcpListener）。
        let h = if p.ptype == "link_udp" {
            tokio::spawn(serve_link_udp_kudus(p.name.clone(), bind, holder.clone()))
        } else {
            tokio::spawn(serve_link_kudus(p.name.clone(), bind, holder.clone()))
        };
        tasks.insert(p.name.clone(), h.abort_handle());
    }
}

/// link_udp 收包入口（kudus 版）：UdpSocket 收包 → Open{link_udp} + Data。
/// UDP 无连接语义：同 peer 首包建 session（server 侧会话表复用），
/// 后续包经 egress_streams 查表直投。照抄 serve_link_kudus 结构。
async fn serve_link_udp_kudus(
    link_name: String,
    bind: String,
    holder: super::egress::KudusOutHolder,
) {
    let sock = match UdpSocket::bind(&bind).await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            tracing::warn!("link_udp '{link_name}' bind {bind} failed: {e:#}");
            return;
        }
    };
    tracing::info!("link_udp '{link_name}' listen on {bind} (udp)");
    // peer → sid（同 peer 复用 session，UDP 无连接靠表维持有状态）
    let peers: std::sync::Arc<tokio::sync::Mutex<std::collections::HashMap<String, u32>>> =
        std::sync::Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));
    let mut buf = vec![0u8; 2048];
    loop {
        let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
            continue;
        };
        let peer_s = peer.to_string();
        let mut pm = peers.lock().await;
        let sid = match pm.get(&peer_s) {
            Some(s) => *s,
            None => {
                let sid = CTR_KUDUS.fetch_add(2, std::sync::atomic::Ordering::Relaxed) | 1;
                let (dtx, mut drx) = mpsc::unbounded_channel::<Vec<u8>>();
                super::egress::egress_streams().write().await.insert(sid, dtx);
                // host="link名|peer地址"：server 侧查表用 link名，回包路由用 peer。
                // holder 是 Option<Pkt>：读快照后重建 Tx（照抄 serve_link_kudus 的 hout 模式）。
                if let Some(p) = holder.read().await.clone() {
                    let tx = Tx::Kudus(p);
                    tx.send_open_udp(sid, &udp_open_host(&link_name, &peer_s))
                        .unwrap_or(());
                }
                let sock2 = sock.clone();
                tokio::spawn(async move {
                    while let Some(chunk) = drx.recv().await {
                        if chunk.is_empty() {
                            break;
                        }
                        if sock2.send_to(&chunk, peer).await.is_err() {
                            break;
                        }
                    }
                });
                pm.insert(peer_s.clone(), sid);
                tracing::info!("link_udp '{link_name}' session {peer_s} -> sid {sid}");
                sid
            }
        };
        drop(pm);
        // wss down 时丢包（UDP 语义本就可以丢，照抄 ensure_udp_listener：无通道即跳过）。
        if let Some(p) = holder.read().await.clone() {
            p.wait_window().await;
            p.send_data_stream(sid, &buf[..n]);
        }
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
// kudus link 专用 sid 计数器：与 WSS CTR 同奇数序列但基址错开（避免与 egress_streams
// 全局表里其他 kudus 流 sid 碰撞——deliver 按 sid 查表，撞车即错投对方泵导致双端 hang）。
static CTR_KUDUS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0x10000001);

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
        // link_udp 走 UDP 入口，link 走 TCP 入口。
        let h = if p.ptype == "link_udp" {
            tokio::spawn(serve_link_udp(p.name.clone(), bind, out.clone(), status.clone()))
        } else {
            tokio::spawn(serve_link(p.name.clone(), bind, out.clone(), status.clone()))
        };
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

/// link_udp 入口（WSS 版）：UdpSocket 收包 → Open{link_udp, host="名|peer"} + Data。
/// UDP 无连接语义：同 peer 首包建 session（server 侧会话表复用），后续包直投。
pub(crate) async fn serve_link_udp(
    link_name: String,
    bind: String,
    out: OutHolder,
    status: Arc<RwLock<AgentStatus>>,
) {
    let sock = match UdpSocket::bind(&bind).await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            tracing::warn!("link_udp '{link_name}' bind {bind} failed: {e:#}");
            status.write().await.link_err = Some(format!("{link_name} bind failed: {e:#}"));
            return;
        }
    };
    tracing::info!("link_udp '{link_name}' listen on {bind} (udp)");
    let peers: std::sync::Arc<tokio::sync::Mutex<std::collections::HashMap<String, u32>>> =
        std::sync::Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));
    let mut buf = vec![0u8; 2048];
    loop {
        let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
            continue;
        };
        let peer_s = peer.to_string();
        let mut pm = peers.lock().await;
        let sid = match pm.get(&peer_s) {
            Some(s) => *s,
            None => {
                let sid = CTR.fetch_add(2, std::sync::atomic::Ordering::Relaxed) | 1;
                let (dtx, mut drx) = mpsc::unbounded_channel::<Vec<u8>>();
                super::egress::egress_streams().write().await.insert(sid, dtx);
                if let Some(tx) = out.read().await.clone() {
                    let t = Tx::Ws(tx);
                    t.send_open_udp(sid, &udp_open_host(&link_name, &peer_s)).unwrap_or(());
                }
                let sock2 = sock.clone();
                tokio::spawn(async move {
                    while let Some(chunk) = drx.recv().await {
                        if chunk.is_empty() { break; }
                        if sock2.send_to(&chunk, peer).await.is_err() { break; }
                    }
                });
                pm.insert(peer_s.clone(), sid);
                tracing::info!("link_udp '{link_name}' session {peer_s} -> sid {sid}");
                sid
            }
        };
        drop(pm);
        if let Some(tx) = out.read().await.clone() {
            let _ = tx.send(tokio_tungstenite::tungstenite::Message::Binary(
                encode_data(sid, &buf[..n]).into(),
            ));
        }
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
        self.send_open_kind(sid, "link", link_name)
    }

    /// link_udp 版 Open：kind=link_udp，host 已拼好 "名|peer"。
    fn send_open_udp(&self, sid: u32, host: &str) -> anyhow::Result<()> {
        self.send_open_kind(sid, "link_udp", host)
    }

    fn send_open_kind(&self, sid: u32, kind: &str, host: &str) -> anyhow::Result<()> {
        let open = ClientMsg::Open {
            stream: sid,
            kind: kind.to_string(),
            host: host.to_string(),
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
                    kind: kind.to_string(),
                    host: host.to_string(),
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
        let h = if p.ptype == "link_udp" {
            tokio::spawn(serve_link_udp_quic(p.name.clone(), bind, holder.clone()))
        } else {
            tokio::spawn(serve_link_quic(p.name.clone(), bind, holder.clone()))
        };
        tasks.insert(p.name.clone(), h.abort_handle());
    }
}

/// link_udp 入口（QUIC 版）：UdpSocket 收包 → Open{link_udp} + control 复用帧。
async fn serve_link_udp_quic(
    link_name: String,
    bind: String,
    holder: super::egress::QuicOutHolder,
) {
    let sock = match UdpSocket::bind(&bind).await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            tracing::warn!("link_udp '{link_name}' bind {bind} failed: {e:#}");
            return;
        }
    };
    tracing::info!("link_udp '{link_name}' listen on {bind} (udp)");
    let peers: std::sync::Arc<tokio::sync::Mutex<std::collections::HashMap<String, u32>>> =
        std::sync::Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));
    let mut buf = vec![0u8; 2048];
    loop {
        let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
            continue;
        };
        let peer_s = peer.to_string();
        let mut pm = peers.lock().await;
        let sid = match pm.get(&peer_s) {
            Some(s) => *s,
            None => {
                let sid = CTR.fetch_add(2, std::sync::atomic::Ordering::Relaxed) | 1;
                let (dtx, mut drx) = mpsc::unbounded_channel::<Vec<u8>>();
                super::egress::egress_streams().write().await.insert(sid, dtx);
                if let Some(tx) = holder.read().await.clone() {
                    let t = Tx::Quic(tx);
                    t.send_open_udp(sid, &udp_open_host(&link_name, &peer_s)).unwrap_or(());
                }
                let sock2 = sock.clone();
                tokio::spawn(async move {
                    while let Some(chunk) = drx.recv().await {
                        if chunk.is_empty() { break; }
                        if sock2.send_to(&chunk, peer).await.is_err() { break; }
                    }
                });
                pm.insert(peer_s.clone(), sid);
                tracing::info!("link_udp '{link_name}' session {peer_s} -> sid {sid}");
                sid
            }
        };
        drop(pm);
        if let Some(tx) = holder.read().await.clone() {
            let _ = tx.send(encode_frame(&encode_data(sid, &buf[..n])));
        }
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
    // kudus 走独立计数器：link 与 pump_tcp（open_stream 同 egress_streams 全局表）
    // 共享 sid 命名空间，基址错开防撞车错投（已现网踩坑：首流 sid=1 双泵互投 hang）。
    let sid = if matches!(tx, Tx::Kudus(_)) {
        CTR_KUDUS.fetch_add(2, std::sync::atomic::Ordering::Relaxed) | 1
    } else {
        CTR.fetch_add(2, std::sync::atomic::Ordering::Relaxed) | 1
    };
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
                            p2.wait_window().await;
                            p2.send_data_stream(sid, &b[..n]);
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


#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::proto::ProxyConfig;

    fn test_proxy(name: &str, port: u16) -> ProxyConfig {
        ProxyConfig {
            name: name.into(),
            ptype: "link".into(),
            local_ip: "127.0.0.1".into(),
            local_port: port,
            domains: vec![],
            remote_port: 0,
            set_x_forwarded_proto: None,
            basic_auth: None,
            enabled: true,
            link_agent: "other".into(),
            link_host: "127.0.0.1".into(),
            link_port: 22,
            rate_limit: None,
        }
    }

    /// RED: link 任务表在 session 退出时必须被清空释放，否则重连 bind 必然 Address in use。
    /// 现场 12:28:47 welcomed 后 9 条全 bind failed：控制面活、数据面全死。
    #[tokio::test]
    async fn link_guard_abort_releases_tasks_on_session_exit() {
        let holder: super::super::egress::KudusOutHolder =
            std::sync::Arc::new(tokio::sync::RwLock::new(None));
        let port = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let proxies = vec![test_proxy("git", port)];
        let ctx = super::super::kudus_session::KCtx {
            proxies: tokio::sync::RwLock::new(vec![]),
            link_tasks: tokio::sync::Mutex::new(std::collections::HashMap::new()),
            streams: tokio::sync::RwLock::new(std::collections::HashMap::new()),
            pending: tokio::sync::RwLock::new(std::collections::HashMap::new()),
            udp_pool: std::sync::Arc::new(tokio::sync::Mutex::new(
                crate::agent::udp_pool::UdpPool::new(crate::agent::udp_pool::PoolKind::Udp),
            )),
            link_udp_pool: std::sync::Arc::new(tokio::sync::Mutex::new(
                crate::agent::udp_pool::UdpPool::new(crate::agent::udp_pool::PoolKind::LinkUdp),
            )),
        };
        // 第一个 session 建监听
        sync_link_listeners_kudus(&ctx, &proxies, "workmac", &holder).await;
        assert_eq!(ctx.link_tasks.lock().await.len(), 1);
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(tokio::net::TcpStream::connect(format!("127.0.0.1:{port}")).await.is_ok());
        // session 退出路径：Guard drop 必须 abort 监听释放端口
        {
            let _guard = LinkGuard::new(&ctx.link_tasks);
            // guard 存活时任务还在
            assert_eq!(ctx.link_tasks.lock().await.len(), 1);
        } // guard drop
        assert_eq!(ctx.link_tasks.lock().await.len(), 0);
        // 给 OS 一点时间回收端口，然后重连能重新 bind
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        sync_link_listeners_kudus(&ctx, &proxies, "workmac", &holder).await;
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert_eq!(ctx.link_tasks.lock().await.len(), 1);
        assert!(
            tokio::net::TcpStream::connect(format!("127.0.0.1:{port}")).await.is_ok(),
            "reconnect must re-bind the link port"
        );
    }
}
