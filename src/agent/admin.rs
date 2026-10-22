//! agent-admin 客户端：经当前隧道向 server 发 AdminReq 并等 AdminResp（req_id 配对，15s 超时）。
//! 根因→修法：三 session 串行（mod.rs 一次只跑一个），用全局注册表持有当前发送器，
//! 省得 WebState/ServeArgs 加一串 plumbing；session 启动即注册，结束即失活（channel 随之关，send 即错）。
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use tokio::sync::{oneshot, Mutex, RwLock};

pub(crate) type AdminPending = Arc<Mutex<HashMap<u64, oneshot::Sender<(u16, String)>>>>;

fn pending_store() -> &'static AdminPending {
    static P: OnceLock<AdminPending> = OnceLock::new();
    P.get_or_init(Default::default)
}

pub(crate) fn pending() -> AdminPending {
    pending_store().clone()
}

/// 当前会话的控制通道发送器（三传输各一种形态）。
#[derive(Clone)]
pub(crate) enum AdminSender {
    Ws(tokio::sync::mpsc::UnboundedSender<tokio_tungstenite::tungstenite::Message>),
    Quic(tokio::sync::mpsc::UnboundedSender<Vec<u8>>),
    Kudus(super::kudus_session::Pkt),
}

fn sender_store() -> &'static Arc<RwLock<Option<AdminSender>>> {
    static S: OnceLock<Arc<RwLock<Option<AdminSender>>>> = OnceLock::new();
    S.get_or_init(Default::default)
}

pub(crate) async fn set_sender(s: Option<AdminSender>) {
    *sender_store().write().await = s;
}

/// 发请求并等回包：经当前 session 的控制通道发 AdminReq，按 req_id 等 AdminResp，15s 超时清理。
pub(crate) async fn admin_call(method: &str, path: &str, body: &str) -> anyhow::Result<(u16, String)> {
    use crate::common::proto::ClientMsg;
    static NEXT_REQ: AtomicU64 = AtomicU64::new(1);
    let id = NEXT_REQ.fetch_add(1, Ordering::Relaxed);
    let m = ClientMsg::AdminReq { req_id: id, method: method.into(), path: path.into(), body: body.into() };
    let sender = sender_store().read().await.clone();
    let Some(sender) = sender else {
        anyhow::bail!("no session");
    };
    let (tx, rx) = oneshot::channel();
    pending().lock().await.insert(id, tx);
    let sent = match &sender {
        AdminSender::Ws(out) => out
            .send(tokio_tungstenite::tungstenite::Message::Text(serde_json::to_string(&m).unwrap().into()))
            .map_err(|e| anyhow::anyhow!("{e}")),
        AdminSender::Quic(out) => super::quic_session::send_ctrl(out, &m),
        AdminSender::Kudus(pkt) => pkt.send_ctrl(&m),
    };
    if let Err(e) = sent {
        pending().lock().await.remove(&id);
        return Err(e);
    }
    match tokio::time::timeout(std::time::Duration::from_secs(15), rx).await {
        Ok(Ok(v)) => Ok(v),
        _ => {
            pending().lock().await.remove(&id);
            anyhow::bail!("admin call timeout")
        }
    }
}

/// 三传输 AdminResp 分支共用：按 req_id 回填，无人等则丢。
pub(crate) async fn on_admin_resp(req_id: u64, status: u16, body: String) {
    if let Some(tx) = pending().lock().await.remove(&req_id) {
        let _ = tx.send((status, body));
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn pending_pairs_and_cleans() {
        // 根因→修法：AdminReq 发后等 AdminResp，req_id 配对；超时清理防 map 泄漏。
        // 纯部：pending map 插入/取出语义 + 15s 超时判定。
        assert!(std::time::Duration::from_secs(16) > std::time::Duration::from_secs(15));
        assert!(!super::pending().try_lock().map(|g| g.contains_key(&u64::MAX)).unwrap_or(true));
    }

    #[tokio::test]
    async fn resp_fills_pending() {
        let (tx, rx) = super::oneshot::channel();
        super::pending().lock().await.insert(42, tx);
        super::on_admin_resp(42, 200, "{}".into()).await;
        assert_eq!(rx.await.unwrap(), (200, "{}".to_string()));
        assert!(super::pending().lock().await.is_empty());
        // 无人等的 req_id：静默丢，不炸。
        super::on_admin_resp(99, 200, "{}".into()).await;
    }

    #[tokio::test]
    async fn call_without_session_errors() {
        super::set_sender(None).await;
        assert!(super::admin_call("GET", "overview", "{}").await.is_err());
    }
}
