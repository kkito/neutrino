//! server QUIC 监听：独立 UDP 端口，自签证书，token 真认证。
//! 与 `tunnel.rs::ws_loop` 语义对齐：首帧 Hello → token 校验 → Welcome，
//! 之后控制循环见本文件 `handle_conn`（Task 3 补全 Register/心跳/泵）。
use crate::common::proto::*;
use crate::common::quic::{decode_frames, encode_frame, CONTROL_MAX};
use super::state::{log_ev, Shared};
use std::sync::Arc;
use std::time::Duration;

type S = Arc<Shared>;

/// 空 token 直接拒绝：防"没配 token 的 agent 蹭上没配 token 的 server"。
pub(crate) fn check_token(got: &str, want: &str) -> bool {
    if got.is_empty() || want.is_empty() {
        return false;
    }
    got == want
}

/// rcgen 现场自签（SAN=neutrino-quic）：返回 (cert_der, pkcs8_der)。
pub fn make_self_signed() -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let ck = rcgen::generate_simple_self_signed(vec!["neutrino-quic".into()])?;
    let cert_der = ck.cert.der().to_vec();
    let key_der = ck.key_pair.serialize_der();
    Ok((cert_der, key_der))
}

/// 证书指纹（sha256 hex 前 16）：运维核对用，启动时打印。
pub fn cert_fingerprint(cert_der: &[u8]) -> String {
    use sha2::Digest;
    let d = sha2::Sha256::digest(cert_der);
    hex16(&d)
}

fn hex16(d: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(16);
    for b in d.iter().take(8) {
        s.push(H[(b >> 4) as usize] as char);
        s.push(H[(b & 0xf) as usize] as char);
    }
    s
}

async fn read_frame(recv: &mut quinn::RecvStream) -> anyhow::Result<Vec<u8>> {
    let mut hdr = [0u8; 4];
    recv.read_exact(&mut hdr).await?;
    let len = u32::from_be_bytes(hdr) as usize;
    if len > CONTROL_MAX {
        anyhow::bail!("control frame too large");
    }
    let mut body = vec![0u8; len];
    recv.read_exact(&mut body).await?;
    Ok(body)
}

async fn handle_conn(s: S, token: Arc<String>, conn: quinn::Connection) {
    // 首个双向 stream 约定为 control（15s 超时）
    let (mut send, mut recv) = match tokio::time::timeout(
        Duration::from_secs(15),
        conn.accept_bi(),
    )
    .await
    {
        Ok(Ok(v)) => v,
        _ => return,
    };
    let body = match tokio::time::timeout(Duration::from_secs(15), read_frame(&mut recv)).await
    {
        Ok(Ok(b)) => b,
        _ => return,
    };
    let hello: ClientMsg = match serde_json::from_slice(&body) {
        Ok(h @ ClientMsg::Hello { .. }) => h,
        _ => return,
    };
    let (hostname, tok) = match hello {
        ClientMsg::Hello { hostname, token, .. } => (hostname, token),
        _ => return,
    };
    if !check_token(&tok, &token) {
        conn.close(401u32.into(), b"bad token");
        log_ev(&s, format!("quic auth failed from agent '{hostname}'"));
        return;
    }
    let w = serde_json::to_string(&ServerMsg::Welcome {
        agent_id: uuid::Uuid::new_v4().to_string()[..8].to_string(),
        interval: 30,
    })
    .unwrap();
    if send.write_all(&encode_frame(w.as_bytes())).await.is_err() {
        return;
    }
    log_ev(&s, format!("quic agent '{hostname}' welcomed"));
    // Task 3 接管：完整控制循环（Register/心跳/隧道泵）。
    let _ = decode_frames(&[]);
    conn.closed().await;
}

/// 绑 UDP + accept 循环（每个连接 spawn handle_conn）。
pub(crate) async fn run_quic(s: S, token: Arc<String>, bind: &str) -> anyhow::Result<()> {
    let (cert_der, key_der) = make_self_signed()?;
    let cert = rustls::pki_types::CertificateDer::from(cert_der.clone());
    let key = rustls::pki_types::PrivateKeyDer::try_from(key_der)
        .map_err(|e| anyhow::anyhow!("bad key: {e}"))?;
    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)?;
    server_crypto.alpn_protocols = vec![b"neutrino/1".to_vec()];
    let server_config =
        quinn::ServerConfig::with_crypto(Arc::new(quinn::crypto::rustls::QuicServerConfig::try_from(
            server_crypto,
        )?));
    let addr: std::net::SocketAddr = bind.parse()?;
    let endpoint = quinn::Endpoint::server(server_config, addr)?;
    tracing::info!(
        "quic listening on {bind} fp={}",
        cert_fingerprint(&cert_der)
    );
    log_ev(&s, format!("quic listening {bind}"));
    loop {
        let Some(incoming) = endpoint.accept().await else {
            break;
        };
        let s2 = s.clone();
        let t2 = token.clone();
        tokio::spawn(async move {
            match incoming.await {
                Ok(conn) => handle_conn(s2, t2, conn).await,
                Err(e) => tracing::debug!("quic incoming failed: {e:#}"),
            }
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_check_rejects_empty_and_mismatch() {
        assert!(check_token("s3cret", "s3cret"));
        assert!(!check_token("wrong", "s3cret"));
        assert!(!check_token("", "s3cret"));
        assert!(!check_token("", ""));
    }

    #[test]
    fn self_signed_cert_roundtrip() {
        let (cert, key) = make_self_signed().unwrap();
        assert!(!cert.is_empty() && !key.is_empty());
        let fp1 = cert_fingerprint(&cert);
        let fp2 = cert_fingerprint(&cert);
        assert_eq!(fp1, fp2);
        assert_eq!(fp1.len(), 16);
    }
}
