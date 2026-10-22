//! server QUIC 监听：独立 UDP 端口，自签证书，token 真认证。
//! 与 `tunnel.rs::ws_loop` 语义对齐：首帧 Hello → token 校验 → Welcome →
//! Register/Config 收敛 → 心跳 → 隧道泵。控制帧全部经 control stream 的
//! length-prefixed JSON；数据走每隧道一条 QUIC 双向 stream。
use crate::common::proto::*;
use crate::common::quic::{decode_dgram, encode_dgram, encode_frame, CONTROL_MAX};
use super::state::{log_ev, save_state, AgentHandle, AgentInfo, Shared};
use crate::server::tunnel::{on_register, spawn_egress_dial, spawn_link_relay, spawn_link_udp_relay};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock};

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
    let (mut ctl_send, mut ctl_recv) = match tokio::time::timeout(
        Duration::from_secs(15),
        conn.accept_bi(),
    )
    .await
    {
        Ok(Ok(v)) => v,
        _ => return,
    };
    let body =
        match tokio::time::timeout(Duration::from_secs(15), read_frame(&mut ctl_recv)).await {
            Ok(Ok(b)) => b,
            _ => return,
        };
    let hello: ClientMsg = match serde_json::from_slice(&body) {
        Ok(h @ ClientMsg::Hello { .. }) => h,
        _ => return,
    };
    let (hostname, version, tok) = match hello {
        ClientMsg::Hello {
            hostname,
            version,
            token,
        } => (hostname, version, token),
        _ => return,
    };
    if !check_token(&tok, &token) {
        conn.close(401u32.into(), b"bad token");
        log_ev(&s, format!("quic auth failed from agent '{hostname}'"));
        return;
    }
    // 注册：与 ws_loop 同一套 agents/outbox/incoming/pending 表，
    // WebUI/conns/traffic 按 agent_id 找，QUIC agent 天然可见。
    let agent_id = uuid::Uuid::new_v4().to_string()[..8].to_string();
    let (ctl_tx, mut ctl_rx) = mpsc::unbounded_channel::<ServerMsg>();
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<(u32, Vec<u8>, bool)>();
    let incoming: Arc<RwLock<HashMap<u32, mpsc::UnboundedSender<Vec<u8>>>>> =
        Arc::new(RwLock::new(HashMap::new()));
    let pending: Arc<RwLock<HashMap<u32, Vec<Vec<u8>>>>> =
        Arc::new(RwLock::new(HashMap::new()));
    let (prx, ptx) = s.totals.read().await.get(&hostname).cloned().unwrap_or((0, 0));
    {
        s.agents.write().await.insert(
            agent_id.clone(),
            AgentHandle {
                info: AgentInfo {
                    agent_id: agent_id.clone(),
                    hostname: hostname.clone(),
                    version,
                    online_secs: 0,
                    rtt_ms: -1,
                    rx_bytes: prx,
                    tx_bytes: ptx,
                    proxies: vec![],
                },
                connected_at: chrono::Utc::now(),
                ctl: ctl_tx.clone(),
                incoming: incoming.clone(),
                pending: pending.clone(),
            },
        );
        // outbox 沿用 (sid, payload)：QUIC 数据 stream 内 UDP 包已套 dgram 帧，
        // 此处只做跨任务搬运，第三元组恒 false（占位以对齐类型，见下泵）。
        let (plain_tx, plain_rx) = mpsc::unbounded_channel::<(u32, Vec<u8>)>();
        s.outbox.write().await.insert(agent_id.clone(), plain_tx);
        let s3 = s.clone();
        let aid3 = agent_id.clone();
        tokio::spawn(async move {
            let mut plain_rx = plain_rx;
            while let Some((sid, chunk)) = plain_rx.recv().await {
                let _ = out_tx.send((sid, chunk, false));
            }
            let _ = (&s3, &aid3);
        });
    }
    log_ev(&s, format!("quic agent '{hostname}' connected id={agent_id}"));
    let w = serde_json::to_string(&ServerMsg::Welcome {
        agent_id: agent_id.clone(),
        interval: 30,
    })
    .unwrap();
    if ctl_send.write_all(&encode_frame(w.as_bytes())).await.is_err() {
        cleanup(&s, &agent_id, &hostname).await;
        return;
    }
    // server 心跳：每 15s Ping，Pong 回来算 RTT（与 WSS 版同周期）。
    let last_ping = Arc::new(RwLock::new(None::<Instant>));
    {
        let ctl = ctl_tx.clone();
        let lp = last_ping.clone();
        tokio::spawn(async move {
            let mut iv = tokio::time::interval(Duration::from_secs(15));
            loop {
                iv.tick().await;
                *lp.write().await = Some(Instant::now());
                if ctl
                    .send(ServerMsg::Ping {
                        ts: chrono::Utc::now().timestamp(),
                    })
                    .is_err()
                {
                    break;
                }
            }
        });
    }
    // 数据 stream 泵：每个隧道一条 QUIC 双向 stream，首帧 Open，之后纯字节。
    // UDP 访客包在 stream 内再套 dgram 帧保边界（见 design §3）。
    let conn2 = conn.clone();
    let pump_data = async {
        loop {
            let (ds, mut dr) = conn2.accept_bi().await?;
            let s = s.clone();
            let agent_id = agent_id.clone();
            let ctl_tx = ctl_tx.clone();
            tokio::spawn(async move {
                // 首帧 Open（control 编码复用：len+JSON）
                let open_body = match read_frame(&mut dr).await {
                    Ok(b) => b,
                    Err(_) => return,
                };
                let (sid, kind, host, port) = match serde_json::from_slice::<ClientMsg>(&open_body) {
                    Ok(ClientMsg::Open { stream, kind, host, port }) => (stream, kind, host, port),
                    _ => return,
                };
                if kind == "egress" {
                    spawn_egress_dial(&s, &agent_id, sid, host, port, ctl_tx);
                    drain_stream_into_incoming(&s, &agent_id, sid, dr, ds).await;
                    return;
                }
                if kind == "link_udp" {
                    let hostname = s
                        .agents
                        .read()
                        .await
                        .get(&agent_id)
                        .map(|h| h.info.hostname.clone())
                        .unwrap_or_default();
                    let (name, peer) = host.split_once('|').map(|(a, b)| (a.to_string(), b.to_string()))
                        .unwrap_or((host.clone(), String::new()));
                    spawn_link_udp_relay(&s, &agent_id, &hostname, sid, peer, name, ctl_tx);
                    drain_stream_into_incoming(&s, &agent_id, sid, dr, ds).await;
                    return;
                }
                if kind == "link" {
                    let hostname = s
                        .agents
                        .read()
                        .await
                        .get(&agent_id)
                        .map(|h| h.info.hostname.clone())
                        .unwrap_or_default();
                    spawn_link_relay(&s, &agent_id, &hostname, sid, host, ctl_tx);
                    drain_stream_into_incoming(&s, &agent_id, sid, dr, ds).await;
                    return;
                }
                // 普通隧道（http/tcp/udp agent 发起的场景极少，主要走收到的 Open；
                // 此处统一按 incoming 注册，ingress/outbox 侧泵与 WSS 一致）。
                let _ = (&kind, &host, &port);
                drain_stream_into_incoming(&s, &agent_id, sid, dr, ds).await;
            });
        }
        #[allow(unreachable_code)]
        anyhow::Ok::<()>(())
    };
    // 写泵：ctl（ServerMsg）与 out（数据）都经 control stream 发，
    // 数据帧复用 [stream:u32 BE][payload] 二进制编码（与 WSS Binary 同形），
    // UDP 包先套 dgram 帧再进 payload（对端按 decode_dgram 拆）。
    let write_pump = async {
        loop {
            tokio::select! {
                Some(m) = ctl_rx.recv() => {
                    let t = serde_json::to_string(&m).unwrap();
                    let is_close_stream = matches!(m, ServerMsg::Close { .. });
                    if ctl_send.write_all(&encode_frame(t.as_bytes())).await.is_err() { break; }
                    let _ = is_close_stream;
                }
                Some((id, payload, _)) = out_rx.recv() => {
                    let b = encode_data(id, &payload);
                    // 每条隧道数据走独立 stream：sid 复用 QUIC stream 太重，
                    // 此处沿用 control 复用帧（agent 侧按 sid 分发），队头影响限于同 agent。
                    if ctl_send.write_all(&encode_frame(&b)).await.is_err() { break; }
                    if let Some(h) = s.agents.write().await.get_mut(&agent_id) {
                        h.info.tx_bytes += payload.len() as u64;
                    }
                }
                else => break,
            }
        }
    };
    // 控制读循环：control stream 上只走 ClientMsg（agent 发来的）。
    let read_ctrl = async {
        loop {
            let body = read_frame(&mut ctl_recv).await?;
            // 先试 JSON 控制帧，再试二进制数据帧（agent 数据泵经 control 复用发回）。
            if let Ok(cm) = serde_json::from_slice::<ClientMsg>(&body) {
                match cm {
                    ClientMsg::Register { proxies } => {
                        on_register(&s, &agent_id, &hostname, proxies).await;
                    }
                    ClientMsg::Ping { ts } => {
                        let _ = ctl_tx.send(ServerMsg::Pong { ts });
                    }
                    ClientMsg::AdminReq { req_id, method, path, body } => {
                        let (st, rb) = crate::server::api::dispatch_admin(&s, &hostname, &method, &path, &body).await;
                        let _ = ctl_tx.send(ServerMsg::AdminResp { req_id, status: st, body: rb });
                    }
                    ClientMsg::Pong { .. } => {
                        if let Some(t0) = *last_ping.read().await {
                            let ms = t0.elapsed().as_millis() as i64;
                            if let Some(h) = s.agents.write().await.get_mut(&agent_id) {
                                h.info.rtt_ms = ms;
                            }
                        }
                    }
                    ClientMsg::Close { stream, .. } => {
                        if let Some(h) = s.agents.read().await.get(&agent_id) {
                            h.incoming.write().await.remove(&stream);
                            h.pending.write().await.remove(&stream);
                        }
                    }
                    ClientMsg::Open { stream, kind, host, port } if kind == "egress" => {
                        spawn_egress_dial(&s, &agent_id, stream, host, port, ctl_tx.clone());
                    }
                    ClientMsg::Open { stream, kind, host, .. } if kind == "link" => {
                        spawn_link_relay(&s, &agent_id, &hostname, stream, host, ctl_tx.clone());
                    }
                    ClientMsg::Open { stream, kind, host, .. } if kind == "link_udp" => {
                        let (name, peer) = host.split_once('|').map(|(a, b)| (a.to_string(), b.to_string()))
                            .unwrap_or((host.clone(), String::new()));
                        spawn_link_udp_relay(&s, &agent_id, &hostname, stream, peer, name, ctl_tx.clone());
                    }
                    _ => {}
                }
                continue;
            }
            if let Some((id, payload)) = decode_data(&body) {
                // UDP 包带 dgram 内帧：拆出每个 datagram 依次投递。
                let mut off = 0;
                let mut delivered = false;
                while let Some((dg, used)) = decode_dgram(&payload[off..]) {
                    off += used;
                    delivered = true;
                    deliver(&s, &agent_id, id, dg).await;
                }
                if !delivered {
                    deliver(&s, &agent_id, id, payload).await;
                }
            }
        }
        #[allow(unreachable_code)]
        anyhow::Ok::<()>(())
    };
    let _ = tokio::join!(
        async { let _ = pump_data.await; },
        async { write_pump.await; },
        async { let _ = read_ctrl.await; },
    );
    cleanup(&s, &agent_id, &hostname).await;
    log_ev(&s, format!("quic agent '{hostname}' disconnected"));
}

/// UDP 访客包下发：payload 先套 dgram 帧再进复用帧（agent 拆边界用）。
#[allow(dead_code)]
fn udp_out(id: u32, payload: &[u8]) -> Vec<u8> {
    encode_frame(&encode_data(id, &encode_dgram(payload)))
}

/// agent 发来的数据投递到 incoming，附带 rx 记账（与 WSS Binary 分支同语义）。
async fn deliver(s: &S, agent_id: &str, id: u32, payload: &[u8]) {
    let waiter = s
        .agents
        .read()
        .await
        .get(agent_id)
        .map(|h| (h.incoming.clone(), h.pending.clone()));
    if let Some((st, pe)) = waiter {
        if let Some(tx) = st.read().await.get(&id).cloned() {
            let _ = tx.send(payload.to_vec());
            if let Some(h) = s.agents.write().await.get_mut(agent_id) {
                h.info.rx_bytes += payload.len() as u64;
            }
        } else {
            let mut p = pe.write().await;
            let e = p.entry(id).or_default();
            if e.len() < 64 {
                e.push(payload.to_vec());
            }
        }
    }
}

/// agent 开的出向数据 stream：字节流进 incoming，写端开着即可（读到 FIN 即收尾）。
async fn drain_stream_into_incoming(
    s: &S,
    agent_id: &str,
    sid: u32,
    mut dr: quinn::RecvStream,
    _ds: quinn::SendStream,
) {
    let mut b = vec![0u8; 32 * 1024];
    loop {
        match dr.read(&mut b).await {
            Ok(Some(n)) if n > 0 => {
                deliver(s, agent_id, sid, &b[..n]).await;
            }
            _ => break,
        }
    }
}

/// 下线清理：与 ws_loop 尾部一致（计数落盘、路由摘除）。
async fn cleanup(s: &S, agent_id: &str, hostname: &str) {
    {
        let mut ag = s.agents.write().await;
        if let Some(h) = ag.remove(agent_id) {
            s.totals.write().await.insert(hostname.to_string(), (h.info.rx_bytes, h.info.tx_bytes));
        }
        s.outbox.write().await.remove(agent_id);
        for v in s.domains.write().await.values_mut() {
            v.retain(|a| *a != agent_id);
        }
        for v in s.tcp_ports.write().await.values_mut() {
            v.retain(|a| *a != agent_id);
        }
    }
    save_state(s).await;
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
    use super::{cert_fingerprint, check_token, make_self_signed};

    #[test]
    fn token_check_rejects_empty_and_mismatch() {
        assert!(check_token("s3cret", "s3cret"));
        assert!(!check_token("wrong", "s3cret"));
        assert!(!check_token("", "s3cret"));
        assert!(!check_token("", ""));
    }

    #[test]
    fn quic_register_converges_without_extra_push() {
        // RED 证明见 Task 5 e2e：Task-2 的 server 对 Register 无响应，路由表空。
        // 此处锁定收敛判定函数（与 WSS 共用，QUIC 不另起语义）。
        let proxies = vec![crate::common::proto::ProxyConfig {
            name: "web".into(),
            ptype: "http".into(),
            local_ip: "127.0.0.1".into(),
            local_port: 80,
            domains: vec!["a.test".into()],
            remote_port: 0,
            set_x_forwarded_proto: None,
            basic_auth: None,
            enabled: true,
            link_agent: String::new(),
            link_host: String::new(),
            link_port: 0,
            rate_limit: None,
        }];
        assert!(crate::server::tunnel::needs_config_push(&[], &proxies));
        assert!(!crate::server::tunnel::needs_config_push(&proxies, &proxies));
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
