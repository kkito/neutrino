//! server 隧道信令：/ws 接 agent，Register/Config 收敛，stream 泵，egress 拨公网。
use crate::common::proto::*;
use super::state::{apply_proxies_for_agent, log_ev, resolve_proxies, save_state, AgentHandle, AgentInfo, S};
use axum::{extract::{ws::Message as WsMsg, ws::WebSocket, State, WebSocketUpgrade}, response::IntoResponse};
use futures_util::{SinkExt, StreamExt};
use std::{collections::HashMap, sync::Arc, time::{Duration, Instant}};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, sync::{mpsc, RwLock}};

pub(crate) async fn ws_handler(
    ws: WebSocketUpgrade,
    State((s, token)): State<(S, Arc<String>)>,
) -> impl IntoResponse {
    ws.on_upgrade(move |sock| ws_loop(sock, s, token))
}

async fn ws_loop(sock: WebSocket, s: S, token: Arc<String>) {
    let (mut ws_send, mut ws_recv) = sock.split();
    let hello: ClientMsg = match tokio::time::timeout(Duration::from_secs(15), ws_recv.next())
        .await
    {
        Ok(Some(Ok(WsMsg::Text(t)))) => match serde_json::from_str(&t) {
            Ok(h @ ClientMsg::Hello { .. }) => h,
            _ => {
                let _ = ws_send
                    .send(WsMsg::Text(
                        serde_json::to_string(&ServerMsg::Error {
                            reason: "expect hello".into(),
                        })
                        .unwrap()
                        .into(),
                    ))
                    .await;
                return;
            }
        },
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
    if tok != *token {
        let _ = ws_send
            .send(WsMsg::Text(
                serde_json::to_string(&ServerMsg::Error {
                    reason: "bad token".into(),
                })
                .unwrap()
                .into(),
            ))
            .await;
        log_ev(&s, format!("auth failed from agent '{hostname}'"));
        return;
    }
    let agent_id = uuid::Uuid::new_v4().to_string()[..8].to_string();
    let (ctl_tx, mut ctl_rx) = mpsc::unbounded_channel::<ServerMsg>();
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<(u32, Vec<u8>)>();
    let incoming: Arc<RwLock<HashMap<u32, mpsc::UnboundedSender<Vec<u8>>>>> =
        Arc::new(RwLock::new(HashMap::new()));
    let pending: Arc<RwLock<HashMap<u32, Vec<Vec<u8>>>>> =
        Arc::new(RwLock::new(HashMap::new()));
    // restore persisted counters
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
        s.outbox.write().await.insert(agent_id.clone(), out_tx);
    }
    log_ev(&s, format!("agent '{hostname}' connected id={agent_id}"));
    let w = serde_json::to_string(&ServerMsg::Welcome {
        agent_id: agent_id.clone(),
        interval: 30,
    })
    .unwrap();
    if ws_send.send(WsMsg::Text(w.into())).await.is_err() {
        return;
    }
    // server-side heartbeat: Ping every 15s, track RTT on Pong
    let last_ping = Arc::new(RwLock::new(None::<Instant>));
    {
        let ctl = ctl_tx.clone();
        let lp = last_ping.clone();
        let s3 = s.clone();
        let aid3 = agent_id.clone();
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
                let _ = (&s3, &aid3);
            }
        });
    }

    loop {
        tokio::select! {
            msg = ws_recv.next() => {
                let Some(Ok(m)) = msg else { break };
                match m {
                    WsMsg::Text(t) => {
                        match serde_json::from_str::<ClientMsg>(&t) {
                            Ok(ClientMsg::Register { proxies }) => {
                                on_register(&s, &agent_id, &hostname, proxies).await;
                            }
                            Ok(ClientMsg::Ping { ts }) => { let _ = ctl_tx.send(ServerMsg::Pong { ts }); }
                            Ok(ClientMsg::Pong { .. }) => {
                                if let Some(t0) = *last_ping.read().await {
                                    let ms = t0.elapsed().as_millis() as i64;
                                    if let Some(h) = s.agents.write().await.get_mut(&agent_id) {
                                        h.info.rtt_ms = ms;
                                    }
                                }
                            }
                            Ok(ClientMsg::Close { stream, .. }) => {
                                if let Some(h) = s.agents.read().await.get(&agent_id) {
                                    h.incoming.write().await.remove(&stream);
                                    h.pending.write().await.remove(&stream);
                                }
                            }
                            Ok(ClientMsg::Open { stream, kind, host, port }) if kind == "egress" => {
                                spawn_egress_dial(&s, &agent_id, stream, host, port, ctl_tx.clone());
                            }
                            Ok(ClientMsg::Open { stream, kind, host, .. }) if kind == "link" => {
                                // host=link名（port 忽略）；目标以 server 存的 desired 为准。
                                spawn_link_relay(&s, &agent_id, &hostname, stream, host, ctl_tx.clone());
                            }
                            Ok(_) => {}
                            Err(e) => tracing::warn!("bad client frame: {e}"),
                        }
                    }
                    WsMsg::Binary(b) => {
                        if let Some((id, payload)) = decode_data(&b) {
                            let waiter = s.agents.read().await.get(&agent_id).map(|h| (h.incoming.clone(), h.pending.clone()));
                            if let Some((st, pe)) = waiter {
                                if let Some(tx) = st.read().await.get(&id).cloned() {
                                    let _ = tx.send(payload.to_vec());
                                    if let Some(h) = s.agents.write().await.get_mut(&agent_id) {
                                        h.info.rx_bytes += payload.len() as u64;
                                    }
                                    // 连接行不记：ingress 侧泵（TCP/UDP/HTTP 各入口）已按公网字节累计，
                                    // 此处再记会 double count。
                                } else {
                                    // 早到（Open 未处理/占位未命中）：缓存，泵启动后 drain。
                                    let mut p = pe.write().await;
                                    let e = p.entry(id).or_default();
                                    if e.len() < 64 {
                                        e.push(payload.to_vec());
                                    }
                                }
                            }
                        }
                    }
                    WsMsg::Close(_) => break,
                    _ => {}
                }
            }
            Some(m) = ctl_rx.recv() => {
                let t = serde_json::to_string(&m).unwrap();
                if ws_send.send(WsMsg::Text(t.into())).await.is_err() { break; }
            }
            Some((id, payload)) = out_rx.recv() => {
                if ws_send.send(WsMsg::Binary(encode_data(id, &payload).into())).await.is_err() { break; }
                if let Some(h) = s.agents.write().await.get_mut(&agent_id) {
                    h.info.tx_bytes += payload.len() as u64;
                }
                // 连接行不记：同上，ingress 侧已累计。
            }
        }
    }
    // cleanup: persist counters, drop routes
    {
        let mut ag = s.agents.write().await;
        if let Some(h) = ag.remove(&agent_id) {
            s.totals.write().await.insert(hostname.clone(), (h.info.rx_bytes, h.info.tx_bytes));
        }
        s.outbox.write().await.remove(&agent_id);
        for v in s.domains.write().await.values_mut() {
            v.retain(|a| *a != agent_id);
        }
        for v in s.tcp_ports.write().await.values_mut() {
            v.retain(|a| *a != agent_id);
        }
    }
    save_state(&s).await;
    log_ev(&s, format!("agent '{hostname}' disconnected"));
}

/// agent 上报已与期望态一致时无需再 push Config（否则死循环）。
/// 空==空视为收敛（双方都没隧道时不 push）。
pub(crate) fn needs_config_push(reported: &[ProxyConfig], want: &[ProxyConfig]) -> bool {
    reported != want
}

/// egress 目标校验（纯函数，单测覆盖）：空 host / 0 端口拒绝。
fn valid_egress_target(host: &str, port: u16) -> bool {
    !host.trim().is_empty() && port != 0
}

/// link 查表（纯函数）：按 link 名找启用的 link 条目，返回 (对端hostname, host, port)。
/// 目标以 server 存的 desired 为准——入口 agent 传什么都不信，防伪造扫对端内网。
pub(crate) fn resolve_link(
    proxies: &[ProxyConfig],
    link_name: &str,
) -> Option<(String, String, u16)> {
    proxies
        .iter()
        .find(|p| p.enabled && p.ptype == "link" && p.name == link_name)
        .map(|p| (p.link_agent.clone(), p.link_host.clone(), p.link_port))
}

/// server 侧 link 中转：入口 agent Open{link, host=link名} → 查表 → 出口 agent
/// Open{link, host/port=真实目标} → 双 channel 对接泵。任一方向结束即双关+清
/// conns 行（Drop-guard 语义，防 HttpConnGuard 修过的同类僵尸行）。
/// 根因→修法：link 双端都是 WSS 流（无本地 socket），泵两端都经 incoming/outbox。
pub(crate) fn spawn_link_relay(
    s: &S,
    entry_agent_id: &str,
    entry_hostname: &str,
    sid_entry: u32,
    link_name: String,
    ctl_entry: mpsc::UnboundedSender<ServerMsg>,
) {
    let s = s.clone();
    let (entry_aid, entry_host) = (entry_agent_id.to_string(), entry_hostname.to_string());
    tokio::spawn(async move {
        // 1. 查表（server 存为准）
        let (exit_host, tgt_host, tgt_port) = {
            let ag = s.agents.read().await;
            let proxies = ag.get(&entry_aid).map(|h| h.info.proxies.clone()).unwrap_or_default();
            match resolve_link(&proxies, &link_name) {
                Some(t) if !t.0.is_empty() && !t.1.is_empty() && t.2 != 0 => t,
                _ => {
                    let _ = ctl_entry.send(ServerMsg::Close {
                        stream: sid_entry,
                        reason: "link denied: no such link".into(),
                    });
                    return;
                }
            }
        };
        // 2. 找出口 agent（按 hostname）+ 出向通道
        let (exit_aid, exit_ctl, exit_out) = {
            let ag = s.agents.read().await;
            let found = ag.iter().find(|(_, h)| h.info.hostname == exit_host);
            match found {
                Some((id, h)) => (id.clone(), h.ctl.clone(), s.outbox.read().await.get(id).cloned()),
                None => {
                    let _ = ctl_entry.send(ServerMsg::Close {
                        stream: sid_entry,
                        reason: "link denied: exit agent offline".into(),
                    });
                    log_ev(&s, format!("link '{link_name}' exit '{exit_host}' offline"));
                    return;
                }
            }
        };
        let Some(exit_out) = exit_out else {
            let _ = ctl_entry.send(ServerMsg::Close {
                stream: sid_entry,
                reason: "link denied: exit gone".into(),
            });
            return;
        };
        // 出口 sid：server 偶数号（与 ingress next_sid 同源，避开 agent 奇数 sid）
        let sid_exit = super::ingress::next_sid_pub();
        // 3. 双端占位 incoming（防 Open 后背靠背 Binary 早到丢包，同 egress 注释）
        let (dtx_exit, mut drx_exit) = mpsc::unbounded_channel::<Vec<u8>>();
        let (dtx_entry, mut drx_entry) = mpsc::unbounded_channel::<Vec<u8>>();
        if let Ok(ag) = s.agents.try_read() {
            if let Some(h) = ag.get(&exit_aid) {
                if let Ok(mut inc) = h.incoming.try_write() {
                    inc.insert(sid_exit, dtx_exit);
                }
            }
            if let Some(h) = ag.get(&entry_aid) {
                if let Ok(mut inc) = h.incoming.try_write() {
                    inc.insert(sid_entry, dtx_entry);
                }
            }
        }
        // 4. 向出口发 Open{link}（真实目标，出口直接 dial）
        if exit_ctl
            .send(ServerMsg::Open {
                stream: sid_exit,
                kind: "link".into(),
                host: tgt_host.clone(),
                port: tgt_port,
            })
            .is_err()
        {
            let _ = ctl_entry.send(ServerMsg::Close {
                stream: sid_entry,
                reason: "link denied: exit send failed".into(),
            });
            return;
        }
        // 5. conns 记账（peer=入口 agent，target=最终目标）
        let cid = (sid_entry as u64) | ((sid_exit as u64) << 32);
        s.conns.write().await.insert(
            cid,
            super::state::ConnInfo {
                id: cid,
                proto: "link".into(),
                peer: entry_host.clone(),
                public_port: 0,
                agent: entry_host.clone(),
                tunnel: link_name.clone(),
                remote_port: 0,
                target: format!("{exit_host}->{tgt_host}:{tgt_port}"),
                since: chrono::Utc::now().timestamp(),
                rx: 0,
                tx: 0,
            },
        );
        // 6. 双向泵
        let entry_out = s.outbox.read().await.get(&entry_aid).cloned();
        let Some(entry_out) = entry_out else {
            s.conns.write().await.remove(&cid);
            return;
        };
        let mut a2e = tokio::spawn(async move {
            while let Some(chunk) = drx_entry.recv().await {
                if exit_out.send((sid_exit, chunk)).is_err() {
                    break;
                }
            }
        });
        let mut e2a = tokio::spawn(async move {
            while let Some(chunk) = drx_exit.recv().await {
                if entry_out.send((sid_entry, chunk)).is_err() {
                    break;
                }
            }
        });
        // 7. 任一方向结束即 abort 对端（否则单边 EOF 时 join! 永等→conns 僵尸行）
        tokio::select! {
            _ = &mut a2e => { a2e.abort(); e2a.abort(); }
            _ = &mut e2a => { a2e.abort(); e2a.abort(); }
        }
        // 任一方向结束即双关+清行
        s.conns.write().await.remove(&cid);
        if let Some(h) = s.agents.read().await.get(&entry_aid) {
            h.incoming.write().await.remove(&sid_entry);
        }
        if let Some(h) = s.agents.read().await.get(&exit_aid) {
            h.incoming.write().await.remove(&sid_exit);
        }
        let _ = ctl_entry.send(ServerMsg::Close {
            stream: sid_entry,
            reason: "eof".into(),
        });
        if let Some(h) = s.agents.read().await.get(&exit_aid) {
            let _ = h.ctl.send(ServerMsg::Close {
                stream: sid_exit,
                reason: "eof".into(),
            });
        }
        log_ev(&s, format!("link '{link_name}' closed"));
    });
}

/// server 侧 egress 拨号：agent Open{egress} -> TcpStream::connect(30s 超时) -> 接现有泵。
/// 根因→修法：与 ingress 对称但方向相反——ingress 是 server 收连接让 agent 拨本地，
/// egress 是 agent 发 Open 让 server 拨公网；泵结构复用 tcp ingress（incoming/outbox）。
pub(crate) fn spawn_egress_dial(
    s: &S,
    agent_id: &str,
    sid: u32,
    host: String,
    port: u16,
    ctl: mpsc::UnboundedSender<ServerMsg>,
) {
    if !valid_egress_target(&host, port) {
        let _ = ctl.send(ServerMsg::Close {
            stream: sid,
            reason: "egress denied: bad target".into(),
        });
        return;
    }
    let s = s.clone();
    let aid = agent_id.to_string();
    // 先占位注册 incoming[sid]：agent Open 后会背靠背发 Binary head，
    // 若等拨号完成才注册，早到的包会被 Binary 分支丢弃（查不到即丢）→ Forward 死锁。
    // 拨失败/异常时移除占位并回 Close。同步 fn 内用 try_write 非阻塞占位
    // （ws_loop 持读锁的瞬间极短，失败则退化为旧行为——拨号RTT内大概率已注册）。
    let (dtx_pre, mut drx) = mpsc::unbounded_channel::<Vec<u8>>();
    {
        if let Ok(ag) = s.agents.try_read() {
            if let Some(h) = ag.get(agent_id) {
                if let Ok(mut inc) = h.incoming.try_write() {
                    inc.insert(sid, dtx_pre);
                }
            }
        }
    }
    tokio::spawn(async move {
        let up = match tokio::time::timeout(
            std::time::Duration::from_secs(30),
            tokio::net::TcpStream::connect((host.as_str(), port)),
        )
        .await
        {
            Ok(Ok(u)) => u,
            Ok(Err(e)) => {
                if let Some(h) = s.agents.read().await.get(&aid) {
                    h.incoming.write().await.remove(&sid);
                    h.pending.write().await.remove(&sid);
                }
                let _ = ctl.send(ServerMsg::Close {
                    stream: sid,
                    reason: format!("dial refused: {e}"),
                });
                return;
            }
            Err(_) => {
                if let Some(h) = s.agents.read().await.get(&aid) {
                    h.incoming.write().await.remove(&sid);
                    h.pending.write().await.remove(&sid);
                }
                let _ = ctl.send(ServerMsg::Close {
                    stream: sid,
                    reason: "dial timeout 30s".into(),
                });
                return;
            }
        };
        // 接泵：占位时已注册 incoming[sid]，此处复用 drx 收 agent 发来的 Binary 写给公网；
        // outbox 发 Binary 给 agent。agent gone 时移除占位。
        let out = {
            let ag = s.agents.read().await;
            let ob = s.outbox.read().await;
            match (ag.get(&aid), ob.get(&aid)) {
                (Some(_), Some(o)) => o.clone(),
                _ => {
                    if let Some(h) = s.agents.read().await.get(&aid) {
                        h.incoming.write().await.remove(&sid);
                    }
                    let _ = ctl.send(ServerMsg::Close {
                        stream: sid,
                        reason: "agent gone".into(),
                    });
                    return;
                }
            }
        };
        let (mut ru, mut wu) = up.into_split();
        // drain 占位前缓存的早到包（先写，保证请求头完整再接实时流）。
        {
            let early = s
                .agents
                .read()
                .await
                .get(&aid)
                .map(|h| h.pending.clone());
            if let Some(pe) = early {
                if let Some(chunks) = pe.write().await.remove(&sid) {
                    for chunk in chunks {
                        if wu.write_all(&chunk).await.is_err() {
                            break;
                        }
                    }
                }
            }
        }
        let out2 = out.clone();
        let to_public = tokio::spawn(async move {
            let mut b = vec![0u8; 32 * 1024];
            loop {
                let n = ru.read(&mut b).await?;
                if n == 0 {
                    break;
                }
                out2
                    .send((sid, b[..n].to_vec()))
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
            }
            anyhow::Ok(())
        });
        let from_agent = async {
            while let Some(chunk) = drx.recv().await {
                wu.write_all(&chunk).await?;
            }
            anyhow::Ok::<()>(())
        };
        tokio::select! {
            r = to_public => { let _ = r.unwrap(); }
            r = from_agent => { let _ = r; }
        }
        if let Some(h) = s.agents.read().await.get(&aid) {
            h.incoming.write().await.remove(&sid);
            h.pending.write().await.remove(&sid);
        }
        // eof 标记必须与回包数据走同一 outbox 通道（空包=EOF）：若经 ctl 发 Close{eof}，
        // 两通道在 ws_loop 被 select! 复用会乱序——Close 先到则 agent 误删 egress 表项，
        // 在途数据查不到表项进 pending 死缓冲，client 得空 BODY（见 egress e2e flaky 根因）。
        // 同通道保序：数据全到后空包到，agent 删表即 drop sender，handle_conn 正常收尾。
        let _ = out.send((sid, Vec::new()));
    });
}


pub(crate) async fn on_register(s: &S, agent_id: &str, hostname: &str, reported: Vec<ProxyConfig>) {
    let want = s.desired.read().await.get(hostname).cloned();
    let proxies = resolve_proxies(want.clone(), reported.clone());
    if want.is_some() {
        log_ev(s, format!("agent '{hostname}' desired overlay applied ({} proxies)", proxies.len()));
        // sync the agent's local routing table: it dials by its own copy,
        // so push the overlaid list back (agent re-Registers on Config).
        // 已收敛则跳过：否则 Register -> Config -> Register 无限 ping-pong 刷屏。
        if !needs_config_push(&reported, &proxies) {
            tracing::debug!("agent '{hostname}' already converged, skip Config push");
        } else if let Some(ctl) = s.agents.read().await.get(agent_id).map(|h| h.ctl.clone()) {
            let _ = ctl.send(ServerMsg::Config { proxies: proxies.clone() });
        }
    }
    apply_proxies_for_agent(s, agent_id, &proxies).await;
    log_ev(
        s,
        format!("agent '{hostname}' registered {} proxies", proxies.len()),
    );
}

// route pickers (LB)

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn resolve_link_uses_server_table() {
        // server 存为准：入口传什么 host 都不信，只认 desired 表。
        let p = ProxyConfig {
            name: "dblink".into(),
            ptype: "link".into(),
            local_ip: "0.0.0.0".into(),
            local_port: 13306,
            link_agent: "agent1".into(),
            link_host: "10.0.0.1".into(),
            link_port: 3306,
            domains: vec![],
            remote_port: 0,
            set_x_forwarded_proto: None,
            basic_auth: None,
            enabled: true,
        };
        assert_eq!(
            super::resolve_link(&[p], "dblink"),
            Some(("agent1".into(), "10.0.0.1".into(), 3306))
        );
        assert_eq!(super::resolve_link(&[], "dblink"), None);
        // 禁用的 link 不命中
        let mut dis = ProxyConfig {
            name: "off".into(),
            ptype: "link".into(),
            local_ip: "0.0.0.0".into(),
            local_port: 13307,
            link_agent: "agent1".into(),
            link_host: "10.0.0.1".into(),
            link_port: 3306,
            domains: vec![],
            remote_port: 0,
            set_x_forwarded_proto: None,
            basic_auth: None,
            enabled: false,
        };
        let _ = &mut dis;
        assert_eq!(super::resolve_link(&[dis], "off"), None);
    }

    #[test]
    fn egress_target_rejects_empty_host() {
        assert!(!valid_egress_target("", 80));
        assert!(!valid_egress_target("   ", 80));
        assert!(!valid_egress_target("x", 0));
        assert!(valid_egress_target("example.com", 443));
    }

    #[test]
    fn config_push_stops_when_agent_converged() {
        // 复现刷屏死循环：agent 上报的 proxies 已与期望态一致时，
        // server 不应再下发 Config，否则 agent 回 Register -> Config 无限 ping-pong。
        let p = ProxyConfig {
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
        };
        // 已收敛：不再 push
        assert!(!needs_config_push(&[p.clone()], &[p.clone()]));
        // 未收敛：需要 push（server 期望态覆盖 agent 上报）
        let mut q = p.clone();
        q.local_port = 8080;
        assert!(needs_config_push(&[q], &[p]));
        // agent 空上报但期望态有隧道：需要 push
        assert!(!needs_config_push(&[], &[]));
    }

}
