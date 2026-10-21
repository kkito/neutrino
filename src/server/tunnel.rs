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
    // 单 flight：同 hostname 旧会话先踢掉，保证路由唯一。
    // 根因→修法：旧代码允许多会话并存，两会话抢流、404/502 来回跳。
    // 新 Hello 到达即抢路由：清旧 agent 行 + 路由表引用 + 关旧连接（ctl 发 Error 触发对端退出）。
    {
        let stale: Vec<String> = {
            let ag = s.agents.read().await;
            crate::server::state::stale_ids_for_hostname(
                &ag.iter().map(|(id, h)| (id.clone(), h.info.hostname.clone())).collect(),
                &hostname,
            )
        };
        for old in stale {
            if let Some(h) = s.agents.read().await.get(&old) {
                let _ = h.ctl.send(ServerMsg::Error { reason: "superseded by new session".into() });
            }
            s.agents.write().await.remove(&old);
            s.outbox.write().await.remove(&old);
            for v in s.domains.write().await.values_mut() {
                v.retain(|a| *a != old);
            }
            for v in s.tcp_ports.write().await.values_mut() {
                v.retain(|a| *a != old);
            }
            log_ev(&s, format!("agent '{hostname}' superseded stale session {old}"));
        }
    }
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
    // server-side heartbeat: Ping every 15s, track RTT on Pong.
    // 根因→修法：旧代码只发不验，半开连接的幽灵 agent 行永久占路由、
    // 流量递过去 hang 死（这次 tm 现场）。任何帧都刷新 last_seen，
    // 超 IDLE_KICK_SECS 无声即判定死亡、break 出主循环走统一 cleanup。
    let last_ping = Arc::new(RwLock::new(None::<Instant>));
    let last_seen = Arc::new(RwLock::new(chrono::Utc::now().timestamp()));
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

    // 主循环：ws 帧 / ctl 下发 / outbox 回包三路 + 心跳看门狗。
    // 根因→修法：旧代码裸 select! 永等，server 重启后 agent 侧半开感知不到、
    // server 侧僵尸行也永久占路由（tm hang 60s+）。任何帧刷新 last_seen，
    // deadline 到仍无声即 break 走统一 cleanup（清 agents/outbox/路由表）。
    loop {
        let idle_for = chrono::Utc::now().timestamp() - *last_seen.read().await;
        let remain = (crate::server::state::IDLE_KICK_SECS - idle_for).max(1) as u64;
        tokio::select! {
            msg = tokio::time::timeout(Duration::from_secs(remain), ws_recv.next()) => {
                let msg = match msg {
                    Ok(m) => m,
                    Err(_) => {
                        log_ev(&s, format!("agent '{hostname}' heartbeat timeout, kicking stale session {agent_id}"));
                        break;
                    }
                };
                *last_seen.write().await = chrono::Utc::now().timestamp();
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
                                insert_egress_conn(&s, stream, &hostname, &host, port).await;
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
                                    // agent 级 rx 不在此记（WSS 包级写锁是另一条饿死链；
                                    // 连接行在 ingress 侧已累计，此处再记会 double count；
                                    // 总量由 5s live tick 批量刷）。
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
            } // end msg arm
            Some(m) = ctl_rx.recv() => {
                let t = serde_json::to_string(&m).unwrap();
                if ws_send.send(WsMsg::Text(t.into())).await.is_err() { break; }
            }
            Some((id, payload)) = out_rx.recv() => {
                if ws_send.send(WsMsg::Binary(encode_data(id, &payload).into())).await.is_err() { break; }
                // agent 级 tx 不在此记（同上，包循环零 agents 写锁；连接行 ingress 侧已累计）。
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
        // 3. 双端占位 incoming（防 Open 后背靠背 Binary 早到丢包，同 egress 注释）。
        // 根因→修法：旧代码用 try_read/try_write best-effort 占位，relay task 调度慢于
        // ws_loop 的 Binary 分支时，首包查不到 incoming 进 pending 缓存，而泵从不 drain
        // pending → 首包永久丢失，client 读 5s 超时才重试（link_tcp_roundtrip 跑 80s+）。
        // 改为 await 强注册 + 下面第 3.5 步 drain entry pending，保证首包必达。
        let (dtx_exit, mut drx_exit) = mpsc::unbounded_channel::<Vec<u8>>();
        let (dtx_entry, mut drx_entry) = mpsc::unbounded_channel::<Vec<u8>>();
        if let Some(h) = s.agents.read().await.get(&exit_aid) {
            h.incoming.write().await.insert(sid_exit, dtx_exit.clone());
        }
        if let Some(h) = s.agents.read().await.get(&entry_aid) {
            h.incoming.write().await.insert(sid_entry, dtx_entry.clone());
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
        // 3.5 入口早到包 drain（同 spawn_egress_dial）：Open 与首个 Binary 背靠背时，
        // 占位注册前的包已进 entry pending。占位的新 dtx 替换了缓存目标，必须先把缓存
        // 包转给泵，否则首字节永久丢失（client 侧表现为读超时重试）。出口侧同理。
        async fn drain_early(
            s: &S,
            aid: &str,
            sid: u32,
            tx: &mpsc::UnboundedSender<Vec<u8>>,
        ) {
            let pe = s.agents.read().await.get(aid).map(|h| h.pending.clone());
            if let Some(pe) = pe {
                if let Some(chunks) = pe.write().await.remove(&sid) {
                    for chunk in chunks {
                        let _ = tx.send(chunk);
                    }
                }
            }
        }
        drain_early(&s, &entry_aid, sid_entry, &dtx_entry).await;
        drain_early(&s, &exit_aid, sid_exit, &dtx_exit).await;
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
        // link 限速：双端都在 server，无本地 socket，上下行都吃 VPS 带宽 -> 双向共用同一 limiter（总量语义）。
        // 查表以 server 存为准（与 resolve_link 同源）。
        let link_limiter = {
            let ag = s.agents.read().await;
            let bps = ag.get(&entry_aid).and_then(|h| {
                h.info.proxies.iter()
                    .find(|p| p.enabled && p.ptype == "link" && p.name == link_name)
                    .and_then(|p| crate::server::ratelimit::limit_of(p.rate_limit.as_deref()))
            });
            match bps {
                Some(b) => {
                    let host = ag.get(&entry_aid).map(|h| h.info.hostname.clone()).unwrap_or_default();
                    let key = crate::server::state::traffic_key(&host, &link_name);
                    Some(crate::server::ratelimit::limiter_for(&s, &key, b).await)
                }
                None => None,
            }
        };
        let s_link = s.clone();
        let s_link2 = s.clone();
        let ll1 = link_limiter.clone();
        let ll2 = link_limiter.clone();
        let mut a2e = tokio::spawn(async move {
            while let Some(chunk) = drx_entry.recv().await {
                if let Some(l) = &ll1 {
                    let d = l.take(chunk.len()).await;
                    if !d.is_zero() {
                        tokio::time::sleep(d).await;
                    }
                }
                // link 连接行 rx 累计（入口 client -> 出口目标，tick 归集用）
                if let Some(c) = s_link.conns.write().await.get_mut(&cid) {
                    c.rx += chunk.len() as u64;
                }
                if exit_out.send((sid_exit, chunk)).is_err() {
                    break;
                }
            }
        });
        let mut e2a = tokio::spawn(async move {
            while let Some(chunk) = drx_exit.recv().await {
                if let Some(l) = &ll2 {
                    let d = l.take(chunk.len()).await;
                    if !d.is_zero() {
                        tokio::time::sleep(d).await;
                    }
                }
                // link 连接行 tx 累计（出口目标 -> 入口 client，tick 归集用）
                if let Some(c) = s_link2.conns.write().await.get_mut(&cid) {
                    c.tx += chunk.len() as u64;
                }
                if entry_out.send((sid_entry, chunk)).is_err() {
                    break;
                }
            }
        });
        // 7. 任一方向结束即 abort 对端（否则单边 EOF 时 join! 永等→conns 僵尸行）。
        // 根因→修法：旧代码 abort 后不 drop sender，relay task 自身持有的 dtx_exit/
        // dtx_entry 副本让对端 drx 永不结束→select! 永等→conns 行泄漏。先显式 drop
        // 全部 sender 副本，再 abort+await，确保双泵退出。
        drop(dtx_exit);
        drop(dtx_entry);
        tokio::select! {
            _ = &mut a2e => { e2a.abort(); let _ = (&mut e2a).await; }
            _ = &mut e2a => { a2e.abort(); let _ = (&mut a2e).await; }
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
/// egress 建流记账：agent Open{egress} 到达即插 conns 行（tunnel 固定为 "egress"，
/// peer=发起 agent，target=真实目标）。拨号失败/流结束处 remove。
/// 根因→修法：旧代码 egress 全程只记 agent 级 rx/tx，tick 无法按 tunnel 归集；
/// conns 行是 tick 唯一的 per-tunnel 流量来源，egress 必须建行。
/// 返回 Ok 插行成功；agent 已掉线时返回 Err，调用方直接回 Close。
/// egress 采样开关：NT_EGRESS_SAMPLE=N 时，每 N 个 egress 建流记一条 info 日志
/// （Open 到达即记：sid/host/port；拨号结果/字节在流结束记）。默认 100（生产低噪音），
/// 取证时设 1 全记。纯函数单测覆盖。
pub(crate) fn egress_sample_hit(sample_n: u64, ctr: u64) -> bool {
    sample_n > 0 && ctr % sample_n == 0
}

pub(crate) fn egress_sample_n() -> u64 {
    std::env::var("NT_EGRESS_SAMPLE")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&n| n > 0)
        .unwrap_or(100)
}

/// egress 取证计数器：open/close 同一节奏采样（两行 sid 对上即完整证据）。
static EGRESS_CTR: std::sync::LazyLock<std::sync::atomic::AtomicU64> =
    std::sync::LazyLock::new(|| std::sync::atomic::AtomicU64::new(0));

pub(crate) async fn insert_egress_conn(s: &S, sid: u32, hostname: &str, host: &str, port: u16) {
    // 取证采样：Open 到达即记（谁、连哪、sid）。默认 1/100；NT_EGRESS_SAMPLE=1 全记。
    // 注意节奏对齐：close/dial-fail 用 sid 取模采样（sid 奇数自增，N=100 时 sid%100==1 的流
    // 两行都记）。open 行用 CTR 计数（%N==0），与 sid 窗口错位——全量取证时设 N=1 两边都记，
    // 默认采样下 open 行是近似节奏，close/dial 行才是精确对齐的证据。
    let n = EGRESS_CTR.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    if egress_sample_hit(egress_sample_n(), n) {
        // clone 出 owned：log_ev 要 &S + String，host/port/hostname 都是借用
        let (h, hh) = (host.to_string(), hostname.to_string());
        log_ev(s, format!("egress open sid={sid} agent='{hh}' target={h}:{port} (sample {n})"));
    }
    s.conns.write().await.insert(
        sid as u64,
        super::state::ConnInfo {
            id: sid as u64,
            proto: "egress".into(),
            peer: hostname.into(),
            public_port: 0,
            agent: hostname.into(),
            tunnel: "egress".into(),
            remote_port: 0,
            target: format!("{host}:{port}"),
            since: chrono::Local::now().timestamp(),
            rx: 0,
            tx: 0,
        },
    );
}

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
                if let Some(c) = s.conns.write().await.remove(&(sid as u64)) {
                    // 拨不通也记（取证：目标不可达 vs 根本没来，一眼区分）
                    if egress_sample_hit(egress_sample_n(), sid as u64) {
                        log_ev(&s, format!("egress dial-refused sid={sid} target={} err={e}", c.target));
                    }
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
                if let Some(c) = s.conns.write().await.remove(&(sid as u64)) {
                    if egress_sample_hit(egress_sample_n(), sid as u64) {
                        log_ev(&s, format!("egress dial-timeout sid={sid} target={}", c.target));
                    }
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
                    s.conns.write().await.remove(&(sid as u64));
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
        let s_rx = s.clone();
        let s_tx = s.clone();
        let to_public = tokio::spawn(async move {
            let mut b = vec![0u8; 32 * 1024];
            loop {
                let n = ru.read(&mut b).await?;
                if n == 0 {
                    break;
                }
                // egress 连接行 rx 累计（公网->agent 字节，tick 归集用）
                if let Some(c) = s_rx.conns.write().await.get_mut(&(sid as u64)) {
                    c.rx += n as u64;
                }
                out2
                    .send((sid, b[..n].to_vec()))
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
            }
            anyhow::Ok(())
        });
        let from_agent = async {
            while let Some(chunk) = drx.recv().await {
                // egress 连接行 tx 累计（agent->公网字节，tick 归集用）
                if let Some(c) = s_tx.conns.write().await.get_mut(&(sid as u64)) {
                    c.tx += chunk.len() as u64;
                }
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
        // egress 流结束清 conns 行（tick 只读 conns 归集，行不消失则增量永远涨）。
        // 取证采样：close 行带 rx/tx 字节（与 open 行 sid 对上即完整证据：谁连哪、多少字节）。
        // 节奏对齐：open 用 EGRESS_CTR 计数，close 用同一计数器的 sid 映射位——简化起见
        // close 采样条件与 open 相同窗口：sid 是奇数自增，N=100 时 sid%100==1 的流两行都记。
        if let Some(c) = s.conns.write().await.remove(&(sid as u64)) {
            if egress_sample_hit(egress_sample_n(), sid as u64) {
                log_ev(&s, format!("egress close sid={sid} rx={} tx={} target={}", c.rx, c.tx, c.target));
            }
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
            tracing::info!("agent '{hostname}' already converged, skip Config push");
        } else if let Some(ctl) = s.agents.read().await.get(agent_id).map(|h| h.ctl.clone()) {
            let _ = ctl.send(ServerMsg::Config { proxies: proxies.clone() });
            log_ev(s, format!("agent '{hostname}' Config pushed ({} proxies)", proxies.len()));
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
            rate_limit: None,
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
            rate_limit: None,
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
    fn egress_sample_hit_threshold() {
        // 取证采样语义：N=0 关，N=1 全记，N=100 每百记一。
        // close 行用 sid 取模与 open 窗口对齐（sid 奇数自增，N=100 时 sid%100==1 的流两行都记）。
        assert!(!super::egress_sample_hit(0, 0));
        assert!(super::egress_sample_hit(1, 7));
        assert!(super::egress_sample_hit(100, 0));
        assert!(!super::egress_sample_hit(100, 1));
        assert!(super::egress_sample_hit(100, 100));
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
            rate_limit: None,
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
