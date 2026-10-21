//! Agent side: out-bound WSS, local dial, stream pumps.
pub mod egress;
pub mod kudus_session;
pub mod link;
pub mod local_ingress;
pub mod quic_session;
pub mod session;
pub mod stream;
pub mod web;

use crate::common::proto::*;
use std::sync::Arc;
use tokio::sync::RwLock;


#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct EgressHttp {
    #[serde(default = "egress_ip_default")]
    pub listen_ip: String,
    #[serde(default = "egress_port_default")]
    pub listen_port: u16,
    #[serde(default)]
    pub enabled: bool,
}

fn egress_ip_default() -> String {
    "0.0.0.0".into()
}

fn egress_port_default() -> u16 {
    18080
}

impl Default for EgressHttp {
    fn default() -> Self {
        Self {
            listen_ip: egress_ip_default(),
            listen_port: egress_port_default(),
            enabled: false,
        }
    }
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
struct EgressCfg {
    #[serde(default)]
    pub http: EgressHttp,
}

/// agent 本地 HTTP 入口（内网 `http://<name><suffix>` 直访名下 http 隧道，不走公网 server）。
/// 默认关：避免无 root 时 :80 bind 失败刷 warn，也避免用户无感知暴露内网；
/// suffix 为空同样不启动（与 enabled 双保险，原因写 status.local_ingress_err）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct LocalIngress {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "local_ingress_ip_default")]
    pub listen_ip: String,
    #[serde(default = "local_ingress_port_default")]
    pub listen_port: u16,
    #[serde(default)]
    pub suffix: String,
}

fn local_ingress_ip_default() -> String {
    "0.0.0.0".into()
}

fn local_ingress_port_default() -> u16 {
    80
}

impl Default for LocalIngress {
    fn default() -> Self {
        Self {
            enabled: false,
            listen_ip: local_ingress_ip_default(),
            listen_port: local_ingress_port_default(),
            suffix: String::new(),
        }
    }
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
pub(crate) struct AgentFileConfig {
    hostname: String,
    #[serde(default)]
    token: String,
    #[serde(default)]
    server: String,
    #[serde(default)]
    proxies: Vec<ProxyConfig>,
    /// agent 本地出网代理（只本地生效，不走 server desired）。
    #[serde(default)]
    egress: EgressCfg,
    /// agent 本地 HTTP 入口（内网直访，不走 server；默认关）。
    #[serde(default)]
    local_ingress: LocalIngress,
}

/// Hot-updatable upstream dial config (WebUI can change without restart).
#[derive(Debug, Clone)]
pub struct Upstream {
    pub server_url: String,
    pub hostname: String,
    pub token: String,
}

pub use self::web::AgentStatus;


async fn load_or_default(config_path: &str, url: &str) -> anyhow::Result<AgentFileConfig> {
    match tokio::fs::read_to_string(config_path).await {
        Ok(raw) => Ok(toml::from_str(&raw)?),
        // config 文件缺失也允许启动：用 CLI --server + 默认 hostname/token 先跑，
        // 用户稍后在本地 WebUI 里填上行地址，保存即落盘+重连。
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::warn!("{config_path} not found, starting unconfigured (set upstream via WebUI); see agent.toml.example");
            Ok(AgentFileConfig {
                hostname: std::env::var("HOSTNAME")
                    .ok()
                    .filter(|h| !h.trim().is_empty())
                    .unwrap_or_else(|| "agent".into()),
                token: String::new(),
                server: url.to_string(),
                proxies: vec![],
                egress: EgressCfg::default(),
                local_ingress: LocalIngress::default(),
            })
        }
        Err(e) => Err(anyhow::anyhow!("read {config_path}: {e} (see agent.toml.example)")),
    }
}

/// 默认上行（与 CLI --server 默认值保持一致，单测 enforce）。
pub const DEFAULT_AGENT_SERVER: &str = "wss://tunnel.nat.kkito.cn:7443/ws";

/// 启动上行解析：显式 CLI > 文件 > CLI 默认。
/// cli_explicit 指用户是否在命令行改了 --server（与默认值不同即算显式）。
fn resolve_initial_url(cli_url: &str, cfg: &AgentFileConfig, cli_explicit: bool) -> String {
    if cli_explicit {
        cli_url.to_string()
    } else if cfg.server.trim().is_empty() {
        cli_url.to_string()
    } else {
        cfg.server.clone()
    }
}

/// WebUI 热重启读取的当前 [egress.http]（agent.toml 唯一来源）。
async fn read_egress_file2(path: &str) -> (String, u16, bool) {
    let raw = tokio::fs::read_to_string(path).await.unwrap_or_default();
    let v: toml::Value = toml::from_str(&raw).unwrap_or(toml::Value::Table(Default::default()));
    let h = v.get("egress").and_then(|e| e.get("http"));
    (
        h.and_then(|x| x.get("listen_ip"))
            .and_then(|x| x.as_str())
            .unwrap_or("0.0.0.0")
            .to_string(),
        h.and_then(|x| x.get("listen_port")).and_then(|x| x.as_integer()).unwrap_or(18080) as u16,
        h.and_then(|x| x.get("enabled")).and_then(|x| x.as_bool()).unwrap_or(false),
    )
}

/// WebUI 热重启读取的当前 [local_ingress]（agent.toml 唯一来源）。
/// 供 reload watcher 重起本地入口监听（仿 read_egress_file2）。
async fn read_local_ingress_file2(path: &str) -> (bool, String, u16, String) {
    let raw = tokio::fs::read_to_string(path).await.unwrap_or_default();
    let v: toml::Value = toml::from_str(&raw).unwrap_or(toml::Value::Table(Default::default()));
    let h = v.get("local_ingress");
    (
        h.and_then(|x| x.get("enabled")).and_then(|x| x.as_bool()).unwrap_or(false),
        h.and_then(|x| x.get("listen_ip"))
            .and_then(|x| x.as_str())
            .unwrap_or("0.0.0.0")
            .to_string(),
        h.and_then(|x| x.get("listen_port")).and_then(|x| x.as_integer()).unwrap_or(80) as u16,
        h.and_then(|x| x.get("suffix"))
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string(),
    )
}

/// backoff 睡眠，可被 redial 打断：被打断返回 true（调用方立即重拨）。
/// seen 为进入睡眠前的 generation：订阅前已到的 bump 也算打断，避免间隙丢失。
async fn sleep_backoff_or_redial(
    dur: std::time::Duration,
    mut rx: tokio::sync::watch::Receiver<u64>,
    seen: u64,
) -> bool {
    if *rx.borrow() != seen {
        return true;
    }
    tokio::select! {
        _ = tokio::time::sleep(dur) => false,
        woke = async {
            loop {
                if rx.changed().await.is_err() {
                    return false;
                }
                if *rx.borrow_and_update() != seen {
                    return true;
                }
            }
        } => woke,
    }
}

pub async fn run(url: &str, config_path: &str, web: &str, web_user: &str, web_pass: &str) -> anyhow::Result<()> {
    let cfg: AgentFileConfig = load_or_default(config_path, url).await?;
    if !cfg.proxies.is_empty() {
        tracing::warn!("local proxies in {config_path} ignored: server is source of truth");
    }
    // 启动优先级：显式 --server > 文件 server > 默认值。
    // 文件里的 server 是 WebUI 上次保存的；用户本次显式传参则覆盖它
    // （并在 WebUI 保存时回写文件，后续启动不用再传）。
    let cli_explicit = url != DEFAULT_AGENT_SERVER;
    let initial_url = resolve_initial_url(url, &cfg, cli_explicit);
    let upstream = Arc::new(RwLock::new(Upstream {
        server_url: initial_url.clone(),
        hostname: cfg.hostname.clone(),
        token: cfg.token.clone(),
    }));
    tracing::info!(
        "agent '{}' -> {initial_url} ({} proxies)",
        cfg.hostname,
        cfg.proxies.len()
    );
    // shared status for local WebUI
    let status = Arc::new(RwLock::new(self::web::AgentStatus {
        version: crate::common::proto::VERSION.into(),
        server_url: initial_url.clone(),
        hostname: cfg.hostname.clone(),
        ..Default::default()
    }));
    // 出站通道持有者：session 建连后注入，egress 监听经它发 Open/数据。
    let egress_out: self::egress::OutHolder = Arc::new(RwLock::new(None));
    let quic_egress_out: self::egress::QuicOutHolder = Arc::new(RwLock::new(None));
    let kudus_egress_out: self::egress::KudusOutHolder = Arc::new(RwLock::new(None));
    let dual_out = || self::egress::DualOut { ws: egress_out.clone(), quic: quic_egress_out.clone(), kudus: kudus_egress_out.clone() };
    // egress 热重启通道：WebUI 保存只 abort/重起本监听，不断 WSS 主链。
    let (egress_tx, egress_rx) = tokio::sync::watch::channel(0u64);
    let egress_cur: Arc<tokio::sync::Mutex<Option<tokio::task::AbortHandle>>> =
        Arc::new(tokio::sync::Mutex::new(None));
    // egress 本地监听（与 WSS 主链解耦：bind 失败/未启用只影响本 task）。
    {
        let h = tokio::spawn({
            let http = cfg.egress.http.clone();
            let bind = format!("{}:{}", http.listen_ip, http.listen_port);
            let st = status.clone();
            let oh = dual_out();
            async move {
                self::egress::serve_egress(bind, http, oh, st).await;
            }
        });
        *egress_cur.lock().await = Some(h.abort_handle());
    }
    {
        // 热重启 watcher：bump 即按 agent.toml 最新 [egress.http] 重起监听
        let cur2 = egress_cur.clone();
        let st2 = status.clone();
        let mk = dual_out();
        let cfg_path2 = config_path.to_string();
        let mut rx = egress_rx;
        tokio::spawn(async move {
            let mut seen = *rx.borrow_and_update();
            loop {
                if rx.changed().await.is_err() {
                    break;
                }
                let v = *rx.borrow_and_update();
                if v == seen {
                    continue;
                }
                seen = v;
                if let Some(h) = cur2.lock().await.take() {
                    h.abort();
                }
                let (ip, port, en) = read_egress_file2(&cfg_path2).await;
                let bind = format!("{ip}:{port}");
                let http = EgressHttp {
                    listen_ip: ip,
                    listen_port: port,
                    enabled: en,
                };
                let h = tokio::spawn({
                    let st = st2.clone();
                    let oh = mk.clone();
                    async move {
                        self::egress::serve_egress(bind, http, oh, st).await;
                    }
                });
                *cur2.lock().await = Some(h.abort_handle());
            }
        });
    }
    // bumped by WebUI to force an immediate redial (settings save / button)
    let (redial_tx, redial_rx) = tokio::sync::watch::channel(0u64);
    if web.is_empty() {
        println!("agent local webui disabled (enable with --web 127.0.0.1:8080)");
    } else {
        // persist web password hash under agent data file.
        // NOTE: --web-pass only takes effect on FIRST run (when the file
        // doesn't exist yet). Afterwards the persisted hash wins; delete
        // the file to reset to the CLI value.
        let data_path = format!("{config_path}.webpass");
        let (hash, fresh) = match tokio::fs::read_to_string(&data_path).await {
            Ok(h) if !h.trim().is_empty() => {
                if web_pass != "neutrino123" {
                    tracing::warn!("--web-pass ignored: {data_path} already exists (delete it to reset password)");
                }
                (h.trim().to_string(), false)
            }
            _ => {
                let h = bcrypt::hash(web_pass, bcrypt::DEFAULT_COST)?;
                let _ = tokio::fs::write(&data_path, &h).await;
                (h, true)
            }
        };
        if !fresh {
            println!("agent webui password: persisted ({data_path}); delete it to reset to --web-pass");
        }
        let w = web.to_string();
        let u = web_user.to_string();
        println!("agent local webui: http://{w}/ (user {u})");
        let ph = Arc::new(RwLock::new(hash));
        tokio::spawn(self::web::serve(self::web::ServeArgs {
            bind: w,
            user: u,
            pass_hash: ph,
            data_path,
            status: status.clone(),
            upstream: upstream.clone(),
            config_path: config_path.to_string(),
            redial: redial_tx.clone(),
            egress_reload: egress_tx.clone(),
        }));
    }
    let mut backoff = vec![1u64, 2, 5, 10, 30, 60];
    let mut reconnects = 0u64;
    // abort handle for the live session; WebUI redial aborts it so the loop
    // immediately redials with the new upstream (no waiting, no restart).
    // watch channel carries a monotonically increasing generation; the loop
    // re-checks it after every session so no bump is ever lost (no take race:
    // watcher only aborts, generation compare happens in-loop).
    let cur: Arc<tokio::sync::Mutex<Option<tokio::task::AbortHandle>>> =
        Arc::new(tokio::sync::Mutex::new(None));
    {
        let cur2 = cur.clone();
        tokio::spawn(async move {
            let mut rx = redial_rx;
            // skip the initial value; only future bumps count
            let mut seen = *rx.borrow_and_update();
            loop {
                if rx.changed().await.is_err() {
                    break;
                }
                let v = *rx.borrow_and_update();
                if v != seen {
                    seen = v;
                    if let Some(h) = cur2.lock().await.as_ref() {
                        h.abort();
                    }
                }
            }
        });
    }
    let mut redial_seen = *redial_tx.borrow();
    loop {
        // bump arrived while not in a session (backoff / debounce gap):
        // count the redial without spawning a stale session first, so no
        // user click is ever lost (the old debounce consumed them).
        {
            let gen_now = *redial_tx.borrow();
            if gen_now != redial_seen {
                redial_seen = gen_now;
                reconnects += 1;
                backoff = vec![1u64, 2, 5, 10, 30, 60];
                {
                    let mut st = status.write().await;
                    st.online = false;
                    st.reconnects = reconnects;
                    st.last_error = Some("redial requested".into());
                }
                tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                continue;
            }
        }
        // snapshot hot-updatable dial config
        let up = upstream.read().await.clone();
        {
            let mut st = status.write().await;
            st.server_url = up.server_url.clone();
            st.hostname = up.hostname.clone();
            st.transport = match crate::common::quic::parse_server_url(&up.server_url) {
                crate::common::quic::Transport::Quic { .. } => "quic".into(),
                crate::common::quic::Transport::Kudus { .. } => "kudus".into(),
                _ => "wss".into(),
            };
        }
        // transport 选路：quic:// 走 QUIC 会话，kudus:// 走 kudus 会话，其余走 WSS 老路。
        // QUIC/kudus 也要 egress 通道：session 注入的是各自 framer/Pkt，egress 侧同构。
        let is_quic = matches!(
            crate::common::quic::parse_server_url(&up.server_url),
            crate::common::quic::Transport::Quic { .. }
        );
        let is_kudus = matches!(
            crate::common::quic::parse_server_url(&up.server_url),
            crate::common::quic::Transport::Kudus { .. }
        );
        // run session in a task so the watcher can abort it on redial
        // QUIC/WSS 闭包都要 'static：status/egress holder 每次 clone 进去，
        // up/cfg 同理（循环引用，不能 move 外层 Arc）。
        let sess = if is_quic {
            let (up2, cfg2, st2, qh) = (up.clone(), cfg.clone(), status.clone(), quic_egress_out.clone());
            tokio::spawn(async move {
                quic_session::session(up2, cfg2, st2, qh).await
            })
        } else if is_kudus {
            let (up2, cfg2, st2, kh) = (up.clone(), cfg.clone(), status.clone(), kudus_egress_out.clone());
            tokio::spawn(async move {
                kudus_session::session(up2, cfg2, st2, kh).await
            })
        } else {
            let (up2, cfg2, st2, eh) = (up.clone(), cfg.clone(), status.clone(), egress_out.clone());
            tokio::spawn(async move {
                session::session(up2, cfg2, st2, eh).await
            })
        };
        *cur.lock().await = Some(sess.abort_handle());
        let err = match sess.await {
            Ok(Ok(())) => String::from("closed"),
            Ok(Err(e)) => format!("{e:#}"),
            Err(j) if j.is_cancelled() => String::from("redial requested"),
            Err(j) => format!("task: {j}"),
        };
        *cur.lock().await = None;
        reconnects += 1;
        // a redial bump that arrived while the session was already exiting
        // (watcher had nothing/old handle to abort) still counts: compare
        // generations in-loop so the signal is never lost.
        let gen_now = *redial_tx.borrow();
        let bumped = gen_now != redial_seen;
        redial_seen = gen_now;
        let redial = err == "redial requested" || bumped;
        {
            let mut st = status.write().await;
            st.online = false;
            st.reconnects = reconnects;
            st.last_error = Some(err);
        }
        if redial {
            // user-triggered: immediate redial, reset backoff
            backoff = vec![1u64, 2, 5, 10, 30, 60];
            // small debounce so rapid double-clicks don't spin; bumps arriving
            // during the debounce coalesce (consume them so the next session
            // starts once with the latest upstream instead of redialing twice).
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            redial_seen = *redial_tx.borrow();
        } else {
            let s = backoff.first().cloned().unwrap_or(60);
            if backoff.len() > 1 {
                backoff.remove(0);
            }
            tracing::warn!("session ended; retry in {s}s (WebUI save reconnects immediately)");
            // 睡眠可被 WebUI 保存打断：打断后按 redial 走（立即重拨+重置 backoff）。
            // 传 seen=redial_seen：subscribe 间隙到达的 bump 也算打断，不丢。
            if sleep_backoff_or_redial(std::time::Duration::from_secs(s), redial_tx.subscribe(), redial_seen).await {
                reconnects += 1;
                backoff = vec![1u64, 2, 5, 10, 30, 60];
                {
                    let mut st = status.write().await;
                    st.online = false;
                    st.reconnects = reconnects;
                    st.last_error = Some("redial requested".into());
                }
                tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                redial_seen = *redial_tx.borrow();
                continue;
            }
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn egress_config_defaults_off_and_fullbind() {
        let c: AgentFileConfig = toml::from_str("hostname = \"h\"\n").unwrap();
        assert!(!c.egress.http.enabled);
        assert_eq!(c.egress.http.listen_port, 18080);
        assert_eq!(c.egress.http.listen_ip, "0.0.0.0");
    }

    /// RED: backoff 睡眠必须可被 redial 打断。
    /// 现场：session 刚失败，主循环进 30s+ 睡眠，此时 WebUI 点保存 bump。
    /// 判定函数 sleep_backoff_or_redial：redial 到达即早返 true。
    #[tokio::test]
    async fn backoff_sleep_is_interruptible_by_redial() {
        let (tx, rx) = tokio::sync::watch::channel(0u64);
        // 无 bump：睡满（用 50ms 代表，便于测试）
        let t0 = std::time::Instant::now();
        let woke = sleep_backoff_or_redial(Duration::from_millis(50), rx.clone(), 0).await;
        assert!(!woke);
        assert!(t0.elapsed() >= Duration::from_millis(50));
        // 睡眠中到达的 bump：30s 睡眠也必须毫秒级打断
        let h = tokio::spawn(async move {
            sleep_backoff_or_redial(Duration::from_secs(30), rx, 0).await
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        tx.send_replace(1);
        let woke = tokio::time::timeout(Duration::from_secs(2), h)
            .await
            .expect("redial must interrupt backoff")
            .unwrap();
        assert!(woke, "redial during backoff must interrupt sleep");
    }

    #[tokio::test]
    async fn backoff_sleep_catches_pre_subscribe_bump() {
        // bump 发生在 subscribe 间隙（借出旧句柄后、新订阅前）：
        // 新订阅看到的 generation 已变，必须直接判打断，不能再睡。
        let (tx, rx) = tokio::sync::watch::channel(0u64);
        tx.send_replace(7);
        let woke = sleep_backoff_or_redial(Duration::from_secs(30), rx, 0).await;
        assert!(woke, "stale-observed generation must count as redial");
    }

    #[tokio::test]
    async fn cli_server_overrides_file() {
        // RED: 启动时显式传 --server，必须优先于文件里的 server。
        // 现场：文件里是旧地址，CLI 给了新地址，实际拨的应是 CLI 的。
        // 默认值不算“显式传”：只有用户改了 CLI 默认值才覆盖文件。
        let dir = std::env::temp_dir().join(format!("nt-agent-test-{}", uuid::Uuid::new_v4()));
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let p = dir.join("agent.toml");
        tokio::fs::write(&p, "hostname = \"h\"\ntoken = \"t\"\nserver = \"ws://file-old/ws\"\n").await.unwrap();
        let cfg = load_or_default(p.to_str().unwrap(), "ws://cli-new/ws").await.unwrap();
        assert_eq!(resolve_initial_url("ws://cli-new/ws", &cfg, true), "ws://cli-new/ws");
        // 没显式传（还是默认值）：文件优先
        assert_eq!(resolve_initial_url(super::DEFAULT_AGENT_SERVER, &cfg, false), "ws://file-old/ws");
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn missing_config_starts_unconfigured() {
        let cfg = load_or_default("/nonexistent-dir-xyz/agent.toml", "ws://x:7440/ws").await.unwrap();
        assert_eq!(cfg.server, "ws://x:7440/ws");
        assert!(cfg.proxies.is_empty());
        // hostname 回退：HOSTNAME 为空时用默认名而非 panic
        assert!(!cfg.hostname.trim().is_empty());
    }

    #[tokio::test]
    async fn load_or_default_reads_existing_file() {
        let dir = std::env::temp_dir().join(format!("nt-agent-test-{}", uuid::Uuid::new_v4()));
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let p = dir.join("agent.toml");
        tokio::fs::write(&p, "hostname = \"h1\"\ntoken = \"t1\"\nserver = \"ws://s1/ws\"\n").await.unwrap();
        let cfg = load_or_default(p.to_str().unwrap(), "ws://cli/ws").await.unwrap();
        assert_eq!(cfg.hostname, "h1");
        assert_eq!(cfg.token, "t1");
        assert_eq!(cfg.server, "ws://s1/ws");
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn load_or_default_rejects_broken_toml() {
        let dir = std::env::temp_dir().join(format!("nt-agent-test-{}", uuid::Uuid::new_v4()));
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let p = dir.join("agent.toml");
        tokio::fs::write(&p, "[[[").await.unwrap();
        assert!(load_or_default(p.to_str().unwrap(), "ws://cli/ws").await.is_err());
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }
}
