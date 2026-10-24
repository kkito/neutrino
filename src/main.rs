pub mod agent;
pub mod common;
pub mod server;

pub(crate) use server::auth::{mint_jwt as server_mint_jwt, verify_jwt as server_auth_verify};

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "neutrino", version, about = "stealth WSS tunnel: server | agent")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run as server (natproxy side)
    Server {
        #[arg(long, default_value = "127.0.0.1:7440")]
        listen: String,
        /// deprecated alias: HTTP 入站已并入 --listen 同端口（Host 路由）；传入仅 warn 忽略
        #[arg(long, default_value = "")]
        http_in: String,
        #[arg(long, default_value = "./data")]
        data: String,
        /// desired tunnels file (hostname -> proxies)
        #[arg(long, default_value = "./data/desired.toml")]
        desired: String,
        /// pre-shared token (or env NEUTRINO_TOKEN)
        #[arg(long, default_value = "welcome2neutrino")]
        token: String,
        /// QUIC UDP listen (empty = disabled), e.g. 0.0.0.0:7444
        #[arg(long, default_value = "")]
        quic_listen: String,
        /// kudus UDP listen (empty = disabled), e.g. 0.0.0.0:7445
        #[arg(long, default_value = "")]
        kudus_listen: String,
        /// 允许已连 agent 经隧道读写 server 管理 API（默认关；开了 = token 即最高权，见 spec）。
        #[arg(long, default_value_t = false)]
        allow_agent_admin: bool,
        /// UDP ingress session 空闲回收秒数（默认 5）。语义：该 peer 静默多久就回收；
        /// 每包刷新 TTL，故活跃 uTP 长连接不会被回收，扫描器一问一答即清。
        #[arg(long, default_value_t = 5)]
        udp_session_ttl: u64,
        /// detach to background (log to file, print pid and exit)
        #[arg(long)]
        detach: bool,
        /// log file for --detach (empty = <data>/neutrino.log)
        #[arg(long, default_value = "")]
        log_file: String,
        /// optional pid file for --detach
        #[arg(long, default_value = "")]
        pid_file: String,
        /// live 速率快照 tick 周期（毫秒）0=默认 5000。仅调试/测试用，生产勿改。
        #[arg(long, default_value_t = 0)]
        live_tick_ms: u64,
        /// 流量归集/落盘 tick 周期（毫秒）0=默认 60000。仅调试/测试用。
        #[arg(long, default_value_t = 0)]
        traffic_tick_ms: u64,
        /// 限速器窗口计数 tick 周期（毫秒）0=默认 300000。仅调试/测试用。
        #[arg(long, default_value_t = 0)]
        limiter_tick_ms: u64,
        /// 定期落盘 tick 周期（毫秒）0=默认 30000。仅调试/测试用。
        #[arg(long, default_value_t = 0)]
        persist_tick_ms: u64,
    },
    /// Run as agent (snail side)
    Agent {
        #[arg(long, default_value = agent::DEFAULT_AGENT_SERVER)]
        server: String,
        #[arg(long, default_value = "agent.toml")]
        config: String,
        /// local WebUI bind (empty = disabled), e.g. 127.0.0.1:8080
        #[arg(long, default_value = "")]
        web: String,
        #[arg(long, default_value = "admin")]
        web_user: String,
        #[arg(long, default_value = "neutrino123")]
        web_pass: String,
        /// detach to background (log to file, print pid and exit)
        #[arg(long)]
        detach: bool,
        /// log file for --detach (empty = ./neutrino-agent.log)
        #[arg(long, default_value = "")]
        log_file: String,
        /// optional pid file for --detach
        #[arg(long, default_value = "")]
        pid_file: String,
        /// UDP 流空闲回收秒数（默认 5，0=默认）。静默这么久没包就拆流；
        /// BT uTP 长连接在丢包链路上静默可能超过 5s，可按现场放宽（如 60）。
        #[arg(long, default_value_t = 0)]
        udp_idle_secs: u64,
    },
    /// bcrypt-hash a password for WebUI
    Genhash { password: String },
}

/// --log-file 只在 --detach 时生效（spec §15.5）。
///
/// 根因→修法：旧代码在 systemd（非 detach）下传 `--log-file` 会被静默忽略
/// （tracing 固定写 stdout），运维以为日志写进了文件，实际只在 journal 里。
fn should_warn_log_file_ignored(detach: bool, log_file: &str) -> bool {
    !detach && !log_file.is_empty()
}

/// Strip the `--detach` flag from argv for the background respawn.
fn strip_detach(args: Vec<String>) -> Vec<String> {
    args.into_iter().filter(|a| a != "--detach").collect()
}

/// Relaunch self in background: stdio to log file, print pid + log, exit.
/// (systemd/podman 不需要此 flag；仅裸跑时用。Windows 下退化为普通后台进程。)
fn detach_spawn(log_file: &str, pid_file: &str) -> anyhow::Result<()> {
    if let Some(p) = std::path::Path::new(log_file).parent() {
        if !p.as_os_str().is_empty() {
            std::fs::create_dir_all(p)?;
        }
    }
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_file)?;
    let err = log.try_clone()?;
    let args: Vec<String> = strip_detach(std::env::args().skip(1).collect());
    let mut cmd = std::process::Command::new(std::env::current_exe()?);
    cmd.args(&args)
        .stdin(std::process::Stdio::null())
        .stdout(log)
        .stderr(err);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        unsafe {
            // SAFETY: setsid(2) 无参数、无失败路径副作用，pre_exec 中仅调它。
            cmd.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
    }
    let child = cmd.spawn()?;
    if !pid_file.is_empty() {
        std::fs::write(pid_file, child.id().to_string())?;
    }
    println!("detached pid={} log={log_file}", child.id());
    Ok(())
}

#[cfg(test)]
mod main_tests {
    use super::strip_detach;
    use clap::Parser;

    /// spec §15.5：--log-file 只在 --detach 时生效。
    /// 旧代码：systemd（非 detach）下传了完全无效且无任何提示。
    #[test]
    fn log_file_warns_when_ignored() {
        assert!(
            super::should_warn_log_file_ignored(false, "/tmp/x.log"),
            "非 detach 传了 --log-file 应 warn"
        );
        assert!(
            !super::should_warn_log_file_ignored(true, "/tmp/x.log"),
            "detach 时生效，不 warn"
        );
        assert!(!super::should_warn_log_file_ignored(false, ""), "未传不 warn");
        assert!(!super::should_warn_log_file_ignored(true, ""), "detach 未传不 warn");
    }

    #[test]
    fn agent_admin_switch_defaults_off() {
        // 根因→修法：--allow-agent-admin 默认关，不传即锁死（B 信任模型下默认开等于裸奔）。
        let cli = super::Cli::try_parse_from(["neutrino", "server"]).unwrap();
        match cli.cmd {
            super::Cmd::Server { allow_agent_admin, .. } => assert!(!allow_agent_admin),
            _ => panic!("want server"),
        }
    }

    #[test]
    fn detach_flag_stripped() {
        let a = strip_detach(vec![
            "server".into(),
            "--detach".into(),
            "--token".into(),
            "s3".into(),
        ]);
        assert_eq!(a, vec!["server", "--token", "s3"]);
        // no flag -> untouched
        let b = strip_detach(vec!["agent".into(), "--web".into(), "x".into()]);
        assert_eq!(b.len(), 3);
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info");
    }
    // stdout 时间戳用本地 wall clock（默认 SystemTime 打 UTC，如 HKT 机器 18:00 打成 10:00Z）。
    let timer = tracing_subscriber::fmt::time::ChronoLocal::new("%Y-%m-%dT%H:%M:%S%.3f%:z".to_string());
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stdout)
        .with_timer(timer)
        .init();
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Server {
            listen,
            http_in,
            data,
            desired,
            token,
            quic_listen,
            kudus_listen,
            allow_agent_admin,
            udp_session_ttl,
            detach,
            log_file,
            pid_file,
            live_tick_ms,
            traffic_tick_ms,
            limiter_tick_ms,
            persist_tick_ms,
        } => {
            if should_warn_log_file_ignored(detach, &log_file) {
                tracing::warn!(
                    "--log-file 仅在 --detach 时生效，当前已忽略；systemd 场景请用 journalctl -u <unit>"
                );
            }
            let log = if log_file.is_empty() {
                format!("{data}/neutrino.log")
            } else {
                log_file
            };
            if detach {
                return detach_spawn(&log, &pid_file);
            }
            let token =
                std::env::var("NEUTRINO_TOKEN").unwrap_or(token);
            let ticks = server::TickPeriods::from_millis(
                live_tick_ms,
                traffic_tick_ms,
                limiter_tick_ms,
                persist_tick_ms,
            );
            server::run_with_ticks(&listen, &http_in, &data, &token, &desired, &quic_listen, &kudus_listen, allow_agent_admin, udp_session_ttl, ticks).await
        }
        Cmd::Agent { server, config, web, web_user, web_pass, detach, log_file, pid_file, udp_idle_secs } => {
            if should_warn_log_file_ignored(detach, &log_file) {
                tracing::warn!(
                    "--log-file 仅在 --detach 时生效，当前已忽略；systemd 场景请用 journalctl -u <unit>"
                );
            }
            let log = if log_file.is_empty() {
                "./neutrino-agent.log".to_string()
            } else {
                log_file
            };
            if detach {
                return detach_spawn(&log, &pid_file);
            }
            agent::run(&server, &config, &web, &web_user, &web_pass, udp_idle_secs).await
        }
        Cmd::Genhash { password } => {
            let h = bcrypt::hash(&password, bcrypt::DEFAULT_COST)?;
            println!("{h}");
            Ok(())
        }
    }
}
