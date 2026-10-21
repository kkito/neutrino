pub mod agent;
pub mod common;
pub mod server;

pub(crate) use server::auth::{mint_jwt as server_mint_jwt, verify_jwt as server_auth_verify};

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "neutrino", about = "stealth WSS tunnel: server | agent")]
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
        /// detach to background (log to file, print pid and exit)
        #[arg(long)]
        detach: bool,
        /// log file for --detach (empty = <data>/neutrino.log)
        #[arg(long, default_value = "")]
        log_file: String,
        /// optional pid file for --detach
        #[arg(long, default_value = "")]
        pid_file: String,
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
    },
    /// bcrypt-hash a password for WebUI
    Genhash { password: String },
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
            detach,
            log_file,
            pid_file,
        } => {
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
            server::run(&listen, &http_in, &data, &token, &desired, &quic_listen, &kudus_listen).await
        }
        Cmd::Agent { server, config, web, web_user, web_pass, detach, log_file, pid_file } => {
            let log = if log_file.is_empty() {
                "./neutrino-agent.log".to_string()
            } else {
                log_file
            };
            if detach {
                return detach_spawn(&log, &pid_file);
            }
            agent::run(&server, &config, &web, &web_user, &web_pass).await
        }
        Cmd::Genhash { password } => {
            let h = bcrypt::hash(&password, bcrypt::DEFAULT_COST)?;
            println!("{h}");
            Ok(())
        }
    }
}
