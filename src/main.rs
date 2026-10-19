pub mod agent;
pub mod agent_web;
pub mod desired;
pub mod proto;
pub mod server;

pub(crate) use server::{mint_jwt as server_mint_jwt, verify_jwt as server_auth_verify};

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
        #[arg(long, default_value = "127.0.0.1:7080")]
        http_in: String,
        #[arg(long, default_value = "./data")]
        data: String,
        /// desired tunnels file (hostname -> proxies)
        #[arg(long, default_value = "./data/desired.toml")]
        desired: String,
        /// pre-shared token (or env NEUTRINO_TOKEN)
        #[arg(long, default_value = "welcome2ll")]
        token: String,
    },
    /// Run as agent (snail side)
    Agent {
        #[arg(long, default_value = "wss://tunnel.nat.kkito.cn:7443/ws")]
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
    },
    /// bcrypt-hash a password for WebUI
    Genhash { password: String },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stdout)
        .init();
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Server {
            listen,
            http_in,
            data,
            desired,
            token,
        } => {
            let token =
                std::env::var("NEUTRINO_TOKEN").unwrap_or(token);
            server::run(&listen, &http_in, &data, &token, &desired).await
        }
        Cmd::Agent { server, config, web, web_user, web_pass } => agent::run(&server, &config, &web, &web_user, &web_pass).await,
        Cmd::Genhash { password } => {
            let h = bcrypt::hash(&password, bcrypt::DEFAULT_COST)?;
            println!("{h}");
            Ok(())
        }
    }
}
