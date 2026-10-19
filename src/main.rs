pub mod agent;
pub mod desired;
pub mod proto;
pub mod server;

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
            token,
        } => {
            let token =
                std::env::var("NEUTRINO_TOKEN").unwrap_or(token);
            server::run(&listen, &http_in, &data, &token).await
        }
        Cmd::Agent { server, config } => agent::run(&server, &config).await,
        Cmd::Genhash { password } => {
            let h = bcrypt::hash(&password, bcrypt::DEFAULT_COST)?;
            println!("{h}");
            Ok(())
        }
    }
}
