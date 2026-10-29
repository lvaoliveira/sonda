use anyhow::Result;
use clap::Parser;
use sonda_server::config::{Config, ProcessEnv};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

/// The sonda server: stores analyses uploaded by `sonda upload` and serves
/// the web app.
///
/// Secrets come from the environment, never flags: DATABASE_URL or
/// DATABASE_URL_FILE, optionally DATABASE_PASSWORD or DATABASE_PASSWORD_FILE,
/// and SONDA_TOKEN or SONDA_TOKEN_FILE.
#[derive(Parser)]
#[command(version)]
struct Cli {
    /// Address to listen on. Anything but localhost exposes the server.
    #[arg(long, env = "SONDA_LISTEN", default_value = "127.0.0.1:9000")]
    listen: SocketAddr,
    /// Directory of the built web app (web/dist) to serve.
    #[arg(long, env = "SONDA_WEB_DIR")]
    web_dir: Option<PathBuf>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("sonda=info,sqlx=warn"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
    match start(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("sonda-server: error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

#[tokio::main]
async fn start(cli: Cli) -> Result<()> {
    let config = Config::load(cli.listen, cli.web_dir, &ProcessEnv)?;
    sonda_server::run(config).await
}
