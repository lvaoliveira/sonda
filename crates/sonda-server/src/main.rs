use anyhow::Result;
use clap::{Parser, Subcommand};
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
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Known-vulnerability data for dependencies (ADR-0009).
    Advisories {
        #[command(subcommand)]
        action: AdvisoriesAction,
    },
}

#[derive(Subcommand)]
enum AdvisoriesAction {
    /// Import OSV records: JSON files, or directories of them such as an
    /// unzipped export from osv-vulnerabilities (npm, crates.io, PyPI). Only
    /// GitHub, RustSec, PyPA and Go advisories are kept. Needs only
    /// DATABASE_URL.
    Import {
        #[arg(required = true)]
        paths: Vec<PathBuf>,
    },
    /// Fetch what changed since the last sync from OSV (or
    /// SONDA_ADVISORY_SYNC_URL), once: for cron, where the server's own
    /// daily sync (SONDA_ADVISORY_SYNC=true) isn't wanted. Needs only
    /// DATABASE_URL.
    Sync,
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
    match cli.command {
        None => {
            let config = Config::load(cli.listen, cli.web_dir, &ProcessEnv)?;
            sonda_server::run(config).await
        }
        Some(Command::Advisories {
            action: AdvisoriesAction::Import { paths },
        }) => {
            let pool =
                sonda_server::db::connect(sonda_server::config::database(&ProcessEnv)?).await?;
            sonda_server::db::migrate(&pool).await?;
            report(&sonda_server::advisories::import(&pool, &paths).await?);
            Ok(())
        }
        Some(Command::Advisories {
            action: AdvisoriesAction::Sync,
        }) => {
            let url = std::env::var("SONDA_ADVISORY_SYNC_URL")
                .unwrap_or_else(|_| sonda_server::advisory_sync::DEFAULT_BASE_URL.into());
            let url = sonda_server::advisory_sync::check_base_url(&url)
                .map_err(|e| anyhow::anyhow!("SONDA_ADVISORY_SYNC_URL: {e}"))?;
            let pool =
                sonda_server::db::connect(sonda_server::config::database(&ProcessEnv)?).await?;
            sonda_server::db::migrate(&pool).await?;
            report(&sonda_server::advisory_sync::sync_once(&pool, &url).await?);
            Ok(())
        }
    }
}

fn report(s: &sonda_server::advisories::ImportSummary) {
    println!(
        "read {} records: {} imported, {} unchanged, {} skipped (other databases or ecosystems), {} errors",
        s.read, s.imported, s.unchanged, s.skipped, s.errors
    );
    for e in &s.first_errors {
        println!("  {e}");
    }
}
