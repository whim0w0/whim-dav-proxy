mod backoff;

mod config;

mod crypto;

mod errors;

mod service;

use clap::Parser;
use std::process;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "whim-dav-proxy")]
#[command(version = "0.1.0")]
struct Cli {
    #[arg(short, long, default_value = "config.yaml")]
    config: String,
}

#[tokio::main]
async fn main() -> () {
    let cli: Cli = Cli::parse();

    let cfg: config::RootConfig = match config::RootConfig::load(&cli.config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to load config: {}", e);
            process::exit(1);
        }
    };

    if let Err(e) = cfg.validate() {
        eprintln!("Invalid config: {}", e);
        process::exit(1);
    }

    let filter: EnvFilter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&cfg.log.level));

    let fmt = tracing_subscriber::fmt().with_env_filter(filter);

    match cfg.log.format.as_str() {
        "console" | "text" | "pretty" => fmt.init(),
        _ => fmt.json().init(),
    }

    tracing::info!(config = %cli.config, "Starting whim-dav-proxy (Rust)");
    tracing::info!(backends = cfg.backends.len(), "Configuration loaded");

    let mgr: service::server::ServerManager = match service::server::ServerManager::new(&cfg).await
    {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Failed to create server manager: {}", e);
            process::exit(1);
        }
    };

    tracing::info!("All backends started");

    tokio::signal::ctrl_c()
        .await
        .expect("failed to listen for ctrl+c");

    tracing::info!("Received shutdown signal, stopping...");

    mgr.shutdown().await;

    tracing::info!("Server stopped");
}
