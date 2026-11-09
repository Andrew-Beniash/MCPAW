use anyhow::Result;
use clap::Parser;
use mcpaw::config::WbConfig;
use mcpaw::daemon::start_daemon;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "wbd",
    about = "MCP and Agent Workbench core daemon (proxies, trace store, modules, and local UI)"
)]
struct WbdArgs {
    /// Path to wb.toml configuration file
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Bind address (must be 127.0.0.1 / localhost unless --i-understand-this-exposes-traffic is passed)
    #[arg(long)]
    bind: Option<String>,

    /// MCP & LLM proxy port (default: 7410)
    #[arg(long)]
    mcp_port: Option<u16>,

    /// Web UI & REST/SSE API port (default: 7411)
    #[arg(long)]
    ui_port: Option<u16>,

    /// Override data directory for SQLite trace store and Unix IPC socket
    #[arg(long)]
    data_dir: Option<PathBuf>,

    /// Enable development mode (allows header-chosen upstreams and fake LLM endpoints)
    #[arg(long, default_value_t = false)]
    dev: bool,

    /// Required flag to allow binding to non-loopback addresses such as 0.0.0.0
    #[arg(long = "i-understand-this-exposes-traffic", default_value_t = false)]
    allow_non_loopback: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = WbdArgs::parse();
    let mut cfg = WbConfig::load_or_default(args.config.as_deref())?;

    if let Some(b) = args.bind {
        cfg.daemon.bind = b;
    }
    if let Some(mp) = args.mcp_port {
        cfg.daemon.mcp_port = mp;
    }
    if let Some(up) = args.ui_port {
        cfg.daemon.ui_port = up;
    }
    if let Some(dd) = args.data_dir {
        cfg.daemon.data_dir = Some(dd);
    }
    if args.dev {
        cfg.daemon.dev_mode = true;
    }

    let daemon = start_daemon(cfg, args.allow_non_loopback).await?;

    println!("MCP and Agent Workbench daemon (wbd) running:");
    println!("  MCP & LLM Proxy : http://{}", daemon.mcp_addr);
    println!("  Web UI & API    : {}", daemon.launch_url());
    println!("  IPC Socket      : {}", daemon.socket_path.display());
    println!("  SQLite Store    : {}", daemon.db_path.display());

    tokio::signal::ctrl_c().await?;
    println!("\nShutting down wbd...");
    Ok(())
}
