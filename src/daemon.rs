use crate::api::{build_api_router, generate_ui_token, ApiState};
use crate::bus::EventBus;
use crate::config::WbConfig;
use crate::models::WorkbenchEvent;
use crate::modules::ModuleHost;
use crate::pricing::PriceTable;
use crate::proxy_http::{build_proxy_router, ProxyState};
use crate::proxy_stdio::start_ipc_listener;
use crate::redact::Redactor;
use crate::store::TraceStore;
use anyhow::{Context, Result};
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpListener;

pub struct RunningDaemon {
    pub mcp_addr: SocketAddr,
    pub ui_addr: SocketAddr,
    pub socket_path: PathBuf,
    pub db_path: PathBuf,
    pub ui_token: String,
    pub bus: EventBus,
    shutdown_tx: Option<tokio::sync::watch::Sender<bool>>,
}

impl RunningDaemon {
    pub fn launch_url(&self) -> String {
        format!("http://{}/?token={}", self.ui_addr, self.ui_token)
    }

    pub fn shutdown(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(true);
        }
    }
}

impl Drop for RunningDaemon {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// M12: Writes `ui.token` atomically with `0o600` permissions from creation so the token is
/// never world-readable even momentarily.
fn write_ui_token_secure(token_path: &Path, ui_token: &str) {
    if let Some(parent) = token_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let tmp_path = token_path.with_extension(format!("tmp.{}", std::process::id()));
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp_path)
        {
            if f.write_all(ui_token.as_bytes()).is_ok() && f.sync_all().is_ok() {
                let _ = std::fs::rename(&tmp_path, token_path);
            }
        }
    }
    #[cfg(not(unix))]
    {
        if std::fs::write(&tmp_path, ui_token).is_ok() {
            let _ = std::fs::rename(&tmp_path, token_path);
        }
    }
}

pub async fn start_daemon(
    config: WbConfig,
    allow_non_loopback: bool,
) -> Result<RunningDaemon> {
    // 1. Validate bind address (§8)
    config.validate_bind_address(allow_non_loopback)?;

    let db_path = config.resolve_db_path();
    let socket_path = config.resolve_socket_path();

    // 2. Open SQLite WAL TraceStore
    let store = TraceStore::open(
        &db_path,
        config.daemon.idle_run_gap_secs,
        config.capture.payloads,
    )?;

    // Pre-populate configured servers in catalog (M5: include command_argv)
    for srv in &config.servers {
        let cmd_or_url = srv
            .upstream
            .clone()
            .or_else(|| srv.command.clone())
            .unwrap_or_default();
        let mut command_argv = Vec::new();
        if let Some(ref c) = srv.command {
            command_argv.push(c.clone());
            command_argv.extend(srv.args.clone());
        }
        let _ = store.apply_event(&WorkbenchEvent::ServerObserved {
            server_id: srv.id.clone(),
            transport: srv.transport.clone(),
            command_or_url: cmd_or_url,
            command_argv,
            protocol_version: None,
            deprecated_feature: None,
        });
    }

    // 3. Initialize Redactor, ModuleHost, PriceTable, and EventBus
    let redactor = Redactor::new(config.capture.payloads, &config.capture.redact);
    let module_host = ModuleHost::new(config.breaker.clone(), config.policy.clone());
    let price_table = Arc::new(PriceTable::new(&config.pricing.overrides));
    let bus = EventBus::new(store.clone(), redactor, module_host, 4096);

    // 4. Start Unix IPC listener for `wb wrap`
    start_ipc_listener(socket_path.clone(), bus.clone()).await?;

    // H5: Use connect_timeout without a total request timeout so long SSE streams,
    // slow Tasks, and human elicitation waits are never prematurely terminated by the proxy.
    let http_client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(15))
        .pool_idle_timeout(Duration::from_secs(90))
        .build()?;

    let config_arc = Arc::new(Mutex::new(config.clone()));
    let ui_token = generate_ui_token();

    // Write UI token to data_dir atomically with 0600 permissions (M12)
    let token_path = config.resolve_data_dir().join("ui.token");
    write_ui_token_secure(&token_path, &ui_token);

    let bind_host = if config.daemon.bind == "localhost" {
        "127.0.0.1"
    } else {
        config.daemon.bind.as_str()
    };

    let mcp_bind = format!("{}:{}", bind_host, config.daemon.mcp_port);
    let ui_bind = format!("{}:{}", bind_host, config.daemon.ui_port);

    let mcp_listener = TcpListener::bind(&mcp_bind)
        .await
        .with_context(|| format!("Failed to bind MCP/LLM proxy listener on {}", mcp_bind))?;
    let ui_listener = TcpListener::bind(&ui_bind)
        .await
        .with_context(|| format!("Failed to bind UI/API listener on {}", ui_bind))?;

    let mcp_addr = mcp_listener.local_addr()?;
    let ui_addr = ui_listener.local_addr()?;

    // Update config_arc with actual bound ports in case port 0 was passed
    {
        let mut cfg_guard = config_arc.lock().unwrap();
        cfg_guard.daemon.mcp_port = mcp_addr.port();
        cfg_guard.daemon.ui_port = ui_addr.port();
    }

    let proxy_router = build_proxy_router(ProxyState {
        config: config_arc.clone(),
        bus: bus.clone(),
        price_table: price_table.clone(),
        http_client: http_client.clone(),
    });

    let api_router = build_api_router(ApiState {
        config: config_arc.clone(),
        bus: bus.clone(),
        ui_token: ui_token.clone(),
        http_client: http_client.clone(),
    });

    let (shutdown_tx, mut shutdown_rx1) = tokio::sync::watch::channel(false);
    let mut shutdown_rx2 = shutdown_tx.subscribe();
    let mut shutdown_rx3 = shutdown_tx.subscribe();

    // Spawn MCP & LLM proxy server
    tokio::spawn(async move {
        let _ = axum::serve(mcp_listener, proxy_router)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx1.changed().await;
            })
            .await;
    });

    // Spawn UI & REST/SSE API server
    tokio::spawn(async move {
        let _ = axum::serve(ui_listener, api_router)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx2.changed().await;
            })
            .await;
    });

    // Spawn hourly retention enforcement task (N-09)
    let retention_store = store.clone();
    let retention_days = config.capture.retention_days;
    let max_db_mb = config.capture.max_db_mb;
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(3600));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let _ = retention_store.enforce_retention(retention_days, max_db_mb);
                }
                _ = shutdown_rx3.changed() => break,
            }
        }
    });

    Ok(RunningDaemon {
        mcp_addr,
        ui_addr,
        socket_path,
        db_path,
        ui_token,
        bus,
        shutdown_tx: Some(shutdown_tx),
    })
}
