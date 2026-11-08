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
use std::net::SocketAddr;
use std::path::PathBuf;
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

    // Pre-populate configured servers in catalog
    for srv in &config.servers {
        let cmd_or_url = srv
            .upstream
            .clone()
            .or_else(|| srv.command.clone())
            .unwrap_or_default();
        let _ = store.apply_event(&WorkbenchEvent::ServerObserved {
            server_id: srv.id.clone(),
            transport: srv.transport.clone(),
            command_or_url: cmd_or_url,
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

    let http_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(120))
        .build()?;

    let config_arc = Arc::new(Mutex::new(config.clone()));
    let ui_token = generate_ui_token();

    // Write UI token to data_dir so local CLI (`wb`) commands can authenticate automatically
    let token_path = config.resolve_data_dir().join("ui.token");
    if let Some(parent) = token_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(&token_path, &ui_token);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if token_path.exists() {
            let _ = std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o600));
        }
    }

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
