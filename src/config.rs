use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CaptureLevel {
    Off,
    Metadata,
    Full,
}

impl Default for CaptureLevel {
    fn default() -> Self {
        CaptureLevel::Metadata
    }
}

impl std::fmt::Display for CaptureLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CaptureLevel::Off => write!(f, "off"),
            CaptureLevel::Metadata => write!(f, "metadata"),
            CaptureLevel::Full => write!(f, "full"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonConfig {
    #[serde(default = "default_mcp_port")]
    pub mcp_port: u16,
    #[serde(default = "default_ui_port")]
    pub ui_port: u16,
    #[serde(default = "default_bind")]
    pub bind: String,
    #[serde(default = "default_idle_run_gap_secs")]
    pub idle_run_gap_secs: u64,
    #[serde(default)]
    pub data_dir: Option<PathBuf>,
    #[serde(default)]
    pub socket_path: Option<PathBuf>,
    #[serde(default)]
    pub llm_upstream: Option<String>,
    #[serde(default)]
    pub anthropic_upstream: Option<String>,
}

fn default_mcp_port() -> u16 {
    7410
}
fn default_ui_port() -> u16 {
    7411
}
fn default_bind() -> String {
    "127.0.0.1".to_string()
}
fn default_idle_run_gap_secs() -> u64 {
    30
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            mcp_port: default_mcp_port(),
            ui_port: default_ui_port(),
            bind: default_bind(),
            idle_run_gap_secs: default_idle_run_gap_secs(),
            data_dir: None,
            socket_path: None,
            llm_upstream: None,
            anthropic_upstream: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureConfig {
    #[serde(default)]
    pub payloads: CaptureLevel,
    #[serde(default = "default_redact_patterns")]
    pub redact: Vec<String>,
    #[serde(default = "default_retention_days")]
    pub retention_days: u32,
    #[serde(default = "default_max_db_mb")]
    pub max_db_mb: u64,
    #[serde(default)]
    pub inject_traceparent: bool,
}

pub fn default_redact_patterns() -> Vec<String> {
    vec![
        "authorization".to_string(),
        "api[_-]?key".to_string(),
        r"(?i)bearer\s+\S+".to_string(),
        r"sk-[A-Za-z0-9_-]{10,}".to_string(),
    ]
}

fn default_retention_days() -> u32 {
    14
}
fn default_max_db_mb() -> u64 {
    2048
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            payloads: CaptureLevel::Metadata,
            redact: default_redact_patterns(),
            retention_days: default_retention_days(),
            max_db_mb: default_max_db_mb(),
            inject_traceparent: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub id: String,
    #[serde(default = "default_transport")]
    pub transport: String,
    #[serde(default)]
    pub upstream: Option<String>,
    #[serde(default)]
    pub command: Option<String>,
    #[serde(default)]
    pub args: Vec<String>,
}

fn default_transport() -> String {
    "stdio".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelPriceOverride {
    pub model: String,
    pub input_per_1m: f64,
    pub cached_per_1m: f64,
    pub output_per_1m: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PricingConfig {
    #[serde(default = "default_pricing_source")]
    pub source: String,
    #[serde(default)]
    pub overrides: Vec<ModelPriceOverride>,
}

fn default_pricing_source() -> String {
    "bundled".to_string()
}

impl Default for PricingConfig {
    fn default() -> Self {
        Self {
            source: default_pricing_source(),
            overrides: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportConfig {
    #[serde(default)]
    pub otlp_endpoint: String,
}

impl Default for ExportConfig {
    fn default() -> Self {
        Self {
            otlp_endpoint: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreakerConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_max_run_cost_usd")]
    pub max_run_cost_usd: f64,
    #[serde(default = "default_max_run_tokens")]
    pub max_run_tokens: u64,
    #[serde(default = "default_max_identical_tool_calls")]
    pub max_identical_tool_calls: u32,
}

fn default_true() -> bool {
    true
}
fn default_max_run_cost_usd() -> f64 {
    5.0
}
fn default_max_run_tokens() -> u64 {
    500_000
}
fn default_max_identical_tool_calls() -> u32 {
    5
}

impl Default for BreakerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_run_cost_usd: default_max_run_cost_usd(),
            max_run_tokens: default_max_run_tokens(),
            max_identical_tool_calls: default_max_identical_tool_calls(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyEffect {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub id: String,
    #[serde(default = "default_wildcard")]
    pub server: String,
    #[serde(default = "default_wildcard")]
    pub tool: String,
    #[serde(default)]
    pub arg_pattern: Option<String>,
    pub effect: PolicyEffect,
    #[serde(default)]
    pub reason: String,
}

fn default_wildcard() -> String {
    "*".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub fail_closed: bool,
    #[serde(default)]
    pub block_on_schema_change: bool,
    #[serde(default)]
    pub rules: Vec<PolicyRule>,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            fail_closed: true,
            block_on_schema_change: false,
            rules: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WbConfig {
    #[serde(default)]
    pub daemon: DaemonConfig,
    #[serde(default)]
    pub capture: CaptureConfig,
    #[serde(default, rename = "server")]
    pub servers: Vec<ServerConfig>,
    #[serde(default)]
    pub pricing: PricingConfig,
    #[serde(default)]
    pub export: ExportConfig,
    #[serde(default)]
    pub breaker: BreakerConfig,
    #[serde(default)]
    pub policy: PolicyConfig,
}

impl WbConfig {
    pub fn load_or_default(path: Option<&Path>) -> Result<Self> {
        let resolved = match path {
            Some(p) => Some(p.to_path_buf()),
            None => std::env::var("WB_CONFIG")
                .ok()
                .map(PathBuf::from)
                .or_else(Self::default_config_path),
        };

        if let Some(p) = resolved {
            if p.exists() {
                let raw = std::fs::read_to_string(&p)
                    .with_context(|| format!("failed to read config at {}", p.display()))?;
                let cfg: WbConfig = toml::from_str(&raw)
                    .with_context(|| format!("failed to parse TOML config at {}", p.display()))?;
                return Ok(cfg);
            }
        }
        Ok(WbConfig::default())
    }

    pub fn default_config_path() -> Option<PathBuf> {
        std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config/workbench/wb.toml"))
    }

    pub fn resolve_data_dir(&self) -> PathBuf {
        if let Some(ref d) = self.daemon.data_dir {
            return d.clone();
        }
        if let Ok(env_dir) = std::env::var("WB_DATA_DIR") {
            return PathBuf::from(env_dir);
        }
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(".local/share/workbench");
        }
        std::env::temp_dir().join("mcp-workbench")
    }

    pub fn resolve_db_path(&self) -> PathBuf {
        self.resolve_data_dir().join("traces.sqlite")
    }

    pub fn resolve_socket_path(&self) -> PathBuf {
        if let Some(ref s) = self.daemon.socket_path {
            return s.clone();
        }
        if let Ok(env_sock) = std::env::var("WB_SOCKET") {
            return PathBuf::from(env_sock);
        }
        self.resolve_data_dir().join("wbd.sock")
    }

    /// Enforces §8 Security requirement:
    /// "Bind to 127.0.0.1 only. Refuse to start on 0.0.0.0 without --i-understand-this-exposes-traffic."
    pub fn validate_bind_address(&self, allow_non_loopback: bool) -> Result<()> {
        let host = self.daemon.bind.trim();
        if host == "127.0.0.1" || host == "localhost" || host == "::1" || host == "[::1]" {
            return Ok(());
        }
        if let Ok(ip) = host.parse::<IpAddr>() {
            if ip.is_loopback() {
                return Ok(());
            }
        }
        if !allow_non_loopback {
            bail!(
                "Refusing to bind Workbench daemon to non-loopback address '{}' without --i-understand-this-exposes-traffic. \
                 The Workbench observes all agent traffic and secrets; bind to 127.0.0.1 for local safety.",
                host
            );
        }
        Ok(())
    }
}

/// Rewrites a client MCP config JSON (such as Claude Code or Claude Desktop)
/// to wrap each stdio server with `wb wrap --id <id> -- <command> <args...>`,
/// saving a `.wb-backup` file alongside it for one-command undo.
pub fn setup_client_config(
    config_path: &Path,
    wb_bin: &str,
    undo: bool,
) -> Result<Vec<String>> {
    let backup_path = config_path.with_extension("json.wb-backup");

    if undo {
        if !backup_path.exists() {
            bail!("No backup file found at {}", backup_path.display());
        }
        std::fs::copy(&backup_path, config_path)?;
        std::fs::remove_file(&backup_path)?;
        return Ok(vec!["Restored original configuration from backup.".to_string()]);
    }

    let raw = std::fs::read_to_string(config_path)
        .with_context(|| format!("Failed to read client config at {}", config_path.display()))?;
    let mut root: serde_json::Value =
        serde_json::from_str(&raw).context("Client config is not valid JSON")?;

    if !backup_path.exists() {
        std::fs::write(&backup_path, &raw)
            .with_context(|| format!("Failed to write backup at {}", backup_path.display()))?;
    }

    let mut wrapped_servers = Vec::new();
    if let Some(servers) = root.get_mut("mcpServers").and_then(|v| v.as_object_mut()) {
        for (server_id, entry) in servers.iter_mut() {
            let Some(obj) = entry.as_object_mut() else {
                continue;
            };
            let Some(cmd) = obj.get("command").and_then(|c| c.as_str()).map(String::from) else {
                continue;
            };
            let existing_args: Vec<String> = obj
                .get("args")
                .and_then(|a| a.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();

            // Skip if already wrapped
            if (cmd == "wb" || cmd.ends_with("/wb"))
                && existing_args.first().map(|s| s.as_str()) == Some("wrap")
            {
                continue;
            }

            let mut new_args = vec![
                "wrap".to_string(),
                "--id".to_string(),
                server_id.clone(),
                "--".to_string(),
                cmd,
            ];
            new_args.extend(existing_args);

            obj.insert(
                "command".to_string(),
                serde_json::Value::String(wb_bin.to_string()),
            );
            obj.insert(
                "args".to_string(),
                serde_json::Value::Array(
                    new_args
                        .into_iter()
                        .map(serde_json::Value::String)
                        .collect(),
                ),
            );
            wrapped_servers.push(server_id.clone());
        }
    }

    let formatted = serde_json::to_string_pretty(&root)?;
    std::fs::write(config_path, formatted)?;
    Ok(wrapped_servers)
}
