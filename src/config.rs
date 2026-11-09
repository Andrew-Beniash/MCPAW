use anyhow::{bail, Context, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum CaptureLevel {
    Off,
    #[default]
    Metadata,
    Full,
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
    /// Enables developer/testing features (such as fake LLM scenarios and allowlisted test upstreams)
    #[serde(default)]
    pub dev_mode: bool,
    /// Optional bearer token required on proxy port (:7410) HTTP requests
    #[serde(default)]
    pub proxy_token: Option<String>,
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
            dev_mode: false,
            proxy_token: None,
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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExportConfig {
    #[serde(default)]
    pub otlp_endpoint: String,
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

impl PolicyRule {
    pub fn validate(&self) -> Result<()> {
        if let Some(ref pat) = self.arg_pattern {
            if !pat.is_empty() {
                Regex::new(pat).with_context(|| {
                    format!(
                        "Invalid regex in policy rule '{}' arg_pattern: '{}'",
                        self.id, pat
                    )
                })?;
            }
        }
        Ok(())
    }
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
    #[serde(skip)]
    pub loaded_from: Option<PathBuf>,
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
                let mut cfg: WbConfig = toml::from_str(&raw)
                    .with_context(|| format!("failed to parse TOML config at {}", p.display()))?;
                cfg.validate_policy_rules()?;
                cfg.loaded_from = Some(p);
                return Ok(cfg);
            }
        }
        Ok(WbConfig::default())
    }

    pub fn validate_policy_rules(&self) -> Result<()> {
        for rule in &self.policy.rules {
            rule.validate()?;
        }
        Ok(())
    }

    /// Atomically persists only the `[policy]` table of the config file this config was loaded
    /// from (H3, N7). Comments and formatting elsewhere in the file are preserved via `toml_edit`.
    /// Returns `Ok(false)` without writing when the daemon was not started from a config file, so
    /// a file is never created at the default path as a side effect.
    pub fn save_policy_atomic(&self, policy: &PolicyConfig) -> Result<bool> {
        let Some(path) = self.loaded_from.clone() else {
            return Ok(false);
        };
        let existing = std::fs::read_to_string(&path).unwrap_or_default();
        let mut doc: toml_edit::DocumentMut = existing
            .parse()
            .with_context(|| format!("failed to parse {} for update", path.display()))?;

        #[derive(Serialize)]
        struct PolicyOnly<'a> {
            policy: &'a PolicyConfig,
        }
        let fragment = toml::to_string_pretty(&PolicyOnly { policy })?;
        let fragment_doc: toml_edit::DocumentMut = fragment.parse()?;
        if let Some(item) = fragment_doc.get("policy") {
            doc["policy"] = item.clone();
        }

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp_path = path.with_extension(format!("toml.tmp.{}", std::process::id()));
        {
            use std::io::Write;
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut f = opts.open(&tmp_path)?;
            f.write_all(doc.to_string().as_bytes())?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp_path, &path)?;
        Ok(true)
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

#[derive(Debug, Serialize, Deserialize)]
struct BackupMetadata {
    pub backup_file: PathBuf,
    pub wrapped_sha256: String,
    pub created_at_unix: u64,
}

fn sha256_str(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    hex::encode(h.finalize())
}

fn wrap_mcp_servers_map(
    servers: &mut serde_json::Map<String, serde_json::Value>,
    wb_bin: &str,
    wrapped_servers: &mut Vec<String>,
) {
    for (server_id, entry) in servers.iter_mut() {
        let Some(obj) = entry.as_object_mut() else {
            continue;
        };
        let Some(cmd) = obj
            .get("command")
            .and_then(|c| c.as_str())
            .map(String::from)
        else {
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

/// Safe, atomic client configuration rewriter (`wb setup claude-code`, H9):
/// - Preserves JSON key order (`serde_json/preserve_order`)
/// - Handles both top-level `mcpServers` and project-scoped `projects.<path>.mcpServers`
/// - Uses timestamped backups + hash check so `--undo` refuses to clobber subsequent edits
/// - Refuses to overwrite if the file changed on disk since read, and writes via atomic rename
pub fn setup_client_config(config_path: &Path, wb_bin: &str, undo: bool) -> Result<Vec<String>> {
    let meta_path = config_path.with_extension("json.wb-backup-meta");
    let legacy_backup_path = config_path.with_extension("json.wb-backup");

    if undo {
        let current_raw = std::fs::read_to_string(config_path)
            .with_context(|| format!("Failed to read {}", config_path.display()))?;
        let current_hash = sha256_str(&current_raw);

        if meta_path.exists() {
            let meta_raw = std::fs::read_to_string(&meta_path)?;
            let meta: BackupMetadata = serde_json::from_str(&meta_raw)?;
            if meta.wrapped_sha256 != current_hash {
                bail!(
                    "Refusing to restore backup because {} was modified after `wb setup` ran. \
                     Inspect the backup manually at {}.",
                    config_path.display(),
                    meta.backup_file.display()
                );
            }
            if !meta.backup_file.exists() {
                bail!("Backup file missing at {}", meta.backup_file.display());
            }
            let tmp_restore = config_path.with_extension("json.wb-tmp");
            std::fs::copy(&meta.backup_file, &tmp_restore)?;
            std::fs::rename(&tmp_restore, config_path)?;
            let _ = std::fs::remove_file(&meta.backup_file);
            let _ = std::fs::remove_file(&meta_path);
            let _ = std::fs::remove_file(&legacy_backup_path);
            return Ok(vec![
                "Restored original configuration from backup.".to_string()
            ]);
        } else if legacy_backup_path.exists() {
            let tmp_restore = config_path.with_extension("json.wb-tmp");
            std::fs::copy(&legacy_backup_path, &tmp_restore)?;
            std::fs::rename(&tmp_restore, config_path)?;
            let _ = std::fs::remove_file(&legacy_backup_path);
            return Ok(vec![
                "Restored original configuration from backup.".to_string()
            ]);
        } else {
            bail!("No backup file found for {}", config_path.display());
        }
    }

    let raw = std::fs::read_to_string(config_path)
        .with_context(|| format!("Failed to read client config at {}", config_path.display()))?;
    let initial_hash = sha256_str(&raw);

    let mut root: serde_json::Value =
        serde_json::from_str(&raw).context("Client config is not valid JSON")?;

    let mut wrapped_servers = Vec::new();

    // 1. Top-level `mcpServers`
    if let Some(servers) = root.get_mut("mcpServers").and_then(|v| v.as_object_mut()) {
        wrap_mcp_servers_map(servers, wb_bin, &mut wrapped_servers);
    }

    // 2. Project-scoped `projects.<path>.mcpServers` (Claude Code ~/.claude.json structure)
    if let Some(projects) = root.get_mut("projects").and_then(|v| v.as_object_mut()) {
        for (_proj_path, proj_val) in projects.iter_mut() {
            if let Some(servers) = proj_val
                .get_mut("mcpServers")
                .and_then(|v| v.as_object_mut())
            {
                wrap_mcp_servers_map(servers, wb_bin, &mut wrapped_servers);
            }
        }
    }

    // Verify the file was not modified concurrently by the client while we processed it
    let verify_raw = std::fs::read_to_string(config_path)?;
    if sha256_str(&verify_raw) != initial_hash {
        bail!(
            "Client config at {} changed on disk during setup; aborting to prevent data loss.",
            config_path.display()
        );
    }

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let ts_backup_path = config_path.with_extension(format!("json.wb-backup.{}", ts));
    std::fs::write(&ts_backup_path, &raw)
        .with_context(|| format!("Failed to write backup at {}", ts_backup_path.display()))?;
    // Also maintain `.wb-backup` symlink/copy for compatibility
    let _ = std::fs::write(&legacy_backup_path, &raw);

    let formatted = serde_json::to_string_pretty(&root)?;
    let wrapped_hash = sha256_str(&formatted);

    let tmp_path = config_path.with_extension("json.wb-tmp");
    std::fs::write(&tmp_path, &formatted)?;
    std::fs::rename(&tmp_path, config_path)?;

    let meta = BackupMetadata {
        backup_file: ts_backup_path,
        wrapped_sha256: wrapped_hash,
        created_at_unix: ts,
    };
    std::fs::write(&meta_path, serde_json::to_string_pretty(&meta)?)?;

    Ok(wrapped_servers)
}
