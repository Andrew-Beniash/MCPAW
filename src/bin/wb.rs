use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use mcpaw::config::{setup_client_config, WbConfig};
use mcpaw::daemon::start_daemon;
use mcpaw::fixtures::run_stdio_fixture;
use mcpaw::modules::PolicyModule;
use mcpaw::pricing::PRICE_TABLE_DATE;
use mcpaw::proxy_stdio::{now_ns, run_stdio_wrapper};
use mcpaw::redact::Redactor;
use mcpaw::store::TraceStore;
use serde_json::json;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "wb",
    about = "MCP and Agent Workbench CLI — stdio wrapper, trace inspector, policy tester, and exporter"
)]
struct Cli {
    /// Path to wb.toml configuration file
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,

    /// Override data directory for SQLite trace store and Unix IPC socket
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Start the Workbench daemon (wbd) in the foreground
    Up {
        #[arg(long)]
        bind: Option<String>,
        #[arg(long)]
        mcp_port: Option<u16>,
        #[arg(long)]
        ui_port: Option<u16>,
        #[arg(long, default_value_t = false)]
        dev: bool,
        #[arg(long = "i-understand-this-exposes-traffic", default_value_t = false)]
        allow_non_loopback: bool,
    },

    /// Wrap a stdio MCP server with byte-identical forwarding and trace capture
    Wrap {
        /// Logical server identifier (e.g. "invoices", "filesystem")
        #[arg(long)]
        id: String,

        /// Enforce fail-closed transport policy on tools/call
        #[arg(long, default_value_t = false)]
        policy: bool,

        /// Explicit run ID to attach recorded spans to
        #[arg(long)]
        run_id: Option<String>,

        /// Override Unix socket path for daemon IPC
        #[arg(long)]
        socket: Option<PathBuf>,

        /// Command and arguments of the target MCP server (after `--`)
        #[arg(required = true, num_args = 1.., last = true)]
        cmd: Vec<String>,
    },

    /// Rewrite a client configuration file (e.g. claude-code) to wrap stdio servers with backup & undo
    Setup {
        /// Target client name (e.g. "claude-code", "cursor", "claude-desktop")
        client: String,

        /// Path to client JSON config file
        #[arg(long)]
        config_path: Option<PathBuf>,

        /// Restore original client configuration from .wb-backup
        #[arg(long, default_value_t = false)]
        undo: bool,
    },

    /// List discovered MCP servers and their tool catalogs
    Servers {
        /// Include full tool definitions for each server
        #[arg(long, default_value_t = false)]
        tools: bool,

        /// Output as JSON
        #[arg(long, default_value_t = false)]
        json: bool,
    },

    /// Inspect or compare recorded runs
    Runs {
        #[command(subcommand)]
        action: RunsAction,
    },

    /// Export runs to OTLP JSON, JSONL, or MockMCP Studio fixtures
    Export {
        /// Export format: otlp | jsonl | mockmcp
        #[arg(long, default_value = "jsonl")]
        format: String,

        /// Comma-separated list of run IDs (defaults to all runs)
        #[arg(long)]
        runs: Option<String>,

        /// Print a redaction preview with byte count before writing
        #[arg(long, default_value_t = false)]
        preview: bool,

        /// Write export to a file instead of stdout
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Import a JSONL run archive into the local trace store
    Import {
        /// Path to JSONL export file
        file: PathBuf,
    },

    /// Export a run as deterministic replay fixtures for MockMCP Studio
    Replay {
        /// Run ID to export for replay
        run_id: String,

        /// Output file path
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Test and inspect policy rules
    Policy {
        #[command(subcommand)]
        action: PolicyAction,
    },

    /// Run a built-in chaos or protocol conformance MCP stdio fixture server
    Fixture {
        /// Fixture name: echo | slow | crashy | huge | chatty | liar | weird-schema | dual
        kind: String,
    },
}

#[derive(Subcommand, Debug)]
enum RunsAction {
    /// List recorded runs
    Ls {
        #[arg(long)]
        status: Option<String>,
        #[arg(long)]
        since: Option<String>,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Show detailed span tree, token breakdown, and cost for a run
    Show {
        run_id: String,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Compare two runs side-by-side and highlight the first divergence
    Diff {
        left_run_id: String,
        right_run_id: String,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
}

#[derive(Subcommand, Debug)]
enum PolicyAction {
    /// Test a hypothetical tool call against configured policy rules
    Test {
        #[arg(long)]
        server: String,
        #[arg(long)]
        tool: String,
        #[arg(long, default_value = "{}")]
        args: String,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // H10 + N2: In `wb wrap`, a config that fails to load must not stop the user's MCP server, but it
    // must not silently disable a firewall either. If the raw file looks like it enables the policy
    // (or `--policy` was passed), the wrapper fails closed on `tools/call` while still forwarding
    // everything else, and the error names the config problem.
    let mut wrap_config_error: Option<String> = None;
    let mut cfg = match &cli.command {
        Commands::Wrap { policy, .. } => match WbConfig::load_or_default(cli.config.as_deref()) {
            Ok(c) => c,
            Err(e) => {
                if *policy {
                    return Err(e);
                }
                let raw = raw_config_text(cli.config.as_deref());
                let policy_may_be_enabled = raw
                    .as_deref()
                    .map(config_text_enables_policy)
                    .unwrap_or(false);
                eprintln!(
                    "wb wrap warning: failed to load configuration ({:#}); {}",
                    e,
                    if policy_may_be_enabled {
                        "policy appears to be enabled, so tools/call is blocked (fail-closed) until the config is fixed."
                    } else {
                        "continuing with default observation settings."
                    }
                );
                if policy_may_be_enabled {
                    wrap_config_error = Some(format!("{:#}", e));
                }
                WbConfig::default()
            }
        },
        Commands::Fixture { .. } => WbConfig::default(),
        _ => WbConfig::load_or_default(cli.config.as_deref())?,
    };

    if let Some(dd) = cli.data_dir {
        cfg.daemon.data_dir = Some(dd);
    }

    match cli.command {
        Commands::Up {
            bind,
            mcp_port,
            ui_port,
            dev,
            allow_non_loopback,
        } => {
            if let Some(b) = bind {
                cfg.daemon.bind = b;
            }
            if let Some(mp) = mcp_port {
                cfg.daemon.mcp_port = mp;
            }
            if let Some(up) = ui_port {
                cfg.daemon.ui_port = up;
            }
            if dev {
                cfg.daemon.dev_mode = true;
            }
            let daemon = start_daemon(cfg, allow_non_loopback).await?;
            println!("MCP and Agent Workbench daemon running:");
            println!("  MCP & LLM Proxy : http://{}", daemon.mcp_addr);
            println!("  Web UI & API    : {}", daemon.launch_url());
            println!("  IPC Socket      : {}", daemon.socket_path.display());
            println!("  SQLite Store    : {}", daemon.db_path.display());
            tokio::signal::ctrl_c().await?;
        }

        Commands::Wrap {
            id,
            policy,
            run_id,
            socket,
            cmd,
        } => {
            let Some((program, args)) = cmd.split_first() else {
                bail!("wb wrap requires a command after `--`");
            };
            let sock_path = socket.unwrap_or_else(|| cfg.resolve_socket_path());
            let enforce_policy = policy || cfg.policy.enabled;
            let code = run_stdio_wrapper(
                id,
                program.clone(),
                args.to_vec(),
                sock_path,
                enforce_policy,
                run_id,
                wrap_config_error,
            )
            .await?;
            std::process::exit(code);
        }

        Commands::Setup {
            client,
            config_path,
            undo,
        } => {
            let resolved_path = match config_path {
                Some(p) => p,
                None => default_client_config_path(&client)?,
            };
            let current_exe = std::env::current_exe()
                .ok()
                .and_then(|p| p.to_str().map(String::from))
                .unwrap_or_else(|| "wb".to_string());
            let result = setup_client_config(&resolved_path, &current_exe, undo)?;
            if undo {
                println!(
                    "Restored original {} config at {}",
                    client,
                    resolved_path.display()
                );
            } else {
                println!(
                    "Wrapped {} server(s) in {}: {:?}",
                    result.len(),
                    resolved_path.display(),
                    result
                );
            }
        }

        Commands::Servers { tools, json } => {
            let store = open_store(&cfg)?;
            let servers = store.list_servers()?;
            if json {
                if tools {
                    let mut full = Vec::new();
                    for s in servers {
                        let t = store.get_server_tools(&s.id)?;
                        full.push(json!({ "server": s, "tools": t }));
                    }
                    println!("{}", serde_json::to_string_pretty(&full)?);
                } else {
                    println!("{}", serde_json::to_string_pretty(&servers)?);
                }
            } else {
                if servers.is_empty() {
                    println!("No MCP servers recorded yet.");
                }
                for s in servers {
                    println!(
                        "{:<18} transport={:<6} tools={:<3} schema_changes={:<2} versions={:?} deprecated={:?}",
                        s.id,
                        s.transport,
                        s.tool_count,
                        s.schema_changes,
                        s.protocol_versions_seen,
                        s.deprecated_features_seen
                    );
                    if tools {
                        let t_list = store.get_server_tools(&s.id)?;
                        for t in t_list {
                            println!(
                                "  - {} [hash: {}] changed={}x : {}",
                                t.name,
                                &t.schema_hash[..12.min(t.schema_hash.len())],
                                t.changed_count,
                                t.description
                            );
                            for w in &t.poison_warnings {
                                println!("    ! WARNING: {}", w);
                            }
                        }
                    }
                }
            }
        }

        Commands::Runs { action } => {
            let store = open_store(&cfg)?;
            match action {
                RunsAction::Ls {
                    status,
                    since,
                    json,
                } => {
                    let runs = store.list_runs(since.as_deref(), status.as_deref())?;
                    if json {
                        println!("{}", serde_json::to_string_pretty(&runs)?);
                    } else if runs.is_empty() {
                        println!("No runs recorded.");
                    } else {
                        println!(
                            "{:<40} {:<8} {:<6} {:<6} {:<18} STARTED AT",
                            "RUN ID", "STATUS", "SPANS", "ERRS", "COST (USD)"
                        );
                        for r in runs {
                            let prefix = if r.estimated_cost { "~" } else { "" };
                            println!(
                                "{:<40} {:<8} {:<6} {:<6} {:<18} {}",
                                r.id,
                                r.status,
                                r.span_count,
                                r.error_count,
                                format!(
                                    "{}${:.4} [{}]",
                                    prefix, r.total_cost_usd, PRICE_TABLE_DATE
                                ),
                                r.started_at
                            );
                        }
                    }
                }
                RunsAction::Show { run_id, json } => {
                    let Some(run) = store.get_run(&run_id)? else {
                        bail!("Run '{}' not found", run_id);
                    };
                    let spans = store.get_run_spans(&run_id)?;
                    let xray = store.get_run_xray(&run_id)?;
                    if json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&json!({
                                "run": run,
                                "price_table_date": PRICE_TABLE_DATE,
                                "spans": spans,
                                "xray": xray,
                            }))?
                        );
                    } else {
                        let prefix = if run.estimated_cost { "~" } else { "" };
                        println!(
                            "Run: {} (status: {}, spans: {}, errors: {}, cost: {}${:.4} [table {}], tokens: {})",
                            run.id,
                            run.status,
                            run.span_count,
                            run.error_count,
                            prefix,
                            run.total_cost_usd,
                            PRICE_TABLE_DATE,
                            run.total_tokens
                        );
                        println!("Spans:");
                        for (i, s) in spans.iter().enumerate() {
                            let dur = s
                                .duration_ms()
                                .map(|d| format!("{:.2}ms", d))
                                .unwrap_or_else(|| "in-flight".to_string());
                            println!(
                                "  #{:<3} [{:<6}] {:<28} status={:<13} dur={}",
                                i,
                                s.kind.as_str(),
                                s.name,
                                s.status.as_str(),
                                dur
                            );
                        }
                    }
                }
                RunsAction::Diff {
                    left_run_id,
                    right_run_id,
                    json,
                } => {
                    let diff = store.diff_runs(&left_run_id, &right_run_id)?;
                    if json {
                        println!("{}", serde_json::to_string_pretty(&diff)?);
                    } else {
                        println!(
                            "Diffing Left ({}) vs Right ({}):",
                            diff.left_run.id, diff.right_run.id
                        );
                        if let Some(idx) = diff.first_divergence_index {
                            println!(
                                "FIRST DIVERGENCE at step #{}: {}",
                                idx,
                                diff.first_divergence_reason
                                    .as_deref()
                                    .unwrap_or("diverged")
                            );
                        } else {
                            println!("Runs aligned with zero divergences.");
                        }
                        for e in diff.entries {
                            let marker = if e.diverged { ">>" } else { "  " };
                            let l_name =
                                e.left_span.as_ref().map(|s| s.name.as_str()).unwrap_or("—");
                            let r_name = e
                                .right_span
                                .as_ref()
                                .map(|s| s.name.as_str())
                                .unwrap_or("—");
                            println!(
                                "{} #{:<3} {:<28} | {:<28}",
                                marker, e.step_index, l_name, r_name
                            );
                        }
                    }
                }
            }
        }

        Commands::Export {
            format,
            runs,
            preview,
            output,
        } => {
            let store = open_store(&cfg)?;
            let redactor = Redactor::new(cfg.capture.payloads, &cfg.capture.redact);
            let run_ids: Vec<String> = runs
                .map(|s| {
                    s.split(',')
                        .map(|p| p.trim().to_string())
                        .filter(|p| !p.is_empty())
                        .collect()
                })
                .unwrap_or_default();

            // M14: Reject unknown export format
            let fmt = format.to_lowercase();
            let raw = match fmt.as_str() {
                "otlp" => serde_json::to_string_pretty(&store.export_otlp(&run_ids)?)?,
                "mockmcp" => serde_json::to_string_pretty(&store.export_mockmcp(&run_ids)?)?,
                "jsonl" => store.export_jsonl(&run_ids)?,
                other => bail!(
                    "Unsupported export format '{}'. Valid formats: jsonl, otlp, mockmcp",
                    other
                ),
            };
            let redacted = redactor.redact_str(&raw);

            // M14: Print preview summary and first 4 KB of redacted content
            if preview {
                let sample: String = redacted.chars().take(4096).collect();
                eprintln!(
                    "=== Export Preview (format={}, {} bytes after redaction) ===\n{}",
                    fmt,
                    redacted.len(),
                    sample
                );
            }
            if let Some(out_path) = output {
                std::fs::write(&out_path, &redacted)?;
                eprintln!("Wrote {} bytes to {}", redacted.len(), out_path.display());
            } else {
                println!("{}", redacted);
            }
        }

        Commands::Import { file } => {
            let store = open_store(&cfg)?;
            let content = std::fs::read_to_string(&file)
                .with_context(|| format!("Failed to read {}", file.display()))?;
            let count = store.import_jsonl(&content)?;
            println!("Imported {} run(s) from {}", count, file.display());
        }

        Commands::Replay { run_id, output } => {
            let store = open_store(&cfg)?;
            let redactor = Redactor::new(cfg.capture.payloads, &cfg.capture.redact);
            let fixtures = store.export_mockmcp(&[run_id])?;
            let serialized = redactor.redact_str(&serde_json::to_string_pretty(&fixtures)?);
            if let Some(out_path) = output {
                std::fs::write(&out_path, &serialized)?;
                println!("Wrote MockMCP replay fixtures to {}", out_path.display());
            } else {
                println!("{}", serialized);
            }
        }

        Commands::Policy { action } => match action {
            PolicyAction::Test {
                server,
                tool,
                args,
                json,
            } => {
                let policy_mod = PolicyModule::new(cfg.policy.clone());
                let (verdict, decision) =
                    policy_mod.evaluate_call("cli-policy-test", &server, &tool, &args, now_ns());
                let allowed = !verdict.is_blocked();
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&json!({
                            "allowed": allowed,
                            "verdict": verdict,
                            "decision": decision,
                        }))?
                    );
                } else if allowed {
                    println!("ALLOW: {}:{} with args {}", server, tool, args);
                } else {
                    println!(
                        "DENY: {}:{} — {:?}",
                        server,
                        tool,
                        decision.map(|d| d.reason).unwrap_or_default()
                    );
                    std::process::exit(2);
                }
            }
        },

        Commands::Fixture { kind } => {
            let code = run_stdio_fixture(&kind)?;
            std::process::exit(code);
        }
    }

    Ok(())
}

fn open_store(cfg: &WbConfig) -> Result<TraceStore> {
    TraceStore::open(
        &cfg.resolve_db_path(),
        cfg.daemon.idle_run_gap_secs,
        cfg.capture.payloads,
    )
}

fn default_client_config_path(client: &str) -> Result<PathBuf> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .context("HOME environment variable not set")?;
    match client.to_lowercase().as_str() {
        "claude-code" => Ok(home.join(".claude.json")),
        "cursor" => Ok(home.join(".cursor/mcp.json")),
        "claude-desktop" => Ok(
            home.join("Library/Application Support/Claude/claude_desktop_config.json"),
        ),
        other => bail!(
            "Unknown client '{}'. Pass --config-path explicitly or use claude-code | cursor | claude-desktop.",
            other
        ),
    }
}

/// Reads the raw text of the config that `WbConfig::load_or_default` would have used.
fn raw_config_text(explicit: Option<&std::path::Path>) -> Option<String> {
    let path = explicit
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("WB_CONFIG").map(PathBuf::from))
        .or_else(WbConfig::default_config_path)?;
    std::fs::read_to_string(path).ok()
}

/// Best-effort check for an enabled policy in a config that failed to parse. Recognizes the three
/// TOML spellings: a `[policy]` table with `enabled = true`, a dotted `policy.enabled = true`, and an
/// inline `policy = { enabled = true, ... }`. When in doubt it answers `true`, because a false
/// positive only blocks `tools/call` until the config is fixed, while a false negative turns the
/// firewall off.
fn config_text_enables_policy(raw: &str) -> bool {
    let mut in_policy = false;
    for line in raw.lines() {
        let t = line.split('#').next().unwrap_or("").trim();
        let compact: String = t.chars().filter(|c| !c.is_whitespace()).collect();
        if compact.starts_with('[') {
            in_policy = compact == "[policy]";
            continue;
        }
        if in_policy && compact == "enabled=true" {
            return true;
        }
        if compact == "policy.enabled=true" {
            return true;
        }
        if compact.starts_with("policy={") && compact.contains("enabled=true") {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::config_text_enables_policy;

    #[test]
    fn detects_every_toml_spelling_of_enabled_policy() {
        assert!(config_text_enables_policy("[policy]\nenabled = true\n"));
        assert!(config_text_enables_policy(
            "[ policy ]\n  enabled=true # on\n"
        ));
        assert!(config_text_enables_policy("policy.enabled = true\n"));
        assert!(config_text_enables_policy(
            "policy = { enabled = true, fail_closed = true }\n"
        ));
    }

    #[test]
    fn ignores_disabled_or_unrelated_settings() {
        assert!(!config_text_enables_policy("[policy]\nenabled = false\n"));
        assert!(!config_text_enables_policy("[breaker]\nenabled = true\n"));
        assert!(!config_text_enables_policy(
            "# [policy]\n# enabled = true\n"
        ));
        assert!(!config_text_enables_policy(""));
    }
}
