use crate::config::CaptureLevel;
use crate::models::*;
use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

const BLOB_THRESHOLD_BYTES: usize = 64 * 1024; // 64 KB (§4.1)

#[derive(Clone)]
pub struct TraceStore {
    db_path: PathBuf,
    write_conn: Arc<Mutex<Connection>>,
    read_conn: Arc<Mutex<Connection>>,
    idle_run_gap_secs: u64,
    capture_level: CaptureLevel,
}

impl TraceStore {
    pub fn open(
        db_path: &Path,
        idle_run_gap_secs: u64,
        capture_level: CaptureLevel,
    ) -> Result<Self> {
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let write_conn = Connection::open(db_path).with_context(|| {
            format!("failed to open SQLite trace store at {}", db_path.display())
        })?;

        // Enforce 0600 file permissions on Unix (§8 Threat Model)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if db_path.exists() {
                let _ = std::fs::set_permissions(db_path, std::fs::Permissions::from_mode(0o600));
            }
        }

        write_conn.execute_batch(
            r#"
            PRAGMA auto_vacuum = INCREMENTAL;
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;
            PRAGMA foreign_keys = ON;
            PRAGMA busy_timeout = 5000;
            PRAGMA temp_store = MEMORY;

            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                started_at TEXT NOT NULL,
                client_name TEXT,
                client_version TEXT,
                negotiated_version TEXT,
                capabilities_json TEXT
            );

            CREATE TABLE IF NOT EXISTS runs (
                id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                label TEXT,
                status TEXT NOT NULL DEFAULT 'ok',
                started_at TEXT NOT NULL,
                ended_at TEXT,
                last_activity_ns INTEGER NOT NULL DEFAULT 0,
                total_cost_usd REAL NOT NULL DEFAULT 0.0,
                total_tokens INTEGER NOT NULL DEFAULT 0,
                estimated_cost INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_runs_started_at ON runs(started_at DESC);
            CREATE INDEX IF NOT EXISTS idx_runs_session ON runs(session_id);

            CREATE TABLE IF NOT EXISTS spans (
                id TEXT PRIMARY KEY,
                trace_id TEXT NOT NULL,
                run_id TEXT NOT NULL,
                parent_id TEXT,
                kind TEXT NOT NULL,
                name TEXT NOT NULL,
                start_ns INTEGER NOT NULL,
                end_ns INTEGER,
                status TEXT NOT NULL,
                attributes_json TEXT NOT NULL DEFAULT '{}'
            );
            CREATE INDEX IF NOT EXISTS idx_spans_run_id ON spans(run_id, start_ns ASC);
            CREATE INDEX IF NOT EXISTS idx_spans_trace_id ON spans(trace_id);

            CREATE TABLE IF NOT EXISTS mcp_servers (
                id TEXT PRIMARY KEY,
                transport TEXT NOT NULL,
                command_or_url TEXT NOT NULL,
                command_argv_json TEXT NOT NULL DEFAULT '[]',
                protocol_versions_json TEXT NOT NULL DEFAULT '[]',
                deprecated_features_json TEXT NOT NULL DEFAULT '[]',
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS tool_definitions (
                server_id TEXT NOT NULL,
                name TEXT NOT NULL,
                description TEXT NOT NULL,
                input_schema_json TEXT NOT NULL,
                schema_hash TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                changed_count INTEGER NOT NULL DEFAULT 0,
                previous_description TEXT,
                previous_schema_hash TEXT,
                poison_warnings_json TEXT NOT NULL DEFAULT '[]',
                PRIMARY KEY (server_id, name)
            );

            CREATE TABLE IF NOT EXISTS tool_schema_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                server_id TEXT NOT NULL,
                name TEXT NOT NULL,
                description TEXT NOT NULL,
                input_schema_json TEXT NOT NULL,
                schema_hash TEXT NOT NULL,
                recorded_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS blobs (
                id TEXT PRIMARY KEY,
                compressed INTEGER NOT NULL DEFAULT 1,
                data BLOB NOT NULL,
                raw_size INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS mcp_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                span_id TEXT NOT NULL,
                direction TEXT NOT NULL,
                jsonrpc_id TEXT,
                method TEXT,
                payload_ref TEXT,
                inline_payload TEXT,
                bytes INTEGER NOT NULL,
                timestamp_ns INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_mcp_messages_span ON mcp_messages(span_id, timestamp_ns ASC);

            CREATE TABLE IF NOT EXISTS model_calls (
                span_id TEXT PRIMARY KEY,
                provider TEXT NOT NULL,
                model TEXT NOT NULL,
                input_tokens INTEGER NOT NULL,
                output_tokens INTEGER NOT NULL,
                cached_tokens INTEGER NOT NULL DEFAULT 0,
                cost_usd REAL NOT NULL DEFAULT 0.0,
                cost_estimated INTEGER NOT NULL DEFAULT 0,
                finish_reason TEXT,
                context_breakdown_json TEXT NOT NULL DEFAULT '{}',
                request_payload_ref TEXT,
                request_inline TEXT,
                response_payload_ref TEXT,
                response_inline TEXT
            );

            CREATE TABLE IF NOT EXISTS policy_decisions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id TEXT NOT NULL,
                span_id TEXT NOT NULL,
                server_id TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                verdict TEXT NOT NULL,
                reason TEXT NOT NULL,
                timestamp_ns INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_policy_decisions_span ON policy_decisions(span_id);

            CREATE TABLE IF NOT EXISTS annotations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id TEXT NOT NULL,
                author TEXT NOT NULL,
                text TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_annotations_target ON annotations(target_id);
            "#,
        )?;

        // Ensure `command_argv_json` column exists on existing databases
        let _ = write_conn.execute(
            "ALTER TABLE mcp_servers ADD COLUMN command_argv_json TEXT NOT NULL DEFAULT '[]'",
            [],
        );

        // Open a separate read connection (M1) so readers don't contend on the writer mutex
        let read_conn = Connection::open(db_path)?;
        read_conn.execute_batch(
            "PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 5000; PRAGMA query_only = ON;",
        )?;

        Ok(Self {
            db_path: db_path.to_path_buf(),
            write_conn: Arc::new(Mutex::new(write_conn)),
            read_conn: Arc::new(Mutex::new(read_conn)),
            idle_run_gap_secs,
            capture_level,
        })
    }

    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    fn store_payload(
        tx: &rusqlite::Transaction<'_>,
        payload: Option<&str>,
    ) -> Result<(Option<String>, Option<String>)> {
        let Some(text) = payload else {
            return Ok((None, None));
        };
        if text.len() > BLOB_THRESHOLD_BYTES {
            let blob_id = format!("blob-{}", Uuid::new_v4());
            let compressed =
                zstd::encode_all(text.as_bytes(), 3).unwrap_or_else(|_| text.as_bytes().to_vec());
            tx.execute(
                "INSERT INTO blobs (id, compressed, data, raw_size) VALUES (?1, 1, ?2, ?3)",
                params![blob_id, compressed, text.len() as i64],
            )?;
            Ok((Some(blob_id), None))
        } else {
            Ok((None, Some(text.to_string())))
        }
    }

    fn load_payload(
        conn: &Connection,
        payload_ref: Option<String>,
        inline_payload: Option<String>,
    ) -> Option<String> {
        if let Some(inline) = inline_payload {
            return Some(inline);
        }
        if let Some(blob_id) = payload_ref {
            if let Ok(Some((compressed, data))) = conn
                .query_row(
                    "SELECT compressed, data FROM blobs WHERE id = ?1",
                    params![blob_id],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)),
                )
                .optional()
            {
                if compressed == 1 {
                    if let Ok(decoded) = zstd::decode_all(data.as_slice()) {
                        return String::from_utf8(decoded).ok();
                    }
                }
                return String::from_utf8(data).ok();
            }
        }
        None
    }

    /// Resolves or creates the active `Run`, linking activity within `idle_run_gap_secs` (§5, H2).
    fn resolve_or_create_run(
        tx: &rusqlite::Transaction<'_>,
        session_id: &str,
        explicit_run_id: &str,
        run_label: Option<&str>,
        timestamp_ns: u64,
        idle_run_gap_secs: u64,
    ) -> Result<String> {
        let now_str = Utc::now().to_rfc3339();
        tx.execute(
            "INSERT OR IGNORE INTO sessions (id, started_at) VALUES (?1, ?2)",
            params![session_id, now_str],
        )?;

        if !explicit_run_id.is_empty() && explicit_run_id != "auto" {
            tx.execute(
                "INSERT OR IGNORE INTO runs (id, session_id, label, status, started_at, last_activity_ns)
                 VALUES (?1, ?2, ?3, 'ok', ?4, ?5)",
                params![explicit_run_id, session_id, run_label, now_str, timestamp_ns as i64],
            )?;
            return Ok(explicit_run_id.to_string());
        }

        // Check latest run for this session (or across active sessions within idle_run_gap_secs)
        let latest: Option<(String, i64)> = tx
            .query_row(
                "SELECT id, last_activity_ns FROM runs WHERE session_id = ?1 ORDER BY last_activity_ns DESC LIMIT 1",
                params![session_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?
            .or_else(|| {
                tx.query_row(
                    "SELECT id, last_activity_ns FROM runs ORDER BY last_activity_ns DESC LIMIT 1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .ok()
                .flatten()
            });

        let gap_ns = idle_run_gap_secs.saturating_mul(1_000_000_000);
        if let Some((run_id, last_ns)) = latest {
            let last_u64 = last_ns.max(0) as u64;
            if timestamp_ns.saturating_sub(last_u64) <= gap_ns {
                return Ok(run_id);
            }
        }

        let new_run_id = format!("run-{}", Uuid::new_v4());
        tx.execute(
            "INSERT INTO runs (id, session_id, label, status, started_at, last_activity_ns)
             VALUES (?1, ?2, ?3, 'ok', ?4, ?5)",
            params![
                new_run_id,
                session_id,
                run_label,
                now_str,
                timestamp_ns as i64
            ],
        )?;
        Ok(new_run_id)
    }

    pub fn apply_event(&self, event: &WorkbenchEvent) -> Result<()> {
        self.apply_events_batch(std::slice::from_ref(event))
    }

    pub fn apply_events_batch(&self, events: &[WorkbenchEvent]) -> Result<()> {
        if events.is_empty() {
            return Ok(());
        }
        let mut conn = self.write_conn.lock().unwrap();
        let tx = conn.transaction()?;

        for ev in events {
            match ev {
                WorkbenchEvent::SessionStarted { session } => {
                    tx.execute(
                        "INSERT INTO sessions (id, started_at, client_name, client_version, negotiated_version, capabilities_json)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                         ON CONFLICT(id) DO UPDATE SET
                           client_name = COALESCE(excluded.client_name, sessions.client_name),
                           client_version = COALESCE(excluded.client_version, sessions.client_version),
                           negotiated_version = COALESCE(excluded.negotiated_version, sessions.negotiated_version),
                           capabilities_json = COALESCE(excluded.capabilities_json, sessions.capabilities_json)",
                        params![
                            session.id,
                            session.started_at,
                            session.client_name,
                            session.client_version,
                            session.negotiated_version,
                            session.capabilities_json,
                        ],
                    )?;
                }
                WorkbenchEvent::ServerObserved {
                    server_id,
                    transport,
                    command_or_url,
                    command_argv,
                    protocol_version,
                    deprecated_feature,
                } => {
                    let now = Utc::now().to_rfc3339();
                    let existing: Option<(String, String, String)> = tx
                        .query_row(
                            "SELECT protocol_versions_json, deprecated_features_json, command_argv_json FROM mcp_servers WHERE id = ?1",
                            params![server_id],
                            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                        )
                        .optional()?;

                    let (mut versions, mut deprecated, existing_argv): (
                        Vec<String>,
                        Vec<String>,
                        Vec<String>,
                    ) = match existing {
                        Some((v_json, d_json, a_json)) => (
                            serde_json::from_str(&v_json).unwrap_or_default(),
                            serde_json::from_str(&d_json).unwrap_or_default(),
                            serde_json::from_str(&a_json).unwrap_or_default(),
                        ),
                        None => (Vec::new(), Vec::new(), Vec::new()),
                    };

                    if let Some(ver) = protocol_version {
                        if !versions.contains(ver) {
                            versions.push(ver.clone());
                        }
                    }
                    if let Some(dep) = deprecated_feature {
                        if !deprecated.contains(dep) {
                            deprecated.push(dep.clone());
                        }
                    }

                    let argv_to_store = if !command_argv.is_empty() {
                        command_argv
                    } else {
                        &existing_argv
                    };

                    let v_str = serde_json::to_string(&versions)?;
                    let d_str = serde_json::to_string(&deprecated)?;
                    let a_str = serde_json::to_string(argv_to_store)?;

                    tx.execute(
                        "INSERT INTO mcp_servers (id, transport, command_or_url, command_argv_json, protocol_versions_json, deprecated_features_json, first_seen, last_seen)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)
                         ON CONFLICT(id) DO UPDATE SET
                           transport = excluded.transport,
                           command_or_url = CASE WHEN excluded.command_or_url != '' THEN excluded.command_or_url ELSE mcp_servers.command_or_url END,
                           command_argv_json = CASE WHEN excluded.command_argv_json != '[]' THEN excluded.command_argv_json ELSE mcp_servers.command_argv_json END,
                           protocol_versions_json = excluded.protocol_versions_json,
                           deprecated_features_json = excluded.deprecated_features_json,
                           last_seen = excluded.last_seen",
                        params![server_id, transport, command_or_url, a_str, v_str, d_str, now],
                    )?;
                }
                WorkbenchEvent::ToolsDiscovered { server_id, tools } => {
                    let now = Utc::now().to_rfc3339();
                    for tool in tools {
                        let existing: Option<(String, String, u32)> = tx
                            .query_row(
                                "SELECT description, schema_hash, changed_count FROM tool_definitions WHERE server_id = ?1 AND name = ?2",
                                params![server_id, tool.name],
                                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                            )
                            .optional()?;

                        let schema_str = serde_json::to_string(&tool.input_schema)?;
                        let warnings_str = serde_json::to_string(&tool.poison_warnings)?;

                        match existing {
                            None => {
                                tx.execute(
                                    "INSERT INTO tool_definitions
                                     (server_id, name, description, input_schema_json, schema_hash, first_seen, last_seen, changed_count, poison_warnings_json)
                                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6, 0, ?7)",
                                    params![
                                        server_id,
                                        tool.name,
                                        tool.description,
                                        schema_str,
                                        tool.schema_hash,
                                        now,
                                        warnings_str
                                    ],
                                )?;
                                tx.execute(
                                    "INSERT INTO tool_schema_history
                                     (server_id, name, description, input_schema_json, schema_hash, recorded_at)
                                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                                    params![
                                        server_id,
                                        tool.name,
                                        tool.description,
                                        schema_str,
                                        tool.schema_hash,
                                        now
                                    ],
                                )?;
                            }
                            Some((prev_desc, prev_hash, prev_count)) => {
                                if prev_hash != tool.schema_hash {
                                    let new_count = prev_count + 1;
                                    tx.execute(
                                        "UPDATE tool_definitions SET
                                           description = ?3,
                                           input_schema_json = ?4,
                                           schema_hash = ?5,
                                           last_seen = ?6,
                                           changed_count = ?7,
                                           previous_description = ?8,
                                           previous_schema_hash = ?9,
                                           poison_warnings_json = ?10
                                         WHERE server_id = ?1 AND name = ?2",
                                        params![
                                            server_id,
                                            tool.name,
                                            tool.description,
                                            schema_str,
                                            tool.schema_hash,
                                            now,
                                            new_count,
                                            prev_desc,
                                            prev_hash,
                                            warnings_str
                                        ],
                                    )?;
                                    tx.execute(
                                        "INSERT INTO tool_schema_history
                                         (server_id, name, description, input_schema_json, schema_hash, recorded_at)
                                         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                                        params![
                                            server_id,
                                            tool.name,
                                            tool.description,
                                            schema_str,
                                            tool.schema_hash,
                                            now
                                        ],
                                    )?;
                                } else {
                                    tx.execute(
                                        "UPDATE tool_definitions SET last_seen = ?3, poison_warnings_json = ?4 WHERE server_id = ?1 AND name = ?2",
                                        params![server_id, tool.name, now, warnings_str],
                                    )?;
                                }
                            }
                        }
                    }
                }
                WorkbenchEvent::SpanRecorded {
                    span,
                    session_id,
                    run_label,
                    mcp_messages,
                    model_call,
                    policy_decisions,
                } => {
                    let run_id = Self::resolve_or_create_run(
                        &tx,
                        session_id,
                        &span.run_id,
                        run_label.as_deref(),
                        span.start_ns,
                        self.idle_run_gap_secs,
                    )?;

                    let attr_str = if self.capture_level == CaptureLevel::Off {
                        "{}".to_string()
                    } else {
                        serde_json::to_string(&span.attributes)?
                    };

                    let norm_trace_id = normalize_trace_id(&span.trace_id);
                    let norm_span_id = normalize_span_id(&span.id);
                    let norm_parent_id = span.parent_id.as_deref().map(normalize_span_id);

                    tx.execute(
                        "INSERT OR REPLACE INTO spans (id, trace_id, run_id, parent_id, kind, name, start_ns, end_ns, status, attributes_json)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                        params![
                            norm_span_id,
                            norm_trace_id,
                            run_id,
                            norm_parent_id,
                            span.kind.as_str(),
                            span.name,
                            span.start_ns as i64,
                            span.end_ns.map(|n| n as i64),
                            span.status.as_str(),
                            attr_str,
                        ],
                    )?;

                    let is_err = matches!(span.status, SpanStatus::Error | SpanStatus::Blocked);
                    let now_str = Utc::now().to_rfc3339();
                    tx.execute(
                        "UPDATE runs SET
                           last_activity_ns = MAX(last_activity_ns, ?2),
                           ended_at = ?3,
                           status = CASE WHEN ?4 THEN 'error' ELSE status END
                         WHERE id = ?1",
                        params![
                            run_id,
                            span.end_ns.unwrap_or(span.start_ns) as i64,
                            now_str,
                            is_err
                        ],
                    )?;

                    for msg in mcp_messages {
                        let (payload_ref, inline_payload) =
                            if self.capture_level == CaptureLevel::Full {
                                Self::store_payload(&tx, msg.payload.as_deref())?
                            } else {
                                (None, None)
                            };
                        let method_col = if self.capture_level == CaptureLevel::Off {
                            None
                        } else {
                            msg.method.clone()
                        };
                        let id_col = if self.capture_level == CaptureLevel::Off {
                            None
                        } else {
                            msg.jsonrpc_id.clone()
                        };
                        tx.execute(
                            "INSERT INTO mcp_messages (span_id, direction, jsonrpc_id, method, payload_ref, inline_payload, bytes, timestamp_ns)
                             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                            params![
                                norm_span_id,
                                msg.direction.as_str(),
                                id_col,
                                method_col,
                                payload_ref,
                                inline_payload,
                                msg.bytes as i64,
                                msg.timestamp_ns as i64,
                            ],
                        )?;
                    }

                    if let Some(mc) = model_call {
                        let (req_ref, req_inline) = if self.capture_level == CaptureLevel::Full {
                            Self::store_payload(&tx, mc.request_payload.as_deref())?
                        } else {
                            (None, None)
                        };
                        let (resp_ref, resp_inline) = if self.capture_level == CaptureLevel::Full {
                            Self::store_payload(&tx, mc.response_payload.as_deref())?
                        } else {
                            (None, None)
                        };
                        let cb_json = serde_json::to_string(&mc.context_breakdown)?;
                        tx.execute(
                            "INSERT OR REPLACE INTO model_calls
                             (span_id, provider, model, input_tokens, output_tokens, cached_tokens, cost_usd, cost_estimated, finish_reason, context_breakdown_json, request_payload_ref, request_inline, response_payload_ref, response_inline)
                             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
                            params![
                                span.id,
                                mc.provider,
                                mc.model,
                                mc.input_tokens as i64,
                                mc.output_tokens as i64,
                                mc.cached_tokens as i64,
                                mc.cost_usd,
                                if mc.cost_estimated { 1 } else { 0 },
                                mc.finish_reason,
                                cb_json,
                                req_ref,
                                req_inline,
                                resp_ref,
                                resp_inline,
                            ],
                        )?;

                        let call_tokens = (mc.input_tokens + mc.output_tokens) as i64;
                        tx.execute(
                            "UPDATE runs SET
                               total_cost_usd = total_cost_usd + ?2,
                               total_tokens = total_tokens + ?3,
                               estimated_cost = CASE WHEN ?4 THEN 1 ELSE estimated_cost END
                             WHERE id = ?1",
                            params![run_id, mc.cost_usd, call_tokens, mc.cost_estimated],
                        )?;
                    }

                    for pd in policy_decisions {
                        tx.execute(
                            "INSERT INTO policy_decisions (rule_id, span_id, server_id, tool_name, verdict, reason, timestamp_ns)
                             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                            params![
                                pd.rule_id,
                                span.id,
                                pd.server_id,
                                pd.tool_name,
                                pd.verdict,
                                pd.reason,
                                pd.timestamp_ns as i64
                            ],
                        )?;
                    }
                }
                WorkbenchEvent::SpanUpdated {
                    span_id,
                    end_ns,
                    status,
                    attributes_patch,
                    response_message,
                } => {
                    let existing: Option<(String, String)> = tx
                        .query_row(
                            "SELECT run_id, attributes_json FROM spans WHERE id = ?1",
                            params![span_id],
                            |row| Ok((row.get(0)?, row.get(1)?)),
                        )
                        .optional()?;

                    if let Some((run_id, attr_json)) = existing {
                        let mut attrs: BTreeMap<String, Value> =
                            serde_json::from_str(&attr_json).unwrap_or_default();
                        if self.capture_level != CaptureLevel::Off {
                            for (k, v) in attributes_patch {
                                attrs.insert(k.clone(), v.clone());
                            }
                        }
                        let new_attr_json = serde_json::to_string(&attrs)?;
                        tx.execute(
                            "UPDATE spans SET end_ns = ?2, status = ?3, attributes_json = ?4 WHERE id = ?1",
                            params![span_id, *end_ns as i64, status.as_str(), new_attr_json],
                        )?;

                        let is_err = matches!(status, SpanStatus::Error | SpanStatus::Blocked);
                        let now_str = Utc::now().to_rfc3339();
                        tx.execute(
                            "UPDATE runs SET
                               last_activity_ns = MAX(last_activity_ns, ?2),
                               ended_at = ?3,
                               status = CASE WHEN ?4 THEN 'error' ELSE status END
                             WHERE id = ?1",
                            params![run_id, *end_ns as i64, now_str, is_err],
                        )?;
                    }

                    if let Some(msg) = response_message {
                        let (payload_ref, inline_payload) =
                            if self.capture_level == CaptureLevel::Full {
                                Self::store_payload(&tx, msg.payload.as_deref())?
                            } else {
                                (None, None)
                            };
                        tx.execute(
                            "INSERT INTO mcp_messages (span_id, direction, jsonrpc_id, method, payload_ref, inline_payload, bytes, timestamp_ns)
                             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                            params![
                                span_id,
                                msg.direction.as_str(),
                                msg.jsonrpc_id,
                                msg.method,
                                payload_ref,
                                inline_payload,
                                msg.bytes as i64,
                                msg.timestamp_ns as i64,
                            ],
                        )?;
                    }
                }
                WorkbenchEvent::PolicyEvaluated { decision } => {
                    tx.execute(
                        "INSERT INTO policy_decisions (rule_id, span_id, server_id, tool_name, verdict, reason, timestamp_ns)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                        params![
                            decision.rule_id,
                            decision.span_id,
                            decision.server_id,
                            decision.tool_name,
                            decision.verdict,
                            decision.reason,
                            decision.timestamp_ns as i64
                        ],
                    )?;
                }
            }
        }

        tx.commit()?;
        Ok(())
    }

    pub fn list_servers(&self) -> Result<Vec<McpServer>> {
        let conn = self.read_conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT s.id, s.transport, s.command_or_url, s.command_argv_json, s.protocol_versions_json, s.deprecated_features_json, s.first_seen, s.last_seen,
                    (SELECT COUNT(*) FROM tool_definitions t WHERE t.server_id = s.id) as tool_count,
                    (SELECT COALESCE(SUM(changed_count), 0) FROM tool_definitions t WHERE t.server_id = s.id) as schema_changes
             FROM mcp_servers s
             ORDER BY s.id ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            let a_json: String = row.get(3)?;
            let v_json: String = row.get(4)?;
            let d_json: String = row.get(5)?;
            Ok(McpServer {
                id: row.get(0)?,
                transport: row.get(1)?,
                command_or_url: row.get(2)?,
                command_argv: serde_json::from_str(&a_json).unwrap_or_default(),
                protocol_versions_seen: serde_json::from_str(&v_json).unwrap_or_default(),
                deprecated_features_seen: serde_json::from_str(&d_json).unwrap_or_default(),
                first_seen: row.get(6)?,
                last_seen: row.get(7)?,
                tool_count: row.get::<_, i64>(8)? as usize,
                schema_changes: row.get::<_, i64>(9)? as usize,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn get_server_tools(&self, server_id: &str) -> Result<Vec<ToolDefinition>> {
        let conn = self.read_conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT server_id, name, description, input_schema_json, schema_hash, first_seen, last_seen, changed_count, previous_description, previous_schema_hash, poison_warnings_json
             FROM tool_definitions
             WHERE server_id = ?1
             ORDER BY name ASC",
        )?;
        let rows = stmt.query_map(params![server_id], |row| {
            let schema_str: String = row.get(3)?;
            let warnings_str: String = row.get(10)?;
            Ok(ToolDefinition {
                server_id: row.get(0)?,
                name: row.get(1)?,
                description: row.get(2)?,
                input_schema: serde_json::from_str(&schema_str).unwrap_or(json!({})),
                schema_hash: row.get(4)?,
                first_seen: row.get(5)?,
                last_seen: row.get(6)?,
                changed_count: row.get::<_, u32>(7)?,
                previous_description: row.get(8)?,
                previous_schema_hash: row.get(9)?,
                poison_warnings: serde_json::from_str(&warnings_str).unwrap_or_default(),
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn get_tool_schema_history(
        &self,
        server_id: &str,
        tool_name: Option<&str>,
    ) -> Result<Vec<ToolSchemaChange>> {
        let conn = self.read_conn.lock().unwrap();
        let mut out = Vec::new();
        if let Some(name) = tool_name {
            let mut stmt = conn.prepare(
                "SELECT id, server_id, name, description, input_schema_json, schema_hash, recorded_at
                 FROM tool_schema_history WHERE server_id = ?1 AND name = ?2 ORDER BY id DESC",
            )?;
            let rows = stmt.query_map(params![server_id, name], |row| {
                let s_str: String = row.get(4)?;
                Ok(ToolSchemaChange {
                    id: row.get(0)?,
                    server_id: row.get(1)?,
                    name: row.get(2)?,
                    description: row.get(3)?,
                    input_schema: serde_json::from_str(&s_str).unwrap_or(json!({})),
                    schema_hash: row.get(5)?,
                    recorded_at: row.get(6)?,
                })
            })?;
            for r in rows {
                out.push(r?);
            }
        } else {
            let mut stmt = conn.prepare(
                "SELECT id, server_id, name, description, input_schema_json, schema_hash, recorded_at
                 FROM tool_schema_history WHERE server_id = ?1 ORDER BY id DESC",
            )?;
            let rows = stmt.query_map(params![server_id], |row| {
                let s_str: String = row.get(4)?;
                Ok(ToolSchemaChange {
                    id: row.get(0)?,
                    server_id: row.get(1)?,
                    name: row.get(2)?,
                    description: row.get(3)?,
                    input_schema: serde_json::from_str(&s_str).unwrap_or(json!({})),
                    schema_hash: row.get(5)?,
                    recorded_at: row.get(6)?,
                })
            })?;
            for r in rows {
                out.push(r?);
            }
        }
        Ok(out)
    }

    pub fn list_runs(&self, since: Option<&str>, status: Option<&str>) -> Result<Vec<Run>> {
        let conn = self.read_conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT r.id, r.session_id, r.label, r.status, r.started_at, r.ended_at, r.total_cost_usd, r.total_tokens, r.estimated_cost,
                    (SELECT COUNT(*) FROM spans s WHERE s.run_id = r.id) as span_count,
                    (SELECT COUNT(*) FROM spans s WHERE s.run_id = r.id AND s.status IN ('error', 'blocked')) as error_count
             FROM runs r
             WHERE (?1 IS NULL OR r.started_at >= ?1)
               AND (?2 IS NULL OR r.status = ?2)
             ORDER BY r.started_at DESC",
        )?;
        let rows = stmt.query_map(params![since, status], |row| {
            Ok(Run {
                id: row.get(0)?,
                session_id: row.get(1)?,
                label: row.get(2)?,
                status: row.get(3)?,
                started_at: row.get(4)?,
                ended_at: row.get(5)?,
                total_cost_usd: row.get(6)?,
                total_tokens: row.get::<_, i64>(7)? as u64,
                estimated_cost: row.get::<_, i64>(8)? != 0,
                span_count: row.get::<_, i64>(9)? as u64,
                error_count: row.get::<_, i64>(10)? as u64,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn get_run(&self, run_id: &str) -> Result<Option<Run>> {
        let conn = self.read_conn.lock().unwrap();
        let run = conn
            .query_row(
                "SELECT r.id, r.session_id, r.label, r.status, r.started_at, r.ended_at, r.total_cost_usd, r.total_tokens, r.estimated_cost,
                        (SELECT COUNT(*) FROM spans s WHERE s.run_id = r.id) as span_count,
                        (SELECT COUNT(*) FROM spans s WHERE s.run_id = r.id AND s.status IN ('error', 'blocked')) as error_count
                 FROM runs r
                 WHERE r.id = ?1",
                params![run_id],
                |row| {
                    Ok(Run {
                        id: row.get(0)?,
                        session_id: row.get(1)?,
                        label: row.get(2)?,
                        status: row.get(3)?,
                        started_at: row.get(4)?,
                        ended_at: row.get(5)?,
                        total_cost_usd: row.get(6)?,
                        total_tokens: row.get::<_, i64>(7)? as u64,
                        estimated_cost: row.get::<_, i64>(8)? != 0,
                        span_count: row.get::<_, i64>(9)? as u64,
                        error_count: row.get::<_, i64>(10)? as u64,
                    })
                },
            )
            .optional()?;
        Ok(run)
    }

    pub fn get_run_spans(&self, run_id: &str) -> Result<Vec<Span>> {
        let conn = self.read_conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, trace_id, run_id, parent_id, kind, name, start_ns, end_ns, status, attributes_json
             FROM spans
             WHERE run_id = ?1
             ORDER BY start_ns ASC",
        )?;
        let rows = stmt.query_map(params![run_id], |row| {
            let kind_str: String = row.get(4)?;
            let status_str: String = row.get(8)?;
            let attr_str: String = row.get(9)?;
            Ok(Span {
                id: row.get(0)?,
                trace_id: row.get(1)?,
                run_id: row.get(2)?,
                parent_id: row.get(3)?,
                kind: SpanKind::from_str_lossy(&kind_str),
                name: row.get(5)?,
                start_ns: row.get::<_, i64>(6)? as u64,
                end_ns: row.get::<_, Option<i64>>(7)?.map(|v| v as u64),
                status: SpanStatus::from_str_lossy(&status_str),
                attributes: serde_json::from_str(&attr_str).unwrap_or_default(),
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn get_span_detail(&self, span_id: &str) -> Result<Option<SpanDetail>> {
        let conn = self.read_conn.lock().unwrap();
        let Some(span) = conn
            .query_row(
                "SELECT id, trace_id, run_id, parent_id, kind, name, start_ns, end_ns, status, attributes_json
                 FROM spans WHERE id = ?1",
                params![span_id],
                |row| {
                    let kind_str: String = row.get(4)?;
                    let status_str: String = row.get(8)?;
                    let attr_str: String = row.get(9)?;
                    Ok(Span {
                        id: row.get(0)?,
                        trace_id: row.get(1)?,
                        run_id: row.get(2)?,
                        parent_id: row.get(3)?,
                        kind: SpanKind::from_str_lossy(&kind_str),
                        name: row.get(5)?,
                        start_ns: row.get::<_, i64>(6)? as u64,
                        end_ns: row.get::<_, Option<i64>>(7)?.map(|v| v as u64),
                        status: SpanStatus::from_str_lossy(&status_str),
                        attributes: serde_json::from_str(&attr_str).unwrap_or_default(),
                    })
                },
            )
            .optional()?
        else {
            return Ok(None);
        };

        let mut msg_stmt = conn.prepare(
            "SELECT id, span_id, direction, jsonrpc_id, method, payload_ref, inline_payload, bytes, timestamp_ns
             FROM mcp_messages WHERE span_id = ?1 ORDER BY timestamp_ns ASC, id ASC",
        )?;
        let msg_rows = msg_stmt.query_map(params![span_id], |row| {
            let dir_str: String = row.get(2)?;
            let p_ref: Option<String> = row.get(5)?;
            let p_inline: Option<String> = row.get(6)?;
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                MessageDirection::from_str_lossy(&dir_str),
                row.get::<_, Option<String>>(3)?,
                row.get::<_, Option<String>>(4)?,
                p_ref,
                p_inline,
                row.get::<_, i64>(7)? as usize,
                row.get::<_, i64>(8)? as u64,
            ))
        })?;
        let mut mcp_messages = Vec::new();
        for mr in msg_rows {
            let (id, s_id, direction, jsonrpc_id, method, p_ref, p_inline, bytes, timestamp_ns) =
                mr?;
            let payload = Self::load_payload(&conn, p_ref, p_inline);
            mcp_messages.push(McpMessage {
                id,
                span_id: s_id,
                direction,
                jsonrpc_id,
                method,
                payload,
                bytes,
                timestamp_ns,
            });
        }

        let model_call_raw = conn
            .query_row(
                "SELECT provider, model, input_tokens, output_tokens, cached_tokens, cost_usd, cost_estimated, finish_reason, context_breakdown_json, request_payload_ref, request_inline, response_payload_ref, response_inline
                 FROM model_calls WHERE span_id = ?1",
                params![span_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)? as u64,
                        row.get::<_, i64>(3)? as u64,
                        row.get::<_, i64>(4)? as u64,
                        row.get::<_, f64>(5)?,
                        row.get::<_, i64>(6)? != 0,
                        row.get::<_, Option<String>>(7)?,
                        row.get::<_, String>(8)?,
                        row.get::<_, Option<String>>(9)?,
                        row.get::<_, Option<String>>(10)?,
                        row.get::<_, Option<String>>(11)?,
                        row.get::<_, Option<String>>(12)?,
                    ))
                },
            )
            .optional()?;

        let model_call = model_call_raw.map(
            |(
                provider,
                model,
                input_tokens,
                output_tokens,
                cached_tokens,
                cost_usd,
                cost_estimated,
                finish_reason,
                cb_json,
                req_ref,
                req_inline,
                resp_ref,
                resp_inline,
            )| {
                let request_payload = Self::load_payload(&conn, req_ref, req_inline);
                let response_payload = Self::load_payload(&conn, resp_ref, resp_inline);
                ModelCall {
                    span_id: span_id.to_string(),
                    provider,
                    model,
                    input_tokens,
                    output_tokens,
                    cached_tokens,
                    cost_usd,
                    cost_estimated,
                    finish_reason,
                    context_breakdown: serde_json::from_str(&cb_json).unwrap_or_default(),
                    request_payload,
                    response_payload,
                }
            },
        );

        let mut pd_stmt = conn.prepare(
            "SELECT id, rule_id, span_id, server_id, tool_name, verdict, reason, timestamp_ns
             FROM policy_decisions WHERE span_id = ?1 ORDER BY id ASC",
        )?;
        let pd_rows = pd_stmt.query_map(params![span_id], |row| {
            Ok(PolicyDecision {
                id: row.get(0)?,
                rule_id: row.get(1)?,
                span_id: row.get(2)?,
                server_id: row.get(3)?,
                tool_name: row.get(4)?,
                verdict: row.get(5)?,
                reason: row.get(6)?,
                timestamp_ns: row.get::<_, i64>(7)? as u64,
            })
        })?;
        let mut policy_decisions = Vec::new();
        for pr in pd_rows {
            policy_decisions.push(pr?);
        }

        let mut ann_stmt = conn.prepare(
            "SELECT id, target_id, author, text, created_at FROM annotations WHERE target_id = ?1 ORDER BY id ASC",
        )?;
        let ann_rows = ann_stmt.query_map(params![span_id], |row| {
            Ok(Annotation {
                id: row.get(0)?,
                target_id: row.get(1)?,
                author: row.get(2)?,
                text: row.get(3)?,
                created_at: row.get(4)?,
            })
        })?;
        let mut annotations = Vec::new();
        for ar in ann_rows {
            annotations.push(ar?);
        }

        Ok(Some(SpanDetail {
            span,
            mcp_messages,
            model_call,
            policy_decisions,
            annotations,
        }))
    }

    pub fn get_run_xray(&self, run_id: &str) -> Result<Vec<ModelCall>> {
        let spans = self.get_run_spans(run_id)?;
        let mut out = Vec::new();
        for sp in spans {
            if sp.kind == SpanKind::Llm {
                if let Some(detail) = self.get_span_detail(&sp.id)? {
                    if let Some(mc) = detail.model_call {
                        out.push(mc);
                    }
                }
            }
        }
        Ok(out)
    }

    pub fn add_annotation(&self, target_id: &str, author: &str, text: &str) -> Result<Annotation> {
        let conn = self.write_conn.lock().unwrap();
        let created_at = Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO annotations (target_id, author, text, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![target_id, author, text, created_at],
        )?;
        let id = conn.last_insert_rowid();
        Ok(Annotation {
            id,
            target_id: target_id.to_string(),
            author: author.to_string(),
            text: text.to_string(),
            created_at,
        })
    }

    pub fn list_annotations(&self, target_id: &str) -> Result<Vec<Annotation>> {
        let conn = self.read_conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, target_id, author, text, created_at FROM annotations WHERE target_id = ?1 ORDER BY id ASC",
        )?;
        let rows = stmt.query_map(params![target_id], |row| {
            Ok(Annotation {
                id: row.get(0)?,
                target_id: row.get(1)?,
                author: row.get(2)?,
                text: row.get(3)?,
                created_at: row.get(4)?,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn list_policy_decisions(&self, limit: usize) -> Result<Vec<PolicyDecision>> {
        let conn = self.read_conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, rule_id, span_id, server_id, tool_name, verdict, reason, timestamp_ns
             FROM policy_decisions ORDER BY id DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], |row| {
            Ok(PolicyDecision {
                id: row.get(0)?,
                rule_id: row.get(1)?,
                span_id: row.get(2)?,
                server_id: row.get(3)?,
                tool_name: row.get(4)?,
                verdict: row.get(5)?,
                reason: row.get(6)?,
                timestamp_ns: row.get::<_, i64>(7)? as u64,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Compares two runs side-by-side and highlights the first divergence (F-14, UC-04).
    pub fn diff_runs(&self, left_run_id: &str, right_run_id: &str) -> Result<RunDiff> {
        let left_run = self
            .get_run(left_run_id)?
            .with_context(|| format!("Run '{}' not found", left_run_id))?;
        let right_run = self
            .get_run(right_run_id)?
            .with_context(|| format!("Run '{}' not found", right_run_id))?;

        let left_spans = self.get_run_spans(left_run_id)?;
        let right_spans = self.get_run_spans(right_run_id)?;

        let max_len = left_spans.len().max(right_spans.len());
        let mut entries = Vec::with_capacity(max_len);
        let mut first_divergence_index = None;
        let mut first_divergence_reason = None;

        for idx in 0..max_len {
            let l = left_spans.get(idx).cloned();
            let r = right_spans.get(idx).cloned();
            let mut diverged = false;
            let mut reason = None;

            match (&l, &r) {
                (Some(ls), Some(rs)) => {
                    if ls.kind != rs.kind {
                        diverged = true;
                        reason = Some(format!(
                            "Span kind changed from '{}' to '{}'",
                            ls.kind.as_str(),
                            rs.kind.as_str()
                        ));
                    } else if ls.name != rs.name {
                        diverged = true;
                        reason = Some(format!(
                            "Step name / tool choice diverged: '{}' vs '{}'",
                            ls.name, rs.name
                        ));
                    } else if ls.attributes.get(semconv::GEN_AI_TOOL_NAME)
                        != rs.attributes.get(semconv::GEN_AI_TOOL_NAME)
                    {
                        diverged = true;
                        reason = Some(format!(
                            "Tool name diverged: {:?} vs {:?}",
                            ls.attributes.get(semconv::GEN_AI_TOOL_NAME),
                            rs.attributes.get(semconv::GEN_AI_TOOL_NAME)
                        ));
                    } else if ls.status != rs.status {
                        diverged = true;
                        reason = Some(format!(
                            "Status diverged: '{}' vs '{}'",
                            ls.status.as_str(),
                            rs.status.as_str()
                        ));
                    } else if ls.attributes.get(semconv::GEN_AI_TOOL_CALL_ARGUMENTS)
                        != rs.attributes.get(semconv::GEN_AI_TOOL_CALL_ARGUMENTS)
                    {
                        diverged = true;
                        reason = Some("Tool call arguments diverged".to_string());
                    }
                }
                (Some(ls), None) => {
                    diverged = true;
                    reason = Some(format!("Right run ended early (left has '{}')", ls.name));
                }
                (None, Some(rs)) => {
                    diverged = true;
                    reason = Some(format!("Left run ended early (right has '{}')", rs.name));
                }
                (None, None) => {}
            }

            if diverged && first_divergence_index.is_none() {
                first_divergence_index = Some(idx);
                first_divergence_reason = reason.clone();
            }

            entries.push(SpanDiffEntry {
                step_index: idx,
                left_span: l,
                right_span: r,
                diverged,
                divergence_reason: reason,
            });
        }

        Ok(RunDiff {
            left_run,
            right_run,
            first_divergence_index,
            first_divergence_reason,
            entries,
        })
    }

    /// Exports selected runs to JSONL format (F-09, UC-10).
    pub fn export_jsonl(&self, run_ids: &[String]) -> Result<String> {
        let target_runs = if run_ids.is_empty() {
            self.list_runs(None, None)?
        } else {
            let mut v = Vec::new();
            for id in run_ids {
                if let Some(r) = self.get_run(id)? {
                    v.push(r);
                }
            }
            v
        };

        let mut lines = Vec::new();
        for run in target_runs {
            lines.push(serde_json::to_string(&json!({
                "record_type": "run",
                "run": run,
            }))?);
            let spans = self.get_run_spans(&run.id)?;
            for sp in spans {
                if let Some(detail) = self.get_span_detail(&sp.id)? {
                    lines.push(serde_json::to_string(&json!({
                        "record_type": "span_detail",
                        "detail": detail,
                    }))?);
                }
            }
        }
        Ok(lines.join("\n"))
    }

    /// Imports a JSONL export into the local trace store (UC-10).
    pub fn import_jsonl(&self, jsonl_content: &str) -> Result<usize> {
        let mut imported_runs = 0;
        let mut conn = self.write_conn.lock().unwrap();
        let tx = conn.transaction()?;

        for line in jsonl_content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let val: Value = serde_json::from_str(trimmed)?;
            match val.get("record_type").and_then(|v| v.as_str()) {
                Some("run") => {
                    let run: Run = serde_json::from_value(val["run"].clone())?;
                    tx.execute(
                        "INSERT OR IGNORE INTO sessions (id, started_at) VALUES (?1, ?2)",
                        params![run.session_id, run.started_at],
                    )?;
                    tx.execute(
                        "INSERT OR REPLACE INTO runs (id, session_id, label, status, started_at, ended_at, total_cost_usd, total_tokens, estimated_cost)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                        params![
                            run.id,
                            run.session_id,
                            run.label,
                            run.status,
                            run.started_at,
                            run.ended_at,
                            run.total_cost_usd,
                            run.total_tokens as i64,
                            if run.estimated_cost { 1 } else { 0 },
                        ],
                    )?;
                    imported_runs += 1;
                }
                Some("span_detail") => {
                    let detail: SpanDetail = serde_json::from_value(val["detail"].clone())?;
                    let sp = detail.span;
                    let attr_str = serde_json::to_string(&sp.attributes)?;
                    let norm_trace = normalize_trace_id(&sp.trace_id);
                    tx.execute(
                        "INSERT OR REPLACE INTO spans (id, trace_id, run_id, parent_id, kind, name, start_ns, end_ns, status, attributes_json)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                        params![
                            sp.id,
                            norm_trace,
                            sp.run_id,
                            sp.parent_id,
                            sp.kind.as_str(),
                            sp.name,
                            sp.start_ns as i64,
                            sp.end_ns.map(|e| e as i64),
                            sp.status.as_str(),
                            attr_str,
                        ],
                    )?;
                    for msg in detail.mcp_messages {
                        let (p_ref, p_inline) = Self::store_payload(&tx, msg.payload.as_deref())?;
                        tx.execute(
                            "INSERT INTO mcp_messages (span_id, direction, jsonrpc_id, method, payload_ref, inline_payload, bytes, timestamp_ns)
                             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                            params![
                                sp.id,
                                msg.direction.as_str(),
                                msg.jsonrpc_id,
                                msg.method,
                                p_ref,
                                p_inline,
                                msg.bytes as i64,
                                msg.timestamp_ns as i64,
                            ],
                        )?;
                    }
                    if let Some(mc) = detail.model_call {
                        let (req_ref, req_inline) =
                            Self::store_payload(&tx, mc.request_payload.as_deref())?;
                        let (resp_ref, resp_inline) =
                            Self::store_payload(&tx, mc.response_payload.as_deref())?;
                        let cb_json = serde_json::to_string(&mc.context_breakdown)?;
                        tx.execute(
                            "INSERT OR REPLACE INTO model_calls
                             (span_id, provider, model, input_tokens, output_tokens, cached_tokens, cost_usd, cost_estimated, finish_reason, context_breakdown_json, request_payload_ref, request_inline, response_payload_ref, response_inline)
                             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
                            params![
                                sp.id,
                                mc.provider,
                                mc.model,
                                mc.input_tokens as i64,
                                mc.output_tokens as i64,
                                mc.cached_tokens as i64,
                                mc.cost_usd,
                                if mc.cost_estimated { 1 } else { 0 },
                                mc.finish_reason,
                                cb_json,
                                req_ref,
                                req_inline,
                                resp_ref,
                                resp_inline,
                            ],
                        )?;
                    }
                }
                _ => {}
            }
        }
        tx.commit()?;
        Ok(imported_runs)
    }

    /// Exports runs in standard OpenTelemetry OTLP/JSON `resourceSpans` structure (F-09, §14.5)
    /// compatible out of the box with Jaeger and standard OTLP collectors.
    pub fn export_otlp(&self, run_ids: &[String]) -> Result<Value> {
        let target_runs = if run_ids.is_empty() {
            self.list_runs(None, None)?
        } else {
            let mut v = Vec::new();
            for id in run_ids {
                if let Some(r) = self.get_run(id)? {
                    v.push(r);
                }
            }
            v
        };

        let mut otlp_spans = Vec::new();
        for run in target_runs {
            let spans = self.get_run_spans(&run.id)?;
            for sp in spans {
                let trace_id_hex = normalize_trace_id(&sp.trace_id);
                let span_id_hex = normalize_span_id(&sp.id);
                let parent_id_hex = sp
                    .parent_id
                    .as_deref()
                    .map(normalize_span_id)
                    .unwrap_or_default();

                let mut attributes = vec![
                    json!({
                        "key": "workbench.run_id",
                        "value": { "stringValue": sp.run_id }
                    }),
                    json!({
                        "key": "workbench.span.kind",
                        "value": { "stringValue": sp.kind.as_str() }
                    }),
                ];

                for (k, v) in &sp.attributes {
                    let otlp_val = match v {
                        Value::String(s) => json!({ "stringValue": s }),
                        Value::Number(n) => {
                            if let Some(i) = n.as_i64() {
                                json!({ "intValue": i.to_string() })
                            } else if let Some(f) = n.as_f64() {
                                json!({ "doubleValue": f })
                            } else {
                                json!({ "stringValue": n.to_string() })
                            }
                        }
                        Value::Bool(b) => json!({ "boolValue": b }),
                        other => json!({ "stringValue": other.to_string() }),
                    };
                    attributes.push(json!({
                        "key": k,
                        "value": otlp_val,
                    }));
                }

                let status_code = match sp.status {
                    SpanStatus::Ok => 1,
                    SpanStatus::Error | SpanStatus::Blocked => 2,
                    _ => 0,
                };

                otlp_spans.push(json!({
                    "traceId": trace_id_hex,
                    "spanId": span_id_hex,
                    "parentSpanId": parent_id_hex,
                    "name": sp.name,
                    "kind": 3, // SPAN_KIND_CLIENT
                    "startTimeUnixNano": sp.start_ns.to_string(),
                    "endTimeUnixNano": sp.end_ns.unwrap_or(sp.start_ns).to_string(),
                    "attributes": attributes,
                    "status": {
                        "code": status_code,
                        "message": sp.status.as_str()
                    }
                }));
            }
        }

        Ok(json!({
            "resourceSpans": [
                {
                    "resource": {
                        "attributes": [
                            {
                                "key": "service.name",
                                "value": { "stringValue": "mcp-agent-workbench" }
                            },
                            {
                                "key": "service.version",
                                "value": { "stringValue": env!("CARGO_PKG_VERSION") }
                            }
                        ]
                    },
                    "scopeSpans": [
                        {
                            "scope": {
                                "name": "mcpaw.tracer",
                                "version": env!("CARGO_PKG_VERSION")
                            },
                            "spans": otlp_spans
                        }
                    ]
                }
            ]
        }))
    }

    /// Exports deterministic tool call/response fixtures for MockMCP Studio (F-15).
    pub fn export_mockmcp(&self, run_ids: &[String]) -> Result<Value> {
        let target_runs = if run_ids.is_empty() {
            self.list_runs(None, None)?
        } else {
            let mut v = Vec::new();
            for id in run_ids {
                if let Some(r) = self.get_run(id)? {
                    v.push(r);
                }
            }
            v
        };

        let mut fixtures = Vec::new();
        for run in target_runs {
            let spans = self.get_run_spans(&run.id)?;
            for sp in spans {
                if sp.kind != SpanKind::Mcp {
                    continue;
                }
                if let Some(detail) = self.get_span_detail(&sp.id)? {
                    let req = detail
                        .mcp_messages
                        .iter()
                        .find(|m| m.direction == MessageDirection::ClientToServer);
                    let resp = detail
                        .mcp_messages
                        .iter()
                        .find(|m| m.direction == MessageDirection::ServerToClient);
                    fixtures.push(json!({
                        "run_id": run.id,
                        "span_id": sp.id,
                        "name": sp.name,
                        "method": sp.attributes.get(semconv::MCP_METHOD_NAME),
                        "tool_name": sp.attributes.get(semconv::GEN_AI_TOOL_NAME),
                        "server_id": sp.attributes.get(semconv::MCP_SERVER_ID),
                        "request_payload": req.and_then(|r| r.payload.clone()),
                        "response_payload": resp.and_then(|r| r.payload.clone()),
                        "duration_ms": sp.duration_ms(),
                        "status": sp.status.as_str(),
                    }));
                }
            }
        }

        Ok(json!({
            "format": "mockmcp-studio-v1",
            "generated_at": Utc::now().to_rfc3339(),
            "fixtures": fixtures
        }))
    }

    /// Ingests external agent-emitted OTel spans and joins them by `trace_id` (F-16).
    pub fn ingest_otel_spans(&self, payload: &Value) -> Result<usize> {
        let mut count = 0;
        let Some(resource_spans) = payload.get("resourceSpans").and_then(|v| v.as_array()) else {
            return Ok(0);
        };

        let mut conn = self.write_conn.lock().unwrap();
        let tx = conn.transaction()?;

        for rs in resource_spans {
            let Some(scope_spans) = rs.get("scopeSpans").and_then(|v| v.as_array()) else {
                continue;
            };
            for ss in scope_spans {
                let Some(spans) = ss.get("spans").and_then(|v| v.as_array()) else {
                    continue;
                };
                for sp in spans {
                    let raw_trace_id = sp
                        .get("traceId")
                        .and_then(|v| v.as_str())
                        .unwrap_or("external-trace");
                    let trace_id = normalize_trace_id(raw_trace_id);
                    let span_id = sp
                        .get("spanId")
                        .and_then(|v| v.as_str())
                        .map(String::from)
                        .unwrap_or_else(|| format!("ext-{}", Uuid::new_v4()));
                    let parent_id = sp
                        .get("parentSpanId")
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.is_empty())
                        .map(String::from);
                    let name = sp
                        .get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("external.span")
                        .to_string();
                    let start_ns: u64 = sp
                        .get("startTimeUnixNano")
                        .and_then(|v| {
                            v.as_str()
                                .and_then(|s| s.parse().ok())
                                .or_else(|| v.as_u64())
                        })
                        .unwrap_or(0);
                    let end_ns: Option<u64> = sp.get("endTimeUnixNano").and_then(|v| {
                        v.as_str()
                            .and_then(|s| s.parse().ok())
                            .or_else(|| v.as_u64())
                    });

                    let matched_run: Option<String> = tx
                        .query_row(
                            "SELECT run_id FROM spans WHERE trace_id = ?1 LIMIT 1",
                            params![trace_id],
                            |row| row.get(0),
                        )
                        .optional()?;

                    let run_id = match matched_run {
                        Some(r) => r,
                        None => Self::resolve_or_create_run(
                            &tx,
                            "otel-ingest",
                            "auto",
                            Some("otel-ingested"),
                            start_ns,
                            self.idle_run_gap_secs,
                        )?,
                    };

                    let mut attrs = BTreeMap::new();
                    attrs.insert("otel.ingested".to_string(), json!(true));
                    if let Some(attr_arr) = sp.get("attributes").and_then(|v| v.as_array()) {
                        for item in attr_arr {
                            if let Some(k) = item.get("key").and_then(|v| v.as_str()) {
                                if let Some(val_obj) = item.get("value") {
                                    let extracted = val_obj
                                        .get("stringValue")
                                        .or_else(|| val_obj.get("intValue"))
                                        .or_else(|| val_obj.get("doubleValue"))
                                        .or_else(|| val_obj.get("boolValue"))
                                        .cloned()
                                        .unwrap_or(Value::Null);
                                    attrs.insert(k.to_string(), extracted);
                                }
                            }
                        }
                    }

                    tx.execute(
                        "INSERT OR REPLACE INTO spans (id, trace_id, run_id, parent_id, kind, name, start_ns, end_ns, status, attributes_json)
                         VALUES (?1, ?2, ?3, ?4, 'mcp', ?5, ?6, ?7, 'ok', ?8)",
                        params![
                            span_id,
                            trace_id,
                            run_id,
                            parent_id,
                            name,
                            start_ns as i64,
                            end_ns.map(|e| e as i64),
                            serde_json::to_string(&attrs)?
                        ],
                    )?;
                    count += 1;
                }
            }
        }

        tx.commit()?;
        Ok(count)
    }

    /// Enforces retention age (`retention_days`) and size (`max_db_mb`) caps;
    /// oldest runs, their blobs, and their annotations are evicted first, followed by incremental vacuum (N-09, M4).
    pub fn enforce_retention(&self, retention_days: u32, max_db_mb: u64) -> Result<usize> {
        let mut evicted = 0;
        let cutoff: DateTime<Utc> = Utc::now() - Duration::days(retention_days as i64);
        let cutoff_str = cutoff.to_rfc3339();

        let mut conn = self.write_conn.lock().unwrap();
        let tx = conn.transaction()?;

        let old_run_ids: Vec<String> = {
            let mut stmt = tx.prepare("SELECT id FROM runs WHERE started_at < ?1")?;
            let rows = stmt.query_map(params![cutoff_str], |row| row.get(0))?;
            rows.filter_map(|r| r.ok()).collect()
        };

        for run_id in &old_run_ids {
            Self::delete_run_cascade(&tx, run_id)?;
            evicted += 1;
        }

        tx.commit()?;

        let max_bytes = max_db_mb.saturating_mul(1024 * 1024);
        if let Ok(meta) = std::fs::metadata(&self.db_path) {
            if meta.len() > max_bytes {
                let tx2 = conn.transaction()?;
                let oldest_runs: Vec<String> = {
                    let mut stmt =
                        tx2.prepare("SELECT id FROM runs ORDER BY started_at ASC LIMIT 20")?;
                    let rows = stmt.query_map([], |row| row.get(0))?;
                    rows.filter_map(|r| r.ok()).collect()
                };
                for run_id in oldest_runs {
                    Self::delete_run_cascade(&tx2, &run_id)?;
                    evicted += 1;
                }
                tx2.commit()?;
            }
        }

        if evicted > 0 {
            let _ = conn.execute_batch("PRAGMA incremental_vacuum;");
        }

        Ok(evicted)
    }

    fn delete_run_cascade(tx: &rusqlite::Transaction<'_>, run_id: &str) -> Result<()> {
        // M4: Delete blobs referenced by mcp_messages or model_calls in this run
        tx.execute(
            "DELETE FROM blobs WHERE id IN (
                SELECT payload_ref FROM mcp_messages WHERE payload_ref IS NOT NULL AND span_id IN (SELECT id FROM spans WHERE run_id = ?1)
                UNION
                SELECT request_payload_ref FROM model_calls WHERE request_payload_ref IS NOT NULL AND span_id IN (SELECT id FROM spans WHERE run_id = ?1)
                UNION
                SELECT response_payload_ref FROM model_calls WHERE response_payload_ref IS NOT NULL AND span_id IN (SELECT id FROM spans WHERE run_id = ?1)
            )",
            params![run_id],
        )?;
        // M4: Delete annotations attached to the run or any span in the run
        tx.execute(
            "DELETE FROM annotations WHERE target_id = ?1 OR target_id IN (SELECT id FROM spans WHERE run_id = ?1)",
            params![run_id],
        )?;
        tx.execute(
            "DELETE FROM mcp_messages WHERE span_id IN (SELECT id FROM spans WHERE run_id = ?1)",
            params![run_id],
        )?;
        tx.execute(
            "DELETE FROM model_calls WHERE span_id IN (SELECT id FROM spans WHERE run_id = ?1)",
            params![run_id],
        )?;
        tx.execute(
            "DELETE FROM policy_decisions WHERE span_id IN (SELECT id FROM spans WHERE run_id = ?1)",
            params![run_id],
        )?;
        tx.execute("DELETE FROM spans WHERE run_id = ?1", params![run_id])?;
        tx.execute("DELETE FROM runs WHERE id = ?1", params![run_id])?;
        Ok(())
    }
}
