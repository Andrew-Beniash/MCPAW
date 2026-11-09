use crate::models::ToolDefinition;
use chrono::Utc;
use regex::Regex;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::sync::LazyLock;

#[derive(Debug, Clone)]
pub enum ParsedMcpFrame {
    Request {
        /// Canonical JSON representation of `id` (`"1"` vs `"\"1\""`) so string and integer IDs never collide (M7)
        id_key: String,
        /// Exact JSON `id` value (`Value::Number` or `Value::String`)
        id_raw: Value,
        method: String,
        is_known_method: bool,
        protocol_version: Option<String>,
        protocol_era: String,
        tool_name: Option<String>,
        tool_arguments_raw: Option<String>,
        tool_arguments_canonical: Option<String>,
        task_id: Option<String>,
        is_elicitation: bool,
        deprecated_feature: Option<String>,
        traceparent: Option<String>,
        tracestate: Option<String>,
        client_name: Option<String>,
        client_version: Option<String>,
    },
    Response {
        id_key: String,
        id_raw: Value,
        is_error: bool,
        error_message: Option<String>,
        negotiated_version: Option<String>,
        capabilities_json: Option<String>,
        discovered_tools: Option<Vec<ToolDefinition>>,
        task_id: Option<String>,
        result_raw: Option<String>,
    },
    Notification {
        method: String,
        protocol_version: Option<String>,
        deprecated_feature: Option<String>,
    },
    Batch(Vec<ParsedMcpFrame>),
    Malformed,
}

pub fn compute_schema_hash(name: &str, description: &str, input_schema: &Value) -> String {
    let mut hasher = Sha256::new();
    hasher.update(name.as_bytes());
    hasher.update(b"\0");
    hasher.update(description.as_bytes());
    hasher.update(b"\0");
    let canonical_schema = canonicalize_json(input_schema);
    hasher.update(canonical_schema.as_bytes());
    hex::encode(hasher.finalize())
}

/// Produces a deterministic, key-sorted JSON string for hashing regardless of `preserve_order`.
pub fn canonicalize_json(val: &Value) -> String {
    match val {
        Value::Object(map) => {
            let mut sorted: Vec<(&String, &Value)> = map.iter().collect();
            sorted.sort_by(|(a, _), (b, _)| a.cmp(b));
            let inner: Vec<String> = sorted
                .into_iter()
                .map(|(k, v)| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(k).unwrap_or_default(),
                        canonicalize_json(v)
                    )
                })
                .collect();
            format!("{{{}}}", inner.join(","))
        }
        Value::Array(arr) => {
            let inner: Vec<String> = arr.iter().map(canonicalize_json).collect();
            format!("[{}]", inner.join(","))
        }
        other => serde_json::to_string(other).unwrap_or_default(),
    }
}

static POISON_CHECKS: LazyLock<Vec<(Regex, &'static str)>> = LazyLock::new(|| {
    let specs: &[(&str, &'static str)] = &[
        (
            r"(?i)(~/.ssh|/etc/passwd|/etc/shadow|\.env|id_rsa)",
            "References sensitive local file paths (e.g. ~/.ssh, .env)",
        ),
        (
            r"(?i)(ignore\s+(all\s+)?previous\s+instructions|do\s+not\s+tell\s+the\s+user|hide\s+this\s+from)",
            "Contains covert instruction override phrasing",
        ),
        (
            r"(?i)(also\s+send|exfiltrate|forward\s+the\s+contents\s+of|silently\s+call)",
            "Instructs model to silently exfiltrate or side-channel data",
        ),
        (
            r"(?i)(<important>|<system>|<!--|\[system\])",
            "Contains embedded pseudo-system tags or HTML comments",
        ),
    ];
    specs
        .iter()
        .filter_map(|(pat, msg)| Regex::new(pat).ok().map(|re| (re, *msg)))
        .collect()
});

/// Scans a tool description for suspicious prompt-injection / tool-poisoning signals (UC-05, Pain Point #7, M9).
pub fn scan_tool_poisoning(description: &str) -> Vec<String> {
    let mut warnings = Vec::new();
    for (re, msg) in POISON_CHECKS.iter() {
        if re.is_match(description) {
            warnings.push((*msg).to_string());
        }
    }
    warnings
}

pub fn is_known_mcp_method(method: &str) -> bool {
    matches!(
        method,
        "initialize"
            | "ping"
            | "tools/list"
            | "tools/call"
            | "resources/list"
            | "resources/read"
            | "resources/templates/list"
            | "resources/subscribe"
            | "resources/unsubscribe"
            | "prompts/list"
            | "prompts/get"
            | "completion/complete"
            | "elicitation/create"
            | "roots/list"
            | "sampling/createMessage"
            | "logging/setLevel"
            | "tasks/create"
            | "tasks/get"
            | "tasks/status"
            | "tasks/result"
            | "tasks/list"
            | "tasks/cancel"
    ) || method.starts_with("notifications/")
        || method.starts_with("$/")
        || method.starts_with("resources/")
        || method.starts_with("prompts/")
        || method.starts_with("tasks/")
        || method.starts_with("elicitation/")
        || method.starts_with("roots/")
        || method.starts_with("sampling/")
        || method.starts_with("logging/")
}

pub fn detect_deprecated_feature(method: &str) -> Option<String> {
    if method.starts_with("roots/") || method == "notifications/roots/list_changed" {
        Some("roots".to_string())
    } else if method.starts_with("sampling/") {
        Some("sampling".to_string())
    } else if method.starts_with("logging/") || method == "notifications/message" {
        Some("logging".to_string())
    } else {
        None
    }
}

/// Classifies the MCP protocol era (H8).
/// Reads `io.modelcontextprotocol/protocolVersion` or `protocolVersion` in `_meta`,
/// `MCP-Protocol-Version` HTTP header, or the negotiated `initialize` version.
/// Labels `"unknown"` when no version or `initialize` handshake is present instead of assuming stateless.
pub fn classify_protocol_era(
    method: &str,
    meta_version: Option<&str>,
    header_version: Option<&str>,
    session_has_initialize: bool,
) -> (Option<String>, String) {
    let explicit_ver = meta_version.or(header_version).map(|s| s.to_string());
    if let Some(ref v) = explicit_ver {
        if v.starts_with("2026-") {
            if session_has_initialize {
                return (Some(v.clone()), "dual".to_string());
            }
            return (Some(v.clone()), "2026-07-28 (stateless)".to_string());
        }
        if v.starts_with("2025-") {
            return (Some(v.clone()), "2025-11-25 (stateful)".to_string());
        }
        if v.starts_with("2024-") {
            return (Some(v.clone()), "2024-11-05 (legacy)".to_string());
        }
        return (Some(v.clone()), format!("{} (custom)", v));
    }
    if method == "initialize" || session_has_initialize {
        (None, "2024-11-05/2025-11-25 (stateful)".to_string())
    } else {
        (None, "unknown".to_string())
    }
}

pub fn parse_mcp_payload(
    raw: &str,
    server_id: &str,
    header_protocol_version: Option<&str>,
    session_has_initialize: bool,
) -> ParsedMcpFrame {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return ParsedMcpFrame::Malformed;
    }
    let Ok(val) = serde_json::from_str::<Value>(trimmed) else {
        return ParsedMcpFrame::Malformed;
    };
    parse_mcp_value(&val, server_id, header_protocol_version, session_has_initialize)
}

/// Canonicalizes a JSON-RPC `id` so string `"1"` (`"\"1\""`) and integer `1` (`"1"`) remain distinct (M7).
pub fn jsonrpc_id_to_key(v: &Value) -> Option<(String, Value)> {
    match v {
        Value::String(_) | Value::Number(_) => {
            let key = serde_json::to_string(v).ok()?;
            Some((key, v.clone()))
        }
        _ => None,
    }
}

/// Extracts all `tools/call` invocations from either a single JSON-RPC request object
/// OR a JSON-RPC batch array (B3: prevents batch policy bypass).
pub fn extract_tools_call_checks(raw: &str) -> Vec<(Value, String, String)> {
    let mut out = Vec::new();
    let Ok(val) = serde_json::from_str::<Value>(raw.trim()) else {
        return out;
    };
    match val {
        Value::Array(items) => {
            for item in items {
                if let Some(entry) = extract_single_tools_call(&item) {
                    out.push(entry);
                }
            }
        }
        other => {
            if let Some(entry) = extract_single_tools_call(&other) {
                out.push(entry);
            }
        }
    }
    out
}

fn extract_single_tools_call(val: &Value) -> Option<(Value, String, String)> {
    let obj = val.as_object()?;
    let method = obj.get("method")?.as_str()?;
    if method != "tools/call" {
        return None;
    }
    let id_val = obj.get("id").cloned().unwrap_or(Value::Null);
    let params = obj.get("params");
    let tool_name = params
        .and_then(|p| p.get("name"))
        .and_then(|n| n.as_str())
        .unwrap_or("")
        .to_string();
    let args_raw = params
        .and_then(|p| p.get("arguments"))
        .map(canonicalize_json)
        .unwrap_or_else(|| "{}".to_string());
    Some((id_val, tool_name, args_raw))
}

pub fn parse_mcp_value(
    val: &Value,
    server_id: &str,
    header_protocol_version: Option<&str>,
    session_has_initialize: bool,
) -> ParsedMcpFrame {
    if let Value::Array(arr) = val {
        let items = arr
            .iter()
            .map(|v| parse_mcp_value(v, server_id, header_protocol_version, session_has_initialize))
            .collect();
        return ParsedMcpFrame::Batch(items);
    }

    let Some(obj) = val.as_object() else {
        return ParsedMcpFrame::Malformed;
    };

    let id_pair = obj.get("id").and_then(jsonrpc_id_to_key);
    let method = obj.get("method").and_then(|m| m.as_str()).map(String::from);
    let params = obj.get("params");

    // H8: Read `io.modelcontextprotocol/protocolVersion` as well as `protocolVersion` / `mcpProtocolVersion` in `_meta`
    let meta = params.and_then(|p| p.get("_meta")).and_then(|m| m.as_object());
    let meta_version = meta
        .and_then(|m| {
            m.get("io.modelcontextprotocol/protocolVersion")
                .or_else(|| m.get("protocolVersion"))
                .or_else(|| m.get("mcpProtocolVersion"))
                .or_else(|| m.get("version"))
        })
        .and_then(|v| v.as_str())
        .or_else(|| {
            params
                .and_then(|p| p.get("protocolVersion"))
                .and_then(|v| v.as_str())
        });

    let traceparent = meta
        .and_then(|m| m.get("traceparent"))
        .and_then(|v| v.as_str())
        .map(String::from);
    let tracestate = meta
        .and_then(|m| m.get("tracestate"))
        .and_then(|v| v.as_str())
        .map(String::from);

    match (id_pair, method) {
        (Some((id_key, id_raw)), Some(method_name)) => {
            let known = is_known_mcp_method(&method_name);
            let deprecated_feature = detect_deprecated_feature(&method_name);
            let is_elicitation = method_name.starts_with("elicitation/");
            let (protocol_version, protocol_era) = classify_protocol_era(
                &method_name,
                meta_version,
                header_protocol_version,
                session_has_initialize,
            );

            let mut tool_name = None;
            let mut tool_arguments_raw = None;
            let mut tool_arguments_canonical = None;
            if method_name == "tools/call" {
                if let Some(p) = params {
                    tool_name = p.get("name").and_then(|n| n.as_str()).map(String::from);
                    if let Some(args) = p.get("arguments") {
                        let canonical = canonicalize_json(args);
                        let raw_str = serde_json::to_string(args).unwrap_or_else(|_| canonical.clone());
                        tool_arguments_raw = Some(raw_str);
                        tool_arguments_canonical = Some(canonical);
                    } else {
                        tool_arguments_raw = Some("{}".to_string());
                        tool_arguments_canonical = Some("{}".to_string());
                    }
                }
            }

            let task_id = params
                .and_then(|p| p.get("taskId").or_else(|| p.get("id")))
                .and_then(|v| match v {
                    Value::String(s) => Some(s.clone()),
                    Value::Number(n) => Some(n.to_string()),
                    _ => None,
                })
                .filter(|_| method_name.starts_with("tasks/"));

            let client_name = params
                .and_then(|p| p.get("clientInfo"))
                .and_then(|c| c.get("name"))
                .and_then(|n| n.as_str())
                .map(String::from);
            let client_version = params
                .and_then(|p| p.get("clientInfo"))
                .and_then(|c| c.get("version"))
                .and_then(|n| n.as_str())
                .map(String::from);

            ParsedMcpFrame::Request {
                id_key,
                id_raw,
                method: method_name,
                is_known_method: known,
                protocol_version,
                protocol_era,
                tool_name,
                tool_arguments_raw,
                tool_arguments_canonical,
                task_id,
                is_elicitation,
                deprecated_feature,
                traceparent,
                tracestate,
                client_name,
                client_version,
            }
        }
        (None, Some(method_name)) => {
            let deprecated_feature = detect_deprecated_feature(&method_name);
            let (protocol_version, _) = classify_protocol_era(
                &method_name,
                meta_version,
                header_protocol_version,
                session_has_initialize,
            );
            ParsedMcpFrame::Notification {
                method: method_name,
                protocol_version,
                deprecated_feature,
            }
        }
        (Some((id_key, id_raw)), None) => {
            let error_obj = obj.get("error");
            let result_obj = obj.get("result");
            if error_obj.is_none() && result_obj.is_none() {
                return ParsedMcpFrame::Malformed;
            }
            let is_error = error_obj.is_some()
                || result_obj
                    .and_then(|r| r.get("isError"))
                    .and_then(|b| b.as_bool())
                    .unwrap_or(false);
            let error_message = error_obj
                .and_then(|e| e.get("message"))
                .and_then(|m| m.as_str())
                .map(String::from);

            let negotiated_version = result_obj
                .and_then(|r| r.get("protocolVersion"))
                .and_then(|v| v.as_str())
                .map(String::from);
            let capabilities_json = result_obj
                .and_then(|r| r.get("capabilities"))
                .map(canonicalize_json);

            let task_id = result_obj
                .and_then(|r| r.get("taskId"))
                .and_then(|v| match v {
                    Value::String(s) => Some(s.clone()),
                    Value::Number(n) => Some(n.to_string()),
                    _ => None,
                });

            let discovered_tools = result_obj
                .and_then(|r| r.get("tools"))
                .and_then(|t| t.as_array())
                .map(|tools_arr| {
                    let now = Utc::now().to_rfc3339();
                    tools_arr
                        .iter()
                        .filter_map(|t| {
                            let name = t.get("name")?.as_str()?.to_string();
                            let description = t
                                .get("description")
                                .and_then(|d| d.as_str())
                                .unwrap_or("")
                                .to_string();
                            let input_schema = t
                                .get("inputSchema")
                                .cloned()
                                .unwrap_or_else(|| serde_json::json!({"type": "object"}));
                            let schema_hash =
                                compute_schema_hash(&name, &description, &input_schema);
                            let poison_warnings = scan_tool_poisoning(&description);
                            Some(ToolDefinition {
                                server_id: server_id.to_string(),
                                name,
                                description,
                                input_schema,
                                schema_hash,
                                first_seen: now.clone(),
                                last_seen: now.clone(),
                                changed_count: 0,
                                previous_description: None,
                                previous_schema_hash: None,
                                poison_warnings,
                            })
                        })
                        .collect()
                });

            let result_raw = result_obj.map(|r| serde_json::to_string(r).unwrap_or_default());

            ParsedMcpFrame::Response {
                id_key,
                id_raw,
                is_error,
                error_message,
                negotiated_version,
                capabilities_json,
                discovered_tools,
                task_id,
                result_raw,
            }
        }
        (None, None) => ParsedMcpFrame::Malformed,
    }
}
