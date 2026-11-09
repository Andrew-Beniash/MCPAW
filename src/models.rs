use crate::config::PolicyEffect;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Normalizes a W3C `traceparent` (`00-<32hex>-<16hex>-<flags>`) or arbitrary identifier
/// into a valid 32-character lowercase hexadecimal OpenTelemetry `traceId`.
pub fn normalize_trace_id(input: &str) -> String {
    let trimmed = input.trim();
    // Check W3C traceparent format: version(2)-trace_id(32)-parent_id(16)-flags(2)
    let parts: Vec<&str> = trimmed.split('-').collect();
    if parts.len() == 4
        && parts[0].len() == 2
        && parts[1].len() == 32
        && parts[1].chars().all(|c| c.is_ascii_hexdigit())
    {
        return parts[1].to_lowercase();
    }
    let hex_only: String = trimmed.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex_only.len() == 32 {
        return hex_only.to_lowercase();
    }
    let mut hasher = Sha256::new();
    hasher.update(trimmed.as_bytes());
    let digest = hex::encode(hasher.finalize());
    digest[..32].to_string()
}

/// Normalizes any span identifier into a valid 16-character lowercase hexadecimal OpenTelemetry `spanId`.
pub fn normalize_span_id(input: &str) -> String {
    let hex_only: String = input.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex_only.len() >= 16 {
        hex_only[..16].to_lowercase()
    } else {
        let mut hasher = Sha256::new();
        hasher.update(input.as_bytes());
        let digest = hex::encode(hasher.finalize());
        digest[..16].to_string()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub started_at: String,
    pub client_name: Option<String>,
    pub client_version: Option<String>,
    pub negotiated_version: Option<String>,
    pub capabilities_json: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Run {
    pub id: String,
    pub session_id: String,
    pub label: Option<String>,
    pub status: String,
    pub started_at: String,
    pub ended_at: Option<String>,
    pub total_cost_usd: f64,
    pub total_tokens: u64,
    pub estimated_cost: bool,
    pub span_count: u64,
    pub error_count: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpanKind {
    Mcp,
    Llm,
    Policy,
}

impl SpanKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            SpanKind::Mcp => "mcp",
            SpanKind::Llm => "llm",
            SpanKind::Policy => "policy",
        }
    }

    pub fn from_str_lossy(s: &str) -> Self {
        match s {
            "llm" => SpanKind::Llm,
            "policy" => SpanKind::Policy,
            _ => SpanKind::Mcp,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpanStatus {
    InFlight,
    Ok,
    Error,
    WaitingHuman,
    Blocked,
}

impl SpanStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            SpanStatus::InFlight => "in_flight",
            SpanStatus::Ok => "ok",
            SpanStatus::Error => "error",
            SpanStatus::WaitingHuman => "waiting_human",
            SpanStatus::Blocked => "blocked",
        }
    }

    pub fn from_str_lossy(s: &str) -> Self {
        match s {
            "in_flight" => SpanStatus::InFlight,
            "error" => SpanStatus::Error,
            "waiting_human" => SpanStatus::WaitingHuman,
            "blocked" => SpanStatus::Blocked,
            _ => SpanStatus::Ok,
        }
    }
}

/// Pinned OpenTelemetry GenAI & MCP semantic convention attribute keys (§5).
pub mod semconv {
    pub const MCP_METHOD_NAME: &str = "mcp.method.name";
    pub const MCP_PROTOCOL_VERSION: &str = "mcp.protocol.version";
    pub const MCP_PROTOCOL_ERA: &str = "mcp.protocol.era";
    pub const MCP_SERVER_ID: &str = "mcp.server.id";
    pub const GEN_AI_TOOL_NAME: &str = "gen_ai.tool.name";
    pub const GEN_AI_TOOL_CALL_ARGUMENTS: &str = "gen_ai.tool.call.arguments";
    pub const GEN_AI_TOOL_CALL_RESULT: &str = "gen_ai.tool.call.result";
    pub const GEN_AI_SYSTEM: &str = "gen_ai.system";
    pub const GEN_AI_REQUEST_MODEL: &str = "gen_ai.request.model";
    pub const GEN_AI_USAGE_INPUT_TOKENS: &str = "gen_ai.usage.input_tokens";
    pub const GEN_AI_USAGE_OUTPUT_TOKENS: &str = "gen_ai.usage.output_tokens";
    pub const GEN_AI_USAGE_CACHED_TOKENS: &str = "gen_ai.usage.cached_tokens";
    pub const NETWORK_TRANSPORT: &str = "network.transport";
    pub const JSONRPC_REQUEST_ID: &str = "jsonrpc.request.id";
    pub const MCP_TASK_ID: &str = "mcp.task.id";
    pub const WB_POLICY_CHECKED: &str = "wb.policy_checked";
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Span {
    pub id: String,
    pub trace_id: String,
    pub run_id: String,
    pub parent_id: Option<String>,
    pub kind: SpanKind,
    pub name: String,
    pub start_ns: u64,
    pub end_ns: Option<u64>,
    pub status: SpanStatus,
    pub attributes: BTreeMap<String, serde_json::Value>,
}

impl Span {
    pub fn duration_ms(&self) -> Option<f64> {
        self.end_ns
            .map(|end| (end.saturating_sub(self.start_ns)) as f64 / 1_000_000.0)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpServer {
    pub id: String,
    pub transport: String,
    pub command_or_url: String,
    #[serde(default)]
    pub command_argv: Vec<String>,
    pub protocol_versions_seen: Vec<String>,
    pub deprecated_features_seen: Vec<String>,
    pub first_seen: String,
    pub last_seen: String,
    pub tool_count: usize,
    pub schema_changes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    pub server_id: String,
    pub name: String,
    pub description: String,
    pub input_schema: serde_json::Value,
    pub schema_hash: String,
    pub first_seen: String,
    pub last_seen: String,
    pub changed_count: u32,
    pub previous_description: Option<String>,
    pub previous_schema_hash: Option<String>,
    pub poison_warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolSchemaChange {
    pub id: i64,
    pub server_id: String,
    pub name: String,
    pub description: String,
    pub input_schema: serde_json::Value,
    pub schema_hash: String,
    pub recorded_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageDirection {
    ClientToServer,
    ServerToClient,
}

impl MessageDirection {
    pub fn as_str(&self) -> &'static str {
        match self {
            MessageDirection::ClientToServer => "client_to_server",
            MessageDirection::ServerToClient => "server_to_client",
        }
    }

    pub fn from_str_lossy(s: &str) -> Self {
        match s {
            "server_to_client" => MessageDirection::ServerToClient,
            _ => MessageDirection::ClientToServer,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpMessage {
    pub id: i64,
    pub span_id: String,
    pub direction: MessageDirection,
    pub jsonrpc_id: Option<String>,
    pub method: Option<String>,
    pub payload: Option<String>,
    pub bytes: usize,
    pub timestamp_ns: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ContextBreakdown {
    pub system_tokens: u64,
    pub tools_tokens: u64,
    pub user_tokens: u64,
    pub assistant_tokens: u64,
    pub tool_results_tokens: u64,
    pub total_tokens: u64,
    pub by_tool_result: BTreeMap<String, u64>,
    pub bloat_warning: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelCall {
    pub span_id: String,
    pub provider: String,
    pub model: String,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cached_tokens: u64,
    pub cost_usd: f64,
    pub cost_estimated: bool,
    pub finish_reason: Option<String>,
    pub context_breakdown: ContextBreakdown,
    pub request_payload: Option<String>,
    pub response_payload: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub id: i64,
    pub rule_id: String,
    pub span_id: String,
    pub server_id: String,
    pub tool_name: String,
    pub verdict: String,
    pub reason: String,
    pub timestamp_ns: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Annotation {
    pub id: i64,
    pub target_id: String,
    pub author: String,
    pub text: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpanDetail {
    pub span: Span,
    pub mcp_messages: Vec<McpMessage>,
    pub model_call: Option<ModelCall>,
    pub policy_decisions: Vec<PolicyDecision>,
    pub annotations: Vec<Annotation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpanDiffEntry {
    pub step_index: usize,
    pub left_span: Option<Span>,
    pub right_span: Option<Span>,
    pub diverged: bool,
    pub divergence_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunDiff {
    pub left_run: Run,
    pub right_run: Run,
    pub first_divergence_index: Option<usize>,
    pub first_divergence_reason: Option<String>,
    pub entries: Vec<SpanDiffEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    Pass,
    Annotate(String),
    Block(String),
}

impl Verdict {
    pub fn is_blocked(&self) -> bool {
        matches!(self, Verdict::Block(_))
    }
}

/// Event flowing through the Workbench in-process bounded Event Bus.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event_type", rename_all = "snake_case")]
#[allow(clippy::large_enum_variant)]
pub enum WorkbenchEvent {
    SessionStarted {
        session: Session,
    },
    ServerObserved {
        server_id: String,
        transport: String,
        command_or_url: String,
        #[serde(default)]
        command_argv: Vec<String>,
        protocol_version: Option<String>,
        deprecated_feature: Option<String>,
    },
    ToolsDiscovered {
        server_id: String,
        tools: Vec<ToolDefinition>,
    },
    SpanRecorded {
        span: Span,
        session_id: String,
        run_label: Option<String>,
        mcp_messages: Vec<McpMessage>,
        model_call: Option<ModelCall>,
        policy_decisions: Vec<PolicyDecision>,
    },
    SpanUpdated {
        span_id: String,
        end_ns: u64,
        status: SpanStatus,
        attributes_patch: BTreeMap<String, serde_json::Value>,
        response_message: Option<McpMessage>,
    },
    PolicyEvaluated {
        decision: PolicyDecision,
    },
}

/// Wire message sent from `wb wrap` to `wbd` over the local Unix socket / IPC channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "ipc_type", rename_all = "snake_case")]
#[allow(clippy::large_enum_variant)]
pub enum IpcRequest {
    ObserveEvent {
        event: WorkbenchEvent,
    },
    PolicyCheck {
        session_id: String,
        run_id: Option<String>,
        server_id: String,
        tool_name: String,
        arguments_raw: String,
        #[serde(default)]
        jsonrpc_id: Option<serde_json::Value>,
        #[serde(default)]
        raw_request_line: Option<String>,
    },
    QueryMode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcResponse {
    pub allowed: bool,
    pub reason: Option<String>,
    pub rule_id: Option<String>,
    #[serde(default)]
    pub policy_enabled: bool,
}

impl PolicyEffect {
    pub fn as_str(&self) -> &'static str {
        match self {
            PolicyEffect::Allow => "allow",
            PolicyEffect::Deny => "deny",
        }
    }
}
