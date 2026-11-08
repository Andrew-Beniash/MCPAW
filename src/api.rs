use crate::bus::EventBus;
use crate::config::{PolicyRule, WbConfig};
use crate::pricing::PRICE_TABLE_DATE;
use crate::proxy_stdio::now_ns;
use crate::ui::INDEX_HTML;
use axum::{
    body::Body,
    extract::{Path as AxumPath, Query, Request, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{
        sse::{Event as SseEvent, KeepAlive, Sse},
        Html, IntoResponse, Response,
    },
    routing::{get, post},
    Json, Router,
};
use futures::Stream;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use tokio::process::Command;

#[derive(Clone)]
pub struct ApiState {
    pub config: Arc<Mutex<WbConfig>>,
    pub bus: EventBus,
    pub ui_token: String,
    pub http_client: reqwest::Client,
}

pub fn generate_ui_token() -> String {
    if let Ok(tok) = std::env::var("WB_UI_TOKEN") {
        if !tok.trim().is_empty() {
            return tok;
        }
    }
    let mut bytes = [0u8; 32]; // 256 bits (§8)
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

pub fn build_api_router(state: ApiState) -> Router {
    let api_routes = Router::new()
        .route("/status", get(get_status))
        .route("/servers", get(list_servers))
        .route("/servers/:id/tools", get(get_server_tools))
        .route("/servers/:id/schema-history", get(get_server_schema_history))
        .route("/servers/:id/call", post(manual_tool_call))
        .route("/runs", get(list_runs))
        .route("/runs/diff", get(diff_runs))
        .route("/runs/:id", get(get_run))
        .route("/runs/:id/spans", get(get_run_spans))
        .route("/runs/:id/xray", get(get_run_xray))
        .route("/runs/:id/annotations", post(add_target_annotation))
        .route("/spans/:id", get(get_span_detail))
        .route("/spans/:id/annotations", post(add_target_annotation))
        .route("/stream", get(sse_stream))
        .route("/export", post(export_runs))
        .route("/import", post(import_runs))
        .route("/policies", get(get_policies).post(update_policies))
        .route("/policies/test", post(test_policy))
        .route("/ingest/otel", post(ingest_otel))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_ui_token,
        ));

    Router::new()
        .route("/", get(serve_ui))
        .nest("/api", api_routes)
        .layer(middleware::from_fn(enforce_loopback_host_and_origin))
        .with_state(state)
}

/// Enforces §8 Security requirement:
/// "DNS rebinding and CSRF. Validate Host and Origin on every request against an allowlist (127.0.0.1, localhost)."
async fn enforce_loopback_host_and_origin(req: Request, next: Next) -> Response {
    let headers = req.headers();

    // 1. Validate Host header
    if let Some(host_val) = headers.get(header::HOST) {
        let Ok(host_str) = host_val.to_str() else {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "Invalid Host header"})),
            )
                .into_response();
        };
        if !is_allowed_loopback_host(host_str) {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "Forbidden Host (DNS rebinding protection)"})),
            )
                .into_response();
        }
    } else {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "Missing Host header"})),
        )
            .into_response();
    }

    // 2. Validate Origin header if present (CSRF protection)
    if let Some(origin_val) = headers.get(header::ORIGIN) {
        let Ok(origin_str) = origin_val.to_str() else {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "Invalid Origin header"})),
            )
                .into_response();
        };
        if !is_allowed_loopback_origin(origin_str) {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "Forbidden cross-origin request (CSRF protection)"})),
            )
                .into_response();
        }
    }

    next.run(req).await
}

fn is_allowed_loopback_host(host_with_port: &str) -> bool {
    let trimmed = host_with_port.trim().to_lowercase();
    let host_only = if trimmed.starts_with('[') {
        trimmed
            .split(']')
            .next()
            .map(|s| format!("{}]", s))
            .unwrap_or(trimmed)
    } else {
        trimmed
            .split(':')
            .next()
            .unwrap_or(&trimmed)
            .to_string()
    };
    matches!(host_only.as_str(), "127.0.0.1" | "localhost" | "[::1]")
}

fn is_allowed_loopback_origin(origin: &str) -> bool {
    let lower = origin.trim().to_lowercase();
    if lower == "null" {
        return false;
    }
    let without_scheme = lower
        .strip_prefix("http://")
        .or_else(|| lower.strip_prefix("https://"));
    let Some(rest) = without_scheme else {
        return false;
    };
    let host_port = rest.split('/').next().unwrap_or("");
    is_allowed_loopback_host(host_port)
}

/// Enforces §8 UI Token requirement on `/api/*` endpoints.
async fn require_ui_token(
    State(state): State<ApiState>,
    req: Request,
    next: Next,
) -> Response {
    let headers = req.headers();
    let expected = &state.ui_token;

    // 1. Check Authorization: Bearer <token>
    if let Some(auth) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        if let Some(tok) = auth.strip_prefix("Bearer ").or_else(|| auth.strip_prefix("bearer ")) {
            if constant_time_eq(tok.trim(), expected) {
                return next.run(req).await;
            }
        }
    }

    // 2. Check X-WB-Token header
    if let Some(tok) = headers.get("x-wb-token").and_then(|v| v.to_str().ok()) {
        if constant_time_eq(tok.trim(), expected) {
            return next.run(req).await;
        }
    }

    // 3. Check Cookie: wb_token=<token>
    if let Some(cookie_hdr) = headers.get(header::COOKIE).and_then(|v| v.to_str().ok()) {
        for part in cookie_hdr.split(';') {
            let kv = part.trim();
            if let Some(val) = kv.strip_prefix("wb_token=") {
                if constant_time_eq(val.trim(), expected) {
                    return next.run(req).await;
                }
            }
        }
    }

    // 4. Check ?token=<token> query parameter
    if let Some(query) = req.uri().query() {
        for pair in query.split('&') {
            if let Some(val) = pair.strip_prefix("token=") {
                if constant_time_eq(val.trim(), expected) {
                    return next.run(req).await;
                }
            }
        }
    }

    (
        StatusCode::UNAUTHORIZED,
        Json(json!({
            "error": "Unauthorized: valid Workbench UI token required"
        })),
    )
        .into_response()
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.bytes().zip(b.bytes()) {
        diff |= x ^ y;
    }
    diff == 0
}

async fn serve_ui(
    State(state): State<ApiState>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let mut resp_headers = HeaderMap::new();
    // If launched with `/?token=<valid_token>`, set HttpOnly, SameSite=Strict cookie (§8)
    if let Some(tok) = params.get("token") {
        if constant_time_eq(tok, &state.ui_token) {
            if let Ok(cookie_val) = HeaderValue::from_str(&format!(
                "wb_token={}; HttpOnly; SameSite=Strict; Path=/",
                state.ui_token
            )) {
                resp_headers.insert(header::SET_COOKIE, cookie_val);
            }
        }
    }
    (resp_headers, Html(INDEX_HTML)).into_response()
}

async fn get_status(State(state): State<ApiState>) -> impl IntoResponse {
    state.bus.flush().await;
    let cfg = state.config.lock().unwrap().clone();
    let (breaker_enabled, max_cost, max_tokens, max_loops, policy_enabled, policy_rules_count) = {
        let mods = state.bus.modules.lock().unwrap();
        (
            mods.breaker.config.enabled,
            mods.breaker.config.max_run_cost_usd,
            mods.breaker.config.max_run_tokens,
            mods.breaker.config.max_identical_tool_calls,
            mods.policy.config.enabled,
            mods.policy.config.rules.len(),
        )
    };
    Json(json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
        "capture_level": cfg.capture.payloads.to_string(),
        "full_capture_banner": cfg.capture.payloads == crate::config::CaptureLevel::Full,
        "dropped_events": state.bus.dropped_count(),
        "price_table_date": PRICE_TABLE_DATE,
        "mcp_port": cfg.daemon.mcp_port,
        "ui_port": cfg.daemon.ui_port,
        "modules": {
            "circuit_breaker": {
                "enabled": breaker_enabled,
                "max_run_cost_usd": max_cost,
                "max_run_tokens": max_tokens,
                "max_identical_tool_calls": max_loops,
            },
            "context_xray": {
                "enabled": true
            },
            "policy_firewall": {
                "enabled": policy_enabled,
                "rules_count": policy_rules_count
            }
        }
    }))
}

async fn list_servers(State(state): State<ApiState>) -> Response {
    state.bus.flush().await;
    match state.bus.store.list_servers() {
        Ok(servers) => Json(servers).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn get_server_tools(
    State(state): State<ApiState>,
    AxumPath(server_id): AxumPath<String>,
) -> Response {
    state.bus.flush().await;
    match state.bus.store.get_server_tools(&server_id) {
        Ok(tools) => Json(tools).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn get_server_schema_history(
    State(state): State<ApiState>,
    AxumPath(server_id): AxumPath<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    state.bus.flush().await;
    let tool = params.get("tool").map(|s| s.as_str());
    match state.bus.store.get_tool_schema_history(&server_id, tool) {
        Ok(history) => Json(history).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

#[derive(Debug, Deserialize)]
struct ManualCallRequest {
    pub tool_name: String,
    #[serde(default)]
    pub arguments: Value,
}

/// F-10: Manual tool call panel endpoint.
async fn manual_tool_call(
    State(state): State<ApiState>,
    AxumPath(server_id): AxumPath<String>,
    Json(req): Json<ManualCallRequest>,
) -> Response {
    let mcp_port = state.config.lock().unwrap().daemon.mcp_port;
    let rpc_req = json!({
        "jsonrpc": "2.0",
        "id": format!("manual-{}", uuid::Uuid::new_v4()),
        "method": "tools/call",
        "params": {
            "name": req.tool_name,
            "arguments": req.arguments
        }
    });

    // Check if HTTP server is configured, or if stdio server command is known
    let servers = state.bus.store.list_servers().unwrap_or_default();
    let srv_info = servers.into_iter().find(|s| s.id == server_id);

    if let Some(srv) = srv_info {
        if srv.transport == "http" {
            let proxy_url = format!("http://127.0.0.1:{}/mcp/{}", mcp_port, server_id);
            match state
                .http_client
                .post(&proxy_url)
                .header("x-mcp-upstream", &srv.command_or_url)
                .json(&rpc_req)
                .send()
                .await
            {
                Ok(resp) => {
                    let body: Value = resp.json().await.unwrap_or_else(|_| json!({}));
                    return Json(body).into_response();
                }
                Err(e) => {
                    return (
                        StatusCode::BAD_GATEWAY,
                        Json(json!({"error": e.to_string()})),
                    )
                        .into_response();
                }
            }
        } else if srv.transport == "stdio" && !srv.command_or_url.is_empty() {
            // Spawn one-shot call against the stdio server command
            let parts: Vec<&str> = srv.command_or_url.split_whitespace().collect();
            if let Some((cmd, args)) = parts.split_first() {
                if let Ok(mut child) = Command::new(cmd)
                    .args(args)
                    .stdin(std::process::Stdio::piped())
                    .stdout(std::process::Stdio::piped())
                    .spawn()
                {
                    if let Some(mut stdin) = child.stdin.take() {
                        use tokio::io::AsyncWriteExt;
                        let line = format!("{}\n", rpc_req);
                        let _ = stdin.write_all(line.as_bytes()).await;
                        let _ = stdin.flush().await;
                    }
                    if let Ok(output) = child.wait_with_output().await {
                        let out_str = String::from_utf8_lossy(&output.stdout);
                        if let Some(last_line) = out_str.lines().last() {
                            if let Ok(val) = serde_json::from_str::<Value>(last_line) {
                                return Json(val).into_response();
                            }
                        }
                        return Json(json!({ "raw_output": out_str })).into_response();
                    }
                }
            }
        }
    }

    (
        StatusCode::NOT_FOUND,
        Json(json!({"error": format!("Server '{}' is not reachable for manual call", server_id)})),
    )
        .into_response()
}

async fn list_runs(
    State(state): State<ApiState>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    state.bus.flush().await;
    let since = params.get("since").filter(|s| !s.is_empty()).map(|s| s.as_str());
    let status = params.get("status").filter(|s| !s.is_empty()).map(|s| s.as_str());
    match state.bus.store.list_runs(since, status) {
        Ok(runs) => Json(runs).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn get_run(
    State(state): State<ApiState>,
    AxumPath(run_id): AxumPath<String>,
) -> Response {
    state.bus.flush().await;
    match state.bus.store.get_run(&run_id) {
        Ok(Some(run)) => Json(run).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Run not found"})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn get_run_spans(
    State(state): State<ApiState>,
    AxumPath(run_id): AxumPath<String>,
) -> Response {
    state.bus.flush().await;
    match state.bus.store.get_run_spans(&run_id) {
        Ok(spans) => Json(spans).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn get_run_xray(
    State(state): State<ApiState>,
    AxumPath(run_id): AxumPath<String>,
) -> Response {
    state.bus.flush().await;
    match state.bus.store.get_run_xray(&run_id) {
        Ok(calls) => Json(calls).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn diff_runs(
    State(state): State<ApiState>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    state.bus.flush().await;
    let Some(left) = params.get("left") else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Missing 'left' run ID query param"})),
        )
            .into_response();
    };
    let Some(right) = params.get("right") else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Missing 'right' run ID query param"})),
        )
            .into_response();
    };
    match state.bus.store.diff_runs(left, right) {
        Ok(diff) => Json(diff).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn get_span_detail(
    State(state): State<ApiState>,
    AxumPath(span_id): AxumPath<String>,
) -> Response {
    state.bus.flush().await;
    match state.bus.store.get_span_detail(&span_id) {
        Ok(Some(detail)) => Json(detail).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Span not found"})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

#[derive(Debug, Deserialize)]
struct CreateAnnotationRequest {
    pub author: String,
    pub text: String,
}

async fn add_target_annotation(
    State(state): State<ApiState>,
    AxumPath(target_id): AxumPath<String>,
    Json(req): Json<CreateAnnotationRequest>,
) -> Response {
    match state
        .bus
        .store
        .add_annotation(&target_id, &req.author, &req.text)
    {
        Ok(ann) => (StatusCode::CREATED, Json(ann)).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn sse_stream(
    State(state): State<ApiState>,
) -> Sse<impl Stream<Item = Result<SseEvent, Infallible>>> {
    let mut rx = state.bus.subscribe_sse();
    let stream = async_stream::stream! {
        loop {
            match rx.recv().await {
                Ok(ev) => {
                    if let Ok(json_str) = serde_json::to_string(&ev) {
                        yield Ok(SseEvent::default().data(json_str));
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    };
    Sse::new(stream).keep_alive(KeepAlive::default())
}

#[derive(Debug, Deserialize)]
pub struct ExportRequest {
    #[serde(default)]
    pub run_ids: Vec<String>,
    #[serde(default = "default_export_format")]
    pub format: String,
    #[serde(default)]
    pub preview: bool,
}

fn default_export_format() -> String {
    "jsonl".to_string()
}

#[derive(Debug, Serialize)]
pub struct ExportResponse {
    pub format: String,
    pub bytes: usize,
    pub preview: bool,
    pub content: String,
}

async fn export_runs(
    State(state): State<ApiState>,
    Json(req): Json<ExportRequest>,
) -> Response {
    state.bus.flush().await;
    let fmt = req.format.to_lowercase();
    let content_res = match fmt.as_str() {
        "otlp" => state
            .bus
            .store
            .export_otlp(&req.run_ids)
            .and_then(|v| Ok(serde_json::to_string_pretty(&v)?)),
        "mockmcp" => state
            .bus
            .store
            .export_mockmcp(&req.run_ids)
            .and_then(|v| Ok(serde_json::to_string_pretty(&v)?)),
        _ => state.bus.store.export_jsonl(&req.run_ids),
    };

    match content_res {
        Ok(raw_content) => {
            // Ensure exported bytes pass through the redactor as an additional safeguard
            let redacted = state.bus.redactor.redact_str(&raw_content);
            if req.preview {
                return Json(ExportResponse {
                    format: fmt,
                    bytes: redacted.len(),
                    preview: true,
                    content: redacted,
                })
                .into_response();
            }
            let content_type = if fmt == "jsonl" {
                "application/x-ndjson"
            } else {
                "application/json"
            };
            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, content_type)],
                Body::from(redacted),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

#[derive(Debug, Deserialize)]
struct ImportRequest {
    pub jsonl: String,
}

async fn import_runs(
    State(state): State<ApiState>,
    Json(req): Json<ImportRequest>,
) -> Response {
    match state.bus.store.import_jsonl(&req.jsonl) {
        Ok(count) => Json(json!({ "imported_runs": count })).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn get_policies(State(state): State<ApiState>) -> Response {
    state.bus.flush().await;
    let (enabled, fail_closed, block_on_schema_change, rules) = {
        let mods = state.bus.modules.lock().unwrap();
        (
            mods.policy.config.enabled,
            mods.policy.config.fail_closed,
            mods.policy.config.block_on_schema_change,
            mods.policy.config.rules.clone(),
        )
    };
    let recent_decisions = state
        .bus
        .store
        .list_policy_decisions(100)
        .unwrap_or_default();
    Json(json!({
        "enabled": enabled,
        "fail_closed": fail_closed,
        "block_on_schema_change": block_on_schema_change,
        "rules": rules,
        "recent_decisions": recent_decisions
    }))
    .into_response()
}

#[derive(Debug, Deserialize)]
struct UpdatePoliciesRequest {
    pub enabled: bool,
    #[serde(default)]
    pub block_on_schema_change: Option<bool>,
    pub rules: Vec<PolicyRule>,
}

async fn update_policies(
    State(state): State<ApiState>,
    Json(req): Json<UpdatePoliciesRequest>,
) -> Response {
    {
        let mut mods = state.bus.modules.lock().unwrap();
        if let Some(b) = req.block_on_schema_change {
            mods.policy.config.block_on_schema_change = b;
        }
        mods.policy.update_rules(req.enabled, req.rules.clone());
    }
    {
        let mut cfg = state.config.lock().unwrap();
        cfg.policy.enabled = req.enabled;
        cfg.policy.rules = req.rules;
    }
    Json(json!({ "status": "updated" })).into_response()
}

#[derive(Debug, Deserialize)]
struct TestPolicyRequest {
    pub server: String,
    pub tool: String,
    #[serde(default)]
    pub arguments: Value,
}

async fn test_policy(
    State(state): State<ApiState>,
    Json(req): Json<TestPolicyRequest>,
) -> Response {
    let args_str = match &req.arguments {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    };
    let (verdict, decision) = {
        let mods = state.bus.modules.lock().unwrap();
        mods.policy.evaluate_call(
            "policy-test",
            &req.server,
            &req.tool,
            &args_str,
            now_ns(),
        )
    };
    Json(json!({
        "allowed": !verdict.is_blocked(),
        "verdict": verdict,
        "decision": decision
    }))
    .into_response()
}

async fn ingest_otel(
    State(state): State<ApiState>,
    Json(payload): Json<Value>,
) -> Response {
    match state.bus.store.ingest_otel_spans(&payload) {
        Ok(ingested) => Json(json!({ "ingested_spans": ingested })).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}
