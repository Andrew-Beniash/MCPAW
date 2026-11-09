use crate::bus::EventBus;
use crate::config::{PolicyRule, WbConfig};
use crate::models::*;
use crate::pricing::PRICE_TABLE_DATE;
use crate::proxy_stdio::now_ns;
use crate::ui::{APP_JS, INDEX_HTML};
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
use std::collections::{BTreeMap, HashMap};
use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use uuid::Uuid;

const UI_CSP_HEADER: &str = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'";

#[derive(Clone)]
pub struct ApiState {
    pub config: Arc<Mutex<WbConfig>>,
    pub bus: EventBus,
    pub ui_token: String,
    pub http_client: reqwest::Client,
}

/// Generates a 256-bit UI token, or uses `WB_UI_TOKEN` if it is at least 32 characters (M12).
pub fn generate_ui_token() -> String {
    if let Ok(tok) = std::env::var("WB_UI_TOKEN") {
        let trimmed = tok.trim();
        if trimmed.len() >= 32 {
            return trimmed.to_string();
        } else if !trimmed.is_empty() {
            eprintln!(
                "wb warning: WB_UI_TOKEN is shorter than 32 characters ({} chars); ignoring and generating a random 256-bit token.",
                trimmed.len()
            );
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
        .route(
            "/servers/:id/schema-history",
            get(get_server_schema_history),
        )
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
        .route("/app.js", get(serve_app_js))
        .nest("/api", api_routes)
        .layer(middleware::from_fn(enforce_loopback_host_and_origin))
        .with_state(state)
}

/// Enforces §8 Security requirement:
/// "DNS rebinding and CSRF. Validate Host and Origin on every request against an allowlist (127.0.0.1, localhost)."
pub async fn enforce_loopback_host_and_origin(req: Request, next: Next) -> Response {
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
        trimmed.split(':').next().unwrap_or(&trimmed).to_string()
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
async fn require_ui_token(State(state): State<ApiState>, req: Request, next: Next) -> Response {
    let headers = req.headers();
    let expected = &state.ui_token;

    // 1. Check Authorization: Bearer <token>
    if let Some(auth) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        if let Some(tok) = auth
            .strip_prefix("Bearer ")
            .or_else(|| auth.strip_prefix("bearer "))
        {
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
    resp_headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(UI_CSP_HEADER),
    );
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

async fn serve_app_js() -> Response {
    let mut resp_headers = HeaderMap::new();
    resp_headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/javascript; charset=utf-8"),
    );
    resp_headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(UI_CSP_HEADER),
    );
    (resp_headers, APP_JS).into_response()
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

/// F-10 & M5: Manual tool call panel endpoint.
/// Uses unredacted `command_argv`, runs `initialize` handshake, checks policy, and records a span.
async fn manual_tool_call(
    State(state): State<ApiState>,
    AxumPath(server_id): AxumPath<String>,
    Json(req): Json<ManualCallRequest>,
) -> Response {
    state.bus.flush().await;
    let (mcp_port, proxy_token, cfg_server) = {
        let cfg = state.config.lock().unwrap();
        let found = cfg.servers.iter().find(|s| s.id == server_id).cloned();
        (cfg.daemon.mcp_port, cfg.daemon.proxy_token.clone(), found)
    };

    let rpc_id = format!("manual-{}", Uuid::new_v4());
    let rpc_req = json!({
        "jsonrpc": "2.0",
        "id": rpc_id,
        "method": "tools/call",
        "params": {
            "name": req.tool_name,
            "arguments": req.arguments
        }
    });
    let rpc_req_str = serde_json::to_string(&rpc_req).unwrap_or_default();
    let args_raw = serde_json::to_string(&req.arguments).unwrap_or_else(|_| "{}".to_string());

    // Check if HTTP server is configured, or if stdio server command is known
    let servers = state.bus.store.list_servers().unwrap_or_default();
    let srv_info = servers.into_iter().find(|s| s.id == server_id);

    if let Some(srv) = srv_info {
        if srv.transport == "http" {
            let proxy_url = format!("http://127.0.0.1:{}/mcp/{}", mcp_port, server_id);
            let mut req_builder = state
                .http_client
                .post(&proxy_url)
                .header(header::HOST, format!("127.0.0.1:{}", mcp_port))
                .json(&rpc_req);
            if let Some(tok) = proxy_token {
                if !tok.trim().is_empty() {
                    req_builder = req_builder.header("x-wb-proxy-token", tok);
                }
            }
            match req_builder.send().await {
                Ok(resp) => {
                    let body: Value = resp.json().await.unwrap_or_else(|_| json!({}));
                    state.bus.flush().await;
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
        } else if srv.transport == "stdio" {
            // M5: 1. Evaluate policy & circuit breaker before spawning stdio server
            let start_ns = now_ns();
            let span_id = normalize_span_id(&format!("manual-{}", Uuid::new_v4()));
            let session_id = format!("manual-stdio-{}", server_id);
            let check = state.bus.check_tool_call_policy(
                &session_id,
                "auto",
                &span_id,
                &server_id,
                &req.tool_name,
                &args_raw,
                start_ns,
                true,
                Some(&rpc_req_str),
            );
            if !check.allowed {
                let reason = check
                    .reason
                    .unwrap_or_else(|| "Denied by policy".to_string());
                state.bus.flush().await;
                return Json(json!({
                    "jsonrpc": "2.0",
                    "id": rpc_id,
                    "error": {
                        "code": -32001,
                        "message": format!("MCP Workbench Policy Block: {}", reason)
                    }
                }))
                .into_response();
            }

            // M5: 2. Resolve unredacted argv array (preserving paths with spaces)
            let argv: Vec<String> = if let Some(ref cs) = cfg_server {
                if let Some(ref cmd) = cs.command {
                    let mut v = vec![cmd.clone()];
                    v.extend(cs.args.clone());
                    v
                } else {
                    srv.command_argv.clone()
                }
            } else if !srv.command_argv.is_empty() {
                srv.command_argv.clone()
            } else {
                srv.command_or_url
                    .split_whitespace()
                    .map(String::from)
                    .collect()
            };

            if let Some((cmd, args)) = argv.split_first() {
                if let Ok(mut child) = Command::new(cmd)
                    .args(args)
                    .stdin(std::process::Stdio::piped())
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::null())
                    .spawn()
                {
                    let init_req = json!({
                        "jsonrpc": "2.0",
                        "id": "manual-init-0",
                        "method": "initialize",
                        "params": {
                            "protocolVersion": "2025-11-25",
                            "capabilities": {},
                            "clientInfo": { "name": "mcpaw-manual", "version": env!("CARGO_PKG_VERSION") }
                        }
                    });
                    let init_notif = json!({
                        "jsonrpc": "2.0",
                        "method": "notifications/initialized"
                    });

                    if let Some(mut stdin) = child.stdin.take() {
                        let payload = format!("{}\n{}\n{}\n", init_req, init_notif, rpc_req_str);
                        let _ = stdin.write_all(payload.as_bytes()).await;
                        let _ = stdin.flush().await;
                        // Drop stdin so EOF is sent after requests
                    }

                    let mut matched_resp: Option<Value> = None;
                    let mut last_line_str = String::new();
                    if let Some(stdout) = child.stdout.take() {
                        let mut reader = BufReader::new(stdout).lines();
                        let read_fut = async {
                            while let Ok(Some(line)) = reader.next_line().await {
                                let trimmed = line.trim();
                                if trimmed.is_empty() {
                                    continue;
                                }
                                last_line_str = trimmed.to_string();
                                if let Ok(val) = serde_json::from_str::<Value>(trimmed) {
                                    if val.get("id").and_then(|v| v.as_str()) == Some(&rpc_id) {
                                        matched_resp = Some(val);
                                        break;
                                    }
                                }
                            }
                        };
                        let _ = tokio::time::timeout(Duration::from_secs(15), read_fut).await;
                    }
                    let _ = child.kill().await;

                    let end_ns = now_ns();
                    let resp_val = matched_resp.unwrap_or_else(|| {
                        serde_json::from_str::<Value>(&last_line_str)
                            .unwrap_or_else(|_| json!({ "raw_output": last_line_str }))
                    });
                    let resp_str = serde_json::to_string(&resp_val).unwrap_or_default();
                    let is_err = resp_val.get("error").is_some()
                        || resp_val
                            .get("result")
                            .and_then(|r| r.get("isError"))
                            .and_then(|b| b.as_bool())
                            .unwrap_or(false);

                    // M5: 3. Record span for the manual stdio call
                    let mut attrs = BTreeMap::new();
                    attrs.insert(
                        semconv::MCP_SERVER_ID.to_string(),
                        Value::String(server_id.clone()),
                    );
                    attrs.insert(
                        semconv::MCP_METHOD_NAME.to_string(),
                        Value::String("tools/call".to_string()),
                    );
                    attrs.insert(
                        semconv::GEN_AI_TOOL_NAME.to_string(),
                        Value::String(req.tool_name.clone()),
                    );
                    attrs.insert(
                        semconv::GEN_AI_TOOL_CALL_ARGUMENTS.to_string(),
                        Value::String(args_raw),
                    );
                    if let Some(res_obj) = resp_val.get("result") {
                        attrs.insert(
                            semconv::GEN_AI_TOOL_CALL_RESULT.to_string(),
                            Value::String(res_obj.to_string()),
                        );
                    }
                    attrs.insert(
                        semconv::NETWORK_TRANSPORT.to_string(),
                        Value::String("pipe".to_string()),
                    );
                    attrs.insert(semconv::WB_POLICY_CHECKED.to_string(), Value::Bool(true));

                    let span = Span {
                        id: span_id.clone(),
                        trace_id: normalize_trace_id(&session_id),
                        run_id: "auto".to_string(),
                        parent_id: None,
                        kind: SpanKind::Mcp,
                        name: format!("tools/call {}", req.tool_name),
                        start_ns,
                        end_ns: Some(end_ns),
                        status: if is_err {
                            SpanStatus::Error
                        } else {
                            SpanStatus::Ok
                        },
                        attributes: attrs,
                    };
                    state.bus.publish(WorkbenchEvent::SpanRecorded {
                        span,
                        session_id,
                        run_label: None,
                        mcp_messages: vec![
                            McpMessage {
                                id: 0,
                                span_id: span_id.clone(),
                                direction: MessageDirection::ClientToServer,
                                jsonrpc_id: Some(json!(rpc_id).to_string()),
                                method: Some("tools/call".to_string()),
                                payload: Some(rpc_req_str.clone()),
                                bytes: rpc_req_str.len(),
                                timestamp_ns: start_ns,
                            },
                            McpMessage {
                                id: 0,
                                span_id,
                                direction: MessageDirection::ServerToClient,
                                jsonrpc_id: Some(json!(rpc_id).to_string()),
                                method: Some("tools/call".to_string()),
                                payload: Some(resp_str.clone()),
                                bytes: resp_str.len(),
                                timestamp_ns: end_ns,
                            },
                        ],
                        model_call: None,
                        policy_decisions: Vec::new(),
                    });
                    state.bus.flush().await;
                    return Json(resp_val).into_response();
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
    let since = params
        .get("since")
        .filter(|s| !s.is_empty())
        .map(|s| s.as_str());
    let status = params
        .get("status")
        .filter(|s| !s.is_empty())
        .map(|s| s.as_str());
    match state.bus.store.list_runs(since, status) {
        Ok(runs) => Json(runs).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn get_run(State(state): State<ApiState>, AxumPath(run_id): AxumPath<String>) -> Response {
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

async fn export_runs(State(state): State<ApiState>, Json(req): Json<ExportRequest>) -> Response {
    state.bus.flush().await;
    let fmt = req.format.to_lowercase();
    // M14: Reject unknown export formats instead of silently falling back to jsonl
    if !matches!(fmt.as_str(), "otlp" | "mockmcp" | "jsonl") {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": format!("Unsupported export format '{}'. Valid formats: jsonl, otlp, mockmcp", fmt)
            })),
        )
            .into_response();
    }
    // N9: exports can be large; run the blocking SQLite read off the async workers.
    let store = state.bus.store.clone();
    let run_ids = req.run_ids.clone();
    let fmt_for_task = fmt.clone();
    let content_res = tokio::task::spawn_blocking(move || match fmt_for_task.as_str() {
        "otlp" => store
            .export_otlp(&run_ids)
            .and_then(|v| Ok(serde_json::to_string_pretty(&v)?)),
        "mockmcp" => store
            .export_mockmcp(&run_ids)
            .and_then(|v| Ok(serde_json::to_string_pretty(&v)?)),
        _ => store.export_jsonl(&run_ids),
    })
    .await
    .unwrap_or_else(|e| Err(anyhow::anyhow!("export task failed: {}", e)));

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

async fn import_runs(State(state): State<ApiState>, Json(req): Json<ImportRequest>) -> Response {
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
    // M9: Validate all regex patterns in rules before applying
    for rule in &req.rules {
        if let Err(e) = rule.validate() {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": e.to_string() })),
            )
                .into_response();
        }
    }

    // N7: Persist first, then apply, so a failed save never leaves the daemon enforcing rules that
    // are not on disk.
    let (new_policy, persisted) = {
        let mut cfg = state.config.lock().unwrap();
        let mut candidate = cfg.policy.clone();
        candidate.enabled = req.enabled;
        if let Some(b) = req.block_on_schema_change {
            candidate.block_on_schema_change = b;
        }
        candidate.rules = req.rules.clone();
        match cfg.save_policy_atomic(&candidate) {
            Ok(persisted) => {
                cfg.policy = candidate.clone();
                (candidate, persisted)
            }
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": format!("Failed to save wb.toml; policy not changed: {}", e) })),
                )
                    .into_response();
            }
        }
    };
    {
        let mut mods = state.bus.modules.lock().unwrap();
        mods.policy.config.block_on_schema_change = new_policy.block_on_schema_change;
        if let Err(e) = mods
            .policy
            .update_rules(new_policy.enabled, new_policy.rules.clone())
        {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": e.to_string() })),
            )
                .into_response();
        }
    }
    Json(json!({ "status": "updated", "persisted": persisted })).into_response()
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
        mods.policy
            .evaluate_call("policy-test", &req.server, &req.tool, &args_str, now_ns())
    };
    Json(json!({
        "allowed": !verdict.is_blocked(),
        "verdict": verdict,
        "decision": decision
    }))
    .into_response()
}

async fn ingest_otel(State(state): State<ApiState>, Json(payload): Json<Value>) -> Response {
    match state.bus.store.ingest_otel_spans(&payload) {
        Ok(ingested) => Json(json!({ "ingested_spans": ingested })).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}
