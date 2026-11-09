use crate::api::enforce_loopback_host_and_origin;
use crate::bus::EventBus;
use crate::config::WbConfig;
use crate::mcp_parser::{extract_tools_call_checks, parse_mcp_payload, ParsedMcpFrame};
use crate::models::*;
use crate::modules::analyze_context_window;
use crate::pricing::PriceTable;
use crate::proxy_stdio::now_ns;
use axum::{
    body::Body,
    extract::{Path as AxumPath, Request, State},
    http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{any, post},
    Json, Router,
};
use bytes::Bytes;
use futures::StreamExt;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::Read;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use uuid::Uuid;

/// Maximum bytes buffered in memory per HTTP response for observation (H6).
const MAX_OBSERVATION_BUFFER_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone)]
pub struct ProxyState {
    pub config: Arc<Mutex<WbConfig>>,
    pub bus: EventBus,
    pub price_table: Arc<PriceTable>,
    pub http_client: reqwest::Client,
}

pub fn build_proxy_router(state: ProxyState) -> Router {
    Router::new()
        .route("/mcp/:server_id", any(handle_mcp_http_root))
        .route("/mcp/:server_id/*rest", any(handle_mcp_http_subpath))
        .route("/v1/chat/completions", post(handle_llm_proxy))
        .route("/v1/responses", post(handle_llm_proxy))
        .route("/v1/messages", post(handle_llm_proxy))
        .route("/fake-llm/v1/chat/completions", post(handle_fake_llm))
        .route("/fake-llm/v1/messages", post(handle_fake_llm))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_proxy_token_if_configured,
        ))
        .layer(middleware::from_fn(enforce_loopback_host_and_origin))
        .with_state(state)
}

/// Optional proxy token check (B4). If `daemon.proxy_token` is set in `wb.toml`,
/// callers must supply it via `X-WB-Proxy-Token`, `X-WB-Token`, or `Authorization: Bearer`.
async fn require_proxy_token_if_configured(
    State(state): State<ProxyState>,
    req: Request,
    next: Next,
) -> Response {
    let expected_opt = {
        let cfg = state.config.lock().unwrap();
        cfg.daemon
            .proxy_token
            .clone()
            .filter(|s| !s.trim().is_empty())
    };
    let Some(expected) = expected_opt else {
        return next.run(req).await;
    };

    let headers = req.headers();
    if let Some(tok) = headers
        .get("x-wb-proxy-token")
        .or_else(|| headers.get("x-wb-token"))
        .and_then(|v| v.to_str().ok())
    {
        if tok.trim() == expected {
            return next.run(req).await;
        }
    }
    if let Some(auth) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        if let Some(tok) = auth
            .strip_prefix("Bearer ")
            .or_else(|| auth.strip_prefix("bearer "))
        {
            if tok.trim() == expected {
                return next.run(req).await;
            }
        }
    }

    (
        StatusCode::UNAUTHORIZED,
        Json(json!({
            "error": "Unauthorized: valid proxy_token required"
        })),
    )
        .into_response()
}

fn is_hop_by_hop_or_internal_header(lower_name: &str) -> bool {
    matches!(
        lower_name,
        "host"
            | "content-length"
            | "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "x-mcp-upstream"
            | "x-llm-upstream"
            | "x-wb-proxy-token"
            | "x-fake-llm-scenario"
    )
}

/// Prevents SSRF to the daemon's own UI port or proxy port (B4).
fn is_forbidden_self_upstream(url: &str, ui_port: u16, mcp_port: u16) -> bool {
    let lower = url.trim().to_lowercase();
    let without_scheme = lower
        .strip_prefix("http://")
        .or_else(|| lower.strip_prefix("https://"))
        .unwrap_or(&lower);
    let host_port = without_scheme.split('/').next().unwrap_or("");
    let (host, port_opt) = if host_port.starts_with('[') {
        if let Some(idx) = host_port.find(']') {
            let h = &host_port[..=idx];
            let p = host_port[idx + 1..]
                .strip_prefix(':')
                .and_then(|s| s.parse::<u16>().ok());
            (h, p)
        } else {
            (host_port, None)
        }
    } else if let Some((h, p_str)) = host_port.split_once(':') {
        (h, p_str.parse::<u16>().ok())
    } else {
        (host_port, None)
    };

    let is_loopback = matches!(
        host,
        "127.0.0.1" | "localhost" | "[::1]" | "0.0.0.0" | "::1"
    );
    if is_loopback {
        if let Some(p) = port_opt {
            if p == ui_port || p == mcp_port {
                return true;
            }
        }
    }
    false
}

async fn handle_mcp_http_root(
    State(state): State<ProxyState>,
    AxumPath(server_id): AxumPath<String>,
    req: Request,
) -> Response {
    handle_mcp_http_inner(state, server_id, String::new(), req).await
}

async fn handle_mcp_http_subpath(
    State(state): State<ProxyState>,
    AxumPath((server_id, rest)): AxumPath<(String, String)>,
    req: Request,
) -> Response {
    handle_mcp_http_inner(state, server_id, format!("/{}", rest), req).await
}

async fn handle_mcp_http_inner(
    state: ProxyState,
    server_id: String,
    subpath: String,
    req: Request,
) -> Response {
    let start_ns = now_ns();
    let method = req.method().clone();
    let headers = req.headers().clone();
    let query = req
        .uri()
        .query()
        .map(|q| format!("?{}", q))
        .unwrap_or_default();

    // B4: Resolve upstream URL from config; only allow `x-mcp-upstream` if `dev_mode` is enabled
    // or if the header URL matches an already-configured server upstream.
    let (configured_upstream, dev_mode, ui_port, mcp_port, is_allowed_header_upstream) = {
        let cfg = state.config.lock().unwrap();
        let configured = cfg
            .servers
            .iter()
            .find(|s| s.id == server_id)
            .and_then(|s| s.upstream.clone());
        let hdr_up = headers
            .get("x-mcp-upstream")
            .and_then(|v| v.to_str().ok())
            .map(String::from);
        let matches_configured = hdr_up.as_ref().is_some_and(|u| {
            cfg.servers
                .iter()
                .any(|s| s.upstream.as_deref() == Some(u.as_str()))
        });
        (
            configured,
            cfg.daemon.dev_mode,
            cfg.daemon.ui_port,
            cfg.daemon.mcp_port,
            matches_configured,
        )
    };

    let header_upstream = headers
        .get("x-mcp-upstream")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    if let Some(ref hdr_url) = header_upstream {
        if !dev_mode && !is_allowed_header_upstream {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({
                    "jsonrpc": "2.0",
                    "id": null,
                    "error": {
                        "code": -32003,
                        "message": "Header-chosen x-mcp-upstream is disabled unless --dev mode is enabled or URL is in [[server]]"
                    }
                })),
            )
                .into_response();
        }
        if is_forbidden_self_upstream(hdr_url, ui_port, mcp_port) {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({
                    "jsonrpc": "2.0",
                    "id": null,
                    "error": {
                        "code": -32003,
                        "message": "Forbidden upstream target (cannot proxy to Workbench daemon ports)"
                    }
                })),
            )
                .into_response();
        }
    }

    let upstream_base = if dev_mode || is_allowed_header_upstream {
        header_upstream.or(configured_upstream)
    } else {
        configured_upstream
    };

    let Some(base_url) = upstream_base else {
        return (
            StatusCode::BAD_GATEWAY,
            Json(json!({
                "jsonrpc": "2.0",
                "id": null,
                "error": {
                    "code": -32002,
                    "message": format!("No upstream configured for MCP HTTP server '{}'", server_id)
                }
            })),
        )
            .into_response();
    };

    if is_forbidden_self_upstream(&base_url, ui_port, mcp_port) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "jsonrpc": "2.0",
                "id": null,
                "error": {
                    "code": -32003,
                    "message": "Forbidden upstream target (cannot proxy to Workbench daemon ports)"
                }
            })),
        )
            .into_response();
    }

    let target_url = format!("{}{}{}", base_url.trim_end_matches('/'), subpath, query);

    let header_proto_version = headers
        .get("mcp-protocol-version")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    // M11: Distinct session ID when Mcp-Session-Id is absent
    let session_id = headers
        .get("mcp-session-id")
        .or_else(|| headers.get("x-wb-session-id"))
        .and_then(|v| v.to_str().ok())
        .map(String::from)
        .unwrap_or_else(|| format!("http-sess-{}-{}", server_id, Uuid::new_v4()));

    let header_traceparent = headers
        .get("traceparent")
        .and_then(|v| v.to_str().ok())
        .map(normalize_trace_id);

    let explicit_run_id = headers
        .get("x-wb-run-id")
        .and_then(|v| v.to_str().ok())
        .map(String::from)
        .or_else(|| header_traceparent.as_ref().map(|tp| format!("run-tp-{}", tp)))
        .unwrap_or_else(|| "auto".to_string());

    let req_bytes = match axum::body::to_bytes(req.into_body(), 100 * 1024 * 1024).await {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("Failed to read request body: {}", e),
            )
                .into_response();
        }
    };

    let req_str = String::from_utf8_lossy(&req_bytes).into_owned();
    let parsed_req = parse_mcp_payload(
        &req_str,
        &server_id,
        header_proto_version.as_deref(),
        false,
    );

    // Register server observation
    state.bus.publish(WorkbenchEvent::ServerObserved {
        server_id: server_id.clone(),
        transport: "http".to_string(),
        command_or_url: base_url.clone(),
        command_argv: Vec::new(),
        protocol_version: header_proto_version.clone(),
        deprecated_feature: None,
    });

    // B3, H1, M7: Evaluate Policy & Circuit Breaker on every `tools/call` (single or JSON-RPC batch)
    let span_id = normalize_span_id(&format!("span-{}", Uuid::new_v4()));
    let tool_checks = extract_tools_call_checks(&req_str);
    let mut policy_checked = false;

    for (id_raw, tool_name, arguments_raw) in &tool_checks {
        policy_checked = true;
        let id_key = serde_json::to_string(id_raw).unwrap_or_else(|_| "null".to_string());
        let check = state.bus.check_tool_call_policy(
            &session_id,
            &explicit_run_id,
            &span_id,
            &server_id,
            tool_name,
            arguments_raw,
            start_ns,
            false,
            None,
        );
        if !check.allowed {
            let reason = check
                .reason
                .unwrap_or_else(|| "Denied by policy".to_string());
            let err_payload = json!({
                "jsonrpc": "2.0",
                "id": id_raw,
                "error": {
                    "code": -32001,
                    "message": format!("MCP Workbench Policy Block: {}", reason)
                }
            });
            let err_str = serde_json::to_string(&err_payload).unwrap_or_default();

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
                Value::String(tool_name.clone()),
            );
            attrs.insert(
                semconv::GEN_AI_TOOL_CALL_ARGUMENTS.to_string(),
                Value::String(arguments_raw.clone()),
            );
            attrs.insert(
                semconv::NETWORK_TRANSPORT.to_string(),
                Value::String("tcp".to_string()),
            );
            attrs.insert(semconv::WB_POLICY_CHECKED.to_string(), Value::Bool(true));
            attrs.insert("policy.blocked".to_string(), Value::Bool(true));
            attrs.insert("error.message".to_string(), Value::String(reason));

            let trace_id = header_traceparent
                .clone()
                .unwrap_or_else(|| normalize_trace_id(&session_id));

            let blocked_span = Span {
                id: span_id.clone(),
                trace_id,
                run_id: explicit_run_id,
                parent_id: None,
                kind: SpanKind::Mcp,
                name: format!("tools/call {}", tool_name),
                start_ns,
                end_ns: Some(now_ns()),
                status: SpanStatus::Blocked,
                attributes: attrs,
            };
            state.bus.publish(WorkbenchEvent::SpanRecorded {
                span: blocked_span,
                session_id,
                run_label: None,
                mcp_messages: vec![
                    McpMessage {
                        id: 0,
                        span_id: span_id.clone(),
                        direction: MessageDirection::ClientToServer,
                        jsonrpc_id: Some(id_key.clone()),
                        method: Some("tools/call".to_string()),
                        payload: Some(req_str),
                        bytes: req_bytes.len(),
                        timestamp_ns: start_ns,
                    },
                    McpMessage {
                        id: 0,
                        span_id,
                        direction: MessageDirection::ServerToClient,
                        jsonrpc_id: Some(id_key),
                        method: Some("tools/call".to_string()),
                        payload: Some(err_str.clone()),
                        bytes: err_str.len(),
                        timestamp_ns: now_ns(),
                    },
                ],
                model_call: None,
                policy_decisions: Vec::new(),
            });

            return (
                StatusCode::OK,
                [("content-type", "application/json")],
                err_str,
            )
                .into_response();
        }
    }

    // M6: Map all HTTP methods and preserve multi-value & non-ASCII headers
    let req_method = reqwest::Method::from_bytes(method.as_str().as_bytes())
        .unwrap_or(reqwest::Method::POST);
    let mut upstream_req = state.http_client.request(req_method, &target_url);
    for (k, v) in headers.iter() {
        let name = k.as_str().to_lowercase();
        if is_hop_by_hop_or_internal_header(&name) {
            continue;
        }
        if let (Ok(hn), Ok(hv)) = (
            reqwest::header::HeaderName::from_bytes(k.as_str().as_bytes()),
            reqwest::header::HeaderValue::from_bytes(v.as_bytes()),
        ) {
            upstream_req = upstream_req.header(hn, hv);
        }
    }
    if !req_bytes.is_empty() {
        upstream_req = upstream_req.body(req_bytes.clone());
    }

    let upstream_resp = match upstream_req.send().await {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                format!("Upstream MCP HTTP connection error: {}", e),
            )
                .into_response();
        }
    };

    let resp_status =
        StatusCode::from_u16(upstream_resp.status().as_u16()).unwrap_or(StatusCode::OK);
    let mut resp_headers = HeaderMap::new();
    for (k, v) in upstream_resp.headers().iter() {
        let name = k.as_str().to_lowercase();
        if name == "transfer-encoding" || name == "content-length" {
            continue;
        }
        if let (Ok(hn), Ok(hv)) = (
            HeaderName::from_bytes(k.as_str().as_bytes()),
            HeaderValue::from_bytes(v.as_bytes()),
        ) {
            resp_headers.append(hn, hv);
        }
    }

    let content_encoding = upstream_resp
        .headers()
        .get("content-encoding")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    let is_sse = upstream_resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.contains("text/event-stream"))
        .unwrap_or(false);

    let is_get_sse = is_sse && method == axum::http::Method::GET;

    // Stream response chunks byte-for-byte to the client while teeing to an accumulator for observation (H6)
    let (client_tx, client_rx) = mpsc::channel::<Result<Bytes, std::io::Error>>(128);
    let bus_clone = state.bus.clone();
    let req_bytes_len = req_bytes.len();

    tokio::spawn(async move {
        let mut byte_stream = upstream_resp.bytes_stream();
        let mut collected = Vec::new();
        let mut sse_line_buf = String::new();
        let mut total_resp_bytes = 0usize;

        while let Some(chunk_res) = byte_stream.next().await {
            match chunk_res {
                Ok(chunk) => {
                    total_resp_bytes += chunk.len();
                    if collected.len() < MAX_OBSERVATION_BUFFER_BYTES {
                        let remaining = MAX_OBSERVATION_BUFFER_BYTES - collected.len();
                        let take_len = remaining.min(chunk.len());
                        collected.extend_from_slice(&chunk[..take_len]);
                    }

                    // H6: For long-lived GET SSE streams, parse and emit one span per SSE event as it arrives
                    if is_get_sse {
                        sse_line_buf.push_str(&String::from_utf8_lossy(&chunk));
                        while let Some(pos) = sse_line_buf.find("\n\n") {
                            let event_block = sse_line_buf[..pos].to_string();
                            sse_line_buf.drain(..pos + 2);
                            for data_payload in extract_sse_data_lines(&event_block) {
                                if !data_payload.trim().is_empty() {
                                    let ev_now = now_ns();
                                    let ev_span_id =
                                        normalize_span_id(&format!("sse-{}", Uuid::new_v4()));
                                    record_http_mcp_exchange(
                                        &bus_clone,
                                        &server_id,
                                        &session_id,
                                        &explicit_run_id,
                                        ev_span_id,
                                        ev_now,
                                        ev_now,
                                        header_proto_version.clone(),
                                        header_traceparent.clone(),
                                        ParsedMcpFrame::Malformed,
                                        "",
                                        0,
                                        &data_payload,
                                        data_payload.len(),
                                        true,
                                        resp_status.is_success(),
                                        false,
                                    );
                                }
                            }
                        }
                    }

                    if client_tx.send(Ok(chunk)).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    let _ = client_tx
                        .send(Err(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            e.to_string(),
                        )))
                        .await;
                    break;
                }
            }
        }

        if !is_get_sse {
            let end_ns = now_ns();
            let resp_raw =
                decompress_for_observation(&collected, content_encoding.as_deref());
            record_http_mcp_exchange(
                &bus_clone,
                &server_id,
                &session_id,
                &explicit_run_id,
                span_id,
                start_ns,
                end_ns,
                header_proto_version,
                header_traceparent,
                parsed_req,
                &req_str,
                req_bytes_len,
                &resp_raw,
                total_resp_bytes,
                is_sse,
                resp_status.is_success(),
                policy_checked,
            );
        }
    });

    let body = Body::from_stream(ReceiverStream::new(client_rx));
    let mut response = Response::new(body);
    *response.status_mut() = resp_status;
    *response.headers_mut() = resp_headers;
    response
}

#[allow(clippy::too_many_arguments)]
fn record_http_mcp_exchange(
    bus: &EventBus,
    server_id: &str,
    session_id: &str,
    run_id: &str,
    span_id: String,
    start_ns: u64,
    end_ns: u64,
    header_proto_version: Option<String>,
    header_traceparent: Option<String>,
    parsed_req: ParsedMcpFrame,
    req_str: &str,
    req_bytes_len: usize,
    resp_raw: &str,
    resp_bytes_len: usize,
    is_sse: bool,
    http_ok: bool,
    policy_checked: bool,
) {
    // Extract JSON-RPC payload from SSE `data:` lines if response was an SSE stream
    let effective_resp_json = if is_sse {
        extract_sse_data_lines(resp_raw)
            .into_iter()
            .last()
            .unwrap_or_else(|| resp_raw.to_string())
    } else {
        resp_raw.to_string()
    };

    let parsed_resp = parse_mcp_payload(
        &effective_resp_json,
        server_id,
        header_proto_version.as_deref(),
        false,
    );

    let mut attrs = BTreeMap::new();
    attrs.insert(
        semconv::MCP_SERVER_ID.to_string(),
        Value::String(server_id.to_string()),
    );
    attrs.insert(
        semconv::NETWORK_TRANSPORT.to_string(),
        Value::String("tcp".to_string()),
    );
    if is_sse {
        attrs.insert("http.response.sse".to_string(), Value::Bool(true));
    }
    if policy_checked {
        attrs.insert(semconv::WB_POLICY_CHECKED.to_string(), Value::Bool(true));
    }

    let mut span_name = "mcp.http".to_string();
    let mut req_id_opt = None;
    let mut method_opt = None;
    let mut trace_id = header_traceparent.unwrap_or_else(|| normalize_trace_id(session_id));
    let mut is_elicitation = false;

    if let ParsedMcpFrame::Request {
        id_key,
        method,
        is_known_method,
        protocol_version,
        protocol_era,
        tool_name,
        tool_arguments_raw,
        task_id,
        is_elicitation: elic,
        deprecated_feature,
        traceparent,
        ..
    } = parsed_req
    {
        req_id_opt = Some(id_key.clone());
        method_opt = Some(method.clone());
        is_elicitation = elic;
        if let Some(tp) = traceparent {
            trace_id = normalize_trace_id(&tp);
        }
        attrs.insert(
            semconv::JSONRPC_REQUEST_ID.to_string(),
            Value::String(id_key),
        );
        attrs.insert(
            semconv::MCP_PROTOCOL_ERA.to_string(),
            Value::String(protocol_era),
        );
        if let Some(ref ver) = protocol_version {
            attrs.insert(
                semconv::MCP_PROTOCOL_VERSION.to_string(),
                Value::String(ver.clone()),
            );
        }
        if is_known_method {
            attrs.insert(
                semconv::MCP_METHOD_NAME.to_string(),
                Value::String(method.clone()),
            );
        } else {
            attrs.insert(
                semconv::MCP_METHOD_NAME.to_string(),
                Value::String("unknown".to_string()),
            );
            attrs.insert("mcp.raw_method".to_string(), Value::String(method.clone()));
        }
        if let Some(ref t) = tool_name {
            span_name = format!("tools/call {}", t);
            attrs.insert(
                semconv::GEN_AI_TOOL_NAME.to_string(),
                Value::String(t.clone()),
            );
        } else {
            span_name = method;
        }
        if let Some(args) = tool_arguments_raw {
            attrs.insert(
                semconv::GEN_AI_TOOL_CALL_ARGUMENTS.to_string(),
                Value::String(args),
            );
        }
        if let Some(tid) = task_id {
            attrs.insert(semconv::MCP_TASK_ID.to_string(), Value::String(tid));
        }
        if let Some(ref dep) = deprecated_feature {
            attrs.insert(
                "mcp.deprecated_feature".to_string(),
                Value::String(dep.clone()),
            );
        }
        if protocol_version.is_some() || deprecated_feature.is_some() {
            bus.publish(WorkbenchEvent::ServerObserved {
                server_id: server_id.to_string(),
                transport: "http".to_string(),
                command_or_url: String::new(),
                command_argv: Vec::new(),
                protocol_version,
                deprecated_feature,
            });
        }
    } else if let ParsedMcpFrame::Notification { method, .. } = &parsed_resp {
        span_name = method.clone();
        method_opt = Some(method.clone());
        attrs.insert(
            semconv::MCP_METHOD_NAME.to_string(),
            Value::String(if crate::mcp_parser::is_known_mcp_method(method) {
                method.clone()
            } else {
                "unknown".to_string()
            }),
        );
    }

    let mut is_err = !http_ok;
    if let ParsedMcpFrame::Response {
        is_error,
        error_message,
        negotiated_version,
        discovered_tools,
        result_raw,
        ..
    } = parsed_resp
    {
        if is_error {
            is_err = true;
        }
        if let Some(err_msg) = error_message {
            attrs.insert("error.message".to_string(), Value::String(err_msg));
        }
        if let Some(ver) = negotiated_version {
            attrs.insert(
                semconv::MCP_PROTOCOL_VERSION.to_string(),
                Value::String(ver.clone()),
            );
            bus.publish(WorkbenchEvent::ServerObserved {
                server_id: server_id.to_string(),
                transport: "http".to_string(),
                command_or_url: String::new(),
                command_argv: Vec::new(),
                protocol_version: Some(ver),
                deprecated_feature: None,
            });
        }
        if let Some(tools) = discovered_tools {
            bus.publish(WorkbenchEvent::ToolsDiscovered {
                server_id: server_id.to_string(),
                tools,
            });
        }
        if let Some(res_str) = result_raw {
            if method_opt.as_deref() == Some("tools/call") {
                attrs.insert(
                    semconv::GEN_AI_TOOL_CALL_RESULT.to_string(),
                    Value::String(res_str),
                );
            }
        }
    }

    let status = if is_err {
        SpanStatus::Error
    } else if is_elicitation && resp_raw.trim().is_empty() {
        SpanStatus::WaitingHuman
    } else {
        SpanStatus::Ok
    };

    let mut messages = Vec::new();
    if req_bytes_len > 0 {
        messages.push(McpMessage {
            id: 0,
            span_id: span_id.clone(),
            direction: MessageDirection::ClientToServer,
            jsonrpc_id: req_id_opt.clone(),
            method: method_opt.clone(),
            payload: Some(req_str.to_string()),
            bytes: req_bytes_len,
            timestamp_ns: start_ns,
        });
    }
    if resp_bytes_len > 0 {
        messages.push(McpMessage {
            id: 0,
            span_id: span_id.clone(),
            direction: MessageDirection::ServerToClient,
            jsonrpc_id: req_id_opt,
            method: method_opt,
            payload: Some(resp_raw.to_string()),
            bytes: resp_bytes_len,
            timestamp_ns: end_ns,
        });
    }

    let span = Span {
        id: span_id,
        trace_id,
        run_id: run_id.to_string(),
        parent_id: None,
        kind: SpanKind::Mcp,
        name: span_name,
        start_ns,
        end_ns: Some(end_ns),
        status,
        attributes: attrs,
    };

    bus.publish(WorkbenchEvent::SpanRecorded {
        span,
        session_id: session_id.to_string(),
        run_label: None,
        mcp_messages: messages,
        model_call: None,
        policy_decisions: Vec::new(),
    });
}

fn extract_sse_data_lines(raw_sse: &str) -> Vec<String> {
    let mut events = Vec::new();
    let mut current_data = Vec::new();
    for line in raw_sse.lines() {
        let trimmed = line.trim_end_matches('\r');
        if let Some(rest) = trimmed.strip_prefix("data:") {
            current_data.push(rest.trim_start().to_string());
        } else if trimmed.is_empty() && !current_data.is_empty() {
            events.push(current_data.join("\n"));
            current_data.clear();
        }
    }
    if !current_data.is_empty() {
        events.push(current_data.join("\n"));
    }
    events
}

/// H4: Decompresses `gzip`, `deflate`, or `zstd` response bodies in memory *only* for observation
/// and token-usage parsing, while the raw compressed bytes are streamed untouched to the client.
fn decompress_for_observation(raw_bytes: &[u8], content_encoding: Option<&str>) -> String {
    let Some(enc) = content_encoding else {
        return String::from_utf8_lossy(raw_bytes).into_owned();
    };
    let lower = enc.trim().to_lowercase();
    if lower.contains("gzip") || lower.contains("x-gzip") {
        let mut decoder = flate2::read::GzDecoder::new(raw_bytes);
        let mut out = Vec::new();
        if decoder.read_to_end(&mut out).is_ok() {
            return String::from_utf8_lossy(&out).into_owned();
        }
    } else if lower.contains("deflate") {
        let mut decoder = flate2::read::ZlibDecoder::new(raw_bytes);
        let mut out = Vec::new();
        if decoder.read_to_end(&mut out).is_ok() {
            return String::from_utf8_lossy(&out).into_owned();
        }
        let mut raw_decoder = flate2::read::DeflateDecoder::new(raw_bytes);
        out.clear();
        if raw_decoder.read_to_end(&mut out).is_ok() {
            return String::from_utf8_lossy(&out).into_owned();
        }
    } else if lower.contains("zstd") {
        if let Ok(out) = zstd::stream::decode_all(raw_bytes) {
            return String::from_utf8_lossy(&out).into_owned();
        }
    }
    String::from_utf8_lossy(raw_bytes).into_owned()
}

/// Proxies OpenAI-compatible (`/v1/chat/completions`, `/v1/responses`) and
/// Anthropic-compatible (`/v1/messages`) LLM requests, supporting both JSON and streaming SSE (§4.1, §11).
async fn handle_llm_proxy(
    State(state): State<ProxyState>,
    req: Request,
) -> Response {
    let start_ns = now_ns();
    let uri_path = req.uri().path().to_string();
    let headers = req.headers().clone();

    let is_anthropic = uri_path.contains("/v1/messages");
    let provider = if is_anthropic { "anthropic" } else { "openai" };

    // H2: Unique session ID if not provided, and link run via x-wb-run-id / traceparent / active run
    let session_id = headers
        .get("x-wb-session-id")
        .and_then(|v| v.to_str().ok())
        .map(String::from)
        .unwrap_or_else(|| format!("llm-sess-{}", Uuid::new_v4()));

    let header_traceparent = headers
        .get("traceparent")
        .and_then(|v| v.to_str().ok())
        .map(normalize_trace_id);

    let explicit_run_id = headers
        .get("x-wb-run-id")
        .and_then(|v| v.to_str().ok())
        .map(String::from)
        .or_else(|| header_traceparent.as_ref().map(|tp| format!("run-tp-{}", tp)))
        .unwrap_or_else(|| "auto".to_string());

    // H2: Check Circuit Breaker budget keyed by run_id before forwarding LLM call
    {
        let mods = state.bus.modules.lock().unwrap();
        if let Verdict::Block(reason) = mods.breaker.check_llm_call(&explicit_run_id) {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({
                    "error": {
                        "type": "circuit_breaker_tripped",
                        "message": reason
                    }
                })),
            )
                .into_response();
        }
    }

    let req_bytes = match axum::body::to_bytes(req.into_body(), 100 * 1024 * 1024).await {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("Failed to read LLM request body: {}", e),
            )
                .into_response();
        }
    };

    let req_str = String::from_utf8_lossy(&req_bytes).into_owned();
    let req_json: Value = serde_json::from_str(&req_str).unwrap_or_else(|_| json!({}));
    let model_name = req_json
        .get("model")
        .and_then(|m| m.as_str())
        .unwrap_or("unknown-model")
        .to_string();

    let (configured_upstream, dev_mode, ui_port, mcp_port) = {
        let cfg = state.config.lock().unwrap();
        let up = if is_anthropic {
            cfg.daemon
                .anthropic_upstream
                .clone()
                .or_else(|| cfg.daemon.llm_upstream.clone())
        } else {
            cfg.daemon.llm_upstream.clone()
        };
        (
            up,
            cfg.daemon.dev_mode,
            cfg.daemon.ui_port,
            cfg.daemon.mcp_port,
        )
    };

    // B4: Disallow header-chosen `x-llm-upstream` unless `dev_mode` is enabled or it matches config
    let header_llm_upstream = headers
        .get("x-llm-upstream")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    if let Some(ref hdr_url) = header_llm_upstream {
        let matches_configured = configured_upstream.as_deref() == Some(hdr_url.as_str());
        if !dev_mode && !matches_configured {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({
                    "error": {
                        "type": "forbidden_upstream",
                        "message": "Header-chosen x-llm-upstream is disabled unless --dev mode is enabled"
                    }
                })),
            )
                .into_response();
        }
        if is_forbidden_self_upstream(hdr_url, ui_port, mcp_port) {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({
                    "error": {
                        "type": "forbidden_upstream",
                        "message": "Cannot proxy to Workbench daemon ports"
                    }
                })),
            )
                .into_response();
        }
    }

    let upstream_override = if dev_mode {
        header_llm_upstream.or(configured_upstream)
    } else {
        configured_upstream
    };

    // M15: Fake LLM is only reachable when configured (`llm_upstream = "fake"`) or in `dev_mode`
    let use_fake = upstream_override.as_deref() == Some("fake")
        || (dev_mode && headers.contains_key("x-fake-llm-scenario"));

    if use_fake {
        let fake_resp = generate_fake_llm_response(&headers, &req_json, is_anthropic);
        return finalize_and_stream_llm_response(
            state,
            fake_resp,
            start_ns,
            provider.to_string(),
            model_name,
            session_id,
            explicit_run_id,
            header_traceparent,
            req_str,
            req_json,
        )
        .await;
    }

    let base_url = upstream_override.unwrap_or_else(|| {
        if is_anthropic {
            "https://api.anthropic.com".to_string()
        } else {
            "https://api.openai.com".to_string()
        }
    });

    if is_forbidden_self_upstream(&base_url, ui_port, mcp_port) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": {
                    "type": "forbidden_upstream",
                    "message": "Cannot proxy to Workbench daemon ports"
                }
            })),
        )
            .into_response();
    }

    let target_url = format!("{}{}", base_url.trim_end_matches('/'), uri_path);

    let mut upstream_req = state
        .http_client
        .request(reqwest::Method::POST, &target_url);
    for (k, v) in headers.iter() {
        let name = k.as_str().to_lowercase();
        if is_hop_by_hop_or_internal_header(&name) {
            continue;
        }
        if let (Ok(hn), Ok(hv)) = (
            reqwest::header::HeaderName::from_bytes(k.as_str().as_bytes()),
            reqwest::header::HeaderValue::from_bytes(v.as_bytes()),
        ) {
            upstream_req = upstream_req.header(hn, hv);
        }
    }
    upstream_req = upstream_req.body(req_bytes);

    let upstream_resp = match upstream_req.send().await {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                format!("Upstream LLM connection error: {}", e),
            )
                .into_response();
        }
    };

    let resp_status =
        StatusCode::from_u16(upstream_resp.status().as_u16()).unwrap_or(StatusCode::OK);
    let mut resp_headers = HeaderMap::new();
    for (k, v) in upstream_resp.headers().iter() {
        let name = k.as_str().to_lowercase();
        if name == "transfer-encoding" || name == "content-length" {
            continue;
        }
        if let (Ok(hn), Ok(hv)) = (
            HeaderName::from_bytes(k.as_str().as_bytes()),
            HeaderValue::from_bytes(v.as_bytes()),
        ) {
            resp_headers.append(hn, hv);
        }
    }

    let content_encoding = upstream_resp
        .headers()
        .get("content-encoding")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    let is_sse = upstream_resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.contains("text/event-stream"))
        .unwrap_or(false);

    let (client_tx, client_rx) = mpsc::channel::<Result<Bytes, std::io::Error>>(128);
    let bus_clone = state.bus.clone();
    let price_table = state.price_table.clone();
    let provider_str = provider.to_string();

    tokio::spawn(async move {
        let mut byte_stream = upstream_resp.bytes_stream();
        let mut collected = Vec::new();
        while let Some(chunk_res) = byte_stream.next().await {
            match chunk_res {
                Ok(chunk) => {
                    if collected.len() < MAX_OBSERVATION_BUFFER_BYTES {
                        let remaining = MAX_OBSERVATION_BUFFER_BYTES - collected.len();
                        let take_len = remaining.min(chunk.len());
                        collected.extend_from_slice(&chunk[..take_len]);
                    }
                    if client_tx.send(Ok(chunk)).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    let _ = client_tx
                        .send(Err(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            e.to_string(),
                        )))
                        .await;
                    break;
                }
            }
        }
        let end_ns = now_ns();
        // H4: Decompress response copy in memory for usage/cost extraction while raw bytes went to client
        let resp_raw = decompress_for_observation(&collected, content_encoding.as_deref());
        record_llm_call(
            &bus_clone,
            &price_table,
            &provider_str,
            &model_name,
            &session_id,
            &explicit_run_id,
            header_traceparent,
            start_ns,
            end_ns,
            &req_str,
            &req_json,
            &resp_raw,
            is_sse,
            resp_status.is_success(),
        );
    });

    let body = Body::from_stream(ReceiverStream::new(client_rx));
    let mut response = Response::new(body);
    *response.status_mut() = resp_status;
    *response.headers_mut() = resp_headers;
    response
}

struct FakeLlmOutput {
    status: StatusCode,
    is_sse: bool,
    chunks: Vec<Bytes>,
}

async fn handle_fake_llm(
    State(state): State<ProxyState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // M15: Gate `/fake-llm/v1/*` behind `dev_mode` or `llm_upstream = "fake"`
    let allowed = {
        let cfg = state.config.lock().unwrap();
        cfg.daemon.dev_mode || cfg.daemon.llm_upstream.as_deref() == Some("fake")
    };
    if !allowed {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Fake LLM endpoint requires --dev mode"})),
        )
            .into_response();
    }

    let req_json: Value = serde_json::from_slice(&body).unwrap_or_else(|_| json!({}));
    let out = generate_fake_llm_response(&headers, &req_json, false);
    let content_type = if out.is_sse {
        "text/event-stream"
    } else {
        "application/json"
    };
    let stream = futures::stream::iter(out.chunks.into_iter().map(Ok::<_, std::io::Error>));
    (
        out.status,
        [(
            HeaderName::from_static("content-type"),
            HeaderValue::from_static(content_type),
        )],
        Body::from_stream(stream),
    )
        .into_response()
}

fn generate_fake_llm_response(
    headers: &HeaderMap,
    req_json: &Value,
    is_anthropic: bool,
) -> FakeLlmOutput {
    let scenario = headers
        .get("x-fake-llm-scenario")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("default");
    let model = req_json
        .get("model")
        .and_then(|m| m.as_str())
        .unwrap_or("gpt-4o");
    let stream_requested = req_json
        .get("stream")
        .and_then(|s| s.as_bool())
        .unwrap_or(false)
        || scenario.starts_with("stream");

    if scenario == "stream_no_usage" {
        let chunks = vec![
            Bytes::from("data: {\"id\":\"chatcmpl-fake\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"Hello \"}}]}\n\n"),
            Bytes::from("data: {\"id\":\"chatcmpl-fake\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"from streamed completion without usage block.\"},\"finish_reason\":\"stop\"}]}\n\n"),
            Bytes::from("data: [DONE]\n\n"),
        ];
        return FakeLlmOutput {
            status: StatusCode::OK,
            is_sse: true,
            chunks,
        };
    }

    if stream_requested {
        let chunks = vec![
            Bytes::from(format!(
                "data: {{\"id\":\"chatcmpl-fake\",\"model\":\"{}\",\"choices\":[{{\"index\":0,\"delta\":{{\"role\":\"assistant\",\"content\":\"Analyzing \"}}}}]}}\n\n",
                model
            )),
            Bytes::from(format!(
                "data: {{\"id\":\"chatcmpl-fake\",\"model\":\"{}\",\"choices\":[{{\"index\":0,\"delta\":{{\"content\":\"invoice records.\"}},\"finish_reason\":\"stop\"}}],\"usage\":{{\"prompt_tokens\":1200,\"completion_tokens\":300,\"prompt_tokens_details\":{{\"cached_tokens\":200}}}}}}\n\n",
                model
            )),
            Bytes::from("data: [DONE]\n\n"),
        ];
        return FakeLlmOutput {
            status: StatusCode::OK,
            is_sse: true,
            chunks,
        };
    }

    if scenario == "loop" {
        let payload = json!({
            "id": "chatcmpl-loop",
            "object": "chat.completion",
            "model": model,
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": null,
                    "tool_calls": [{
                        "id": "call_loop_1",
                        "type": "function",
                        "function": {
                            "name": "read_file",
                            "arguments": "{\"path\":\"/workspace/invoice.pdf\"}"
                        }
                    }]
                },
                "finish_reason": "tool_calls"
            }],
            "usage": {
                "prompt_tokens": 2000,
                "completion_tokens": 150,
                "total_tokens": 2150
            }
        });
        return FakeLlmOutput {
            status: StatusCode::OK,
            is_sse: false,
            chunks: vec![Bytes::from(serde_json::to_vec(&payload).unwrap())],
        };
    }

    if is_anthropic {
        let payload = json!({
            "id": "msg_fake_01",
            "type": "message",
            "role": "assistant",
            "model": model,
            "content": [
                {
                    "type": "text",
                    "text": "Deterministic Anthropic response from Workbench fake provider."
                }
            ],
            "stop_reason": "end_turn",
            "usage": {
                "input_tokens": 1500,
                "cache_read_input_tokens": 500,
                "output_tokens": 250
            }
        });
        return FakeLlmOutput {
            status: StatusCode::OK,
            is_sse: false,
            chunks: vec![Bytes::from(serde_json::to_vec(&payload).unwrap())],
        };
    }

    let payload = json!({
        "id": "chatcmpl-fake-01",
        "object": "chat.completion",
        "model": model,
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": "Deterministic OpenAI response from Workbench fake provider."
            },
            "finish_reason": "stop"
        }],
        "usage": {
            "prompt_tokens": 1000,
            "completion_tokens": 200,
            "total_tokens": 1200,
            "prompt_tokens_details": {
                "cached_tokens": 200
            }
        }
    });

    FakeLlmOutput {
        status: StatusCode::OK,
        is_sse: false,
        chunks: vec![Bytes::from(serde_json::to_vec(&payload).unwrap())],
    }
}

#[allow(clippy::too_many_arguments)]
async fn finalize_and_stream_llm_response(
    state: ProxyState,
    fake: FakeLlmOutput,
    start_ns: u64,
    provider: String,
    model_name: String,
    session_id: String,
    run_id: String,
    header_traceparent: Option<String>,
    req_str: String,
    req_json: Value,
) -> Response {
    let mut all_bytes = Vec::new();
    for c in &fake.chunks {
        all_bytes.extend_from_slice(c);
    }
    let resp_raw = String::from_utf8_lossy(&all_bytes).into_owned();
    let end_ns = now_ns();

    record_llm_call(
        &state.bus,
        &state.price_table,
        &provider,
        &model_name,
        &session_id,
        &run_id,
        header_traceparent,
        start_ns,
        end_ns,
        &req_str,
        &req_json,
        &resp_raw,
        fake.is_sse,
        fake.status.is_success(),
    );

    let content_type = if fake.is_sse {
        "text/event-stream"
    } else {
        "application/json"
    };
    let stream = futures::stream::iter(fake.chunks.into_iter().map(Ok::<_, std::io::Error>));
    (
        fake.status,
        [(
            HeaderName::from_static("content-type"),
            HeaderValue::from_static(content_type),
        )],
        Body::from_stream(stream),
    )
        .into_response()
}

#[allow(clippy::too_many_arguments)]
fn record_llm_call(
    bus: &EventBus,
    price_table: &PriceTable,
    provider: &str,
    model_name: &str,
    session_id: &str,
    run_id: &str,
    header_traceparent: Option<String>,
    start_ns: u64,
    end_ns: u64,
    req_str: &str,
    req_json: &Value,
    resp_raw: &str,
    is_sse: bool,
    http_ok: bool,
) {
    let (
        input_tokens,
        cached_tokens,
        output_tokens,
        cost_estimated,
        finish_reason,
        reassembled_text,
    ) = extract_llm_usage_and_completion(req_str, resp_raw, is_sse);

    let cost_usd =
        price_table.calculate_cost(model_name, input_tokens, cached_tokens, output_tokens);
    let context_breakdown = analyze_context_window(
        req_json,
        if cost_estimated {
            None
        } else {
            Some(input_tokens)
        },
    );

    let span_id = normalize_span_id(&format!("llm-{}", Uuid::new_v4()));
    let mut attrs = BTreeMap::new();
    attrs.insert(
        semconv::GEN_AI_SYSTEM.to_string(),
        Value::String(provider.to_string()),
    );
    attrs.insert(
        semconv::GEN_AI_REQUEST_MODEL.to_string(),
        Value::String(model_name.to_string()),
    );
    attrs.insert(
        semconv::GEN_AI_USAGE_INPUT_TOKENS.to_string(),
        json!(input_tokens),
    );
    attrs.insert(
        semconv::GEN_AI_USAGE_OUTPUT_TOKENS.to_string(),
        json!(output_tokens),
    );
    attrs.insert(
        semconv::GEN_AI_USAGE_CACHED_TOKENS.to_string(),
        json!(cached_tokens),
    );
    attrs.insert("gen_ai.cost_usd".to_string(), json!(cost_usd));
    attrs.insert("gen_ai.cost_estimated".to_string(), json!(cost_estimated));
    if let Some(ref warning) = context_breakdown.bloat_warning {
        attrs.insert(
            "xray.bloat_warning".to_string(),
            Value::String(warning.clone()),
        );
    }

    let response_payload_to_store = if is_sse && !reassembled_text.is_empty() {
        json!({
            "stream_reassembled": reassembled_text,
            "raw_sse": resp_raw
        })
        .to_string()
    } else {
        resp_raw.to_string()
    };

    let model_call = ModelCall {
        span_id: span_id.clone(),
        provider: provider.to_string(),
        model: model_name.to_string(),
        input_tokens,
        output_tokens,
        cached_tokens,
        cost_usd,
        cost_estimated,
        finish_reason,
        context_breakdown,
        request_payload: Some(req_str.to_string()),
        response_payload: Some(response_payload_to_store),
    };

    let trace_id = header_traceparent.unwrap_or_else(|| normalize_trace_id(session_id));

    let span = Span {
        id: span_id,
        trace_id,
        run_id: run_id.to_string(),
        parent_id: None,
        kind: SpanKind::Llm,
        name: format!("chat {}", model_name),
        start_ns,
        end_ns: Some(end_ns),
        status: if http_ok {
            SpanStatus::Ok
        } else {
            SpanStatus::Error
        },
        attributes: attrs,
    };

    bus.publish(WorkbenchEvent::SpanRecorded {
        span,
        session_id: session_id.to_string(),
        run_label: None,
        mcp_messages: Vec::new(),
        model_call: Some(model_call),
        policy_decisions: Vec::new(),
    });
}

fn extract_llm_usage_and_completion(
    req_str: &str,
    resp_raw: &str,
    is_sse: bool,
) -> (u64, u64, u64, bool, Option<String>, String) {
    let mut input_tokens = None;
    let mut cached_tokens = 0u64;
    let mut output_tokens = None;
    let mut finish_reason = None;
    let mut reassembled = String::new();

    if is_sse {
        for data_line in extract_sse_data_lines(resp_raw) {
            if data_line.trim() == "[DONE]" {
                continue;
            }
            if let Ok(val) = serde_json::from_str::<Value>(&data_line) {
                if let Some(choices) = val.get("choices").and_then(|c| c.as_array()) {
                    for choice in choices {
                        if let Some(content) = choice
                            .get("delta")
                            .and_then(|d| d.get("content"))
                            .and_then(|c| c.as_str())
                        {
                            reassembled.push_str(content);
                        }
                        if let Some(fr) = choice.get("finish_reason").and_then(|f| f.as_str()) {
                            finish_reason = Some(fr.to_string());
                        }
                    }
                }
                if let Some(usage) = val.get("usage") {
                    parse_usage_object(
                        usage,
                        &mut input_tokens,
                        &mut cached_tokens,
                        &mut output_tokens,
                    );
                }
            }
        }
    } else if let Ok(val) = serde_json::from_str::<Value>(resp_raw) {
        if let Some(usage) = val.get("usage") {
            parse_usage_object(
                usage,
                &mut input_tokens,
                &mut cached_tokens,
                &mut output_tokens,
            );
        }
        if let Some(choices) = val.get("choices").and_then(|c| c.as_array()) {
            if let Some(first) = choices.first() {
                if let Some(fr) = first.get("finish_reason").and_then(|f| f.as_str()) {
                    finish_reason = Some(fr.to_string());
                }
            }
        } else if let Some(sr) = val.get("stop_reason").and_then(|s| s.as_str()) {
            finish_reason = Some(sr.to_string());
        }
    }

    match (input_tokens, output_tokens) {
        (Some(inp), Some(out)) => (inp, cached_tokens, out, false, finish_reason, reassembled),
        _ => {
            // §11: When a stream ends without a usage block, estimate with tokenizer and mark with `~`
            let est_in = PriceTable::estimate_tokens(req_str);
            let est_out = if !reassembled.is_empty() {
                PriceTable::estimate_tokens(&reassembled)
            } else {
                PriceTable::estimate_tokens(resp_raw)
            };
            (est_in, 0, est_out, true, finish_reason, reassembled)
        }
    }
}

fn parse_usage_object(
    usage: &Value,
    input_tokens: &mut Option<u64>,
    cached_tokens: &mut u64,
    output_tokens: &mut Option<u64>,
) {
    if let Some(pt) = usage
        .get("prompt_tokens")
        .or_else(|| usage.get("input_tokens"))
        .and_then(|v| v.as_u64())
    {
        let cache_read = usage
            .get("cache_read_input_tokens")
            .and_then(|v| v.as_u64())
            .or_else(|| {
                usage
                    .get("prompt_tokens_details")
                    .and_then(|d| d.get("cached_tokens"))
                    .and_then(|v| v.as_u64())
            })
            .unwrap_or(0);
        // For Anthropic, input_tokens + cache_read_input_tokens is total input
        if usage.get("cache_read_input_tokens").is_some() {
            *input_tokens = Some(pt + cache_read);
        } else {
            *input_tokens = Some(pt);
        }
        *cached_tokens = cache_read;
    }
    if let Some(ct) = usage
        .get("completion_tokens")
        .or_else(|| usage.get("output_tokens"))
        .and_then(|v| v.as_u64())
    {
        *output_tokens = Some(ct);
    }
}
