use crate::bus::EventBus;
use crate::mcp_parser::{parse_mcp_payload, ParsedMcpFrame};
use crate::models::*;
use anyhow::{Context, Result};
use chrono::Utc;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::process::Command;
use tokio::sync::mpsc;
use uuid::Uuid;

pub fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

/// Starts the Unix domain socket listener inside `wbd` that receives observation events
/// and synchronous policy checks from `wb wrap` instances.
pub async fn start_ipc_listener(socket_path: PathBuf, bus: EventBus) -> Result<()> {
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if socket_path.exists() {
        let _ = std::fs::remove_file(&socket_path);
    }

    let listener = UnixListener::bind(&socket_path)
        .with_context(|| format!("Failed to bind Unix IPC socket at {}", socket_path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600));
    }

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            let bus_clone = bus.clone();
            tokio::spawn(async move {
                let _ = handle_ipc_connection(stream, bus_clone).await;
            });
        }
    });

    Ok(())
}

async fn handle_ipc_connection(stream: UnixStream, bus: EventBus) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();

    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let Ok(req) = serde_json::from_str::<IpcRequest>(&line) else {
            continue;
        };
        match req {
            IpcRequest::ObserveEvent { event } => {
                bus.publish(event);
            }
            IpcRequest::PolicyCheck {
                session_id,
                server_id,
                tool_name,
                arguments_raw,
                ..
            } => {
                let span_id = format!("pol-{}", Uuid::new_v4());
                let resp = bus.check_tool_call_policy(
                    &session_id,
                    &span_id,
                    &server_id,
                    &tool_name,
                    &arguments_raw,
                    now_ns(),
                );
                let mut encoded = serde_json::to_string(&resp)?;
                encoded.push('\n');
                writer.write_all(encoded.as_bytes()).await?;
                writer.flush().await?;
            }
        }
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct PendingRequest {
    span_id: String,
    trace_id: String,
    method: String,
    tool_name: Option<String>,
    start_ns: u64,
    is_elicitation: bool,
    request_msg: McpMessage,
    attributes: BTreeMap<String, Value>,
}

#[derive(Debug)]
enum RawLineDirection {
    ClientToServer(String, usize, u64),
    ServerToClient(String, usize, u64),
}

/// Runs `wb wrap --id <server_id> [--policy] -- <command> <args...>`.
/// Forwards stdin/stdout byte-for-byte with fail-open observation and fail-closed policy (§4.1, §8).
pub async fn run_stdio_wrapper(
    server_id: String,
    command: String,
    args: Vec<String>,
    socket_path: PathBuf,
    policy_enforced: bool,
    run_id_override: Option<String>,
) -> Result<i32> {
    let session_id = format!("sess-{}", Uuid::new_v4());
    let run_id = run_id_override.unwrap_or_else(|| "auto".to_string());
    let full_cmd = if args.is_empty() {
        command.clone()
    } else {
        format!("{} {}", command, args.join(" "))
    };

    let mut child = Command::new(&command)
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("Failed to spawn wrapped MCP server '{}'", full_cmd))?;

    let mut child_stdin = child.stdin.take().expect("child stdin piped");
    let mut child_stdout = child.stdout.take().expect("child stdout piped");
    let mut child_stderr = child.stderr.take().expect("child stderr piped");

    // Channel for asynchronous observation processing so forwarding never blocks
    let (obs_tx, mut obs_rx) = mpsc::unbounded_channel::<RawLineDirection>();
    let sock_for_obs = socket_path.clone();
    let server_id_obs = server_id.clone();
    let session_id_obs = session_id.clone();
    let run_id_obs = run_id.clone();
    let full_cmd_obs = full_cmd.clone();

    let obs_handle = tokio::spawn(async move {
        let mut ipc_stream: Option<UnixStream> = UnixStream::connect(&sock_for_obs).await.ok();

        // Send initial session and server registration events
        let init_events = vec![
            WorkbenchEvent::SessionStarted {
                session: Session {
                    id: session_id_obs.clone(),
                    started_at: Utc::now().to_rfc3339(),
                    client_name: None,
                    client_version: None,
                    negotiated_version: None,
                    capabilities_json: None,
                },
            },
            WorkbenchEvent::ServerObserved {
                server_id: server_id_obs.clone(),
                transport: "stdio".to_string(),
                command_or_url: full_cmd_obs.clone(),
                protocol_version: None,
                deprecated_feature: None,
            },
        ];
        for ev in init_events {
            send_ipc_observe(&mut ipc_stream, &sock_for_obs, ev).await;
        }

        let mut pending: HashMap<String, PendingRequest> = HashMap::new();
        let mut task_origins: HashMap<String, String> = HashMap::new();
        let mut session_has_initialize = false;

        while let Some(item) = obs_rx.recv().await {
            match item {
                RawLineDirection::ClientToServer(line, byte_len, ts_ns) => {
                    let parsed = parse_mcp_payload(&line, &server_id_obs, None, session_has_initialize);
                    process_client_frame(
                        parsed,
                        &line,
                        byte_len,
                        ts_ns,
                        &server_id_obs,
                        &session_id_obs,
                        &run_id_obs,
                        &mut session_has_initialize,
                        &mut pending,
                        &task_origins,
                        &mut ipc_stream,
                        &sock_for_obs,
                    )
                    .await;
                }
                RawLineDirection::ServerToClient(line, byte_len, ts_ns) => {
                    let parsed = parse_mcp_payload(&line, &server_id_obs, None, session_has_initialize);
                    process_server_frame(
                        parsed,
                        &line,
                        byte_len,
                        ts_ns,
                        &server_id_obs,
                        &session_id_obs,
                        &run_id_obs,
                        &mut pending,
                        &mut task_origins,
                        &mut ipc_stream,
                        &sock_for_obs,
                    )
                    .await;
                }
            }
        }

        // Flush any remaining in-flight requests (e.g., if server crashed mid-response)
        let end_ns = now_ns();
        for (_, req) in pending.drain() {
            let span = Span {
                id: req.span_id.clone(),
                trace_id: req.trace_id,
                run_id: run_id_obs.clone(),
                parent_id: None,
                kind: SpanKind::Mcp,
                name: req
                    .tool_name
                    .as_ref()
                    .map(|t| format!("tools/call {}", t))
                    .unwrap_or_else(|| req.method.clone()),
                start_ns: req.start_ns,
                end_ns: Some(end_ns),
                status: SpanStatus::Error,
                attributes: req.attributes,
            };
            send_ipc_observe(
                &mut ipc_stream,
                &sock_for_obs,
                WorkbenchEvent::SpanRecorded {
                    span,
                    session_id: session_id_obs.clone(),
                    run_label: None,
                    mcp_messages: vec![req.request_msg],
                    model_call: None,
                    policy_decisions: Vec::new(),
                },
            )
            .await;
        }

        // Wait for daemon IPC reader to process all sent lines before closing
        if let Some(mut stream) = ipc_stream.take() {
            let _ = stream.shutdown().await;
            let mut ack_buf = [0u8; 8];
            let _ = stream.read(&mut ack_buf).await;
        }
    });

    // Shared stdout lock so policy error responses and child stdout never interleave
    let stdout_lock = Arc::new(Mutex::new(std::io::stdout()));

    // Task 1: Forward stdin -> child_stdin
    let obs_tx_stdin = obs_tx.clone();
    let stdout_for_policy = stdout_lock.clone();
    let sock_for_policy = socket_path.clone();
    let server_for_policy = server_id.clone();
    let session_for_policy = session_id.clone();
    let run_for_policy = run_id.clone();

    let stdin_task = tokio::spawn(async move {
        let mut stdin = tokio::io::stdin();
        let mut buf = vec![0u8; 65536];
        let mut line_acc: Vec<u8> = Vec::with_capacity(4096);

        loop {
            let Ok(n) = stdin.read(&mut buf).await else {
                break;
            };
            if n == 0 {
                // Flush any trailing unterminated bytes in policy mode
                if policy_enforced && !line_acc.is_empty() {
                    let _ = child_stdin.write_all(&line_acc).await;
                    let _ = child_stdin.flush().await;
                    line_acc.clear();
                }
                break;
            }
            let chunk = &buf[..n];

            if !policy_enforced {
                // Observation mode: write exact bytes immediately before doing anything else!
                if child_stdin.write_all(chunk).await.is_err() {
                    break;
                }
                let _ = child_stdin.flush().await;

                line_acc.extend_from_slice(chunk);
                while let Some(pos) = line_acc.iter().position(|&b| b == b'\n') {
                    let raw_line: Vec<u8> = line_acc.drain(..=pos).collect();
                    let byte_len = raw_line.len();
                    let line_str = String::from_utf8_lossy(&raw_line).into_owned();
                    let _ = obs_tx_stdin.send(RawLineDirection::ClientToServer(
                        line_str,
                        byte_len,
                        now_ns(),
                    ));
                }
            } else {
                // Policy mode: inspect complete JSON-RPC lines for `tools/call` before forwarding
                line_acc.extend_from_slice(chunk);
                while let Some(pos) = line_acc.iter().position(|&b| b == b'\n') {
                    let raw_line: Vec<u8> = line_acc.drain(..=pos).collect();
                    let byte_len = raw_line.len();
                    let line_str = String::from_utf8_lossy(&raw_line).into_owned();
                    let ts_ns = now_ns();

                    if let Some((req_id_val, tool_name, args_raw)) =
                        extract_tools_call_check(&line_str)
                    {
                        let check_res = check_policy_over_ipc(
                            &sock_for_policy,
                            &session_for_policy,
                            &run_for_policy,
                            &server_for_policy,
                            &tool_name,
                            &args_raw,
                        )
                        .await;

                        if !check_res.allowed {
                            let reason = check_res.reason.unwrap_or_else(|| {
                                "Blocked by policy (daemon unreachable or rule denied)".to_string()
                            });
                            let err_json = json!({
                                "jsonrpc": "2.0",
                                "id": req_id_val,
                                "error": {
                                    "code": -32001,
                                    "message": format!("MCP Workbench Policy Block: {}", reason)
                                }
                            });
                            let mut err_line = serde_json::to_string(&err_json).unwrap_or_default();
                            if raw_line.ends_with(b"\r\n") {
                                err_line.push_str("\r\n");
                            } else {
                                err_line.push('\n');
                            }
                            {
                                use std::io::Write;
                                let mut out = stdout_for_policy.lock().unwrap();
                                let _ = out.write_all(err_line.as_bytes());
                                let _ = out.flush();
                            }
                            continue;
                        }
                    }

                    if child_stdin.write_all(&raw_line).await.is_err() {
                        break;
                    }
                    let _ = child_stdin.flush().await;
                    let _ = obs_tx_stdin.send(RawLineDirection::ClientToServer(
                        line_str, byte_len, ts_ns,
                    ));
                }
            }
        }
        drop(child_stdin);
    });

    // Task 2: Forward child_stdout -> stdout byte-for-byte
    let obs_tx_stdout = obs_tx.clone();
    let stdout_for_child = stdout_lock.clone();
    let stdout_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        let mut line_acc: Vec<u8> = Vec::with_capacity(4096);

        loop {
            let Ok(n) = child_stdout.read(&mut buf).await else {
                break;
            };
            if n == 0 {
                if !line_acc.is_empty() {
                    let byte_len = line_acc.len();
                    let line_str = String::from_utf8_lossy(&line_acc).into_owned();
                    let _ = obs_tx_stdout.send(RawLineDirection::ServerToClient(
                        line_str,
                        byte_len,
                        now_ns(),
                    ));
                    line_acc.clear();
                }
                break;
            }
            let chunk = &buf[..n];
            {
                use std::io::Write;
                let mut out = stdout_for_child.lock().unwrap();
                if out.write_all(chunk).is_err() {
                    break;
                }
                let _ = out.flush();
            }

            line_acc.extend_from_slice(chunk);
            while let Some(pos) = line_acc.iter().position(|&b| b == b'\n') {
                let raw_line: Vec<u8> = line_acc.drain(..=pos).collect();
                let byte_len = raw_line.len();
                let line_str = String::from_utf8_lossy(&raw_line).into_owned();
                let _ = obs_tx_stdout.send(RawLineDirection::ServerToClient(
                    line_str,
                    byte_len,
                    now_ns(),
                ));
            }
        }
    });

    // Task 3: Forward child_stderr -> stderr untouched
    let stderr_task = tokio::spawn(async move {
        let mut stderr = tokio::io::stderr();
        let mut buf = vec![0u8; 16384];
        loop {
            let Ok(n) = child_stderr.read(&mut buf).await else {
                break;
            };
            if n == 0 {
                break;
            }
            if stderr.write_all(&buf[..n]).await.is_err() {
                break;
            }
            let _ = stderr.flush().await;
        }
    });

    let status = child.wait().await?;
    let _ = stdout_task.await;
    let _ = stderr_task.await;
    stdin_task.abort();
    drop(obs_tx);

    // Wait briefly for the observation channel to finish flushing to `wbd`
    let _ = tokio::time::timeout(Duration::from_millis(250), obs_handle).await;

    Ok(status.code().unwrap_or(1))
}

fn extract_tools_call_check(line: &str) -> Option<(Value, String, String)> {
    let val: Value = serde_json::from_str(line.trim()).ok()?;
    let method = val.get("method")?.as_str()?;
    if method != "tools/call" {
        return None;
    }
    let id_val = val.get("id")?.clone();
    let params = val.get("params")?;
    let tool_name = params.get("name")?.as_str()?.to_string();
    let args_raw = params
        .get("arguments")
        .map(|a| a.to_string())
        .unwrap_or_else(|| "{}".to_string());
    Some((id_val, tool_name, args_raw))
}

/// Fail-closed policy check over IPC (§8): if `wbd` is unreachable, returns `allowed: false`.
async fn check_policy_over_ipc(
    socket_path: &Path,
    session_id: &str,
    run_id: &str,
    server_id: &str,
    tool_name: &str,
    arguments_raw: &str,
) -> IpcResponse {
    let Ok(Ok(stream)) =
        tokio::time::timeout(Duration::from_millis(500), UnixStream::connect(socket_path)).await
    else {
        return IpcResponse {
            allowed: false,
            reason: Some(
                "Policy enforcement is enabled (fail-closed) and Workbench daemon (wbd) is unreachable"
                    .to_string(),
            ),
            rule_id: Some("fail-closed".to_string()),
        };
    };

    let (reader, mut writer) = stream.into_split();
    let req = IpcRequest::PolicyCheck {
        session_id: session_id.to_string(),
        run_id: Some(run_id.to_string()),
        server_id: server_id.to_string(),
        tool_name: tool_name.to_string(),
        arguments_raw: arguments_raw.to_string(),
    };
    let Ok(mut payload) = serde_json::to_string(&req) else {
        return IpcResponse {
            allowed: false,
            reason: Some("Failed to serialize policy check".to_string()),
            rule_id: None,
        };
    };
    payload.push('\n');

    if writer.write_all(payload.as_bytes()).await.is_err() || writer.flush().await.is_err() {
        return IpcResponse {
            allowed: false,
            reason: Some("Policy IPC write failed (fail-closed)".to_string()),
            rule_id: Some("fail-closed".to_string()),
        };
    }

    let mut lines = BufReader::new(reader).lines();
    if let Ok(Ok(Some(resp_line))) =
        tokio::time::timeout(Duration::from_millis(500), lines.next_line()).await
    {
        if let Ok(parsed) = serde_json::from_str::<IpcResponse>(&resp_line) {
            return parsed;
        }
    }

    IpcResponse {
        allowed: false,
        reason: Some("Policy IPC read timed out or daemon closed connection (fail-closed)".to_string()),
        rule_id: Some("fail-closed".to_string()),
    }
}

async fn send_ipc_observe(
    stream_opt: &mut Option<UnixStream>,
    socket_path: &Path,
    event: WorkbenchEvent,
) {
    if stream_opt.is_none() {
        *stream_opt = UnixStream::connect(socket_path).await.ok();
    }
    let Some(stream) = stream_opt.as_mut() else {
        return;
    };
    let req = IpcRequest::ObserveEvent { event };
    let Ok(mut encoded) = serde_json::to_string(&req) else {
        return;
    };
    encoded.push('\n');
    if stream.write_all(encoded.as_bytes()).await.is_err() || stream.flush().await.is_err() {
        *stream_opt = None;
    }
}

#[allow(clippy::too_many_arguments)]
async fn process_client_frame(
    frame: ParsedMcpFrame,
    raw_line: &str,
    byte_len: usize,
    ts_ns: u64,
    server_id: &str,
    session_id: &str,
    run_id: &str,
    session_has_initialize: &mut bool,
    pending: &mut HashMap<String, PendingRequest>,
    task_origins: &HashMap<String, String>,
    ipc_stream: &mut Option<UnixStream>,
    socket_path: &Path,
) {
    match frame {
        ParsedMcpFrame::Batch(items) => {
            for item in items {
                Box::pin(process_client_frame(
                    item,
                    raw_line,
                    byte_len,
                    ts_ns,
                    server_id,
                    session_id,
                    run_id,
                    session_has_initialize,
                    pending,
                    task_origins,
                    ipc_stream,
                    socket_path,
                ))
                .await;
            }
        }
        ParsedMcpFrame::Request {
            id,
            method,
            is_known_method,
            protocol_version,
            protocol_era,
            tool_name,
            tool_arguments_raw,
            task_id,
            is_elicitation,
            deprecated_feature,
            traceparent,
            client_name,
            client_version,
            ..
        } => {
            if method == "initialize" {
                *session_has_initialize = true;
                if client_name.is_some() || client_version.is_some() {
                    send_ipc_observe(
                        ipc_stream,
                        socket_path,
                        WorkbenchEvent::SessionStarted {
                            session: Session {
                                id: session_id.to_string(),
                                started_at: Utc::now().to_rfc3339(),
                                client_name,
                                client_version,
                                negotiated_version: protocol_version.clone(),
                                capabilities_json: None,
                            },
                        },
                    )
                    .await;
                }
            }

            if protocol_version.is_some() || deprecated_feature.is_some() {
                send_ipc_observe(
                    ipc_stream,
                    socket_path,
                    WorkbenchEvent::ServerObserved {
                        server_id: server_id.to_string(),
                        transport: "stdio".to_string(),
                        command_or_url: String::new(),
                        protocol_version: protocol_version.clone(),
                        deprecated_feature: deprecated_feature.clone(),
                    },
                )
                .await;
            }

            let span_id = format!("span-{}", Uuid::new_v4());
            let trace_id = traceparent
                .clone()
                .unwrap_or_else(|| format!("trace-{}", session_id));

            let mut attrs = BTreeMap::new();
            attrs.insert(
                semconv::MCP_SERVER_ID.to_string(),
                Value::String(server_id.to_string()),
            );
            attrs.insert(
                semconv::NETWORK_TRANSPORT.to_string(),
                Value::String("pipe".to_string()),
            );
            attrs.insert(
                semconv::JSONRPC_REQUEST_ID.to_string(),
                Value::String(id.clone()),
            );
            attrs.insert(
                semconv::MCP_PROTOCOL_ERA.to_string(),
                Value::String(protocol_era),
            );
            if let Some(ver) = protocol_version {
                attrs.insert(semconv::MCP_PROTOCOL_VERSION.to_string(), Value::String(ver));
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
            if let Some(ref t_name) = tool_name {
                attrs.insert(
                    semconv::GEN_AI_TOOL_NAME.to_string(),
                    Value::String(t_name.clone()),
                );
            }
            if let Some(ref args) = tool_arguments_raw {
                attrs.insert(
                    semconv::GEN_AI_TOOL_CALL_ARGUMENTS.to_string(),
                    Value::String(args.clone()),
                );
            }
            if let Some(ref tid) = task_id {
                attrs.insert(semconv::MCP_TASK_ID.to_string(), Value::String(tid.clone()));
                if let Some(origin_span) = task_origins.get(tid) {
                    attrs.insert(
                        "mcp.task.origin_span_id".to_string(),
                        Value::String(origin_span.clone()),
                    );
                }
            }
            if let Some(dep) = deprecated_feature {
                attrs.insert("mcp.deprecated_feature".to_string(), Value::String(dep));
            }

            let req_msg = McpMessage {
                id: 0,
                span_id: span_id.clone(),
                direction: MessageDirection::ClientToServer,
                jsonrpc_id: Some(id.clone()),
                method: Some(method.clone()),
                payload: Some(raw_line.trim_end().to_string()),
                bytes: byte_len,
                timestamp_ns: ts_ns,
            };

            // If elicitation, immediately emit an in-flight span marked WaitingHuman (§6)
            if is_elicitation {
                let elicitation_span = Span {
                    id: span_id.clone(),
                    trace_id: trace_id.clone(),
                    run_id: run_id.to_string(),
                    parent_id: None,
                    kind: SpanKind::Mcp,
                    name: method.clone(),
                    start_ns: ts_ns,
                    end_ns: None,
                    status: SpanStatus::WaitingHuman,
                    attributes: attrs.clone(),
                };
                send_ipc_observe(
                    ipc_stream,
                    socket_path,
                    WorkbenchEvent::SpanRecorded {
                        span: elicitation_span,
                        session_id: session_id.to_string(),
                        run_label: None,
                        mcp_messages: vec![req_msg.clone()],
                        model_call: None,
                        policy_decisions: Vec::new(),
                    },
                )
                .await;
            }

            pending.insert(
                id,
                PendingRequest {
                    span_id,
                    trace_id,
                    method,
                    tool_name,
                    start_ns: ts_ns,
                    is_elicitation,
                    request_msg: req_msg,
                    attributes: attrs,
                },
            );
        }
        ParsedMcpFrame::Notification {
            method,
            protocol_version,
            deprecated_feature,
        } => {
            if protocol_version.is_some() || deprecated_feature.is_some() {
                send_ipc_observe(
                    ipc_stream,
                    socket_path,
                    WorkbenchEvent::ServerObserved {
                        server_id: server_id.to_string(),
                        transport: "stdio".to_string(),
                        command_or_url: String::new(),
                        protocol_version,
                        deprecated_feature,
                    },
                )
                .await;
            }
            let span_id = format!("span-{}", Uuid::new_v4());
            let mut attrs = BTreeMap::new();
            attrs.insert(
                semconv::MCP_SERVER_ID.to_string(),
                Value::String(server_id.to_string()),
            );
            attrs.insert(
                semconv::MCP_METHOD_NAME.to_string(),
                Value::String(method.clone()),
            );
            attrs.insert(
                semconv::NETWORK_TRANSPORT.to_string(),
                Value::String("pipe".to_string()),
            );
            let span = Span {
                id: span_id.clone(),
                trace_id: format!("trace-{}", session_id),
                run_id: run_id.to_string(),
                parent_id: None,
                kind: SpanKind::Mcp,
                name: method.clone(),
                start_ns: ts_ns,
                end_ns: Some(ts_ns),
                status: SpanStatus::Ok,
                attributes: attrs,
            };
            let msg = McpMessage {
                id: 0,
                span_id,
                direction: MessageDirection::ClientToServer,
                jsonrpc_id: None,
                method: Some(method),
                payload: Some(raw_line.trim_end().to_string()),
                bytes: byte_len,
                timestamp_ns: ts_ns,
            };
            send_ipc_observe(
                ipc_stream,
                socket_path,
                WorkbenchEvent::SpanRecorded {
                    span,
                    session_id: session_id.to_string(),
                    run_label: None,
                    mcp_messages: vec![msg],
                    model_call: None,
                    policy_decisions: Vec::new(),
                },
            )
            .await;
        }
        _ => {}
    }
}

#[allow(clippy::too_many_arguments)]
async fn process_server_frame(
    frame: ParsedMcpFrame,
    raw_line: &str,
    byte_len: usize,
    ts_ns: u64,
    server_id: &str,
    session_id: &str,
    run_id: &str,
    pending: &mut HashMap<String, PendingRequest>,
    task_origins: &mut HashMap<String, String>,
    ipc_stream: &mut Option<UnixStream>,
    socket_path: &Path,
) {
    match frame {
        ParsedMcpFrame::Batch(items) => {
            for item in items {
                Box::pin(process_server_frame(
                    item,
                    raw_line,
                    byte_len,
                    ts_ns,
                    server_id,
                    session_id,
                    run_id,
                    pending,
                    task_origins,
                    ipc_stream,
                    socket_path,
                ))
                .await;
            }
        }
        ParsedMcpFrame::Response {
            id,
            is_error,
            error_message,
            negotiated_version,
            capabilities_json,
            discovered_tools,
            task_id,
            result_raw,
        } => {
            if negotiated_version.is_some() || capabilities_json.is_some() {
                send_ipc_observe(
                    ipc_stream,
                    socket_path,
                    WorkbenchEvent::SessionStarted {
                        session: Session {
                            id: session_id.to_string(),
                            started_at: Utc::now().to_rfc3339(),
                            client_name: None,
                            client_version: None,
                            negotiated_version: negotiated_version.clone(),
                            capabilities_json,
                        },
                    },
                )
                .await;
                if let Some(ver) = negotiated_version.clone() {
                    send_ipc_observe(
                        ipc_stream,
                        socket_path,
                        WorkbenchEvent::ServerObserved {
                            server_id: server_id.to_string(),
                            transport: "stdio".to_string(),
                            command_or_url: String::new(),
                            protocol_version: Some(ver),
                            deprecated_feature: None,
                        },
                    )
                    .await;
                }
            }

            if let Some(tools) = discovered_tools {
                send_ipc_observe(
                    ipc_stream,
                    socket_path,
                    WorkbenchEvent::ToolsDiscovered {
                        server_id: server_id.to_string(),
                        tools,
                    },
                )
                .await;
            }

            if let Some(mut req) = pending.remove(&id) {
                if let Some(tid) = task_id {
                    task_origins
                        .entry(tid.clone())
                        .or_insert_with(|| req.span_id.clone());
                    req.attributes
                        .insert(semconv::MCP_TASK_ID.to_string(), Value::String(tid));
                }
                if let Some(res_str) = result_raw {
                    if req.method == "tools/call" {
                        req.attributes.insert(
                            semconv::GEN_AI_TOOL_CALL_RESULT.to_string(),
                            Value::String(res_str),
                        );
                    }
                }
                if let Some(err_msg) = error_message {
                    req.attributes
                        .insert("error.message".to_string(), Value::String(err_msg));
                }
                if let Some(ver) = negotiated_version {
                    req.attributes
                        .insert(semconv::MCP_PROTOCOL_VERSION.to_string(), Value::String(ver));
                }

                let resp_msg = McpMessage {
                    id: 0,
                    span_id: req.span_id.clone(),
                    direction: MessageDirection::ServerToClient,
                    jsonrpc_id: Some(id),
                    method: Some(req.method.clone()),
                    payload: Some(raw_line.trim_end().to_string()),
                    bytes: byte_len,
                    timestamp_ns: ts_ns,
                };

                let status = if is_error {
                    SpanStatus::Error
                } else {
                    SpanStatus::Ok
                };

                if req.is_elicitation {
                    send_ipc_observe(
                        ipc_stream,
                        socket_path,
                        WorkbenchEvent::SpanUpdated {
                            span_id: req.span_id,
                            end_ns: ts_ns,
                            status,
                            attributes_patch: req.attributes,
                            response_message: Some(resp_msg),
                        },
                    )
                    .await;
                } else {
                    let span_name = match req.tool_name {
                        Some(ref t) => format!("tools/call {}", t),
                        None => req.method.clone(),
                    };
                    let parent_id = req
                        .attributes
                        .get("mcp.task.origin_span_id")
                        .and_then(|v| v.as_str())
                        .map(String::from)
                        .or_else(|| {
                            req.attributes
                                .get(semconv::MCP_TASK_ID)
                                .and_then(|v| v.as_str())
                                .and_then(|tid| task_origins.get(tid))
                                .filter(|&orig| orig != &req.span_id)
                                .cloned()
                        });

                    let span = Span {
                        id: req.span_id,
                        trace_id: req.trace_id,
                        run_id: run_id.to_string(),
                        parent_id,
                        kind: SpanKind::Mcp,
                        name: span_name,
                        start_ns: req.start_ns,
                        end_ns: Some(ts_ns),
                        status,
                        attributes: req.attributes,
                    };
                    send_ipc_observe(
                        ipc_stream,
                        socket_path,
                        WorkbenchEvent::SpanRecorded {
                            span,
                            session_id: session_id.to_string(),
                            run_label: None,
                            mcp_messages: vec![req.request_msg, resp_msg],
                            model_call: None,
                            policy_decisions: Vec::new(),
                        },
                    )
                    .await;
                }
            } else {
                // Unpaired response (e.g., malformed upstream sending response with unknown ID)
                let span_id = format!("span-{}", Uuid::new_v4());
                let mut attrs = BTreeMap::new();
                attrs.insert(
                    semconv::MCP_SERVER_ID.to_string(),
                    Value::String(server_id.to_string()),
                );
                attrs.insert(
                    semconv::JSONRPC_REQUEST_ID.to_string(),
                    Value::String(id.clone()),
                );
                attrs.insert("mcp.unpaired_response".to_string(), Value::Bool(true));
                let span = Span {
                    id: span_id.clone(),
                    trace_id: format!("trace-{}", session_id),
                    run_id: run_id.to_string(),
                    parent_id: None,
                    kind: SpanKind::Mcp,
                    name: "unpaired_response".to_string(),
                    start_ns: ts_ns,
                    end_ns: Some(ts_ns),
                    status: if is_error {
                        SpanStatus::Error
                    } else {
                        SpanStatus::Ok
                    },
                    attributes: attrs,
                };
                let resp_msg = McpMessage {
                    id: 0,
                    span_id,
                    direction: MessageDirection::ServerToClient,
                    jsonrpc_id: Some(id),
                    method: None,
                    payload: Some(raw_line.trim_end().to_string()),
                    bytes: byte_len,
                    timestamp_ns: ts_ns,
                };
                send_ipc_observe(
                    ipc_stream,
                    socket_path,
                    WorkbenchEvent::SpanRecorded {
                        span,
                        session_id: session_id.to_string(),
                        run_label: None,
                        mcp_messages: vec![resp_msg],
                        model_call: None,
                        policy_decisions: Vec::new(),
                    },
                )
                .await;
            }
        }
        ParsedMcpFrame::Notification {
            method,
            protocol_version,
            deprecated_feature,
        } => {
            if protocol_version.is_some() || deprecated_feature.is_some() {
                send_ipc_observe(
                    ipc_stream,
                    socket_path,
                    WorkbenchEvent::ServerObserved {
                        server_id: server_id.to_string(),
                        transport: "stdio".to_string(),
                        command_or_url: String::new(),
                        protocol_version,
                        deprecated_feature,
                    },
                )
                .await;
            }
            let span_id = format!("span-{}", Uuid::new_v4());
            let mut attrs = BTreeMap::new();
            attrs.insert(
                semconv::MCP_SERVER_ID.to_string(),
                Value::String(server_id.to_string()),
            );
            attrs.insert(
                semconv::MCP_METHOD_NAME.to_string(),
                Value::String(method.clone()),
            );
            attrs.insert(
                semconv::NETWORK_TRANSPORT.to_string(),
                Value::String("pipe".to_string()),
            );
            let span = Span {
                id: span_id.clone(),
                trace_id: format!("trace-{}", session_id),
                run_id: run_id.to_string(),
                parent_id: None,
                kind: SpanKind::Mcp,
                name: method.clone(),
                start_ns: ts_ns,
                end_ns: Some(ts_ns),
                status: SpanStatus::Ok,
                attributes: attrs,
            };
            let msg = McpMessage {
                id: 0,
                span_id,
                direction: MessageDirection::ServerToClient,
                jsonrpc_id: None,
                method: Some(method),
                payload: Some(raw_line.trim_end().to_string()),
                bytes: byte_len,
                timestamp_ns: ts_ns,
            };
            send_ipc_observe(
                ipc_stream,
                socket_path,
                WorkbenchEvent::SpanRecorded {
                    span,
                    session_id: session_id.to_string(),
                    run_label: None,
                    mcp_messages: vec![msg],
                    model_call: None,
                    policy_decisions: Vec::new(),
                },
            )
            .await;
        }
        _ => {}
    }
}
