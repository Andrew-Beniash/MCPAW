use crate::bus::EventBus;
use crate::mcp_parser::{extract_tools_call_checks, parse_mcp_payload, ParsedMcpFrame};
use crate::models::*;
use anyhow::{Context, Result};
use chrono::Utc;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
#[cfg(unix)]
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

/// Starts the Unix domain socket listener inside `wbd` (guarded with `#[cfg(unix)]` for H11).
#[cfg(unix)]
pub async fn start_ipc_listener(socket_path: PathBuf, bus: EventBus) -> Result<()> {
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if socket_path.exists() {
        let _ = std::fs::remove_file(&socket_path);
    }

    let listener = UnixListener::bind(&socket_path).with_context(|| {
        format!(
            "Failed to bind Unix IPC socket at {}",
            socket_path.display()
        )
    })?;

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

#[cfg(not(unix))]
pub async fn start_ipc_listener(_socket_path: PathBuf, _bus: EventBus) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
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
                run_id,
                server_id,
                tool_name,
                arguments_raw,
                raw_request_line,
                ..
            } => {
                let span_id = format!("pol-{}", Uuid::new_v4());
                let eff_run = run_id.as_deref().unwrap_or("auto");
                let resp = bus.check_tool_call_policy(
                    &session_id,
                    eff_run,
                    &span_id,
                    &server_id,
                    &tool_name,
                    &arguments_raw,
                    now_ns(),
                    true,
                    raw_request_line.as_deref(),
                );
                let mut encoded = serde_json::to_string(&resp)?;
                encoded.push('\n');
                writer.write_all(encoded.as_bytes()).await?;
                writer.flush().await?;
            }
            IpcRequest::QueryMode => {
                let resp = IpcResponse {
                    allowed: true,
                    reason: None,
                    rule_id: None,
                    policy_enabled: bus.is_policy_enabled(),
                };
                let mut encoded = serde_json::to_string(&resp)?;
                encoded.push('\n');
                writer.write_all(encoded.as_bytes()).await?;
                writer.flush().await?;
            }
        }
    }
    Ok(())
}

/// Client-facing stdout shared by the forwarding and policy tasks (N5). Writes are serialized by
/// `Stdout`'s own lock, so a policy error line can never interleave with a server chunk.
#[derive(Clone)]
struct ClientStdout;

impl ClientStdout {
    fn new() -> Self {
        ClientStdout
    }

    fn write_all(&self, bytes: &[u8]) -> std::io::Result<()> {
        let write = || {
            use std::io::Write as _;
            let mut out = std::io::stdout().lock();
            out.write_all(bytes)?;
            out.flush()
        };
        match tokio::runtime::Handle::try_current().map(|h| h.runtime_flavor()) {
            Ok(tokio::runtime::RuntimeFlavor::MultiThread) => tokio::task::block_in_place(write),
            _ => write(),
        }
    }
}

/// Builds the JSON-RPC reply for a policy-blocked line (N4). A single request gets one error
/// object; a batch is rejected as a whole with an array holding one error entry per request id.
fn build_block_reply(line: &str, denied_id: &Value, reason: &str) -> Value {
    let err = |id: &Value, msg: String| {
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": { "code": -32001, "message": msg }
        })
    };
    let denied_msg = format!("MCP Workbench Policy Block: {}", reason);
    if let Ok(Value::Array(items)) = serde_json::from_str::<Value>(line.trim()) {
        let entries: Vec<Value> = items
            .iter()
            .filter(|it| it.get("method").is_some())
            .filter_map(|it| it.get("id"))
            .map(|id| {
                if id == denied_id {
                    err(id, denied_msg.clone())
                } else {
                    err(
                        id,
                        "MCP Workbench Policy Block: batch rejected because another request in it was denied"
                            .to_string(),
                    )
                }
            })
            .collect();
        return Value::Array(entries);
    }
    err(denied_id, denied_msg)
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
    ClientToServer {
        line: String,
        byte_len: usize,
        ts_ns: u64,
        policy_checked: bool,
    },
    ServerToClient {
        line: String,
        byte_len: usize,
        ts_ns: u64,
    },
}

/// Runs `wb wrap --id <server_id> [--policy] -- <command> <args...>`.
/// Forwards stdin/stdout byte-for-byte with fail-open observation and fail-closed policy (§4.1, §8).
pub async fn run_stdio_wrapper(
    server_id: String,
    command: String,
    args: Vec<String>,
    socket_path: PathBuf,
    mut policy_enforced: bool,
    run_id_override: Option<String>,
    config_error: Option<String>,
) -> Result<i32> {
    // N6: Policy enforcement needs the Unix-socket IPC to `wbd`; refuse rather than block every call.
    #[cfg(not(unix))]
    if policy_enforced {
        anyhow::bail!(
            "policy enforcement requires Unix sockets and is not supported on this platform yet; \
             run `wb wrap` without --policy and disable [policy] enabled"
        );
    }

    let session_id = format!("sess-{}", Uuid::new_v4());
    let run_id = run_id_override.unwrap_or_else(|| "auto".to_string());
    let full_cmd = if args.is_empty() {
        command.clone()
    } else {
        format!("{} {}", command, args.join(" "))
    };
    let mut command_argv = Vec::with_capacity(1 + args.len());
    command_argv.push(command.clone());
    command_argv.extend(args.iter().cloned());

    // H3: If policy wasn't explicitly passed on CLI, query daemon if reachable to see if policy was enabled dynamically
    // N2: A config that failed to load must never silently disable the firewall. If the daemon is
    // reachable it is the source of truth; otherwise fail closed on `tools/call` (traffic still flows).
    let mut local_block_reason: Option<String> = None;
    if let Some(err) = config_error {
        match query_daemon_policy_mode(&socket_path).await {
            Some(daemon_pol) => {
                policy_enforced = policy_enforced || daemon_pol;
            }
            None => {
                policy_enforced = true;
                local_block_reason = Some(format!(
                    "wb configuration is invalid and the Workbench daemon is unreachable, so policy \
                     cannot be evaluated (fail-closed): {err}"
                ));
            }
        }
    } else if !policy_enforced {
        if let Some(daemon_pol) = query_daemon_policy_mode(&socket_path).await {
            policy_enforced = daemon_pol;
        }
    }

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

    // M2: Bounded observation channel (4096) with try_send so memory never grows if daemon stalls
    let (obs_tx, mut obs_rx) = mpsc::channel::<RawLineDirection>(4096);
    let sock_for_obs = socket_path.clone();
    let server_id_obs = server_id.clone();
    let session_id_obs = session_id.clone();
    let run_id_obs = run_id.clone();
    let full_cmd_obs = full_cmd.clone();

    let obs_handle = tokio::spawn(async move {
        #[cfg(unix)]
        let mut ipc_stream: Option<UnixStream> = UnixStream::connect(&sock_for_obs).await.ok();
        #[cfg(not(unix))]
        let mut ipc_stream: Option<()> = None;

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
                command_argv,
                protocol_version: None,
                deprecated_feature: None,
            },
        ];
        for ev in init_events {
            send_ipc_observe(&mut ipc_stream, &sock_for_obs, ev).await;
        }

        // H7: Separate pending maps for client->server requests and server->client requests (elicitation, sampling, roots)
        let mut client_pending: HashMap<String, PendingRequest> = HashMap::new();
        let mut server_pending: HashMap<String, PendingRequest> = HashMap::new();
        let mut early_client_responses: HashMap<String, (ParsedMcpFrame, String, usize, u64)> =
            HashMap::new();
        let mut task_origins: HashMap<String, String> = HashMap::new();
        let mut session_has_initialize = false;

        while let Some(item) = obs_rx.recv().await {
            match item {
                RawLineDirection::ClientToServer {
                    line,
                    byte_len,
                    ts_ns,
                    policy_checked,
                } => {
                    let parsed =
                        parse_mcp_payload(&line, &server_id_obs, None, session_has_initialize);
                    process_client_frame(
                        parsed,
                        &line,
                        byte_len,
                        ts_ns,
                        policy_checked,
                        &server_id_obs,
                        &session_id_obs,
                        &run_id_obs,
                        &mut session_has_initialize,
                        &mut client_pending,
                        &mut server_pending,
                        &mut early_client_responses,
                        &mut task_origins,
                        &mut ipc_stream,
                        &sock_for_obs,
                    )
                    .await;
                }
                RawLineDirection::ServerToClient {
                    line,
                    byte_len,
                    ts_ns,
                } => {
                    let parsed =
                        parse_mcp_payload(&line, &server_id_obs, None, session_has_initialize);
                    process_server_frame(
                        parsed,
                        &line,
                        byte_len,
                        ts_ns,
                        &server_id_obs,
                        &session_id_obs,
                        &run_id_obs,
                        session_has_initialize,
                        &mut client_pending,
                        &mut server_pending,
                        &mut early_client_responses,
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
        for (_, req) in client_pending.drain().chain(server_pending.drain()) {
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

        #[cfg(unix)]
        if let Some(mut stream) = ipc_stream.take() {
            let _ = stream.shutdown().await;
            let mut ack_buf = [0u8; 8];
            let _ = stream.read(&mut ack_buf).await;
        }
    });

    // M3: Single async writer task for client stdout so slow client reads never block worker threads
    // N5: Server output is written straight to the process stdout from the forwarding task.
    // `tokio::io::stdout()` hands every write and flush to the blocking pool (two thread hops per
    // chunk), which cost ~1 ms at p99. A direct std write inside `block_in_place` has no hop, and
    // still tells the runtime this worker may block (M3), so a slow client never stalls other tasks.
    let shared_stdout = ClientStdout::new();

    // Task 1: Forward stdin -> child_stdin
    let obs_tx_stdin = obs_tx.clone();
    let stdout_for_policy = shared_stdout.clone();
    let sock_for_policy = socket_path.clone();
    let server_for_policy = server_id.clone();
    let session_for_policy = session_id.clone();
    let run_for_policy = run_id.clone();

    let stdin_task = tokio::spawn(async move {
        let mut stdin = tokio::io::stdin();
        let mut buf = vec![0u8; 65536];
        let mut line_acc: Vec<u8> = Vec::with_capacity(4096);

        while let Ok(n) = stdin.read(&mut buf).await {
            if n == 0 {
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
                    let _ = obs_tx_stdin.try_send(RawLineDirection::ClientToServer {
                        line: line_str,
                        byte_len,
                        ts_ns: now_ns(),
                        policy_checked: false,
                    });
                }
            } else {
                // Policy mode: inspect complete JSON-RPC lines (including batches, B3) for `tools/call` before forwarding
                line_acc.extend_from_slice(chunk);
                while let Some(pos) = line_acc.iter().position(|&b| b == b'\n') {
                    let raw_line: Vec<u8> = line_acc.drain(..=pos).collect();
                    let byte_len = raw_line.len();
                    let line_str = String::from_utf8_lossy(&raw_line).into_owned();
                    let ts_ns = now_ns();

                    // B3: Extract all `tools/call` items from either a single JSON-RPC object or a JSON-RPC batch array
                    let tool_calls = extract_tools_call_checks(&line_str);
                    let mut blocked_error: Option<(Value, String)> = None;

                    for (req_id_val, tool_name, args_raw) in &tool_calls {
                        if let Some(ref why) = local_block_reason {
                            blocked_error = Some((req_id_val.clone(), why.clone()));
                            break;
                        }
                        let check_res = check_policy_over_ipc(
                            &sock_for_policy,
                            &session_for_policy,
                            &run_for_policy,
                            &server_for_policy,
                            tool_name,
                            args_raw,
                            Some(req_id_val.clone()),
                            Some(&line_str),
                        )
                        .await;

                        if !check_res.allowed {
                            let reason = check_res.reason.unwrap_or_else(|| {
                                "Blocked by policy (daemon unreachable or rule denied)".to_string()
                            });
                            blocked_error = Some((req_id_val.clone(), reason));
                            break;
                        }
                    }

                    if let Some((req_id_val, reason)) = blocked_error {
                        // N4: JSON-RPC 2.0 requires an array reply with one entry per request of a batch.
                        let err_json = build_block_reply(&line_str, &req_id_val, &reason);
                        let mut err_line = serde_json::to_string(&err_json).unwrap_or_default();
                        if raw_line.ends_with(b"\r\n") {
                            err_line.push_str("\r\n");
                        } else {
                            err_line.push('\n');
                        }
                        let _ = stdout_for_policy.write_all(err_line.as_bytes());
                        continue;
                    }

                    if child_stdin.write_all(&raw_line).await.is_err() {
                        break;
                    }
                    let _ = child_stdin.flush().await;
                    let _ = obs_tx_stdin.try_send(RawLineDirection::ClientToServer {
                        line: line_str,
                        byte_len,
                        ts_ns,
                        policy_checked: !tool_calls.is_empty(),
                    });
                }
            }
        }
        drop(child_stdin);
    });

    // Task 2: Forward child_stdout -> stdout byte-for-byte via async stdout channel
    let obs_tx_stdout = obs_tx.clone();
    let stdout_for_child = shared_stdout.clone();
    let stdout_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        let mut line_acc: Vec<u8> = Vec::with_capacity(4096);

        while let Ok(n) = child_stdout.read(&mut buf).await {
            if n == 0 {
                if !line_acc.is_empty() {
                    let byte_len = line_acc.len();
                    let line_str = String::from_utf8_lossy(&line_acc).into_owned();
                    let _ = obs_tx_stdout.try_send(RawLineDirection::ServerToClient {
                        line: line_str,
                        byte_len,
                        ts_ns: now_ns(),
                    });
                    line_acc.clear();
                }
                break;
            }
            let chunk = &buf[..n];
            if stdout_for_child.write_all(chunk).is_err() {
                break;
            }

            line_acc.extend_from_slice(chunk);
            while let Some(pos) = line_acc.iter().position(|&b| b == b'\n') {
                let raw_line: Vec<u8> = line_acc.drain(..=pos).collect();
                let byte_len = raw_line.len();
                let line_str = String::from_utf8_lossy(&raw_line).into_owned();
                let _ = obs_tx_stdout.try_send(RawLineDirection::ServerToClient {
                    line: line_str,
                    byte_len,
                    ts_ns: now_ns(),
                });
            }
        }
    });

    // Task 3: Forward child_stderr -> stderr untouched
    let stderr_task = tokio::spawn(async move {
        let mut stderr = tokio::io::stderr();
        let mut buf = vec![0u8; 16384];
        while let Ok(n) = child_stderr.read(&mut buf).await {
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

    let _ = tokio::time::timeout(Duration::from_millis(250), obs_handle).await;

    Ok(status.code().unwrap_or(1))
}

#[cfg(unix)]
async fn query_daemon_policy_mode(socket_path: &Path) -> Option<bool> {
    let Ok(Ok(stream)) =
        tokio::time::timeout(Duration::from_millis(100), UnixStream::connect(socket_path)).await
    else {
        return None;
    };
    let (reader, mut writer) = stream.into_split();
    let mut payload = serde_json::to_string(&IpcRequest::QueryMode).ok()?;
    payload.push('\n');
    writer.write_all(payload.as_bytes()).await.ok()?;
    writer.flush().await.ok()?;
    let mut lines = BufReader::new(reader).lines();
    let resp_line = tokio::time::timeout(Duration::from_millis(100), lines.next_line())
        .await
        .ok()?
        .ok()??;
    let parsed: IpcResponse = serde_json::from_str(&resp_line).ok()?;
    Some(parsed.policy_enabled)
}

#[cfg(not(unix))]
async fn query_daemon_policy_mode(_socket_path: &Path) -> Option<bool> {
    None
}

/// Fail-closed policy check over IPC (§8): if `wbd` is unreachable, returns `allowed: false`.
#[allow(clippy::too_many_arguments)]
async fn check_policy_over_ipc(
    socket_path: &Path,
    session_id: &str,
    run_id: &str,
    server_id: &str,
    tool_name: &str,
    arguments_raw: &str,
    jsonrpc_id: Option<Value>,
    raw_request_line: Option<&str>,
) -> IpcResponse {
    #[cfg(unix)]
    {
        let Ok(Ok(stream)) =
            tokio::time::timeout(Duration::from_millis(500), UnixStream::connect(socket_path))
                .await
        else {
            return IpcResponse {
                allowed: false,
                reason: Some(
                    "Policy enforcement is enabled (fail-closed) and Workbench daemon (wbd) is unreachable"
                        .to_string(),
                ),
                rule_id: Some("fail-closed".to_string()),
                policy_enabled: true,
            };
        };

        let (reader, mut writer) = stream.into_split();
        let req = IpcRequest::PolicyCheck {
            session_id: session_id.to_string(),
            run_id: Some(run_id.to_string()),
            server_id: server_id.to_string(),
            tool_name: tool_name.to_string(),
            arguments_raw: arguments_raw.to_string(),
            jsonrpc_id,
            raw_request_line: raw_request_line.map(String::from),
        };
        let Ok(mut payload) = serde_json::to_string(&req) else {
            return IpcResponse {
                allowed: false,
                reason: Some("Failed to serialize policy check".to_string()),
                rule_id: None,
                policy_enabled: true,
            };
        };
        payload.push('\n');

        if writer.write_all(payload.as_bytes()).await.is_err() || writer.flush().await.is_err() {
            return IpcResponse {
                allowed: false,
                reason: Some("Policy IPC write failed (fail-closed)".to_string()),
                rule_id: Some("fail-closed".to_string()),
                policy_enabled: true,
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
    }

    #[cfg(not(unix))]
    let _ = (
        socket_path,
        session_id,
        run_id,
        server_id,
        tool_name,
        arguments_raw,
        jsonrpc_id,
        raw_request_line,
    );

    IpcResponse {
        allowed: false,
        reason: Some(
            "Policy IPC read timed out or daemon closed connection (fail-closed)".to_string(),
        ),
        rule_id: Some("fail-closed".to_string()),
        policy_enabled: true,
    }
}

#[cfg(unix)]
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

#[cfg(not(unix))]
async fn send_ipc_observe(
    _stream_opt: &mut Option<()>,
    _socket_path: &Path,
    _event: WorkbenchEvent,
) {
}

#[cfg(unix)]
type IpcStreamOpt = Option<UnixStream>;
#[cfg(not(unix))]
type IpcStreamOpt = Option<()>;

#[allow(clippy::too_many_arguments)]
async fn process_client_frame(
    frame: ParsedMcpFrame,
    raw_line: &str,
    byte_len: usize,
    ts_ns: u64,
    policy_checked: bool,
    server_id: &str,
    session_id: &str,
    run_id: &str,
    session_has_initialize: &mut bool,
    client_pending: &mut HashMap<String, PendingRequest>,
    server_pending: &mut HashMap<String, PendingRequest>,
    early_client_responses: &mut HashMap<String, (ParsedMcpFrame, String, usize, u64)>,
    task_origins: &mut HashMap<String, String>,
    ipc_stream: &mut IpcStreamOpt,
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
                    policy_checked,
                    server_id,
                    session_id,
                    run_id,
                    session_has_initialize,
                    client_pending,
                    server_pending,
                    early_client_responses,
                    task_origins,
                    ipc_stream,
                    socket_path,
                ))
                .await;
            }
        }
        ParsedMcpFrame::Request {
            id_key,
            id_raw,
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
                        command_argv: Vec::new(),
                        protocol_version: protocol_version.clone(),
                        deprecated_feature: deprecated_feature.clone(),
                    },
                )
                .await;
            }

            let span_id = normalize_span_id(&format!("span-{}", Uuid::new_v4()));
            let trace_id = traceparent
                .as_deref()
                .map(normalize_trace_id)
                .unwrap_or_else(|| normalize_trace_id(session_id));

            let mut attrs = BTreeMap::new();
            attrs.insert(
                semconv::MCP_SERVER_ID.to_string(),
                Value::String(server_id.to_string()),
            );
            attrs.insert(
                semconv::NETWORK_TRANSPORT.to_string(),
                Value::String("pipe".to_string()),
            );
            attrs.insert(semconv::JSONRPC_REQUEST_ID.to_string(), id_raw);
            attrs.insert(
                semconv::MCP_PROTOCOL_ERA.to_string(),
                Value::String(protocol_era),
            );
            if policy_checked {
                attrs.insert(semconv::WB_POLICY_CHECKED.to_string(), Value::Bool(true));
            }
            if let Some(ver) = protocol_version {
                attrs.insert(
                    semconv::MCP_PROTOCOL_VERSION.to_string(),
                    Value::String(ver),
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
                jsonrpc_id: Some(id_key.clone()),
                method: Some(method.clone()),
                payload: Some(raw_line.trim_end().to_string()),
                bytes: byte_len,
                timestamp_ns: ts_ns,
            };

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

            client_pending.insert(
                id_key,
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
        // H7: Client responding to a server-initiated request (such as elicitation/create, sampling/createMessage, roots/list)
        ParsedMcpFrame::Response {
            ref id_key,
            is_error,
            ref error_message,
            ref result_raw,
            ..
        } => {
            if server_pending.contains_key(id_key) {
                complete_pending_request(
                    id_key.clone(),
                    is_error,
                    error_message.clone(),
                    None,
                    None,
                    result_raw.clone(),
                    raw_line,
                    byte_len,
                    ts_ns,
                    MessageDirection::ClientToServer,
                    run_id,
                    session_id,
                    server_id,
                    server_pending,
                    task_origins,
                    ipc_stream,
                    socket_path,
                )
                .await;
            } else {
                early_client_responses.insert(
                    id_key.clone(),
                    (frame, raw_line.to_string(), byte_len, ts_ns),
                );
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
                        command_argv: Vec::new(),
                        protocol_version,
                        deprecated_feature,
                    },
                )
                .await;
            }
            let span_id = normalize_span_id(&format!("span-{}", Uuid::new_v4()));
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
                trace_id: normalize_trace_id(session_id),
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
        ParsedMcpFrame::Malformed => {}
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
    session_has_initialize: bool,
    client_pending: &mut HashMap<String, PendingRequest>,
    server_pending: &mut HashMap<String, PendingRequest>,
    early_client_responses: &mut HashMap<String, (ParsedMcpFrame, String, usize, u64)>,
    task_origins: &mut HashMap<String, String>,
    ipc_stream: &mut IpcStreamOpt,
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
                    session_has_initialize,
                    client_pending,
                    server_pending,
                    early_client_responses,
                    task_origins,
                    ipc_stream,
                    socket_path,
                ))
                .await;
            }
        }
        // H7: Server-initiated requests to the client (elicitation/create, sampling/createMessage, roots/list)
        ParsedMcpFrame::Request {
            id_key,
            id_raw,
            method,
            is_known_method,
            protocol_version,
            protocol_era,
            is_elicitation,
            deprecated_feature,
            traceparent,
            ..
        } => {
            if protocol_version.is_some() || deprecated_feature.is_some() {
                send_ipc_observe(
                    ipc_stream,
                    socket_path,
                    WorkbenchEvent::ServerObserved {
                        server_id: server_id.to_string(),
                        transport: "stdio".to_string(),
                        command_or_url: String::new(),
                        command_argv: Vec::new(),
                        protocol_version: protocol_version.clone(),
                        deprecated_feature: deprecated_feature.clone(),
                    },
                )
                .await;
            }

            let span_id = normalize_span_id(&format!("span-{}", Uuid::new_v4()));
            let trace_id = traceparent
                .as_deref()
                .map(normalize_trace_id)
                .unwrap_or_else(|| normalize_trace_id(session_id));

            let mut attrs = BTreeMap::new();
            attrs.insert(
                semconv::MCP_SERVER_ID.to_string(),
                Value::String(server_id.to_string()),
            );
            attrs.insert(
                semconv::NETWORK_TRANSPORT.to_string(),
                Value::String("pipe".to_string()),
            );
            attrs.insert(semconv::JSONRPC_REQUEST_ID.to_string(), id_raw);
            attrs.insert(
                semconv::MCP_PROTOCOL_ERA.to_string(),
                Value::String(protocol_era),
            );
            attrs.insert(
                "mcp.direction".to_string(),
                Value::String("server_to_client".to_string()),
            );
            if let Some(ver) = protocol_version {
                attrs.insert(
                    semconv::MCP_PROTOCOL_VERSION.to_string(),
                    Value::String(ver),
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
            if let Some(dep) = deprecated_feature {
                attrs.insert("mcp.deprecated_feature".to_string(), Value::String(dep));
            }

            let req_msg = McpMessage {
                id: 0,
                span_id: span_id.clone(),
                direction: MessageDirection::ServerToClient,
                jsonrpc_id: Some(id_key.clone()),
                method: Some(method.clone()),
                payload: Some(raw_line.trim_end().to_string()),
                bytes: byte_len,
                timestamp_ns: ts_ns,
            };

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

            server_pending.insert(
                id_key.clone(),
                PendingRequest {
                    span_id,
                    trace_id,
                    method,
                    tool_name: None,
                    start_ns: ts_ns,
                    is_elicitation,
                    request_msg: req_msg,
                    attributes: attrs,
                },
            );

            if let Some((
                ParsedMcpFrame::Response {
                    is_error,
                    error_message,
                    result_raw,
                    ..
                },
                early_line,
                early_len,
                early_ts,
            )) = early_client_responses.remove(&id_key)
            {
                complete_pending_request(
                    id_key,
                    is_error,
                    error_message,
                    None,
                    None,
                    result_raw,
                    &early_line,
                    early_len,
                    ts_ns.max(early_ts),
                    MessageDirection::ClientToServer,
                    run_id,
                    session_id,
                    server_id,
                    server_pending,
                    task_origins,
                    ipc_stream,
                    socket_path,
                )
                .await;
            }
        }
        ParsedMcpFrame::Response {
            id_key,
            is_error,
            error_message,
            negotiated_version,
            capabilities_json,
            discovered_tools,
            task_id,
            result_raw,
            ..
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
                            command_argv: Vec::new(),
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

            complete_pending_request(
                id_key,
                is_error,
                error_message,
                negotiated_version,
                task_id,
                result_raw,
                raw_line,
                byte_len,
                ts_ns,
                MessageDirection::ServerToClient,
                run_id,
                session_id,
                server_id,
                client_pending,
                task_origins,
                ipc_stream,
                socket_path,
            )
            .await;
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
                        command_argv: Vec::new(),
                        protocol_version,
                        deprecated_feature,
                    },
                )
                .await;
            }
            let span_id = normalize_span_id(&format!("span-{}", Uuid::new_v4()));
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
                trace_id: normalize_trace_id(session_id),
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
        ParsedMcpFrame::Malformed => {}
    }
}

#[allow(clippy::too_many_arguments)]
async fn complete_pending_request(
    id_key: String,
    is_error: bool,
    error_message: Option<String>,
    negotiated_version: Option<String>,
    task_id: Option<String>,
    result_raw: Option<String>,
    raw_line: &str,
    byte_len: usize,
    ts_ns: u64,
    resp_direction: MessageDirection,
    run_id: &str,
    session_id: &str,
    server_id: &str,
    pending_map: &mut HashMap<String, PendingRequest>,
    task_origins: &mut HashMap<String, String>,
    ipc_stream: &mut IpcStreamOpt,
    socket_path: &Path,
) {
    if let Some(mut req) = pending_map.remove(&id_key) {
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
            req.attributes.insert(
                semconv::MCP_PROTOCOL_VERSION.to_string(),
                Value::String(ver),
            );
        }

        let resp_msg = McpMessage {
            id: 0,
            span_id: req.span_id.clone(),
            direction: resp_direction,
            jsonrpc_id: Some(id_key),
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
        let span_id = format!("span-{}", Uuid::new_v4());
        let mut attrs = BTreeMap::new();
        attrs.insert(
            semconv::MCP_SERVER_ID.to_string(),
            Value::String(server_id.to_string()),
        );
        attrs.insert(
            semconv::JSONRPC_REQUEST_ID.to_string(),
            Value::String(id_key.clone()),
        );
        attrs.insert("mcp.unpaired_response".to_string(), Value::Bool(true));
        let span = Span {
            id: span_id.clone(),
            trace_id: normalize_trace_id(session_id),
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
            direction: resp_direction,
            jsonrpc_id: Some(id_key),
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
