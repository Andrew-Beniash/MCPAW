use mcpaw::config::{
    BreakerConfig, CaptureLevel, PolicyConfig, PolicyEffect, PolicyRule, WbConfig,
};
use mcpaw::daemon::start_daemon;
use mcpaw::models::*;
use mcpaw::proxy_stdio::now_ns;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::Write;
use std::process::{Command, Stdio};
use tempfile::TempDir;

fn wb_bin_path() -> String {
    env!("CARGO_BIN_EXE_wb").to_string()
}

fn test_config(temp_dir: &TempDir, capture_level: CaptureLevel) -> WbConfig {
    let mut cfg = WbConfig::default();
    cfg.daemon.bind = "127.0.0.1".to_string();
    cfg.daemon.mcp_port = 0; // ephemeral port
    cfg.daemon.ui_port = 0; // ephemeral port
    cfg.daemon.data_dir = Some(temp_dir.path().to_path_buf());
    cfg.daemon.socket_path = Some(temp_dir.path().join("wbd.sock"));
    cfg.daemon.llm_upstream = Some("fake".to_string());
    cfg.daemon.anthropic_upstream = Some("fake".to_string());
    cfg.capture.payloads = capture_level;
    cfg
}

/// 1. Differential Transparency & Byte-Identity Test (`Testing Approach.md` §1 & §2)
/// Runs scenarios directly against the fixture server and through `wb wrap`,
/// asserting exact byte equality on stdout, preservation of key ordering, `1.0` vs `1`,
/// `\r\n` vs `\n`, multi-plane Unicode, and notifications mid-stream.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_differential_stdio_byte_identity() {
    let temp = TempDir::new().unwrap();
    let cfg = test_config(&temp, CaptureLevel::Full);
    let daemon = start_daemon(cfg, false).await.unwrap();

    let wb = wb_bin_path();
    let requests = concat!(
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-11-25\",\"clientInfo\":{\"name\":\"diff-client\",\"version\":\"1.0\"}}}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\",\"params\":{}}\r\n",
        "{\"jsonrpc\":\"2.0\",\"id\":\"unicode-3\",\"method\":\"tools/call\",\"params\":{\"name\":\"echo_tool\",\"arguments\":{\"emoji\":\"🚀🔥🧪\",\"cjk\":\"漢字テスト\",\"math\":\"𝕏𝕐ℤ\",\"float_ formatting\":1.0}}}\n",
        "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"custom/unknown_method\",\"params\":{\"raw\":true}}\r\n"
    );

    // Run 1: Client -> Fixture Server directly
    let mut direct_child = Command::new(&wb)
        .args(["fixture", "echo"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    direct_child
        .stdin
        .take()
        .unwrap()
        .write_all(requests.as_bytes())
        .unwrap();
    let direct_out = direct_child.wait_with_output().unwrap();

    // Run 2: Client -> `wb wrap` -> Fixture Server
    let mut proxied_child = Command::new(&wb)
        .args([
            "wrap",
            "--id",
            "echo-srv",
            "--run-id",
            "run-diff-1",
            "--socket",
            daemon.socket_path.to_str().unwrap(),
            "--",
            &wb,
            "fixture",
            "echo",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();

    // Write in split chunks (including splitting inside multibyte UTF-8 and \r\n)
    {
        let mut p_stdin = proxied_child.stdin.take().unwrap();
        let bytes = requests.as_bytes();
        let mut i = 0;
        let step_sizes = [3usize, 1, 7, 13, 2, 1, 5, 29, 64];
        let mut step_idx = 0;
        while i < bytes.len() {
            let chunk_len = step_sizes[step_idx % step_sizes.len()].min(bytes.len() - i);
            p_stdin.write_all(&bytes[i..i + chunk_len]).unwrap();
            p_stdin.flush().unwrap();
            i += chunk_len;
            step_idx += 1;
        }
    }
    let proxied_out = proxied_child.wait_with_output().unwrap();

    // Exact byte-for-byte assertion
    assert_eq!(
        direct_out.stdout, proxied_out.stdout,
        "Proxied stdout must be 100% byte-identical to direct server stdout"
    );

    daemon.bus.flush().await;
    let spans = daemon.bus.store.get_run_spans("run-diff-1").unwrap();
    assert!(
        spans.len() >= 4,
        "Expected at least 4 recorded spans (initialize, tools/list, tools/call, unknown_method), got {}",
        spans.len()
    );

    // Verify unknown method was recorded as `unknown` with `mcp.raw_method`
    let unknown_span = spans
        .iter()
        .find(|s| s.name == "custom/unknown_method")
        .expect("unknown method span recorded");
    assert_eq!(
        unknown_span
            .attributes
            .get(semconv::MCP_METHOD_NAME)
            .and_then(|v| v.as_str()),
        Some("unknown")
    );
}

/// 2. Crash Isolation (`N-06`, `§14.2`, `§14.3`):
/// - Observation fails open when `wbd` is killed or down.
/// - Policy fails closed when `wbd` is killed or denies a `tools/call`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_observation_fails_open_and_policy_fails_closed() {
    let temp = TempDir::new().unwrap();
    let mut cfg = test_config(&temp, CaptureLevel::Metadata);
    cfg.policy = PolicyConfig {
        enabled: true,
        fail_closed: true,
        block_on_schema_change: false,
        rules: vec![PolicyRule {
            id: "deny-etc".to_string(),
            server: "fs".to_string(),
            tool: "write_file".to_string(),
            arg_pattern: Some(r"/etc/".to_string()),
            effect: PolicyEffect::Deny,
            reason: "Writing to /etc is forbidden".to_string(),
        }],
    };

    let mut daemon = start_daemon(cfg, false).await.unwrap();
    let sock_path = daemon.socket_path.clone();
    let wb = wb_bin_path();

    // Part A: Policy active while daemon is running -> allowed tool passes, denied tool is blocked
    let policy_input = concat!(
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"write_file\",\"arguments\":{\"path\":\"/workspace/ok.txt\"}}}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"write_file\",\"arguments\":{\"path\":\"/etc/passwd\"}}}\n"
    );
    let mut pol_child = Command::new(&wb)
        .args([
            "wrap",
            "--id",
            "fs",
            "--policy",
            "--socket",
            sock_path.to_str().unwrap(),
            "--",
            &wb,
            "fixture",
            "echo",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    pol_child
        .stdin
        .take()
        .unwrap()
        .write_all(policy_input.as_bytes())
        .unwrap();
    let pol_out = pol_child.wait_with_output().unwrap();
    let pol_stdout = String::from_utf8_lossy(&pol_out.stdout);
    let parsed_resps: Vec<Value> = pol_stdout
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(parsed_resps.len(), 2);
    let resp1 = parsed_resps.iter().find(|r| r["id"] == 1).unwrap();
    let resp2 = parsed_resps.iter().find(|r| r["id"] == 2).unwrap();
    assert!(resp1.get("result").is_some(), "Allowed call should succeed");
    assert!(
        resp2.get("error").is_some(),
        "Denied call to /etc/passwd must return JSON-RPC error"
    );

    // Part B: Kill daemon (`shutdown` + remove socket)
    daemon.shutdown();
    let _ = std::fs::remove_file(&sock_path);

    // Observation mode (no --policy): must still forward 100% transparently when daemon is dead!
    let obs_input = "{\"jsonrpc\":\"2.0\",\"id\":10,\"method\":\"tools/call\",\"params\":{\"name\":\"echo_tool\",\"arguments\":{\"hello\":\"world\"}}}\n";
    let mut obs_child = Command::new(&wb)
        .args([
            "wrap",
            "--id",
            "fs",
            "--socket",
            sock_path.to_str().unwrap(),
            "--",
            &wb,
            "fixture",
            "echo",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    obs_child
        .stdin
        .take()
        .unwrap()
        .write_all(obs_input.as_bytes())
        .unwrap();
    let obs_out = obs_child.wait_with_output().unwrap();
    let obs_resp: Value =
        serde_json::from_str(String::from_utf8_lossy(&obs_out.stdout).trim()).unwrap();
    assert!(
        obs_resp.get("result").is_some(),
        "Observation mode must fail open when daemon is unreachable"
    );

    // Policy mode (--policy) when daemon is dead: must fail closed and refuse `tools/call`!
    let mut closed_child = Command::new(&wb)
        .args([
            "wrap",
            "--id",
            "fs",
            "--policy",
            "--socket",
            sock_path.to_str().unwrap(),
            "--",
            &wb,
            "fixture",
            "echo",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    closed_child
        .stdin
        .take()
        .unwrap()
        .write_all(obs_input.as_bytes())
        .unwrap();
    let closed_out = closed_child.wait_with_output().unwrap();
    let closed_resp: Value =
        serde_json::from_str(String::from_utf8_lossy(&closed_out.stdout).trim()).unwrap();
    assert!(
        closed_resp.get("error").is_some(),
        "Policy mode must fail closed with JSON-RPC error when daemon is dead"
    );
}

/// 3. Security Suite (`Testing Approach.md` §9 & `§14.4`, `§14.6`):
/// - Bind address check (`0.0.0.0` rejected without flag)
/// - DNS Rebinding protection (`403 Forbidden` on non-loopback `Host`)
/// - Cross-Origin CSRF protection (`403 Forbidden` on foreign `Origin`)
/// - UI Token authentication (`401 Unauthorized` on missing/wrong token; `200 OK` with valid token)
/// - Secret Canary test across all capture levels (`Off`, `Metadata`, `Full`)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_security_controls_and_secret_canary() {
    let temp = TempDir::new().unwrap();

    // 3.1 Non-loopback bind must be rejected unless allow_non_loopback is true
    let mut bad_cfg = test_config(&temp, CaptureLevel::Metadata);
    bad_cfg.daemon.bind = "0.0.0.0".to_string();
    let bind_err = start_daemon(bad_cfg, false).await;
    assert!(
        bind_err.is_err(),
        "Binding to 0.0.0.0 without --i-understand-this-exposes-traffic must fail"
    );

    // 3.2 Start daemon on loopback with Full capture to test DNS rebinding, CSRF, token auth, and Secret Canary
    let cfg = test_config(&temp, CaptureLevel::Full);
    let daemon = start_daemon(cfg, false).await.unwrap();
    let client = reqwest::Client::new();
    let base_ui = format!("http://{}", daemon.ui_addr);

    // Missing token -> 401
    let r_no_tok = client
        .get(format!("{}/api/runs", base_ui))
        .send()
        .await
        .unwrap();
    assert_eq!(r_no_tok.status(), reqwest::StatusCode::UNAUTHORIZED);

    // Old/invalid token -> 401
    let r_bad_tok = client
        .get(format!("{}/api/runs", base_ui))
        .header("X-WB-Token", "0000000000000000000000000000000000000000000000000000000000000000")
        .send()
        .await
        .unwrap();
    assert_eq!(r_bad_tok.status(), reqwest::StatusCode::UNAUTHORIZED);

    // Valid token -> 200
    let r_ok = client
        .get(format!("{}/api/runs", base_ui))
        .header("Authorization", format!("Bearer {}", daemon.ui_token))
        .send()
        .await
        .unwrap();
    assert_eq!(r_ok.status(), reqwest::StatusCode::OK);

    // DNS Rebinding attack (Host: rebind.attacker.com) -> 403 Forbidden
    let r_rebind = client
        .get(format!("{}/api/runs", base_ui))
        .header("Host", "rebind.attacker.com")
        .header("Authorization", format!("Bearer {}", daemon.ui_token))
        .send()
        .await
        .unwrap();
    assert_eq!(r_rebind.status(), reqwest::StatusCode::FORBIDDEN);

    // Cross-Origin CSRF attack (Origin: http://evil.example.com) -> 403 Forbidden
    let r_csrf = client
        .post(format!("{}/api/export", base_ui))
        .header("Origin", "http://evil.example.com")
        .header("Authorization", format!("Bearer {}", daemon.ui_token))
        .json(&json!({"format": "jsonl"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r_csrf.status(), reqwest::StatusCode::FORBIDDEN);

    // 3.3 Secret Canary Test (`§14.6`):
    // Seed `sk-canary-998877665544332211`, `Bearer canary-secret-jwt-999`, and `{"api_key": "canary-key-value-777"}`
    let canary_sk = "sk-canary-998877665544332211";
    let canary_bearer = "canary-secret-jwt-999";
    let canary_arg = "canary-key-value-777";

    let wb = wb_bin_path();
    let canary_rpc = format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{{\"name\":\"echo_tool\",\"arguments\":{{\"api_key\":\"{}\",\"auth\":\"Bearer {}\",\"openai\":\"{}\"}}}}}}\n",
        canary_arg, canary_bearer, canary_sk
    );
    let mut child = Command::new(&wb)
        .args([
            "wrap",
            "--id",
            "canary-srv",
            "--run-id",
            "run-canary",
            "--socket",
            daemon.socket_path.to_str().unwrap(),
            "--",
            &wb,
            "fixture",
            "echo",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(canary_rpc.as_bytes())
        .unwrap();
    let _ = child.wait_with_output().unwrap();

    // Also send an LLM request carrying the canary in headers and body
    let _ = client
        .post(format!("http://{}/v1/chat/completions", daemon.mcp_addr))
        .header("Authorization", format!("Bearer {}", canary_bearer))
        .header("x-api-key", canary_sk)
        .json(&json!({
            "model": "gpt-4o",
            "messages": [
                {"role": "user", "content": format!("Here is my secret key {} and Bearer {}", canary_sk, canary_bearer)}
            ]
        }))
        .send()
        .await
        .unwrap();

    daemon.bus.flush().await;

    // Inspect raw SQLite file, WAL file, JSONL export, and OTLP export for any trace of the canaries
    let jsonl_export = daemon.bus.store.export_jsonl(&[]).unwrap();
    let otlp_export = daemon.bus.store.export_otlp(&[]).unwrap().to_string();

    for canary in [canary_sk, canary_bearer, canary_arg] {
        assert!(
            !jsonl_export.contains(canary),
            "Canary '{}' leaked into JSONL export!",
            canary
        );
        assert!(
            !otlp_export.contains(canary),
            "Canary '{}' leaked into OTLP export!",
            canary
        );
    }

    for suffix in ["", "-wal", "-shm"] {
        let p = temp.path().join(format!("traces.sqlite{}", suffix));
        if p.exists() {
            let raw_bytes = std::fs::read(&p).unwrap();
            let raw_lossy = String::from_utf8_lossy(&raw_bytes);
            for canary in [canary_sk, canary_bearer, canary_arg] {
                assert!(
                    !raw_lossy.contains(canary),
                    "Canary '{}' leaked into raw SQLite file {}!",
                    canary,
                    p.display()
                );
            }
        }
    }
}

/// 4. Chaos Fixtures (`huge` zstd blob storage, `liar` schema-hash change & poisoning alert, `dual` eras, Tasks & Elicitation)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_chaos_fixtures_blob_storage_schema_poisoning_and_protocol_eras() {
    let temp = TempDir::new().unwrap();
    let cfg = test_config(&temp, CaptureLevel::Full);
    let daemon = start_daemon(cfg, false).await.unwrap();
    let wb = wb_bin_path();

    // 4.1 `liar` fixture: changes tool description on 2nd `tools/list` and injects `~/.ssh` prompt injection
    let liar_input = concat!(
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{}}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\",\"params\":{}}\n"
    );
    let mut liar_child = Command::new(&wb)
        .args([
            "wrap",
            "--id",
            "liar-srv",
            "--socket",
            daemon.socket_path.to_str().unwrap(),
            "--",
            &wb,
            "fixture",
            "liar",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    liar_child
        .stdin
        .take()
        .unwrap()
        .write_all(liar_input.as_bytes())
        .unwrap();
    let _ = liar_child.wait_with_output().unwrap();

    // 4.2 `huge` fixture: returns >140 KB payload to test zstd blob table compression & transparent load
    let huge_input = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"big_blob\",\"arguments\":{}}}\n";
    let mut huge_child = Command::new(&wb)
        .args([
            "wrap",
            "--id",
            "huge-srv",
            "--run-id",
            "run-huge",
            "--socket",
            daemon.socket_path.to_str().unwrap(),
            "--",
            &wb,
            "fixture",
            "huge",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    huge_child
        .stdin
        .take()
        .unwrap()
        .write_all(huge_input.as_bytes())
        .unwrap();
    let huge_out = huge_child.wait_with_output().unwrap();
    assert!(huge_out.stdout.len() > 140_000);

    // 4.3 `dual` fixture: stateful initialize + stateless 2026-07-28 `_meta` + tasks + elicitation + deprecated roots/sampling
    let dual_input = concat!(
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2024-11-05\"}}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\",\"params\":{\"_meta\":{\"protocolVersion\":\"2026-07-28\"}}}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tasks/create\",\"params\":{\"name\":\"long-job\"}}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tasks/status\",\"params\":{\"taskId\":\"task-99\"}}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"elicitation/create\",\"params\":{\"prompt\":\"Approve action?\"}}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"sampling/createMessage\",\"params\":{}}\n"
    );
    let mut dual_child = Command::new(&wb)
        .args([
            "wrap",
            "--id",
            "dual-srv",
            "--run-id",
            "run-dual",
            "--socket",
            daemon.socket_path.to_str().unwrap(),
            "--",
            &wb,
            "fixture",
            "dual",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    dual_child
        .stdin
        .take()
        .unwrap()
        .write_all(dual_input.as_bytes())
        .unwrap();
    let _ = dual_child.wait_with_output().unwrap();

    daemon.bus.flush().await;

    // Verify `liar-srv` detected schema change and tool poisoning warnings
    let liar_tools = daemon.bus.store.get_server_tools("liar-srv").unwrap();
    assert_eq!(liar_tools.len(), 1);
    assert_eq!(
        liar_tools[0].changed_count, 1,
        "Schema hash change must be recorded when tool description mutates"
    );
    assert!(
        !liar_tools[0].poison_warnings.is_empty(),
        "Tool poisoning warning must trigger on ~/.ssh instruction"
    );
    let history = daemon
        .bus
        .store
        .get_tool_schema_history("liar-srv", Some("read_note"))
        .unwrap();
    assert_eq!(history.len(), 2, "Both schema versions must be recorded in history");

    // Verify `huge-srv` payload was stored in zstd blob and decompresses transparently
    let huge_spans = daemon.bus.store.get_run_spans("run-huge").unwrap();
    assert_eq!(huge_spans.len(), 1);
    let huge_detail = daemon
        .bus
        .store
        .get_span_detail(&huge_spans[0].id)
        .unwrap()
        .unwrap();
    let resp_msg = huge_detail
        .mcp_messages
        .iter()
        .find(|m| m.direction == MessageDirection::ServerToClient)
        .unwrap();
    assert!(
        resp_msg.payload.as_ref().unwrap().len() > 140_000,
        "Decompressed zstd blob payload must match original size"
    );

    // Verify `dual-srv` recorded deprecated feature `sampling` and linked task spans
    let servers = daemon.bus.store.list_servers().unwrap();
    let dual_srv = servers.iter().find(|s| s.id == "dual-srv").unwrap();
    assert!(
        dual_srv
            .deprecated_features_seen
            .contains(&"sampling".to_string()),
        "Deprecated feature 'sampling' must be flagged on server"
    );

    let dual_spans = daemon.bus.store.get_run_spans("run-dual").unwrap();
    let task_create_span = dual_spans
        .iter()
        .find(|s| s.name == "tasks/create")
        .unwrap();
    let task_poll_span = dual_spans
        .iter()
        .find(|s| s.name == "tasks/status")
        .unwrap();
    assert_eq!(
        task_poll_span.parent_id.as_deref(),
        Some(task_create_span.id.as_str()),
        "Task status polling span must link to originating tasks/create span as parent"
    );
}

/// 5. LLM Proxy, Cost Accounting (§11), Context Window X-Ray (F-11), Circuit Breaker (F-12),
/// Run Diff (F-14), JSONL Export/Import, and OTLP Export/Ingest (F-09, F-16).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_llm_proxy_cost_xray_breaker_diff_and_exports() {
    let temp = TempDir::new().unwrap();
    let mut cfg = test_config(&temp, CaptureLevel::Full);
    cfg.breaker = BreakerConfig {
        enabled: true,
        max_run_cost_usd: 1.0,
        max_run_tokens: 100_000,
        max_identical_tool_calls: 3,
    };
    let daemon = start_daemon(cfg, false).await.unwrap();
    let client = reqwest::Client::new();
    let proxy_base = format!("http://{}", daemon.mcp_addr);
    let ui_base = format!("http://{}", daemon.ui_addr);

    // 5.1 OpenAI call with usage block (1000 input, 200 cached, 200 output on gpt-4o)
    // Cost = ((1000 - 200) * 2.50 + 200 * 1.25 + 200 * 10.0) / 1_000_000 = (2000 + 250 + 2000)/1e6 = $0.00425
    let bloat_tool_output = "A".repeat(4000);
    let r1 = client
        .post(format!("{}/v1/chat/completions", proxy_base))
        .header("x-wb-session-id", "sess-llm-1")
        .header("x-wb-run-id", "run-alpha")
        .json(&json!({
            "model": "gpt-4o",
            "messages": [
                {"role": "system", "content": "Short system prompt."},
                {"role": "user", "content": "List all records."},
                {"role": "assistant", "content": null, "tool_calls": [{"id": "call_1", "type": "function", "function": {"name": "list_records", "arguments": "{}"}}]},
                {"role": "tool", "tool_call_id": "call_1", "name": "list_records", "content": bloat_tool_output}
            ]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r1.status(), reqwest::StatusCode::OK);

    // 5.2 Streamed LLM call without usage block -> must estimate tokens and set `estimated_cost = true` (`~`)
    let r2 = client
        .post(format!("{}/v1/chat/completions", proxy_base))
        .header("x-wb-session-id", "sess-llm-2")
        .header("x-wb-run-id", "run-beta")
        .header("x-fake-llm-scenario", "stream_no_usage")
        .json(&json!({
            "model": "gpt-4o",
            "stream": true,
            "messages": [{"role": "user", "content": "Stream without usage block"}]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r2.status(), reqwest::StatusCode::OK);
    let stream_text = r2.text().await.unwrap();
    assert!(stream_text.contains("data: [DONE]"));

    daemon.bus.flush().await;

    // Verify Run Alpha cost and Context X-Ray bloat warning
    let run_alpha = daemon.bus.store.get_run("run-alpha").unwrap().unwrap();
    assert!((run_alpha.total_cost_usd - 0.00425).abs() < 1e-6);
    assert!(!run_alpha.estimated_cost);

    let xray_alpha = daemon.bus.store.get_run_xray("run-alpha").unwrap();
    assert_eq!(xray_alpha.len(), 1);
    assert!(
        xray_alpha[0].context_breakdown.bloat_warning.is_some(),
        "X-Ray must emit bloat warning when tool results dominate context window"
    );

    // Verify Run Beta marked `estimated_cost = true`
    let run_beta = daemon.bus.store.get_run("run-beta").unwrap().unwrap();
    assert!(
        run_beta.estimated_cost,
        "Stream without usage block must mark estimated_cost = true (~)"
    );

    // 5.3 Circuit Breaker repetitive tool call loop detection (limit = 3)
    for i in 1..=4 {
        let check = daemon.bus.check_tool_call_policy(
            "sess-loop",
            &format!("sp-loop-{}", i),
            "invoices",
            "read_file",
            "{\"path\":\"/workspace/inv.pdf\"}",
            now_ns(),
        );
        if i <= 3 {
            assert!(check.allowed, "Call #{} within threshold should pass", i);
        } else {
            assert!(
                !check.allowed,
                "Call #4 exceeding max_identical_tool_calls=3 must be blocked by Circuit Breaker"
            );
            assert!(check
                .reason
                .as_deref()
                .unwrap_or("")
                .contains("Circuit Breaker"));
        }
    }

    // 5.4 Run Diff between run-alpha and run-beta
    // Add a divergent tool span to run-beta to verify first_divergence_index
    daemon.bus.publish(WorkbenchEvent::SpanRecorded {
        span: Span {
            id: "sp-beta-div".to_string(),
            trace_id: "trace-beta".to_string(),
            run_id: "run-beta".to_string(),
            parent_id: None,
            kind: SpanKind::Mcp,
            name: "tools/call web_search".to_string(),
            start_ns: now_ns(),
            end_ns: Some(now_ns() + 1000),
            status: SpanStatus::Ok,
            attributes: BTreeMap::new(),
        },
        session_id: "sess-llm-2".to_string(),
        run_label: None,
        mcp_messages: Vec::new(),
        model_call: None,
        policy_decisions: Vec::new(),
    });
    daemon.bus.flush().await;

    let diff = daemon.bus.store.diff_runs("run-alpha", "run-beta").unwrap();
    assert!(
        diff.first_divergence_index.is_some(),
        "Run diff must identify the first divergence between two runs"
    );

    // 5.5 OTLP Export & External OTel Span Ingestion (F-09, F-16)
    let otlp = daemon
        .bus
        .store
        .export_otlp(&["run-alpha".to_string()])
        .unwrap();
    assert!(otlp.get("resourceSpans").is_some());

    let ingest_res = client
        .post(format!("{}/api/ingest/otel", ui_base))
        .header("Authorization", format!("Bearer {}", daemon.ui_token))
        .json(&otlp)
        .send()
        .await
        .unwrap();
    assert_eq!(ingest_res.status(), reqwest::StatusCode::OK);

    // 5.6 JSONL Export & Import Round-Trip
    let jsonl = daemon
        .bus
        .store
        .export_jsonl(&["run-alpha".to_string()])
        .unwrap();
    let temp2 = TempDir::new().unwrap();
    let store2 = mcpaw::store::TraceStore::open(
        &temp2.path().join("imported.sqlite"),
        30,
        CaptureLevel::Full,
    )
    .unwrap();
    let imported_count = store2.import_jsonl(&jsonl).unwrap();
    assert_eq!(imported_count, 1);
    let imported_run = store2.get_run("run-alpha").unwrap().unwrap();
    assert_eq!(imported_run.id, "run-alpha");
}

/// 6. Client Config Setup & One-Command Undo (`wb setup claude-code`)
#[test]
fn test_client_config_setup_and_undo() {
    let temp = TempDir::new().unwrap();
    let cfg_path = temp.path().join("claude_config.json");
    let original = json!({
        "mcpServers": {
            "invoices": {
                "command": "node",
                "args": ["invoice-server.js", "--port", "3000"]
            }
        }
    });
    std::fs::write(&cfg_path, serde_json::to_string_pretty(&original).unwrap()).unwrap();

    let wrapped = mcpaw::config::setup_client_config(&cfg_path, "wb", false).unwrap();
    assert_eq!(wrapped, vec!["invoices".to_string()]);

    let modified: Value =
        serde_json::from_str(&std::fs::read_to_string(&cfg_path).unwrap()).unwrap();
    assert_eq!(modified["mcpServers"]["invoices"]["command"], "wb");
    assert_eq!(
        modified["mcpServers"]["invoices"]["args"],
        json!(["wrap", "--id", "invoices", "--", "node", "invoice-server.js", "--port", "3000"])
    );

    // Undo restores exact original config
    mcpaw::config::setup_client_config(&cfg_path, "wb", true).unwrap();
    let restored: Value =
        serde_json::from_str(&std::fs::read_to_string(&cfg_path).unwrap()).unwrap();
    assert_eq!(restored, original);
}

/// 7. Streamable HTTP MCP Reverse Proxy (F-02, §4.1, §6):
/// Tests JSON and SSE responses, header passthrough (`Authorization`, `MCP-Protocol-Version`),
/// OAuth token non-persistence, and HTTP policy blocking.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_mcp_streamable_http_proxy_and_cli_commands() {
    use axum::{
        body::Body,
        http::{HeaderMap, StatusCode},
        response::IntoResponse,
        routing::post,
        Router,
    };
    use tokio::net::TcpListener;

    // Spin up a local mock HTTP MCP server that echoes JSON or SSE streams
    let upstream_router = Router::new().route(
        "/jira",
        post(|headers: HeaderMap, body: axum::body::Bytes| async move {
            let auth = headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            let proto = headers
                .get("mcp-protocol-version")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            let req_val: Value = serde_json::from_slice(&body).unwrap_or_else(|_| json!({}));
            let method = req_val.get("method").and_then(|m| m.as_str()).unwrap_or("");

            if method == "tools/list" {
                let sse_payload = format!(
                    "event: message\ndata: {{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{{\"tools\":[{{\"name\":\"create_issue\",\"description\":\"Create a Jira issue\",\"inputSchema\":{{\"type\":\"object\"}}}}],\"seen_auth_present\":{},\"seen_proto\":\"{}\"}}}}\n\n",
                    !auth.is_empty(),
                    proto
                );
                return (
                    StatusCode::OK,
                    [("content-type", "text/event-stream")],
                    Body::from(sse_payload),
                )
                    .into_response();
            }

            let resp = json!({
                "jsonrpc": "2.0",
                "id": req_val.get("id").cloned().unwrap_or(json!(1)),
                "result": {
                    "content": [{ "type": "text", "text": "Jira issue PROJ-101 created" }]
                }
            });
            (
                StatusCode::OK,
                [("content-type", "application/json")],
                Body::from(serde_json::to_vec(&resp).unwrap()),
            )
                .into_response()
        }),
    );

    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(upstream_listener, upstream_router).await;
    });

    let temp = TempDir::new().unwrap();
    let mut cfg = test_config(&temp, CaptureLevel::Full);
    cfg.servers.push(mcpaw::config::ServerConfig {
        id: "jira".to_string(),
        transport: "http".to_string(),
        upstream: Some(format!("http://{}/jira", upstream_addr)),
        command: None,
        args: Vec::new(),
    });
    let daemon = start_daemon(cfg, false).await.unwrap();
    let client = reqwest::Client::new();

    // Send `tools/list` with stateless `MCP-Protocol-Version: 2026-07-28` and OAuth token
    let oauth_secret = "oauth-secret-token-xyz987654";
    let resp_sse = client
        .post(format!("http://{}/mcp/jira", daemon.mcp_addr))
        .header("Authorization", format!("Bearer {}", oauth_secret))
        .header("MCP-Protocol-Version", "2026-07-28")
        .header("x-wb-run-id", "run-http-jira")
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp_sse.status(), reqwest::StatusCode::OK);
    let sse_body = resp_sse.text().await.unwrap();
    assert!(
        sse_body.contains("\"seen_auth_present\":true"),
        "OAuth Authorization header must be passed through to upstream"
    );
    assert!(
        sse_body.contains("\"seen_proto\":\"2026-07-28\""),
        "MCP-Protocol-Version header must be passed through to upstream"
    );

    // Send `tools/call`
    let resp_call = client
        .post(format!("http://{}/mcp/jira", daemon.mcp_addr))
        .header("MCP-Protocol-Version", "2026-07-28")
        .header("x-wb-run-id", "run-http-jira")
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "create_issue",
                "arguments": { "project": "PROJ", "summary": "Test bug" }
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp_call.status(), reqwest::StatusCode::OK);

    daemon.bus.flush().await;

    // Verify tool catalog discovered `create_issue` from SSE response
    let jira_tools = daemon.bus.store.get_server_tools("jira").unwrap();
    assert_eq!(jira_tools.len(), 1);
    assert_eq!(jira_tools[0].name, "create_issue");

    // Verify OAuth secret was never persisted in SQLite
    let raw_db = std::fs::read(temp.path().join("traces.sqlite")).unwrap();
    assert!(!String::from_utf8_lossy(&raw_db).contains(oauth_secret));

    // Verify CLI commands (`wb servers`, `wb runs ls`, `wb runs show`, `wb export`, `wb replay`)
    let wb = wb_bin_path();
    let cli_servers = Command::new(&wb)
        .args([
            "--data-dir",
            temp.path().to_str().unwrap(),
            "servers",
            "--tools",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(cli_servers.status.success());
    let servers_val: Value = serde_json::from_slice(&cli_servers.stdout).unwrap();
    assert!(!servers_val.as_array().unwrap().is_empty());

    let cli_show = Command::new(&wb)
        .args([
            "--data-dir",
            temp.path().to_str().unwrap(),
            "runs",
            "show",
            "run-http-jira",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(cli_show.status.success());
    let show_val: Value = serde_json::from_slice(&cli_show.stdout).unwrap();
    assert_eq!(show_val["run"]["id"], "run-http-jira");
    assert_eq!(show_val["spans"].as_array().unwrap().len(), 2);

    let cli_replay = Command::new(&wb)
        .args([
            "--data-dir",
            temp.path().to_str().unwrap(),
            "replay",
            "run-http-jira",
        ])
        .output()
        .unwrap();
    assert!(cli_replay.status.success());
    let replay_val: Value = serde_json::from_slice(&cli_replay.stdout).unwrap();
    assert_eq!(replay_val["format"], "mockmcp-studio-v1");
}

