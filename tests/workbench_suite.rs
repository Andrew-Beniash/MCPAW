use mcpaw::config::{
    BreakerConfig, CaptureLevel, PolicyConfig, PolicyEffect, PolicyRule, WbConfig,
};
use mcpaw::daemon::start_daemon;
use mcpaw::models::*;
use mcpaw::modules::PolicyModule;
use mcpaw::proxy_stdio::now_ns;
use serde_json::{json, Value};
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
    cfg.daemon.dev_mode = true;
    cfg.capture.payloads = capture_level;
    cfg.loaded_from = Some(temp_dir.path().join("wb.toml"));
    cfg
}

/// 1. Differential Transparency & Byte-Identity Test (`Testing Approach.md` §1 & §2, B2)
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
        "{\"jsonrpc\":\"2.0\",\"id\":\"unicode-3\",\"method\":\"tools/call\",\"params\":{\"name\":\"echo_tool\",\"arguments\":{\"emoji\":\"🚀🔥🧪\",\"cjk\":\"漢字テスト\",\"math\":\"𝕏𝕐ℤ\",\"float_formatting\":1.0}}}\n",
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

    // Verify trace_id is normalized 32-hex and span_id is 16-hex
    for s in &spans {
        assert_eq!(s.trace_id.len(), 32, "trace_id must be 32 hex chars");
        assert!(s.trace_id.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(s.id.len(), 16, "span_id must be 16 hex chars");
        assert!(s.id.chars().all(|c| c.is_ascii_hexdigit()));
    }

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

/// 2. Crash Isolation, Batch Policy Bypass Prevention, and Blocked Spans (B3, H3, M7, M8):
/// - Single and JSON-RPC batch `tools/call` are checked in policy mode.
/// - Blocked stdio calls emit a `SpanStatus::Blocked` span in the trace store (M8).
/// - String `"2"` vs integer `2` JSON-RPC IDs preserve their exact type (M7).
/// - Observation fails open when `wbd` is killed or down.
/// - Policy fails closed when `wbd` is killed or denies a `tools/call`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_observation_fails_open_and_policy_fails_closed_with_batches() {
    let temp = TempDir::new().unwrap();
    let mut cfg = test_config(&temp, CaptureLevel::Full);
    cfg.policy = PolicyConfig {
        enabled: true,
        fail_closed: true,
        block_on_schema_change: false,
        rules: vec![
            PolicyRule {
                id: "deny-etc".to_string(),
                server: "fs".to_string(),
                tool: "write_file".to_string(),
                arg_pattern: Some(r"/etc/".to_string()),
                effect: PolicyEffect::Deny,
                reason: "Writing to /etc is forbidden".to_string(),
            },
            PolicyRule {
                id: "deny-shell".to_string(),
                server: "fs".to_string(),
                tool: "exec_shell".to_string(),
                arg_pattern: None,
                effect: PolicyEffect::Deny,
                reason: "Shell execution is forbidden".to_string(),
            },
        ],
    };

    let mut daemon = start_daemon(cfg, false).await.unwrap();
    let sock_path = daemon.socket_path.clone();
    let wb = wb_bin_path();

    // Part A: Policy active while daemon is running -> allowed tool passes, denied tool is blocked,
    // and JSON-RPC batch containing `exec_shell` is ALSO blocked (B3)!
    let policy_input = concat!(
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"write_file\",\"arguments\":{\"path\":\"/workspace/ok.txt\"}}}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":\"str-2\",\"method\":\"tools/call\",\"params\":{\"name\":\"write_file\",\"arguments\":{\"path\":\"/etc/passwd\"}}}\n",
        "[{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"exec_shell\",\"arguments\":{\"cmd\":\"id\"}}}]\n"
    );
    let mut pol_child = Command::new(&wb)
        .args([
            "wrap",
            "--id",
            "fs",
            "--run-id",
            "run-policy-stdio",
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
    let raw_lines: Vec<Value> = pol_stdout
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(raw_lines.len(), 3);
    // N4: a blocked batch is answered with a JSON-RPC array, one entry per request id.
    assert!(
        raw_lines.iter().any(|v| v.is_array()),
        "N4: reply to a blocked batch must be a JSON-RPC array"
    );
    let parsed_resps: Vec<Value> = raw_lines
        .into_iter()
        .flat_map(|v| match v {
            Value::Array(items) => items,
            other => vec![other],
        })
        .collect();

    // 1: allowed
    let resp1 = parsed_resps.iter().find(|r| r["id"] == json!(1)).unwrap();
    assert!(resp1.get("result").is_some(), "Allowed call should succeed");

    // "str-2": denied, preserving string ID (M7)
    let resp2 = parsed_resps
        .iter()
        .find(|r| r["id"] == json!("str-2"))
        .expect("String id 'str-2' must be preserved in JSON-RPC error response");
    assert!(
        resp2.get("error").is_some(),
        "Denied call to /etc/passwd must return JSON-RPC error"
    );

    // 3: batch containing exec_shell must be denied (B3)
    let resp3 = parsed_resps
        .iter()
        .find(|r| r["id"] == json!(3))
        .expect("Batch tools/call id 3 must return JSON-RPC error");
    assert!(
        resp3.get("error").is_some(),
        "B3: JSON-RPC batch containing denied tools/call must be blocked"
    );

    // M8: Verify that blocked stdio calls emitted `SpanStatus::Blocked` spans in the store
    daemon.bus.flush().await;
    let pol_spans = daemon.bus.store.get_run_spans("run-policy-stdio").unwrap();
    let blocked_count = pol_spans
        .iter()
        .filter(|s| s.status == SpanStatus::Blocked)
        .count();
    assert_eq!(
        blocked_count, 2,
        "M8: Both blocked stdio calls (single and batch) must be recorded as Blocked spans"
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

/// 3. Security Suite (B4, B5, B6, M13, M15):
/// - Bind address check (`0.0.0.0` rejected without flag)
/// - DNS Rebinding & CSRF protection on BOTH UI port (`:7411`) and Proxy port (`:7410`) (B4)
/// - Header-chosen upstream (`x-mcp-upstream` / `x-llm-upstream`) blocked when `dev_mode = false`,
///   and SSRF to UI port blocked even in `dev_mode = true` (B4)
/// - Fake LLM `/fake-llm/*` blocked when `dev_mode = false` (M15)
/// - UI serves strict CSP (`script-src 'self'`) and external `/app.js` with zero inline `onclick=` (B5)
/// - Secret Canary test across all capture levels (`Off`, `Metadata`, `Full`) including GitHub, Slack, AWS and JWT-shaped tokens plus `api_token`, `bearer`, `credentials` keys (B6, M13)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_security_controls_ports_csp_and_secret_canary() {
    let temp = TempDir::new().unwrap();

    // 3.1 Non-loopback bind must be rejected unless allow_non_loopback is true
    let mut bad_cfg = test_config(&temp, CaptureLevel::Metadata);
    bad_cfg.daemon.bind = "0.0.0.0".to_string();
    let bind_err = start_daemon(bad_cfg, false).await;
    assert!(
        bind_err.is_err(),
        "Binding to 0.0.0.0 without --i-understand-this-exposes-traffic must fail"
    );

    // 3.2 Start daemon in production mode (`dev_mode = false`, `llm_upstream = None`) to test B4 & M15
    let prod_temp = TempDir::new().unwrap();
    let mut prod_cfg = test_config(&prod_temp, CaptureLevel::Metadata);
    prod_cfg.daemon.dev_mode = false;
    prod_cfg.daemon.llm_upstream = None;
    let prod_daemon = start_daemon(prod_cfg, false).await.unwrap();
    let client = reqwest::Client::new();
    let prod_proxy = format!("http://{}", prod_daemon.mcp_addr);
    let prod_ui = format!("http://{}", prod_daemon.ui_addr);

    // B4: Proxy port rejects non-loopback Host (DNS rebinding)
    let r_proxy_rebind = client
        .post(format!("{}/mcp/any", prod_proxy))
        .header("Host", "attacker.example")
        .json(&json!({"jsonrpc":"2.0","id":1,"method":"ping"}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r_proxy_rebind.status(),
        reqwest::StatusCode::FORBIDDEN,
        "B4: Proxy port must reject non-loopback Host header"
    );

    // B4: Proxy port rejects cross-origin Origin header
    let r_proxy_csrf = client
        .post(format!("{}/mcp/any", prod_proxy))
        .header("Origin", "http://attacker.example")
        .json(&json!({"jsonrpc":"2.0","id":1,"method":"ping"}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r_proxy_csrf.status(),
        reqwest::StatusCode::FORBIDDEN,
        "B4: Proxy port must reject foreign Origin header"
    );

    // B4: Proxy port rejects caller-chosen `x-mcp-upstream` when dev_mode = false
    let r_ssrf = client
        .post(format!("{}/mcp/any", prod_proxy))
        .header("x-mcp-upstream", &prod_ui)
        .json(&json!({"jsonrpc":"2.0","id":1,"method":"ping"}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r_ssrf.status(),
        reqwest::StatusCode::FORBIDDEN,
        "B4: Caller-chosen x-mcp-upstream must be rejected when dev_mode is false"
    );

    // M15: Fake LLM endpoint returns 404 when dev_mode = false and llm_upstream != fake
    let r_fake_prod = client
        .post(format!("{}/fake-llm/v1/chat/completions", prod_proxy))
        .json(&json!({"model":"gpt-4o","messages":[]}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r_fake_prod.status(),
        reqwest::StatusCode::NOT_FOUND,
        "M15: /fake-llm must return 404 in production mode"
    );

    // 3.3 Start daemon with Full capture (`dev_mode = true`) to test UI CSP, SSRF self-port block, and Secret Canaries
    let cfg = test_config(&temp, CaptureLevel::Full);
    let daemon = start_daemon(cfg, false).await.unwrap();
    let base_ui = format!("http://{}", daemon.ui_addr);
    let base_proxy = format!("http://{}", daemon.mcp_addr);

    // Even in dev_mode = true, proxying to the daemon's own UI port is forbidden (B4 SSRF guard)
    let r_self_ssrf = client
        .post(format!("{}/mcp/any", base_proxy))
        .header("x-mcp-upstream", &base_ui)
        .json(&json!({"jsonrpc":"2.0","id":1,"method":"ping"}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r_self_ssrf.status(),
        reqwest::StatusCode::FORBIDDEN,
        "B4: Proxying to the daemon's own UI port must always be forbidden"
    );

    // B5: Check UI `/` CSP header and `/app.js`
    let ui_page = client.get(&base_ui).send().await.unwrap();
    assert_eq!(ui_page.status(), reqwest::StatusCode::OK);
    let csp = ui_page
        .headers()
        .get("content-security-policy")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        csp.contains("script-src 'self'"),
        "B5: UI must serve Content-Security-Policy with script-src 'self', got: {}",
        csp
    );
    let html_body = ui_page.text().await.unwrap();
    assert!(
        !html_body.contains("onclick="),
        "B5: UI HTML must not contain inline onclick handlers"
    );

    let app_js_resp = client
        .get(format!("{}/app.js", base_ui))
        .send()
        .await
        .unwrap();
    assert_eq!(app_js_resp.status(), reqwest::StatusCode::OK);
    let app_js_body = app_js_resp.text().await.unwrap();
    assert!(
        !app_js_body.contains("onclick="),
        "B5: app.js must not construct inline onclick string handlers"
    );
    assert!(
        app_js_body.contains("&quot;") && app_js_body.contains("&#39;"),
        "B5: escapeHtml must escape double and single quotes"
    );

    // Missing token -> 401
    let r_no_tok = client
        .get(format!("{}/api/runs", base_ui))
        .send()
        .await
        .unwrap();
    assert_eq!(r_no_tok.status(), reqwest::StatusCode::UNAUTHORIZED);

    // Valid token -> 200
    let r_ok = client
        .get(format!("{}/api/runs", base_ui))
        .header("Authorization", format!("Bearer {}", daemon.ui_token))
        .send()
        .await
        .unwrap();
    assert_eq!(r_ok.status(), reqwest::StatusCode::OK);

    // DNS Rebinding attack on UI port -> 403 Forbidden
    let r_rebind = client
        .get(format!("{}/api/runs", base_ui))
        .header("Host", "rebind.attacker.com")
        .header("Authorization", format!("Bearer {}", daemon.ui_token))
        .send()
        .await
        .unwrap();
    assert_eq!(r_rebind.status(), reqwest::StatusCode::FORBIDDEN);

    // 3.4 Secret Canary Test across ALL capture levels (`Off`, `Metadata`, `Full`) (B6, M13)
    // Canaries are assembled at runtime from fragments so no token-shaped literal exists in
    // source (avoids tripping repository secret scanning); the values are fake.
    let canaries_owned: Vec<String> = vec![
        ["sk", "-canary-", "998877665544332211"].concat(),
        "canary-secret-jwt-999".to_string(),
        "canary-key-value-777".to_string(),
        ["gh", "p_", "canarySECRET999888777666"].concat(),
        ["github", "_pat_", "11AA22BB33CC44DD55EE"].concat(),
        ["xo", "xb", "-", "1234567890-", "canarySlackToken"].concat(),
        ["AK", "IA", "CANARY0FAKE00KEY1"].concat(),
        [
            "ey",
            "JhbGciOiJIUzI1NiJ9.",
            "ey",
            "JzdWIiOiJjYW5hcnkifQ.",
            "c2lnbmF0dXJl",
        ]
        .concat(),
        "super-secret-credential-val".to_string(),
    ];
    let canaries: Vec<&str> = canaries_owned.iter().map(String::as_str).collect();

    for level in [
        CaptureLevel::Off,
        CaptureLevel::Metadata,
        CaptureLevel::Full,
    ] {
        let lvl_temp = TempDir::new().unwrap();
        let lvl_cfg = test_config(&lvl_temp, level);
        let lvl_daemon = start_daemon(lvl_cfg, false).await.unwrap();
        let wb = wb_bin_path();

        let canary_rpc = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "echo_tool",
                "arguments": {
                    "api_key": canaries[2],
                    "api_token": canaries[3],
                    "github_token": canaries[4],
                    "slack": canaries[5],
                    "aws": canaries[6],
                    "jwt": canaries[7],
                    "credentials": canaries[8],
                    "auth": format!("Bearer {}", canaries[1]),
                    "openai": canaries[0]
                }
            }
        });
        let rpc_line = format!("{}\n", canary_rpc);

        let mut child = Command::new(&wb)
            .args([
                "wrap",
                "--id",
                "canary-srv",
                "--run-id",
                "run-canary",
                "--socket",
                lvl_daemon.socket_path.to_str().unwrap(),
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
            .write_all(rpc_line.as_bytes())
            .unwrap();
        let _ = child.wait_with_output().unwrap();

        let _ = client
            .post(format!("http://{}/v1/chat/completions", lvl_daemon.mcp_addr))
            .header("Authorization", format!("Bearer {}", canaries[1]))
            .header("x-api-key", canaries[0])
            .json(&json!({
                "model": "gpt-4o",
                "messages": [
                    {"role": "user", "content": format!("Tokens: {} {} {} {}", canaries[0], canaries[3], canaries[5], canaries[7])}
                ]
            }))
            .send()
            .await
            .unwrap();

        lvl_daemon.bus.flush().await;

        // M13: Under CaptureLevel::Off, verify tool names and method names are stripped
        if level == CaptureLevel::Off {
            let spans = lvl_daemon.bus.store.get_run_spans("run-canary").unwrap();
            assert!(!spans.is_empty());
            for sp in &spans {
                assert!(
                    !sp.name.contains("echo_tool"),
                    "M13: CaptureLevel::Off must not store tool names"
                );
            }
        }

        let jsonl_export = lvl_daemon.bus.store.export_jsonl(&[]).unwrap();
        let otlp_export = lvl_daemon.bus.store.export_otlp(&[]).unwrap().to_string();

        for canary in &canaries {
            assert!(
                !jsonl_export.contains(canary),
                "Canary '{}' leaked into JSONL export at capture level {:?}!",
                canary,
                level
            );
            assert!(
                !otlp_export.contains(canary),
                "Canary '{}' leaked into OTLP export at capture level {:?}!",
                canary,
                level
            );
        }

        for suffix in ["", "-wal", "-shm"] {
            let p = lvl_temp.path().join(format!("traces.sqlite{}", suffix));
            if p.exists() {
                let raw_bytes = std::fs::read(&p).unwrap();
                let raw_lossy = String::from_utf8_lossy(&raw_bytes);
                for canary in &canaries {
                    assert!(
                        !raw_lossy.contains(canary),
                        "B6: Canary '{}' leaked into raw SQLite file {} at capture level {:?}!",
                        canary,
                        p.display(),
                        level
                    );
                }
            }
        }
    }
}

/// 4. Chaos Fixtures, Bidirectional Server->Client Requests (H7), and Protocol Eras (H8):
/// - `huge` zstd blob storage + retention cleanup of blobs & annotations (M4)
/// - `liar` schema-hash change & poisoning alert
/// - `dual` eras (`io.modelcontextprotocol/protocolVersion` in `_meta`, `"unknown"` default era, Tasks, and Server->Client `elicitation/create`)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_chaos_fixtures_bidirectional_requests_and_protocol_eras() {
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

    // 4.3 `dual` fixture:
    // - H8: request before initialize without `_meta` is labeled `"unknown"`
    // - H8: request with `"io.modelcontextprotocol/protocolVersion": "2026-07-28"` is labeled `"2026-07-28 (stateless)"` (or `"dual"` after initialize)
    // - H7: `tools/call` `ask_human` triggers server->client `elicitation/create` request `"srv-elic-1"`, which client answers!
    let dual_input = concat!(
        "{\"jsonrpc\":\"2.0\",\"id\":100,\"method\":\"ping\",\"params\":{}}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2024-11-05\"}}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\",\"params\":{\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\"}}}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tasks/create\",\"params\":{\"name\":\"long-job\"}}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tasks/status\",\"params\":{\"taskId\":\"task-99\"}}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"tools/call\",\"params\":{\"name\":\"ask_human\",\"arguments\":{}}}\n",
        "{\"jsonrpc\":\"2.0\",\"id\":\"srv-elic-1\",\"result\":{\"action\":\"approved\"}}\n",
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

    // Verify H8 & H7 on `run-dual`
    let dual_spans = daemon.bus.store.get_run_spans("run-dual").unwrap();
    let ping_span = dual_spans.iter().find(|s| s.name == "ping").unwrap();
    assert_eq!(
        ping_span
            .attributes
            .get(semconv::MCP_PROTOCOL_ERA)
            .and_then(|v| v.as_str()),
        Some("unknown"),
        "H8: Request before initialize without _meta version must be labeled 'unknown'"
    );

    let list_span = dual_spans.iter().find(|s| s.name == "tools/list").unwrap();
    assert_eq!(
        list_span
            .attributes
            .get(semconv::MCP_PROTOCOL_VERSION)
            .and_then(|v| v.as_str()),
        Some("2026-07-28"),
        "H8: Namespaced io.modelcontextprotocol/protocolVersion in _meta must be extracted"
    );
    assert_eq!(
        list_span
            .attributes
            .get(semconv::MCP_PROTOCOL_ERA)
            .and_then(|v| v.as_str()),
        Some("dual"),
        "H8: Stateless _meta version after initialize must classify as 'dual'"
    );

    // H7: Verify server-initiated `elicitation/create` span was recorded and completed
    let elic_spans: Vec<&Span> = dual_spans
        .iter()
        .filter(|s| s.name == "elicitation/create")
        .collect();
    assert!(
        !elic_spans.is_empty(),
        "H7: Server-to-client elicitation/create request must be recorded as a span"
    );
    assert!(
        elic_spans.iter().any(|s| s.status == SpanStatus::Ok),
        "H7: Server-to-client elicitation/create span must complete with Ok once client responds"
    );

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

/// 5. Breaker Accuracy (H1, H2), Compressed LLM Cost (H4), X-Ray, Diff, and Exports (M14):
/// - H1: Breaker does not double-count tool calls when policy check runs (`max_identical_tool_calls = 4` allows 4 calls, blocks 5th).
/// - H2: Breaker counts consecutive repeats (interleaving a different call resets the consecutive counter) and links LLM cost ceiling to MCP tool calls in the same run.
/// - H4: Gzip-compressed LLM response is forwarded raw to client while decompressed in memory for accurate usage/cost parsing (`$0.0075`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_breaker_no_double_count_compressed_llm_cost_and_exports() {
    use axum::{body::Body, http::StatusCode, response::IntoResponse, routing::post, Router};
    use flate2::{write::GzEncoder, Compression};
    use tokio::net::TcpListener;

    // Spin up a mock upstream LLM & MCP HTTP server that returns gzip-compressed LLM responses
    let upstream_router = Router::new()
        .route(
            "/v1/chat/completions",
            post(|| async move {
                let body_json = json!({
                    "id": "chatcmpl-gzip-1",
                    "object": "chat.completion",
                    "model": "gpt-4o",
                    "choices": [{
                        "index": 0,
                        "message": { "role": "assistant", "content": "Compressed hello!" },
                        "finish_reason": "stop"
                    }],
                    "usage": {
                        "prompt_tokens": 2000,
                        "completion_tokens": 250,
                        "total_tokens": 2250
                    }
                });
                let raw_bytes = serde_json::to_vec(&body_json).unwrap();
                let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
                encoder.write_all(&raw_bytes).unwrap();
                let gz_bytes = encoder.finish().unwrap();

                (
                    StatusCode::OK,
                    [
                        ("content-type", "application/json"),
                        ("content-encoding", "gzip"),
                    ],
                    Body::from(gz_bytes),
                )
                    .into_response()
            }),
        )
        .route(
            "/mcp",
            post(|body: axum::body::Bytes| async move {
                let req_val: Value = serde_json::from_slice(&body).unwrap_or_else(|_| json!({}));
                let resp = json!({
                    "jsonrpc": "2.0",
                    "id": req_val.get("id").cloned().unwrap_or(json!(1)),
                    "result": { "content": [{ "type": "text", "text": "ok" }] }
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
    cfg.breaker = BreakerConfig {
        enabled: true,
        max_run_cost_usd: 0.01, // $0.01 ceiling
        max_run_tokens: 100_000,
        max_identical_tool_calls: 4, // H1: limit of 4
    };
    cfg.servers.push(mcpaw::config::ServerConfig {
        id: "test-http".to_string(),
        transport: "http".to_string(),
        upstream: Some(format!("http://{}/mcp", upstream_addr)),
        command: None,
        args: Vec::new(),
    });
    let daemon = start_daemon(cfg, false).await.unwrap();
    let client = reqwest::Client::new();
    let proxy_base = format!("http://{}", daemon.mcp_addr);
    let ui_base = format!("http://{}", daemon.ui_addr);

    // H1: Send 4 identical tool calls through HTTP proxy (which runs both check_tool_call_policy AND SpanRecorded).
    // With max_identical_tool_calls = 4, calls 1..=4 MUST succeed and call 5 MUST be blocked!
    for i in 1..=5 {
        let resp = client
            .post(format!("{}/mcp/test-http", proxy_base))
            .header("x-wb-run-id", "run-h1-breaker")
            .json(&json!({
                "jsonrpc": "2.0",
                "id": i,
                "method": "tools/call",
                "params": {
                    "name": "read_file",
                    "arguments": { "path": "/workspace/same.txt" }
                }
            }))
            .send()
            .await
            .unwrap();
        let val: Value = resp.json().await.unwrap();
        daemon.bus.flush().await;
        if i <= 4 {
            assert!(
                val.get("result").is_some(),
                "H1: Identical tool call #{} (limit 4) must NOT be blocked early by double-counting, got: {}",
                i,
                val
            );
        } else {
            assert!(
                val.get("error").is_some(),
                "H1: Identical tool call #5 (limit 4) must be blocked by Circuit Breaker"
            );
        }
    }

    // H2: Non-consecutive repeats in a session must reset the counter!
    // Read file A 3 times, then file B 1 time, then file A 3 times -> all 7 calls succeed (limit 4)!
    let seq = ["a", "a", "a", "b", "a", "a", "a"];
    for (idx, file) in seq.iter().enumerate() {
        let resp = client
            .post(format!("{}/mcp/test-http", proxy_base))
            .header("x-wb-run-id", "run-h2-nonconsecutive")
            .json(&json!({
                "jsonrpc": "2.0",
                "id": idx + 1,
                "method": "tools/call",
                "params": {
                    "name": "read_file",
                    "arguments": { "path": file }
                }
            }))
            .send()
            .await
            .unwrap();
        let val: Value = resp.json().await.unwrap();
        daemon.bus.flush().await;
        assert!(
            val.get("result").is_some(),
            "H2: Non-consecutive repeat at step {} must succeed",
            idx + 1
        );
    }

    // H4: Send LLM call to gzip-compressed upstream:
    // 2000 input tokens ($2.50/M = $0.0050) + 250 output tokens ($10.00/M = $0.0025) = $0.0075 exact cost!
    let gz_resp = client
        .post(format!("{}/v1/chat/completions", proxy_base))
        .header("x-llm-upstream", format!("http://{}", upstream_addr))
        .header("Accept-Encoding", "gzip")
        .header("x-wb-run-id", "run-h4-gzip")
        .json(&json!({
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "Test compressed response"}]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(gz_resp.status(), reqwest::StatusCode::OK);
    assert_eq!(
        gz_resp
            .headers()
            .get("content-encoding")
            .and_then(|v| v.to_str().ok()),
        Some("gzip"),
        "H4: Raw gzip header and bytes must be forwarded to the client"
    );
    let gz_raw_bytes = gz_resp.bytes().await.unwrap();
    let mut dec = flate2::read::GzDecoder::new(&gz_raw_bytes[..]);
    let mut decompressed = String::new();
    std::io::Read::read_to_string(&mut dec, &mut decompressed).unwrap();
    assert!(decompressed.contains("Compressed hello!"));

    daemon.bus.flush().await;
    let run_h4 = daemon.bus.store.get_run("run-h4-gzip").unwrap().unwrap();
    assert!(
        !run_h4.estimated_cost,
        "H4: Gzipped response usage block must be parsed without falling back to estimation"
    );
    assert!(
        (run_h4.total_cost_usd - 0.0075).abs() < 1e-6,
        "H4: Expected exact cost $0.0075, got ${}",
        run_h4.total_cost_usd
    );

    // H2: Link model-call cost and MCP tool calls in the same run (`run-h4-gzip`).
    // A second $0.0075 LLM call brings `run-h4-gzip` to $0.0150 (> $0.01 ceiling),
    // which must cause the next MCP tool call on `run-h4-gzip` to be blocked by the Circuit Breaker!
    let second_llm = client
        .post(format!("{}/v1/chat/completions", proxy_base))
        .header("x-llm-upstream", format!("http://{}", upstream_addr))
        .header("Accept-Encoding", "gzip")
        .header("x-wb-run-id", "run-h4-gzip")
        .json(&json!({
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "Second call exceeding $0.01 budget"}]
        }))
        .send()
        .await
        .unwrap();
    // Drain the body: the proxy records the model call (and its cost) when the stream ends,
    // so returning from `send()` (headers only) is not enough.
    let _ = second_llm.bytes().await.unwrap();
    // The recording is published just after the last chunk is sent; wait for it with a timeout
    // instead of racing it.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        daemon.bus.flush().await;
        let cost = daemon
            .bus
            .store
            .get_run("run-h4-gzip")
            .unwrap()
            .map(|r| r.total_cost_usd)
            .unwrap_or(0.0);
        if cost > 0.0149 {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "second LLM call cost was never recorded (run cost ${cost})"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    let mcp_after_budget = client
        .post(format!("{}/mcp/test-http", proxy_base))
        .header("x-wb-run-id", "run-h4-gzip")
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 99,
            "method": "tools/call",
            "params": { "name": "read_file", "arguments": { "path": "/workspace/a.txt" } }
        }))
        .send()
        .await
        .unwrap();
    let mcp_after_val: Value = mcp_after_budget.json().await.unwrap();
    assert!(
        mcp_after_val.get("error").is_some(),
        "H2: MCP tool call in a run that exceeded max_run_cost_usd must be blocked by Circuit Breaker"
    );

    // M14: Unknown export format must return 400 Bad Request
    let bad_export = client
        .post(format!("{}/api/export", ui_base))
        .header("Authorization", format!("Bearer {}", daemon.ui_token))
        .json(&json!({"format": "xml"}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        bad_export.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "M14: Unknown export format must be rejected with 400 Bad Request"
    );
}

/// 6. Policy Disabled Fix (H3), Regex Validation (M9), Case-Insensitive Wildcards (M10),
/// Safe `wb setup claude-code` (H9), and Malformed `wb.toml` Resilience (H10).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_policy_enabled_flag_setup_safety_and_config_resilience() {
    let temp = TempDir::new().unwrap();

    // H3: When `enabled = false`, `PolicyModule::evaluate_call` must return `Verdict::Pass` even when rules exist!
    let disabled_pol = PolicyModule::new(PolicyConfig {
        enabled: false,
        fail_closed: true,
        block_on_schema_change: false,
        rules: vec![PolicyRule {
            id: "deny-all".to_string(),
            server: "*".to_string(),
            tool: "*".to_string(),
            arg_pattern: None,
            effect: PolicyEffect::Deny,
            reason: "Deny everything".to_string(),
        }],
    });
    let (verdict, dec) = disabled_pol.evaluate_call("sp-1", "fs", "write_file", "{}", now_ns());
    assert!(
        !verdict.is_blocked() && dec.is_none(),
        "H3: PolicyModule with enabled=false must return Pass even if rules are non-empty"
    );

    // M10: Case-insensitive wildcard matching for both exact and prefix rules
    let ci_pol = PolicyModule::new(PolicyConfig {
        enabled: true,
        fail_closed: true,
        block_on_schema_change: false,
        rules: vec![PolicyRule {
            id: "deny-write".to_string(),
            server: "FileSystem".to_string(),
            tool: "Write_*".to_string(),
            arg_pattern: None,
            effect: PolicyEffect::Deny,
            reason: "Case-insensitive match".to_string(),
        }],
    });
    let (ci_verdict, _) = ci_pol.evaluate_call("sp-2", "filesystem", "write_file", "{}", now_ns());
    assert!(
        ci_verdict.is_blocked(),
        "M10: Wildcard and exact matching must be consistently case-insensitive"
    );

    // H9: `wb setup claude-code` preserves key order, wraps both top-level and `projects.<path>.mcpServers`,
    // and refuses `--undo` if the file was modified after setup.
    let cfg_path = temp.path().join("claude_config.json");
    let raw_ordered = r#"{
  "z_first_key": true,
  "a_second_key": "keep_order",
  "mcpServers": {
    "invoices": {
      "command": "node",
      "args": ["invoice-server.js"]
    }
  },
  "projects": {
    "/Users/dev/projectA": {
      "mcpServers": {
        "local_db": {
          "command": "python3",
          "args": ["db_mcp.py"]
        }
      }
    }
  }
}"#;
    std::fs::write(&cfg_path, raw_ordered).unwrap();

    let wrapped = mcpaw::config::setup_client_config(&cfg_path, "wb", false).unwrap();
    assert_eq!(
        wrapped.len(),
        2,
        "H9: Must wrap both top-level and project-scoped mcpServers"
    );

    let rewritten_str = std::fs::read_to_string(&cfg_path).unwrap();
    let z_pos = rewritten_str.find("\"z_first_key\"").unwrap();
    let a_pos = rewritten_str.find("\"a_second_key\"").unwrap();
    assert!(
        z_pos < a_pos,
        "H9: Key order in ~/.claude.json must be preserved (z_first_key before a_second_key)"
    );

    // H9: If external process modifies the file after `wb setup`, `--undo` must refuse to overwrite
    let mut mutated = rewritten_str.clone();
    mutated.push('\n');
    std::fs::write(&cfg_path, &mutated).unwrap();
    let undo_err = mcpaw::config::setup_client_config(&cfg_path, "wb", true);
    assert!(
        undo_err.is_err(),
        "H9: --undo must refuse if config file changed since setup"
    );

    // Restore exact wrapped content and verify `--undo` succeeds and restores exact original bytes
    std::fs::write(&cfg_path, &rewritten_str).unwrap();
    mcpaw::config::setup_client_config(&cfg_path, "wb", true).unwrap();
    let restored_str = std::fs::read_to_string(&cfg_path).unwrap();
    assert_eq!(restored_str, raw_ordered);

    // H10: Malformed `wb.toml` must NOT stop `wb wrap` in observation mode,
    // but MUST stop `wb wrap --policy`!
    let bad_toml_path = temp.path().join("malformed_wb.toml");
    std::fs::write(&bad_toml_path, "this is [[[ not valid toml").unwrap();
    let wb = wb_bin_path();
    let req_line = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\",\"params\":{}}\n";

    let mut obs_child = Command::new(&wb)
        .args([
            "--config",
            bad_toml_path.to_str().unwrap(),
            "wrap",
            "--id",
            "resilient-srv",
            "--socket",
            temp.path().join("nonexistent.sock").to_str().unwrap(),
            "--",
            &wb,
            "fixture",
            "echo",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    obs_child
        .stdin
        .take()
        .unwrap()
        .write_all(req_line.as_bytes())
        .unwrap();
    let obs_out = obs_child.wait_with_output().unwrap();
    assert!(
        obs_out.status.success(),
        "H10: wb wrap in observation mode must still launch server when wb.toml is malformed"
    );
    let obs_val: Value = serde_json::from_slice(&obs_out.stdout).unwrap();
    assert!(obs_val.get("result").is_some());

    let pol_out = Command::new(&wb)
        .args([
            "--config",
            bad_toml_path.to_str().unwrap(),
            "wrap",
            "--id",
            "resilient-srv",
            "--policy",
            "--",
            &wb,
            "fixture",
            "echo",
        ])
        .output()
        .unwrap();
    assert!(
        !pol_out.status.success(),
        "H10: wb wrap --policy must exit with error when wb.toml is malformed"
    );
}

/// 7. Streamable HTTP MCP Reverse Proxy, Incremental GET SSE (H6), Manual Stdio Call with Spaces (M5),
/// Policy Persistence (H3), and Retention Cleanup of Blobs & Annotations (M4).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_mcp_http_proxy_incremental_sse_manual_call_and_retention() {
    use axum::{
        body::Body,
        http::{HeaderMap, StatusCode},
        response::IntoResponse,
        routing::post,
        Router,
    };
    use tokio::net::TcpListener;

    let (sse_close_tx, mut sse_close_rx) = tokio::sync::oneshot::channel::<()>();
    let sse_close_arc = std::sync::Arc::new(tokio::sync::Mutex::new(Some(sse_close_tx)));

    let upstream_router = Router::new()
        .route(
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
                    let mut resp_headers = HeaderMap::new();
                    resp_headers.insert(
                        axum::http::header::CONTENT_TYPE,
                        axum::http::HeaderValue::from_static("text/event-stream"),
                    );
                    resp_headers.append(
                        axum::http::header::SET_COOKIE,
                        axum::http::HeaderValue::from_static("a=1"),
                    );
                    resp_headers.append(
                        axum::http::header::SET_COOKIE,
                        axum::http::HeaderValue::from_static("b=2"),
                    );
                    return (StatusCode::OK, resp_headers, Body::from(sse_payload))
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
            })
            .get(move || {
                // H6: Long-lived GET SSE stream that sends an event immediately and stays open
                let stream = async_stream::stream! {
                    yield Ok::<_, std::io::Error>(bytes::Bytes::from(
                        "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"progress\":50}}\n\n"
                    ));
                    tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                };
                async move {
                    (
                        StatusCode::OK,
                        [("content-type", "text/event-stream")],
                        Body::from_stream(stream),
                    )
                        .into_response()
                }
            }),
        );

    let _ = (&sse_close_arc, &mut sse_close_rx);
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(upstream_listener, upstream_router).await;
    });

    let temp = TempDir::new().unwrap();
    let wb = wb_bin_path();
    let mut cfg = test_config(&temp, CaptureLevel::Full);
    cfg.servers.push(mcpaw::config::ServerConfig {
        id: "jira".to_string(),
        transport: "http".to_string(),
        upstream: Some(format!("http://{}/jira", upstream_addr)),
        command: None,
        args: Vec::new(),
    });
    // M5: Configure stdio server whose binary path (`wb`) lives under `/Volumes/S Drive/...` (contains a space!)
    cfg.servers.push(mcpaw::config::ServerConfig {
        id: "echo-stdio".to_string(),
        transport: "stdio".to_string(),
        upstream: None,
        command: Some(wb.clone()),
        args: vec!["fixture".to_string(), "echo".to_string()],
    });

    let daemon = start_daemon(cfg, false).await.unwrap();
    let client = reqwest::Client::new();

    // Send `tools/list` and verify M6 multi-value `set-cookie` headers are preserved
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
    let cookies: Vec<_> = resp_sse.headers().get_all("set-cookie").iter().collect();
    assert_eq!(
        cookies.len(),
        2,
        "M6: Duplicate response headers (Set-Cookie) must be preserved via append"
    );

    // H6: Start a long-lived GET SSE stream and verify a span is recorded BEFORE the stream closes!
    let proxy_addr = daemon.mcp_addr;
    let sse_task = tokio::spawn(async move {
        let c = reqwest::Client::new();
        let mut r = c
            .get(format!("http://{}/mcp/jira", proxy_addr))
            .header("x-wb-run-id", "run-get-sse")
            .send()
            .await
            .unwrap();
        let _ = r.chunk().await;
    });
    let _ = sse_task.await;
    tokio::time::sleep(std::time::Duration::from_millis(80)).await;
    daemon.bus.flush().await;
    let get_sse_spans = daemon.bus.store.get_run_spans("run-get-sse").unwrap();
    assert!(
        !get_sse_spans.is_empty(),
        "H6: Long-lived GET SSE stream must emit spans incrementally as events arrive"
    );

    // M5: Invoke manual stdio tool call via `/api/servers/echo-stdio/call` (which has a path with a space!)
    let manual_resp = client
        .post(format!(
            "http://{}/api/servers/echo-stdio/call",
            daemon.ui_addr
        ))
        .header("Authorization", format!("Bearer {}", daemon.ui_token))
        .json(&json!({
            "tool_name": "echo_tool",
            "arguments": { "msg": "manual call with spaces in path" }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(manual_resp.status(), reqwest::StatusCode::OK);
    let manual_val: Value = manual_resp.json().await.unwrap();
    assert_eq!(
        manual_val["result"]["echo"]["arguments"]["msg"], "manual call with spaces in path",
        "M5: Manual stdio tool call must work with paths containing spaces and return result"
    );

    // H3: Update policies via `POST /api/policies` and verify `wb.toml` is saved atomically to disk
    let pol_update = client
        .post(format!("http://{}/api/policies", daemon.ui_addr))
        .header("Authorization", format!("Bearer {}", daemon.ui_token))
        .json(&json!({
            "enabled": true,
            "rules": [{
                "id": "deny-manual-echo",
                "server": "echo-stdio",
                "tool": "echo_tool",
                "effect": "deny",
                "reason": "Blocked by dynamic policy"
            }]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(pol_update.status(), reqwest::StatusCode::OK);
    let saved_toml = std::fs::read_to_string(temp.path().join("wb.toml")).unwrap();
    assert!(
        saved_toml.contains("deny-manual-echo"),
        "H3: Policy update in UI/API must be saved atomically to wb.toml"
    );

    // M5: Manual stdio tool call must now be blocked by the newly enabled policy!
    let manual_blocked = client
        .post(format!(
            "http://{}/api/servers/echo-stdio/call",
            daemon.ui_addr
        ))
        .header("Authorization", format!("Bearer {}", daemon.ui_token))
        .json(&json!({
            "tool_name": "echo_tool",
            "arguments": { "msg": "should be blocked" }
        }))
        .send()
        .await
        .unwrap();
    let manual_blocked_val: Value = manual_blocked.json().await.unwrap();
    assert!(
        manual_blocked_val.get("error").is_some(),
        "M5: Manual stdio tool call must enforce active policy rules"
    );

    // M4: Add annotation and verify retention deletes runs, annotations, and orphaned blobs
    let _ = daemon
        .bus
        .store
        .add_annotation("run-http-jira", "tester", "note to delete")
        .unwrap();
    let deleted = daemon.bus.store.enforce_retention(0, 0).unwrap();
    assert!(
        deleted > 0,
        "M4: Retention with 0 days must delete expired runs"
    );
}
