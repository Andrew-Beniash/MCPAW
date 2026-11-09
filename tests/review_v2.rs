//! Focused regression tests for the v0.1 re-review findings (N2, N3, N4, N5, N6, N7).

use mcpaw::config::{CaptureLevel, PolicyConfig, PolicyEffect, PolicyRule, WbConfig};
use mcpaw::daemon::start_daemon;
use mcpaw::modules::PolicyModule;
use mcpaw::proxy_stdio::now_ns;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Output, Stdio};
use tempfile::TempDir;

fn wb() -> String {
    env!("CARGO_BIN_EXE_wb").to_string()
}

fn test_config(temp: &TempDir) -> WbConfig {
    let mut cfg = WbConfig::default();
    cfg.daemon.bind = "127.0.0.1".to_string();
    cfg.daemon.mcp_port = 0;
    cfg.daemon.ui_port = 0;
    cfg.daemon.data_dir = Some(temp.path().to_path_buf());
    cfg.daemon.socket_path = Some(temp.path().join("wbd.sock"));
    cfg.capture.payloads = CaptureLevel::Metadata;
    cfg
}

fn run_with_input(args: &[&str], input: &str) -> Output {
    let mut child = Command::new(wb())
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn json_lines(out: &Output) -> Vec<Value> {
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

const DENY_SHELL_CALL: &str = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"exec_shell\",\"arguments\":{\"cmd\":\"id\"}}}\n";
const PING: &str = "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\",\"params\":{}}\n";

/// N2: an invalid config that enables the policy must fail closed on `tools/call`
/// (and name the config problem) while ordinary traffic still flows.
#[test]
fn n2_invalid_config_with_policy_enabled_blocks_tool_calls() {
    let temp = TempDir::new().unwrap();
    let bad = temp.path().join("wb.toml");
    std::fs::write(
        &bad,
        "[policy]\nenabled = true\n\n[[policy.rules]]\nid = \"d\"\ntool = \"exec_shell\"\narg_pattern = \"(?!x)\"\neffect = \"deny\"\n",
    )
    .unwrap();
    let sock = temp.path().join("none.sock");
    let w = wb();
    let out = run_with_input(
        &[
            "--config",
            bad.to_str().unwrap(),
            "wrap",
            "--id",
            "srv",
            "--socket",
            sock.to_str().unwrap(),
            "--",
            &w,
            "fixture",
            "echo",
        ],
        &format!("{DENY_SHELL_CALL}{PING}"),
    );
    let resps = json_lines(&out);
    assert_eq!(resps.len(), 2);
    let call = resps.iter().find(|r| r["id"] == json!(1)).unwrap();
    let msg = call["error"]["message"].as_str().unwrap_or("");
    assert!(
        msg.contains("configuration is invalid"),
        "tools/call must be blocked with a config-naming error, got {call}"
    );
    let ping = resps.iter().find(|r| r["id"] == json!(2)).unwrap();
    assert!(
        ping.get("result").is_some(),
        "non-tool traffic must still flow"
    );
}

/// N2 (control): an invalid config that does NOT enable the policy keeps the server usable.
#[test]
fn n2_invalid_config_without_policy_still_forwards_tool_calls() {
    let temp = TempDir::new().unwrap();
    let bad = temp.path().join("wb.toml");
    std::fs::write(&bad, "this is [[[ not toml").unwrap();
    let sock = temp.path().join("none.sock");
    let w = wb();
    let out = run_with_input(
        &[
            "--config",
            bad.to_str().unwrap(),
            "wrap",
            "--id",
            "srv",
            "--socket",
            sock.to_str().unwrap(),
            "--",
            &w,
            "fixture",
            "echo",
        ],
        DENY_SHELL_CALL,
    );
    assert!(json_lines(&out)[0].get("result").is_some());
}

/// N3: the shipped example config loads and its rules behave as documented.
#[test]
fn n3_example_config_loads_and_rules_behave() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("wb.example.toml");
    let mut cfg = WbConfig::load_or_default(Some(&path)).expect("wb.example.toml must load");
    cfg.policy.enabled = true;
    let pol = PolicyModule::new(cfg.policy.clone());
    let (inside, _) = pol.evaluate_call(
        "s",
        "filesystem",
        "write_file",
        "{\"path\":\"/workspace/a.txt\"}",
        now_ns(),
    );
    assert!(!inside.is_blocked(), "writes inside /workspace are allowed");
    let (outside, _) = pol.evaluate_call(
        "s",
        "filesystem",
        "write_file",
        "{\"path\":\"/etc/passwd\"}",
        now_ns(),
    );
    assert!(outside.is_blocked(), "writes outside /workspace are denied");

    // The allow rule must not be satisfiable by traversal or by another argument's text.
    for (args, why) in [
        (
            "{\"path\":\"/workspace/../etc/passwd\"}",
            "path traversal out of /workspace",
        ),
        ("{\"path\":\"/workspace/..\"}", "trailing '..' component"),
        (
            "{\"content\":\"\\\"/workspace/\\\"\",\"path\":\"/etc/passwd\"}",
            "'/workspace/' appearing in a different argument",
        ),
        (
            "{\"content\":\"\\\"path\\\":\\\"/workspace/x\\\"\",\"path\":\"/etc/passwd\"}",
            "a quoted '\"path\":\"/workspace/' inside another argument",
        ),
    ] {
        let (v, _) = pol.evaluate_call("s", "filesystem", "write_file", args, now_ns());
        assert!(v.is_blocked(), "must deny {why}: {args}");
    }
    let (nested, _) = pol.evaluate_call(
        "s",
        "filesystem",
        "write_file",
        "{\"content\":\"a..b\",\"path\":\"/workspace/notes/v1..2.txt\"}",
        now_ns(),
    );
    assert!(
        !nested.is_blocked(),
        "'..' that is not a path component (e.g. in a file name) stays allowed"
    );
}

/// N4: a blocked batch gets an array reply with one error entry per request id.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn n4_blocked_batch_reply_is_array_with_entry_per_id() {
    let temp = TempDir::new().unwrap();
    let mut cfg = test_config(&temp);
    cfg.policy = PolicyConfig {
        enabled: true,
        fail_closed: true,
        block_on_schema_change: false,
        rules: vec![PolicyRule {
            id: "deny-shell".to_string(),
            server: "*".to_string(),
            tool: "exec_shell".to_string(),
            arg_pattern: None,
            effect: PolicyEffect::Deny,
            reason: "no shell".to_string(),
        }],
    };
    let daemon = start_daemon(cfg, false).await.unwrap();
    let w = wb();
    let batch = "[{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"tools/call\",\"params\":{\"name\":\"exec_shell\",\"arguments\":{}}},{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"tools/call\",\"params\":{\"name\":\"read_file\",\"arguments\":{}}},{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}]\n";
    let sock = daemon.socket_path.clone();
    let out = tokio::task::spawn_blocking(move || {
        run_with_input(
            &[
                "wrap",
                "--id",
                "srv",
                "--policy",
                "--socket",
                sock.to_str().unwrap(),
                "--",
                &w,
                "fixture",
                "echo",
            ],
            batch,
        )
    })
    .await
    .unwrap();
    let lines = json_lines(&out);
    assert_eq!(lines.len(), 1, "exactly one reply line for the batch");
    let arr = lines[0].as_array().expect("batch reply must be an array");
    assert_eq!(
        arr.len(),
        2,
        "one entry per request id (notification skipped)"
    );
    for (entry, id) in arr.iter().zip([5, 6]) {
        assert_eq!(entry["id"], json!(id));
        assert!(entry.get("error").is_some());
    }
}

/// N7: a failed save must not change the live policy.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn n7_failed_save_leaves_live_policy_unchanged() {
    let temp = TempDir::new().unwrap();
    let blocker = temp.path().join("file.txt");
    std::fs::write(&blocker, "x").unwrap();
    let mut cfg = test_config(&temp);
    // Parent "directory" is a regular file, so saving must fail.
    cfg.loaded_from = Some(blocker.join("wb.toml"));
    let daemon = start_daemon(cfg, false).await.unwrap();
    let client = reqwest::Client::new();
    let base = format!("http://{}/api/policies", daemon.ui_addr);
    let resp = client
        .post(&base)
        .bearer_auth(&daemon.ui_token)
        .json(&json!({"enabled": true, "rules": []}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::INTERNAL_SERVER_ERROR);
    let cur: Value = client
        .get(&base)
        .bearer_auth(&daemon.ui_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(cur["enabled"], json!(false), "policy must not be applied");
}

/// N7: saving updates only `[policy]` and preserves comments elsewhere; no file is created
/// when the daemon was not started from a config file.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn n7_save_preserves_comments_and_does_not_create_default_file() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("wb.toml");
    std::fs::write(&path, "# keep me\n[daemon]\nmcp_port = 0 # inline\n").unwrap();
    let mut cfg = test_config(&temp);
    cfg.loaded_from = Some(path.clone());
    let daemon = start_daemon(cfg, false).await.unwrap();
    let client = reqwest::Client::new();
    let r = client
        .post(format!("http://{}/api/policies", daemon.ui_addr))
        .bearer_auth(&daemon.ui_token)
        .json(&json!({"enabled": true, "rules": [{"id":"r1","tool":"x","effect":"deny"}]}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::OK);
    let saved = std::fs::read_to_string(&path).unwrap();
    assert!(saved.contains("# keep me") && saved.contains("# inline"));
    assert!(saved.contains("r1"));

    let temp2 = TempDir::new().unwrap();
    let cfg2 = test_config(&temp2); // loaded_from = None
    let d2 = start_daemon(cfg2, false).await.unwrap();
    let r2: Value = client
        .post(format!("http://{}/api/policies", d2.ui_addr))
        .bearer_auth(&d2.ui_token)
        .json(&json!({"enabled": true, "rules": []}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r2["persisted"], json!(false));
}

/// N6: on non-Unix platforms `--policy` is refused at startup with a clear message.
#[cfg(not(unix))]
#[test]
fn n6_policy_refused_on_non_unix() {
    let w = wb();
    let out = run_with_input(
        &["wrap", "--id", "s", "--policy", "--", &w, "fixture", "echo"],
        "",
    );
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("not supported on this platform"));
}

fn round_trip_latencies(mut child: std::process::Child, n: usize) -> Vec<f64> {
    let mut stdin = child.stdin.take().unwrap();
    let mut reader = BufReader::new(child.stdout.take().unwrap());
    let payload = "x".repeat(1024);
    let mut lat = Vec::with_capacity(n);
    let mut line = String::new();
    for i in 0..n + 50 {
        let req = format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":{i},\"method\":\"custom/echo\",\"params\":{{\"p\":\"{payload}\"}}}}\n"
        );
        let t = std::time::Instant::now();
        stdin.write_all(req.as_bytes()).unwrap();
        stdin.flush().unwrap();
        line.clear();
        reader.read_line(&mut line).unwrap();
        if i >= 50 {
            lat.push(t.elapsed().as_secs_f64() * 1000.0);
        }
    }
    drop(stdin);
    let _ = child.wait();
    lat.sort_by(|a, b| a.partial_cmp(b).unwrap());
    lat
}

/// N5: reports added p50/p99 latency of `wb wrap` in observation mode. Run with
/// `cargo test --release --test review_v2 -- --ignored --nocapture bench_`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "benchmark: run explicitly; reported by CI, non-blocking"]
async fn bench_added_latency_observation_mode() {
    let temp = TempDir::new().unwrap();
    let daemon = start_daemon(test_config(&temp), false).await.unwrap();
    let w = wb();
    let sock = daemon.socket_path.clone();
    let (direct, wrapped) = tokio::task::spawn_blocking(move || {
        let spawn = |args: Vec<String>| {
            Command::new(&w)
                .args(args)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .unwrap()
        };
        let d = round_trip_latencies(spawn(vec!["fixture".into(), "echo".into()]), 2000);
        let p = round_trip_latencies(
            spawn(vec![
                "wrap".into(),
                "--id".into(),
                "bench".into(),
                "--socket".into(),
                sock.to_str().unwrap().into(),
                "--".into(),
                w.clone(),
                "fixture".into(),
                "echo".into(),
            ]),
            2000,
        );
        (d, p)
    })
    .await
    .unwrap();
    let pct = |v: &Vec<f64>, q: f64| v[((v.len() as f64 * q) as usize).min(v.len() - 1)];
    println!(
        "added p50 = {:+.3} ms, added p99 = {:+.3} ms (direct p50 {:.3}, wrapped p50 {:.3})",
        pct(&wrapped, 0.50) - pct(&direct, 0.50),
        pct(&wrapped, 0.99) - pct(&direct, 0.99),
        pct(&direct, 0.50),
        pct(&wrapped, 0.50),
    );
}
