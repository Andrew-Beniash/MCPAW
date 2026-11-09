use crate::models::{
    semconv, IpcResponse, McpMessage, MessageDirection, Span, SpanKind, SpanStatus, Verdict,
    WorkbenchEvent,
};
use crate::modules::ModuleHost;
use crate::redact::Redactor;
use crate::store::TraceStore;
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc as std_mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{broadcast, oneshot};

enum BusCommand {
    Event(WorkbenchEvent),
    Flush(oneshot::Sender<()>),
}

#[derive(Clone)]
pub struct EventBus {
    tx: std_mpsc::SyncSender<BusCommand>,
    sse_tx: broadcast::Sender<WorkbenchEvent>,
    pub dropped_events: Arc<AtomicU64>,
    pub redactor: Arc<Redactor>,
    pub modules: Arc<Mutex<ModuleHost>>,
    pub store: TraceStore,
}

impl EventBus {
    pub fn new(
        store: TraceStore,
        redactor: Redactor,
        modules: ModuleHost,
        channel_capacity: usize,
    ) -> Self {
        let (tx, rx) = std_mpsc::sync_channel::<BusCommand>(channel_capacity);
        let (sse_tx, _) = broadcast::channel::<WorkbenchEvent>(1024);
        let dropped_events = Arc::new(AtomicU64::new(0));
        let redactor_arc = Arc::new(redactor);
        let modules_arc = Arc::new(Mutex::new(modules));

        let writer_store = store.clone();
        // M1: Dedicated OS writer thread for SQLite batch transactions (every 50 ms or 500 events)
        // so blocking disk I/O never runs on tokio async worker threads.
        std::thread::Builder::new()
            .name("wb-sqlite-writer".to_string())
            .spawn(move || {
                let mut batch: Vec<WorkbenchEvent> = Vec::with_capacity(500);
                loop {
                    match rx.recv_timeout(Duration::from_millis(50)) {
                        Ok(BusCommand::Event(ev)) => {
                            batch.push(ev);
                            while batch.len() < 500 {
                                match rx.try_recv() {
                                    Ok(BusCommand::Event(next_ev)) => batch.push(next_ev),
                                    Ok(BusCommand::Flush(ack)) => {
                                        if !batch.is_empty() {
                                            let _ = writer_store.apply_events_batch(&batch);
                                            batch.clear();
                                        }
                                        let _ = ack.send(());
                                    }
                                    Err(_) => break,
                                }
                            }
                            if batch.len() >= 500 {
                                let _ = writer_store.apply_events_batch(&batch);
                                batch.clear();
                            }
                        }
                        Ok(BusCommand::Flush(ack)) => {
                            while let Ok(cmd) = rx.try_recv() {
                                match cmd {
                                    BusCommand::Event(ev) => batch.push(ev),
                                    BusCommand::Flush(other_ack) => {
                                        if !batch.is_empty() {
                                            let _ = writer_store.apply_events_batch(&batch);
                                            batch.clear();
                                        }
                                        let _ = other_ack.send(());
                                    }
                                }
                            }
                            if !batch.is_empty() {
                                let _ = writer_store.apply_events_batch(&batch);
                                batch.clear();
                            }
                            let _ = ack.send(());
                        }
                        Err(std_mpsc::RecvTimeoutError::Timeout) => {
                            if !batch.is_empty() {
                                let _ = writer_store.apply_events_batch(&batch);
                                batch.clear();
                            }
                        }
                        Err(std_mpsc::RecvTimeoutError::Disconnected) => {
                            if !batch.is_empty() {
                                let _ = writer_store.apply_events_batch(&batch);
                            }
                            break;
                        }
                    }
                }
            })
            .expect("failed to spawn wb-sqlite-writer thread");

        Self {
            tx,
            sse_tx,
            dropped_events,
            redactor: redactor_arc,
            modules: modules_arc,
            store,
        }
    }

    /// Publishes an observation event without ever blocking the proxy hot path (§4.1).
    /// Runs redaction *before* the event reaches any subscriber (§8).
    pub fn publish(&self, mut event: WorkbenchEvent) -> Verdict {
        let verdict = {
            let mut mods = self.modules.lock().unwrap();
            mods.dispatch(&event)
        };

        self.redactor.sanitize_event(&mut event);

        let _ = self.sse_tx.send(event.clone());

        if self.tx.try_send(BusCommand::Event(event)).is_err() {
            self.dropped_events.fetch_add(1, Ordering::Relaxed);
        }

        verdict
    }

    /// Evaluates Policy & Circuit Breaker synchronously for a `tools/call` request.
    /// When `record_blocked_span` is true (stdio IPC path, M8), emits a `Blocked` span on denial.
    #[allow(clippy::too_many_arguments)]
    pub fn check_tool_call_policy(
        &self,
        session_id: &str,
        run_id: &str,
        span_id: &str,
        server_id: &str,
        tool_name: &str,
        arguments_raw: &str,
        timestamp_ns: u64,
        record_blocked_span: bool,
        raw_request_line: Option<&str>,
    ) -> IpcResponse {
        let (verdict, decision, rule_id, policy_enabled) = {
            let mut mods = self.modules.lock().unwrap();
            let pol_enabled = mods.policy.config.enabled;
            let (pol_verdict, pol_decision) = mods.policy.evaluate_call(
                span_id,
                server_id,
                tool_name,
                arguments_raw,
                timestamp_ns,
            );
            if let Verdict::Block(reason) = pol_verdict {
                let r_id = pol_decision.as_ref().map(|d| d.rule_id.clone());
                (Verdict::Block(reason), pol_decision, r_id, pol_enabled)
            } else {
                let brk_verdict =
                    mods.breaker
                        .check_tool_call(run_id, server_id, tool_name, arguments_raw);
                if let Verdict::Block(reason) = brk_verdict {
                    (
                        Verdict::Block(reason),
                        pol_decision,
                        Some("circuit_breaker".to_string()),
                        pol_enabled,
                    )
                } else {
                    (Verdict::Pass, pol_decision, None, pol_enabled)
                }
            }
        };

        if let Some(ref dec) = decision {
            self.publish(WorkbenchEvent::PolicyEvaluated {
                decision: dec.clone(),
            });
        }

        match verdict {
            Verdict::Block(reason) => {
                if record_blocked_span {
                    let mut attrs = BTreeMap::new();
                    attrs.insert(
                        semconv::MCP_SERVER_ID.to_string(),
                        Value::String(server_id.to_string()),
                    );
                    attrs.insert(
                        semconv::MCP_METHOD_NAME.to_string(),
                        Value::String("tools/call".to_string()),
                    );
                    attrs.insert(
                        semconv::GEN_AI_TOOL_NAME.to_string(),
                        Value::String(tool_name.to_string()),
                    );
                    attrs.insert(
                        semconv::GEN_AI_TOOL_CALL_ARGUMENTS.to_string(),
                        Value::String(arguments_raw.to_string()),
                    );
                    attrs.insert(
                        semconv::NETWORK_TRANSPORT.to_string(),
                        Value::String("pipe".to_string()),
                    );
                    attrs.insert(semconv::WB_POLICY_CHECKED.to_string(), Value::Bool(true));
                    attrs.insert("policy.blocked".to_string(), Value::Bool(true));
                    attrs.insert("error.message".to_string(), Value::String(reason.clone()));

                    let mut messages = Vec::new();
                    if let Some(line) = raw_request_line {
                        messages.push(McpMessage {
                            id: 0,
                            span_id: span_id.to_string(),
                            direction: MessageDirection::ClientToServer,
                            jsonrpc_id: None,
                            method: Some("tools/call".to_string()),
                            payload: Some(line.trim_end().to_string()),
                            bytes: line.len(),
                            timestamp_ns,
                        });
                    }

                    let blocked_span = Span {
                        id: span_id.to_string(),
                        trace_id: format!("trace-{}", session_id),
                        run_id: run_id.to_string(),
                        parent_id: None,
                        kind: SpanKind::Mcp,
                        name: format!("tools/call {}", tool_name),
                        start_ns: timestamp_ns,
                        end_ns: Some(timestamp_ns),
                        status: SpanStatus::Blocked,
                        attributes: attrs,
                    };
                    self.publish(WorkbenchEvent::SpanRecorded {
                        span: blocked_span,
                        session_id: session_id.to_string(),
                        run_label: None,
                        mcp_messages: messages,
                        model_call: None,
                        policy_decisions: Vec::new(),
                    });
                }

                IpcResponse {
                    allowed: false,
                    reason: Some(reason),
                    rule_id,
                    policy_enabled,
                }
            }
            _ => IpcResponse {
                allowed: true,
                reason: None,
                rule_id: None,
                policy_enabled,
            },
        }
    }

    pub fn is_policy_enabled(&self) -> bool {
        self.modules.lock().unwrap().policy.config.enabled
    }

    pub fn subscribe_sse(&self) -> broadcast::Receiver<WorkbenchEvent> {
        self.sse_tx.subscribe()
    }

    pub fn dropped_count(&self) -> u64 {
        self.dropped_events.load(Ordering::Relaxed)
    }

    /// Flushes any pending batched events in the writer channel to SQLite.
    pub async fn flush(&self) {
        let (ack_tx, ack_rx) = oneshot::channel();
        if self.tx.send(BusCommand::Flush(ack_tx)).is_ok() {
            let _ = ack_rx.await;
        }
    }
}
