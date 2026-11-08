use crate::models::{IpcResponse, Verdict, WorkbenchEvent};
use crate::modules::ModuleHost;
use crate::redact::Redactor;
use crate::store::TraceStore;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{broadcast, mpsc, oneshot};

enum BusCommand {
    Event(WorkbenchEvent),
    Flush(oneshot::Sender<()>),
}

#[derive(Clone)]
pub struct EventBus {
    tx: mpsc::Sender<BusCommand>,
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
        let (tx, mut rx) = mpsc::channel::<BusCommand>(channel_capacity);
        let (sse_tx, _) = broadcast::channel::<WorkbenchEvent>(1024);
        let dropped_events = Arc::new(AtomicU64::new(0));
        let redactor_arc = Arc::new(redactor);
        let modules_arc = Arc::new(Mutex::new(modules));

        let writer_store = store.clone();
        // Background SQLite writer task: batches inserts every 50 ms or 500 events (§4.1)
        tokio::spawn(async move {
            let mut batch: Vec<WorkbenchEvent> = Vec::with_capacity(500);
            let mut interval = tokio::time::interval(Duration::from_millis(50));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

            loop {
                tokio::select! {
                    maybe_cmd = rx.recv() => {
                        match maybe_cmd {
                            Some(BusCommand::Event(ev)) => {
                                batch.push(ev);
                                if batch.len() >= 500 {
                                    let _ = writer_store.apply_events_batch(&batch);
                                    batch.clear();
                                }
                            }
                            Some(BusCommand::Flush(ack)) => {
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
                            None => {
                                if !batch.is_empty() {
                                    let _ = writer_store.apply_events_batch(&batch);
                                }
                                break;
                            }
                        }
                    }
                    _ = interval.tick() => {
                        if !batch.is_empty() {
                            let _ = writer_store.apply_events_batch(&batch);
                            batch.clear();
                        }
                    }
                }
            }
        });

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
        // 1. Run module host analysis on event
        let verdict = {
            let mut mods = self.modules.lock().unwrap();
            mods.dispatch(&event)
        };

        // 2. Redact before persistence or SSE broadcast
        self.redactor.sanitize_event(&mut event);

        // 3. Fan out to live SSE subscribers (best effort)
        let _ = self.sse_tx.send(event.clone());

        // 4. Send to bounded SQLite writer queue; if full, drop observation event and increment counter
        if self.tx.try_send(BusCommand::Event(event)).is_err() {
            self.dropped_events.fetch_add(1, Ordering::Relaxed);
        }

        verdict
    }

    /// Evaluates Policy & Circuit Breaker synchronously for a `tools/call` request.
    pub fn check_tool_call_policy(
        &self,
        session_id: &str,
        span_id: &str,
        server_id: &str,
        tool_name: &str,
        arguments_raw: &str,
        timestamp_ns: u64,
    ) -> IpcResponse {
        let (verdict, decision, rule_id) = {
            let mut mods = self.modules.lock().unwrap();
            let (pol_verdict, pol_decision) = mods.policy.evaluate_call(
                span_id,
                server_id,
                tool_name,
                arguments_raw,
                timestamp_ns,
            );
            if let Verdict::Block(reason) = pol_verdict {
                let r_id = pol_decision.as_ref().map(|d| d.rule_id.clone());
                (Verdict::Block(reason), pol_decision, r_id)
            } else {
                let brk_verdict = mods.breaker.check_tool_call(
                    session_id,
                    server_id,
                    tool_name,
                    arguments_raw,
                );
                if let Verdict::Block(reason) = brk_verdict {
                    (
                        Verdict::Block(reason),
                        pol_decision,
                        Some("circuit_breaker".to_string()),
                    )
                } else {
                    (Verdict::Pass, pol_decision, None)
                }
            }
        };

        if let Some(dec) = decision {
            self.publish(WorkbenchEvent::PolicyEvaluated { decision: dec });
        }

        match verdict {
            Verdict::Block(reason) => IpcResponse {
                allowed: false,
                reason: Some(reason),
                rule_id,
            },
            _ => IpcResponse {
                allowed: true,
                reason: None,
                rule_id: None,
            },
        }
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
        if self.tx.send(BusCommand::Flush(ack_tx)).await.is_ok() {
            let _ = ack_rx.await;
        }
    }
}
