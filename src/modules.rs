use crate::config::{BreakerConfig, PolicyConfig, PolicyEffect, PolicyRule};
use crate::models::{
    semconv, ContextBreakdown, PolicyDecision, SpanKind, Verdict, WorkbenchEvent,
};
use crate::pricing::PriceTable;
use axum::Router;
use regex::Regex;
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};

/// Module trait as specified in §4.1:
/// ```rust
/// # use mcpaw::models::{WorkbenchEvent, Verdict};
/// # use axum::Router;
/// trait Module {
///     fn on_event(&mut self, ev: &WorkbenchEvent) -> Verdict;
///     fn routes(&self) -> Option<Router>;
/// }
/// ```
pub trait Module: Send + Sync {
    fn name(&self) -> &'static str;
    fn on_event(&mut self, ev: &WorkbenchEvent) -> Verdict;
    fn routes(&self) -> Option<Router> {
        None
    }
}

/// Analyzes an OpenAI-compatible or Anthropic-compatible LLM request payload
/// to produce a `ContextBreakdown` for the Context Window X-Ray module (F-11, UC-07).
pub fn analyze_context_window(req_json: &Value, actual_input_tokens: Option<u64>) -> ContextBreakdown {
    let mut system_tokens = 0u64;
    let mut tools_tokens = 0u64;
    let mut user_tokens = 0u64;
    let mut assistant_tokens = 0u64;
    let mut tool_results_tokens = 0u64;
    let mut by_tool_result: BTreeMap<String, u64> = BTreeMap::new();
    let mut tool_call_id_to_name: HashMap<String, String> = HashMap::new();

    // Anthropic top-level `system` field
    if let Some(sys) = req_json.get("system") {
        system_tokens += PriceTable::estimate_tokens(&sys.to_string());
    }

    // Tool definitions (`tools` array)
    if let Some(tools) = req_json.get("tools").and_then(|t| t.as_array()) {
        for tool in tools {
            tools_tokens += PriceTable::estimate_tokens(&tool.to_string());
        }
    }

    // Messages array (OpenAI and Anthropic)
    if let Some(messages) = req_json.get("messages").and_then(|m| m.as_array()) {
        for msg in messages {
            let role = msg.get("role").and_then(|r| r.as_str()).unwrap_or("user");
            let content = msg.get("content");

            // Track tool_calls in assistant messages so we can attribute tool results by name
            if let Some(tcs) = msg.get("tool_calls").and_then(|v| v.as_array()) {
                for tc in tcs {
                    if let (Some(id), Some(name)) = (
                        tc.get("id").and_then(|v| v.as_str()),
                        tc.get("function")
                            .and_then(|f| f.get("name"))
                            .and_then(|n| n.as_str())
                            .or_else(|| tc.get("name").and_then(|n| n.as_str())),
                    ) {
                        tool_call_id_to_name.insert(id.to_string(), name.to_string());
                    }
                }
            }

            // Check if Anthropic content array has tool_use or tool_result blocks
            if let Some(Value::Array(blocks)) = content {
                let mut block_handled = false;
                for block in blocks {
                    if let Some(btype) = block.get("type").and_then(|t| t.as_str()) {
                        match btype {
                            "tool_use" => {
                                block_handled = true;
                                if let (Some(id), Some(name)) = (
                                    block.get("id").and_then(|v| v.as_str()),
                                    block.get("name").and_then(|v| v.as_str()),
                                ) {
                                    tool_call_id_to_name.insert(id.to_string(), name.to_string());
                                }
                                assistant_tokens +=
                                    PriceTable::estimate_tokens(&block.to_string());
                            }
                            "tool_result" => {
                                block_handled = true;
                                let tok = PriceTable::estimate_tokens(&block.to_string());
                                tool_results_tokens += tok;
                                let tool_name = block
                                    .get("tool_use_id")
                                    .and_then(|v| v.as_str())
                                    .and_then(|id| tool_call_id_to_name.get(id))
                                    .cloned()
                                    .or_else(|| {
                                        block.get("name").and_then(|n| n.as_str()).map(String::from)
                                    })
                                    .unwrap_or_else(|| "tool_result".to_string());
                                *by_tool_result.entry(tool_name).or_insert(0) += tok;
                            }
                            _ => {}
                        }
                    }
                }
                if block_handled {
                    continue;
                }
            }

            let text_repr = content
                .map(|c| match c {
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                })
                .unwrap_or_default();
            let est = PriceTable::estimate_tokens(&text_repr);

            match role {
                "system" | "developer" => system_tokens += est,
                "assistant" => {
                    let tc_tokens = msg
                        .get("tool_calls")
                        .map(|t| PriceTable::estimate_tokens(&t.to_string()))
                        .unwrap_or(0);
                    assistant_tokens += est + tc_tokens;
                }
                "tool" | "function" => {
                    tool_results_tokens += est;
                    let tool_name = msg
                        .get("name")
                        .and_then(|n| n.as_str())
                        .map(String::from)
                        .or_else(|| {
                            msg.get("tool_call_id")
                                .and_then(|id| id.as_str())
                                .and_then(|id| tool_call_id_to_name.get(id))
                                .cloned()
                        })
                        .unwrap_or_else(|| "tool_result".to_string());
                    *by_tool_result.entry(tool_name).or_insert(0) += est;
                }
                _ => user_tokens += est,
            }
        }
    }

    let raw_sum =
        system_tokens + tools_tokens + user_tokens + assistant_tokens + tool_results_tokens;

    // Scale category estimates proportionally if provider supplied exact input_tokens
    if let Some(actual) = actual_input_tokens {
        if raw_sum > 0 && actual > 0 {
            let scale = actual as f64 / raw_sum as f64;
            system_tokens = (system_tokens as f64 * scale).round() as u64;
            tools_tokens = (tools_tokens as f64 * scale).round() as u64;
            user_tokens = (user_tokens as f64 * scale).round() as u64;
            assistant_tokens = (assistant_tokens as f64 * scale).round() as u64;
            tool_results_tokens = actual.saturating_sub(
                system_tokens + tools_tokens + user_tokens + assistant_tokens,
            );
            for val in by_tool_result.values_mut() {
                *val = (*val as f64 * scale).round() as u64;
            }
        }
    }

    let total_tokens = actual_input_tokens
        .filter(|&t| t > 0)
        .unwrap_or(raw_sum);

    let mut bloat_warning = None;
    if total_tokens >= 100 {
        let tool_pct = (tool_results_tokens as f64 / total_tokens as f64) * 100.0;
        let sys_pct = (system_tokens as f64 / total_tokens as f64) * 100.0;
        if tool_pct >= 60.0 {
            let top_tool = by_tool_result
                .iter()
                .max_by_key(|(_, &v)| v)
                .map(|(k, _)| k.as_str())
                .unwrap_or("unknown");
            bloat_warning = Some(format!(
                "Context bloat detected: tool results consume {:.0}% of context (top contributor: '{}'); system prompt is {:.1}%.",
                tool_pct, top_tool, sys_pct
            ));
        }
    }

    ContextBreakdown {
        system_tokens,
        tools_tokens,
        user_tokens,
        assistant_tokens,
        tool_results_tokens,
        total_tokens,
        by_tool_result,
        bloat_warning,
    }
}

/// Circuit Breaker module (F-12, UC-03): detects repetitive tool loops and budget overruns.
pub struct BreakerModule {
    pub config: BreakerConfig,
    session_cost_usd: HashMap<String, f64>,
    session_tokens: HashMap<String, u64>,
    tool_call_counts: HashMap<(String, String, String), u32>,
}

impl BreakerModule {
    pub fn new(config: BreakerConfig) -> Self {
        Self {
            config,
            session_cost_usd: HashMap::new(),
            session_tokens: HashMap::new(),
            tool_call_counts: HashMap::new(),
        }
    }

    pub fn check_tool_call(
        &mut self,
        session_key: &str,
        server_id: &str,
        tool_name: &str,
        canonical_args: &str,
    ) -> Verdict {
        if !self.config.enabled {
            return Verdict::Pass;
        }
        if let Some(&cost) = self.session_cost_usd.get(session_key) {
            if cost > self.config.max_run_cost_usd {
                return Verdict::Block(format!(
                    "Circuit Breaker: run cost ${:.4} exceeded budget ceiling ${:.2}",
                    cost, self.config.max_run_cost_usd
                ));
            }
        }
        if let Some(&tokens) = self.session_tokens.get(session_key) {
            if tokens > self.config.max_run_tokens {
                return Verdict::Block(format!(
                    "Circuit Breaker: run tokens {} exceeded budget ceiling {}",
                    tokens, self.config.max_run_tokens
                ));
            }
        }

        let key = (
            session_key.to_string(),
            format!("{}:{}", server_id, tool_name),
            canonical_args.to_string(),
        );
        let count = self.tool_call_counts.entry(key).or_insert(0);
        *count += 1;

        if *count > self.config.max_identical_tool_calls {
            return Verdict::Block(format!(
                "Circuit Breaker: repetitive loop detected — tool '{}:{}' called {} times with identical arguments (limit: {})",
                server_id, tool_name, *count, self.config.max_identical_tool_calls
            ));
        }

        Verdict::Pass
    }

    pub fn check_llm_call(&self, session_key: &str) -> Verdict {
        if !self.config.enabled {
            return Verdict::Pass;
        }
        if let Some(&cost) = self.session_cost_usd.get(session_key) {
            if cost > self.config.max_run_cost_usd {
                return Verdict::Block(format!(
                    "Circuit Breaker: run cost ${:.4} exceeded budget ceiling ${:.2}",
                    cost, self.config.max_run_cost_usd
                ));
            }
        }
        if let Some(&tokens) = self.session_tokens.get(session_key) {
            if tokens > self.config.max_run_tokens {
                return Verdict::Block(format!(
                    "Circuit Breaker: run tokens {} exceeded budget ceiling {}",
                    tokens, self.config.max_run_tokens
                ));
            }
        }
        Verdict::Pass
    }
}

impl Module for BreakerModule {
    fn name(&self) -> &'static str {
        "circuit_breaker"
    }

    fn on_event(&mut self, ev: &WorkbenchEvent) -> Verdict {
        if !self.config.enabled {
            return Verdict::Pass;
        }
        if let WorkbenchEvent::SpanRecorded {
            span,
            session_id,
            model_call,
            ..
        } = ev
        {
            if let Some(mc) = model_call {
                let cost_entry = self.session_cost_usd.entry(session_id.clone()).or_insert(0.0);
                *cost_entry += mc.cost_usd;
                let tok_entry = self.session_tokens.entry(session_id.clone()).or_insert(0);
                *tok_entry += mc.input_tokens + mc.output_tokens;

                if *cost_entry > self.config.max_run_cost_usd {
                    return Verdict::Block(format!(
                        "Circuit Breaker: run cost ${:.4} exceeded budget ceiling ${:.2}",
                        *cost_entry, self.config.max_run_cost_usd
                    ));
                }
                if *tok_entry > self.config.max_run_tokens {
                    return Verdict::Block(format!(
                        "Circuit Breaker: run tokens {} exceeded budget ceiling {}",
                        *tok_entry, self.config.max_run_tokens
                    ));
                }
            } else if span.kind == SpanKind::Mcp {
                if let (Some(server_id), Some(tool_name)) = (
                    span.attributes
                        .get(semconv::MCP_SERVER_ID)
                        .and_then(|v| v.as_str()),
                    span.attributes
                        .get(semconv::GEN_AI_TOOL_NAME)
                        .and_then(|v| v.as_str()),
                ) {
                    let args = span
                        .attributes
                        .get(semconv::GEN_AI_TOOL_CALL_ARGUMENTS)
                        .and_then(|v| v.as_str())
                        .unwrap_or("{}");
                    return self.check_tool_call(session_id, server_id, tool_name, args);
                }
            }
        }
        Verdict::Pass
    }
}

/// Context Window X-Ray module (F-11, UC-07).
pub struct XRayModule;

impl Module for XRayModule {
    fn name(&self) -> &'static str {
        "context_xray"
    }

    fn on_event(&mut self, ev: &WorkbenchEvent) -> Verdict {
        if let WorkbenchEvent::SpanRecorded {
            model_call: Some(mc),
            ..
        } = ev
        {
            if let Some(ref warning) = mc.context_breakdown.bloat_warning {
                return Verdict::Annotate(warning.clone());
            }
        }
        Verdict::Pass
    }
}

/// Policy / Firewall module (F-13, §8).
pub struct PolicyModule {
    pub config: PolicyConfig,
    changed_tools: HashMap<(String, String), String>,
    seen_tool_hashes: HashMap<(String, String), String>,
}

impl PolicyModule {
    pub fn new(config: PolicyConfig) -> Self {
        Self {
            config,
            changed_tools: HashMap::new(),
            seen_tool_hashes: HashMap::new(),
        }
    }

    pub fn evaluate_call(
        &self,
        span_id: &str,
        server_id: &str,
        tool_name: &str,
        arguments_raw: &str,
        timestamp_ns: u64,
    ) -> (Verdict, Option<PolicyDecision>) {
        if !self.config.enabled && self.config.rules.is_empty() {
            return (Verdict::Pass, None);
        }

        if self.config.block_on_schema_change {
            if let Some(new_hash) = self
                .changed_tools
                .get(&(server_id.to_string(), tool_name.to_string()))
            {
                let reason = format!(
                    "Tool '{}' on server '{}' changed its description/schema mid-session (hash {})",
                    tool_name,
                    server_id,
                    &new_hash[..8.min(new_hash.len())]
                );
                let decision = PolicyDecision {
                    id: 0,
                    rule_id: "schema-change-guard".to_string(),
                    span_id: span_id.to_string(),
                    server_id: server_id.to_string(),
                    tool_name: tool_name.to_string(),
                    verdict: "deny".to_string(),
                    reason: reason.clone(),
                    timestamp_ns,
                };
                return (Verdict::Block(reason), Some(decision));
            }
        }

        for rule in &self.config.rules {
            if !wildcard_match(&rule.server, server_id) {
                continue;
            }
            if !wildcard_match(&rule.tool, tool_name) {
                continue;
            }
            if let Some(ref pat) = rule.arg_pattern {
                if !pat.is_empty() {
                    let matched = match Regex::new(pat) {
                        Ok(re) => re.is_match(arguments_raw),
                        Err(_) => arguments_raw.contains(pat),
                    };
                    if !matched {
                        continue;
                    }
                }
            }

            let reason = if rule.reason.is_empty() {
                format!(
                    "Matched policy rule '{}' ({}) on {}:{}",
                    rule.id,
                    rule.effect.as_str(),
                    server_id,
                    tool_name
                )
            } else {
                rule.reason.clone()
            };

            let decision = PolicyDecision {
                id: 0,
                rule_id: rule.id.clone(),
                span_id: span_id.to_string(),
                server_id: server_id.to_string(),
                tool_name: tool_name.to_string(),
                verdict: rule.effect.as_str().to_string(),
                reason: reason.clone(),
                timestamp_ns,
            };

            match rule.effect {
                PolicyEffect::Deny => return (Verdict::Block(reason), Some(decision)),
                PolicyEffect::Allow => return (Verdict::Pass, Some(decision)),
            }
        }

        (Verdict::Pass, None)
    }

    pub fn update_rules(&mut self, enabled: bool, rules: Vec<PolicyRule>) {
        self.config.enabled = enabled;
        self.config.rules = rules;
    }
}

impl Module for PolicyModule {
    fn name(&self) -> &'static str {
        "policy_firewall"
    }

    fn on_event(&mut self, ev: &WorkbenchEvent) -> Verdict {
        match ev {
            WorkbenchEvent::ToolsDiscovered { server_id, tools } => {
                for t in tools {
                    let key = (server_id.clone(), t.name.clone());
                    if let Some(prev) = self.seen_tool_hashes.get(&key) {
                        if prev != &t.schema_hash {
                            self.changed_tools.insert(key.clone(), t.schema_hash.clone());
                        }
                    }
                    self.seen_tool_hashes.insert(key, t.schema_hash.clone());
                }
                Verdict::Pass
            }
            WorkbenchEvent::SpanRecorded { span, .. } => {
                if span.kind == SpanKind::Mcp {
                    if let (Some(server_id), Some(tool_name)) = (
                        span.attributes
                            .get(semconv::MCP_SERVER_ID)
                            .and_then(|v| v.as_str()),
                        span.attributes
                            .get(semconv::GEN_AI_TOOL_NAME)
                            .and_then(|v| v.as_str()),
                    ) {
                        let args = span
                            .attributes
                            .get(semconv::GEN_AI_TOOL_CALL_ARGUMENTS)
                            .and_then(|v| v.as_str())
                            .unwrap_or("{}");
                        let (verdict, _) = self.evaluate_call(
                            &span.id,
                            server_id,
                            tool_name,
                            args,
                            span.start_ns,
                        );
                        return verdict;
                    }
                }
                Verdict::Pass
            }
            _ => Verdict::Pass,
        }
    }
}

fn wildcard_match(pattern: &str, value: &str) -> bool {
    if pattern == "*" || pattern.is_empty() {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return value.starts_with(prefix);
    }
    pattern.eq_ignore_ascii_case(value)
}

/// Hosts all compiled modules over the shared event stream (§4.1).
pub struct ModuleHost {
    pub breaker: BreakerModule,
    pub xray: XRayModule,
    pub policy: PolicyModule,
}

impl ModuleHost {
    pub fn new(breaker_cfg: BreakerConfig, policy_cfg: PolicyConfig) -> Self {
        Self {
            breaker: BreakerModule::new(breaker_cfg),
            xray: XRayModule,
            policy: PolicyModule::new(policy_cfg),
        }
    }

    pub fn dispatch(&mut self, ev: &WorkbenchEvent) -> Verdict {
        let v_policy = self.policy.on_event(ev);
        if v_policy.is_blocked() {
            return v_policy;
        }
        let v_breaker = self.breaker.on_event(ev);
        if v_breaker.is_blocked() {
            return v_breaker;
        }
        self.xray.on_event(ev)
    }
}
