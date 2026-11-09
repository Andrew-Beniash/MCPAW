use crate::config::CaptureLevel;
use crate::models::{semconv, WorkbenchEvent};
use regex::Regex;
use serde_json::Value;

#[derive(Debug, Clone)]
pub struct Redactor {
    pub capture_level: CaptureLevel,
    key_regexes: Vec<Regex>,
    value_regexes: Vec<Regex>,
}

impl Redactor {
    pub fn new(capture_level: CaptureLevel, patterns: &[String]) -> Self {
        let mut key_regexes = Vec::new();
        let mut value_regexes = Vec::new();

        // B6: Match key names on fragments rather than exact anchored strings
        if let Ok(re) = Regex::new(
            r"(?i)(token|secret|passw|api[_-]?key|auth|bearer|credential|private[_-]?key|session[_-]?key|cookie|canary)",
        ) {
            key_regexes.push(re);
        }

        // B6: Value regexes for well-known token prefixes and serialized key-value credentials
        let builtin_value_patterns = [
            r"sk-[A-Za-z0-9_-]{6,}",
            r"ghp_[A-Za-z0-9_]{8,}",
            r"github_pat_[A-Za-z0-9_]{8,}",
            r"gh[ousr]_[A-Za-z0-9_]{8,}",
            r"xox[baprs]-[A-Za-z0-9-]{8,}",
            r"AKIA[0-9A-Z]{16}",
            r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{6,}",
            r"(?i)bearer\s+[A-Za-z0-9._~+/=-]+",
            r"(?i)basic\s+[A-Za-z0-9+/=]{8,}",
            r#"(?i)["']?[a-z0-9_.-]*(?:token|secret|passw|api[_-]?key|auth|bearer|credential|private[_-]?key|cookie|canary)[a-z0-9_.-]*["']?\s*[:=]\s*["']?[A-Za-z0-9._~+/=-]{6,}["']?"#,
        ];
        for pat in builtin_value_patterns {
            if let Ok(re) = Regex::new(pat) {
                value_regexes.push(re);
            }
        }

        for pat in patterns {
            let ci_pat = if pat.starts_with("(?i)") {
                pat.clone()
            } else {
                format!("(?i){}", pat)
            };
            if let Ok(re) = Regex::new(&ci_pat) {
                if !pat.contains("\\s") && !pat.contains("sk-") {
                    if let Ok(key_re) = Regex::new(&ci_pat) {
                        key_regexes.push(key_re);
                    }
                }
                value_regexes.push(re);
            }
        }

        Self {
            capture_level,
            key_regexes,
            value_regexes,
        }
    }

    pub fn is_sensitive_key(&self, key: &str) -> bool {
        // Do not treat standard token count metrics (`input_tokens`, `output_tokens`, `cached_tokens`, `total_tokens`) as secrets
        let lower = key.to_lowercase();
        if lower.ends_with("_tokens") || lower == "tokens" || lower == "max_run_tokens" {
            return false;
        }
        self.key_regexes.iter().any(|re| re.is_match(key))
    }

    pub fn redact_str(&self, input: &str) -> String {
        let mut out = input.to_string();
        for re in &self.value_regexes {
            out = re.replace_all(&out, "[REDACTED]").into_owned();
        }
        out
    }

    pub fn redact_json_value(&self, val: &mut Value) {
        match val {
            Value::Object(map) => {
                for (k, v) in map.iter_mut() {
                    if self.is_sensitive_key(k) {
                        *v = Value::String("[REDACTED]".to_string());
                    } else {
                        self.redact_json_value(v);
                    }
                }
            }
            Value::Array(arr) => {
                for item in arr.iter_mut() {
                    self.redact_json_value(item);
                }
            }
            Value::String(s) => {
                let trimmed = s.trim();
                if (trimmed.starts_with('{') && trimmed.ends_with('}'))
                    || (trimmed.starts_with('[') && trimmed.ends_with(']'))
                {
                    if let Ok(mut inner) = serde_json::from_str::<Value>(trimmed) {
                        self.redact_json_value(&mut inner);
                        if let Ok(re_serialized) = serde_json::to_string(&inner) {
                            *s = self.redact_str(&re_serialized);
                            return;
                        }
                    }
                }
                *s = self.redact_str(s);
            }
            _ => {}
        }
    }

    pub fn redact_payload_str(&self, payload: &str) -> String {
        if let Ok(mut parsed) = serde_json::from_str::<Value>(payload) {
            self.redact_json_value(&mut parsed);
            if let Ok(serialized) = serde_json::to_string(&parsed) {
                return self.redact_str(&serialized);
            }
        }
        self.redact_str(payload)
    }

    /// Runs before an event reaches any bus subscriber or persistence store (§8).
    pub fn sanitize_event(&self, event: &mut WorkbenchEvent) {
        match event {
            WorkbenchEvent::SessionStarted { .. } => {}
            WorkbenchEvent::ServerObserved { command_or_url, .. } => {
                *command_or_url = self.redact_str(command_or_url);
            }
            WorkbenchEvent::ToolsDiscovered { tools, .. } => {
                for tool in tools.iter_mut() {
                    tool.description = self.redact_str(&tool.description);
                    self.redact_json_value(&mut tool.input_schema);
                }
            }
            WorkbenchEvent::SpanRecorded {
                span,
                mcp_messages,
                model_call,
                policy_decisions,
                ..
            } => {
                match self.capture_level {
                    CaptureLevel::Off => {
                        // M13: Under `off`, keep only counts and timing (drop tool names, method names, and message metadata)
                        span.name = span.kind.as_str().to_string();
                        span.attributes.clear();
                        for msg in mcp_messages.iter_mut() {
                            msg.payload = None;
                            msg.method = None;
                            msg.jsonrpc_id = None;
                        }
                        if let Some(mc) = model_call.as_mut() {
                            mc.request_payload = None;
                            mc.response_payload = None;
                        }
                    }
                    CaptureLevel::Metadata => {
                        span.attributes.remove(semconv::GEN_AI_TOOL_CALL_ARGUMENTS);
                        span.attributes.remove(semconv::GEN_AI_TOOL_CALL_RESULT);
                        for v in span.attributes.values_mut() {
                            self.redact_json_value(v);
                        }
                        for msg in mcp_messages.iter_mut() {
                            msg.payload = None;
                        }
                        if let Some(mc) = model_call.as_mut() {
                            mc.request_payload = None;
                            mc.response_payload = None;
                        }
                    }
                    CaptureLevel::Full => {
                        for v in span.attributes.values_mut() {
                            self.redact_json_value(v);
                        }
                        for msg in mcp_messages.iter_mut() {
                            if let Some(ref p) = msg.payload {
                                msg.payload = Some(self.redact_payload_str(p));
                            }
                        }
                        if let Some(mc) = model_call.as_mut() {
                            if let Some(ref req) = mc.request_payload {
                                mc.request_payload = Some(self.redact_payload_str(req));
                            }
                            if let Some(ref resp) = mc.response_payload {
                                mc.response_payload = Some(self.redact_payload_str(resp));
                            }
                        }
                    }
                }
                for pd in policy_decisions.iter_mut() {
                    pd.reason = self.redact_str(&pd.reason);
                }
            }
            WorkbenchEvent::SpanUpdated {
                attributes_patch,
                response_message,
                ..
            } => match self.capture_level {
                CaptureLevel::Off => {
                    attributes_patch.clear();
                    if let Some(msg) = response_message.as_mut() {
                        msg.payload = None;
                        msg.method = None;
                        msg.jsonrpc_id = None;
                    }
                }
                CaptureLevel::Metadata => {
                    attributes_patch.remove(semconv::GEN_AI_TOOL_CALL_ARGUMENTS);
                    attributes_patch.remove(semconv::GEN_AI_TOOL_CALL_RESULT);
                    for v in attributes_patch.values_mut() {
                        self.redact_json_value(v);
                    }
                    if let Some(msg) = response_message.as_mut() {
                        msg.payload = None;
                    }
                }
                CaptureLevel::Full => {
                    for v in attributes_patch.values_mut() {
                        self.redact_json_value(v);
                    }
                    if let Some(msg) = response_message.as_mut() {
                        if let Some(ref p) = msg.payload {
                            msg.payload = Some(self.redact_payload_str(p));
                        }
                    }
                }
            },
            WorkbenchEvent::PolicyEvaluated { decision } => {
                decision.reason = self.redact_str(&decision.reason);
            }
        }
    }
}
