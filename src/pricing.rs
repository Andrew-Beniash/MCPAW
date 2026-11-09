use crate::config::ModelPriceOverride;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub const PRICE_TABLE_DATE: &str = "2026-11-01";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelPricing {
    pub model_prefix: String,
    pub input_per_1m: f64,
    pub cached_per_1m: f64,
    pub output_per_1m: f64,
}

#[derive(Debug, Clone)]
pub struct PriceTable {
    pub version_date: String,
    entries: Vec<ModelPricing>,
    overrides: HashMap<String, ModelPricing>,
}

impl Default for PriceTable {
    fn default() -> Self {
        Self::new(&[])
    }
}

impl PriceTable {
    pub fn new(custom_overrides: &[ModelPriceOverride]) -> Self {
        let entries = vec![
            ModelPricing {
                model_prefix: "claude-opus-4".to_string(),
                input_per_1m: 15.0,
                cached_per_1m: 1.5,
                output_per_1m: 75.0,
            },
            ModelPricing {
                model_prefix: "claude-sonnet-4".to_string(),
                input_per_1m: 3.0,
                cached_per_1m: 0.3,
                output_per_1m: 15.0,
            },
            ModelPricing {
                model_prefix: "claude-3-7-sonnet".to_string(),
                input_per_1m: 3.0,
                cached_per_1m: 0.3,
                output_per_1m: 15.0,
            },
            ModelPricing {
                model_prefix: "claude-3-5-sonnet".to_string(),
                input_per_1m: 3.0,
                cached_per_1m: 0.3,
                output_per_1m: 15.0,
            },
            ModelPricing {
                model_prefix: "claude-3-5-haiku".to_string(),
                input_per_1m: 0.80,
                cached_per_1m: 0.08,
                output_per_1m: 4.0,
            },
            ModelPricing {
                model_prefix: "claude-3-opus".to_string(),
                input_per_1m: 15.0,
                cached_per_1m: 1.5,
                output_per_1m: 75.0,
            },
            ModelPricing {
                model_prefix: "gpt-4o-mini".to_string(),
                input_per_1m: 0.15,
                cached_per_1m: 0.075,
                output_per_1m: 0.60,
            },
            ModelPricing {
                model_prefix: "gpt-4o".to_string(),
                input_per_1m: 2.50,
                cached_per_1m: 1.25,
                output_per_1m: 10.0,
            },
            ModelPricing {
                model_prefix: "gpt-4.1".to_string(),
                input_per_1m: 2.00,
                cached_per_1m: 0.50,
                output_per_1m: 8.0,
            },
            ModelPricing {
                model_prefix: "o3-mini".to_string(),
                input_per_1m: 1.10,
                cached_per_1m: 0.55,
                output_per_1m: 4.40,
            },
            ModelPricing {
                model_prefix: "o1".to_string(),
                input_per_1m: 15.0,
                cached_per_1m: 7.50,
                output_per_1m: 60.0,
            },
            ModelPricing {
                model_prefix: "gemini-2.5-pro".to_string(),
                input_per_1m: 1.25,
                cached_per_1m: 0.31,
                output_per_1m: 10.0,
            },
            ModelPricing {
                model_prefix: "gemini-2.5-flash".to_string(),
                input_per_1m: 0.15,
                cached_per_1m: 0.0375,
                output_per_1m: 0.60,
            },
        ];

        let mut overrides = HashMap::new();
        for o in custom_overrides {
            overrides.insert(
                o.model.to_lowercase(),
                ModelPricing {
                    model_prefix: o.model.clone(),
                    input_per_1m: o.input_per_1m,
                    cached_per_1m: o.cached_per_1m,
                    output_per_1m: o.output_per_1m,
                },
            );
        }

        Self {
            version_date: PRICE_TABLE_DATE.to_string(),
            entries,
            overrides,
        }
    }

    pub fn lookup(&self, model: &str) -> ModelPricing {
        let lower = model.to_lowercase();
        if let Some(exact) = self.overrides.get(&lower) {
            return exact.clone();
        }
        for entry in &self.entries {
            if lower.contains(&entry.model_prefix) {
                return entry.clone();
            }
        }
        // Default mid-tier fallback rate ($3 / $0.30 / $15 per 1M tokens)
        ModelPricing {
            model_prefix: "default".to_string(),
            input_per_1m: 3.0,
            cached_per_1m: 0.3,
            output_per_1m: 15.0,
        }
    }

    /// Computes USD cost according to §11:
    /// Cost = (input_tokens - cached_tokens) * input_price + cached_tokens * cache_price + output_tokens * output_price
    pub fn calculate_cost(
        &self,
        model: &str,
        input_tokens: u64,
        cached_tokens: u64,
        output_tokens: u64,
    ) -> f64 {
        let pricing = self.lookup(model);
        let billable_input = input_tokens.saturating_sub(cached_tokens) as f64;
        let cached = cached_tokens.min(input_tokens) as f64;
        let output = output_tokens as f64;

        (billable_input * pricing.input_per_1m
            + cached * pricing.cached_per_1m
            + output * pricing.output_per_1m)
            / 1_000_000.0
    }

    /// Fallback token estimator (~4 chars per token) used only when a provider omits `usage`.
    pub fn estimate_tokens(text: &str) -> u64 {
        if text.is_empty() {
            return 0;
        }
        (text.chars().count() as u64).div_ceil(4)
    }
}
