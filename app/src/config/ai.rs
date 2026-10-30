//! Dashboard AI settings: OpsAgent's model ids, the price table, BYOK defaults and tool
//! support (dashboard-ai.md; plan 5 Global Constraints).
use opsagent_core::{
    ai::ModelRole,
    model::{AiProvider, ModelPrice},
};
use sea_orm::prelude::Decimal;

use super::{invalid, ConfigError};

/// OpsAgent's key: explanations and other short work.
pub const MODEL_ROUTINE: &str = "claude-haiku-5-5";
/// OpsAgent's key: chat turns with tools.
pub const MODEL_CHAT: &str = "claude-sonnet-5-5";

/// OpenAI ids that can call tools; every Anthropic model can.
pub const OPENAI_TOOL_PREFIXES: [&str; 5] = ["gpt-4.1", "gpt-4o", "gpt-5", "o3", "o4"];

/// The BYOK defaults per provider and role: the first id in the key's live list wins, else
/// the first tool-capable model.
pub fn preferred_models(provider: AiProvider, role: ModelRole) -> &'static [&'static str] {
    match (provider, role) {
        (AiProvider::Anthropic, ModelRole::Routine) => &["claude-haiku-5-5", "claude-haiku-4-5"],
        (AiProvider::Anthropic, ModelRole::Chat) => &["claude-sonnet-5-5", "claude-sonnet-4-5"],
        (AiProvider::OpenAi, ModelRole::Routine) => &["gpt-5-mini", "gpt-4.1-mini"],
        (AiProvider::OpenAi, ModelRole::Chat) => &["gpt-5", "gpt-4.1"],
    }
}

/// List prices, US$ per million tokens: (input, output, cache read, cache write), in
/// thousandths of a dollar.
/// Anthropic: https://platform.claude.com/docs/en/about-claude/pricing (read 2026-10-30;
/// cache write is the 5-minute rate, the only one we use).
/// OpenAI: https://developers.openai.com/api/docs/pricing (standard tier, read 2026-10-30;
/// OpenAI bills no cache writes, so that column repeats input and is never used).
const PRICES: [(&str, [i64; 4]); 8] = [
    // shortcut: Haiku 5.5's prompts-up-to-100k-tokens tier; our turns stay far below it.
    ("claude-haiku-5-5", [100, 500, 10, 125]),
    ("claude-sonnet-5-5", [2_000, 10_000, 100, 2_500]),
    ("claude-haiku-4-5", [1_000, 5_000, 100, 1_250]),
    ("claude-sonnet-4-5", [3_000, 15_000, 300, 3_750]),
    ("gpt-5", [1_250, 10_000, 125, 1_250]),
    ("gpt-5-mini", [250, 2_000, 25, 250]),
    ("gpt-4.1", [2_000, 8_000, 500, 2_000]),
    ("gpt-4.1-mini", [400, 1_600, 100, 400]),
];

/// The model's list price, `None` when unpriced (metering then marks the row `estimated`).
pub fn model_price(model: &str) -> Option<ModelPrice> {
    let usd = |milli: i64| Decimal::new(milli, 3);
    PRICES
        .iter()
        .find(|(id, _)| *id == model)
        .map(|(_, [i, o, r, w])| ModelPrice {
            input: usd(*i),
            output: usd(*o),
            cache_read: usd(*r),
            cache_write: usd(*w),
        })
}

/// `OPSAGENT_MODEL_PROVIDER`: `live` (the default) calls the providers; `fake` serves
/// `FakeModels::demo` for both and is refused in production.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModelMode {
    Live,
    Fake,
}

pub(super) fn model_mode(v: &str, production: bool) -> Result<ModelMode, ConfigError> {
    match v {
        "fake" if production => Err(invalid(
            "OPSAGENT_MODEL_PROVIDER",
            "fake is not allowed in production",
        )),
        "fake" => Ok(ModelMode::Fake),
        "live" => Ok(ModelMode::Live),
        _ => Err(invalid("OPSAGENT_MODEL_PROVIDER", "must be live or fake")),
    }
}

/// What the model adapters and `AiAccess` need. No `Debug`: it holds OpsAgent's key.
#[derive(Clone)]
pub struct ModelSettings {
    pub mode: ModelMode,
    /// Empty: no OpsAgent key (`ai_unavailable` unless the organisation has its own).
    pub anthropic_api_key: String,
    pub anthropic_api_base: String,
    /// Sent as `anthropic-version`.
    pub anthropic_version: String,
    pub openai_api_base: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn price_table_has_both_opsagent_models() {
        let haiku = model_price(MODEL_ROUTINE).expect("routine priced");
        assert_eq!(haiku.input, Decimal::new(1, 1));
        assert_eq!(haiku.output, Decimal::new(5, 1));
        let sonnet = model_price(MODEL_CHAT).expect("chat priced");
        assert_eq!(
            (
                sonnet.input,
                sonnet.output,
                sonnet.cache_read,
                sonnet.cache_write
            ),
            (
                Decimal::from(2),
                Decimal::from(10),
                Decimal::new(1, 1),
                Decimal::new(25, 1)
            )
        );
        assert_eq!(model_price("claude-unknown"), None);
        // Every preferred default is priced, so only off-list BYOK models are estimated.
        for p in AiProvider::ALL {
            for r in ModelRole::ALL {
                for id in preferred_models(p, *r) {
                    assert!(model_price(id).is_some(), "{id}");
                }
            }
        }
        assert_eq!(
            preferred_models(AiProvider::Anthropic, ModelRole::Routine)[0],
            MODEL_ROUTINE
        );
        assert_eq!(
            preferred_models(AiProvider::Anthropic, ModelRole::Chat)[0],
            MODEL_CHAT
        );
    }
}
