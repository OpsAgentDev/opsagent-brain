//! The model port (dashboard-ai.md, The model port): one streamed turn of a chat model, with
//! tools, behind a provider-neutral shape. No I/O here.
use async_trait::async_trait;
use rust_decimal::Decimal;
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AiProvider {
    Anthropic,
    OpenAi,
}

impl AiProvider {
    pub const ALL: [AiProvider; 2] = [Self::Anthropic, Self::OpenAi];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Anthropic => "anthropic",
            Self::OpenAi => "openai",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.as_str() == s)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MsgRole {
    User,
    Assistant,
}

impl MsgRole {
    pub const ALL: [MsgRole; 2] = [Self::User, Self::Assistant];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Assistant => "assistant",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|r| r.as_str() == s)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ToolCall {
    pub id: String,
    pub name: String,
    pub args: Value,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Part {
    Text(String),
    ToolCall(ToolCall),
    ToolResult { call_id: String, content: String },
}

#[derive(Debug, Clone, PartialEq)]
pub struct ModelMessage {
    pub role: MsgRole,
    pub parts: Vec<Part>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ToolDef {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ModelRequest {
    pub model: String,
    pub system: String,
    pub messages: Vec<ModelMessage>,
    pub tools: Vec<ToolDef>,
    pub max_tokens: u32,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Usage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_read_tokens: u64,
    pub cache_write_tokens: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReason {
    EndTurn,
    ToolUse,
    MaxTokens,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ModelTurn {
    pub text: String,
    pub tool_calls: Vec<ToolCall>,
    pub usage: Usage,
    pub stop: StopReason,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelInfo {
    pub id: String,
    pub tools: bool,
}

/// Stable codes only; never the provider's text.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ModelError {
    #[error("auth")]
    Auth,
    #[error("rate_limited")]
    RateLimited,
    #[error("outage")]
    Outage,
    #[error("model_gone")]
    ModelGone,
    #[error("model: {0}")]
    Other(String),
}

/// Receives the turn's text as it streams.
pub trait TextSink: Send {
    fn delta(&mut self, text: &str);
}

#[async_trait]
pub trait ModelProvider: Send + Sync {
    /// One model call; text deltas go to `sink` as they arrive.
    async fn stream(
        &self,
        api_key: &str,
        req: &ModelRequest,
        sink: &mut dyn TextSink,
    ) -> Result<ModelTurn, ModelError>;

    async fn list_models(&self, api_key: &str) -> Result<Vec<ModelInfo>, ModelError>;
}

/// List prices in US dollars per million tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModelPrice {
    pub input: Decimal,
    pub output: Decimal,
    pub cache_read: Decimal,
    pub cache_write: Decimal,
}

/// The call's cost in credits (1 credit = US$0.01 at list price).
pub fn credits(u: &Usage, p: &ModelPrice) -> Decimal {
    let tokens = |n: u64, per_million: Decimal| Decimal::from(n) * per_million;
    let usd = tokens(u.input_tokens, p.input)
        + tokens(u.output_tokens, p.output)
        + tokens(u.cache_read_tokens, p.cache_read)
        + tokens(u.cache_write_tokens, p.cache_write);
    usd * Decimal::from(100) / Decimal::from(1_000_000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credits_from_usage_and_price() {
        let price = ModelPrice {
            input: Decimal::from(1),
            output: Decimal::from(5),
            cache_read: Decimal::new(1, 1),
            cache_write: Decimal::new(125, 2),
        };
        let only = |u: Usage| credits(&u, &price);
        let m = 1_000_000;
        let input = Usage {
            input_tokens: m,
            ..Default::default()
        };
        assert_eq!(only(input), Decimal::from(100));
        let output = Usage {
            output_tokens: m,
            ..Default::default()
        };
        assert_eq!(only(output), Decimal::from(500));
        let cache = Usage {
            cache_read_tokens: m,
            cache_write_tokens: m,
            ..Default::default()
        };
        assert_eq!(only(cache), Decimal::from(135));
        let small = Usage {
            input_tokens: 1000,
            output_tokens: 200,
            ..Default::default()
        };
        assert_eq!(only(small), Decimal::new(2, 1));
    }

    #[test]
    fn names_round_trip() {
        for p in AiProvider::ALL {
            assert_eq!(AiProvider::parse(p.as_str()), Some(p));
        }
        for r in MsgRole::ALL {
            assert_eq!(MsgRole::parse(r.as_str()), Some(r));
        }
        assert_eq!(AiProvider::parse("gemini"), None);
    }
}
