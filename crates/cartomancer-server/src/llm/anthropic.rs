//! Anthropic LLM provider — Claude Messages API.

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use super::LlmProvider;

pub struct AnthropicProvider {
    http: reqwest::Client,
    api_key: String,
    model: String,
    max_tokens: u32,
}

#[derive(Serialize)]
struct MessagesRequest<'a> {
    model: &'a str,
    max_tokens: u32,
    messages: Vec<ApiMessage<'a>>,
}

#[derive(Serialize)]
struct ApiMessage<'a> {
    role: &'a str,
    content: &'a str,
}

#[derive(Deserialize)]
struct MessagesResponse {
    content: Vec<ContentBlock>,
}

#[derive(Deserialize)]
struct ContentBlock {
    text: Option<String>,
}

impl AnthropicProvider {
    pub fn new(api_key: &str, model: &str, max_tokens: u32) -> Self {
        Self {
            http: reqwest::Client::new(),
            api_key: api_key.to_string(),
            model: model.to_string(),
            max_tokens,
        }
    }
}

#[async_trait]
impl LlmProvider for AnthropicProvider {
    fn name(&self) -> &str {
        "anthropic"
    }

    async fn complete(&self, prompt: &str) -> Result<String> {
        let body = MessagesRequest {
            model: &self.model,
            max_tokens: self.max_tokens,
            messages: vec![ApiMessage {
                role: "user",
                content: prompt,
            }],
        };

        let resp = self
            .http
            .post("https://api.anthropic.com/v1/messages")
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await
            .context("Failed to connect to Anthropic API")?
            .error_for_status()
            .context("Anthropic API returned an error")?
            .json::<MessagesResponse>()
            .await
            .context("Failed to parse Anthropic response")?;

        let text = resp
            .content
            .into_iter()
            .filter_map(|block| block.text)
            .collect::<Vec<_>>()
            .join("");

        Ok(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_request_serialization() {
        let req = MessagesRequest {
            model: "claude-sonnet-4-20250514",
            max_tokens: 1024,
            messages: vec![ApiMessage {
                role: "user",
                content: "hello",
            }],
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("claude-sonnet"));
        assert!(json.contains("hello"));
    }

    #[test]
    fn response_deserialization() {
        let json = r#"{"content":[{"type":"text","text":"Hello world"}]}"#;
        let resp: MessagesResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.content[0].text.as_deref(), Some("Hello world"));
    }
}
