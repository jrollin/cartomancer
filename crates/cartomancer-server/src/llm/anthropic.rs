//! Anthropic LLM provider — Claude Messages API.

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use super::LlmProvider;

pub struct AnthropicProvider {
    http: reqwest::Client,
    base_url: String,
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

const DEFAULT_BASE_URL: &str = "https://api.anthropic.com";

/// Anthropic Messages API limits for `max_tokens`.
const MAX_TOKENS_MIN: u32 = 1;
const MAX_TOKENS_MAX: u32 = 128_000;

impl AnthropicProvider {
    pub fn new(api_key: &str, model: &str, max_tokens: u32) -> Self {
        Self::with_base_url(DEFAULT_BASE_URL, api_key, model, max_tokens)
    }

    /// Build a provider pointing at an arbitrary base URL (useful for testing).
    pub fn with_base_url(base_url: &str, api_key: &str, model: &str, max_tokens: u32) -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(120))
                .build()
                .expect("failed to build HTTP client"),
            base_url: base_url.trim_end_matches('/').to_string(),
            api_key: api_key.to_string(),
            model: model.to_string(),
            max_tokens,
        }
    }

    /// Validate that `max_tokens` is within the Anthropic API range (1..=128,000).
    pub fn validate_max_tokens(value: u32) -> anyhow::Result<()> {
        if !(MAX_TOKENS_MIN..=MAX_TOKENS_MAX).contains(&value) {
            anyhow::bail!(
                "max_tokens must be between {MAX_TOKENS_MIN} and {MAX_TOKENS_MAX}, got {value}"
            );
        }
        Ok(())
    }
}

#[async_trait]
impl LlmProvider for AnthropicProvider {
    fn name(&self) -> &str {
        "anthropic"
    }

    async fn health_check(&self) -> Result<()> {
        // Send an empty body to verify API key without burning tokens.
        // Anthropic returns 400 (invalid request) for a valid key, 401 for invalid.
        let url = format!("{}/v1/messages", self.base_url);
        let response = self
            .http
            .post(&url)
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .body("{}")
            .send()
            .await
            .context("cannot reach Anthropic API")?;

        match response.status() {
            s if s == reqwest::StatusCode::UNAUTHORIZED => {
                anyhow::bail!("Anthropic API key is invalid (HTTP 401)");
            }
            s if s == reqwest::StatusCode::FORBIDDEN => {
                anyhow::bail!("Anthropic API key lacks permission (HTTP 403)");
            }
            _ => {
                // 400 (bad request) is expected — means auth passed
                Ok(())
            }
        }
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

        let url = format!("{}/v1/messages", self.base_url);
        let response = self
            .http
            .post(&url)
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await
            .context("Failed to connect to Anthropic API")?;

        let status = response.status();
        let body_text = response
            .text()
            .await
            .context("Failed to read Anthropic response body")?;

        if !status.is_success() {
            anyhow::bail!(
                "Anthropic API error (HTTP {}): {}",
                status.as_u16(),
                body_text
            );
        }

        let resp: MessagesResponse =
            serde_json::from_str(&body_text).context("Failed to parse Anthropic response")?;

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
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

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

    #[test]
    fn validate_max_tokens_accepts_valid_range() {
        assert!(AnthropicProvider::validate_max_tokens(1).is_ok());
        assert!(AnthropicProvider::validate_max_tokens(4096).is_ok());
        assert!(AnthropicProvider::validate_max_tokens(128_000).is_ok());
    }

    #[test]
    fn validate_max_tokens_rejects_zero() {
        let err = AnthropicProvider::validate_max_tokens(0).unwrap_err();
        assert!(err.to_string().contains("must be between"));
    }

    #[test]
    fn validate_max_tokens_rejects_too_large() {
        let err = AnthropicProvider::validate_max_tokens(128_001).unwrap_err();
        assert!(err.to_string().contains("must be between"));
    }

    // --- HTTP mocking tests ---

    fn provider_for(server: &MockServer) -> AnthropicProvider {
        AnthropicProvider::with_base_url(&server.uri(), "test-key", "test-model", 1024)
    }

    #[tokio::test]
    async fn health_check_passes_on_bad_request() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .and(header("x-api-key", "test-key"))
            .respond_with(ResponseTemplate::new(400).set_body_string("bad request"))
            .mount(&server)
            .await;

        let provider = provider_for(&server);
        provider.health_check().await.unwrap();
    }

    #[tokio::test]
    async fn health_check_fails_on_unauthorized() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;

        let provider = provider_for(&server);
        let err = provider.health_check().await.unwrap_err();
        assert!(err.to_string().contains("invalid"));
    }

    #[tokio::test]
    async fn health_check_fails_on_forbidden() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&server)
            .await;

        let provider = provider_for(&server);
        let err = provider.health_check().await.unwrap_err();
        assert!(err.to_string().contains("permission"));
    }

    #[tokio::test]
    async fn complete_returns_text_on_success() {
        let server = MockServer::start().await;
        let body = r#"{"content":[{"type":"text","text":"This is dangerous."}]}"#;
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .and(header("x-api-key", "test-key"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&server)
            .await;

        let provider = provider_for(&server);
        let result = provider.complete("analyze this").await.unwrap();
        assert_eq!(result, "This is dangerous.");
    }

    #[tokio::test]
    async fn complete_joins_multiple_content_blocks() {
        let server = MockServer::start().await;
        let body =
            r#"{"content":[{"type":"text","text":"First. "},{"type":"text","text":"Second."}]}"#;
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&server)
            .await;

        let provider = provider_for(&server);
        let result = provider.complete("test").await.unwrap();
        assert_eq!(result, "First. Second.");
    }

    #[tokio::test]
    async fn complete_fails_on_api_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(ResponseTemplate::new(429).set_body_string(r#"{"error":"rate limited"}"#))
            .mount(&server)
            .await;

        let provider = provider_for(&server);
        let err = provider.complete("test").await.unwrap_err();
        assert!(err.to_string().contains("429"));
    }

    #[tokio::test]
    async fn complete_sends_correct_model_and_max_tokens() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .and(wiremock::matchers::body_partial_json(serde_json::json!({
                "model": "test-model",
                "max_tokens": 1024
            })))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(r#"{"content":[{"type":"text","text":"ok"}]}"#),
            )
            .mount(&server)
            .await;

        let provider = provider_for(&server);
        let result = provider.complete("test").await.unwrap();
        assert_eq!(result, "ok");
    }
}
