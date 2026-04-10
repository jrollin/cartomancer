//! Ollama LLM provider — local-first, no API key needed.
//!
//! Uses the `/api/chat` endpoint for chat completions.

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use super::LlmProvider;

pub struct OllamaProvider {
    http: reqwest::Client,
    base_url: String,
    model: String,
}

#[derive(Serialize)]
struct ChatRequest<'a> {
    model: &'a str,
    messages: Vec<Message<'a>>,
    stream: bool,
}

#[derive(Serialize)]
struct Message<'a> {
    role: &'a str,
    content: &'a str,
}

#[derive(Deserialize)]
struct ChatResponse {
    message: ResponseMessage,
}

#[derive(Deserialize)]
struct ResponseMessage {
    content: String,
}

impl OllamaProvider {
    pub fn new(base_url: &str, model: &str) -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(300))
                .build()
                .expect("failed to build HTTP client"),
            base_url: base_url.trim_end_matches('/').to_string(),
            model: model.to_string(),
        }
    }
}

#[derive(Deserialize)]
struct TagsResponse {
    models: Vec<TagModel>,
}

#[derive(Deserialize)]
struct TagModel {
    name: String,
}

#[async_trait]
impl LlmProvider for OllamaProvider {
    fn name(&self) -> &str {
        "ollama"
    }

    async fn health_check(&self) -> Result<()> {
        let resp: TagsResponse = self
            .http
            .get(format!("{}/api/tags", self.base_url))
            .send()
            .await
            .context(format!(
                "cannot reach Ollama at {} — is it running?",
                self.base_url
            ))?
            .error_for_status()
            .context("Ollama health check failed")?
            .json()
            .await
            .context("failed to parse Ollama /api/tags response")?;

        let available: Vec<&str> = resp.models.iter().map(|m| m.name.as_str()).collect();
        // Ollama model names may include a `:latest` suffix
        let model_matches = available
            .iter()
            .any(|m| *m == self.model || *m == format!("{}:latest", self.model));

        if !model_matches {
            anyhow::bail!(
                "model '{}' not found in Ollama — available: [{}]. Pull it with: ollama pull {}",
                self.model,
                available.join(", "),
                self.model,
            );
        }

        Ok(())
    }

    async fn complete(&self, prompt: &str) -> Result<String> {
        let body = ChatRequest {
            model: &self.model,
            messages: vec![Message {
                role: "user",
                content: prompt,
            }],
            stream: false,
        };

        let resp = self
            .http
            .post(format!("{}/api/chat", self.base_url))
            .json(&body)
            .send()
            .await
            .context("Failed to connect to Ollama")?
            .error_for_status()
            .context("Ollama returned an error")?
            .json::<ChatResponse>()
            .await
            .context("Failed to parse Ollama response")?;

        Ok(resp.message.content)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chat_request_serialization() {
        let req = ChatRequest {
            model: "gemma4",
            messages: vec![Message {
                role: "user",
                content: "hello",
            }],
            stream: false,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("gemma4"));
        assert!(json.contains("hello"));
        assert!(json.contains(r#""stream":false"#));
    }
}
