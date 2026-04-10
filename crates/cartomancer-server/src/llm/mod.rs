//! LLM provider abstraction for finding deepening.
//!
//! Supports multiple backends:
//! - Ollama (local, default for dev/testing)
//! - Anthropic (production)

pub mod anthropic;
pub mod ollama;

use anyhow::Result;
use async_trait::async_trait;

use cartomancer_core::config::LlmConfig;
use cartomancer_core::finding::Finding;

/// Trait for LLM providers that can deepen findings with analysis.
#[async_trait]
pub trait LlmProvider: Send + Sync {
    /// Provider name (e.g. "ollama", "anthropic").
    fn name(&self) -> &str;

    /// Send a prompt and return the completion text.
    async fn complete(&self, prompt: &str) -> Result<String>;

    /// Deepen a finding by generating LLM analysis from its context.
    async fn deepen(&self, finding: &mut Finding) -> Result<()> {
        let prompt = build_deepening_prompt(finding);
        let analysis = self.complete(&prompt).await?;
        finding.llm_analysis = Some(analysis);
        Ok(())
    }
}

/// Create a provider from configuration.
pub fn create_provider(config: &LlmConfig) -> Result<Box<dyn LlmProvider>> {
    match config.provider {
        cartomancer_core::config::LlmBackend::Ollama => {
            let base_url = config
                .ollama_base_url
                .as_deref()
                .unwrap_or("http://localhost:11434");
            let model = config.ollama_model.as_deref().unwrap_or("gemma4");
            Ok(Box::new(ollama::OllamaProvider::new(base_url, model)))
        }
        cartomancer_core::config::LlmBackend::Anthropic => {
            let api_key = config
                .anthropic_api_key
                .clone()
                .or_else(|| std::env::var("ANTHROPIC_API_KEY").ok())
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "Anthropic API key required: set llm.anthropic_api_key or ANTHROPIC_API_KEY"
                    )
                })?;
            let model = config
                .anthropic_model
                .as_deref()
                .unwrap_or("claude-sonnet-4-20250514");
            Ok(Box::new(anthropic::AnthropicProvider::new(
                &api_key,
                model,
                config.max_tokens,
            )))
        }
    }
}

/// Build the deepening prompt for a finding with its graph context.
fn build_deepening_prompt(finding: &Finding) -> String {
    let mut prompt = format!(
        "Analyze this code finding and explain its impact.\n\n\
         ## Finding\n\
         Rule: {}\n\
         Message: {}\n\
         Severity: {}\n\
         File: {}:{}\n\
         Code: {}\n",
        finding.rule_id,
        finding.message,
        finding.severity,
        finding.file_path,
        finding.start_line,
        finding.snippet,
    );

    if let Some(ctx) = &finding.graph_context {
        prompt.push_str(&format!(
            "\n## Structural Context\n\
             Symbol: {}\n\
             Blast radius: {} symbols affected\n\
             Callers ({}):\n",
            ctx.symbol_name.as_deref().unwrap_or("unknown"),
            ctx.blast_radius,
            ctx.callers.len(),
        ));
        for caller in ctx.callers.iter().take(10) {
            prompt.push_str(&format!("  - {caller}\n"));
        }
        if !ctx.domain_tags.is_empty() {
            prompt.push_str(&format!("Domain: {}\n", ctx.domain_tags.join(", ")));
        }
    }

    prompt.push_str(
        "\n## Task\n\
         Explain why this finding matters given the callers and blast radius above.\n\
         Be concise (2-3 sentences). Focus on the real-world impact.\n\
         Respond in plain text, no JSON.",
    );

    prompt
}
