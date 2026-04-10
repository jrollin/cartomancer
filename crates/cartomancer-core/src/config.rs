//! Application configuration types.

use serde::{Deserialize, Serialize};

use crate::severity::Severity;

/// Top-level configuration (deserialized from `.cartomancer.yaml`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AppConfig {
    #[serde(default)]
    pub github: GitHubConfig,
    #[serde(default)]
    pub semgrep: SemgrepConfig,
    #[serde(default)]
    pub llm: LlmConfig,
    #[serde(default)]
    pub severity: SeverityConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GitHubConfig {
    pub webhook_secret: Option<String>,
    pub token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemgrepConfig {
    #[serde(default = "default_semgrep_rules")]
    pub rules: Vec<String>,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
}

impl Default for SemgrepConfig {
    fn default() -> Self {
        Self {
            rules: default_semgrep_rules(),
            timeout_seconds: default_timeout(),
        }
    }
}

fn default_semgrep_rules() -> Vec<String> {
    vec!["auto".into()]
}

fn default_timeout() -> u64 {
    120
}

/// LLM provider selection and settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmConfig {
    #[serde(default)]
    pub provider: LlmProvider,
    pub ollama_base_url: Option<String>,
    pub ollama_model: Option<String>,
    pub anthropic_api_key: Option<String>,
    pub anthropic_model: Option<String>,
    #[serde(default = "default_max_tokens")]
    pub max_tokens: u32,
}

impl Default for LlmConfig {
    fn default() -> Self {
        Self {
            provider: LlmProvider::default(),
            ollama_base_url: None,
            ollama_model: None,
            anthropic_api_key: None,
            anthropic_model: None,
            max_tokens: default_max_tokens(),
        }
    }
}

fn default_max_tokens() -> u32 {
    4096
}

/// Supported LLM providers.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum LlmProvider {
    #[default]
    Ollama,
    Anthropic,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeverityConfig {
    #[serde(default = "default_blast_threshold")]
    pub blast_radius_threshold: u32,
    #[serde(default = "default_llm_threshold")]
    pub llm_deepening_threshold: Severity,
}

impl Default for SeverityConfig {
    fn default() -> Self {
        Self {
            blast_radius_threshold: default_blast_threshold(),
            llm_deepening_threshold: default_llm_threshold(),
        }
    }
}

fn default_blast_threshold() -> u32 {
    5
}

fn default_llm_threshold() -> Severity {
    Severity::Error
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn llm_provider_deserializes_from_string() {
        let json = r#""ollama""#;
        let provider: LlmProvider = serde_json::from_str(json).unwrap();
        assert!(matches!(provider, LlmProvider::Ollama));

        let json = r#""anthropic""#;
        let provider: LlmProvider = serde_json::from_str(json).unwrap();
        assert!(matches!(provider, LlmProvider::Anthropic));
    }

    #[test]
    fn default_config_is_valid() {
        let config = AppConfig::default();
        assert_eq!(config.semgrep.rules, vec!["auto"]);
        assert_eq!(config.semgrep.timeout_seconds, 120);
        assert_eq!(config.severity.blast_radius_threshold, 5);
        assert!(matches!(config.llm.provider, LlmProvider::Ollama));
    }

    #[test]
    fn deserialize_toml_with_defaults() {
        let toml_str = "[semgrep]\nrules = [\"auto\"]\n";
        let config: AppConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.severity.blast_radius_threshold, 5);
        assert!(matches!(config.llm.provider, LlmProvider::Ollama));
    }
}
