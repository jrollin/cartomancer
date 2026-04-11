//! Application configuration types.

use serde::{Deserialize, Serialize};

use crate::severity::Severity;

/// Top-level configuration (deserialized from `.cartomancer.toml`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AppConfig {
    #[serde(default)]
    pub github: GitHubConfig,
    #[serde(default)]
    pub opengrep: OpengrepConfig,
    #[serde(default)]
    pub llm: LlmConfig,
    #[serde(default)]
    pub severity: SeverityConfig,
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub serve: ServeConfig,
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct GitHubConfig {
    #[serde(skip_serializing)]
    pub webhook_secret: Option<String>,
    #[serde(skip_serializing)]
    pub token: Option<String>,
}

impl std::fmt::Debug for GitHubConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GitHubConfig")
            .field(
                "webhook_secret",
                &self.webhook_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .field("token", &self.token.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpengrepConfig {
    #[serde(default = "default_opengrep_rules")]
    pub rules: Vec<String>,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
    /// Glob patterns passed as `--exclude` to opengrep (e.g. `.github/`, `config/database.yml`).
    #[serde(default)]
    pub exclude: Vec<String>,
    /// Number of parallel jobs (`-j`). When `None`, opengrep auto-detects from CPU count.
    #[serde(default)]
    pub jobs: Option<u32>,
    /// Enable cross-function taint analysis within a file (`--taint-intrafile`).
    #[serde(default)]
    pub taint_intrafile: bool,
    /// Custom inline ignore annotation pattern (`--opengrep-ignore-pattern=<VAL>`).
    #[serde(default)]
    pub ignore_pattern: Option<String>,
    /// Capture enclosing function/class body (`--experimental --output-enclosing-context`).
    #[serde(default)]
    pub enclosing_context: bool,
    /// Use file-size-scaled timeouts instead of flat `timeout_seconds`.
    /// When enabled, `--timeout` is replaced by `--dynamic-timeout`.
    /// `timeout_seconds` is still used as the Rust-side process safety timeout.
    #[serde(default)]
    pub dynamic_timeout: bool,
    /// Base timeout unit in KB for dynamic timeout.
    #[serde(default)]
    pub dynamic_timeout_unit_kb: Option<u32>,
    /// Maximum multiplier for dynamic timeout.
    #[serde(default)]
    pub dynamic_timeout_max_multiplier: Option<f32>,
}

impl Default for OpengrepConfig {
    fn default() -> Self {
        Self {
            rules: default_opengrep_rules(),
            timeout_seconds: default_timeout(),
            exclude: Vec::new(),
            jobs: None,
            taint_intrafile: false,
            ignore_pattern: None,
            enclosing_context: false,
            dynamic_timeout: false,
            dynamic_timeout_unit_kb: None,
            dynamic_timeout_max_multiplier: None,
        }
    }
}

fn default_opengrep_rules() -> Vec<String> {
    vec!["auto".into()]
}

fn default_timeout() -> u64 {
    120
}

/// LLM provider selection and settings.
#[derive(Clone, Serialize, Deserialize)]
pub struct LlmConfig {
    #[serde(default)]
    pub provider: LlmBackend,
    pub ollama_base_url: Option<String>,
    pub ollama_model: Option<String>,
    #[serde(skip_serializing)]
    pub anthropic_api_key: Option<String>,
    pub anthropic_model: Option<String>,
    #[serde(default = "default_max_tokens")]
    pub max_tokens: u32,
    /// Max concurrent LLM requests for finding deepening.
    #[serde(default = "default_max_concurrent_deepening")]
    pub max_concurrent_deepening: usize,
}

impl std::fmt::Debug for LlmConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LlmConfig")
            .field("provider", &self.provider)
            .field("ollama_base_url", &self.ollama_base_url)
            .field("ollama_model", &self.ollama_model)
            .field(
                "anthropic_api_key",
                &self.anthropic_api_key.as_ref().map(|_| "[REDACTED]"),
            )
            .field("anthropic_model", &self.anthropic_model)
            .field("max_tokens", &self.max_tokens)
            .field("max_concurrent_deepening", &self.max_concurrent_deepening)
            .finish()
    }
}

impl Default for LlmConfig {
    fn default() -> Self {
        Self {
            provider: LlmBackend::default(),
            ollama_base_url: None,
            ollama_model: None,
            anthropic_api_key: None,
            anthropic_model: None,
            max_tokens: default_max_tokens(),
            max_concurrent_deepening: default_max_concurrent_deepening(),
        }
    }
}

fn default_max_tokens() -> u32 {
    4096
}

fn default_max_concurrent_deepening() -> usize {
    4
}

/// Supported LLM backends.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum LlmBackend {
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
    #[serde(default = "default_impact_depth")]
    pub impact_depth: u32,
}

impl Default for SeverityConfig {
    fn default() -> Self {
        Self {
            blast_radius_threshold: default_blast_threshold(),
            llm_deepening_threshold: default_llm_threshold(),
            impact_depth: default_impact_depth(),
        }
    }
}

/// Storage configuration for finding persistence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    #[serde(default = "default_db_path")]
    pub db_path: String,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            db_path: default_db_path(),
        }
    }
}

fn default_db_path() -> String {
    ".cartomancer.db".into()
}

/// Serve (webhook server) configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServeConfig {
    /// Maximum number of concurrent PR reviews (bounded by semaphore).
    #[serde(default = "default_max_concurrent_reviews")]
    pub max_concurrent_reviews: usize,
}

impl Default for ServeConfig {
    fn default() -> Self {
        Self {
            max_concurrent_reviews: default_max_concurrent_reviews(),
        }
    }
}

fn default_max_concurrent_reviews() -> usize {
    4
}

fn default_blast_threshold() -> u32 {
    5
}

fn default_llm_threshold() -> Severity {
    Severity::Error
}

fn default_impact_depth() -> u32 {
    3
}

impl AppConfig {
    /// Validate semantic constraints that serde cannot enforce.
    /// Collects all errors before returning, so the user sees everything at once.
    pub fn validate(&self) -> Result<(), String> {
        let mut errors = Vec::<&str>::new();

        if self.opengrep.rules.is_empty() {
            errors.push("opengrep.rules must not be empty");
        }
        if self.opengrep.timeout_seconds == 0 {
            errors.push("opengrep.timeout_seconds must be > 0");
        }
        if let Some(mult) = self.opengrep.dynamic_timeout_max_multiplier {
            if mult <= 0.0 {
                errors.push("opengrep.dynamic_timeout_max_multiplier must be > 0.0");
            }
        }

        if self.severity.blast_radius_threshold == 0 {
            errors.push("severity.blast_radius_threshold must be > 0");
        }
        if self.severity.impact_depth == 0 || self.severity.impact_depth > 20 {
            errors.push("severity.impact_depth must be between 1 and 20");
        }

        if self.llm.max_tokens == 0 {
            errors.push("llm.max_tokens must be > 0");
        }
        if self.llm.max_concurrent_deepening == 0 {
            errors.push("llm.max_concurrent_deepening must be > 0");
        }
        if self.serve.max_concurrent_reviews == 0 {
            errors.push("serve.max_concurrent_reviews must be > 0");
        }

        if matches!(self.llm.provider, LlmBackend::Anthropic) {
            let has_key =
                self.llm.anthropic_api_key.is_some() || std::env::var("ANTHROPIC_API_KEY").is_ok();
            if !has_key {
                errors.push(
                    "llm.anthropic_api_key required when provider is anthropic \
                     (or set ANTHROPIC_API_KEY env var)",
                );
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn llm_provider_deserializes_from_string() {
        let json = r#""ollama""#;
        let provider: LlmBackend = serde_json::from_str(json).unwrap();
        assert!(matches!(provider, LlmBackend::Ollama));

        let json = r#""anthropic""#;
        let provider: LlmBackend = serde_json::from_str(json).unwrap();
        assert!(matches!(provider, LlmBackend::Anthropic));
    }

    #[test]
    fn default_config_is_valid() {
        let config = AppConfig::default();
        assert_eq!(config.opengrep.rules, vec!["auto"]);
        assert_eq!(config.opengrep.timeout_seconds, 120);
        assert!(config.opengrep.exclude.is_empty());
        assert!(config.opengrep.jobs.is_none());
        assert!(!config.opengrep.taint_intrafile);
        assert!(config.opengrep.ignore_pattern.is_none());
        assert!(!config.opengrep.enclosing_context);
        assert!(!config.opengrep.dynamic_timeout);
        assert!(config.opengrep.dynamic_timeout_unit_kb.is_none());
        assert!(config.opengrep.dynamic_timeout_max_multiplier.is_none());
        assert_eq!(config.severity.blast_radius_threshold, 5);
        assert_eq!(config.severity.impact_depth, 3);
        assert!(matches!(config.llm.provider, LlmBackend::Ollama));
        assert_eq!(config.llm.max_concurrent_deepening, 4);
        assert_eq!(config.storage.db_path, ".cartomancer.db");
    }

    #[test]
    fn deserialize_toml_with_defaults() {
        let toml_str = "[opengrep]\nrules = [\"auto\"]\n";
        let config: AppConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.severity.blast_radius_threshold, 5);
        assert!(matches!(config.llm.provider, LlmBackend::Ollama));
    }

    #[test]
    fn deserialize_opengrep_taint_and_ignore() {
        let toml_str = r#"
[opengrep]
taint_intrafile = true
ignore_pattern = "nosec"
"#;
        let config: AppConfig = toml::from_str(toml_str).unwrap();
        assert!(config.opengrep.taint_intrafile);
        assert_eq!(config.opengrep.ignore_pattern.as_deref(), Some("nosec"));
    }

    #[test]
    fn deserialize_opengrep_enclosing_context() {
        let toml_str = r#"
[opengrep]
enclosing_context = true
"#;
        let config: AppConfig = toml::from_str(toml_str).unwrap();
        assert!(config.opengrep.enclosing_context);
    }

    #[test]
    fn deserialize_opengrep_dynamic_timeout() {
        let toml_str = r#"
[opengrep]
dynamic_timeout = true
dynamic_timeout_unit_kb = 10
dynamic_timeout_max_multiplier = 5.0
"#;
        let config: AppConfig = toml::from_str(toml_str).unwrap();
        assert!(config.opengrep.dynamic_timeout);
        assert_eq!(config.opengrep.dynamic_timeout_unit_kb, Some(10));
        assert_eq!(config.opengrep.dynamic_timeout_max_multiplier, Some(5.0));
    }

    #[test]
    fn deserialize_opengrep_exclude_and_jobs() {
        let toml_str = r#"
[opengrep]
rules = ["auto"]
exclude = [".github/", "config/database.yml"]
jobs = 4
"#;
        let config: AppConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(
            config.opengrep.exclude,
            vec![".github/", "config/database.yml"]
        );
        assert_eq!(config.opengrep.jobs, Some(4));
    }

    #[test]
    fn deserialize_llm_concurrency() {
        let toml_str = r#"
[llm]
provider = "ollama"
max_concurrent_deepening = 8
"#;
        let config: AppConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.llm.max_concurrent_deepening, 8);
    }

    #[test]
    fn llm_concurrency_defaults_to_4() {
        let toml_str = r#"
[llm]
provider = "ollama"
"#;
        let config: AppConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.llm.max_concurrent_deepening, 4);
    }

    #[test]
    fn storage_db_path_defaults() {
        let toml_str = "[opengrep]\nrules = [\"auto\"]\n";
        let config: AppConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.storage.db_path, ".cartomancer.db");
    }

    #[test]
    fn storage_db_path_overridable() {
        let toml_str = r#"
[storage]
db_path = "/tmp/custom.db"
"#;
        let config: AppConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.storage.db_path, "/tmp/custom.db");
    }

    mod validate {
        use super::*;

        #[test]
        fn default_config_is_valid() {
            let config = AppConfig::default();
            assert!(config.validate().is_ok());
        }

        #[test]
        fn empty_rules_rejected() {
            let mut config = AppConfig::default();
            config.opengrep.rules = vec![];
            let err = config.validate().unwrap_err();
            assert!(err.contains("rules must not be empty"), "got: {err}");
        }

        #[test]
        fn zero_timeout_rejected() {
            let mut config = AppConfig::default();
            config.opengrep.timeout_seconds = 0;
            let err = config.validate().unwrap_err();
            assert!(err.contains("timeout_seconds must be > 0"), "got: {err}");
        }

        #[test]
        fn zero_blast_threshold_rejected() {
            let mut config = AppConfig::default();
            config.severity.blast_radius_threshold = 0;
            let err = config.validate().unwrap_err();
            assert!(
                err.contains("blast_radius_threshold must be > 0"),
                "got: {err}"
            );
        }

        #[test]
        fn impact_depth_out_of_range_rejected() {
            let mut config = AppConfig::default();
            config.severity.impact_depth = 0;
            let err = config.validate().unwrap_err();
            assert!(
                err.contains("impact_depth must be between 1 and 20"),
                "got: {err}"
            );

            config.severity.impact_depth = 21;
            let err = config.validate().unwrap_err();
            assert!(
                err.contains("impact_depth must be between 1 and 20"),
                "got: {err}"
            );
        }

        #[test]
        fn zero_max_tokens_rejected() {
            let mut config = AppConfig::default();
            config.llm.max_tokens = 0;
            let err = config.validate().unwrap_err();
            assert!(err.contains("max_tokens must be > 0"), "got: {err}");
        }

        #[test]
        fn zero_concurrency_rejected() {
            let mut config = AppConfig::default();
            config.llm.max_concurrent_deepening = 0;
            let err = config.validate().unwrap_err();
            assert!(
                err.contains("max_concurrent_deepening must be > 0"),
                "got: {err}"
            );
        }

        #[test]
        fn negative_dynamic_timeout_multiplier_rejected() {
            let mut config = AppConfig::default();
            config.opengrep.dynamic_timeout_max_multiplier = Some(-1.0);
            let err = config.validate().unwrap_err();
            assert!(
                err.contains("dynamic_timeout_max_multiplier must be > 0.0"),
                "got: {err}"
            );
        }

        #[test]
        fn anthropic_without_key_rejected() {
            let mut config = AppConfig::default();
            config.llm.provider = LlmBackend::Anthropic;
            config.llm.anthropic_api_key = None;
            // Clear env var for this test
            std::env::remove_var("ANTHROPIC_API_KEY");
            let err = config.validate().unwrap_err();
            assert!(err.contains("anthropic_api_key required"), "got: {err}");
        }

        #[test]
        fn zero_max_concurrent_reviews_rejected() {
            let mut config = AppConfig::default();
            config.serve.max_concurrent_reviews = 0;
            let err = config.validate().unwrap_err();
            assert!(
                err.contains("max_concurrent_reviews must be > 0"),
                "got: {err}"
            );
        }

        #[test]
        fn multiple_errors_collected() {
            let mut config = AppConfig::default();
            config.opengrep.rules = vec![];
            config.opengrep.timeout_seconds = 0;
            config.severity.blast_radius_threshold = 0;
            let err = config.validate().unwrap_err();
            // Should contain all three errors
            assert!(err.contains("rules must not be empty"), "got: {err}");
            assert!(err.contains("timeout_seconds must be > 0"), "got: {err}");
            assert!(
                err.contains("blast_radius_threshold must be > 0"),
                "got: {err}"
            );
        }
    }
}
