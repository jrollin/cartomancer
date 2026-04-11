//! Configuration loading from `.cartomancer.toml`.

use std::path::Path;

use anyhow::Result;
use tracing::info;

use cartomancer_core::config::AppConfig;

/// Load configuration from the given TOML path.
/// Falls back to defaults if the file does not exist.
pub fn load_config(path: &str) -> Result<AppConfig> {
    let path = Path::new(path);
    if !path.exists() {
        info!(path = %path.display(), "no config file found, using defaults");
        return Ok(AppConfig::default());
    }

    let content = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", path.display()))?;

    let config: AppConfig = toml::from_str(&content).map_err(|e| {
        anyhow::anyhow!(
            "invalid TOML in {}: {} (hint: check indentation and field names)",
            path.display(),
            e
        )
    })?;

    config
        .validate()
        .map_err(|e| anyhow::anyhow!("config validation failed: {e}"))?;

    info!(
        path = %path.display(),
        provider = ?config.llm.provider,
        opengrep_rules = ?config.opengrep.rules,
        blast_threshold = config.severity.blast_radius_threshold,
        "configuration loaded"
    );

    Ok(config)
}

/// Returns true if the value is a non-empty, non-whitespace string.
fn is_non_empty(s: &str) -> bool {
    !s.trim().is_empty()
}

/// Validate serve-specific requirements (webhook secret and GitHub token).
pub fn validate_for_serve(config: &AppConfig) -> Result<()> {
    let has_secret = config
        .github
        .webhook_secret
        .as_deref()
        .map(is_non_empty)
        .unwrap_or(false)
        || std::env::var("CARTOMANCER_WEBHOOK_SECRET")
            .map(|v| is_non_empty(&v))
            .unwrap_or(false);
    if !has_secret {
        anyhow::bail!(
            "serve requires a webhook secret: set github.webhook_secret in config \
             or CARTOMANCER_WEBHOOK_SECRET env var"
        );
    }

    let has_token = config
        .github
        .token
        .as_deref()
        .map(is_non_empty)
        .unwrap_or(false)
        || std::env::var("GITHUB_TOKEN")
            .map(|v| is_non_empty(&v))
            .unwrap_or(false);
    if !has_token {
        anyhow::bail!(
            "serve requires a GitHub token: set github.token in config \
             or GITHUB_TOKEN env var"
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn missing_file_returns_defaults() {
        let config = load_config("/nonexistent/path/to/.cartomancer.toml").unwrap();
        assert_eq!(config.opengrep.rules, vec!["auto"]);
        assert_eq!(config.opengrep.timeout_seconds, 120);
        assert_eq!(config.severity.blast_radius_threshold, 5);
        assert_eq!(config.severity.impact_depth, 3);
    }

    #[test]
    fn invalid_toml_returns_error() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        write!(tmp, "this is not [[[valid toml").unwrap();
        let result = load_config(tmp.path().to_str().unwrap());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("invalid TOML"), "error was: {err}");
    }

    #[test]
    fn valid_toml_parses_correctly() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        write!(
            tmp,
            "[opengrep]\nrules = [\"p/security\"]\ntimeout_seconds = 60\n\n[severity]\nblast_radius_threshold = 10\n"
        )
        .unwrap();
        let config = load_config(tmp.path().to_str().unwrap()).unwrap();
        assert_eq!(config.opengrep.rules, vec!["p/security"]);
        assert_eq!(config.opengrep.timeout_seconds, 60);
        assert_eq!(config.severity.blast_radius_threshold, 10);
        // Defaults for fields not in the file
        assert_eq!(config.severity.impact_depth, 3);
        assert!(matches!(
            config.llm.provider,
            cartomancer_core::config::LlmBackend::Ollama
        ));
    }

    #[test]
    fn invalid_config_values_rejected() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        write!(tmp, "[opengrep]\nrules = []\ntimeout_seconds = 0\n").unwrap();
        let result = load_config(tmp.path().to_str().unwrap());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("config validation failed"), "got: {err}");
    }

    #[test]
    fn validate_for_serve_missing_secret() {
        std::env::remove_var("CARTOMANCER_WEBHOOK_SECRET");
        std::env::remove_var("GITHUB_TOKEN");
        let config = AppConfig::default();
        let result = validate_for_serve(&config);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("webhook secret"), "got: {err}");
    }

    #[test]
    fn validate_for_serve_missing_token() {
        std::env::remove_var("GITHUB_TOKEN");
        let mut config = AppConfig::default();
        config.github.webhook_secret = Some("test-secret".into());
        let result = validate_for_serve(&config);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("GitHub token"), "got: {err}");
    }

    #[test]
    fn validate_for_serve_all_present() {
        let mut config = AppConfig::default();
        config.github.webhook_secret = Some("test-secret".into());
        config.github.token = Some("ghp_test".into());
        let result = validate_for_serve(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn validate_for_serve_empty_secret_rejected() {
        std::env::remove_var("CARTOMANCER_WEBHOOK_SECRET");
        let mut config = AppConfig::default();
        config.github.webhook_secret = Some("".into());
        config.github.token = Some("ghp_test".into());
        let result = validate_for_serve(&config);
        assert!(result.is_err());
    }

    #[test]
    fn validate_for_serve_whitespace_token_rejected() {
        std::env::remove_var("GITHUB_TOKEN");
        let mut config = AppConfig::default();
        config.github.webhook_secret = Some("secret".into());
        config.github.token = Some("   ".into());
        let result = validate_for_serve(&config);
        assert!(result.is_err());
    }
}
