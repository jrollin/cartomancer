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

    info!(
        path = %path.display(),
        provider = ?config.llm.provider,
        semgrep_rules = ?config.semgrep.rules,
        blast_threshold = config.severity.blast_radius_threshold,
        "configuration loaded"
    );

    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn missing_file_returns_defaults() {
        let config = load_config("/nonexistent/path/to/.cartomancer.toml").unwrap();
        assert_eq!(config.semgrep.rules, vec!["auto"]);
        assert_eq!(config.semgrep.timeout_seconds, 120);
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
            "[semgrep]\nrules = [\"p/security\"]\ntimeout_seconds = 60\n\n[severity]\nblast_radius_threshold = 10\n"
        )
        .unwrap();
        let config = load_config(tmp.path().to_str().unwrap()).unwrap();
        assert_eq!(config.semgrep.rules, vec!["p/security"]);
        assert_eq!(config.semgrep.timeout_seconds, 60);
        assert_eq!(config.severity.blast_radius_threshold, 10);
        // Defaults for fields not in the file
        assert_eq!(config.severity.impact_depth, 3);
        assert!(matches!(
            config.llm.provider,
            cartomancer_core::config::LlmBackend::Ollama
        ));
    }
}
