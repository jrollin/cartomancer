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
