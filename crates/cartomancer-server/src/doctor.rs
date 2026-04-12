//! Doctor command — verify that all dependencies and configuration are healthy.

use std::fmt;
use std::time::Duration;

use anyhow::Result;

use cartomancer_core::config::AppConfig;

/// Result of a single doctor check.
pub struct CheckResult {
    pub name: &'static str,
    pub status: CheckStatus,
    pub detail: String,
}

/// Outcome of a single doctor check.
pub enum CheckStatus {
    /// Check passed.
    Ok,
    /// Non-blocking issue (e.g. optional dependency missing).
    Warn,
    /// Blocking failure — the tool cannot operate correctly.
    Fail,
}

impl fmt::Display for CheckStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CheckStatus::Ok => write!(f, "ok"),
            CheckStatus::Warn => write!(f, "warn"),
            CheckStatus::Fail => write!(f, "FAIL"),
        }
    }
}

impl CheckResult {
    /// Build a passing check result.
    fn ok(name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            name,
            status: CheckStatus::Ok,
            detail: detail.into(),
        }
    }

    /// Build a warning check result (non-blocking).
    fn warn(name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            name,
            status: CheckStatus::Warn,
            detail: detail.into(),
        }
    }

    /// Build a failing check result (blocks operation).
    fn fail(name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            name,
            status: CheckStatus::Fail,
            detail: detail.into(),
        }
    }

    /// Text icon for checklist display: `[+]`, `[~]`, or `[-]`.
    fn icon(&self) -> &'static str {
        match self.status {
            CheckStatus::Ok => "[+]",
            CheckStatus::Warn => "[~]",
            CheckStatus::Fail => "[-]",
        }
    }

    /// Returns `true` when the check status is `Fail`.
    pub fn is_fail(&self) -> bool {
        matches!(self.status, CheckStatus::Fail)
    }
}

/// Run all doctor checks and return the results.
pub async fn run_checks(config: &AppConfig) -> Vec<CheckResult> {
    let mut results = Vec::new();

    results.push(check_config(config));
    results.push(check_opengrep().await);
    results.push(check_custom_rules(config));
    results.push(check_knowledge(config));
    results.push(check_cartog());
    results.push(check_github_token(config));
    results.push(check_llm_provider(config).await);
    results.push(check_storage(config));

    results
}

/// Print results as a text checklist.
pub fn print_text(results: &[CheckResult]) {
    println!("Cartomancer Doctor\n");
    for r in results {
        println!("  {} {:<20} {}", r.icon(), r.name, r.detail);
    }

    let failures = results.iter().filter(|r| r.is_fail()).count();
    let warnings = results
        .iter()
        .filter(|r| matches!(r.status, CheckStatus::Warn))
        .count();

    println!();
    if failures > 0 {
        println!(
            "{} check(s) failed, {} warning(s). Fix the failures above before running.",
            failures, warnings
        );
    } else if warnings > 0 {
        println!("All checks passed with {} warning(s).", warnings);
    } else {
        println!("All checks passed.");
    }
}

/// Print results as JSON.
pub fn print_json(results: &[CheckResult]) -> Result<()> {
    let items: Vec<serde_json::Value> = results
        .iter()
        .map(|r| {
            serde_json::json!({
                "name": r.name,
                "status": r.status.to_string(),
                "detail": r.detail,
            })
        })
        .collect();

    let has_failure = results.iter().any(|r| r.is_fail());
    let output = serde_json::json!({
        "checks": items,
        "ok": !has_failure,
    });
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

// --- Individual checks ---

/// Check custom rules directory (if configured).
fn check_custom_rules(config: &AppConfig) -> CheckResult {
    let Some(ref rules_dir) = config.opengrep.rules_dir else {
        return CheckResult::ok("custom-rules", "disabled (rules_dir not set)");
    };
    if rules_dir.is_empty() {
        return CheckResult::ok("custom-rules", "disabled (rules_dir is empty)");
    }

    // Use current directory as base for path validation
    let base = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    match crate::path_security::validate_path_within(&base, rules_dir) {
        Err(e) => CheckResult::fail("custom-rules", format!("path rejected: {e}")),
        Ok(validated) => {
            if !validated.is_dir() {
                return CheckResult::ok(
                    "custom-rules",
                    format!("{rules_dir} not found (default rules only)"),
                );
            }

            let yaml_count = std::fs::read_dir(&validated)
                .map(|entries| {
                    entries
                        .filter_map(|e| e.ok())
                        .filter(|e| {
                            e.path()
                                .extension()
                                .map(|ext| ext == "yaml" || ext == "yml")
                                .unwrap_or(false)
                        })
                        .count()
                })
                .unwrap_or(0);

            if yaml_count == 0 {
                CheckResult::warn(
                    "custom-rules",
                    format!("{rules_dir} exists but contains no .yaml/.yml files"),
                )
            } else {
                CheckResult::ok(
                    "custom-rules",
                    format!("{yaml_count} rule file(s) in {rules_dir}"),
                )
            }
        }
    }
}

/// Check knowledge file for LLM deepening (if configured).
fn check_knowledge(config: &AppConfig) -> CheckResult {
    let Some(ref knowledge_file) = config.knowledge.knowledge_file else {
        return CheckResult::ok("knowledge", "disabled (no knowledge_file)");
    };
    if knowledge_file.is_empty() {
        return CheckResult::ok("knowledge", "disabled (knowledge_file is empty)");
    }

    let base = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    match crate::path_security::validate_path_within(&base, knowledge_file) {
        Err(e) => CheckResult::fail("knowledge", format!("path rejected: {e}")),
        Ok(validated) => {
            if !validated.exists() {
                return CheckResult::ok(
                    "knowledge",
                    format!("{knowledge_file} not found (default prompts only)"),
                );
            }

            match std::fs::metadata(&validated) {
                Ok(meta) => {
                    let size = meta.len() as usize;
                    let max = config.knowledge.max_knowledge_chars;
                    if size > max {
                        CheckResult::warn(
                            "knowledge",
                            format!(
                                "{knowledge_file} ({size} bytes) exceeds max_knowledge_chars ({max}), will be truncated"
                            ),
                        )
                    } else {
                        CheckResult::ok("knowledge", format!("{knowledge_file} ({size} bytes)"))
                    }
                }
                Err(e) => {
                    CheckResult::warn("knowledge", format!("cannot read {knowledge_file}: {e}"))
                }
            }
        }
    }
}

/// Validate the loaded configuration via `AppConfig::validate()`.
fn check_config(config: &AppConfig) -> CheckResult {
    match config.validate() {
        Ok(()) => CheckResult::ok("config", "valid"),
        Err(e) => CheckResult::fail("config", e),
    }
}

/// Check that a GitHub token is available (config or `GITHUB_TOKEN` env).
fn check_github_token(config: &AppConfig) -> CheckResult {
    let has_token = config
        .github
        .token
        .as_deref()
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false)
        || std::env::var("GITHUB_TOKEN")
            .map(|v| !v.trim().is_empty())
            .unwrap_or(false);

    if has_token {
        CheckResult::ok("github-token", "found")
    } else {
        CheckResult::warn(
            "github-token",
            "not set (set GITHUB_TOKEN or github.token in config for review/serve)",
        )
    }
}

/// Verify that `opengrep` is in PATH and responds to `--version` within 10s.
async fn check_opengrep() -> CheckResult {
    let fut = tokio::process::Command::new("opengrep")
        .arg("--version")
        .output();

    let output = match tokio::time::timeout(Duration::from_secs(10), fut).await {
        Ok(result) => result,
        Err(_) => {
            return CheckResult::fail("opengrep", "timed out waiting for opengrep --version");
        }
    };

    match output {
        Ok(output) if output.status.success() => {
            let version = String::from_utf8_lossy(&output.stdout);
            let version = version.trim();
            // Some tools print version to stderr
            let version = if version.is_empty() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                stderr.trim().to_string()
            } else {
                version.to_string()
            };
            let label = if version.is_empty() {
                "found".to_string()
            } else {
                version.lines().next().unwrap_or("found").to_string()
            };
            CheckResult::ok("opengrep", label)
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            CheckResult::fail(
                "opengrep",
                format!(
                    "exited with code {} — {}",
                    output.status.code().unwrap_or(-1),
                    stderr.trim()
                ),
            )
        }
        Err(_) => CheckResult::fail(
            "opengrep",
            "not found in PATH (install: https://github.com/opengrep/opengrep)",
        ),
    }
}

/// Check whether `cartog` CLI is available (optional — warns if missing).
fn check_cartog() -> CheckResult {
    match std::process::Command::new("cartog")
        .arg("--version")
        .output()
    {
        Ok(output) if output.status.success() => {
            let version = String::from_utf8_lossy(&output.stdout);
            let version = version.trim();
            let label = if version.is_empty() {
                "found".to_string()
            } else {
                version.lines().next().unwrap_or("found").to_string()
            };
            CheckResult::ok(
                "cartog",
                format!("{label} (run `cartog index .` to build the code graph)"),
            )
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            let detail = if !stderr.trim().is_empty() {
                stderr.trim().to_string()
            } else {
                stdout.trim().to_string()
            };
            CheckResult::warn(
                "cartog",
                format!(
                    "exited with code {} — {}",
                    output.status.code().unwrap_or(-1),
                    detail
                ),
            )
        }
        Err(e) => CheckResult::warn(
            "cartog",
            format!(
                "not found in PATH ({}) — graph enrichment will be skipped (install: cargo install cartog)",
                e.kind()
            ),
        ),
    }
}

/// Create the configured LLM provider and run its health check.
async fn check_llm_provider(config: &AppConfig) -> CheckResult {
    let provider_name = format!("{:?}", config.llm.provider).to_lowercase();
    match crate::llm::create_provider(&config.llm, config.knowledge.system_prompt.as_deref()) {
        Ok(provider) => match provider.health_check().await {
            Ok(()) => CheckResult::ok("llm-provider", format!("{} reachable", provider_name)),
            Err(e) => CheckResult::warn(
                "llm-provider",
                format!("{} unreachable — {}", provider_name, e),
            ),
        },
        Err(e) => CheckResult::warn(
            "llm-provider",
            format!("{} not configured — {}", provider_name, e),
        ),
    }
}

/// Verify that the SQLite store can be opened at the configured `db_path`.
fn check_storage(config: &AppConfig) -> CheckResult {
    match cartomancer_store::store::Store::open(&config.storage.db_path) {
        Ok(_) => CheckResult::ok("storage", config.storage.db_path.to_string()),
        Err(e) => CheckResult::fail(
            "storage",
            format!("cannot open {}: {}", config.storage.db_path, e),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_result_icon_mapping() {
        assert_eq!(CheckResult::ok("t", "").icon(), "[+]");
        assert_eq!(CheckResult::warn("t", "").icon(), "[~]");
        assert_eq!(CheckResult::fail("t", "").icon(), "[-]");
    }

    #[test]
    fn check_result_is_fail() {
        assert!(!CheckResult::ok("t", "").is_fail());
        assert!(!CheckResult::warn("t", "").is_fail());
        assert!(CheckResult::fail("t", "").is_fail());
    }

    #[test]
    fn check_config_valid_default() {
        let config = AppConfig::default();
        let result = check_config(&config);
        assert!(matches!(result.status, CheckStatus::Ok));
    }

    #[test]
    fn check_github_token_missing() {
        let saved = std::env::var_os("GITHUB_TOKEN");
        std::env::remove_var("GITHUB_TOKEN");

        let config = AppConfig::default();
        let result = check_github_token(&config);

        // Restore before asserting so panics don't leave env dirty
        match saved {
            Some(val) => std::env::set_var("GITHUB_TOKEN", val),
            None => std::env::remove_var("GITHUB_TOKEN"),
        }

        assert!(matches!(result.status, CheckStatus::Warn));
        assert!(result.detail.contains("not set"));
    }

    #[test]
    fn check_github_token_from_config() {
        let mut config = AppConfig::default();
        config.github.token = Some("ghp_test".into());
        let result = check_github_token(&config);
        assert!(matches!(result.status, CheckStatus::Ok));
    }

    #[test]
    fn check_storage_memory() {
        let mut config = AppConfig::default();
        config.storage.db_path = ":memory:".into();
        let result = check_storage(&config);
        assert!(matches!(result.status, CheckStatus::Ok));
    }

    #[test]
    fn check_storage_bad_path() {
        let tmp = tempfile::tempdir().unwrap();
        let mut config = AppConfig::default();
        // Point db_path at the directory itself — SQLite cannot open a directory
        config.storage.db_path = tmp.path().to_string_lossy().into_owned();
        let result = check_storage(&config);
        // Keep tmp alive until after the assertion
        drop(tmp);
        assert!(matches!(result.status, CheckStatus::Fail));
    }

    #[test]
    fn check_status_display() {
        assert_eq!(format!("{}", CheckStatus::Ok), "ok");
        assert_eq!(format!("{}", CheckStatus::Warn), "warn");
        assert_eq!(format!("{}", CheckStatus::Fail), "FAIL");
    }
}
