//! Doctor command — verify that all dependencies and configuration are healthy.

use std::time::Duration;

use anyhow::Result;
use serde::Serialize;

use cartomancer_core::config::AppConfig;

/// Result of a single doctor check.
#[derive(Serialize)]
pub struct CheckResult {
    pub name: &'static str,
    pub status: CheckStatus,
    pub message: String,
}

/// Outcome of a single doctor check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckStatus {
    /// Check passed.
    Ok,
    /// Non-blocking issue (e.g. optional dependency missing).
    Warn,
    /// Blocking failure — the tool cannot operate correctly.
    Error,
}

impl CheckStatus {
    fn icon(self) -> &'static str {
        match self {
            CheckStatus::Ok => "+",
            CheckStatus::Warn => "!",
            CheckStatus::Error => "x",
        }
    }
}

/// Structured doctor report with summary counts.
#[derive(Serialize)]
pub struct DoctorReport {
    pub checks: Vec<CheckResult>,
    pub summary: DoctorSummary,
}

#[derive(Serialize)]
pub struct DoctorSummary {
    pub total: usize,
    pub ok: usize,
    pub warn: usize,
    pub error: usize,
}

impl CheckResult {
    fn ok(name: &'static str, message: impl Into<String>) -> Self {
        Self {
            name,
            status: CheckStatus::Ok,
            message: message.into(),
        }
    }

    fn warn(name: &'static str, message: impl Into<String>) -> Self {
        Self {
            name,
            status: CheckStatus::Warn,
            message: message.into(),
        }
    }

    fn fail(name: &'static str, message: impl Into<String>) -> Self {
        Self {
            name,
            status: CheckStatus::Error,
            message: message.into(),
        }
    }
}

/// Run all doctor checks and return a structured report.
pub async fn run_checks(config: &AppConfig) -> DoctorReport {
    let checks = vec![
        check_config(config),
        check_git(),
        check_opengrep().await,
        check_custom_rules(config),
        check_knowledge(config),
        check_cartog(),
        check_cartog_db(config),
        check_github_token(config),
        check_llm_provider(config).await,
        check_storage(config),
    ];

    build_report(checks)
}

fn build_report(checks: Vec<CheckResult>) -> DoctorReport {
    let ok = checks
        .iter()
        .filter(|c| c.status == CheckStatus::Ok)
        .count();
    let warn = checks
        .iter()
        .filter(|c| c.status == CheckStatus::Warn)
        .count();
    let error = checks
        .iter()
        .filter(|c| c.status == CheckStatus::Error)
        .count();

    DoctorReport {
        summary: DoctorSummary {
            total: checks.len(),
            ok,
            warn,
            error,
        },
        checks,
    }
}

/// Print report as a text checklist.
pub fn print_text(report: &DoctorReport) {
    println!("Cartomancer Doctor\n");
    for check in &report.checks {
        println!(
            "  [{}] {}: {}",
            check.status.icon(),
            check.name,
            check.message
        );
    }

    println!();
    let s = &report.summary;
    if s.error > 0 {
        println!(
            "{} checks passed, {} warnings, {} errors",
            s.ok, s.warn, s.error
        );
    } else if s.warn > 0 {
        println!("{} checks passed, {} warnings", s.ok, s.warn);
    } else {
        println!("All {} checks passed", s.ok);
    }
}

/// Print report as JSON.
pub fn print_json(report: &DoctorReport) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(report)?);
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

/// Check that `git` is in PATH — required for cloning and `review --work-dir` flows.
fn check_git() -> CheckResult {
    match std::process::Command::new("git").arg("--version").output() {
        Ok(output) if output.status.success() => {
            let version = String::from_utf8_lossy(&output.stdout);
            CheckResult::ok("git", version.trim().to_string())
        }
        Ok(output) => CheckResult::fail(
            "git",
            format!("exited with code {}", output.status.code().unwrap_or(-1)),
        ),
        Err(_) => CheckResult::fail(
            "git",
            "not found in PATH (required for `review` and `serve`)",
        ),
    }
}

/// Check that the configured cartog database exists — warns if missing, because
/// graph enrichment is optional but strongly recommended.
fn check_cartog_db(config: &AppConfig) -> CheckResult {
    let path = std::path::Path::new(&config.severity.cartog_db_path);
    if path.exists() {
        CheckResult::ok("cartog-db", format!("found at {}", path.display()))
    } else {
        CheckResult::warn(
            "cartog-db",
            format!(
                "{} not found — graph enrichment will be skipped (run `cartog index .`)",
                path.display()
            ),
        )
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
    fn check_status_icon_mapping() {
        assert_eq!(CheckStatus::Ok.icon(), "+");
        assert_eq!(CheckStatus::Warn.icon(), "!");
        assert_eq!(CheckStatus::Error.icon(), "x");
    }

    #[test]
    fn check_result_status() {
        assert_eq!(CheckResult::ok("t", "").status, CheckStatus::Ok);
        assert_eq!(CheckResult::warn("t", "").status, CheckStatus::Warn);
        assert_eq!(CheckResult::fail("t", "").status, CheckStatus::Error);
    }

    #[test]
    fn check_config_valid_default() {
        let config = AppConfig::default();
        let result = check_config(&config);
        assert_eq!(result.status, CheckStatus::Ok);
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

        assert_eq!(result.status, CheckStatus::Warn);
        assert!(result.message.contains("not set"));
    }

    #[test]
    fn check_github_token_from_config() {
        let mut config = AppConfig::default();
        config.github.token = Some("ghp_test".into());
        let result = check_github_token(&config);
        assert_eq!(result.status, CheckStatus::Ok);
    }

    #[test]
    fn check_storage_memory() {
        let mut config = AppConfig::default();
        config.storage.db_path = ":memory:".into();
        let result = check_storage(&config);
        assert_eq!(result.status, CheckStatus::Ok);
    }

    #[test]
    fn check_storage_bad_path() {
        let tmp = tempfile::tempdir().unwrap();
        let mut config = AppConfig::default();
        config.storage.db_path = tmp.path().to_string_lossy().into_owned();
        let result = check_storage(&config);
        drop(tmp);
        assert_eq!(result.status, CheckStatus::Error);
    }

    #[test]
    fn build_report_summary_counts() {
        let checks = vec![
            CheckResult::ok("a", "ok"),
            CheckResult::warn("b", "warning"),
            CheckResult::fail("c", "error"),
        ];
        let report = build_report(checks);
        assert_eq!(report.summary.total, 3);
        assert_eq!(report.summary.ok, 1);
        assert_eq!(report.summary.warn, 1);
        assert_eq!(report.summary.error, 1);
    }

    #[test]
    fn check_git_finds_binary() {
        // CI runners and dev machines are expected to have git in PATH.
        let result = check_git();
        assert_eq!(result.status, CheckStatus::Ok, "msg: {}", result.message);
        assert!(result.message.contains("git version"));
    }

    #[test]
    fn check_cartog_db_missing_warns() {
        let mut config = AppConfig::default();
        config.severity.cartog_db_path = "/nonexistent/path/.cartog.db".into();
        let result = check_cartog_db(&config);
        assert_eq!(result.status, CheckStatus::Warn);
        assert!(result.message.contains("not found"));
    }

    #[test]
    fn check_cartog_db_present_ok() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let mut config = AppConfig::default();
        config.severity.cartog_db_path = tmp.path().to_string_lossy().into_owned();
        let result = check_cartog_db(&config);
        assert_eq!(result.status, CheckStatus::Ok);
    }

    #[test]
    fn print_json_serializes_report() {
        let report = build_report(vec![
            CheckResult::ok("a", "fine"),
            CheckResult::warn("b", "missing"),
        ]);
        // print_json writes to stdout; assert the structured shape instead.
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"checks\""));
        assert!(json.contains("\"summary\""));
        assert!(json.contains("\"name\":\"a\""));
        assert!(json.contains("\"status\":\"ok\""));
        assert!(json.contains("\"status\":\"warn\""));
        assert!(json.contains("\"total\":2"));
        // Smoke: the public function does not panic.
        print_json(&report).unwrap();
    }

    #[test]
    fn print_text_does_not_panic_across_branches() {
        // All-ok
        print_text(&build_report(vec![CheckResult::ok("a", "fine")]));
        // With warnings
        print_text(&build_report(vec![
            CheckResult::ok("a", "fine"),
            CheckResult::warn("b", "missing"),
        ]));
        // With errors
        print_text(&build_report(vec![
            CheckResult::ok("a", "fine"),
            CheckResult::warn("b", "missing"),
            CheckResult::fail("c", "broken"),
        ]));
    }

    #[test]
    fn check_cartog_db_empty_path_warns() {
        let mut config = AppConfig::default();
        config.severity.cartog_db_path = String::new();
        let result = check_cartog_db(&config);
        assert_eq!(result.status, CheckStatus::Warn);
    }

    #[test]
    fn check_status_serializes_lowercase() {
        assert_eq!(serde_json::to_string(&CheckStatus::Ok).unwrap(), "\"ok\"");
        assert_eq!(
            serde_json::to_string(&CheckStatus::Warn).unwrap(),
            "\"warn\""
        );
        assert_eq!(
            serde_json::to_string(&CheckStatus::Error).unwrap(),
            "\"error\""
        );
    }
}
