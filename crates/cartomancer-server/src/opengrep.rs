//! Opengrep subprocess runner and JSON output parser.

use std::time::Duration;

use anyhow::{Context, Result};
use tokio::process::Command;
use tracing::{debug, info, warn};

use cartomancer_core::config::OpengrepConfig;
use cartomancer_core::finding::Finding;
use cartomancer_core::severity::Severity;

/// Opengrep JSON output structure.
#[derive(serde::Deserialize)]
struct OpengrepOutput {
    results: Vec<OpengrepResult>,
    #[serde(default)]
    errors: Vec<OpengrepError>,
}

#[derive(serde::Deserialize)]
struct OpengrepResult {
    check_id: String,
    path: String,
    start: Position,
    end: Position,
    extra: Extra,
}

#[derive(serde::Deserialize)]
struct Position {
    line: u32,
    #[allow(dead_code)]
    col: u32,
}

#[derive(serde::Deserialize)]
struct Extra {
    message: String,
    severity: String,
    #[serde(default)]
    lines: String,
    #[serde(default)]
    metadata: Metadata,
    #[serde(default)]
    enclosing_context: Option<String>,
}

#[derive(serde::Deserialize, Default)]
struct Metadata {
    #[allow(dead_code)]
    confidence: Option<String>,
    cwe: Option<Vec<String>>,
}

#[derive(serde::Deserialize)]
struct OpengrepError {
    message: String,
}

/// Build the opengrep `Command` with all flags.
///
/// Extracted for testability — the returned command is ready to spawn.
fn build_command(
    target_dir: &str,
    config: &OpengrepConfig,
    baseline_commit: Option<&str>,
) -> Command {
    let mut cmd = Command::new("opengrep");
    cmd.arg("scan").arg("--json").arg("--quiet");

    if config.dynamic_timeout {
        cmd.arg("--dynamic-timeout");
        if let Some(unit_kb) = config.dynamic_timeout_unit_kb {
            cmd.arg("--dynamic-timeout-unit-kb")
                .arg(unit_kb.to_string());
        }
        if let Some(max_mult) = config.dynamic_timeout_max_multiplier {
            cmd.arg("--dynamic-timeout-max-multiplier")
                .arg(max_mult.to_string());
        }
    } else {
        cmd.arg("--timeout").arg(config.timeout_seconds.to_string());
    }

    cmd.current_dir(target_dir);

    for rule in &config.rules {
        cmd.arg("--config").arg(rule);
    }

    for pattern in &config.exclude {
        cmd.arg("--exclude").arg(pattern);
    }

    if let Some(jobs) = config.jobs {
        cmd.arg("-j").arg(jobs.to_string());
    }

    if config.taint_intrafile {
        cmd.arg("--taint-intrafile");
    }

    if let Some(ref pattern) = config.ignore_pattern {
        cmd.arg(format!("--opengrep-ignore-pattern={pattern}"));
    }

    if config.enclosing_context {
        cmd.arg("--experimental").arg("--output-enclosing-context");
    }

    if let Some(sha) = baseline_commit {
        cmd.arg("--baseline-commit").arg(sha);
    }

    cmd
}

/// Format the command for debug logging.
fn format_command_display(config: &OpengrepConfig, baseline_commit: Option<&str>) -> String {
    let mut parts = vec!["opengrep scan --json --quiet".to_string()];

    if config.dynamic_timeout {
        parts.push("--dynamic-timeout".to_string());
        if let Some(unit_kb) = config.dynamic_timeout_unit_kb {
            parts.push(format!("--dynamic-timeout-unit-kb {unit_kb}"));
        }
        if let Some(max_mult) = config.dynamic_timeout_max_multiplier {
            parts.push(format!("--dynamic-timeout-max-multiplier {max_mult}"));
        }
    } else {
        parts.push(format!("--timeout {}", config.timeout_seconds));
    }

    for r in &config.rules {
        parts.push(format!("--config {r}"));
    }
    for e in &config.exclude {
        parts.push(format!("--exclude {e}"));
    }
    if let Some(jobs) = config.jobs {
        parts.push(format!("-j {jobs}"));
    }
    if config.taint_intrafile {
        parts.push("--taint-intrafile".to_string());
    }
    if let Some(ref pattern) = config.ignore_pattern {
        parts.push(format!("--opengrep-ignore-pattern={pattern}"));
    }
    if config.enclosing_context {
        parts.push("--experimental --output-enclosing-context".to_string());
    }
    if let Some(sha) = baseline_commit {
        parts.push(format!("--baseline-commit {sha}"));
    }
    parts.join(" ")
}

/// Run opengrep against the given directory and return parsed findings.
///
/// Uses `--baseline-commit` when provided to only report new findings.
/// Enforces a timeout on our side (kills the process if exceeded).
pub async fn run_opengrep(
    target_dir: &str,
    config: &OpengrepConfig,
    baseline_commit: Option<&str>,
) -> Result<Vec<Finding>> {
    let mut cmd = build_command(target_dir, config, baseline_commit);

    let cmd_display = format_command_display(config, baseline_commit);
    info!(cmd = %cmd_display, target_dir, "executing opengrep");

    let start = std::time::Instant::now();

    // Enforce timeout on our side — kill opengrep if it hangs
    let timeout_seconds = config.timeout_seconds;
    let timeout_duration = Duration::from_secs(timeout_seconds + 10); // grace period
    let output = tokio::time::timeout(timeout_duration, cmd.output())
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "opengrep timed out after {}s (limit: {}s + 10s grace)",
                timeout_duration.as_secs(),
                timeout_seconds
            )
        })?
        .context("failed to execute opengrep — is it installed and in PATH?")?;

    let elapsed = start.elapsed();

    // opengrep exits 0 = no findings, 1 = findings found, 2+ = error
    let exit_code = output.status.code().unwrap_or(-1);
    debug!(
        exit_code,
        elapsed_ms = elapsed.as_millis() as u64,
        "opengrep exited"
    );

    if exit_code > 1 && output.stdout.is_empty() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "opengrep failed (exit {}, {:.1}s): {}",
            exit_code,
            elapsed.as_secs_f64(),
            stderr.trim()
        );
    }

    if output.stdout.is_empty() {
        info!(
            elapsed_ms = elapsed.as_millis() as u64,
            "opengrep returned no findings"
        );
        return Ok(vec![]);
    }

    let findings = parse_output(&output.stdout, elapsed)?;
    Ok(findings)
}

/// Parse opengrep JSON output into domain findings.
/// On parse failure, logs a warning and returns an empty vec instead of crashing.
fn parse_output(output: &[u8], elapsed: Duration) -> Result<Vec<Finding>> {
    let parsed: OpengrepOutput = match serde_json::from_slice(output) {
        Ok(v) => v,
        Err(e) => {
            let preview = String::from_utf8_lossy(&output[..output.len().min(200)]);
            warn!(
                err = %e,
                output_bytes = output.len(),
                preview = %preview,
                "failed to parse opengrep JSON output, returning empty results"
            );
            return Ok(vec![]);
        }
    };

    for err in &parsed.errors {
        warn!(message = %err.message, "opengrep reported an error");
    }

    let findings: Vec<Finding> = parsed
        .results
        .into_iter()
        .map(|r| Finding {
            rule_id: r.check_id,
            message: r.extra.message,
            severity: map_severity(&r.extra.severity),
            file_path: r.path,
            start_line: r.start.line,
            end_line: r.end.line,
            snippet: r.extra.lines,
            cwe: r.extra.metadata.cwe.and_then(|v| v.into_iter().next()),
            graph_context: None,
            llm_analysis: None,
            escalation_reasons: vec![],
            is_new: None,
            enclosing_context: r.extra.enclosing_context,
            suggested_fix: None,
            agent_prompt: None,
        })
        .collect();

    info!(
        count = findings.len(),
        elapsed_ms = elapsed.as_millis() as u64,
        "opengrep scan complete"
    );
    Ok(findings)
}

fn map_severity(s: &str) -> Severity {
    s.parse().unwrap_or(Severity::Info)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_opengrep_severity() {
        assert_eq!(map_severity("ERROR"), Severity::Error);
        assert_eq!(map_severity("WARNING"), Severity::Warning);
        assert_eq!(map_severity("INFO"), Severity::Info);
    }

    #[test]
    fn parse_empty_results() {
        let json = br#"{"results":[],"errors":[]}"#;
        let findings = parse_output(json, Duration::from_secs(1)).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn parse_single_finding() {
        let json = br#"{
            "results": [{
                "check_id": "python.security.sql-injection",
                "path": "src/db.py",
                "start": {"line": 10, "col": 1, "offset": 0},
                "end": {"line": 10, "col": 50, "offset": 49},
                "extra": {
                    "message": "Possible SQL injection",
                    "severity": "ERROR",
                    "lines": "db.execute(f\"SELECT * WHERE id={user_id}\")",
                    "metadata": {
                        "cwe": ["CWE-89: SQL Injection"],
                        "confidence": "HIGH"
                    }
                }
            }],
            "errors": []
        }"#;
        let findings = parse_output(json, Duration::from_secs(1)).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "python.security.sql-injection");
        assert_eq!(findings[0].severity, Severity::Error);
        assert_eq!(findings[0].cwe.as_deref(), Some("CWE-89: SQL Injection"));
    }

    #[test]
    fn parse_bad_json_returns_empty() {
        let bad = b"this is not json at all {{{";
        let findings = parse_output(bad, Duration::from_secs(1)).unwrap();
        assert!(findings.is_empty());
    }

    fn config_with(exclude: Vec<String>, jobs: Option<u32>) -> OpengrepConfig {
        OpengrepConfig {
            rules: vec!["auto".into()],
            timeout_seconds: 60,
            exclude,
            jobs,
            ..OpengrepConfig::default()
        }
    }

    /// Helper: collect all positions of a flag in the args list.
    fn flag_positions(args: &[&std::ffi::OsStr], flag: &str) -> Vec<usize> {
        args.iter()
            .enumerate()
            .filter(|(_, a)| **a == std::ffi::OsStr::new(flag))
            .map(|(i, _)| i)
            .collect()
    }

    #[test]
    fn build_command_includes_exclude_flags() {
        let cfg = config_with(vec![".github/".into(), "config/database.yml".into()], None);
        let cmd = build_command("/tmp", &cfg, Some("abc123"));
        let args: Vec<_> = cmd.as_std().get_args().collect();
        let positions = flag_positions(&args, "--exclude");
        assert_eq!(positions.len(), 2);
        assert_eq!(args[positions[0] + 1], ".github/");
        assert_eq!(args[positions[1] + 1], "config/database.yml");
    }

    #[test]
    fn build_command_default_omits_exclude_and_jobs() {
        let cfg = OpengrepConfig::default();
        let cmd = build_command("/tmp", &cfg, None);
        let args: Vec<_> = cmd.as_std().get_args().collect();
        assert!(!args.contains(&std::ffi::OsStr::new("--exclude")));
        assert!(!args.contains(&std::ffi::OsStr::new("-j")));
    }

    #[test]
    fn build_command_includes_jobs_flag() {
        let cfg = config_with(vec![], Some(4));
        let cmd = build_command("/tmp", &cfg, None);
        let args: Vec<_> = cmd.as_std().get_args().collect();
        let positions = flag_positions(&args, "-j");
        assert_eq!(positions.len(), 1);
        assert_eq!(args[positions[0] + 1], "4");
    }

    #[test]
    fn format_command_display_full() {
        let cfg = config_with(vec![".github/".into()], Some(8));
        let display = format_command_display(&cfg, Some("abc"));
        assert_eq!(
            display,
            "opengrep scan --json --quiet --timeout 60 --config auto --exclude .github/ -j 8 --baseline-commit abc"
        );
    }

    #[test]
    fn format_command_display_minimal() {
        let cfg = OpengrepConfig::default();
        let display = format_command_display(&cfg, None);
        assert_eq!(
            display,
            "opengrep scan --json --quiet --timeout 120 --config auto"
        );
    }

    #[test]
    fn build_command_with_taint_intrafile() {
        let cfg = OpengrepConfig {
            taint_intrafile: true,
            ..config_with(vec![], None)
        };
        let cmd = build_command("/tmp", &cfg, None);
        let args: Vec<_> = cmd.as_std().get_args().collect();
        assert!(args.contains(&std::ffi::OsStr::new("--taint-intrafile")));
    }

    #[test]
    fn build_command_with_ignore_pattern() {
        let cfg = OpengrepConfig {
            ignore_pattern: Some("nosec".into()),
            ..config_with(vec![], None)
        };
        let cmd = build_command("/tmp", &cfg, None);
        let args: Vec<_> = cmd.as_std().get_args().collect();
        assert!(args.contains(&std::ffi::OsStr::new("--opengrep-ignore-pattern=nosec")));
    }

    #[test]
    fn build_command_with_enclosing_context() {
        let cfg = OpengrepConfig {
            enclosing_context: true,
            ..config_with(vec![], None)
        };
        let cmd = build_command("/tmp", &cfg, None);
        let args: Vec<_> = cmd.as_std().get_args().collect();
        assert!(args.contains(&std::ffi::OsStr::new("--experimental")));
        assert!(args.contains(&std::ffi::OsStr::new("--output-enclosing-context")));
    }

    #[test]
    fn build_command_with_dynamic_timeout() {
        let cfg = OpengrepConfig {
            dynamic_timeout: true,
            ..config_with(vec![], None)
        };
        let cmd = build_command("/tmp", &cfg, None);
        let args: Vec<_> = cmd.as_std().get_args().collect();
        assert!(args.contains(&std::ffi::OsStr::new("--dynamic-timeout")));
        assert!(!args.contains(&std::ffi::OsStr::new("--timeout")));
    }

    #[test]
    fn build_command_with_dynamic_timeout_all_options() {
        let cfg = OpengrepConfig {
            dynamic_timeout: true,
            dynamic_timeout_unit_kb: Some(10),
            dynamic_timeout_max_multiplier: Some(5.0),
            ..config_with(vec![], None)
        };
        let cmd = build_command("/tmp", &cfg, None);
        let args: Vec<_> = cmd.as_std().get_args().collect();
        assert!(args.contains(&std::ffi::OsStr::new("--dynamic-timeout")));
        assert!(args.contains(&std::ffi::OsStr::new("--dynamic-timeout-unit-kb")));
        assert!(args.contains(&std::ffi::OsStr::new("--dynamic-timeout-max-multiplier")));
    }

    #[test]
    fn build_command_default_omits_new_flags() {
        let cfg = OpengrepConfig::default();
        let cmd = build_command("/tmp", &cfg, None);
        let args: Vec<_> = cmd.as_std().get_args().collect();
        assert!(!args.contains(&std::ffi::OsStr::new("--taint-intrafile")));
        assert!(!args.contains(&std::ffi::OsStr::new("--experimental")));
        assert!(!args.contains(&std::ffi::OsStr::new("--dynamic-timeout")));
        assert!(args.contains(&std::ffi::OsStr::new("--timeout")));
    }
}
