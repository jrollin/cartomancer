//! Semgrep subprocess runner and JSON output parser.

use std::time::Duration;

use anyhow::{Context, Result};
use tokio::process::Command;
use tracing::{debug, info, warn};

use cartomancer_core::finding::Finding;
use cartomancer_core::severity::Severity;

/// Semgrep JSON output structure.
#[derive(serde::Deserialize)]
struct SemgrepOutput {
    results: Vec<SemgrepResult>,
    #[serde(default)]
    errors: Vec<SemgrepError>,
}

#[derive(serde::Deserialize)]
struct SemgrepResult {
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
}

#[derive(serde::Deserialize, Default)]
struct Metadata {
    #[allow(dead_code)]
    confidence: Option<String>,
    cwe: Option<Vec<String>>,
}

#[derive(serde::Deserialize)]
struct SemgrepError {
    message: String,
}

/// Run semgrep against the given directory and return parsed findings.
///
/// Uses `--baseline-commit` when provided to only report new findings.
/// Enforces a timeout on our side (kills the process if exceeded).
pub async fn run_semgrep(
    target_dir: &str,
    rules: &[String],
    baseline_commit: Option<&str>,
    timeout_seconds: u64,
) -> Result<Vec<Finding>> {
    let mut cmd = Command::new("semgrep");
    cmd.arg("scan")
        .arg("--json")
        .arg("--quiet")
        .arg("--timeout")
        .arg(timeout_seconds.to_string())
        .current_dir(target_dir);

    for rule in rules {
        cmd.arg("--config").arg(rule);
    }

    if let Some(sha) = baseline_commit {
        cmd.arg("--baseline-commit").arg(sha);
    }

    // Log the full command for debugging
    let cmd_display = format!(
        "semgrep scan --json --quiet --timeout {} {}{}",
        timeout_seconds,
        rules
            .iter()
            .map(|r| format!("--config {r}"))
            .collect::<Vec<_>>()
            .join(" "),
        baseline_commit
            .map(|s| format!(" --baseline-commit {s}"))
            .unwrap_or_default(),
    );
    info!(cmd = %cmd_display, target_dir, "executing semgrep");

    let start = std::time::Instant::now();

    // Enforce timeout on our side — kill semgrep if it hangs
    let timeout_duration = Duration::from_secs(timeout_seconds + 10); // grace period
    let output = tokio::time::timeout(timeout_duration, cmd.output())
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "semgrep timed out after {}s (limit: {}s + 10s grace)",
                timeout_duration.as_secs(),
                timeout_seconds
            )
        })?
        .context("failed to execute semgrep — is it installed and in PATH?")?;

    let elapsed = start.elapsed();

    // semgrep exits 0 = no findings, 1 = findings found, 2+ = error
    let exit_code = output.status.code().unwrap_or(-1);
    debug!(
        exit_code,
        elapsed_ms = elapsed.as_millis() as u64,
        "semgrep exited"
    );

    if exit_code > 1 && output.stdout.is_empty() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "semgrep failed (exit {}, {:.1}s): {}",
            exit_code,
            elapsed.as_secs_f64(),
            stderr.trim()
        );
    }

    if output.stdout.is_empty() {
        info!(
            elapsed_ms = elapsed.as_millis() as u64,
            "semgrep returned no findings"
        );
        return Ok(vec![]);
    }

    let findings = parse_output(&output.stdout, elapsed)?;
    Ok(findings)
}

/// Parse semgrep JSON output into domain findings.
/// On parse failure, logs a warning and returns an empty vec instead of crashing.
fn parse_output(output: &[u8], elapsed: Duration) -> Result<Vec<Finding>> {
    let parsed: SemgrepOutput = match serde_json::from_slice(output) {
        Ok(v) => v,
        Err(e) => {
            let preview = String::from_utf8_lossy(&output[..output.len().min(200)]);
            warn!(
                err = %e,
                output_bytes = output.len(),
                preview = %preview,
                "failed to parse semgrep JSON output, returning empty results"
            );
            return Ok(vec![]);
        }
    };

    for err in &parsed.errors {
        warn!(message = %err.message, "semgrep reported an error");
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
        })
        .collect();

    info!(
        count = findings.len(),
        elapsed_ms = elapsed.as_millis() as u64,
        "semgrep scan complete"
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
    fn map_semgrep_severity() {
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
}
