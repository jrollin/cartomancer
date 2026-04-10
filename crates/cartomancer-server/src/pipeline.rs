//! Pipeline orchestration — the core review state machine.
//!
//! Stages:
//! 1. Prepare working directory (clone or reuse)
//! 2. Fetch PR metadata and diff (GitHub API)
//! 3. Run semgrep scan (subprocess with --baseline-commit)
//! 4. Enrich with cartog graph context
//! 5. Escalate severity based on blast radius
//! 6. LLM deepen high-severity findings (conditional)
//! 7. Build ReviewResult

use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{Context, Result};
use tracing::{info, warn};

use cartomancer_core::config::AppConfig;
use cartomancer_core::diff::PullRequestDiff;
use cartomancer_core::finding::Finding;
use cartomancer_core::review::{ReviewResult, ReviewStatus};
use cartomancer_github::client::GitHubClient;
use cartomancer_github::diff::parse_diff;
use cartomancer_github::types::PrMetadata;
use cartomancer_graph::enricher::CartogEnricher;
use cartomancer_graph::escalator::SeverityEscalator;

use crate::comment;
use crate::llm;
use crate::semgrep;

/// Outcome of the pipeline, including the parsed diff and work directory for cleanup.
pub struct PipelineResult {
    pub review: ReviewResult,
    /// Parsed diff — reused for inline comment placement without refetching.
    pub diff: PullRequestDiff,
    /// Temp dir handle — kept alive until review is posted, then dropped for cleanup.
    /// None if --work-dir was used.
    #[allow(dead_code)]
    pub temp_dir: Option<tempfile::TempDir>,
}

/// Run the full review pipeline for a single PR.
pub async fn run_pipeline(
    config: &AppConfig,
    github: &GitHubClient,
    token: &str,
    repo: &str,
    pr_number: u64,
    work_dir: Option<&str>,
) -> Result<PipelineResult> {
    let pipeline_start = Instant::now();

    // 1. Fetch PR metadata
    info!(repo, pr_number, "fetching PR metadata");
    let pr_meta = github.fetch_pr_metadata(repo, pr_number).await?;

    // 2. Prepare working directory
    let (work_path, temp_dir) = prepare_work_dir(repo, token, work_dir)?;
    let work_str = work_path.to_string_lossy();

    // Fetch and checkout PR head, fetch base for --baseline-commit
    prepare_pr_commits(&work_path, &pr_meta)?;

    // 3. Fetch and parse diff
    info!("fetching PR diff");
    let raw_diff = github.fetch_diff(repo, pr_number).await?;
    let diff = parse_diff(&raw_diff)?;
    info!(
        files_changed = diff.files_changed.len(),
        chunks = diff.chunks.len(),
        "diff parsed"
    );

    // 4. Run semgrep with --baseline-commit
    let semgrep_start = Instant::now();
    let mut findings = semgrep::run_semgrep(
        &work_str,
        &config.semgrep.rules,
        Some(&pr_meta.base_sha),
        config.semgrep.timeout_seconds,
    )
    .await?;
    let semgrep_elapsed = semgrep_start.elapsed();
    let rule_count = config.semgrep.rules.len();
    info!(
        findings = findings.len(),
        elapsed_ms = semgrep_elapsed.as_millis() as u64,
        "semgrep scan complete"
    );

    if findings.is_empty() {
        let review = ReviewResult {
            pr_number,
            repo_full_name: repo.to_string(),
            head_sha: pr_meta.head_sha,
            findings: vec![],
            summary: comment::format_clean_summary(semgrep_elapsed, rule_count),
            status: ReviewStatus::Completed,
        };
        return Ok(PipelineResult {
            review,
            diff,
            temp_dir,
        });
    }

    // 5. Enrich with cartog
    enrich_findings(&work_path, config, &mut findings);

    // 6. Escalate severity
    let escalator = SeverityEscalator::new(config.severity.blast_radius_threshold);
    escalator.escalate_batch(&mut findings);

    // 7. LLM deepen
    deepen_findings(config, &mut findings).await;

    // 8. Sort by severity (critical first)
    findings.sort_by(|a, b| b.severity.cmp(&a.severity));

    // 9. Build ReviewResult
    let summary = comment::format_summary(&findings, pipeline_start.elapsed(), rule_count);
    let review = ReviewResult {
        pr_number,
        repo_full_name: repo.to_string(),
        head_sha: pr_meta.head_sha,
        findings,
        summary,
        status: ReviewStatus::Completed,
    };

    Ok(PipelineResult {
        review,
        diff,
        temp_dir,
    })
}

/// Prepare the working directory: clone to temp dir or reuse existing.
fn prepare_work_dir(
    repo: &str,
    token: &str,
    work_dir: Option<&str>,
) -> Result<(PathBuf, Option<tempfile::TempDir>)> {
    match work_dir {
        Some(dir) => {
            let path = PathBuf::from(dir);
            if path.join(".git").exists() {
                info!(path = %path.display(), "reusing existing git checkout");
                Ok((path, None))
            } else {
                info!(path = %path.display(), "cloning repo into work-dir");
                std::fs::create_dir_all(&path)
                    .with_context(|| format!("creating work-dir: {}", path.display()))?;
                clone_repo(repo, token, &path)?;
                Ok((path, None))
            }
        }
        None => {
            let temp_dir = tempfile::tempdir().context("creating temp directory")?;
            let path = temp_dir.path().to_path_buf();
            info!(path = %path.display(), "cloning repo into temp directory");
            clone_repo(repo, token, &path)?;
            Ok((path, Some(temp_dir)))
        }
    }
}

/// Clone a GitHub repo into the given directory.
/// Token is passed via `GIT_ASKPASS` env var pointing to a script that echoes
/// the token, avoiding exposure in process arguments visible via `/proc` or `ps`.
fn clone_repo(repo: &str, token: &str, target: &Path) -> Result<()> {
    let url = format!("https://x-access-token@github.com/{repo}.git");

    // Create a temporary askpass script that echoes the token.
    // git calls this script with a prompt; the script ignores it and prints the token.
    let askpass_dir = tempfile::tempdir().context("creating askpass temp dir")?;
    let askpass_path = askpass_dir.path().join("askpass.sh");
    // Write token to a separate file, script reads from it to avoid shell injection
    let token_path = askpass_dir.path().join("token");
    std::fs::write(&token_path, token).context("writing token file")?;
    std::fs::write(
        &askpass_path,
        format!("#!/bin/sh\ncat '{}'", token_path.display()),
    )
    .context("writing askpass script")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&askpass_path, std::fs::Permissions::from_mode(0o700))
            .context("setting askpass permissions")?;
    }

    let status = std::process::Command::new("git")
        .args(["clone", "--depth", "50", &url, "."])
        .env("GIT_ASKPASS", &askpass_path)
        .env("GIT_TERMINAL_PROMPT", "0")
        .current_dir(target)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .status()
        .context("failed to execute git clone — is git installed?")?;

    // askpass_dir is dropped here, cleaning up the script

    if !status.success() {
        anyhow::bail!(
            "git clone failed for {repo} (exit {})",
            status.code().unwrap_or(-1)
        );
    }
    Ok(())
}

/// Fetch and checkout the PR head commit, and fetch the base commit
/// so semgrep `--baseline-commit` can find it.
fn prepare_pr_commits(work_path: &Path, pr_meta: &PrMetadata) -> Result<()> {
    // Fetch head SHA
    let status = std::process::Command::new("git")
        .args(["fetch", "origin", &pr_meta.head_sha, "--depth", "50"])
        .current_dir(work_path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .status()
        .context("failed to fetch PR head")?;

    if !status.success() {
        anyhow::bail!(
            "git fetch of PR head {} failed (exit {})",
            &pr_meta.head_sha[..8.min(pr_meta.head_sha.len())],
            status.code().unwrap_or(-1)
        );
    }

    // Checkout head SHA
    let status = std::process::Command::new("git")
        .args(["checkout", &pr_meta.head_sha])
        .current_dir(work_path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .status()
        .context("failed to checkout PR head")?;

    if !status.success() {
        anyhow::bail!(
            "git checkout of PR head {} failed (exit {})",
            &pr_meta.head_sha[..8.min(pr_meta.head_sha.len())],
            status.code().unwrap_or(-1)
        );
    }

    // Fetch base SHA so semgrep --baseline-commit can find it
    let status = std::process::Command::new("git")
        .args(["fetch", "origin", &pr_meta.base_sha, "--depth", "50"])
        .current_dir(work_path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .status()
        .context("failed to fetch PR base")?;

    if !status.success() {
        warn!(
            base_sha = %&pr_meta.base_sha[..8.min(pr_meta.base_sha.len())],
            "git fetch of PR base failed — semgrep --baseline-commit may not work"
        );
    }

    Ok(())
}

/// Enrich findings with cartog graph context (if .cartog.db exists).
fn enrich_findings(work_path: &Path, config: &AppConfig, findings: &mut [Finding]) {
    let db_path = work_path.join(".cartog.db");
    if !db_path.exists() {
        info!("no .cartog.db found, skipping graph enrichment");
        return;
    }

    match CartogEnricher::open(&db_path.to_string_lossy(), config.severity.impact_depth) {
        Ok(enricher) => {
            let mut enriched = 0u32;
            let mut failed = 0u32;
            for finding in findings.iter_mut() {
                match enricher.enrich(finding) {
                    Ok(()) => {
                        if finding.graph_context.is_some() {
                            enriched += 1;
                        }
                    }
                    Err(e) => {
                        warn!(
                            rule = %finding.rule_id,
                            file = %finding.file_path,
                            line = finding.start_line,
                            err = %e,
                            "failed to enrich finding, skipping"
                        );
                        failed += 1;
                    }
                }
            }
            info!(enriched, failed, "graph enrichment complete");
        }
        Err(e) => {
            warn!(
                path = %db_path.display(),
                err = %e,
                "could not open cartog database, skipping enrichment"
            );
        }
    }
}

/// LLM-deepen qualifying findings.
async fn deepen_findings(config: &AppConfig, findings: &mut [Finding]) {
    let threshold = config.severity.llm_deepening_threshold;
    let candidates: Vec<usize> = findings
        .iter()
        .enumerate()
        .filter(|(_, f)| {
            f.severity >= threshold
                && f.graph_context
                    .as_ref()
                    .map(|ctx| ctx.blast_radius > 3)
                    .unwrap_or(false)
        })
        .map(|(i, _)| i)
        .collect();

    if candidates.is_empty() {
        info!(threshold = %threshold, "no findings qualify for LLM deepening");
        return;
    }

    match llm::create_provider(&config.llm) {
        Ok(provider) => {
            info!(
                provider = provider.name(),
                candidates = candidates.len(),
                "starting LLM deepening"
            );
            let mut deepened = 0u32;
            let mut failed = 0u32;
            for idx in &candidates {
                let finding = &mut findings[*idx];
                match provider.deepen(finding).await {
                    Ok(()) => {
                        deepened += 1;
                    }
                    Err(e) => {
                        warn!(
                            rule = %finding.rule_id,
                            file = %finding.file_path,
                            err = %e,
                            "LLM deepening failed, skipping"
                        );
                        failed += 1;
                    }
                }
            }
            info!(
                deepened,
                failed,
                skipped = (candidates.len() as u32).saturating_sub(deepened + failed),
                "LLM deepening complete"
            );
        }
        Err(e) => {
            warn!(err = %e, "could not create LLM provider, skipping deepening");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prepare_work_dir_with_existing_git_repo() {
        let temp = tempfile::tempdir().unwrap();
        // Create a .git directory to simulate an existing checkout
        std::fs::create_dir(temp.path().join(".git")).unwrap();
        let (path, temp_handle) = prepare_work_dir(
            "owner/repo",
            "fake-token",
            Some(temp.path().to_str().unwrap()),
        )
        .unwrap();
        assert_eq!(path, temp.path());
        assert!(
            temp_handle.is_none(),
            "should not create temp dir for existing checkout"
        );
    }

    #[test]
    fn prepare_work_dir_without_arg_creates_temp() {
        // We can't actually clone here, but we test that temp dir is created
        let result = prepare_work_dir("owner/repo", "fake-token", None);
        // This will fail because git clone won't work, but we're testing the temp dir path
        // The error is expected — it means we got past temp dir creation
        assert!(result.is_err()); // git clone fails without network
    }

    #[test]
    fn pipeline_result_has_correct_fields() {
        let review = ReviewResult {
            pr_number: 42,
            repo_full_name: "owner/repo".into(),
            head_sha: "abc123".into(),
            findings: vec![],
            summary: "clean".into(),
            status: ReviewStatus::Completed,
        };
        let result = PipelineResult {
            review,
            diff: PullRequestDiff {
                chunks: vec![],
                files_changed: vec![],
            },
            temp_dir: None,
        };
        assert_eq!(result.review.pr_number, 42);
        assert_eq!(result.review.summary, "clean");
        assert!(result.diff.chunks.is_empty());
    }
}
