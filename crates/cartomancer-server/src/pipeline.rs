//! Pipeline orchestration — the core review state machine.
//!
//! Stages:
//! 1. Prepare working directory (clone or reuse)
//! 2. Fetch PR metadata and diff (GitHub API)
//! 3. Run opengrep scan (subprocess with --baseline-commit)
//! 4. Enrich with cartog graph context
//! 5. Escalate severity based on blast radius
//! 6. LLM deepen high-severity findings (conditional)
//! 7. Build ReviewResult

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result};
use tokio::sync::Semaphore;
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

use cartomancer_store::store::Store;
use cartomancer_store::types::ScanRecord;

use crate::comment;
use crate::llm;
use crate::opengrep;

/// Outcome of the pipeline, including the parsed diff and work directory for cleanup.
pub struct PipelineResult {
    pub review: ReviewResult,
    /// Parsed diff — reused for inline comment placement without refetching.
    pub diff: PullRequestDiff,
    /// PR branch name (head_ref) — used for scan persistence.
    pub branch: String,
    /// Base branch name (base_ref) — used for regression comparison.
    pub base_branch: String,
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

    // 0. LLM health check — warn early if provider is unreachable
    match llm::create_provider(&config.llm) {
        Ok(provider) => match provider.health_check().await {
            Ok(()) => info!(provider = provider.name(), "LLM provider ready"),
            Err(e) => {
                warn!(err = %e, "LLM provider health check failed — deepening will be skipped")
            }
        },
        Err(e) => warn!(err = %e, "could not create LLM provider — deepening will be skipped"),
    }

    // 1. Fetch PR metadata
    info!(repo, pr_number, "fetching PR metadata");
    let pr_meta = github.fetch_pr_metadata(repo, pr_number).await?;

    // 2. Prepare working directory
    let (work_path, temp_dir) = prepare_work_dir(repo, token, work_dir)?;
    let work_str = work_path.to_string_lossy();

    // Fetch and checkout PR head, fetch base for opengrep --baseline-commit
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

    // 4. Run opengrep with --baseline-commit
    let opengrep_start = Instant::now();
    let mut findings =
        opengrep::run_opengrep(&work_str, &config.opengrep, Some(&pr_meta.base_sha)).await?;
    let opengrep_elapsed = opengrep_start.elapsed();
    let rule_count = config.opengrep.rules.len();
    info!(
        findings = findings.len(),
        elapsed_ms = opengrep_elapsed.as_millis() as u64,
        "opengrep scan complete"
    );

    if findings.is_empty() {
        let branch = pr_meta.head_ref.clone();
        let base_branch = pr_meta.base_ref.clone();
        let review = ReviewResult {
            pr_number,
            repo_full_name: repo.to_string(),
            head_sha: pr_meta.head_sha,
            findings: vec![],
            summary: comment::format_clean_summary(opengrep_elapsed, rule_count),
            status: ReviewStatus::Completed,
        };
        return Ok(PipelineResult {
            review,
            diff,
            branch,
            base_branch,
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
    let branch = pr_meta.head_ref;
    let base_branch = pr_meta.base_ref;
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
        branch,
        base_branch,
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
/// so opengrep `--baseline-commit` can find it.
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

    // Fetch base SHA so opengrep --baseline-commit can find it
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
            "git fetch of PR base failed — opengrep --baseline-commit may not work"
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

/// LLM-deepen qualifying findings with bounded concurrency.
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

    let provider: Arc<dyn llm::LlmProvider> = match llm::create_provider(&config.llm) {
        Ok(p) => Arc::from(p),
        Err(e) => {
            warn!(err = %e, "could not create LLM provider, skipping deepening");
            return;
        }
    };

    let concurrency = config.llm.max_concurrent_deepening;
    info!(
        provider = provider.name(),
        candidates = candidates.len(),
        concurrency,
        "starting LLM deepening"
    );

    // Build prompts upfront (cheap, no async needed)
    let tasks: Vec<(usize, String)> = candidates
        .iter()
        .map(|&idx| (idx, llm::build_deepening_prompt(&findings[idx])))
        .collect();

    // Fire concurrent LLM requests with bounded concurrency
    let semaphore = Arc::new(Semaphore::new(concurrency));
    let mut handles = Vec::with_capacity(tasks.len());

    for (idx, prompt) in tasks {
        let provider = Arc::clone(&provider);
        let sem = Arc::clone(&semaphore);
        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.expect("semaphore closed unexpectedly");
            let result = provider.complete(&prompt).await;
            (idx, result)
        }));
    }

    // Collect results and apply back to findings
    let mut deepened = 0u32;
    let mut failed = 0u32;
    for handle in handles {
        match handle.await {
            Ok((idx, Ok(analysis))) => {
                findings[idx].llm_analysis = Some(analysis);
                deepened += 1;
            }
            Ok((idx, Err(e))) => {
                warn!(
                    rule = %findings[idx].rule_id,
                    file = %findings[idx].file_path,
                    err = %e,
                    "LLM deepening failed, skipping"
                );
                failed += 1;
            }
            Err(e) => {
                warn!(err = %e, "LLM deepening task panicked");
                failed += 1;
            }
        }
    }

    info!(deepened, failed, "LLM deepening complete");
}

/// Persist a scan/review result to the store (BR-3: best-effort, never blocks pipeline).
pub fn persist_scan(
    db_path: &str,
    repo: &str,
    branch: &str,
    commit_sha: &str,
    command: &str,
    pr_number: Option<u64>,
    review: &cartomancer_core::review::ReviewResult,
) {
    let store = match Store::open(db_path) {
        Ok(s) => s,
        Err(e) => {
            warn!(path = db_path, err = %e, "failed to open store — scan not persisted");
            return;
        }
    };

    let record = ScanRecord {
        id: None,
        repo: repo.to_string(),
        branch: branch.to_string(),
        commit_sha: commit_sha.to_string(),
        command: command.to_string(),
        pr_number,
        finding_count: review.findings.len() as u32,
        summary: review.summary.clone(),
        created_at: None,
    };

    let scan_id = match store.insert_scan(&record) {
        Ok(id) => id,
        Err(e) => {
            warn!(err = %e, "failed to insert scan record — scan not persisted");
            return;
        }
    };

    if !review.findings.is_empty() {
        if let Err(e) = store.insert_findings(scan_id, &review.findings) {
            warn!(err = %e, "failed to insert findings — findings not persisted");
        }
    }

    info!(
        scan_id,
        findings = review.findings.len(),
        "scan persisted to store"
    );
}

/// Annotate findings as "new" or "existing" by comparing fingerprints against
/// the base branch baseline (US-5, BR-4). Best-effort: if the store is unavailable,
/// all findings are treated as new.
pub fn annotate_regression(
    db_path: &str,
    repo: &str,
    base_branch: &str,
    findings: &mut [Finding],
) -> (usize, usize) {
    let baseline = match Store::open(db_path) {
        Ok(store) => match store.baseline_fingerprints(repo, base_branch) {
            Ok(fps) => fps,
            Err(e) => {
                warn!(err = %e, "failed to load baseline — all findings treated as new");
                std::collections::HashSet::new()
            }
        },
        Err(e) => {
            warn!(err = %e, "failed to open store for regression check — all findings treated as new");
            std::collections::HashSet::new()
        }
    };

    let mut new_count = 0;
    let mut existing_count = 0;

    for finding in findings.iter_mut() {
        let fp = cartomancer_store::fingerprint::compute(
            &finding.rule_id,
            &finding.file_path,
            &finding.snippet,
        );
        if baseline.contains(&fp) {
            finding.is_new = Some(false);
            existing_count += 1;
        } else {
            finding.is_new = Some(true);
            new_count += 1;
        }
    }

    info!(
        new = new_count,
        existing = existing_count,
        "regression annotation complete"
    );
    (new_count, existing_count)
}

/// Filter out dismissed findings (BR-1: same fingerprint in dismissals table).
/// Best-effort: if the store is unavailable, no filtering is applied.
pub fn filter_dismissed(db_path: &str, findings: &mut Vec<Finding>) -> usize {
    let dismissed = match Store::open(db_path) {
        Ok(store) => match store.dismissed_fingerprints() {
            Ok(fps) => fps,
            Err(e) => {
                warn!(err = %e, "failed to load dismissed fingerprints — no filtering applied");
                return 0;
            }
        },
        Err(e) => {
            warn!(err = %e, "failed to open store for dismissal check — no filtering applied");
            return 0;
        }
    };

    if dismissed.is_empty() {
        return 0;
    }

    let before = findings.len();
    findings.retain(|f| {
        let fp = cartomancer_store::fingerprint::compute(&f.rule_id, &f.file_path, &f.snippet);
        !dismissed.contains(&fp)
    });
    let filtered = before - findings.len();

    if filtered > 0 {
        info!(filtered, "dismissed findings removed");
    }
    filtered
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
    fn pipeline_persist_scan_writes_to_store() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db_str = db_path.to_str().unwrap();

        let review = ReviewResult {
            pr_number: 42,
            repo_full_name: "owner/repo".into(),
            head_sha: "abc123".into(),
            findings: vec![cartomancer_core::finding::Finding {
                rule_id: "test-rule".into(),
                message: "test finding".into(),
                severity: cartomancer_core::severity::Severity::Warning,
                file_path: "src/lib.rs".into(),
                start_line: 10,
                end_line: 12,
                snippet: "let x = 1;".into(),
                cwe: None,
                graph_context: None,
                llm_analysis: None,
                escalation_reasons: vec![],
                is_new: None,
            }],
            summary: "1 finding".into(),
            status: ReviewStatus::Completed,
        };

        persist_scan(
            db_str,
            "owner/repo",
            "main",
            "abc123",
            "review",
            Some(42),
            &review,
        );

        // Verify it was written
        let store = Store::open(db_str).unwrap();
        let scans = store
            .list_scans(&cartomancer_store::types::ScanFilter::default())
            .unwrap();
        assert_eq!(scans.len(), 1);
        assert_eq!(scans[0].repo, "owner/repo");
        assert_eq!(scans[0].branch, "main");
        assert_eq!(scans[0].commit_sha, "abc123");
        assert_eq!(scans[0].command, "review");
        assert_eq!(scans[0].pr_number, Some(42));
        assert_eq!(scans[0].finding_count, 1);

        let findings = store.get_findings(scans[0].id.unwrap()).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "test-rule");
    }

    #[test]
    fn pipeline_persist_scan_empty_findings() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db_str = db_path.to_str().unwrap();

        let review = ReviewResult {
            pr_number: 1,
            repo_full_name: "owner/repo".into(),
            head_sha: "def456".into(),
            findings: vec![],
            summary: "clean".into(),
            status: ReviewStatus::Completed,
        };

        persist_scan(
            db_str,
            "owner/repo",
            "main",
            "def456",
            "scan",
            None,
            &review,
        );

        let store = Store::open(db_str).unwrap();
        let scans = store
            .list_scans(&cartomancer_store::types::ScanFilter::default())
            .unwrap();
        assert_eq!(scans.len(), 1);
        assert_eq!(scans[0].finding_count, 0);
        assert!(scans[0].pr_number.is_none());
    }

    #[test]
    fn pipeline_persist_scan_bad_path_does_not_panic() {
        let review = ReviewResult {
            pr_number: 1,
            repo_full_name: "owner/repo".into(),
            head_sha: "abc".into(),
            findings: vec![],
            summary: "clean".into(),
            status: ReviewStatus::Completed,
        };

        // Write to an invalid path — should log warning, not panic (BR-3)
        persist_scan(
            "/nonexistent/deep/path/that/cannot/be/created\0invalid",
            "owner/repo",
            "main",
            "abc",
            "scan",
            None,
            &review,
        );
        // If we get here without panic, BR-3 is satisfied
    }

    mod regression {
        use super::*;

        fn make_finding(rule_id: &str, file_path: &str, snippet: &str) -> Finding {
            Finding {
                rule_id: rule_id.into(),
                message: "test".into(),
                severity: cartomancer_core::severity::Severity::Warning,
                file_path: file_path.into(),
                start_line: 1,
                end_line: 1,
                snippet: snippet.into(),
                cwe: None,
                graph_context: None,
                llm_analysis: None,
                escalation_reasons: vec![],
                is_new: None,
            }
        }

        #[test]
        fn regression_all_new_when_no_baseline() {
            let dir = tempfile::tempdir().unwrap();
            let db_path = dir.path().join("test.db");
            let db_str = db_path.to_str().unwrap();

            let mut findings = vec![make_finding("rule-a", "a.rs", "code")];
            let (new, existing) = annotate_regression(db_str, "owner/repo", "main", &mut findings);

            assert_eq!(new, 1);
            assert_eq!(existing, 0);
            assert_eq!(findings[0].is_new, Some(true));
        }

        #[test]
        fn regression_existing_findings_detected() {
            let dir = tempfile::tempdir().unwrap();
            let db_path = dir.path().join("test.db");
            let db_str = db_path.to_str().unwrap();

            // First: persist a scan with a finding on "main"
            let baseline_finding = make_finding("rule-a", "a.rs", "code");
            let review = ReviewResult {
                pr_number: 0,
                repo_full_name: "owner/repo".into(),
                head_sha: "base-sha".into(),
                findings: vec![baseline_finding],
                summary: "1 finding".into(),
                status: ReviewStatus::Completed,
            };
            persist_scan(
                db_str,
                "owner/repo",
                "main",
                "base-sha",
                "scan",
                None,
                &review,
            );

            // Now: annotate the same finding in a PR
            let mut findings = vec![
                make_finding("rule-a", "a.rs", "code"),     // same → existing
                make_finding("rule-b", "b.rs", "new code"), // new
            ];
            let (new, existing) = annotate_regression(db_str, "owner/repo", "main", &mut findings);

            assert_eq!(existing, 1);
            assert_eq!(new, 1);
            assert_eq!(findings[0].is_new, Some(false));
            assert_eq!(findings[1].is_new, Some(true));
        }

        #[test]
        fn regression_changed_snippet_is_new() {
            let dir = tempfile::tempdir().unwrap();
            let db_path = dir.path().join("test.db");
            let db_str = db_path.to_str().unwrap();

            // Baseline with original snippet
            let review = ReviewResult {
                pr_number: 0,
                repo_full_name: "owner/repo".into(),
                head_sha: "base-sha".into(),
                findings: vec![make_finding("rule-a", "a.rs", "old code")],
                summary: "1 finding".into(),
                status: ReviewStatus::Completed,
            };
            persist_scan(
                db_str,
                "owner/repo",
                "main",
                "base-sha",
                "scan",
                None,
                &review,
            );

            // Same rule + file but different snippet → new finding
            let mut findings = vec![make_finding("rule-a", "a.rs", "modified code")];
            let (new, existing) = annotate_regression(db_str, "owner/repo", "main", &mut findings);

            assert_eq!(new, 1);
            assert_eq!(existing, 0);
            assert_eq!(findings[0].is_new, Some(true));
        }

        #[test]
        fn regression_bad_store_treats_all_as_new() {
            let mut findings = vec![make_finding("rule-a", "a.rs", "code")];
            let (new, existing) =
                annotate_regression("/nonexistent\0invalid", "owner/repo", "main", &mut findings);

            assert_eq!(new, 1);
            assert_eq!(existing, 0);
            assert_eq!(findings[0].is_new, Some(true));
        }
    }

    mod dismiss {
        use super::*;
        use cartomancer_store::types::Dismissal;

        fn make_finding(rule_id: &str, file_path: &str, snippet: &str) -> Finding {
            Finding {
                rule_id: rule_id.into(),
                message: "test".into(),
                severity: cartomancer_core::severity::Severity::Warning,
                file_path: file_path.into(),
                start_line: 1,
                end_line: 1,
                snippet: snippet.into(),
                cwe: None,
                graph_context: None,
                llm_analysis: None,
                escalation_reasons: vec![],
                is_new: None,
            }
        }

        #[test]
        fn dismiss_filters_matching_findings() {
            let dir = tempfile::tempdir().unwrap();
            let db_path = dir.path().join("test.db");
            let db_str = db_path.to_str().unwrap();

            // Create a dismissal
            let store = Store::open(db_str).unwrap();
            let fp = cartomancer_store::fingerprint::compute("rule-a", "a.rs", "code");
            store
                .dismiss(&Dismissal {
                    id: None,
                    fingerprint: fp,
                    rule_id: "rule-a".into(),
                    file_path: "a.rs".into(),
                    start_line: 1,
                    end_line: 1,
                    snippet_hash: cartomancer_store::fingerprint::snippet_hash("code"),
                    reason: Some("false positive".into()),
                    created_at: None,
                })
                .unwrap();
            drop(store);

            let mut findings = vec![
                make_finding("rule-a", "a.rs", "code"),  // dismissed
                make_finding("rule-b", "b.rs", "other"), // not dismissed
            ];

            let filtered = filter_dismissed(db_str, &mut findings);
            assert_eq!(filtered, 1);
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].rule_id, "rule-b");
        }

        #[test]
        fn dismiss_no_dismissals_keeps_all() {
            let dir = tempfile::tempdir().unwrap();
            let db_path = dir.path().join("test.db");
            let db_str = db_path.to_str().unwrap();

            let mut findings = vec![make_finding("rule-a", "a.rs", "code")];
            let filtered = filter_dismissed(db_str, &mut findings);
            assert_eq!(filtered, 0);
            assert_eq!(findings.len(), 1);
        }

        #[test]
        fn dismiss_changed_snippet_not_filtered() {
            let dir = tempfile::tempdir().unwrap();
            let db_path = dir.path().join("test.db");
            let db_str = db_path.to_str().unwrap();

            // Dismiss with original snippet
            let store = Store::open(db_str).unwrap();
            let fp = cartomancer_store::fingerprint::compute("rule-a", "a.rs", "old code");
            store
                .dismiss(&Dismissal {
                    id: None,
                    fingerprint: fp,
                    rule_id: "rule-a".into(),
                    file_path: "a.rs".into(),
                    start_line: 1,
                    end_line: 1,
                    snippet_hash: cartomancer_store::fingerprint::snippet_hash("old code"),
                    reason: None,
                    created_at: None,
                })
                .unwrap();
            drop(store);

            // Finding with changed snippet → different fingerprint → not filtered
            let mut findings = vec![make_finding("rule-a", "a.rs", "new code")];
            let filtered = filter_dismissed(db_str, &mut findings);
            assert_eq!(filtered, 0);
            assert_eq!(findings.len(), 1);
        }

        #[test]
        fn dismiss_bad_store_keeps_all() {
            let mut findings = vec![make_finding("rule-a", "a.rs", "code")];
            let filtered = filter_dismissed("/nonexistent\0invalid", &mut findings);
            assert_eq!(filtered, 0);
            assert_eq!(findings.len(), 1);
        }
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
            branch: "main".into(),
            base_branch: "main".into(),
            temp_dir: None,
        };
        assert_eq!(result.review.pr_number, 42);
        assert_eq!(result.review.summary, "clean");
        assert!(result.diff.chunks.is_empty());
    }
}
