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
use cartomancer_github::diff::{is_line_in_diff, parse_diff};
use cartomancer_github::types::{PrMetadata, ReviewComment};
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
    /// Pipeline wall-clock duration — used for summary regeneration after off-diff splitting.
    pub scan_duration: std::time::Duration,
    /// Number of opengrep rules used — used for summary regeneration after off-diff splitting.
    pub rule_count: usize,
    /// Scan ID from the store (if stage tracking is active). Used by `finalize_and_post`
    /// to update the existing scan record instead of inserting a duplicate.
    pub scan_id: Option<i64>,
    /// Temp dir handle — kept alive until review is posted, then dropped for cleanup.
    /// None if --work-dir was used.
    #[allow(dead_code)]
    pub temp_dir: Option<tempfile::TempDir>,
}

/// Run the full review pipeline for a single PR.
///
/// When `resume_scan_id` is Some, resumes a previously failed scan from its
/// last completed stage (requires the work directory to still exist or a new clone).
pub async fn run_pipeline(
    config: &AppConfig,
    github: &GitHubClient,
    token: &str,
    repo: &str,
    pr_number: u64,
    work_dir: Option<&str>,
    resume_scan_id: Option<i64>,
) -> Result<PipelineResult> {
    use cartomancer_core::review::PipelineStage;

    let pipeline_start = Instant::now();

    // Determine which stage to start from (resume support)
    let (start_stage, mut findings, scan_id, resume_work_dir) = match resume_scan_id {
        Some(sid) => {
            let store = Store::open(&config.storage.db_path)
                .map_err(|e| anyhow::anyhow!("failed to open store for resume: {e}"))?;
            let scan = store
                .get_scan(sid)?
                .ok_or_else(|| anyhow::anyhow!("scan {sid} not found — cannot resume"))?;

            let stage = PipelineStage::from_db(&scan.stage)
                .ok_or_else(|| anyhow::anyhow!("unknown stage '{}' for scan {sid}", scan.stage))?;

            if stage == PipelineStage::Completed {
                anyhow::bail!("scan {sid} already completed — nothing to resume");
            }

            // Verify the stored scan matches the current request
            if scan.repo != repo {
                anyhow::bail!(
                    "scan {sid} belongs to repo '{}', not '{repo}' — cannot resume",
                    scan.repo
                );
            }
            if scan.pr_number != Some(pr_number) {
                anyhow::bail!(
                    "scan {sid} belongs to PR #{}, not #{pr_number} — cannot resume",
                    scan.pr_number.map_or("none".into(), |n| n.to_string())
                );
            }

            // Load persisted findings to resume from
            let stored = store.get_findings(sid)?;
            let resumed_findings = stored_to_findings(&stored);

            info!(scan_id = sid, stage = %stage, findings = resumed_findings.len(), "resuming pipeline");
            (stage, resumed_findings, Some(sid), scan.work_dir)
        }
        None => (PipelineStage::Pending, vec![], None, None),
    };

    // 0. LLM health check — warn early if provider is unreachable
    match llm::create_provider(&config.llm, config.knowledge.system_prompt.as_deref()) {
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

    // Open store for stage persistence (best-effort — stage tracking is optional)
    let store = Store::open(&config.storage.db_path).ok();
    let rule_count = config.opengrep.rules.len();

    // Create or reuse scan record
    let scan_id: Option<i64> = match scan_id {
        Some(id) => Some(id),
        None => {
            if let Some(ref s) = store {
                let record = ScanRecord {
                    id: None,
                    repo: repo.to_string(),
                    branch: pr_meta.head_ref.clone(),
                    commit_sha: pr_meta.head_sha.clone(),
                    command: "review".into(),
                    pr_number: Some(pr_number),
                    finding_count: 0,
                    summary: String::new(),
                    created_at: None,
                    stage: "pending".into(),
                    error_message: None,
                    failed_at_stage: None,
                    work_dir: None,
                };
                match s.insert_scan(&record) {
                    Ok(id) => Some(id),
                    Err(e) => {
                        warn!(err = %e, "failed to create scan record — stage tracking disabled");
                        None
                    }
                }
            } else {
                None
            }
        }
    };

    // Helper to persist stage (best-effort)
    let advance_stage =
        |store: &Option<Store>, scan_id: Option<i64>, stage: &str, findings: &[Finding]| {
            let id = match scan_id {
                Some(id) => id,
                None => return,
            };
            if let Some(ref s) = store {
                if let Err(e) = s.update_scan_findings(id, findings) {
                    warn!(err = %e, stage, "failed to persist findings at stage");
                }
                if let Err(e) = s.update_scan_stage(id, stage) {
                    warn!(err = %e, stage, "failed to update scan stage");
                }
            }
        };

    // Helper to record failure metadata (best-effort)
    let record_failure =
        |store: &Option<Store>, scan_id: Option<i64>, stage: &str, err: &anyhow::Error| {
            if let (Some(id), Some(ref s)) = (scan_id, store) {
                if let Err(e) = s.mark_scan_failed(id, stage, &err.to_string()) {
                    warn!(err = %e, "failed to record scan failure");
                }
            }
        };

    // --- Stage: Prepare (clone + checkout + diff) ---
    let (work_path, temp_dir, diff) = if start_stage < PipelineStage::Prepared {
        // Resolve work-dir: explicit --work-dir flag wins, otherwise fresh clone
        let (work_path, temp_dir) = prepare_work_dir(repo, token, work_dir)?;

        if let Err(e) = prepare_pr_commits(&work_path, &pr_meta) {
            record_failure(&store, scan_id, "prepared", &e);
            return Err(e);
        }

        let diff = match async {
            info!("fetching PR diff");
            let raw_diff = github.fetch_diff(repo, pr_number).await?;
            parse_diff(&raw_diff)
        }
        .await
        {
            Ok(d) => d,
            Err(e) => {
                record_failure(&store, scan_id, "prepared", &e);
                return Err(e);
            }
        };
        info!(
            files_changed = diff.files_changed.len(),
            chunks = diff.chunks.len(),
            "diff parsed"
        );

        // Persist work_dir and advance stage only after all prepare operations succeed
        let work_str = work_path.to_string_lossy();
        if let (Some(id), Some(ref s)) = (scan_id, &store) {
            if let Err(e) = s.update_scan_work_dir(id, &work_str) {
                warn!(err = %e, "failed to persist work_dir");
            }
        }
        advance_stage(&store, scan_id, "prepared", &findings);
        (work_path, temp_dir, diff)
    } else {
        info!(stage = "prepared", "skipping (already completed)");
        // Resolve work-dir for resumed scan: explicit flag > stored path > fresh clone
        let effective_work_dir = work_dir.map(|s| s.to_string()).or(resume_work_dir);
        let (work_path, temp_dir) = prepare_work_dir(repo, token, effective_work_dir.as_deref())?;
        prepare_pr_commits(&work_path, &pr_meta)?;

        info!("fetching PR diff");
        let raw_diff = github.fetch_diff(repo, pr_number).await?;
        let diff = parse_diff(&raw_diff)?;
        (work_path, temp_dir, diff)
    };
    let work_str = work_path.to_string_lossy();

    // --- Stage: Scan ---
    if start_stage < PipelineStage::Scanned {
        let opengrep_start = Instant::now();
        findings = match opengrep::run_opengrep(
            &work_str,
            &config.opengrep,
            Some(&pr_meta.base_sha),
        )
        .await
        {
            Ok(f) => f,
            Err(e) => {
                record_failure(&store, scan_id, "scanned", &e);
                return Err(e);
            }
        };
        let opengrep_elapsed = opengrep_start.elapsed();
        info!(
            findings = findings.len(),
            elapsed_ms = opengrep_elapsed.as_millis() as u64,
            "opengrep scan complete"
        );
        advance_stage(&store, scan_id, "scanned", &findings);
    } else {
        info!(stage = "scanned", "skipping (already completed)");
    }

    if findings.is_empty() {
        let branch = pr_meta.head_ref.clone();
        let base_branch = pr_meta.base_ref.clone();
        let scan_duration = pipeline_start.elapsed();
        advance_stage(&store, scan_id, "completed", &findings);
        let review = ReviewResult {
            pr_number,
            repo_full_name: repo.to_string(),
            head_sha: pr_meta.head_sha,
            findings: vec![],
            summary: comment::format_clean_summary(scan_duration, rule_count),
            status: ReviewStatus::Completed,
        };
        return Ok(PipelineResult {
            review,
            diff,
            branch,
            base_branch,
            scan_duration,
            rule_count,
            scan_id,
            temp_dir,
        });
    }

    // --- Stage: Enrich ---
    if start_stage < PipelineStage::Enriched {
        enrich_findings_batch(&work_path, config, &mut findings);
        advance_stage(&store, scan_id, "enriched", &findings);
    } else {
        info!(stage = "enriched", "skipping (already completed)");
    }

    // --- Stage: Escalate ---
    if start_stage < PipelineStage::Escalated {
        let escalator = SeverityEscalator::new(config.severity.blast_radius_threshold);
        escalator.escalate_batch(&mut findings, &config.knowledge.rules);
        advance_stage(&store, scan_id, "escalated", &findings);
    } else {
        info!(stage = "escalated", "skipping (already completed)");
    }

    // --- Stage: Deepen ---
    if start_stage < PipelineStage::Deepened {
        deepen_findings(config, &work_path, &mut findings).await;
        advance_stage(&store, scan_id, "deepened", &findings);
    } else {
        info!(stage = "deepened", "skipping (already completed)");
    }

    // Sort by severity (critical first)
    findings.sort_by(|a, b| b.severity.cmp(&a.severity));

    // Build ReviewResult and mark completed
    let scan_duration = pipeline_start.elapsed();
    let summary = comment::format_summary(&findings, &[], scan_duration, rule_count);
    let branch = pr_meta.head_ref;
    let base_branch = pr_meta.base_ref;

    advance_stage(&store, scan_id, "completed", &findings);

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
        scan_duration,
        rule_count,
        scan_id,
        temp_dir,
    })
}

/// Convert stored findings back to domain `Finding` structs for pipeline resumption.
fn stored_to_findings(stored: &[cartomancer_store::types::StoredFinding]) -> Vec<Finding> {
    use cartomancer_core::finding::GraphContext;
    use cartomancer_core::severity::Severity;

    stored
        .iter()
        .map(|sf| {
            let severity = sf.severity.parse::<Severity>().unwrap_or(Severity::Warning);

            let graph_context = sf
                .graph_context_json
                .as_deref()
                .and_then(|json| serde_json::from_str::<GraphContext>(json).ok());

            let escalation_reasons: Vec<String> = sf
                .escalation_reasons_json
                .as_deref()
                .and_then(|json| serde_json::from_str(json).ok())
                .unwrap_or_default();

            Finding {
                rule_id: sf.rule_id.clone(),
                message: sf.message.clone(),
                severity,
                file_path: sf.file_path.clone(),
                start_line: sf.start_line,
                end_line: sf.end_line,
                snippet: sf.snippet.clone(),
                cwe: sf.cwe.clone(),
                graph_context,
                llm_analysis: sf.llm_analysis.clone(),
                escalation_reasons,
                is_new: None,
                enclosing_context: sf.enclosing_context.clone(),
                suggested_fix: sf.suggested_fix.clone(),
                agent_prompt: sf.agent_prompt.clone(),
            }
        })
        .collect()
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

/// Enrich findings with cartog graph context using batch-optimized queries.
///
/// Deduplicates DB queries: one `outline()` per unique file, one `impact()` +
/// `refs()` per unique symbol. Falls back gracefully if .cartog.db is missing.
fn enrich_findings_batch(work_path: &Path, config: &AppConfig, findings: &mut [Finding]) {
    let db_path = work_path.join(&config.severity.cartog_db_path);
    if !db_path.exists() {
        info!(path = %db_path.display(), "cartog database not found, skipping graph enrichment");
        return;
    }

    match CartogEnricher::open(&db_path.to_string_lossy(), config.severity.impact_depth) {
        Ok(enricher) => {
            if let Err(e) = enricher.enrich_batch_optimized(findings) {
                warn!(err = %e, "batch enrichment failed");
            }
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
async fn deepen_findings(config: &AppConfig, work_path: &Path, findings: &mut [Finding]) {
    let threshold = config.severity.llm_deepening_threshold;
    let rule_overrides = &config.knowledge.rules;
    let candidates: Vec<usize> = findings
        .iter()
        .enumerate()
        .filter(|(_, f)| {
            // Check if this rule has always_deepen override
            let always = rule_overrides
                .get(&f.rule_id)
                .map(|r| r.always_deepen)
                .unwrap_or(false);
            always
                || (f.severity >= threshold
                    && f.graph_context
                        .as_ref()
                        .map(|ctx| ctx.blast_radius > 3)
                        .unwrap_or(false))
        })
        .map(|(i, _)| i)
        .collect();

    if candidates.is_empty() {
        info!(threshold = %threshold, "no findings qualify for LLM deepening");
        return;
    }

    let provider: Arc<dyn llm::LlmProvider> =
        match llm::create_provider(&config.llm, config.knowledge.system_prompt.as_deref()) {
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

    // Load company knowledge once (used in every prompt)
    let company_context = llm::load_knowledge(work_path, &config.knowledge);
    if !company_context.is_empty() {
        info!(
            chars = company_context.len(),
            "loaded company knowledge for LLM deepening"
        );
    }

    // Build prompts upfront (cheap, no async needed)
    let tasks: Vec<(usize, String)> = candidates
        .iter()
        .map(|&idx| {
            (
                idx,
                llm::build_deepening_prompt(&findings[idx], &company_context),
            )
        })
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
            Ok((idx, Ok(raw))) => {
                let (analysis, fix) = llm::parse_llm_response(&raw);
                findings[idx].llm_analysis = Some(analysis);
                if let Some(ref fix) = fix {
                    findings[idx].agent_prompt = Some(llm::build_agent_prompt(&findings[idx], fix));
                }
                findings[idx].suggested_fix = fix;
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

/// Findings partitioned by diff placement, with comments ready for posting.
pub struct ReviewPayload {
    pub summary: String,
    pub inline_comments: Vec<ReviewComment>,
    pub off_diff_bodies: Vec<String>,
}

/// Partition findings into inline review comments and off-diff comments,
/// regenerating the summary when off-diff findings exist.
pub fn prepare_review_payload(result: &PipelineResult) -> ReviewPayload {
    let review = &result.review;
    let mut inline_comments = Vec::new();
    let mut off_diff_findings: Vec<&Finding> = Vec::new();

    for finding in &review.findings {
        if is_line_in_diff(&result.diff, &finding.file_path, finding.start_line) {
            inline_comments.push(ReviewComment {
                path: finding.file_path.clone(),
                line: finding.start_line,
                body: comment::format_inline_comment(finding),
            });
        } else {
            off_diff_findings.push(finding);
        }
    }

    let summary = if off_diff_findings.is_empty() {
        review.summary.clone()
    } else {
        comment::format_summary(
            &review.findings,
            &off_diff_findings,
            result.scan_duration,
            result.rule_count,
        )
    };

    let off_diff_bodies = off_diff_findings
        .iter()
        .map(|f| comment::format_off_diff_comment(f))
        .collect();

    ReviewPayload {
        summary,
        inline_comments,
        off_diff_bodies,
    }
}

/// Post-pipeline finalization: annotate regression, filter dismissed, persist, post to GitHub.
///
/// Shared between `cmd_review()` (CLI) and webhook handler.
pub async fn finalize_and_post(
    config: &AppConfig,
    github: &GitHubClient,
    repo: &str,
    pr: u64,
    result: &mut PipelineResult,
) -> Result<()> {
    // Annotate findings as new/existing (US-5) and filter dismissed (US-6)
    annotate_regression(
        &config.storage.db_path,
        repo,
        &result.base_branch,
        &mut result.review.findings,
    );
    filter_dismissed(&config.storage.db_path, &mut result.review.findings);

    // Recompute summary to reflect filtered findings
    let payload = prepare_review_payload(result);
    result.review.summary = payload.summary.clone();

    // Persist findings (BR-3: best-effort) but defer "completed" until after posting
    if let Some(sid) = result.scan_id {
        if let Ok(store) = Store::open(&config.storage.db_path) {
            if let Err(e) = store.update_scan_findings(sid, &result.review.findings) {
                warn!(err = %e, "failed to update findings for finalization");
            }
        }
    } else {
        persist_scan(
            &config.storage.db_path,
            repo,
            &result.branch,
            &result.review.head_sha,
            "review",
            Some(pr),
            &result.review,
        );
    }

    // Post to GitHub
    if result.review.findings.is_empty() {
        github
            .post_comment(repo, pr, &result.review.summary)
            .await?;
        info!("clean summary posted for {repo}#{pr}");
    } else {
        github
            .post_review(
                repo,
                pr,
                &result.review.head_sha,
                &payload.summary,
                payload.inline_comments,
            )
            .await?;

        for body in &payload.off_diff_bodies {
            github.post_comment(repo, pr, body).await?;
        }

        info!(
            total = result.review.findings.len(),
            "review posted for {repo}#{pr}"
        );
    }

    // Mark completed only after posting succeeds
    if let Some(sid) = result.scan_id {
        if let Ok(store) = Store::open(&config.storage.db_path) {
            if let Err(e) = store.update_scan_stage(sid, "completed") {
                warn!(err = %e, "failed to mark scan as completed");
            }
        }
    }

    Ok(())
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
        stage: "completed".into(),
        error_message: None,
        failed_at_stage: None,
        work_dir: None,
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
                enclosing_context: None,
                suggested_fix: None,
                agent_prompt: None,
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
                enclosing_context: None,
                suggested_fix: None,
                agent_prompt: None,
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
                enclosing_context: None,
                suggested_fix: None,
                agent_prompt: None,
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

    mod stored_to_findings_tests {
        use super::*;
        use cartomancer_store::types::StoredFinding;

        fn sample_stored_finding() -> StoredFinding {
            StoredFinding {
                id: Some(1),
                scan_id: 1,
                fingerprint: "fp123".into(),
                rule_id: "test-rule".into(),
                severity: "error".into(),
                file_path: "src/lib.rs".into(),
                start_line: 10,
                end_line: 12,
                message: "test finding".into(),
                snippet: "let x = 1;".into(),
                cwe: Some("CWE-798".into()),
                graph_context_json: None,
                llm_analysis: Some("analysis text".into()),
                escalation_reasons_json: None,
                enclosing_context: Some("fn main() { ... }".into()),
                suggested_fix: Some("-old\n+new".into()),
                agent_prompt: Some("fix it".into()),
            }
        }

        #[test]
        fn converts_basic_fields() {
            let stored = vec![sample_stored_finding()];
            let findings = stored_to_findings(&stored);

            assert_eq!(findings.len(), 1);
            let f = &findings[0];
            assert_eq!(f.rule_id, "test-rule");
            assert_eq!(f.severity, cartomancer_core::severity::Severity::Error);
            assert_eq!(f.file_path, "src/lib.rs");
            assert_eq!(f.start_line, 10);
            assert_eq!(f.end_line, 12);
            assert_eq!(f.message, "test finding");
            assert_eq!(f.snippet, "let x = 1;");
            assert_eq!(f.cwe.as_deref(), Some("CWE-798"));
            assert_eq!(f.llm_analysis.as_deref(), Some("analysis text"));
            assert_eq!(f.enclosing_context.as_deref(), Some("fn main() { ... }"));
            assert_eq!(f.suggested_fix.as_deref(), Some("-old\n+new"));
            assert_eq!(f.agent_prompt.as_deref(), Some("fix it"));
            assert!(f.graph_context.is_none());
            assert!(f.escalation_reasons.is_empty());
            assert!(f.is_new.is_none());
        }

        #[test]
        fn invalid_severity_falls_back_to_warning() {
            let mut sf = sample_stored_finding();
            sf.severity = "unknown_level".into();
            let findings = stored_to_findings(&[sf]);
            assert_eq!(
                findings[0].severity,
                cartomancer_core::severity::Severity::Warning
            );
        }

        #[test]
        fn parses_graph_context_json() {
            let mut sf = sample_stored_finding();
            sf.graph_context_json = Some(
                r#"{"symbol_name":"check","callers":["main"],"blast_radius":5,"is_public_api":true,"domain_tags":["auth"]}"#.into(),
            );
            let findings = stored_to_findings(&[sf]);
            let ctx = findings[0].graph_context.as_ref().unwrap();
            assert_eq!(ctx.blast_radius, 5);
            assert_eq!(ctx.callers, vec!["main"]);
            assert!(ctx.is_public_api);
        }

        #[test]
        fn parses_escalation_reasons_json() {
            let mut sf = sample_stored_finding();
            sf.escalation_reasons_json = Some(r#"["high blast radius","auth domain"]"#.into());
            let findings = stored_to_findings(&[sf]);
            assert_eq!(
                findings[0].escalation_reasons,
                vec!["high blast radius", "auth domain"]
            );
        }

        #[test]
        fn invalid_json_fields_are_none() {
            let mut sf = sample_stored_finding();
            sf.graph_context_json = Some("not json".into());
            sf.escalation_reasons_json = Some("{bad".into());
            let findings = stored_to_findings(&[sf]);
            assert!(findings[0].graph_context.is_none());
            assert!(findings[0].escalation_reasons.is_empty());
        }

        #[test]
        fn empty_input_returns_empty() {
            let findings = stored_to_findings(&[]);
            assert!(findings.is_empty());
        }
    }

    mod prepare_review_payload_tests {
        use super::*;
        use cartomancer_core::diff::{DiffChunk, PullRequestDiff};

        fn make_finding(file: &str, line: u32) -> Finding {
            Finding {
                rule_id: "test-rule".into(),
                message: "test finding".into(),
                severity: cartomancer_core::severity::Severity::Warning,
                file_path: file.into(),
                start_line: line,
                end_line: line + 1,
                snippet: "code".into(),
                cwe: None,
                graph_context: None,
                llm_analysis: None,
                escalation_reasons: vec![],
                is_new: None,
                enclosing_context: None,
                suggested_fix: None,
                agent_prompt: None,
            }
        }

        fn make_diff(file: &str, start: u32, lines: u32) -> PullRequestDiff {
            PullRequestDiff {
                chunks: vec![DiffChunk {
                    file_path: file.into(),
                    old_start: 1,
                    new_start: start,
                    old_lines: lines,
                    new_lines: lines,
                    content: String::new(),
                }],
                files_changed: vec![file.into()],
            }
        }

        fn make_result(findings: Vec<Finding>, diff: PullRequestDiff) -> PipelineResult {
            PipelineResult {
                review: ReviewResult {
                    pr_number: 1,
                    repo_full_name: "o/r".into(),
                    head_sha: "abc".into(),
                    findings,
                    summary: "original summary".into(),
                    status: ReviewStatus::Completed,
                },
                diff,
                branch: "feat".into(),
                base_branch: "main".into(),
                scan_duration: std::time::Duration::from_secs(1),
                rule_count: 5,
                scan_id: None,
                temp_dir: None,
            }
        }

        #[test]
        fn empty_findings_returns_original_summary() {
            let result = make_result(vec![], make_diff("a.rs", 1, 10));
            let payload = prepare_review_payload(&result);
            assert!(payload.inline_comments.is_empty());
            assert!(payload.off_diff_bodies.is_empty());
            assert_eq!(payload.summary, "original summary");
        }

        #[test]
        fn inline_finding_becomes_review_comment() {
            let diff = make_diff("src/lib.rs", 10, 5);
            let findings = vec![make_finding("src/lib.rs", 12)];
            let result = make_result(findings, diff);
            let payload = prepare_review_payload(&result);

            assert_eq!(payload.inline_comments.len(), 1);
            assert_eq!(payload.inline_comments[0].path, "src/lib.rs");
            assert_eq!(payload.inline_comments[0].line, 12);
            assert!(payload.off_diff_bodies.is_empty());
        }

        #[test]
        fn off_diff_finding_becomes_comment_body() {
            let diff = make_diff("src/lib.rs", 10, 5);
            // Finding at line 50, outside diff range 10..15
            let findings = vec![make_finding("src/lib.rs", 50)];
            let result = make_result(findings, diff);
            let payload = prepare_review_payload(&result);

            assert!(payload.inline_comments.is_empty());
            assert_eq!(payload.off_diff_bodies.len(), 1);
            // Summary is regenerated when off-diff findings exist
            assert_ne!(payload.summary, "original summary");
        }

        #[test]
        fn mixed_inline_and_off_diff() {
            let diff = make_diff("src/lib.rs", 10, 5);
            let findings = vec![
                make_finding("src/lib.rs", 12), // inline (in diff 10..15)
                make_finding("src/lib.rs", 50), // off-diff
                make_finding("other.rs", 1),    // off-diff (different file)
            ];
            let result = make_result(findings, diff);
            let payload = prepare_review_payload(&result);

            assert_eq!(payload.inline_comments.len(), 1);
            assert_eq!(payload.off_diff_bodies.len(), 2);
        }

        #[test]
        fn all_inline_keeps_original_summary() {
            let diff = make_diff("src/lib.rs", 1, 100);
            let findings = vec![
                make_finding("src/lib.rs", 10),
                make_finding("src/lib.rs", 20),
            ];
            let result = make_result(findings, diff);
            let payload = prepare_review_payload(&result);

            assert_eq!(payload.inline_comments.len(), 2);
            assert!(payload.off_diff_bodies.is_empty());
            assert_eq!(payload.summary, "original summary");
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
            scan_duration: std::time::Duration::from_secs(1),
            rule_count: 10,
            scan_id: None,
            temp_dir: None,
        };
        assert_eq!(result.review.pr_number, 42);
        assert_eq!(result.review.summary, "clean");
        assert!(result.diff.chunks.is_empty());
    }
}
