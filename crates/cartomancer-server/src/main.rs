//! Cartomancer — PR review tool with blast radius awareness.
//!
//! Single binary: serves webhooks, runs CLI commands, orchestrates the
//! opengrep -> cartog -> escalation -> LLM pipeline.

mod cli;
mod comment;
mod config;
mod llm;
mod opengrep;
mod pipeline;
mod webhook;

use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result};
use clap::Parser;
use tokio::sync::Semaphore;
use tracing::info;

use cartomancer_core::finding::Finding;
use cartomancer_core::severity::Severity;
use cartomancer_github::client::GitHubClient;
use cartomancer_graph::enricher::CartogEnricher;
use cartomancer_graph::escalator::SeverityEscalator;

use crate::cli::{Cli, Command, OutputFormat};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let config = config::load_config(&cli.config)?;

    match cli.command {
        Command::Scan { path, format } => cmd_scan(&path, &config, &format).await,
        Command::Serve { port } => cmd_serve(port, config).await,
        Command::Review {
            repo,
            pr,
            work_dir,
            dry_run,
            resume,
            format,
        } => {
            cmd_review(
                &repo,
                pr,
                work_dir.as_deref(),
                dry_run,
                resume,
                &format,
                &config,
            )
            .await
        }
        Command::History { branch, format } => cmd_history(branch.as_deref(), &format, &config),
        Command::Findings {
            scan_id,
            rule,
            severity,
            file,
            branch,
            format,
        } => cmd_findings(scan_id, rule, severity, file, branch, &format, &config),
        Command::Dismiss {
            scan_id,
            finding_index,
            reason,
        } => cmd_dismiss(scan_id, finding_index, reason, &config),
        Command::Dismissed { format } => cmd_dismissed(&format, &config),
        Command::Undismiss { dismissal_id } => cmd_undismiss(dismissal_id, &config),
    }
}

async fn cmd_review(
    repo: &str,
    pr: u64,
    work_dir: Option<&str>,
    dry_run: bool,
    resume_scan_id: Option<i64>,
    format: &OutputFormat,
    config: &cartomancer_core::config::AppConfig,
) -> Result<()> {
    // Resolve GitHub token
    let token = config
        .github
        .token
        .clone()
        .or_else(|| std::env::var("GITHUB_TOKEN").ok())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "GitHub token required: set GITHUB_TOKEN env var or github.token in config"
            )
        })?;

    let github = GitHubClient::new(&token);

    // Run the pipeline
    let mut result =
        pipeline::run_pipeline(config, &github, &token, repo, pr, work_dir, resume_scan_id).await?;

    if dry_run {
        // Dry run still annotates and filters, but doesn't post
        pipeline::annotate_regression(
            &config.storage.db_path,
            repo,
            &result.base_branch,
            &mut result.review.findings,
        );
        pipeline::filter_dismissed(&config.storage.db_path, &mut result.review.findings);

        // Recompute summary to reflect filtered findings
        let payload = pipeline::prepare_review_payload(&result);
        result.review.summary = payload.summary.clone();

        pipeline::persist_scan(
            &config.storage.db_path,
            repo,
            &result.branch,
            &result.review.head_sha,
            "review",
            Some(pr),
            &result.review,
        );

        match format {
            OutputFormat::Json => {
                println!("{}", serde_json::to_string_pretty(&result.review)?);
            }
            OutputFormat::Text => {
                if result.review.findings.is_empty() {
                    println!("{}", result.review.summary);
                } else {
                    println!("{}", payload.summary);
                    println!();
                    print_findings(&result.review.findings);
                    if !payload.off_diff_bodies.is_empty() {
                        println!("\n--- Off-diff findings ---\n");
                        for body in &payload.off_diff_bodies {
                            println!("{body}\n");
                        }
                    }
                }
            }
        }
        return Ok(());
    }

    // Post to GitHub (annotate, filter, persist, post)
    pipeline::finalize_and_post(config, &github, repo, pr, &mut result).await?;

    Ok(())
}

async fn cmd_serve(port: u16, config: cartomancer_core::config::AppConfig) -> Result<()> {
    config::validate_for_serve(&config)?;

    let webhook_secret = config
        .github
        .webhook_secret
        .clone()
        .or_else(|| std::env::var("CARTOMANCER_WEBHOOK_SECRET").ok())
        .expect("validated by validate_for_serve");

    let token = config
        .github
        .token
        .clone()
        .or_else(|| std::env::var("GITHUB_TOKEN").ok())
        .expect("validated by validate_for_serve");

    let max_reviews = config.serve.max_concurrent_reviews;

    let state = webhook::AppState {
        config: Arc::new(config),
        webhook_secret,
        github_token: token,
        review_semaphore: Arc::new(Semaphore::new(max_reviews)),
    };

    let app = webhook::router(state);
    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], port));
    info!(%addr, max_concurrent_reviews = max_reviews, "starting webhook server");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    info!("server shut down");
    Ok(())
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to listen for ctrl+c");
    info!("received shutdown signal");
}

async fn cmd_scan(
    target_dir: &str,
    config: &cartomancer_core::config::AppConfig,
    format: &OutputFormat,
) -> Result<()> {
    let scan_start = Instant::now();

    let target = std::fs::canonicalize(target_dir)
        .with_context(|| format!("resolving path: {target_dir}"))?;
    let target_str = target.to_string_lossy();

    info!(path = %target_str, "starting scan");

    // 1. Run opengrep
    let opengrep_start = Instant::now();
    let mut findings = opengrep::run_opengrep(&target_str, &config.opengrep, None).await?;
    let opengrep_elapsed = opengrep_start.elapsed();

    if findings.is_empty() {
        info!(
            elapsed_ms = opengrep_elapsed.as_millis() as u64,
            "scan complete, no findings"
        );

        // Persist even empty scans (AC-1.1)
        let review_for_persist = cartomancer_core::review::ReviewResult {
            pr_number: 0,
            repo_full_name: git_repo_name(&target).unwrap_or_default(),
            head_sha: git_head_sha(&target).unwrap_or_default(),
            findings: vec![],
            summary: "0 findings".into(),
            status: cartomancer_core::review::ReviewStatus::Completed,
        };
        pipeline::persist_scan(
            &config.storage.db_path,
            &review_for_persist.repo_full_name,
            &git_branch(&target).unwrap_or_else(|| "unknown".into()),
            &review_for_persist.head_sha,
            "scan",
            None,
            &review_for_persist,
        );

        println!("No findings from opengrep.");
        return Ok(());
    }

    log_severity_summary("after opengrep", &findings);

    // 2. Enrich with cartog (if indexed)
    let enrich_start = Instant::now();
    let db_path = target.join(".cartog.db");
    if db_path.exists() {
        match CartogEnricher::open(&db_path.to_string_lossy(), config.severity.impact_depth) {
            Ok(enricher) => {
                let mut enriched = 0u32;
                let mut failed = 0u32;
                for finding in &mut findings {
                    match enricher.enrich(finding) {
                        Ok(()) => {
                            if finding.graph_context.is_some() {
                                enriched += 1;
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
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
                info!(
                    enriched,
                    failed,
                    elapsed_ms = enrich_start.elapsed().as_millis() as u64,
                    "graph enrichment complete"
                );
            }
            Err(e) => {
                tracing::warn!(
                    path = %db_path.display(),
                    err = %e,
                    "could not open cartog database, skipping enrichment"
                );
            }
        }
    } else {
        info!("no .cartog.db found, skipping graph enrichment (run `cartog index .` first)");
    }

    // 3. Escalate severity
    let escalate_start = Instant::now();
    let escalator = SeverityEscalator::new(config.severity.blast_radius_threshold);
    escalator.escalate_batch(&mut findings);
    info!(
        elapsed_ms = escalate_start.elapsed().as_millis() as u64,
        "severity escalation complete"
    );

    log_severity_summary("after escalation", &findings);

    // 4. LLM deepening (conditional)
    let llm_start = Instant::now();
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
        info!(
            threshold = %threshold,
            "no findings qualify for LLM deepening"
        );
    } else {
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
                            info!(
                                rule = %finding.rule_id,
                                file = %finding.file_path,
                                "finding deepened"
                            );
                        }
                        Err(e) => {
                            tracing::warn!(
                                rule = %finding.rule_id,
                                file = %finding.file_path,
                                err = %e,
                                "LLM deepening failed for finding, skipping"
                            );
                            failed += 1;
                        }
                    }
                }
                info!(
                    deepened,
                    failed,
                    skipped = (candidates.len() as u32).saturating_sub(deepened + failed),
                    elapsed_ms = llm_start.elapsed().as_millis() as u64,
                    "LLM deepening complete"
                );
            }
            Err(e) => {
                tracing::warn!(
                    err = %e,
                    candidates = candidates.len(),
                    "could not create LLM provider, skipping deepening"
                );
            }
        }
    }

    log_severity_summary("final", &findings);

    // 5. Sort by severity (critical first)
    findings.sort_by(|a, b| b.severity.cmp(&a.severity));

    // 6. Persist scan results (BR-3: best-effort)
    let review_for_persist = cartomancer_core::review::ReviewResult {
        pr_number: 0,
        repo_full_name: git_repo_name(&target).unwrap_or_default(),
        head_sha: git_head_sha(&target).unwrap_or_default(),
        findings: findings.clone(),
        summary: format!("{} findings", findings.len()),
        status: cartomancer_core::review::ReviewStatus::Completed,
    };
    pipeline::persist_scan(
        &config.storage.db_path,
        &review_for_persist.repo_full_name,
        &git_branch(&target).unwrap_or_else(|| "unknown".into()),
        &review_for_persist.head_sha,
        "scan",
        None,
        &review_for_persist,
    );

    // 7. Output
    match format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&findings)?);
        }
        OutputFormat::Text => {
            print_findings(&findings);
        }
    }

    info!(
        total_elapsed_ms = scan_start.elapsed().as_millis() as u64,
        findings = findings.len(),
        "scan complete"
    );

    Ok(())
}

fn cmd_history(
    branch: Option<&str>,
    format: &OutputFormat,
    config: &cartomancer_core::config::AppConfig,
) -> Result<()> {
    let store = match cartomancer_store::store::Store::open(&config.storage.db_path) {
        Ok(s) => s,
        Err(_) => {
            println!("No scan history found.");
            return Ok(());
        }
    };

    let filter = cartomancer_store::types::ScanFilter {
        branch: branch.map(|s| s.to_string()),
        ..Default::default()
    };
    let scans = store.list_scans(&filter)?;

    if scans.is_empty() {
        println!("No scan history found.");
        return Ok(());
    }

    match format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&scans)?);
        }
        OutputFormat::Text => {
            println!(
                "{:<6} {:<20} {:<20} {:<10} {:<8} Command",
                "ID", "Timestamp", "Branch", "SHA", "Count"
            );
            let sep = "-".repeat(80);
            println!("{sep}");
            for scan in &scans {
                let sha_short = if scan.commit_sha.len() > 7 {
                    &scan.commit_sha[..7]
                } else {
                    &scan.commit_sha
                };
                println!(
                    "{:<6} {:<20} {:<20} {:<10} {:<8} {}",
                    scan.id.unwrap_or(0),
                    scan.created_at.as_deref().unwrap_or("-"),
                    scan.branch,
                    sha_short,
                    scan.finding_count,
                    scan.command,
                );
            }
        }
    }

    Ok(())
}

fn cmd_findings(
    scan_id: Option<i64>,
    rule: Option<String>,
    severity: Option<String>,
    file: Option<String>,
    branch: Option<String>,
    format: &OutputFormat,
    config: &cartomancer_core::config::AppConfig,
) -> Result<()> {
    let store = cartomancer_store::store::Store::open(&config.storage.db_path)?;

    let findings = if let Some(id) = scan_id {
        let results = store.get_findings(id)?;
        if results.is_empty() {
            anyhow::bail!(
                "No findings found for scan ID {id}. Check the ID with `cartomancer history`."
            );
        }
        results
    } else {
        let filter = cartomancer_store::types::FindingFilter {
            rule,
            severity,
            file,
            branch,
        };
        store.search_findings(&filter)?
    };

    if findings.is_empty() {
        println!("No findings match the given filters.");
        return Ok(());
    }

    match format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&findings)?);
        }
        OutputFormat::Text => {
            for (i, f) in findings.iter().enumerate() {
                println!(
                    "{}. [{}] {} ({}:{})",
                    i + 1,
                    f.severity.to_uppercase(),
                    f.rule_id,
                    f.file_path,
                    f.start_line,
                );
                println!(
                    "   Scan: {} | Fingerprint: {}…",
                    f.scan_id,
                    f.fingerprint.get(..12).unwrap_or(&f.fingerprint)
                );
                println!("   {}", f.message);
                if !f.snippet.is_empty() {
                    println!("   > {}", f.snippet.trim());
                }
                if let Some(ref cwe) = f.cwe {
                    println!("   CWE: {cwe}");
                }
                if let Some(ref analysis) = f.llm_analysis {
                    println!("   Analysis: {}", analysis.trim());
                }
                println!();
            }
        }
    }

    Ok(())
}

fn cmd_dismiss(
    scan_id: i64,
    finding_index: usize,
    reason: Option<String>,
    config: &cartomancer_core::config::AppConfig,
) -> Result<()> {
    let store = cartomancer_store::store::Store::open(&config.storage.db_path)?;
    let findings = store.get_findings(scan_id)?;

    if findings.is_empty() {
        anyhow::bail!("No findings found for scan ID {scan_id}.");
    }
    if finding_index == 0 || finding_index > findings.len() {
        anyhow::bail!(
            "Finding index {finding_index} out of range. Valid range: 1..{}",
            findings.len()
        );
    }

    let f = &findings[finding_index - 1];
    let dismissal = cartomancer_store::types::Dismissal {
        id: None,
        fingerprint: f.fingerprint.clone(),
        rule_id: f.rule_id.clone(),
        file_path: f.file_path.clone(),
        start_line: f.start_line,
        end_line: f.end_line,
        snippet_hash: cartomancer_store::fingerprint::snippet_hash(&f.snippet),
        reason,
        created_at: None,
    };

    let id = store.dismiss(&dismissal)?;
    println!(
        "Dismissed finding #{finding_index} (rule: {}, file: {}). Dismissal ID: {id}",
        f.rule_id, f.file_path
    );

    Ok(())
}

fn cmd_dismissed(
    format: &OutputFormat,
    config: &cartomancer_core::config::AppConfig,
) -> Result<()> {
    let store = cartomancer_store::store::Store::open(&config.storage.db_path)?;
    let dismissals = store.list_dismissals()?;

    if dismissals.is_empty() {
        println!("No dismissed findings.");
        return Ok(());
    }

    match format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&dismissals)?);
        }
        OutputFormat::Text => {
            println!(
                "{:<6} {:<30} {:<30} {:<20} Reason",
                "ID", "Rule", "File", "Dismissed At"
            );
            let sep = "-".repeat(100);
            println!("{sep}");
            for d in &dismissals {
                println!(
                    "{:<6} {:<30} {:<30} {:<20} {}",
                    d.id.unwrap_or(0),
                    &d.rule_id,
                    &d.file_path,
                    d.created_at.as_deref().unwrap_or("-"),
                    d.reason.as_deref().unwrap_or("-"),
                );
            }
        }
    }

    Ok(())
}

fn cmd_undismiss(dismissal_id: i64, config: &cartomancer_core::config::AppConfig) -> Result<()> {
    let store = cartomancer_store::store::Store::open(&config.storage.db_path)?;
    store
        .undismiss(dismissal_id)
        .map_err(|e| anyhow::anyhow!("failed to undismiss {dismissal_id}: {e}"))?;
    println!("Dismissal {dismissal_id} removed.");
    Ok(())
}

/// Get the current git branch name, or None if not in a git repo.
fn git_branch(dir: &Path) -> Option<String> {
    std::process::Command::new("git")
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .current_dir(dir)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
}

/// Get the current git HEAD SHA, or None if not in a git repo.
fn git_head_sha(dir: &Path) -> Option<String> {
    std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(dir)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
}

/// Get the remote origin URL as "owner/repo" format, or None.
fn git_repo_name(dir: &Path) -> Option<String> {
    std::process::Command::new("git")
        .args(["remote", "get-url", "origin"])
        .current_dir(dir)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| {
            let url = String::from_utf8_lossy(&o.stdout).trim().to_string();
            parse_repo_name(&url)
        })
}

/// Extract "owner/repo" from a git remote URL.
fn parse_repo_name(url: &str) -> Option<String> {
    let cleaned = url.trim_end_matches(".git");
    // SSH: git@github.com:owner/repo
    if cleaned.contains(':') && !cleaned.contains("://") {
        return cleaned.rsplit(':').next().map(|s| s.to_string());
    }
    // HTTPS: https://github.com/owner/repo
    let parts: Vec<&str> = cleaned.rsplitn(3, '/').collect();
    if parts.len() >= 2 {
        Some(format!("{}/{}", parts[1], parts[0]))
    } else {
        None
    }
}

fn log_severity_summary(label: &str, findings: &[Finding]) {
    let critical = findings
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .count();
    let error = findings
        .iter()
        .filter(|f| f.severity == Severity::Error)
        .count();
    let warning = findings
        .iter()
        .filter(|f| f.severity == Severity::Warning)
        .count();
    let info_count = findings
        .iter()
        .filter(|f| f.severity == Severity::Info)
        .count();

    info!(
        phase = label,
        total = findings.len(),
        critical,
        error,
        warning,
        info = info_count,
        "findings summary"
    );
}

fn print_findings(findings: &[Finding]) {
    let critical = findings
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .count();
    let error = findings
        .iter()
        .filter(|f| f.severity == Severity::Error)
        .count();
    let warning = findings
        .iter()
        .filter(|f| f.severity == Severity::Warning)
        .count();
    let info_count = findings
        .iter()
        .filter(|f| f.severity == Severity::Info)
        .count();

    println!("=== Cartomancer Scan Results ===\n");
    println!(
        "  Critical: {}  Error: {}  Warning: {}  Info: {}\n",
        critical, error, warning, info_count
    );

    for (i, f) in findings.iter().enumerate() {
        println!(
            "{}. [{}] {} ({})",
            i + 1,
            f.severity.to_string().to_uppercase(),
            f.rule_id,
            f.file_path
        );
        println!("   Line {}: {}", f.start_line, f.message);

        if !f.snippet.is_empty() {
            println!("   > {}", f.snippet.trim());
        }

        if let Some(ctx) = &f.graph_context {
            if ctx.blast_radius > 0 {
                println!(
                    "   Blast radius: {} symbols | Callers: {}",
                    ctx.blast_radius,
                    ctx.callers.len()
                );
            }
            if !ctx.domain_tags.is_empty() {
                println!("   Domain: {}", ctx.domain_tags.join(", "));
            }
        }

        if !f.escalation_reasons.is_empty() {
            println!("   Escalated: {}", f.escalation_reasons.join("; "));
        }

        if let Some(cwe) = &f.cwe {
            println!("   CWE: {cwe}");
        }

        if let Some(analysis) = &f.llm_analysis {
            println!("   Analysis: {}", analysis.trim());
        }

        println!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_repo_name_https() {
        assert_eq!(
            parse_repo_name("https://github.com/owner/repo.git"),
            Some("owner/repo".into())
        );
    }

    #[test]
    fn parse_repo_name_https_no_suffix() {
        assert_eq!(
            parse_repo_name("https://github.com/owner/repo"),
            Some("owner/repo".into())
        );
    }

    #[test]
    fn parse_repo_name_ssh() {
        assert_eq!(
            parse_repo_name("git@github.com:owner/repo.git"),
            Some("owner/repo".into())
        );
    }

    #[test]
    fn parse_repo_name_ssh_no_suffix() {
        assert_eq!(
            parse_repo_name("git@github.com:owner/repo"),
            Some("owner/repo".into())
        );
    }

    #[test]
    fn parse_repo_name_https_with_port() {
        assert_eq!(
            parse_repo_name("https://github.com:8080/owner/repo.git"),
            Some("owner/repo".into())
        );
    }

    #[test]
    fn parse_repo_name_bare_string_returns_none() {
        assert_eq!(parse_repo_name("noslash"), None);
    }
}
