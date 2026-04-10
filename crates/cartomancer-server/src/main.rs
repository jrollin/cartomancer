//! Cartomancer — PR review tool with blast radius awareness.
//!
//! Single binary: serves webhooks, runs CLI commands, orchestrates the
//! Semgrep -> cartog -> escalation -> LLM pipeline.

mod cli;
mod config;
mod llm;
mod pipeline;
mod semgrep;
mod webhook;

use std::time::Instant;

use anyhow::{Context, Result};
use clap::Parser;
use tracing::info;

use cartomancer_core::finding::Finding;
use cartomancer_core::severity::Severity;
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
        Command::Serve { port } => {
            todo!("webhook server on port {port}")
        }
        Command::Review { repo, pr } => {
            todo!("GitHub PR review for {repo}#{pr}")
        }
    }
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

    // 1. Run semgrep
    let semgrep_start = Instant::now();
    let mut findings = semgrep::run_semgrep(
        &target_str,
        &config.semgrep.rules,
        None,
        config.semgrep.timeout_seconds,
    )
    .await?;
    let semgrep_elapsed = semgrep_start.elapsed();

    if findings.is_empty() {
        info!(
            elapsed_ms = semgrep_elapsed.as_millis() as u64,
            "scan complete, no findings"
        );
        println!("No findings from semgrep.");
        return Ok(());
    }

    log_severity_summary("after semgrep", &findings);

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
                    skipped = candidates.len() as u32 - deepened - failed,
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

    // 6. Output
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
