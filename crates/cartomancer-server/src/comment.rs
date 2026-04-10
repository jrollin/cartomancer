//! Comment formatting for GitHub PR reviews.
//!
//! Converts findings into markdown comment bodies for inline review comments
//! and summary comments.

use std::time::Duration;

use cartomancer_core::finding::Finding;
use cartomancer_core::severity::Severity;

/// Format an inline review comment body from a finding.
pub fn format_inline_comment(finding: &Finding) -> String {
    let mut body = format!(
        "**{}** `{}`\n\n{}\n",
        finding.severity.to_string().to_uppercase(),
        finding.rule_id,
        finding.message,
    );

    if !finding.snippet.is_empty() {
        body.push_str(&format!("\n```\n{}\n```\n", finding.snippet.trim()));
    }

    if let Some(ctx) = &finding.graph_context {
        if ctx.blast_radius > 0 {
            body.push_str(&format!(
                "\n**Blast radius**: {} symbols | **Callers**: {}\n",
                ctx.blast_radius,
                ctx.callers.len()
            ));
        }
        if !ctx.domain_tags.is_empty() {
            body.push_str(&format!("**Domain**: {}\n", ctx.domain_tags.join(", ")));
        }
    }

    if !finding.escalation_reasons.is_empty() {
        body.push_str(&format!(
            "\n> Escalated: {}\n",
            finding.escalation_reasons.join("; ")
        ));
    }

    if let Some(analysis) = &finding.llm_analysis {
        body.push_str(&format!("\n**Analysis**: {}\n", analysis.trim()));
    }

    if let Some(cwe) = &finding.cwe {
        body.push_str(&format!("\nCWE: {cwe}\n"));
    }

    body
}

/// Format a summary body for the PR review from all findings.
pub fn format_summary(findings: &[Finding], scan_duration: Duration, rule_count: usize) -> String {
    let total = findings.len();
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
    let info = findings
        .iter()
        .filter(|f| f.severity == Severity::Info)
        .count();

    let mut summary = format!(
        "## Cartomancer Review\n\n\
         **{total}** findings | \
         Critical: **{critical}** | Error: **{error}** | Warning: **{warning}** | Info: **{info}**\n\n\
         Scanned in {:.1}s with {rule_count} rule(s).\n",
        scan_duration.as_secs_f64(),
    );

    // Highlight top escalated findings
    let escalated: Vec<&Finding> = findings
        .iter()
        .filter(|f| !f.escalation_reasons.is_empty())
        .take(5)
        .collect();

    if !escalated.is_empty() {
        summary.push_str("\n### Escalated Findings\n\n");
        for f in &escalated {
            summary.push_str(&format!(
                "- **{}** `{}` in `{}:{}` — {}\n",
                f.severity.to_string().to_uppercase(),
                f.rule_id,
                f.file_path,
                f.start_line,
                f.escalation_reasons.join("; "),
            ));
        }
    }

    summary
}

/// Format a clean scan summary comment (zero findings).
pub fn format_clean_summary(scan_duration: Duration, rule_count: usize) -> String {
    format!(
        "## Cartomancer Review\n\n\
         No findings detected.\n\n\
         Scanned in {:.1}s with {rule_count} rule(s).",
        scan_duration.as_secs_f64(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use cartomancer_core::finding::GraphContext;

    fn make_finding() -> Finding {
        Finding {
            rule_id: "python.security.sql-injection".into(),
            message: "Possible SQL injection".into(),
            severity: Severity::Error,
            file_path: "src/db.py".into(),
            start_line: 10,
            end_line: 10,
            snippet: "db.execute(f\"SELECT * WHERE id={user_id}\")".into(),
            cwe: Some("CWE-89".into()),
            graph_context: None,
            llm_analysis: None,
            escalation_reasons: vec![],
            is_new: None,
        }
    }

    #[test]
    fn format_inline_comment_basic() {
        let f = make_finding();
        let body = format_inline_comment(&f);
        assert!(body.contains("**ERROR**"));
        assert!(body.contains("`python.security.sql-injection`"));
        assert!(body.contains("Possible SQL injection"));
        assert!(body.contains("CWE-89"));
    }

    #[test]
    fn format_inline_comment_with_snippet() {
        let f = make_finding();
        let body = format_inline_comment(&f);
        assert!(body.contains("```"));
        assert!(body.contains("db.execute"));
    }

    #[test]
    fn format_inline_comment_with_graph_context() {
        let mut f = make_finding();
        f.graph_context = Some(GraphContext {
            symbol_name: Some("execute_query".into()),
            callers: vec!["handler_a".into(), "handler_b".into()],
            blast_radius: 15,
            is_public_api: true,
            domain_tags: vec!["auth".into()],
        });
        let body = format_inline_comment(&f);
        assert!(body.contains("**Blast radius**: 15"));
        assert!(body.contains("**Callers**: 2"));
        assert!(body.contains("**Domain**: auth"));
    }

    #[test]
    fn format_inline_comment_with_escalation() {
        let mut f = make_finding();
        f.escalation_reasons = vec!["blast radius above threshold".into()];
        let body = format_inline_comment(&f);
        assert!(body.contains("Escalated: blast radius above threshold"));
    }

    #[test]
    fn format_inline_comment_with_llm_analysis() {
        let mut f = make_finding();
        f.llm_analysis = Some("This SQL injection is reachable from the auth flow.".into());
        let body = format_inline_comment(&f);
        assert!(body.contains("**Analysis**: This SQL injection"));
    }

    #[test]
    fn format_summary_with_findings() {
        let findings = vec![
            {
                let mut f = make_finding();
                f.severity = Severity::Critical;
                f.escalation_reasons = vec!["auth domain".into()];
                f
            },
            make_finding(),
            {
                let mut f = make_finding();
                f.severity = Severity::Warning;
                f
            },
        ];
        let summary = format_summary(&findings, Duration::from_secs(5), 42);
        assert!(summary.contains("**3** findings"));
        assert!(summary.contains("Critical: **1**"));
        assert!(summary.contains("Error: **1**"));
        assert!(summary.contains("Warning: **1**"));
        assert!(summary.contains("42 rule(s)"));
        assert!(summary.contains("### Escalated Findings"));
        assert!(summary.contains("auth domain"));
    }

    #[test]
    fn format_clean_summary_content() {
        let summary = format_clean_summary(Duration::from_millis(2500), 10);
        assert!(summary.contains("No findings detected"));
        assert!(summary.contains("2.5s"));
        assert!(summary.contains("10 rule(s)"));
    }

    #[test]
    fn format_inline_comment_empty_snippet() {
        let mut f = make_finding();
        f.snippet = String::new();
        let body = format_inline_comment(&f);
        assert!(!body.contains("```"));
    }
}
