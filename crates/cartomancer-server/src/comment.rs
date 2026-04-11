//! Comment formatting for GitHub PR reviews.
//!
//! Converts findings into markdown comment bodies for inline review comments
//! and summary comments.

use std::fmt;
use std::time::Duration;

use cartomancer_core::finding::Finding;
use cartomancer_core::severity::Severity;

/// Category for review comment display (TD-4: pure display concern).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CommentCategory {
    Actionable,
    Nitpick,
}

impl fmt::Display for CommentCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Actionable => write!(f, "Actionable"),
            Self::Nitpick => write!(f, "Nitpick"),
        }
    }
}

/// Classify a finding into a comment category (BR-1, BR-2).
///
/// - **BR-1**: Actionable if it has a `suggested_fix` OR severity >= Error.
/// - **BR-2**: Nitpick if severity is Info or Warning AND no `suggested_fix`.
pub(crate) fn classify_finding(finding: &Finding) -> CommentCategory {
    if finding.suggested_fix.is_some() || finding.severity >= Severity::Error {
        CommentCategory::Actionable
    } else {
        CommentCategory::Nitpick
    }
}

/// Escape triple backtick sequences to prevent breaking fenced code blocks.
fn escape_fences(s: &str) -> String {
    s.replace("```", "` ` `")
}

/// Format an inline review comment body from a finding.
pub fn format_inline_comment(finding: &Finding) -> String {
    let category = classify_finding(finding);
    let mut body = format!(
        "**{}** _{category}_ `{}`\n\n{}\n",
        finding.severity.to_string().to_uppercase(),
        finding.rule_id,
        finding.message,
    );

    if !finding.snippet.is_empty() {
        body.push_str(&format!(
            "\n```\n{}\n```\n",
            escape_fences(finding.snippet.trim())
        ));
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

    if let Some(fix) = &finding.suggested_fix {
        body.push_str(&format!(
            "\n<details>\n<summary>\u{1f6e0}\u{fe0f} Suggested fix</summary>\n\n```diff\n{}\n```\n</details>\n",
            escape_fences(fix.trim())
        ));
    }

    if let Some(prompt) = &finding.agent_prompt {
        body.push_str(&format!(
            "\n<details>\n<summary>\u{1f916} Prompt for AI Agents</summary>\n\n```\n{}\n```\n</details>\n",
            escape_fences(prompt.trim())
        ));
    }

    if let Some(cwe) = &finding.cwe {
        body.push_str(&format!("\nCWE: {cwe}\n"));
    }

    body
}

/// Format an off-diff comment body with a caution banner.
pub fn format_off_diff_comment(finding: &Finding) -> String {
    format!(
        "> [!CAUTION]\n> This comment is outside the diff range and cannot be posted inline.\n> **{}:{}**\n\n{}",
        finding.file_path,
        finding.start_line,
        format_inline_comment(finding),
    )
}

/// Format a summary body for the PR review from all findings.
pub fn format_summary(
    findings: &[Finding],
    off_diff_findings: &[&Finding],
    scan_duration: Duration,
    rule_count: usize,
) -> String {
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

    let actionable_count = findings
        .iter()
        .filter(|f| classify_finding(f) == CommentCategory::Actionable)
        .count();
    let nitpick_count = total - actionable_count;

    let mut summary = format!(
        "## Cartomancer Review\n\n\
         **Actionable comments posted: {actionable_count}**\n\n\
         **{total}** findings | \
         Critical: **{critical}** | Error: **{error}** | Warning: **{warning}** | Info: **{info}**\n\
         Actionable: **{actionable_count}** | Nitpick: **{nitpick_count}**\n\n\
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
                "- **{}** `{}` in `{}:{}` \u{2014} {}\n",
                f.severity.to_string().to_uppercase(),
                f.rule_id,
                f.file_path,
                f.start_line,
                f.escalation_reasons.join("; "),
            ));
        }
    }

    if !off_diff_findings.is_empty() {
        let off_diff_count = off_diff_findings.len();
        summary.push_str(&format!(
            "\n<details>\n<summary>\u{26a0}\u{fe0f} Outside diff range comments ({off_diff_count})</summary>\n\n"
        ));
        for f in off_diff_findings {
            let truncated_msg: String = f.message.chars().take(80).collect();
            summary.push_str(&format!(
                "- **{}** `{}` in `{}:{}` \u{2014} {}\n",
                f.severity.to_string().to_uppercase(),
                f.rule_id,
                f.file_path,
                f.start_line,
                truncated_msg,
            ));
        }
        summary.push_str("\n</details>\n");
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
            enclosing_context: None,
            suggested_fix: None,
            agent_prompt: None,
        }
    }

    #[test]
    fn format_inline_comment_basic() {
        let f = make_finding();
        let body = format_inline_comment(&f);
        assert!(body.contains("**ERROR**"));
        assert!(body.contains("_Actionable_"));
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
        let summary = format_summary(&findings, &[], Duration::from_secs(5), 42);
        assert!(summary.contains("**Actionable comments posted: 2**"));
        assert!(summary.contains("**3** findings"));
        assert!(summary.contains("Critical: **1**"));
        assert!(summary.contains("Error: **1**"));
        assert!(summary.contains("Warning: **1**"));
        assert!(summary.contains("Actionable: **2** | Nitpick: **1**"));
        assert!(summary.contains("42 rule(s)"));
        assert!(summary.contains("### Escalated Findings"));
        assert!(summary.contains("auth domain"));
        // No off-diff section when empty
        assert!(!summary.contains("Outside diff range"));
    }

    #[test]
    fn format_summary_with_off_diff() {
        let findings = vec![make_finding()];
        let off_diff_finding = {
            let mut f = make_finding();
            f.severity = Severity::Warning;
            f.rule_id = "python.style.naming".into();
            f.file_path = "src/utils.py".into();
            f.start_line = 42;
            f.message = "Variable name too short".into();
            f
        };
        let off_diff = vec![&off_diff_finding];
        let summary = format_summary(&findings, &off_diff, Duration::from_secs(3), 10);
        assert!(summary.contains("Outside diff range comments (1)"));
        assert!(summary.contains("<details>"));
        assert!(summary.contains("**WARNING** `python.style.naming` in `src/utils.py:42`"));
        assert!(summary.contains("Variable name too short"));
        assert!(summary.contains("</details>"));
    }

    #[test]
    fn format_summary_actionable_count() {
        // Critical (actionable) + Warning without fix (nitpick) + Info with fix (actionable)
        let findings = vec![
            {
                let mut f = make_finding();
                f.severity = Severity::Critical;
                f
            },
            {
                let mut f = make_finding();
                f.severity = Severity::Warning;
                f.suggested_fix = None;
                f
            },
            {
                let mut f = make_finding();
                f.severity = Severity::Info;
                f.suggested_fix = Some("fix".into());
                f
            },
        ];
        let summary = format_summary(&findings, &[], Duration::from_secs(1), 5);
        // Critical + Info-with-fix = 2 actionable, Warning = 1 nitpick
        assert!(summary.contains("**Actionable comments posted: 2**"));
        assert!(summary.contains("Actionable: **2** | Nitpick: **1**"));
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

    #[test]
    fn classify_error_without_fix_is_actionable() {
        let mut f = make_finding();
        f.severity = Severity::Error;
        f.suggested_fix = None;
        assert_eq!(classify_finding(&f), CommentCategory::Actionable);
    }

    #[test]
    fn classify_critical_without_fix_is_actionable() {
        let mut f = make_finding();
        f.severity = Severity::Critical;
        f.suggested_fix = None;
        assert_eq!(classify_finding(&f), CommentCategory::Actionable);
    }

    #[test]
    fn classify_warning_with_fix_is_actionable() {
        let mut f = make_finding();
        f.severity = Severity::Warning;
        f.suggested_fix = Some("--- a/src/db.py\n+++ b/src/db.py".into());
        assert_eq!(classify_finding(&f), CommentCategory::Actionable);
    }

    #[test]
    fn classify_warning_without_fix_is_nitpick() {
        let mut f = make_finding();
        f.severity = Severity::Warning;
        f.suggested_fix = None;
        assert_eq!(classify_finding(&f), CommentCategory::Nitpick);
    }

    #[test]
    fn classify_info_without_fix_is_nitpick() {
        let mut f = make_finding();
        f.severity = Severity::Info;
        f.suggested_fix = None;
        assert_eq!(classify_finding(&f), CommentCategory::Nitpick);
    }

    #[test]
    fn classify_info_with_fix_is_actionable() {
        let mut f = make_finding();
        f.severity = Severity::Info;
        f.suggested_fix = Some("--- a/src/db.py\n+++ b/src/db.py".into());
        assert_eq!(classify_finding(&f), CommentCategory::Actionable);
    }

    #[test]
    fn format_inline_comment_with_suggested_fix() {
        let mut f = make_finding();
        f.suggested_fix = Some("--- a/src/db.py\n+++ b/src/db.py\n-bad\n+good".into());
        let body = format_inline_comment(&f);
        assert!(body.contains("<details>"));
        assert!(body.contains("Suggested fix"));
        assert!(body.contains("```diff"));
        assert!(body.contains("-bad"));
        assert!(body.contains("+good"));
    }

    #[test]
    fn format_inline_comment_with_agent_prompt() {
        let mut f = make_finding();
        f.agent_prompt = Some("Replace the f-string with parameterized query.".into());
        let body = format_inline_comment(&f);
        assert!(body.contains("<details>"));
        assert!(body.contains("Prompt for AI Agents"));
        assert!(body.contains("Replace the f-string with parameterized query."));
    }

    #[test]
    fn format_inline_comment_nitpick() {
        let mut f = make_finding();
        f.severity = Severity::Warning;
        f.suggested_fix = None;
        let body = format_inline_comment(&f);
        assert!(body.contains("_Nitpick_"));
    }

    #[test]
    fn format_inline_comment_no_fix_no_details() {
        let f = make_finding();
        let body = format_inline_comment(&f);
        assert!(!body.contains("<details>"));
    }

    #[test]
    fn format_inline_comment_escapes_backticks_in_snippet() {
        let mut f = make_finding();
        f.snippet = "let x = r#\"```\ninjection\n```\"#;".into();
        let body = format_inline_comment(&f);
        // The triple backticks should be escaped
        assert!(!body.contains("```\ninjection\n```"));
        assert!(body.contains("` ` `"));
    }

    #[test]
    fn format_off_diff_comment_has_caution_banner() {
        let f = make_finding();
        let body = format_off_diff_comment(&f);
        assert!(body.contains("[!CAUTION]"));
        assert!(body.contains("src/db.py:10"));
    }

    #[test]
    fn format_off_diff_comment_includes_inline_content() {
        let f = make_finding();
        let inline = format_inline_comment(&f);
        let body = format_off_diff_comment(&f);
        assert!(body.contains(&inline));
    }
}
