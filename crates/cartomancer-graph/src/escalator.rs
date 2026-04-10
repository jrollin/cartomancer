//! SeverityEscalator — escalation rules based on blast radius and domain detection.

use tracing::info;

use cartomancer_core::finding::Finding;
use cartomancer_core::severity::Severity;

/// Rules for escalating severity based on graph context.
pub struct SeverityEscalator {
    /// Blast radius threshold above which severity is escalated.
    pub blast_radius_threshold: u32,
}

impl SeverityEscalator {
    pub fn new(blast_radius_threshold: u32) -> Self {
        Self {
            blast_radius_threshold,
        }
    }

    /// Apply escalation rules to a single finding (mutates severity in place).
    pub fn escalate(&self, finding: &mut Finding) {
        let Some(ctx) = &finding.graph_context else {
            return;
        };

        // Snapshot values from the immutable borrow before mutating.
        let blast_radius = ctx.blast_radius;
        let has_auth = ctx.domain_tags.contains(&"auth".to_string());
        let has_payment = ctx.domain_tags.contains(&"payment".to_string());
        let caller_count = ctx.callers.len();

        // Large blast radius → escalate to at least Error
        if blast_radius >= self.blast_radius_threshold * 4 {
            upgrade(finding, Severity::Critical, "large blast radius");
        } else if blast_radius >= self.blast_radius_threshold {
            upgrade(finding, Severity::Error, "blast radius above threshold");
        }

        // Domain-sensitive: auth or payment → Critical
        if has_auth {
            upgrade(
                finding,
                Severity::Critical,
                "change propagates into authentication flow",
            );
        }
        if has_payment {
            upgrade(
                finding,
                Severity::Critical,
                "change propagates into payment flow",
            );
        }

        // Many callers → at least Error (public interface)
        if caller_count >= 10 {
            upgrade(
                finding,
                Severity::Error,
                "public interface with many callers",
            );
        }
    }

    /// Apply escalation rules to a batch.
    pub fn escalate_batch(&self, findings: &mut [Finding]) {
        let mut escalated_count = 0u32;
        for finding in findings.iter_mut() {
            let before = finding.severity;
            self.escalate(finding);
            if finding.severity > before {
                escalated_count += 1;
            }
        }
        if escalated_count > 0 {
            info!(escalated_count, "findings escalated by graph context");
        }
    }
}

/// Upgrade severity only if the new level is higher than the current one.
fn upgrade(finding: &mut Finding, target: Severity, reason: &str) {
    if target > finding.severity {
        info!(
            rule = %finding.rule_id,
            file = %finding.file_path,
            line = finding.start_line,
            from = %finding.severity,
            to = %target,
            reason,
            "severity escalated"
        );
        finding.severity = target;
        finding.escalation_reasons.push(reason.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cartomancer_core::finding::GraphContext;

    fn make_finding(severity: Severity, blast_radius: u32, domain_tags: Vec<String>) -> Finding {
        Finding {
            rule_id: "TEST-001".into(),
            message: "test".into(),
            severity,
            file_path: "src/lib.rs".into(),
            start_line: 1,
            end_line: 1,
            snippet: String::new(),
            cwe: None,
            graph_context: Some(GraphContext {
                symbol_name: Some("test_fn".into()),
                callers: vec![],
                blast_radius,
                is_public_api: false,
                domain_tags,
            }),
            llm_analysis: None,
            escalation_reasons: vec![],
        }
    }

    #[test]
    fn escalate_large_blast_radius() {
        let escalator = SeverityEscalator::new(5);
        let mut f = make_finding(Severity::Warning, 20, vec![]);
        escalator.escalate(&mut f);
        assert_eq!(f.severity, Severity::Critical);
    }

    #[test]
    fn escalate_auth_domain() {
        let escalator = SeverityEscalator::new(5);
        let mut f = make_finding(Severity::Warning, 1, vec!["auth".into()]);
        escalator.escalate(&mut f);
        assert_eq!(f.severity, Severity::Critical);
    }

    #[test]
    fn no_escalation_without_context() {
        let escalator = SeverityEscalator::new(5);
        let mut f = Finding {
            rule_id: "TEST-001".into(),
            message: "test".into(),
            severity: Severity::Warning,
            file_path: "src/lib.rs".into(),
            start_line: 1,
            end_line: 1,
            snippet: String::new(),
            cwe: None,
            graph_context: None,
            llm_analysis: None,
            escalation_reasons: vec![],
        };
        escalator.escalate(&mut f);
        assert_eq!(f.severity, Severity::Warning);
    }
}
