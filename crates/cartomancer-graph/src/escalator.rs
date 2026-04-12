//! SeverityEscalator — escalation rules based on blast radius and domain detection.

use std::collections::HashMap;

use tracing::info;

use cartomancer_core::config::RuleOverride;
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
    ///
    /// When `rule_overrides` contains an entry for the finding's `rule_id`:
    /// - `min_severity` is applied as a floor **before** other escalation
    /// - `max_severity` is applied as a ceiling **after** all escalation
    pub fn escalate(&self, finding: &mut Finding, rule_overrides: &HashMap<String, RuleOverride>) {
        // Apply min_severity floor from rule override (before other escalation)
        if let Some(rule_cfg) = rule_overrides.get(&finding.rule_id) {
            if let Some(min) = rule_cfg.min_severity {
                if min > finding.severity {
                    upgrade(finding, min, "rule-specific minimum severity");
                }
            }
        }

        let Some(ctx) = &finding.graph_context else {
            // Apply max_severity ceiling even without graph context
            self.apply_max_severity(finding, rule_overrides);
            return;
        };

        // Snapshot values from the immutable borrow before mutating.
        let blast_radius = ctx.blast_radius;
        let has_auth = ctx.domain_tags.iter().any(|t| t == "auth");
        let has_payment = ctx.domain_tags.iter().any(|t| t == "payment");
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

        // Apply max_severity ceiling from rule override (after all escalation)
        self.apply_max_severity(finding, rule_overrides);
    }

    /// Apply max_severity ceiling from rule overrides.
    fn apply_max_severity(
        &self,
        finding: &mut Finding,
        rule_overrides: &HashMap<String, RuleOverride>,
    ) {
        if let Some(rule_cfg) = rule_overrides.get(&finding.rule_id) {
            if let Some(max) = rule_cfg.max_severity {
                if finding.severity > max {
                    finding.severity = max;
                    finding
                        .escalation_reasons
                        .push(format!("capped at {max} by rule override"));
                }
            }
        }
    }

    /// Apply escalation rules to a batch.
    pub fn escalate_batch(
        &self,
        findings: &mut [Finding],
        rule_overrides: &HashMap<String, RuleOverride>,
    ) {
        let mut escalated_count = 0u32;
        for finding in findings.iter_mut() {
            let before = finding.severity;
            self.escalate(finding, rule_overrides);
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

    fn no_overrides() -> HashMap<String, RuleOverride> {
        HashMap::new()
    }

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
            is_new: None,
            enclosing_context: None,
            suggested_fix: None,
            agent_prompt: None,
        }
    }

    #[test]
    fn escalate_large_blast_radius() {
        let escalator = SeverityEscalator::new(5);
        let mut f = make_finding(Severity::Warning, 20, vec![]);
        escalator.escalate(&mut f, &no_overrides());
        assert_eq!(f.severity, Severity::Critical);
    }

    #[test]
    fn escalate_auth_domain() {
        let escalator = SeverityEscalator::new(5);
        let mut f = make_finding(Severity::Warning, 1, vec!["auth".into()]);
        escalator.escalate(&mut f, &no_overrides());
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
            is_new: None,
            enclosing_context: None,
            suggested_fix: None,
            agent_prompt: None,
        };
        escalator.escalate(&mut f, &no_overrides());
        assert_eq!(f.severity, Severity::Warning);
    }

    #[test]
    fn threshold_exact_match_escalates_to_error() {
        let escalator = SeverityEscalator::new(5);
        let mut f = make_finding(Severity::Warning, 5, vec![]);
        escalator.escalate(&mut f, &no_overrides());
        assert_eq!(f.severity, Severity::Error);
    }

    #[test]
    fn just_below_threshold_no_escalation() {
        let escalator = SeverityEscalator::new(5);
        let mut f = make_finding(Severity::Warning, 4, vec![]);
        escalator.escalate(&mut f, &no_overrides());
        assert_eq!(f.severity, Severity::Warning);
    }

    #[test]
    fn blast_radius_between_threshold_and_4x_escalates_to_error() {
        let escalator = SeverityEscalator::new(5);
        // 15 is >= 5 but < 20, so Error not Critical
        let mut f = make_finding(Severity::Info, 15, vec![]);
        escalator.escalate(&mut f, &no_overrides());
        assert_eq!(f.severity, Severity::Error);
    }

    #[test]
    fn escalate_payment_domain() {
        let escalator = SeverityEscalator::new(5);
        let mut f = make_finding(Severity::Warning, 1, vec!["payment".into()]);
        escalator.escalate(&mut f, &no_overrides());
        assert_eq!(f.severity, Severity::Critical);
    }

    #[test]
    fn escalate_many_callers() {
        let escalator = SeverityEscalator::new(5);
        let mut f = make_finding(Severity::Info, 1, vec![]);
        f.graph_context.as_mut().unwrap().callers =
            (0..10).map(|i| format!("caller_{i}")).collect();
        escalator.escalate(&mut f, &no_overrides());
        assert_eq!(f.severity, Severity::Error);
    }

    #[test]
    fn nine_callers_no_escalation_from_caller_rule() {
        let escalator = SeverityEscalator::new(5);
        let mut f = make_finding(Severity::Info, 1, vec![]);
        f.graph_context.as_mut().unwrap().callers = (0..9).map(|i| format!("caller_{i}")).collect();
        escalator.escalate(&mut f, &no_overrides());
        assert_eq!(f.severity, Severity::Info);
    }

    #[test]
    fn auth_overrides_blast_radius_error() {
        let escalator = SeverityEscalator::new(5);
        // blast_radius=6 → Error, then auth → Critical
        let mut f = make_finding(Severity::Warning, 6, vec!["auth".into()]);
        escalator.escalate(&mut f, &no_overrides());
        assert_eq!(f.severity, Severity::Critical);
        assert!(f.escalation_reasons.len() >= 2);
    }

    #[test]
    fn escalate_batch_counts_correctly() {
        let escalator = SeverityEscalator::new(5);
        let mut findings = vec![
            make_finding(Severity::Warning, 20, vec![]), // → Critical
            make_finding(Severity::Warning, 1, vec![]),  // no escalation
            make_finding(Severity::Critical, 20, vec![]), // already Critical
        ];
        escalator.escalate_batch(&mut findings, &no_overrides());
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[1].severity, Severity::Warning);
        assert_eq!(findings[2].severity, Severity::Critical);
    }

    #[test]
    fn escalation_reasons_accumulated() {
        let escalator = SeverityEscalator::new(5);
        let mut f = make_finding(Severity::Info, 6, vec!["auth".into(), "payment".into()]);
        escalator.escalate(&mut f, &no_overrides());
        assert_eq!(f.severity, Severity::Critical);
        // blast_radius >= threshold → Error, auth → Critical, payment → already Critical (no new reason)
        assert!(f.escalation_reasons.len() >= 2);
    }

    #[test]
    fn rule_override_min_severity_floor() {
        let escalator = SeverityEscalator::new(5);
        let mut f = make_finding(Severity::Info, 1, vec![]);
        let mut overrides = HashMap::new();
        overrides.insert(
            "TEST-001".into(),
            RuleOverride {
                min_severity: Some(Severity::Error),
                max_severity: None,
                always_deepen: false,
            },
        );
        escalator.escalate(&mut f, &overrides);
        assert_eq!(f.severity, Severity::Error);
        assert!(f.escalation_reasons.iter().any(|r| r.contains("minimum")));
    }

    #[test]
    fn rule_override_max_severity_ceiling() {
        let escalator = SeverityEscalator::new(5);
        // blast_radius=20 would normally escalate to Critical
        let mut f = make_finding(Severity::Warning, 20, vec![]);
        let mut overrides = HashMap::new();
        overrides.insert(
            "TEST-001".into(),
            RuleOverride {
                min_severity: None,
                max_severity: Some(Severity::Error),
                always_deepen: false,
            },
        );
        escalator.escalate(&mut f, &overrides);
        assert_eq!(f.severity, Severity::Error);
        assert!(f.escalation_reasons.iter().any(|r| r.contains("capped")));
    }

    #[test]
    fn rule_override_unmatched_rule_id_ignored() {
        let escalator = SeverityEscalator::new(5);
        let mut f = make_finding(Severity::Info, 1, vec![]);
        let mut overrides = HashMap::new();
        overrides.insert(
            "OTHER-RULE".into(),
            RuleOverride {
                min_severity: Some(Severity::Critical),
                max_severity: None,
                always_deepen: false,
            },
        );
        escalator.escalate(&mut f, &overrides);
        // Should not be affected — rule_id doesn't match
        assert_eq!(f.severity, Severity::Info);
    }
}
