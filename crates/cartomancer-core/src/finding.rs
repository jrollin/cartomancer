//! Opengrep finding representation and enrichment data.

use serde::{Deserialize, Serialize};

use crate::severity::Severity;

/// A finding from opengrep, potentially enriched with graph context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub message: String,
    pub severity: Severity,
    pub file_path: String,
    pub start_line: u32,
    pub end_line: u32,
    pub snippet: String,
    /// CWE identifier if available (e.g. "CWE-89").
    pub cwe: Option<String>,
    /// Graph enrichment (populated by cartomancer-graph).
    pub graph_context: Option<GraphContext>,
    /// LLM deepening analysis (populated when severity >= threshold).
    pub llm_analysis: Option<String>,
    /// Reasons severity was escalated from original.
    pub escalation_reasons: Vec<String>,
    /// Regression annotation: `Some(true)` = new finding, `Some(false)` = existing in baseline.
    /// `None` when regression detection was not performed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_new: Option<bool>,
}

/// Blast radius and caller context from cartog.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphContext {
    pub symbol_name: Option<String>,
    pub callers: Vec<String>,
    pub blast_radius: u32,
    pub is_public_api: bool,
    /// Domain tags detected from symbol graph (e.g. "auth", "payment").
    pub domain_tags: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finding_default_has_no_enrichment() {
        let f = Finding {
            rule_id: "TEST-001".into(),
            message: "test finding".into(),
            severity: Severity::Warning,
            file_path: "src/lib.rs".into(),
            start_line: 10,
            end_line: 10,
            snippet: "let x = 1;".into(),
            cwe: None,
            graph_context: None,
            llm_analysis: None,
            escalation_reasons: vec![],
            is_new: None,
        };
        assert!(f.graph_context.is_none());
        assert!(f.llm_analysis.is_none());
        assert!(f.escalation_reasons.is_empty());
    }
}
