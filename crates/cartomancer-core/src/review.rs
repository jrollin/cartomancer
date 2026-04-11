//! Review state and final output types.

use serde::{Deserialize, Serialize};

use crate::finding::Finding;

/// State of a review as it progresses through the pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReviewStatus {
    Pending,
    DiffFetched,
    OpengrepScanned,
    GraphEnriched,
    SeverityEscalated,
    LlmDeepened,
    Completed,
    Failed { reason: String },
}

/// Pipeline stage for store-backed resumability.
///
/// Tracks how far a scan has progressed through the pipeline.
/// Stages are ordered: each stage implies all prior stages are complete.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PipelineStage {
    Pending,
    Scanned,
    Enriched,
    Escalated,
    Deepened,
    Completed,
    Failed,
}

impl PipelineStage {
    /// Parse from a database string value.
    pub fn from_db(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(Self::Pending),
            "scanned" => Some(Self::Scanned),
            "enriched" => Some(Self::Enriched),
            "escalated" => Some(Self::Escalated),
            "deepened" => Some(Self::Deepened),
            "completed" => Some(Self::Completed),
            "failed" => Some(Self::Failed),
            _ => None,
        }
    }

    /// Convert to a database string value.
    pub fn as_db_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Scanned => "scanned",
            Self::Enriched => "enriched",
            Self::Escalated => "escalated",
            Self::Deepened => "deepened",
            Self::Completed => "completed",
            Self::Failed => "failed",
        }
    }
}

impl std::fmt::Display for PipelineStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_db_str())
    }
}

/// Final review result ready for posting to GitHub.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewResult {
    pub pr_number: u64,
    pub repo_full_name: String,
    pub head_sha: String,
    pub findings: Vec<Finding>,
    pub summary: String,
    pub status: ReviewStatus,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::severity::Severity;

    #[test]
    fn review_status_variants_serde_round_trip() {
        let statuses = vec![
            ReviewStatus::Pending,
            ReviewStatus::DiffFetched,
            ReviewStatus::OpengrepScanned,
            ReviewStatus::GraphEnriched,
            ReviewStatus::SeverityEscalated,
            ReviewStatus::LlmDeepened,
            ReviewStatus::Completed,
            ReviewStatus::Failed {
                reason: "timeout".into(),
            },
        ];
        for status in &statuses {
            let json = serde_json::to_string(status).unwrap();
            let back: ReviewStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(format!("{back:?}"), format!("{status:?}"));
        }
    }

    #[test]
    fn failed_status_json_shape() {
        let status = ReviewStatus::Failed {
            reason: "oops".into(),
        };
        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("Failed"));
        assert!(json.contains("oops"));
    }

    #[test]
    fn review_result_serde_round_trip() {
        let result = ReviewResult {
            pr_number: 42,
            repo_full_name: "owner/repo".into(),
            head_sha: "abc123".into(),
            findings: vec![Finding {
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
                suggested_fix: Some("-old\n+new".into()),
                agent_prompt: Some("In @src/lib.rs around lines 1-1, fix it.".into()),
            }],
            summary: "1 finding".into(),
            status: ReviewStatus::Completed,
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: ReviewResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.pr_number, 42);
        assert_eq!(back.findings.len(), 1);
        assert_eq!(back.summary, "1 finding");
        assert_eq!(
            back.findings[0].suggested_fix.as_deref(),
            Some("-old\n+new")
        );
        assert_eq!(
            back.findings[0].agent_prompt.as_deref(),
            Some("In @src/lib.rs around lines 1-1, fix it.")
        );
    }

    #[test]
    fn review_result_empty_findings() {
        let result = ReviewResult {
            pr_number: 1,
            repo_full_name: "a/b".into(),
            head_sha: "def456".into(),
            findings: vec![],
            summary: "clean".into(),
            status: ReviewStatus::Completed,
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: ReviewResult = serde_json::from_str(&json).unwrap();
        assert!(back.findings.is_empty());
    }
}
