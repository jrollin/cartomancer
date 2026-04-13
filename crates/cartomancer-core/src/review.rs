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
    Prepared,
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
            "prepared" => Some(Self::Prepared),
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
            Self::Prepared => "prepared",
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

    mod pipeline_stage {
        use crate::review::PipelineStage;

        #[test]
        fn from_db_valid_variants() {
            assert_eq!(
                PipelineStage::from_db("pending"),
                Some(PipelineStage::Pending)
            );
            assert_eq!(
                PipelineStage::from_db("prepared"),
                Some(PipelineStage::Prepared)
            );
            assert_eq!(
                PipelineStage::from_db("scanned"),
                Some(PipelineStage::Scanned)
            );
            assert_eq!(
                PipelineStage::from_db("enriched"),
                Some(PipelineStage::Enriched)
            );
            assert_eq!(
                PipelineStage::from_db("escalated"),
                Some(PipelineStage::Escalated)
            );
            assert_eq!(
                PipelineStage::from_db("deepened"),
                Some(PipelineStage::Deepened)
            );
            assert_eq!(
                PipelineStage::from_db("completed"),
                Some(PipelineStage::Completed)
            );
            assert_eq!(
                PipelineStage::from_db("failed"),
                Some(PipelineStage::Failed)
            );
        }

        #[test]
        fn from_db_invalid_returns_none() {
            assert_eq!(PipelineStage::from_db("unknown"), None);
            assert_eq!(PipelineStage::from_db(""), None);
            assert_eq!(PipelineStage::from_db("PENDING"), None);
        }

        #[test]
        fn as_db_str_round_trip() {
            let stages = [
                PipelineStage::Pending,
                PipelineStage::Prepared,
                PipelineStage::Scanned,
                PipelineStage::Enriched,
                PipelineStage::Escalated,
                PipelineStage::Deepened,
                PipelineStage::Completed,
                PipelineStage::Failed,
            ];
            for stage in &stages {
                let s = stage.as_db_str();
                assert_eq!(PipelineStage::from_db(s).as_ref(), Some(stage));
            }
        }

        #[test]
        fn display_matches_db_str() {
            let stage = PipelineStage::Enriched;
            assert_eq!(format!("{stage}"), "enriched");
            assert_eq!(format!("{}", PipelineStage::Failed), "failed");
        }

        #[test]
        fn ordering_is_correct() {
            assert!(PipelineStage::Pending < PipelineStage::Prepared);
            assert!(PipelineStage::Prepared < PipelineStage::Scanned);
            assert!(PipelineStage::Scanned < PipelineStage::Enriched);
            assert!(PipelineStage::Enriched < PipelineStage::Escalated);
            assert!(PipelineStage::Escalated < PipelineStage::Deepened);
            assert!(PipelineStage::Deepened < PipelineStage::Completed);
        }

        #[test]
        fn serde_round_trip() {
            let stage = PipelineStage::Scanned;
            let json = serde_json::to_string(&stage).unwrap();
            assert_eq!(json, "\"scanned\"");
            let back: PipelineStage = serde_json::from_str(&json).unwrap();
            assert_eq!(back, stage);
        }
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
