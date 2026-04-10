//! Review state and final output types.

use serde::{Deserialize, Serialize};

use crate::finding::Finding;

/// State of a review as it progresses through the pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReviewStatus {
    Pending,
    DiffFetched,
    SemgrepScanned,
    GraphEnriched,
    SeverityEscalated,
    LlmDeepened,
    Completed,
    Failed { reason: String },
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
