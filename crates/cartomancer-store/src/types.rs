//! Store-specific types: scan records, stored findings, dismissals, and query filters.

use serde::{Deserialize, Serialize};

/// A persisted scan record (maps to the `scans` table).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRecord {
    pub id: Option<i64>,
    pub repo: String,
    pub branch: String,
    pub commit_sha: String,
    pub command: String,
    pub pr_number: Option<u64>,
    pub finding_count: u32,
    pub summary: String,
    pub created_at: Option<String>,
    /// Pipeline stage (v4): tracks how far the scan progressed.
    #[serde(default = "default_stage")]
    pub stage: String,
    /// Error message on failure (v4).
    pub error_message: Option<String>,
    /// The stage at which the pipeline failed (v4). `stage` retains the last
    /// successful checkpoint so `--resume` can restart from there.
    pub failed_at_stage: Option<String>,
    /// Work directory path used during this scan (v5). Used by `--resume` to
    /// locate the checkout without re-cloning.
    #[serde(default)]
    pub work_dir: Option<String>,
}

fn default_stage() -> String {
    "completed".into()
}

/// A persisted finding with its fingerprint (maps to the `findings` table).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredFinding {
    pub id: Option<i64>,
    pub scan_id: i64,
    pub fingerprint: String,
    pub rule_id: String,
    pub severity: String,
    pub file_path: String,
    pub start_line: u32,
    pub end_line: u32,
    pub message: String,
    pub snippet: String,
    pub cwe: Option<String>,
    pub graph_context_json: Option<String>,
    pub llm_analysis: Option<String>,
    pub escalation_reasons_json: Option<String>,
    pub enclosing_context: Option<String>,
    pub suggested_fix: Option<String>,
    pub agent_prompt: Option<String>,
}

/// A dismissal record (maps to the `dismissals` table).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dismissal {
    pub id: Option<i64>,
    pub fingerprint: String,
    pub rule_id: String,
    pub file_path: String,
    pub start_line: u32,
    pub end_line: u32,
    pub snippet_hash: String,
    pub reason: Option<String>,
    pub created_at: Option<String>,
}

/// Filter for listing scans.
#[derive(Debug, Default)]
pub struct ScanFilter {
    pub branch: Option<String>,
    pub repo: Option<String>,
}

/// Filter for searching findings across scans.
#[derive(Debug, Default)]
pub struct FindingFilter {
    pub rule: Option<String>,
    pub severity: Option<String>,
    pub file: Option<String>,
    pub branch: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_stage_is_completed() {
        assert_eq!(default_stage(), "completed");
    }

    #[test]
    fn scan_record_default_stage_via_serde() {
        let json = r#"{"id":null,"repo":"r","branch":"b","commit_sha":"s","command":"scan","pr_number":null,"finding_count":0,"summary":"s","created_at":null,"error_message":null,"failed_at_stage":null}"#;
        let record: ScanRecord = serde_json::from_str(json).unwrap();
        assert_eq!(record.stage, "completed");
        assert!(record.failed_at_stage.is_none());
    }
}
