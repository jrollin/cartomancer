//! Diff chunk representation for PR changes.

use serde::{Deserialize, Serialize};

/// A chunk of a unified diff for a single file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffChunk {
    pub file_path: String,
    pub old_start: u32,
    pub new_start: u32,
    pub old_lines: u32,
    pub new_lines: u32,
    pub content: String,
}

/// Parsed representation of a full PR diff.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PullRequestDiff {
    pub chunks: Vec<DiffChunk>,
    pub files_changed: Vec<String>,
}
