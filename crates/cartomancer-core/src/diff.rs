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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diff_chunk_serde_round_trip() {
        let chunk = DiffChunk {
            file_path: "src/main.rs".into(),
            old_start: 10,
            new_start: 12,
            old_lines: 5,
            new_lines: 7,
            content: "+let x = 1;\n-let y = 2;".into(),
        };
        let json = serde_json::to_string(&chunk).unwrap();
        let back: DiffChunk = serde_json::from_str(&json).unwrap();
        assert_eq!(back.file_path, "src/main.rs");
        assert_eq!(back.old_start, 10);
        assert_eq!(back.new_start, 12);
        assert_eq!(back.old_lines, 5);
        assert_eq!(back.new_lines, 7);
        assert_eq!(back.content, chunk.content);
    }

    #[test]
    fn pull_request_diff_serde_round_trip() {
        let diff = PullRequestDiff {
            chunks: vec![DiffChunk {
                file_path: "src/lib.rs".into(),
                old_start: 1,
                new_start: 1,
                old_lines: 3,
                new_lines: 4,
                content: "+use crate::foo;".into(),
            }],
            files_changed: vec!["src/lib.rs".into()],
        };
        let json = serde_json::to_string(&diff).unwrap();
        let back: PullRequestDiff = serde_json::from_str(&json).unwrap();
        assert_eq!(back.chunks.len(), 1);
        assert_eq!(back.files_changed, vec!["src/lib.rs"]);
    }

    #[test]
    fn empty_diff_round_trip() {
        let diff = PullRequestDiff {
            chunks: vec![],
            files_changed: vec![],
        };
        let json = serde_json::to_string(&diff).unwrap();
        let back: PullRequestDiff = serde_json::from_str(&json).unwrap();
        assert!(back.chunks.is_empty());
        assert!(back.files_changed.is_empty());
    }
}
