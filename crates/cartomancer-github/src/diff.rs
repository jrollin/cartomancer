//! Unified diff parsing utilities.

use anyhow::Result;

use cartomancer_core::diff::{DiffChunk, PullRequestDiff};

/// Parse a raw unified diff string (as returned by GitHub) into structured chunks.
///
/// Handles `diff --git` headers, `@@` hunk headers, and `+/-/ ` content lines.
pub fn parse_diff(raw_diff: &str) -> Result<PullRequestDiff> {
    let mut chunks = Vec::new();
    let mut files_changed = Vec::new();

    let mut current_file: Option<String> = None;
    let mut hunk_new_start: u32 = 0;
    let mut hunk_new_lines: u32 = 0;
    let mut hunk_old_start: u32 = 0;
    let mut hunk_old_lines: u32 = 0;
    let mut hunk_content = String::new();
    let mut in_hunk = false;

    for line in raw_diff.lines() {
        if let Some(rest) = line.strip_prefix("diff --git ") {
            // Flush any in-progress hunk
            if in_hunk {
                if let Some(ref file) = current_file {
                    chunks.push(DiffChunk {
                        file_path: file.clone(),
                        old_start: hunk_old_start,
                        new_start: hunk_new_start,
                        old_lines: hunk_old_lines,
                        new_lines: hunk_new_lines,
                        content: hunk_content.clone(),
                    });
                }
                hunk_content.clear();
                in_hunk = false;
            }

            // Parse file path from "a/path b/path"
            let file_path = parse_file_path(rest);
            if !files_changed.contains(&file_path) {
                files_changed.push(file_path.clone());
            }
            current_file = Some(file_path);
        } else if line.starts_with("@@") {
            // Flush previous hunk if any
            if in_hunk {
                if let Some(ref file) = current_file {
                    chunks.push(DiffChunk {
                        file_path: file.clone(),
                        old_start: hunk_old_start,
                        new_start: hunk_new_start,
                        old_lines: hunk_old_lines,
                        new_lines: hunk_new_lines,
                        content: hunk_content.clone(),
                    });
                }
                hunk_content.clear();
            }

            // Parse @@ -old_start,old_lines +new_start,new_lines @@
            if let Some((old_s, old_l, new_s, new_l)) = parse_hunk_header(line) {
                hunk_old_start = old_s;
                hunk_old_lines = old_l;
                hunk_new_start = new_s;
                hunk_new_lines = new_l;
                in_hunk = true;
            }
        } else if in_hunk
            && (line.starts_with('+')
                || line.starts_with('-')
                || line.starts_with(' ')
                || line.is_empty())
        {
            if !hunk_content.is_empty() {
                hunk_content.push('\n');
            }
            hunk_content.push_str(line);
        }
        // Skip other lines (index, ---, +++, etc.)
    }

    // Flush final hunk
    if in_hunk {
        if let Some(ref file) = current_file {
            chunks.push(DiffChunk {
                file_path: file.clone(),
                old_start: hunk_old_start,
                new_start: hunk_new_start,
                old_lines: hunk_old_lines,
                new_lines: hunk_new_lines,
                content: hunk_content,
            });
        }
    }

    Ok(PullRequestDiff {
        chunks,
        files_changed,
    })
}

/// Extract file path from "a/path b/path" after `diff --git`.
/// Uses the "b/" path (new file) as the canonical path.
fn parse_file_path(diff_line: &str) -> String {
    // Format: "a/some/path b/some/path"
    if let Some(b_idx) = diff_line.rfind(" b/") {
        diff_line[b_idx + 3..].to_string()
    } else {
        // Fallback: strip leading "a/" if present
        diff_line
            .split_whitespace()
            .next()
            .unwrap_or(diff_line)
            .strip_prefix("a/")
            .unwrap_or(diff_line)
            .to_string()
    }
}

/// Parse a `@@ -old_start,old_lines +new_start,new_lines @@` header.
/// Returns (old_start, old_lines, new_start, new_lines).
fn parse_hunk_header(line: &str) -> Option<(u32, u32, u32, u32)> {
    // Find the range between @@ markers
    let content = line.strip_prefix("@@ ")?.split(" @@").next()?;
    let parts: Vec<&str> = content.split_whitespace().collect();
    if parts.len() < 2 {
        return None;
    }

    let (old_start, old_lines) = parse_range(parts[0].strip_prefix('-')?)?;
    let (new_start, new_lines) = parse_range(parts[1].strip_prefix('+')?)?;

    Some((old_start, old_lines, new_start, new_lines))
}

/// Parse "start,lines" or "start" (lines defaults to 1).
fn parse_range(s: &str) -> Option<(u32, u32)> {
    if let Some((start, lines)) = s.split_once(',') {
        Some((start.parse().ok()?, lines.parse().ok()?))
    } else {
        Some((s.parse().ok()?, 1))
    }
}

/// Check if a given line number falls within any new-side range of the diff chunks for a file.
pub fn is_line_in_diff(diff: &PullRequestDiff, file_path: &str, line: u32) -> bool {
    diff.chunks.iter().any(|chunk| {
        chunk.file_path == file_path
            && line >= chunk.new_start
            && line < chunk.new_start + chunk.new_lines
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_DIFF: &str = "\
diff --git a/src/main.rs b/src/main.rs
index abc1234..def5678 100644
--- a/src/main.rs
+++ b/src/main.rs
@@ -1,4 +1,5 @@
 use std::io;
+use std::fmt;

 fn main() {
     println!(\"hello\");
@@ -10,3 +11,4 @@ fn helper() {
     let x = 1;
+    let y = 2;
     x
 }
diff --git a/src/lib.rs b/src/lib.rs
new file mode 100644
--- /dev/null
+++ b/src/lib.rs
@@ -0,0 +1,3 @@
+pub fn add(a: i32, b: i32) -> i32 {
+    a + b
+}";

    #[test]
    fn parse_diff_extracts_files_changed() {
        let diff = parse_diff(SAMPLE_DIFF).unwrap();
        assert_eq!(diff.files_changed, vec!["src/main.rs", "src/lib.rs"]);
    }

    #[test]
    fn parse_diff_extracts_correct_chunk_count() {
        let diff = parse_diff(SAMPLE_DIFF).unwrap();
        // 2 hunks in main.rs + 1 hunk in lib.rs = 3
        assert_eq!(diff.chunks.len(), 3);
    }

    #[test]
    fn parse_diff_first_hunk_metadata() {
        let diff = parse_diff(SAMPLE_DIFF).unwrap();
        let chunk = &diff.chunks[0];
        assert_eq!(chunk.file_path, "src/main.rs");
        assert_eq!(chunk.old_start, 1);
        assert_eq!(chunk.old_lines, 4);
        assert_eq!(chunk.new_start, 1);
        assert_eq!(chunk.new_lines, 5);
    }

    #[test]
    fn parse_diff_hunk_content_includes_additions() {
        let diff = parse_diff(SAMPLE_DIFF).unwrap();
        let chunk = &diff.chunks[0];
        assert!(chunk.content.contains("+use std::fmt;"));
    }

    #[test]
    fn parse_diff_new_file() {
        let diff = parse_diff(SAMPLE_DIFF).unwrap();
        let lib_chunk = &diff.chunks[2];
        assert_eq!(lib_chunk.file_path, "src/lib.rs");
        assert_eq!(lib_chunk.old_start, 0);
        assert_eq!(lib_chunk.old_lines, 0);
        assert_eq!(lib_chunk.new_start, 1);
        assert_eq!(lib_chunk.new_lines, 3);
    }

    #[test]
    fn parse_empty_diff() {
        let diff = parse_diff("").unwrap();
        assert!(diff.chunks.is_empty());
        assert!(diff.files_changed.is_empty());
    }

    #[test]
    fn parse_hunk_header_with_comma() {
        let result = parse_hunk_header("@@ -1,4 +1,5 @@ fn main()");
        assert_eq!(result, Some((1, 4, 1, 5)));
    }

    #[test]
    fn parse_hunk_header_without_comma() {
        let result = parse_hunk_header("@@ -1 +1 @@ fn single_line()");
        assert_eq!(result, Some((1, 1, 1, 1)));
    }

    #[test]
    fn is_line_in_diff_returns_true_for_changed_line() {
        let diff = parse_diff(SAMPLE_DIFF).unwrap();
        // Line 2 in new file is within hunk [1, 5) of src/main.rs
        assert!(is_line_in_diff(&diff, "src/main.rs", 2));
    }

    #[test]
    fn is_line_in_diff_returns_false_for_unchanged_line() {
        let diff = parse_diff(SAMPLE_DIFF).unwrap();
        // Line 100 is not in any hunk
        assert!(!is_line_in_diff(&diff, "src/main.rs", 100));
    }

    #[test]
    fn is_line_in_diff_returns_false_for_unknown_file() {
        let diff = parse_diff(SAMPLE_DIFF).unwrap();
        assert!(!is_line_in_diff(&diff, "src/unknown.rs", 1));
    }

    #[test]
    fn parse_file_path_extracts_b_path() {
        assert_eq!(
            parse_file_path("a/src/main.rs b/src/main.rs"),
            "src/main.rs"
        );
    }

    #[test]
    fn parse_file_path_with_spaces_in_name() {
        assert_eq!(
            parse_file_path("a/path with spaces.rs b/path with spaces.rs"),
            "path with spaces.rs"
        );
    }
}
