//! Path security utilities — prevent path traversal attacks.

use std::path::{Path, PathBuf};

use anyhow::{bail, Result};

/// Lexically normalize a path by resolving `.` and `..` components.
/// Unlike `canonicalize()`, this does not require the path to exist.
fn normalize_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            std::path::Component::CurDir => {} // skip `.`
            other => normalized.push(other),
        }
    }
    normalized
}

/// Validate that a relative path stays within the base directory.
///
/// Rejects:
/// - Paths that resolve outside `base_dir` (e.g. `../../etc/passwd`)
/// - Absolute paths that don't start with `base_dir` (e.g. `/etc/passwd`)
///
/// For paths to existing files/dirs, uses canonical resolution.
/// For non-existent paths, uses lexical component analysis as a fallback.
pub fn validate_path_within(base_dir: &Path, relative: &str) -> Result<PathBuf> {
    let relative = relative.trim();
    if relative.is_empty() {
        bail!("path is empty");
    }

    let candidate = Path::new(relative);

    // Reject absolute paths that clearly don't belong under base_dir.
    if candidate.is_absolute() {
        let base_canonical = base_dir
            .canonicalize()
            .unwrap_or_else(|_| normalize_path(base_dir));
        let candidate_canonical = candidate
            .canonicalize()
            .unwrap_or_else(|_| normalize_path(candidate));
        if !candidate_canonical.starts_with(&base_canonical) {
            bail!(
                "path '{}' is absolute and outside project directory (path traversal blocked)",
                relative
            );
        }
        return Ok(candidate_canonical);
    }

    let resolved = base_dir.join(relative);

    // If the path exists, use canonicalize for definitive resolution (follows symlinks).
    if resolved.exists() {
        let canonical = resolved.canonicalize()?;
        let base_canonical = base_dir.canonicalize()?;
        if !canonical.starts_with(&base_canonical) {
            bail!(
                "path '{}' resolves outside project directory (path traversal blocked)",
                relative
            );
        }
        return Ok(canonical);
    }

    // For non-existent paths, do lexical component analysis.
    // Reject if any component is `..` that would escape the base.
    let mut depth: i32 = 0;
    for component in candidate.components() {
        match component {
            std::path::Component::ParentDir => {
                depth -= 1;
                if depth < 0 {
                    bail!(
                        "path '{}' escapes project directory (path traversal blocked)",
                        relative
                    );
                }
            }
            std::path::Component::Normal(_) => {
                depth += 1;
            }
            std::path::Component::CurDir => {} // `.` — no change
            _ => {
                bail!(
                    "path '{}' contains unexpected component (path traversal blocked)",
                    relative
                );
            }
        }
    }

    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn valid_relative_path() {
        let tmp = tempfile::tempdir().unwrap();
        let rules_dir = tmp.path().join(".cartomancer").join("rules");
        fs::create_dir_all(&rules_dir).unwrap();

        let result = validate_path_within(tmp.path(), ".cartomancer/rules");
        assert!(result.is_ok(), "got: {:?}", result);
        assert_eq!(result.unwrap(), rules_dir.canonicalize().unwrap());
    }

    #[test]
    fn parent_traversal_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let result = validate_path_within(tmp.path(), "../../etc/passwd");
        assert!(result.is_err());
        assert!(
            result.unwrap_err().to_string().contains("path traversal"),
            "should mention path traversal"
        );
    }

    #[test]
    fn absolute_path_outside_project_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let result = validate_path_within(tmp.path(), "/etc/passwd");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("path traversal"));
    }

    #[test]
    fn absolute_path_with_dotdot_traversal_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().canonicalize().unwrap();
        // /base/../etc/passwd — lexically starts with /base but normalizes outside
        let malicious = format!("{}/../etc/passwd", base.display());
        let result = validate_path_within(tmp.path(), &malicious);
        assert!(result.is_err(), "got: {:?}", result);
        assert!(result.unwrap_err().to_string().contains("path traversal"));
    }

    #[test]
    fn empty_path_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let result = validate_path_within(tmp.path(), "");
        assert!(result.is_err());
    }

    #[test]
    fn nonexistent_valid_relative_accepted() {
        let tmp = tempfile::tempdir().unwrap();
        // Path doesn't exist but is validly relative
        let result = validate_path_within(tmp.path(), "some/future/dir");
        assert!(result.is_ok());
    }

    #[test]
    fn nonexistent_traversal_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let result = validate_path_within(tmp.path(), "../outside/secret.env");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("path traversal"));
    }

    #[test]
    fn dot_current_dir_accepted() {
        let tmp = tempfile::tempdir().unwrap();
        let result = validate_path_within(tmp.path(), "./rules");
        assert!(result.is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn symlink_outside_project_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let secret_file = outside.path().join("secret.txt");
        fs::write(&secret_file, "secret data").unwrap();

        // Create symlink inside project pointing outside
        let link_path = tmp.path().join("evil-link");
        std::os::unix::fs::symlink(&secret_file, &link_path).unwrap();

        let result = validate_path_within(tmp.path(), "evil-link");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("path traversal"));
    }

    #[cfg(unix)]
    #[test]
    fn symlink_within_project_accepted() {
        let tmp = tempfile::tempdir().unwrap();
        let real_dir = tmp.path().join("real-rules");
        fs::create_dir(&real_dir).unwrap();

        let link_path = tmp.path().join("rules-link");
        std::os::unix::fs::symlink(&real_dir, &link_path).unwrap();

        let result = validate_path_within(tmp.path(), "rules-link");
        assert!(result.is_ok());
    }
}
