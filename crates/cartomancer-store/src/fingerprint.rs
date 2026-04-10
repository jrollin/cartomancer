//! Finding fingerprint computation (BR-4, TD-3).
//!
//! A fingerprint is the SHA-256 hash of length-prefixed `rule_id`, `file_path`, `snippet_content`.
//! It serves as the stable identity of a finding across scans, used for
//! regression detection (US-5) and dismissal matching (US-6).

use sha2::{Digest, Sha256};

/// Compute the finding fingerprint: SHA-256 of length-prefixed `rule_id`, `file_path`, `snippet`.
///
/// Each component is prefixed with its byte length as a little-endian u64,
/// making the hash immune to delimiter collisions (e.g. `("a:b","c")` vs `("a","b:c")`).
pub fn compute(rule_id: &str, file_path: &str, snippet: &str) -> String {
    let mut hasher = Sha256::new();
    for component in [rule_id, file_path, snippet] {
        hasher.update((component.len() as u64).to_le_bytes());
        hasher.update(component.as_bytes());
    }
    format!("{:x}", hasher.finalize())
}

/// Compute the snippet-only hash for dismissal exact matching (BR-1).
pub fn snippet_hash(snippet: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(snippet);
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_deterministic() {
        let fp1 = compute("rule-a", "src/main.rs", "let x = 1;");
        let fp2 = compute("rule-a", "src/main.rs", "let x = 1;");
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn fingerprint_is_hex_sha256() {
        let fp = compute("rule-a", "src/main.rs", "let x = 1;");
        assert_eq!(fp.len(), 64); // SHA-256 = 32 bytes = 64 hex chars
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn fingerprint_changes_with_rule_id() {
        let fp1 = compute("rule-a", "src/main.rs", "let x = 1;");
        let fp2 = compute("rule-b", "src/main.rs", "let x = 1;");
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn fingerprint_changes_with_file_path() {
        let fp1 = compute("rule-a", "src/main.rs", "let x = 1;");
        let fp2 = compute("rule-a", "src/lib.rs", "let x = 1;");
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn fingerprint_changes_with_snippet() {
        let fp1 = compute("rule-a", "src/main.rs", "let x = 1;");
        let fp2 = compute("rule-a", "src/main.rs", "let x = 2;");
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn fingerprint_no_delimiter_collision() {
        // "a:b" as rule_id + "c" as file vs "a" as rule_id + "b:c" as file
        let fp1 = compute("a:b", "c", "d");
        let fp2 = compute("a", "b:c", "d");
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn snippet_hash_is_deterministic() {
        let h1 = snippet_hash("let x = 1;");
        let h2 = snippet_hash("let x = 1;");
        assert_eq!(h1, h2);
    }

    #[test]
    fn snippet_hash_changes_with_content() {
        let h1 = snippet_hash("let x = 1;");
        let h2 = snippet_hash("let x = 2;");
        assert_ne!(h1, h2);
    }

    #[test]
    fn snippet_hash_is_hex_sha256() {
        let h = snippet_hash("some code");
        assert_eq!(h.len(), 64);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
