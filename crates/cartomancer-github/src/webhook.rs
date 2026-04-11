//! GitHub webhook payload types and HMAC signature verification.

use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;

/// Payload from a GitHub `pull_request` webhook event.
#[derive(Debug, Clone, Deserialize)]
pub struct PullRequestEvent {
    pub action: String,
    pub number: u64,
    pub repository: Repository,
    pub pull_request: PullRequest,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Repository {
    pub full_name: String,
    pub clone_url: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PullRequest {
    pub number: u64,
    pub title: String,
    pub head: GitRef,
    pub base: GitRef,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GitRef {
    #[serde(rename = "ref")]
    pub ref_name: String,
    pub sha: String,
}

impl PullRequestEvent {
    /// Returns true if this event should trigger a review.
    pub fn should_review(&self) -> bool {
        matches!(self.action.as_str(), "opened" | "synchronize" | "reopened")
    }
}

type HmacSha256 = Hmac<Sha256>;

/// Verify a GitHub webhook signature (HMAC-SHA256).
///
/// `signature_header` is the value of the `X-Hub-Signature-256` header,
/// formatted as `sha256=<hex>`.
pub fn verify_signature(secret: &str, payload: &[u8], signature_header: &str) -> bool {
    let hex_sig = match signature_header.strip_prefix("sha256=") {
        Some(h) => h,
        None => return false,
    };

    let expected = match decode_hex(hex_sig) {
        Some(bytes) => bytes,
        None => return false,
    };

    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(payload);
    mac.verify_slice(&expected).is_ok()
}

/// Decode a hex string to bytes. Returns None on invalid input.
fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compute the expected signature for a payload with a known secret.
    fn sign(secret: &str, payload: &[u8]) -> String {
        let mut mac =
            HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
        mac.update(payload);
        let result = mac.finalize().into_bytes();
        let hex: String = result.iter().map(|b| format!("{b:02x}")).collect();
        format!("sha256={hex}")
    }

    #[test]
    fn verify_valid_signature() {
        let secret = "test-secret";
        let payload = b"hello world";
        let sig = sign(secret, payload);
        assert!(verify_signature(secret, payload, &sig));
    }

    #[test]
    fn verify_invalid_signature() {
        let payload = b"hello world";
        let sig = sign("correct-secret", payload);
        assert!(!verify_signature("wrong-secret", payload, &sig));
    }

    #[test]
    fn verify_malformed_header_no_prefix() {
        assert!(!verify_signature("secret", b"data", "not-a-valid-header"));
    }

    #[test]
    fn verify_malformed_header_bad_hex() {
        assert!(!verify_signature("secret", b"data", "sha256=zzzz"));
    }

    #[test]
    fn verify_empty_payload() {
        let secret = "test-secret";
        let sig = sign(secret, b"");
        assert!(verify_signature(secret, b"", &sig));
    }

    #[test]
    fn should_review_opened() {
        let event = PullRequestEvent {
            action: "opened".into(),
            number: 1,
            repository: Repository {
                full_name: "owner/repo".into(),
                clone_url: "https://github.com/owner/repo.git".into(),
            },
            pull_request: PullRequest {
                number: 1,
                title: "Test PR".into(),
                head: GitRef {
                    ref_name: "feature".into(),
                    sha: "abc123".into(),
                },
                base: GitRef {
                    ref_name: "main".into(),
                    sha: "def456".into(),
                },
            },
        };
        assert!(event.should_review());
    }

    #[test]
    fn should_not_review_closed() {
        let event = PullRequestEvent {
            action: "closed".into(),
            number: 1,
            repository: Repository {
                full_name: "owner/repo".into(),
                clone_url: "https://github.com/owner/repo.git".into(),
            },
            pull_request: PullRequest {
                number: 1,
                title: "Test PR".into(),
                head: GitRef {
                    ref_name: "feature".into(),
                    sha: "abc123".into(),
                },
                base: GitRef {
                    ref_name: "main".into(),
                    sha: "def456".into(),
                },
            },
        };
        assert!(!event.should_review());
    }
}
