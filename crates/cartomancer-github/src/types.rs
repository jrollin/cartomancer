//! GitHub API response types.

use serde::{Deserialize, Serialize};

/// PR metadata fetched from the GitHub API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrMetadata {
    pub number: u64,
    pub title: String,
    pub head_sha: String,
    pub base_sha: String,
    pub head_ref: String,
    pub base_ref: String,
}

/// GitHub API response for `GET /repos/{owner}/{repo}/pulls/{number}`.
#[derive(Debug, Deserialize)]
pub(crate) struct PullResponse {
    pub number: u64,
    pub title: String,
    pub head: GitRefResponse,
    pub base: GitRefResponse,
}

#[derive(Debug, Deserialize)]
pub(crate) struct GitRefResponse {
    #[serde(rename = "ref")]
    pub ref_name: String,
    pub sha: String,
}

impl From<PullResponse> for PrMetadata {
    fn from(pr: PullResponse) -> Self {
        Self {
            number: pr.number,
            title: pr.title,
            head_sha: pr.head.sha,
            base_sha: pr.base.sha,
            head_ref: pr.head.ref_name,
            base_ref: pr.base.ref_name,
        }
    }
}

/// Inline comment for the GitHub PR Review API.
#[derive(Debug, Clone, Serialize)]
pub struct ReviewComment {
    pub path: String,
    pub line: u32,
    pub body: String,
}

/// Request body for `POST /repos/{owner}/{repo}/pulls/{number}/reviews`.
#[derive(Debug, Serialize)]
pub(crate) struct CreateReviewRequest {
    pub commit_id: String,
    pub body: String,
    pub event: String,
    pub comments: Vec<ReviewComment>,
}

/// Request body for `POST /repos/{owner}/{repo}/issues/{number}/comments`.
#[derive(Debug, Serialize)]
pub(crate) struct CreateCommentRequest {
    pub body: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pull_response_deserializes_from_github_json() {
        let json = r#"{
            "number": 42,
            "title": "Fix auth bug",
            "head": { "ref": "fix-auth", "sha": "abc123" },
            "base": { "ref": "main", "sha": "def456" }
        }"#;
        let pr: PullResponse = serde_json::from_str(json).unwrap();
        assert_eq!(pr.number, 42);
        assert_eq!(pr.title, "Fix auth bug");
        assert_eq!(pr.head.sha, "abc123");
        assert_eq!(pr.base.sha, "def456");
        assert_eq!(pr.head.ref_name, "fix-auth");
        assert_eq!(pr.base.ref_name, "main");
    }

    #[test]
    fn pull_response_converts_to_pr_metadata() {
        let pr = PullResponse {
            number: 7,
            title: "Add feature".into(),
            head: GitRefResponse {
                ref_name: "feature-branch".into(),
                sha: "head111".into(),
            },
            base: GitRefResponse {
                ref_name: "main".into(),
                sha: "base222".into(),
            },
        };
        let meta: PrMetadata = pr.into();
        assert_eq!(meta.number, 7);
        assert_eq!(meta.head_sha, "head111");
        assert_eq!(meta.base_sha, "base222");
        assert_eq!(meta.head_ref, "feature-branch");
        assert_eq!(meta.base_ref, "main");
    }

    #[test]
    fn pull_response_ignores_unknown_fields() {
        let json = r#"{
            "number": 1,
            "title": "Test",
            "head": { "ref": "br", "sha": "aaa", "label": "owner:br" },
            "base": { "ref": "main", "sha": "bbb", "label": "owner:main" },
            "state": "open",
            "user": { "login": "jrollin" }
        }"#;
        let pr: PullResponse = serde_json::from_str(json).unwrap();
        assert_eq!(pr.number, 1);
    }

    #[test]
    fn create_review_request_serializes_correctly() {
        let req = CreateReviewRequest {
            commit_id: "abc123".into(),
            body: "Summary".into(),
            event: "COMMENT".into(),
            comments: vec![ReviewComment {
                path: "src/lib.rs".into(),
                line: 10,
                body: "Finding here".into(),
            }],
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["event"], "COMMENT");
        assert_eq!(json["comments"][0]["path"], "src/lib.rs");
        assert_eq!(json["comments"][0]["line"], 10);
    }

    #[test]
    fn pr_metadata_serde_round_trip() {
        let meta = PrMetadata {
            number: 42,
            title: "Test PR".into(),
            head_sha: "abc".into(),
            base_sha: "def".into(),
            head_ref: "feature".into(),
            base_ref: "main".into(),
        };
        let json = serde_json::to_string(&meta).unwrap();
        let back: PrMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(back.number, 42);
        assert_eq!(back.head_sha, "abc");
    }
}
