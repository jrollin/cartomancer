//! GitHub webhook payload types.

use serde::Deserialize;

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

#[cfg(test)]
mod tests {
    use super::*;

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
