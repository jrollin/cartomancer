//! GitHub REST API client.

use anyhow::Result;

use cartomancer_core::finding::Finding;
use cartomancer_core::review::ReviewResult;

/// GitHub API client for PR operations.
pub struct GitHubClient {
    #[allow(dead_code)]
    http: reqwest::Client,
    #[allow(dead_code)]
    token: String,
}

impl GitHubClient {
    /// Create a new client with the given API token.
    pub fn new(token: &str) -> Self {
        Self {
            http: reqwest::Client::new(),
            token: token.to_string(),
        }
    }

    /// Fetch the raw unified diff for a pull request.
    pub async fn fetch_diff(&self, _repo: &str, _pr_number: u64) -> Result<String> {
        todo!()
    }

    /// Post inline review comments to a pull request.
    pub async fn post_review(&self, _review: &ReviewResult) -> Result<()> {
        todo!()
    }

    /// Post a single inline comment on a specific line.
    pub async fn post_inline_comment(
        &self,
        _repo: &str,
        _pr_number: u64,
        _commit_sha: &str,
        _finding: &Finding,
    ) -> Result<()> {
        todo!()
    }

    /// Post a summary comment on the PR.
    pub async fn post_summary_comment(
        &self,
        _repo: &str,
        _pr_number: u64,
        _summary: &str,
    ) -> Result<()> {
        todo!()
    }
}
