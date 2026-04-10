//! GitHub REST API client.

use std::time::Duration;

use anyhow::{Context, Result};
use tracing::{debug, warn};

use crate::types::{
    CreateCommentRequest, CreateReviewRequest, PrMetadata, PullResponse, ReviewComment,
};

const GITHUB_API_BASE: &str = "https://api.github.com";
const USER_AGENT: &str = "cartomancer";

/// GitHub API client for PR operations.
pub struct GitHubClient {
    http: reqwest::Client,
    token: String,
}

impl GitHubClient {
    /// Create a new client with the given API token.
    pub fn new(token: &str) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent(USER_AGENT)
            .build()
            .expect("failed to build HTTP client");
        Self {
            http,
            token: token.to_string(),
        }
    }

    /// Fetch PR metadata (head SHA, base SHA, title, refs).
    pub async fn fetch_pr_metadata(&self, repo: &str, pr_number: u64) -> Result<PrMetadata> {
        let url = format!("{GITHUB_API_BASE}/repos/{repo}/pulls/{pr_number}");
        let response = self.get_with_retry(&url).await?;
        let status = response.status();
        let body = response
            .text()
            .await
            .context("failed to read PR metadata response")?;

        if status == reqwest::StatusCode::NOT_FOUND {
            anyhow::bail!("PR not found: {repo}#{pr_number}");
        }
        if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
            anyhow::bail!(
                "authentication failed or insufficient permissions for {repo}#{pr_number}: {}",
                body
            );
        }
        if !status.is_success() {
            anyhow::bail!(
                "GitHub API error (HTTP {}) fetching PR {repo}#{pr_number}: {}",
                status.as_u16(),
                body
            );
        }

        let pr: PullResponse =
            serde_json::from_str(&body).context("failed to parse PR metadata")?;
        Ok(pr.into())
    }

    /// Fetch the raw unified diff for a pull request.
    pub async fn fetch_diff(&self, repo: &str, pr_number: u64) -> Result<String> {
        let url = format!("{GITHUB_API_BASE}/repos/{repo}/pulls/{pr_number}");
        let response = self
            .get_with_retry_accept(&url, "application/vnd.github.diff")
            .await?;

        let status = response.status();
        let body = response
            .text()
            .await
            .context("failed to read diff response")?;

        if !status.is_success() {
            anyhow::bail!(
                "GitHub API error (HTTP {}) fetching diff for {repo}#{pr_number}: {}",
                status.as_u16(),
                body
            );
        }

        Ok(body)
    }

    /// Post a PR review with inline comments and a summary body.
    pub async fn post_review(
        &self,
        repo: &str,
        pr_number: u64,
        commit_sha: &str,
        summary: &str,
        comments: Vec<ReviewComment>,
    ) -> Result<()> {
        let url = format!("{GITHUB_API_BASE}/repos/{repo}/pulls/{pr_number}/reviews");
        let body = CreateReviewRequest {
            commit_id: commit_sha.to_string(),
            body: summary.to_string(),
            event: "COMMENT".to_string(),
            comments,
        };

        let response = self.post_with_retry(&url, &body).await?;

        let status = response.status();
        if !status.is_success() {
            let resp_body = response
                .text()
                .await
                .unwrap_or_else(|_| "could not read response body".into());
            anyhow::bail!(
                "GitHub API error (HTTP {}) posting review for {repo}#{pr_number}: {}",
                status.as_u16(),
                resp_body
            );
        }

        debug!("review posted for {repo}#{pr_number}");
        Ok(())
    }

    /// Post a comment on a PR (not an inline review comment).
    pub async fn post_comment(&self, repo: &str, pr_number: u64, body: &str) -> Result<()> {
        let url = format!("{GITHUB_API_BASE}/repos/{repo}/issues/{pr_number}/comments");
        let req_body = CreateCommentRequest {
            body: body.to_string(),
        };

        let response = self.post_with_retry(&url, &req_body).await?;

        let status = response.status();
        if !status.is_success() {
            let resp_body = response
                .text()
                .await
                .unwrap_or_else(|_| "could not read response body".into());
            anyhow::bail!(
                "GitHub API error (HTTP {}) posting comment for {repo}#{pr_number}: {}",
                status.as_u16(),
                resp_body
            );
        }

        debug!("comment posted for {repo}#{pr_number}");
        Ok(())
    }

    /// GET with a single retry on transient errors (5xx, network).
    async fn get_with_retry(&self, url: &str) -> Result<reqwest::Response> {
        self.get_with_retry_accept(url, "application/vnd.github+json")
            .await
    }

    /// GET with a single retry and custom Accept header.
    async fn get_with_retry_accept(&self, url: &str, accept: &str) -> Result<reqwest::Response> {
        let send = || async {
            self.http
                .get(url)
                .bearer_auth(&self.token)
                .header("accept", accept)
                .send()
                .await
                .context("failed to connect to GitHub API")
        };

        match send().await {
            Ok(resp) if resp.status().is_server_error() => {
                warn!(
                    url,
                    status = resp.status().as_u16(),
                    "transient GitHub API error, retrying in 1s"
                );
                tokio::time::sleep(Duration::from_secs(1)).await;
                send().await
            }
            Ok(resp) => Ok(resp),
            Err(e) => {
                warn!(url, err = %e, "GitHub API request failed, retrying in 1s");
                tokio::time::sleep(Duration::from_secs(1)).await;
                send().await
            }
        }
    }

    /// POST with a single retry on transient 5xx errors.
    async fn post_with_retry(
        &self,
        url: &str,
        body: &impl serde::Serialize,
    ) -> Result<reqwest::Response> {
        let response = self
            .http
            .post(url)
            .bearer_auth(&self.token)
            .header("accept", "application/vnd.github+json")
            .json(body)
            .send()
            .await
            .context("failed to connect to GitHub API")?;

        if response.status().is_server_error() {
            warn!(
                url,
                status = response.status().as_u16(),
                "transient GitHub API error on POST, retrying in 1s"
            );
            tokio::time::sleep(Duration::from_secs(1)).await;
            return self
                .http
                .post(url)
                .bearer_auth(&self.token)
                .header("accept", "application/vnd.github+json")
                .json(body)
                .send()
                .await
                .context("failed to connect to GitHub API");
        }

        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_constructor_sets_token() {
        let client = GitHubClient::new("test-token-123");
        assert_eq!(client.token, "test-token-123");
    }
}
