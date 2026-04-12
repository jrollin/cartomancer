//! Axum webhook handler for GitHub events.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::Router;
use tokio::sync::Semaphore;
use tower_http::trace::TraceLayer;
use tracing::{info, warn};

use cartomancer_core::config::AppConfig;
use cartomancer_github::client::GitHubClient;
use cartomancer_github::webhook::{verify_signature, PullRequestEvent};

use crate::pipeline;

/// Shared state for the webhook server.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<AppConfig>,
    pub webhook_secret: String,
    pub github_token: String,
    pub review_semaphore: Arc<Semaphore>,
}

/// Build the Axum router with webhook endpoints.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/webhook", post(handle_webhook))
        .route("/health", get(handle_health))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

async fn handle_health() -> StatusCode {
    StatusCode::OK
}

async fn handle_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> StatusCode {
    // 1. Validate HMAC signature
    let sig = match headers.get("x-hub-signature-256") {
        Some(v) => match v.to_str() {
            Ok(s) => s,
            Err(_) => return StatusCode::UNAUTHORIZED,
        },
        None => return StatusCode::UNAUTHORIZED,
    };

    if !verify_signature(&state.webhook_secret, &body, sig) {
        warn!("webhook signature verification failed");
        return StatusCode::UNAUTHORIZED;
    }

    // 2. Check event type
    let event_type = headers
        .get("x-github-event")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if event_type != "pull_request" {
        info!(event_type, "ignoring non-pull_request event");
        return StatusCode::OK;
    }

    // 3. Parse payload
    let event: PullRequestEvent = match serde_json::from_slice(&body) {
        Ok(e) => e,
        Err(e) => {
            warn!(err = %e, "failed to parse pull_request webhook payload");
            return StatusCode::BAD_REQUEST;
        }
    };

    // 4. Filter by action
    if !event.should_review() {
        info!(
            action = %event.action,
            pr = event.number,
            repo = %event.repository.full_name,
            "skipping non-reviewable action"
        );
        return StatusCode::OK;
    }

    // 5. Try to acquire a semaphore permit (non-blocking check for logging)
    let repo = event.repository.full_name.clone();
    let pr = event.number;

    info!(
        repo = %repo,
        pr,
        action = %event.action,
        "accepted webhook, spawning review"
    );

    // 6. Acquire semaphore permit before spawning to bound concurrency
    let semaphore = Arc::clone(&state.review_semaphore);
    let permit = match semaphore.try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            warn!(
                repo = %repo,
                pr,
                "review concurrency limit reached, rejecting webhook"
            );
            return StatusCode::SERVICE_UNAVAILABLE;
        }
    };

    let config = Arc::clone(&state.config);
    let token = state.github_token.clone();

    tokio::spawn(async move {
        let _permit = permit; // held for the duration of the review
        info!(repo = %repo, pr, "starting review");
        if let Err(e) = run_webhook_review(&config, &token, &repo, pr).await {
            tracing::error!(repo = %repo, pr, err = %e, "webhook review failed");
        }
    });

    StatusCode::ACCEPTED
}

/// Run a full review pipeline and post results to GitHub.
async fn run_webhook_review(
    config: &AppConfig,
    token: &str,
    repo: &str,
    pr: u64,
) -> anyhow::Result<()> {
    let github = GitHubClient::new(token)?;

    let mut result = pipeline::run_pipeline(config, &github, token, repo, pr, None, None).await?;
    pipeline::finalize_and_post(config, &github, repo, pr, &mut result).await?;

    info!(repo, pr, "webhook review completed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    use tower::ServiceExt;

    const TEST_SECRET: &str = "test-webhook-secret";
    const TEST_TOKEN: &str = "ghp_test_token";

    fn test_state() -> AppState {
        AppState {
            config: Arc::new(AppConfig::default()),
            webhook_secret: TEST_SECRET.into(),
            github_token: TEST_TOKEN.into(),
            review_semaphore: Arc::new(Semaphore::new(4)),
        }
    }

    fn sign(payload: &[u8]) -> String {
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(TEST_SECRET.as_bytes()).expect("HMAC key");
        mac.update(payload);
        let result = mac.finalize().into_bytes();
        let hex: String = result.iter().map(|b| format!("{b:02x}")).collect();
        format!("sha256={hex}")
    }

    fn pr_event_payload(action: &str) -> String {
        serde_json::json!({
            "action": action,
            "number": 42,
            "repository": {
                "full_name": "owner/repo",
                "clone_url": "https://github.com/owner/repo.git"
            },
            "pull_request": {
                "number": 42,
                "title": "Test PR",
                "head": { "ref": "feature", "sha": "abc123" },
                "base": { "ref": "main", "sha": "def456" }
            }
        })
        .to_string()
    }

    #[tokio::test]
    async fn health_returns_ok() {
        let app = router(test_state());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn webhook_missing_signature_returns_unauthorized() {
        let app = router(test_state());
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/webhook")
                    .header("x-github-event", "pull_request")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn webhook_invalid_signature_returns_unauthorized() {
        let app = router(test_state());
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/webhook")
                    .header(
                        "x-hub-signature-256",
                        "sha256=0000000000000000000000000000000000000000000000000000000000000000",
                    )
                    .header("x-github-event", "pull_request")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn webhook_non_pr_event_returns_ok() {
        let payload = b"{}";
        let sig = sign(payload);
        let app = router(test_state());
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/webhook")
                    .header("x-hub-signature-256", &sig)
                    .header("x-github-event", "push")
                    .body(Body::from(&payload[..]))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn webhook_closed_action_returns_ok() {
        let payload = pr_event_payload("closed");
        let sig = sign(payload.as_bytes());
        let app = router(test_state());
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/webhook")
                    .header("x-hub-signature-256", &sig)
                    .header("x-github-event", "pull_request")
                    .body(Body::from(payload))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn webhook_opened_action_returns_accepted() {
        let payload = pr_event_payload("opened");
        let sig = sign(payload.as_bytes());
        let app = router(test_state());
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/webhook")
                    .header("x-hub-signature-256", &sig)
                    .header("x-github-event", "pull_request")
                    .body(Body::from(payload))
                    .unwrap(),
            )
            .await
            .unwrap();
        // Returns 202 immediately — the actual review will fail (no real GitHub)
        // but the webhook handler itself accepts the event
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
    }

    #[tokio::test]
    async fn webhook_semaphore_exhausted_returns_503() {
        let state = AppState {
            config: Arc::new(AppConfig::default()),
            webhook_secret: TEST_SECRET.into(),
            github_token: TEST_TOKEN.into(),
            // Zero capacity — all requests will be rejected
            review_semaphore: Arc::new(Semaphore::new(0)),
        };
        let payload = pr_event_payload("opened");
        let sig = sign(payload.as_bytes());
        let app = router(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/webhook")
                    .header("x-hub-signature-256", &sig)
                    .header("x-github-event", "pull_request")
                    .body(Body::from(payload))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn webhook_malformed_payload_returns_bad_request() {
        let payload = b"not valid json";
        let sig = sign(payload);
        let app = router(test_state());
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/webhook")
                    .header("x-hub-signature-256", &sig)
                    .header("x-github-event", "pull_request")
                    .body(Body::from(&payload[..]))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}
