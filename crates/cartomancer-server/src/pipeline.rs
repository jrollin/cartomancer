//! Pipeline orchestration — the core state machine.
//!
//! Stages:
//! 1. Fetch diff (GitHub API)
//! 2. Run semgrep scan (subprocess)
//! 3. Enrich with cartog graph context
//! 4. Escalate severity based on blast radius
//! 5. LLM deepen high-severity findings (conditional)
//! 6. Post review comments to GitHub

use anyhow::Result;

use cartomancer_core::review::ReviewResult;

/// Run the full review pipeline for a single PR.
#[allow(dead_code)] // wired when `review` command is implemented
pub async fn run_pipeline(_repo: &str, _pr_number: u64) -> Result<ReviewResult> {
    todo!()
}
