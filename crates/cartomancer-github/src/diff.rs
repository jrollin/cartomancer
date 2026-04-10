//! Unified diff parsing utilities.

use anyhow::Result;

use cartomancer_core::diff::PullRequestDiff;

/// Parse a raw unified diff string into structured chunks.
pub fn parse_diff(_raw_diff: &str) -> Result<PullRequestDiff> {
    todo!()
}
