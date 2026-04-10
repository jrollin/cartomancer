//! GitHub API integration for Cartomancer.
//!
//! Handles diff fetching, PR comment posting, and webhook payload parsing.
//! Uses raw reqwest calls to the GitHub REST API.

pub mod client;
pub mod diff;
pub mod types;
pub mod webhook;
