//! SQLite persistence layer for Cartomancer scan results.
//!
//! Stores scan records, findings (with fingerprints for deduplication),
//! and dismissals (false positive suppression). Schema is versioned via
//! `PRAGMA user_version` with forward-compatible migrations.

pub mod fingerprint;
pub mod schema;
pub mod store;
pub mod types;
