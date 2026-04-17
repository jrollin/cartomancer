//! Core domain model for the Cartomancer PR review pipeline.
//!
//! Pure types with no side effects, no async, no I/O. Every other crate depends
//! on `cartomancer-core` for shared vocabulary.

pub mod config;
pub mod diff;
pub mod finding;
pub mod review;
pub mod severity;
