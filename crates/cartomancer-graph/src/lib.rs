//! Cartog integration and severity escalation for Cartomancer.
//!
//! This crate wraps the cartog `Database` API to compute blast radius, callers,
//! and impact for opengrep findings, then applies escalation rules to upgrade
//! severity based on graph context.

pub mod enricher;
pub mod escalator;
