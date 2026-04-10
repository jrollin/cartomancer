//! CartogEnricher — wraps cartog Database for blast radius, callers, and impact.

use anyhow::Result;
use cartog::db::Database;
use tracing::debug;

use cartomancer_core::finding::{Finding, GraphContext};

/// Enriches findings with code graph context from cartog.
pub struct CartogEnricher {
    db: Database,
}

/// Signals relevant to domain-sensitive escalation.
const AUTH_SIGNALS: [&str; 8] = [
    "auth",
    "login",
    "token",
    "session",
    "permission",
    "role",
    "oauth",
    "jwt",
];
const PAYMENT_SIGNALS: [&str; 6] = ["payment", "billing", "charge", "stripe", "invoice", "price"];

impl CartogEnricher {
    /// Open the cartog database at the given path.
    pub fn open(db_path: &str) -> Result<Self> {
        let db = Database::open(db_path, cartog::db::DEFAULT_EMBEDDING_DIM)?;
        Ok(Self { db })
    }

    /// Create from an existing in-memory database (for testing).
    pub fn from_db(db: Database) -> Self {
        Self { db }
    }

    /// Enrich a single finding with graph context.
    pub fn enrich(&self, finding: &mut Finding) -> Result<()> {
        let symbol_name = self.resolve_symbol(&finding.file_path, finding.start_line);
        let Some(name) = symbol_name else {
            return Ok(());
        };

        debug!(symbol = %name, "enriching finding");

        let impact = self.db.impact(&name, 3)?;
        let blast_radius = impact.len() as u32;

        let refs = self.db.refs(&name, None)?;
        let callers: Vec<String> = refs
            .iter()
            .filter_map(|(_, sym)| sym.as_ref().map(|s| s.name.clone()))
            .collect();

        let mut all_symbols: Vec<&str> = callers.iter().map(|s| s.as_str()).collect();
        all_symbols.push(&name);
        let domain_tags = detect_domain_tags(&all_symbols);

        finding.graph_context = Some(GraphContext {
            symbol_name: Some(name),
            callers,
            blast_radius,
            is_public_api: false, // TODO: check visibility from cartog
            domain_tags,
        });

        Ok(())
    }

    /// Enrich all findings in a batch.
    pub fn enrich_batch(&self, findings: &mut [Finding]) -> Result<()> {
        for finding in findings.iter_mut() {
            self.enrich(finding)?;
        }
        Ok(())
    }

    /// Resolve the primary symbol at a given file:line using cartog outline.
    fn resolve_symbol(&self, file_path: &str, line: u32) -> Option<String> {
        let symbols = self.db.outline(file_path).ok()?;
        symbols
            .iter()
            .filter(|s| s.start_line <= line && line <= s.end_line)
            .min_by_key(|s| s.end_line - s.start_line)
            .map(|s| s.name.clone())
    }
}

fn detect_domain_tags(symbol_names: &[&str]) -> Vec<String> {
    let mut tags = Vec::new();
    let has = |signals: &[&str]| {
        symbol_names
            .iter()
            .any(|s| signals.iter().any(|sig| s.to_lowercase().contains(sig)))
    };
    if has(&AUTH_SIGNALS) {
        tags.push("auth".into());
    }
    if has(&PAYMENT_SIGNALS) {
        tags.push("payment".into());
    }
    tags
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_auth_domain() {
        let names = vec!["UserAuthService", "validate_token"];
        let tags = detect_domain_tags(&names);
        assert!(tags.contains(&"auth".to_string()));
    }

    #[test]
    fn detect_payment_domain() {
        let names = vec!["StripeClient", "process_charge"];
        let tags = detect_domain_tags(&names);
        assert!(tags.contains(&"payment".to_string()));
    }

    #[test]
    fn detect_no_domain() {
        let names = vec!["parse_config", "read_file"];
        let tags = detect_domain_tags(&names);
        assert!(tags.is_empty());
    }
}
