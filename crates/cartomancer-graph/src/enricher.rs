//! CartogEnricher — wraps cartog Database for blast radius, callers, and impact.

use anyhow::Result;
use cartog::db::Database;
use cartog::types::Visibility;
use tracing::{debug, warn};

use cartomancer_core::finding::{Finding, GraphContext};

/// Enriches findings with code graph context from cartog.
pub struct CartogEnricher {
    db: Database,
    impact_depth: u32,
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
    pub fn open(db_path: &str, impact_depth: u32) -> Result<Self> {
        let db = Database::open(db_path, cartog::db::DEFAULT_EMBEDDING_DIM)?;
        Ok(Self { db, impact_depth })
    }

    /// Create from an existing in-memory database (for testing).
    pub fn from_db(db: Database) -> Self {
        Self {
            db,
            impact_depth: 3,
        }
    }

    /// Enrich a single finding with graph context.
    pub fn enrich(&self, finding: &mut Finding) -> Result<()> {
        let resolved = self.resolve_symbol(&finding.file_path, finding.start_line)?;
        let Some((name, is_public)) = resolved else {
            return Ok(());
        };

        debug!(symbol = %name, "enriching finding");

        let impact = self.db.impact(&name, self.impact_depth)?;
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
            is_public_api: is_public,
            domain_tags,
        });

        Ok(())
    }

    /// Enrich all findings in a batch, logging and skipping individual failures.
    pub fn enrich_batch(&self, findings: &mut [Finding]) -> Result<()> {
        let mut enriched = 0u32;
        let mut failed = 0u32;
        for finding in findings.iter_mut() {
            match self.enrich(finding) {
                Ok(()) => {
                    if finding.graph_context.is_some() {
                        enriched += 1;
                    }
                }
                Err(e) => {
                    warn!(
                        rule = %finding.rule_id,
                        file = %finding.file_path,
                        line = finding.start_line,
                        err = %e,
                        "failed to enrich finding, skipping"
                    );
                    failed += 1;
                }
            }
        }
        debug!(enriched, failed, "batch enrichment complete");
        Ok(())
    }

    /// Resolve the primary symbol at a given file:line using cartog outline.
    /// Returns the symbol name and whether it has public visibility.
    fn resolve_symbol(&self, file_path: &str, line: u32) -> Result<Option<(String, bool)>> {
        let symbols = self.db.outline(file_path)?;
        Ok(symbols
            .iter()
            .filter(|s| s.start_line <= line && line <= s.end_line)
            .min_by_key(|s| s.end_line - s.start_line)
            .map(|s| (s.name.clone(), s.visibility == Visibility::Public)))
    }
}

fn detect_domain_tags(symbol_names: &[&str]) -> Vec<String> {
    let lowered: Vec<String> = symbol_names.iter().map(|s| s.to_lowercase()).collect();
    let mut tags = Vec::new();
    let has = |signals: &[&str]| {
        lowered
            .iter()
            .any(|s| signals.iter().any(|sig| s.contains(sig)))
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
    use cartog::types::{Symbol, SymbolKind};
    use cartomancer_core::severity::Severity;

    fn make_finding(file_path: &str, line: u32) -> Finding {
        Finding {
            rule_id: "TEST-001".into(),
            message: "test".into(),
            severity: Severity::Warning,
            file_path: file_path.into(),
            start_line: line,
            end_line: line,
            snippet: String::new(),
            cwe: None,
            graph_context: None,
            llm_analysis: None,
            escalation_reasons: vec![],
        }
    }

    fn test_enricher() -> CartogEnricher {
        let db = Database::open_memory().unwrap();

        let sym = Symbol::new(
            "process_payment",
            SymbolKind::Function,
            "src/billing.rs",
            10,
            30,
            0,
            500,
            None,
        );
        db.insert_symbol(&sym).unwrap();

        let auth_sym = Symbol::new(
            "validate_token",
            SymbolKind::Function,
            "src/auth.rs",
            5,
            20,
            0,
            300,
            None,
        )
        .with_visibility(Visibility::Private);
        db.insert_symbol(&auth_sym).unwrap();

        // A class containing a method — for narrowest-symbol test
        let class_sym = Symbol::new(
            "BillingService",
            SymbolKind::Class,
            "src/billing.rs",
            1,
            50,
            0,
            1000,
            None,
        );
        db.insert_symbol(&class_sym).unwrap();

        CartogEnricher::from_db(db)
    }

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

    #[test]
    fn enrich_populates_graph_context() {
        let enricher = test_enricher();
        let mut f = make_finding("src/billing.rs", 15);
        enricher.enrich(&mut f).unwrap();
        let ctx = f.graph_context.as_ref().unwrap();
        assert_eq!(ctx.symbol_name.as_deref(), Some("process_payment"));
    }

    #[test]
    fn enrich_no_symbol_at_line() {
        let enricher = test_enricher();
        let mut f = make_finding("src/billing.rs", 999);
        enricher.enrich(&mut f).unwrap();
        assert!(f.graph_context.is_none());
    }

    #[test]
    fn resolve_symbol_picks_narrowest() {
        let enricher = test_enricher();
        // Line 15 is inside both BillingService (1-50) and process_payment (10-30).
        // Should pick process_payment (narrower span).
        let resolved = enricher.resolve_symbol("src/billing.rs", 15).unwrap();
        assert_eq!(resolved.unwrap().0, "process_payment");
    }

    #[test]
    fn resolve_symbol_returns_visibility() {
        let enricher = test_enricher();
        // process_payment defaults to Public visibility
        let (_, is_public) = enricher
            .resolve_symbol("src/billing.rs", 15)
            .unwrap()
            .unwrap();
        assert!(is_public);

        // validate_token was set to Private
        let (_, is_public) = enricher.resolve_symbol("src/auth.rs", 10).unwrap().unwrap();
        assert!(!is_public);
    }

    #[test]
    fn enrich_unknown_file_returns_ok() {
        let enricher = test_enricher();
        let mut f = make_finding("src/nonexistent.rs", 1);
        enricher.enrich(&mut f).unwrap();
        assert!(f.graph_context.is_none());
    }

    #[test]
    fn enrich_batch_continues_on_individual_failures() {
        let enricher = test_enricher();
        let mut findings = vec![
            make_finding("src/billing.rs", 15),
            make_finding("src/nonexistent.rs", 1),
            make_finding("src/auth.rs", 10),
        ];
        enricher.enrich_batch(&mut findings).unwrap();
        // First and third should be enriched (or at least attempted without error)
        // Second has no symbol, so graph_context stays None — that's not a failure
        assert!(findings[0].graph_context.is_some());
        assert!(findings[1].graph_context.is_none());
        assert!(findings[2].graph_context.is_some());
    }
}
