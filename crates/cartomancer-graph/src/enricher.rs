//! CartogEnricher — wraps cartog Database for blast radius, callers, and impact.

use std::collections::{HashMap, HashSet};

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

    /// Batch-enrich findings with deduplicated DB queries.
    ///
    /// Strategy: one `outline()` per unique file, one `impact()` + `refs()` per
    /// unique resolved symbol. Results are distributed back to findings via lookup.
    /// Produces identical `GraphContext` as serial `enrich()` for the same input.
    pub fn enrich_batch_optimized(&self, findings: &mut [Finding]) -> Result<()> {
        if findings.is_empty() {
            return Ok(());
        }

        // Step 1: collect unique file paths
        let mut unique_files: Vec<String> = findings.iter().map(|f| f.file_path.clone()).collect();
        unique_files.sort();
        unique_files.dedup();

        // Step 2: outline() once per file → HashMap<file, Vec<Symbol>>
        let mut outlines: HashMap<String, Vec<cartog::types::Symbol>> =
            HashMap::with_capacity(unique_files.len());
        for file in &unique_files {
            match self.db.outline(file) {
                Ok(symbols) => {
                    outlines.insert(file.clone(), symbols);
                }
                Err(e) => {
                    warn!(file = %file, err = %e, "outline failed, findings in this file will not be enriched");
                }
            }
        }

        // Step 3: resolve symbol per finding → collect unique symbols
        // Track unique symbol names for batched impact/refs queries
        let mut symbol_names: HashSet<String> = HashSet::new();
        // Per-finding resolved symbol: (name, is_public) — preserves per-finding visibility
        let mut finding_symbols: Vec<Option<(String, bool)>> = Vec::with_capacity(findings.len());

        for finding in findings.iter() {
            let resolved = if let Some(symbols) = outlines.get(&finding.file_path) {
                symbols
                    .iter()
                    .filter(|s| {
                        s.start_line <= finding.start_line && finding.start_line <= s.end_line
                    })
                    .min_by_key(|s| s.end_line - s.start_line)
                    .map(|s| (s.name.clone(), s.visibility == Visibility::Public))
            } else {
                None
            };

            match resolved {
                Some((name, is_public)) => {
                    symbol_names.insert(name.clone());
                    finding_symbols.push(Some((name, is_public)));
                }
                None => {
                    finding_symbols.push(None);
                }
            }
        }

        // Step 4: impact() + refs() once per unique symbol → build shared context
        // context_map stores blast_radius, callers, domain_tags — is_public_api is set per-finding
        let mut context_map: HashMap<String, GraphContext> =
            HashMap::with_capacity(symbol_names.len());

        for name in &symbol_names {
            let blast_radius = match self.db.impact(name, self.impact_depth) {
                Ok(impact) => impact.len() as u32,
                Err(e) => {
                    warn!(symbol = %name, err = %e, "impact query failed, skipping symbol");
                    continue;
                }
            };

            let callers: Vec<String> = match self.db.refs(name, None) {
                Ok(refs) => refs
                    .iter()
                    .filter_map(|(_, sym)| sym.as_ref().map(|s| s.name.clone()))
                    .collect(),
                Err(e) => {
                    warn!(symbol = %name, err = %e, "refs query failed, skipping symbol");
                    continue;
                }
            };

            let mut all_symbols: Vec<&str> = callers.iter().map(|s| s.as_str()).collect();
            all_symbols.push(name);
            let domain_tags = detect_domain_tags(&all_symbols);

            context_map.insert(
                name.clone(),
                GraphContext {
                    symbol_name: Some(name.clone()),
                    callers,
                    blast_radius,
                    is_public_api: false, // placeholder — overridden per-finding below
                    domain_tags,
                },
            );
        }

        // Step 5: distribute GraphContext back to findings, with per-finding is_public_api
        let mut enriched = 0u32;
        for (finding, resolved) in findings.iter_mut().zip(finding_symbols.iter()) {
            if let Some((name, is_public)) = resolved {
                if let Some(ctx) = context_map.get(name) {
                    let mut finding_ctx = ctx.clone();
                    finding_ctx.is_public_api = *is_public;
                    finding.graph_context = Some(finding_ctx);
                    enriched += 1;
                }
            }
        }

        debug!(
            enriched,
            unique_files = unique_files.len(),
            unique_symbols = symbol_names.len(),
            "batch enrichment complete"
        );
        Ok(())
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
            is_new: None,
            enclosing_context: None,
            suggested_fix: None,
            agent_prompt: None,
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
        let mut findings = vec![make_finding("src/billing.rs", 15)];
        enricher.enrich_batch_optimized(&mut findings).unwrap();
        let ctx = findings[0].graph_context.as_ref().unwrap();
        assert_eq!(ctx.symbol_name.as_deref(), Some("process_payment"));
    }

    #[test]
    fn enrich_no_symbol_at_line() {
        let enricher = test_enricher();
        let mut findings = vec![make_finding("src/billing.rs", 999)];
        enricher.enrich_batch_optimized(&mut findings).unwrap();
        assert!(findings[0].graph_context.is_none());
    }

    #[test]
    fn enrich_picks_narrowest_symbol() {
        let enricher = test_enricher();
        // Line 15 is inside both BillingService (1-50) and process_payment (10-30).
        // Should pick process_payment (narrower span).
        let mut findings = vec![make_finding("src/billing.rs", 15)];
        enricher.enrich_batch_optimized(&mut findings).unwrap();
        let ctx = findings[0].graph_context.as_ref().unwrap();
        assert_eq!(ctx.symbol_name.as_deref(), Some("process_payment"));
    }

    #[test]
    fn enrich_preserves_visibility() {
        let enricher = test_enricher();
        let mut findings = vec![
            make_finding("src/billing.rs", 15),
            make_finding("src/auth.rs", 10),
        ];
        enricher.enrich_batch_optimized(&mut findings).unwrap();
        // process_payment defaults to Public
        assert!(findings[0].graph_context.as_ref().unwrap().is_public_api);
        // validate_token was set to Private
        assert!(!findings[1].graph_context.as_ref().unwrap().is_public_api);
    }

    #[test]
    fn enrich_unknown_file_returns_ok() {
        let enricher = test_enricher();
        let mut findings = vec![make_finding("src/nonexistent.rs", 1)];
        enricher.enrich_batch_optimized(&mut findings).unwrap();
        assert!(findings[0].graph_context.is_none());
    }

    #[test]
    fn enrich_batch_continues_on_individual_failures() {
        let enricher = test_enricher();
        let mut findings = vec![
            make_finding("src/billing.rs", 15),
            make_finding("src/nonexistent.rs", 1),
            make_finding("src/auth.rs", 10),
        ];
        enricher.enrich_batch_optimized(&mut findings).unwrap();
        assert!(findings[0].graph_context.is_some());
        assert!(findings[1].graph_context.is_none());
        assert!(findings[2].graph_context.is_some());
    }

    #[test]
    fn enrich_batch_optimized_deduplicates_outline_calls() {
        let enricher = test_enricher();
        // Two findings in the same file at same line → should share symbol resolution
        let mut findings = vec![
            make_finding("src/billing.rs", 15),
            make_finding("src/billing.rs", 15),
            make_finding("src/auth.rs", 10),
        ];
        enricher.enrich_batch_optimized(&mut findings).unwrap();
        assert!(findings[0].graph_context.is_some());
        assert!(findings[1].graph_context.is_some());
        assert!(findings[2].graph_context.is_some());

        // Both billing findings should have the same symbol
        let ctx0 = findings[0].graph_context.as_ref().unwrap();
        let ctx1 = findings[1].graph_context.as_ref().unwrap();
        assert_eq!(ctx0.symbol_name, ctx1.symbol_name);
        assert_eq!(ctx0.blast_radius, ctx1.blast_radius);
    }

    #[test]
    fn enrich_batch_optimized_handles_no_symbol() {
        let enricher = test_enricher();
        let mut findings = vec![
            make_finding("src/nonexistent.rs", 1),
            make_finding("src/billing.rs", 999),
        ];
        enricher.enrich_batch_optimized(&mut findings).unwrap();
        assert!(findings[0].graph_context.is_none());
        assert!(findings[1].graph_context.is_none());
    }

    #[test]
    fn enrich_batch_optimized_empty_input() {
        let enricher = test_enricher();
        let mut findings: Vec<Finding> = vec![];
        enricher.enrich_batch_optimized(&mut findings).unwrap();
    }

    #[test]
    fn enrich_batch_optimized_preserves_per_finding_visibility() {
        // Same symbol name "shared_fn" in two files with different visibility
        let db = Database::open_memory().unwrap();

        let public_sym = Symbol::new(
            "shared_fn",
            SymbolKind::Function,
            "src/public_mod.rs",
            1,
            20,
            0,
            400,
            None,
        );
        db.insert_symbol(&public_sym).unwrap();

        let private_sym = Symbol::new(
            "shared_fn",
            SymbolKind::Function,
            "src/private_mod.rs",
            1,
            20,
            0,
            400,
            None,
        )
        .with_visibility(Visibility::Private);
        db.insert_symbol(&private_sym).unwrap();

        let enricher = CartogEnricher::from_db(db);

        let mut findings = vec![
            make_finding("src/public_mod.rs", 10),
            make_finding("src/private_mod.rs", 10),
        ];
        enricher.enrich_batch_optimized(&mut findings).unwrap();

        let ctx0 = findings[0].graph_context.as_ref().unwrap();
        let ctx1 = findings[1].graph_context.as_ref().unwrap();

        // Same symbol name, but different visibility per file
        assert_eq!(ctx0.symbol_name, ctx1.symbol_name);
        assert!(ctx0.is_public_api, "public_mod finding should be public");
        assert!(!ctx1.is_public_api, "private_mod finding should be private");
    }
}
