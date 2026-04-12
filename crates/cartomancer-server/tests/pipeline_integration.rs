//! Integration tests for the review pipeline's post-scan stages.
//!
//! These tests exercise the cross-crate integration paths that matter most:
//! - Store persistence round-trip (core types → store → retrieval)
//! - Severity escalation (core findings → graph escalator → adjusted severity)
//! - Regression detection (store baseline → new vs. existing annotation)
//! - Dismissal filtering (store dismissal → finding suppression)
//!
//! The full pipeline (GitHub API, opengrep subprocess, git clone) is not tested here
//! because it requires external dependencies. Those stages are tested via unit tests
//! with mocked HTTP and subprocess output.

use cartomancer_core::finding::{Finding, GraphContext};
use cartomancer_core::severity::Severity;
use cartomancer_graph::escalator::SeverityEscalator;
use cartomancer_store::store::Store;
use cartomancer_store::types::{Dismissal, ScanFilter, ScanRecord};

/// Build a test finding with configurable fields.
fn make_finding(rule: &str, file: &str, severity: Severity, snippet: &str) -> Finding {
    Finding {
        rule_id: rule.into(),
        message: format!("{rule} finding in {file}"),
        severity,
        file_path: file.into(),
        start_line: 10,
        end_line: 15,
        snippet: snippet.into(),
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

fn make_finding_with_graph(
    rule: &str,
    file: &str,
    severity: Severity,
    snippet: &str,
    blast_radius: u32,
    callers: Vec<&str>,
    domain_tags: Vec<&str>,
) -> Finding {
    let mut f = make_finding(rule, file, severity, snippet);
    f.graph_context = Some(GraphContext {
        symbol_name: Some("target_fn".into()),
        callers: callers.into_iter().map(String::from).collect(),
        blast_radius,
        is_public_api: true,
        domain_tags: domain_tags.into_iter().map(String::from).collect(),
    });
    f
}

fn open_temp_store() -> Store {
    Store::open(":memory:").expect("failed to open in-memory store")
}

fn insert_test_scan(store: &Store, repo: &str, branch: &str, findings: &[Finding]) -> i64 {
    let record = ScanRecord {
        id: None,
        repo: repo.into(),
        branch: branch.into(),
        commit_sha: "abc123".into(),
        command: "review".into(),
        pr_number: Some(42),
        finding_count: findings.len() as u32,
        summary: "test summary".into(),
        created_at: None,
        stage: "completed".into(),
        error_message: None,
        failed_at_stage: None,
    };
    let scan_id = store.insert_scan(&record).expect("insert_scan failed");
    if !findings.is_empty() {
        store
            .insert_findings(scan_id, findings)
            .expect("insert_findings failed");
    }
    scan_id
}

/// Create a dismissal for a finding (mirrors what the CLI dismiss command does).
fn dismiss_finding(store: &Store, finding: &Finding, reason: Option<&str>) -> i64 {
    let fp = cartomancer_store::fingerprint::compute(
        &finding.rule_id,
        &finding.file_path,
        &finding.snippet,
    );
    let snippet_hash = cartomancer_store::fingerprint::compute(
        &finding.rule_id,
        &finding.file_path,
        &finding.snippet,
    );
    let dismissal = Dismissal {
        id: None,
        fingerprint: fp,
        rule_id: finding.rule_id.clone(),
        file_path: finding.file_path.clone(),
        start_line: finding.start_line,
        end_line: finding.end_line,
        snippet_hash,
        reason: reason.map(String::from),
        created_at: None,
    };
    store.dismiss(&dismissal).expect("dismiss failed")
}

// ---------------------------------------------------------------------------
// Store round-trip tests
// ---------------------------------------------------------------------------

#[test]
fn store_round_trip_preserves_finding_fields() {
    let store = open_temp_store();
    let mut finding = make_finding(
        "sql-injection",
        "src/db.rs",
        Severity::Critical,
        "query(raw)",
    );
    finding.cwe = Some("CWE-89".into());
    finding.llm_analysis = Some("SQL injection via string interpolation.".into());
    finding.suggested_fix = Some("-query(raw)\n+query_prepared(stmt)".into());
    finding.agent_prompt = Some("Apply prepared statement fix.".into());
    finding.enclosing_context = Some("fn handler() { query(raw); }".into());
    finding.escalation_reasons = vec!["blast radius >= 20".into(), "auth domain".into()];
    finding.graph_context = Some(GraphContext {
        symbol_name: Some("handler".into()),
        callers: vec!["main".into(), "serve".into()],
        blast_radius: 20,
        is_public_api: true,
        domain_tags: vec!["auth".into()],
    });

    let scan_id = insert_test_scan(&store, "owner/repo", "main", &[finding.clone()]);

    let stored = store.get_findings(scan_id).expect("get_findings failed");
    assert_eq!(stored.len(), 1);

    let s = &stored[0];
    assert_eq!(s.rule_id, "sql-injection");
    assert_eq!(s.file_path, "src/db.rs");
    assert_eq!(s.severity, "critical");
    assert_eq!(s.start_line, 10);
    assert_eq!(s.end_line, 15);
    assert_eq!(s.snippet, "query(raw)");
    assert_eq!(s.cwe.as_deref(), Some("CWE-89"));
    assert_eq!(
        s.llm_analysis.as_deref(),
        Some("SQL injection via string interpolation.")
    );
    assert_eq!(
        s.suggested_fix.as_deref(),
        Some("-query(raw)\n+query_prepared(stmt)")
    );
    assert_eq!(
        s.agent_prompt.as_deref(),
        Some("Apply prepared statement fix.")
    );
    assert_eq!(
        s.enclosing_context.as_deref(),
        Some("fn handler() { query(raw); }")
    );

    // Graph context round-trip via JSON
    let graph: GraphContext = serde_json::from_str(s.graph_context_json.as_ref().unwrap()).unwrap();
    assert_eq!(graph.symbol_name.as_deref(), Some("handler"));
    assert_eq!(graph.blast_radius, 20);
    assert!(graph.is_public_api);
    assert_eq!(graph.callers, vec!["main", "serve"]);
    assert_eq!(graph.domain_tags, vec!["auth"]);

    // Escalation reasons round-trip via JSON
    let reasons: Vec<String> =
        serde_json::from_str(s.escalation_reasons_json.as_ref().unwrap()).unwrap();
    assert_eq!(reasons, vec!["blast radius >= 20", "auth domain"]);
}

#[test]
fn store_round_trip_handles_minimal_finding() {
    let store = open_temp_store();
    let finding = make_finding(
        "info-leak",
        "src/api.rs",
        Severity::Info,
        "println!(secret)",
    );

    let scan_id = insert_test_scan(&store, "owner/repo", "main", &[finding]);

    let stored = store.get_findings(scan_id).expect("get_findings failed");
    assert_eq!(stored.len(), 1);

    let s = &stored[0];
    assert_eq!(s.rule_id, "info-leak");
    assert_eq!(s.severity, "info");
    assert!(s.graph_context_json.is_none());
    assert!(s.llm_analysis.is_none());
    assert!(s.escalation_reasons_json.is_none());
    assert!(s.enclosing_context.is_none());
    assert!(s.suggested_fix.is_none());
    assert!(s.agent_prompt.is_none());
}

#[test]
fn store_multiple_findings_per_scan() {
    let store = open_temp_store();
    let findings: Vec<Finding> = (0..5)
        .map(|i| {
            make_finding(
                &format!("rule-{i}"),
                &format!("src/file{i}.rs"),
                Severity::Warning,
                &format!("snippet {i}"),
            )
        })
        .collect();

    let scan_id = insert_test_scan(&store, "owner/repo", "feature", &findings);

    let stored = store.get_findings(scan_id).expect("get_findings failed");
    assert_eq!(stored.len(), 5);

    for (i, s) in stored.iter().enumerate() {
        assert_eq!(s.rule_id, format!("rule-{i}"));
    }
}

// ---------------------------------------------------------------------------
// Regression detection tests
// ---------------------------------------------------------------------------

#[test]
fn regression_baseline_identifies_new_vs_existing_findings() {
    let store = open_temp_store();

    // Baseline scan on main branch
    let existing = make_finding("xss", "src/view.rs", Severity::Error, "innerHTML = input");
    insert_test_scan(&store, "owner/repo", "main", &[existing]);

    // Load baseline fingerprints
    let baseline = store
        .baseline_fingerprints("owner/repo", "main")
        .expect("baseline_fingerprints failed");
    assert_eq!(baseline.len(), 1, "baseline should have one fingerprint");

    // Simulate annotating PR findings
    let mut pr_findings = vec![
        make_finding("xss", "src/view.rs", Severity::Error, "innerHTML = input"), // existing
        make_finding("sqli", "src/db.rs", Severity::Critical, "exec(raw_sql)"),   // new
    ];

    for f in &mut pr_findings {
        let fp = cartomancer_store::fingerprint::compute(&f.rule_id, &f.file_path, &f.snippet);
        f.is_new = Some(!baseline.contains(&fp));
    }

    assert_eq!(pr_findings[0].is_new, Some(false), "xss should be existing");
    assert_eq!(pr_findings[1].is_new, Some(true), "sqli should be new");
}

// ---------------------------------------------------------------------------
// Dismissal filtering tests
// ---------------------------------------------------------------------------

#[test]
fn dismissal_suppresses_matching_finding() {
    let store = open_temp_store();

    let finding = make_finding(
        "false-positive",
        "src/lib.rs",
        Severity::Warning,
        "safe_code()",
    );
    dismiss_finding(&store, &finding, Some("false positive, safe pattern"));

    // Verify dismissal exists
    let dismissed = store.list_dismissals().expect("list_dismissals failed");
    assert_eq!(dismissed.len(), 1);
    assert_eq!(dismissed[0].rule_id, "false-positive");
    assert_eq!(
        dismissed[0].reason.as_deref(),
        Some("false positive, safe pattern")
    );

    // Check fingerprint-based suppression
    let dismissed_fps = store
        .dismissed_fingerprints()
        .expect("dismissed_fingerprints failed");
    assert_eq!(dismissed_fps.len(), 1);

    let fp = cartomancer_store::fingerprint::compute("false-positive", "src/lib.rs", "safe_code()");
    assert!(
        dismissed_fps.contains(&fp),
        "dismissed fingerprints should contain the finding's fingerprint"
    );
}

#[test]
fn undismiss_restores_finding() {
    let store = open_temp_store();

    let finding = make_finding("rule-1", "src/a.rs", Severity::Warning, "code()");
    dismiss_finding(&store, &finding, None);
    assert_eq!(store.list_dismissals().unwrap().len(), 1);

    let dismissal_id = store.list_dismissals().unwrap()[0].id.unwrap();
    store.undismiss(dismissal_id).unwrap();
    assert_eq!(store.list_dismissals().unwrap().len(), 0);
}

// ---------------------------------------------------------------------------
// Severity escalation integration tests
// ---------------------------------------------------------------------------

#[test]
fn escalator_upgrades_high_blast_radius_to_error() {
    let escalator = SeverityEscalator::new(5);
    let mut findings = vec![make_finding_with_graph(
        "unused-var",
        "src/lib.rs",
        Severity::Warning,
        "let _x = 1;",
        10, // blast_radius >= threshold (5)
        vec!["caller1", "caller2"],
        vec![],
    )];

    escalator.escalate_batch(&mut findings, &Default::default());

    assert!(
        findings[0].severity >= Severity::Error,
        "blast radius 10 (>= 2*threshold) should escalate to at least Error, got {}",
        findings[0].severity
    );
    assert!(
        !findings[0].escalation_reasons.is_empty(),
        "should have escalation reasons"
    );
}

#[test]
fn escalator_upgrades_auth_domain_to_critical() {
    let escalator = SeverityEscalator::new(5);
    let mut findings = vec![make_finding_with_graph(
        "hardcoded-secret",
        "src/auth.rs",
        Severity::Warning,
        "let token = \"abc\";",
        1, // low blast radius
        vec!["login"],
        vec!["auth"], // auth domain tag
    )];

    escalator.escalate_batch(&mut findings, &Default::default());

    assert_eq!(
        findings[0].severity,
        Severity::Critical,
        "auth domain should escalate to Critical"
    );
}

#[test]
fn escalator_preserves_severity_when_no_escalation_needed() {
    let escalator = SeverityEscalator::new(5);
    let mut findings = vec![make_finding_with_graph(
        "style-issue",
        "src/ui.rs",
        Severity::Info,
        "let x = 1;",
        1,      // low blast radius
        vec![], // no callers
        vec![], // no domain tags
    )];

    escalator.escalate_batch(&mut findings, &Default::default());

    assert_eq!(
        findings[0].severity,
        Severity::Info,
        "no escalation trigger — severity should remain Info"
    );
    assert!(
        findings[0].escalation_reasons.is_empty(),
        "should have no escalation reasons"
    );
}

#[test]
fn escalator_many_callers_escalates_to_error() {
    let escalator = SeverityEscalator::new(5);
    let callers: Vec<&str> = (0..12).map(|_| "some_caller").collect();
    let mut findings = vec![make_finding_with_graph(
        "logic-bug",
        "src/core.rs",
        Severity::Warning,
        "if x > 0 {}",
        3,       // below threshold
        callers, // >= 10 callers
        vec![],
    )];

    escalator.escalate_batch(&mut findings, &Default::default());

    assert!(
        findings[0].severity >= Severity::Error,
        ">= 10 callers should escalate to at least Error, got {}",
        findings[0].severity
    );
}

// ---------------------------------------------------------------------------
// End-to-end: persist → retrieve → escalate → regression → dismiss
// ---------------------------------------------------------------------------

#[test]
fn full_post_scan_flow() {
    let store = open_temp_store();

    // Step 1: Create and persist initial findings (simulating baseline on main)
    let baseline_findings = vec![
        make_finding("xss", "src/view.rs", Severity::Error, "innerHTML = input"),
        make_finding("log-leak", "src/api.rs", Severity::Info, "println!(token)"),
    ];
    insert_test_scan(&store, "owner/repo", "main", &baseline_findings);

    // Step 2: Simulate PR with one existing + one new finding
    let mut pr_findings = vec![
        make_finding_with_graph(
            "xss",
            "src/view.rs",
            Severity::Error,
            "innerHTML = input",
            15,
            vec!["render", "template", "page"],
            vec![],
        ),
        make_finding_with_graph(
            "sqli",
            "src/db.rs",
            Severity::Warning,
            "query(user_input)",
            8,
            vec!["handler", "api_endpoint"],
            vec!["payment"],
        ),
    ];

    // Step 3: Escalate severities
    let escalator = SeverityEscalator::new(5);
    escalator.escalate_batch(&mut pr_findings, &Default::default());

    // The payment domain finding should be escalated
    assert_eq!(
        pr_findings[1].severity,
        Severity::Critical,
        "payment domain should escalate to Critical"
    );

    // Step 4: Annotate regression
    let baseline = store.baseline_fingerprints("owner/repo", "main").unwrap();
    for f in &mut pr_findings {
        let fp = cartomancer_store::fingerprint::compute(&f.rule_id, &f.file_path, &f.snippet);
        f.is_new = Some(!baseline.contains(&fp));
    }
    assert_eq!(pr_findings[0].is_new, Some(false)); // xss is existing
    assert_eq!(pr_findings[1].is_new, Some(true)); // sqli is new

    // Step 5: Persist PR scan
    insert_test_scan(&store, "owner/repo", "feature-branch", &pr_findings);

    // Step 6: Dismiss the existing xss finding
    dismiss_finding(
        &store,
        &pr_findings[0],
        Some("known issue, tracked in JIRA"),
    );

    // Step 7: Verify dismissal filters correctly
    let dismissed_fps = store.dismissed_fingerprints().unwrap();
    let xss_fp = cartomancer_store::fingerprint::compute("xss", "src/view.rs", "innerHTML = input");
    assert!(dismissed_fps.contains(&xss_fp));

    let sqli_fp = cartomancer_store::fingerprint::compute("sqli", "src/db.rs", "query(user_input)");
    assert!(
        !dismissed_fps.contains(&sqli_fp),
        "sqli should not be dismissed"
    );

    // Step 8: Verify scan history
    let filter = ScanFilter::default();
    let scans = store.list_scans(&filter).expect("list_scans failed");
    assert_eq!(scans.len(), 2, "should have baseline + PR scans");
}

// ---------------------------------------------------------------------------
// Update scan findings (stage persistence)
// ---------------------------------------------------------------------------

#[test]
fn update_scan_findings_replaces_all_findings() {
    let store = open_temp_store();
    let initial = vec![make_finding(
        "rule-a",
        "src/a.rs",
        Severity::Warning,
        "old code",
    )];
    let scan_id = insert_test_scan(&store, "owner/repo", "main", &initial);

    assert_eq!(store.get_findings(scan_id).unwrap().len(), 1);

    // Replace with enriched findings
    let mut updated = vec![
        make_finding_with_graph(
            "rule-a",
            "src/a.rs",
            Severity::Error,
            "old code",
            10,
            vec!["caller"],
            vec!["auth"],
        ),
        make_finding("rule-b", "src/b.rs", Severity::Info, "new finding"),
    ];
    updated[0].llm_analysis = Some("This is dangerous.".into());

    store
        .update_scan_findings(scan_id, &updated)
        .expect("update_scan_findings failed");

    let stored = store.get_findings(scan_id).unwrap();
    assert_eq!(stored.len(), 2, "should have replaced with 2 findings");
    assert_eq!(stored[0].severity, "error");
    assert!(stored[0].graph_context_json.is_some());
    assert_eq!(
        stored[0].llm_analysis.as_deref(),
        Some("This is dangerous.")
    );
    assert_eq!(stored[1].rule_id, "rule-b");
}

// ---------------------------------------------------------------------------
// Scan stage tracking
// ---------------------------------------------------------------------------

#[test]
fn scan_stage_tracking_progression() {
    let store = open_temp_store();

    let record = ScanRecord {
        id: None,
        repo: "owner/repo".into(),
        branch: "feature".into(),
        commit_sha: "abc123".into(),
        command: "review".into(),
        pr_number: Some(1),
        finding_count: 0,
        summary: String::new(),
        created_at: None,
        stage: "pending".into(),
        error_message: None,
        failed_at_stage: None,
    };
    let scan_id = store.insert_scan(&record).unwrap();

    // Progress through stages
    for stage in &["scanned", "enriched", "escalated", "deepened", "completed"] {
        store.update_scan_stage(scan_id, stage).unwrap();
        let scan = store.get_scan(scan_id).unwrap().unwrap();
        assert_eq!(scan.stage, *stage);
    }
}

#[test]
fn scan_failure_records_error_metadata() {
    let store = open_temp_store();

    let record = ScanRecord {
        id: None,
        repo: "owner/repo".into(),
        branch: "feature".into(),
        commit_sha: "abc123".into(),
        command: "review".into(),
        pr_number: Some(1),
        finding_count: 0,
        summary: String::new(),
        created_at: None,
        stage: "pending".into(),
        error_message: None,
        failed_at_stage: None,
    };
    let scan_id = store.insert_scan(&record).unwrap();

    store
        .mark_scan_failed(scan_id, "enriched", "cartog database not found")
        .unwrap();

    let scan = store.get_scan(scan_id).unwrap().unwrap();
    // mark_scan_failed records where it failed and why, but does not change stage
    assert_eq!(
        scan.stage, "pending",
        "stage should remain at last checkpoint"
    );
    assert_eq!(
        scan.error_message.as_deref(),
        Some("cartog database not found")
    );
    assert_eq!(scan.failed_at_stage.as_deref(), Some("enriched"));
}
