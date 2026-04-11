//! SQLite-backed store for scan results, findings, and dismissals.

use std::collections::HashSet;
use std::path::Path;

use cartomancer_core::finding::Finding;
use rusqlite::{params, Connection};

use crate::fingerprint;
use crate::schema;
use crate::types::*;

/// SQLite persistence layer for cartomancer scan results.
pub struct Store {
    conn: Connection,
}

/// Map a SQLite row to a `StoredFinding` (shared by all finding queries).
fn row_to_stored_finding(row: &rusqlite::Row) -> rusqlite::Result<StoredFinding> {
    Ok(StoredFinding {
        id: Some(row.get(0)?),
        scan_id: row.get(1)?,
        fingerprint: row.get(2)?,
        rule_id: row.get(3)?,
        severity: row.get(4)?,
        file_path: row.get(5)?,
        start_line: row.get(6)?,
        end_line: row.get(7)?,
        message: row.get(8)?,
        snippet: row.get(9)?,
        cwe: row.get(10)?,
        graph_context_json: row.get(11)?,
        llm_analysis: row.get(12)?,
        escalation_reasons_json: row.get(13)?,
        enclosing_context: row.get(14)?,
        suggested_fix: row.get(15)?,
        agent_prompt: row.get(16)?,
    })
}

impl Store {
    /// Open (or create) the SQLite database at `path` and run pending migrations.
    pub fn open(path: &str) -> rusqlite::Result<Self> {
        let conn = if path == ":memory:" {
            Connection::open_in_memory()?
        } else {
            if let Some(parent) = Path::new(path).parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent).ok();
                }
            }
            Connection::open(path)?
        };

        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
        schema::migrate(&conn)?;

        Ok(Self { conn })
    }

    /// Insert a scan record and return its ID.
    pub fn insert_scan(&self, scan: &ScanRecord) -> rusqlite::Result<i64> {
        self.conn.execute(
            "INSERT INTO scans (repo, branch, commit_sha, command, pr_number, finding_count, summary, stage, error_message, failed_at_stage)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                scan.repo,
                scan.branch,
                scan.commit_sha,
                scan.command,
                scan.pr_number.map(|n| n as i64),
                scan.finding_count,
                scan.summary,
                scan.stage,
                scan.error_message,
                scan.failed_at_stage,
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Insert findings for a scan in a single transaction.
    pub fn insert_findings(&self, scan_id: i64, findings: &[Finding]) -> rusqlite::Result<()> {
        let tx = self.conn.unchecked_transaction()?;

        {
            let mut stmt = tx.prepare(
                "INSERT INTO findings (scan_id, fingerprint, rule_id, severity, file_path,
                 start_line, end_line, message, snippet, cwe, graph_context_json,
                 llm_analysis, escalation_reasons_json, enclosing_context,
                 suggested_fix, agent_prompt)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
            )?;

            for f in findings {
                let fp = fingerprint::compute(&f.rule_id, &f.file_path, &f.snippet);
                let graph_json = f
                    .graph_context
                    .as_ref()
                    .map(|g| serde_json::to_string(g).unwrap_or_default());
                let escalation_json = if f.escalation_reasons.is_empty() {
                    None
                } else {
                    Some(serde_json::to_string(&f.escalation_reasons).unwrap_or_default())
                };

                stmt.execute(params![
                    scan_id,
                    fp,
                    f.rule_id,
                    f.severity.to_string(),
                    f.file_path,
                    f.start_line,
                    f.end_line,
                    f.message,
                    f.snippet,
                    f.cwe,
                    graph_json,
                    f.llm_analysis,
                    escalation_json,
                    f.enclosing_context,
                    f.suggested_fix,
                    f.agent_prompt,
                ])?;
            }
        }

        tx.commit()
    }

    /// List scans, optionally filtered, ordered by created_at descending.
    pub fn list_scans(&self, filter: &ScanFilter) -> rusqlite::Result<Vec<ScanRecord>> {
        let mut sql = String::from(
            "SELECT id, repo, branch, commit_sha, command, pr_number, finding_count, summary, created_at, stage, error_message, failed_at_stage
             FROM scans WHERE 1=1",
        );
        let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

        if let Some(ref branch) = filter.branch {
            sql.push_str(" AND branch = ?");
            param_values.push(Box::new(branch.clone()));
        }
        if let Some(ref repo) = filter.repo {
            sql.push_str(" AND repo = ?");
            param_values.push(Box::new(repo.clone()));
        }
        sql.push_str(" ORDER BY created_at DESC");

        let params_ref: Vec<&dyn rusqlite::types::ToSql> =
            param_values.iter().map(|p| p.as_ref()).collect();
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(params_ref.as_slice(), |row| {
            Ok(ScanRecord {
                id: Some(row.get(0)?),
                repo: row.get(1)?,
                branch: row.get(2)?,
                commit_sha: row.get(3)?,
                command: row.get(4)?,
                pr_number: row.get::<_, Option<i64>>(5)?.map(|n| n as u64),
                finding_count: row.get(6)?,
                summary: row.get(7)?,
                created_at: Some(row.get(8)?),
                stage: row.get(9)?,
                error_message: row.get(10)?,
                failed_at_stage: row.get(11)?,
            })
        })?;

        rows.collect()
    }

    /// Get all findings for a specific scan, sorted by severity desc then file path.
    pub fn get_findings(&self, scan_id: i64) -> rusqlite::Result<Vec<StoredFinding>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, scan_id, fingerprint, rule_id, severity, file_path,
                    start_line, end_line, message, snippet, cwe,
                    graph_context_json, llm_analysis, escalation_reasons_json,
                    enclosing_context, suggested_fix, agent_prompt
             FROM findings WHERE scan_id = ?1
             ORDER BY
                 CASE severity
                     WHEN 'critical' THEN 0
                     WHEN 'error' THEN 1
                     WHEN 'warning' THEN 2
                     WHEN 'info' THEN 3
                 END,
                 file_path",
        )?;

        let rows = stmt.query_map(params![scan_id], row_to_stored_finding)?;

        rows.collect()
    }

    /// Search findings across scans with filters (AND logic).
    pub fn search_findings(&self, filter: &FindingFilter) -> rusqlite::Result<Vec<StoredFinding>> {
        let mut sql = String::from(
            "SELECT f.id, f.scan_id, f.fingerprint, f.rule_id, f.severity, f.file_path,
                    f.start_line, f.end_line, f.message, f.snippet, f.cwe,
                    f.graph_context_json, f.llm_analysis, f.escalation_reasons_json,
                    f.enclosing_context, f.suggested_fix, f.agent_prompt
             FROM findings f
             JOIN scans s ON f.scan_id = s.id
             WHERE 1=1",
        );
        let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

        if let Some(ref rule) = filter.rule {
            sql.push_str(" AND f.rule_id LIKE '%' || ? || '%'");
            param_values.push(Box::new(rule.clone()));
        }
        if let Some(ref severity) = filter.severity {
            // Filter at or above the given severity
            let severity_clause = match severity.to_lowercase().as_str() {
                "critical" => "f.severity IN ('critical')",
                "error" => "f.severity IN ('critical', 'error')",
                "warning" => "f.severity IN ('critical', 'error', 'warning')",
                "info" => "f.severity IN ('critical', 'error', 'warning', 'info')",
                _ => "1=1",
            };
            sql.push_str(&format!(" AND {severity_clause}"));
        }
        if let Some(ref file) = filter.file {
            sql.push_str(" AND f.file_path LIKE '%' || ? || '%'");
            param_values.push(Box::new(file.clone()));
        }
        if let Some(ref branch) = filter.branch {
            sql.push_str(" AND s.branch = ?");
            param_values.push(Box::new(branch.clone()));
        }
        sql.push_str(
            " ORDER BY
                 CASE f.severity
                     WHEN 'critical' THEN 0
                     WHEN 'error' THEN 1
                     WHEN 'warning' THEN 2
                     WHEN 'info' THEN 3
                 END,
                 f.file_path",
        );

        let params_ref: Vec<&dyn rusqlite::types::ToSql> =
            param_values.iter().map(|p| p.as_ref()).collect();
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(params_ref.as_slice(), row_to_stored_finding)?;

        rows.collect()
    }

    /// Get the latest scan for a given repo and branch.
    pub fn latest_scan_for_branch(
        &self,
        repo: &str,
        branch: &str,
    ) -> rusqlite::Result<Option<ScanRecord>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, repo, branch, commit_sha, command, pr_number, finding_count, summary, created_at, stage, error_message, failed_at_stage
             FROM scans WHERE repo = ?1 AND branch = ?2 AND stage = 'completed'
             ORDER BY id DESC LIMIT 1",
        )?;

        let mut rows = stmt.query_map(params![repo, branch], |row| {
            Ok(ScanRecord {
                id: Some(row.get(0)?),
                repo: row.get(1)?,
                branch: row.get(2)?,
                commit_sha: row.get(3)?,
                command: row.get(4)?,
                pr_number: row.get::<_, Option<i64>>(5)?.map(|n| n as u64),
                finding_count: row.get(6)?,
                summary: row.get(7)?,
                created_at: Some(row.get(8)?),
                stage: row.get(9)?,
                error_message: row.get(10)?,
                failed_at_stage: row.get(11)?,
            })
        })?;

        match rows.next() {
            Some(r) => Ok(Some(r?)),
            None => Ok(None),
        }
    }

    /// Get all finding fingerprints from the latest scan on a given branch.
    pub fn baseline_fingerprints(
        &self,
        repo: &str,
        branch: &str,
    ) -> rusqlite::Result<HashSet<String>> {
        let scan = self.latest_scan_for_branch(repo, branch)?;
        let scan_id = match scan {
            Some(s) => s.id.unwrap_or(-1),
            None => return Ok(HashSet::new()),
        };

        let mut stmt = self
            .conn
            .prepare("SELECT fingerprint FROM findings WHERE scan_id = ?1")?;

        let rows = stmt.query_map(params![scan_id], |row| row.get::<_, String>(0))?;

        rows.collect::<rusqlite::Result<HashSet<String>>>()
    }

    /// Update the pipeline stage for a scan.
    pub fn update_scan_stage(&self, scan_id: i64, stage: &str) -> rusqlite::Result<()> {
        self.conn.execute(
            "UPDATE scans SET stage = ?1 WHERE id = ?2",
            params![stage, scan_id],
        )?;
        Ok(())
    }

    /// Mark a scan as failed, recording the error and the stage where failure occurred.
    /// The `stage` column retains the last successful checkpoint so `--resume` can
    /// restart from there.
    pub fn mark_scan_failed(
        &self,
        scan_id: i64,
        failed_at: &str,
        error: &str,
    ) -> rusqlite::Result<()> {
        self.conn.execute(
            "UPDATE scans SET failed_at_stage = ?1, error_message = ?2 WHERE id = ?3",
            params![failed_at, error, scan_id],
        )?;
        Ok(())
    }

    /// Replace all findings for a scan (DELETE + INSERT in a transaction).
    /// Used by pipeline stages to persist intermediate results.
    pub fn update_scan_findings(&self, scan_id: i64, findings: &[Finding]) -> rusqlite::Result<()> {
        let tx = self.conn.unchecked_transaction()?;

        tx.execute("DELETE FROM findings WHERE scan_id = ?1", params![scan_id])?;

        {
            let mut stmt = tx.prepare(
                "INSERT INTO findings (scan_id, fingerprint, rule_id, severity, file_path,
                 start_line, end_line, message, snippet, cwe, graph_context_json,
                 llm_analysis, escalation_reasons_json, enclosing_context,
                 suggested_fix, agent_prompt)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
            )?;

            for f in findings {
                let fp = fingerprint::compute(&f.rule_id, &f.file_path, &f.snippet);
                let graph_json = f
                    .graph_context
                    .as_ref()
                    .map(|g| serde_json::to_string(g).unwrap_or_default());
                let escalation_json = if f.escalation_reasons.is_empty() {
                    None
                } else {
                    Some(serde_json::to_string(&f.escalation_reasons).unwrap_or_default())
                };

                stmt.execute(params![
                    scan_id,
                    fp,
                    f.rule_id,
                    f.severity.to_string(),
                    f.file_path,
                    f.start_line,
                    f.end_line,
                    f.message,
                    f.snippet,
                    f.cwe,
                    graph_json,
                    f.llm_analysis,
                    escalation_json,
                    f.enclosing_context,
                    f.suggested_fix,
                    f.agent_prompt,
                ])?;
            }
        }

        // Update the finding_count on the scan record
        tx.execute(
            "UPDATE scans SET finding_count = ?1 WHERE id = ?2",
            params![findings.len() as u32, scan_id],
        )?;

        tx.commit()
    }

    /// Get a single scan by ID.
    pub fn get_scan(&self, scan_id: i64) -> rusqlite::Result<Option<ScanRecord>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, repo, branch, commit_sha, command, pr_number, finding_count, summary, created_at, stage, error_message, failed_at_stage
             FROM scans WHERE id = ?1",
        )?;

        let mut rows = stmt.query_map(params![scan_id], |row| {
            Ok(ScanRecord {
                id: Some(row.get(0)?),
                repo: row.get(1)?,
                branch: row.get(2)?,
                commit_sha: row.get(3)?,
                command: row.get(4)?,
                pr_number: row.get::<_, Option<i64>>(5)?.map(|n| n as u64),
                finding_count: row.get(6)?,
                summary: row.get(7)?,
                created_at: Some(row.get(8)?),
                stage: row.get(9)?,
                error_message: row.get(10)?,
                failed_at_stage: row.get(11)?,
            })
        })?;

        match rows.next() {
            Some(r) => Ok(Some(r?)),
            None => Ok(None),
        }
    }

    /// Insert a dismissal and return its ID.
    pub fn dismiss(&self, dismissal: &Dismissal) -> rusqlite::Result<i64> {
        self.conn.execute(
            "INSERT INTO dismissals (fingerprint, rule_id, file_path, start_line, end_line, snippet_hash, reason)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                dismissal.fingerprint,
                dismissal.rule_id,
                dismissal.file_path,
                dismissal.start_line,
                dismissal.end_line,
                dismissal.snippet_hash,
                dismissal.reason,
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Remove a dismissal by ID.
    pub fn undismiss(&self, dismissal_id: i64) -> rusqlite::Result<()> {
        let changed = self.conn.execute(
            "DELETE FROM dismissals WHERE id = ?1",
            params![dismissal_id],
        )?;
        if changed == 0 {
            return Err(rusqlite::Error::QueryReturnedNoRows);
        }
        Ok(())
    }

    /// List all dismissals.
    pub fn list_dismissals(&self) -> rusqlite::Result<Vec<Dismissal>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, fingerprint, rule_id, file_path, start_line, end_line, snippet_hash, reason, created_at
             FROM dismissals ORDER BY created_at DESC",
        )?;

        let rows = stmt.query_map([], |row| {
            Ok(Dismissal {
                id: Some(row.get(0)?),
                fingerprint: row.get(1)?,
                rule_id: row.get(2)?,
                file_path: row.get(3)?,
                start_line: row.get(4)?,
                end_line: row.get(5)?,
                snippet_hash: row.get(6)?,
                reason: row.get(7)?,
                created_at: Some(row.get(8)?),
            })
        })?;

        rows.collect()
    }

    /// Check if a finding fingerprint is currently dismissed.
    pub fn is_dismissed(&self, fingerprint: &str) -> rusqlite::Result<bool> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM dismissals WHERE fingerprint = ?1",
            params![fingerprint],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    /// Get all dismissed fingerprints as a set for O(1) per-finding checks.
    pub fn dismissed_fingerprints(&self) -> rusqlite::Result<HashSet<String>> {
        let mut stmt = self.conn.prepare("SELECT fingerprint FROM dismissals")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        rows.collect::<rusqlite::Result<HashSet<String>>>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cartomancer_core::finding::{Finding, GraphContext};
    use cartomancer_core::severity::Severity;

    fn test_store() -> Store {
        Store::open(":memory:").unwrap()
    }

    fn sample_scan() -> ScanRecord {
        ScanRecord {
            id: None,
            repo: "owner/repo".into(),
            branch: "main".into(),
            commit_sha: "abc123".into(),
            command: "scan".into(),
            pr_number: None,
            finding_count: 2,
            summary: "Found 2 issues".into(),
            created_at: None,
            stage: "completed".into(),
            error_message: None,
            failed_at_stage: None,
        }
    }

    fn sample_finding() -> Finding {
        Finding {
            rule_id: "rust.lang.security.hardcoded-password".into(),
            message: "Hardcoded password detected".into(),
            severity: Severity::Error,
            file_path: "src/auth.rs".into(),
            start_line: 10,
            end_line: 12,
            snippet: "let password = \"secret\";".into(),
            cwe: Some("CWE-798".into()),
            graph_context: None,
            llm_analysis: None,
            escalation_reasons: vec![],
            is_new: None,
            enclosing_context: None,
            suggested_fix: None,
            agent_prompt: None,
        }
    }

    #[test]
    fn store_open_in_memory() {
        let store = test_store();
        let scans = store.list_scans(&ScanFilter::default()).unwrap();
        assert!(scans.is_empty());
    }

    #[test]
    fn store_insert_scan_returns_id() {
        let store = test_store();
        let id = store.insert_scan(&sample_scan()).unwrap();
        assert!(id > 0);
    }

    #[test]
    fn store_insert_scan_creates_separate_records() {
        let store = test_store();
        let id1 = store.insert_scan(&sample_scan()).unwrap();
        let id2 = store.insert_scan(&sample_scan()).unwrap();
        assert_ne!(id1, id2);

        let scans = store.list_scans(&ScanFilter::default()).unwrap();
        assert_eq!(scans.len(), 2);
    }

    #[test]
    fn store_insert_and_get_findings() {
        let store = test_store();
        let scan_id = store.insert_scan(&sample_scan()).unwrap();

        let findings = vec![sample_finding()];
        store.insert_findings(scan_id, &findings).unwrap();

        let stored = store.get_findings(scan_id).unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].rule_id, "rust.lang.security.hardcoded-password");
        assert_eq!(stored[0].severity, "error");
        assert_eq!(stored[0].cwe, Some("CWE-798".into()));
    }

    #[test]
    fn store_findings_sorted_by_severity_then_path() {
        let store = test_store();
        let scan_id = store.insert_scan(&sample_scan()).unwrap();

        let mut f1 = sample_finding();
        f1.severity = Severity::Warning;
        f1.file_path = "a.rs".into();

        let mut f2 = sample_finding();
        f2.severity = Severity::Critical;
        f2.file_path = "z.rs".into();

        let mut f3 = sample_finding();
        f3.severity = Severity::Critical;
        f3.file_path = "a.rs".into();

        store.insert_findings(scan_id, &[f1, f2, f3]).unwrap();

        let stored = store.get_findings(scan_id).unwrap();
        assert_eq!(stored.len(), 3);
        assert_eq!(stored[0].severity, "critical");
        assert_eq!(stored[0].file_path, "a.rs");
        assert_eq!(stored[1].severity, "critical");
        assert_eq!(stored[1].file_path, "z.rs");
        assert_eq!(stored[2].severity, "warning");
    }

    #[test]
    fn store_findings_with_graph_context() {
        let store = test_store();
        let scan_id = store.insert_scan(&sample_scan()).unwrap();

        let mut finding = sample_finding();
        finding.graph_context = Some(GraphContext {
            symbol_name: Some("check_password".into()),
            callers: vec!["login".into(), "authenticate".into()],
            blast_radius: 15,
            is_public_api: true,
            domain_tags: vec!["auth".into()],
        });
        finding.escalation_reasons = vec!["high blast radius".into()];

        store.insert_findings(scan_id, &[finding]).unwrap();

        let stored = store.get_findings(scan_id).unwrap();
        assert!(stored[0].graph_context_json.is_some());
        assert!(stored[0].escalation_reasons_json.is_some());
    }

    #[test]
    fn store_list_scans_filter_by_branch() {
        let store = test_store();
        store.insert_scan(&sample_scan()).unwrap();

        let mut other = sample_scan();
        other.branch = "feature".into();
        store.insert_scan(&other).unwrap();

        let filter = ScanFilter {
            branch: Some("main".into()),
            ..Default::default()
        };
        let scans = store.list_scans(&filter).unwrap();
        assert_eq!(scans.len(), 1);
        assert_eq!(scans[0].branch, "main");
    }

    #[test]
    fn store_latest_scan_for_branch() {
        let store = test_store();
        let mut s1 = sample_scan();
        s1.commit_sha = "first".into();
        store.insert_scan(&s1).unwrap();

        let mut s2 = sample_scan();
        s2.commit_sha = "second".into();
        store.insert_scan(&s2).unwrap();

        let latest = store.latest_scan_for_branch("owner/repo", "main").unwrap();
        assert!(latest.is_some());
        // Most recent by created_at (both inserted quickly, but id order applies)
        let latest = latest.unwrap();
        assert_eq!(latest.commit_sha, "second");
    }

    #[test]
    fn store_latest_scan_for_branch_none() {
        let store = test_store();
        let latest = store.latest_scan_for_branch("owner/repo", "main").unwrap();
        assert!(latest.is_none());
    }

    #[test]
    fn store_baseline_fingerprints() {
        let store = test_store();
        let scan_id = store.insert_scan(&sample_scan()).unwrap();

        let findings = vec![sample_finding()];
        store.insert_findings(scan_id, &findings).unwrap();

        let fps = store.baseline_fingerprints("owner/repo", "main").unwrap();
        assert_eq!(fps.len(), 1);
    }

    #[test]
    fn store_baseline_fingerprints_empty_when_no_scans() {
        let store = test_store();
        let fps = store.baseline_fingerprints("owner/repo", "main").unwrap();
        assert!(fps.is_empty());
    }

    #[test]
    fn store_dismiss_and_check() {
        let store = test_store();
        let fp = fingerprint::compute("rule-a", "src/main.rs", "let x = 1;");
        let dismissal = Dismissal {
            id: None,
            fingerprint: fp.clone(),
            rule_id: "rule-a".into(),
            file_path: "src/main.rs".into(),
            start_line: 1,
            end_line: 1,
            snippet_hash: fingerprint::snippet_hash("let x = 1;"),
            reason: Some("false positive".into()),
            created_at: None,
        };

        let id = store.dismiss(&dismissal).unwrap();
        assert!(id > 0);
        assert!(store.is_dismissed(&fp).unwrap());
    }

    #[test]
    fn store_undismiss() {
        let store = test_store();
        let fp = fingerprint::compute("rule-a", "src/main.rs", "let x = 1;");
        let dismissal = Dismissal {
            id: None,
            fingerprint: fp.clone(),
            rule_id: "rule-a".into(),
            file_path: "src/main.rs".into(),
            start_line: 1,
            end_line: 1,
            snippet_hash: fingerprint::snippet_hash("let x = 1;"),
            reason: None,
            created_at: None,
        };

        let id = store.dismiss(&dismissal).unwrap();
        assert!(store.is_dismissed(&fp).unwrap());

        store.undismiss(id).unwrap();
        assert!(!store.is_dismissed(&fp).unwrap());
    }

    #[test]
    fn store_undismiss_nonexistent_returns_error() {
        let store = test_store();
        let result = store.undismiss(999);
        assert!(result.is_err());
    }

    #[test]
    fn store_list_dismissals() {
        let store = test_store();
        let dismissal = Dismissal {
            id: None,
            fingerprint: "fp1".into(),
            rule_id: "rule-a".into(),
            file_path: "src/main.rs".into(),
            start_line: 1,
            end_line: 1,
            snippet_hash: "hash1".into(),
            reason: Some("false positive".into()),
            created_at: None,
        };

        store.dismiss(&dismissal).unwrap();
        let dismissals = store.list_dismissals().unwrap();
        assert_eq!(dismissals.len(), 1);
        assert_eq!(dismissals[0].reason, Some("false positive".into()));
    }

    #[test]
    fn store_dismissed_fingerprints() {
        let store = test_store();
        let d1 = Dismissal {
            id: None,
            fingerprint: "fp1".into(),
            rule_id: "rule-a".into(),
            file_path: "a.rs".into(),
            start_line: 1,
            end_line: 1,
            snippet_hash: "h1".into(),
            reason: None,
            created_at: None,
        };
        let d2 = Dismissal {
            id: None,
            fingerprint: "fp2".into(),
            rule_id: "rule-b".into(),
            file_path: "b.rs".into(),
            start_line: 1,
            end_line: 1,
            snippet_hash: "h2".into(),
            reason: None,
            created_at: None,
        };

        store.dismiss(&d1).unwrap();
        store.dismiss(&d2).unwrap();

        let fps = store.dismissed_fingerprints().unwrap();
        assert_eq!(fps.len(), 2);
        assert!(fps.contains("fp1"));
        assert!(fps.contains("fp2"));
    }

    #[test]
    fn store_search_findings_by_rule() {
        let store = test_store();
        let scan_id = store.insert_scan(&sample_scan()).unwrap();

        let mut f1 = sample_finding();
        f1.rule_id = "security.sql-injection".into();
        let mut f2 = sample_finding();
        f2.rule_id = "style.naming".into();
        f2.snippet = "let Foo = 1;".into();

        store.insert_findings(scan_id, &[f1, f2]).unwrap();

        let filter = FindingFilter {
            rule: Some("sql".into()),
            ..Default::default()
        };
        let results = store.search_findings(&filter).unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].rule_id.contains("sql"));
    }

    #[test]
    fn store_search_findings_by_severity() {
        let store = test_store();
        let scan_id = store.insert_scan(&sample_scan()).unwrap();

        let mut f1 = sample_finding();
        f1.severity = Severity::Critical;
        let mut f2 = sample_finding();
        f2.severity = Severity::Info;
        f2.snippet = "different snippet".into();

        store.insert_findings(scan_id, &[f1, f2]).unwrap();

        let filter = FindingFilter {
            severity: Some("error".into()),
            ..Default::default()
        };
        let results = store.search_findings(&filter).unwrap();
        // Should include critical (above error) but not info
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].severity, "critical");
    }

    #[test]
    fn store_search_findings_by_file() {
        let store = test_store();
        let scan_id = store.insert_scan(&sample_scan()).unwrap();

        let mut f1 = sample_finding();
        f1.file_path = "src/auth/login.rs".into();
        let mut f2 = sample_finding();
        f2.file_path = "src/db/query.rs".into();
        f2.snippet = "different snippet".into();

        store.insert_findings(scan_id, &[f1, f2]).unwrap();

        let filter = FindingFilter {
            file: Some("auth".into()),
            ..Default::default()
        };
        let results = store.search_findings(&filter).unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].file_path.contains("auth"));
    }

    #[test]
    fn store_search_findings_by_branch() {
        let store = test_store();

        let mut s1 = sample_scan();
        s1.branch = "main".into();
        let id1 = store.insert_scan(&s1).unwrap();

        let mut s2 = sample_scan();
        s2.branch = "feature".into();
        let id2 = store.insert_scan(&s2).unwrap();

        let f1 = sample_finding();
        let mut f2 = sample_finding();
        f2.snippet = "other code".into();

        store.insert_findings(id1, &[f1]).unwrap();
        store.insert_findings(id2, &[f2]).unwrap();

        let filter = FindingFilter {
            branch: Some("main".into()),
            ..Default::default()
        };
        let results = store.search_findings(&filter).unwrap();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn store_search_findings_combined_filters() {
        let store = test_store();
        let scan_id = store.insert_scan(&sample_scan()).unwrap();

        let mut f1 = sample_finding();
        f1.severity = Severity::Critical;
        f1.rule_id = "security.sql".into();
        f1.file_path = "src/auth.rs".into();

        let mut f2 = sample_finding();
        f2.severity = Severity::Critical;
        f2.rule_id = "security.xss".into();
        f2.file_path = "src/web.rs".into();
        f2.snippet = "different".into();

        store.insert_findings(scan_id, &[f1, f2]).unwrap();

        let filter = FindingFilter {
            severity: Some("critical".into()),
            file: Some("auth".into()),
            ..Default::default()
        };
        let results = store.search_findings(&filter).unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].file_path.contains("auth"));
    }

    #[test]
    fn store_suggested_fix_round_trip() {
        let store = test_store();
        let scan_id = store.insert_scan(&sample_scan()).unwrap();

        let mut finding = sample_finding();
        finding.suggested_fix = Some("--- a/src/auth.rs\n+++ b/src/auth.rs\n@@ -10,1 +10,1 @@\n-let password = \"secret\";\n+let password = std::env::var(\"SECRET\").unwrap();".into());

        store.insert_findings(scan_id, &[finding]).unwrap();

        let stored = store.get_findings(scan_id).unwrap();
        assert_eq!(stored.len(), 1);
        assert!(stored[0].suggested_fix.is_some());
        assert!(stored[0]
            .suggested_fix
            .as_ref()
            .unwrap()
            .contains("std::env::var"));
        assert_eq!(stored[0].agent_prompt, None);
    }

    #[test]
    fn store_agent_prompt_round_trip() {
        let store = test_store();
        let scan_id = store.insert_scan(&sample_scan()).unwrap();

        let mut finding = sample_finding();
        finding.agent_prompt =
            Some("In @src/auth.rs around lines 10-12, fix the hardcoded password.".into());

        store.insert_findings(scan_id, &[finding]).unwrap();

        let stored = store.get_findings(scan_id).unwrap();
        assert_eq!(stored.len(), 1);
        assert!(stored[0].agent_prompt.is_some());
        assert!(stored[0]
            .agent_prompt
            .as_ref()
            .unwrap()
            .contains("fix the hardcoded password"));
    }

    #[test]
    fn store_full_finding_round_trip() {
        let store = test_store();
        let scan_id = store.insert_scan(&sample_scan()).unwrap();

        let finding = Finding {
            rule_id: "rust.lang.security.hardcoded-password".into(),
            message: "Hardcoded password detected".into(),
            severity: Severity::Critical,
            file_path: "src/auth.rs".into(),
            start_line: 10,
            end_line: 15,
            snippet: "let password = \"secret\";".into(),
            cwe: Some("CWE-798".into()),
            graph_context: Some(GraphContext {
                symbol_name: Some("check_password".into()),
                callers: vec!["login".into(), "authenticate".into(), "verify_user".into()],
                blast_radius: 42,
                is_public_api: true,
                domain_tags: vec!["auth".into(), "security".into()],
            }),
            llm_analysis: Some("This is a critical security issue. Hardcoded passwords can be extracted from compiled binaries.".into()),
            escalation_reasons: vec![
                "high blast radius (42 symbols)".into(),
                "auth domain".into(),
            ],
            is_new: Some(true),
            enclosing_context: Some("fn check_password(input: &str) -> bool {\n    let password = \"secret\";\n    input == password\n}".into()),
            suggested_fix: Some("--- a/src/auth.rs\n+++ b/src/auth.rs\n@@ -10,3 +10,3 @@\n-    let password = \"secret\";\n+    let password = std::env::var(\"APP_SECRET\").expect(\"APP_SECRET not set\");\n".into()),
            agent_prompt: Some("In `@src/auth.rs` around lines 10-15, Hardcoded password detected. Rule: rust.lang.security.hardcoded-password. Severity: critical. CWE: CWE-798. Apply this fix:\n\n```diff\n-    let password = \"secret\";\n+    let password = std::env::var(\"APP_SECRET\").expect(\"APP_SECRET not set\");\n```".into()),
        };

        store
            .insert_findings(scan_id, std::slice::from_ref(&finding))
            .unwrap();

        let stored = store.get_findings(scan_id).unwrap();
        assert_eq!(stored.len(), 1);
        let s = &stored[0];

        // Core fields
        assert_eq!(s.rule_id, finding.rule_id);
        assert_eq!(s.severity, "critical");
        assert_eq!(s.file_path, finding.file_path);
        assert_eq!(s.start_line, finding.start_line);
        assert_eq!(s.end_line, finding.end_line);
        assert_eq!(s.message, finding.message);
        assert_eq!(s.snippet, finding.snippet);
        assert_eq!(s.cwe, finding.cwe);

        // Graph context (stored as JSON, verify round-trip)
        let graph_json = s
            .graph_context_json
            .as_ref()
            .expect("graph_context_json should be set");
        let graph: GraphContext = serde_json::from_str(graph_json).unwrap();
        assert_eq!(graph.symbol_name.as_deref(), Some("check_password"));
        assert_eq!(graph.callers.len(), 3);
        assert_eq!(graph.blast_radius, 42);
        assert!(graph.is_public_api);
        assert_eq!(graph.domain_tags, vec!["auth", "security"]);

        // LLM analysis
        assert_eq!(s.llm_analysis.as_deref(), finding.llm_analysis.as_deref());

        // Escalation reasons (stored as JSON array)
        let esc_json = s
            .escalation_reasons_json
            .as_ref()
            .expect("escalation_reasons_json should be set");
        let reasons: Vec<String> = serde_json::from_str(esc_json).unwrap();
        assert_eq!(reasons.len(), 2);
        assert!(reasons[0].contains("blast radius"));

        // Enclosing context
        assert_eq!(
            s.enclosing_context.as_deref(),
            finding.enclosing_context.as_deref()
        );

        // Suggested fix
        assert_eq!(s.suggested_fix.as_deref(), finding.suggested_fix.as_deref());

        // Agent prompt
        assert_eq!(s.agent_prompt.as_deref(), finding.agent_prompt.as_deref());
    }

    #[test]
    fn store_finding_with_no_optional_fields_round_trip() {
        let store = test_store();
        let scan_id = store.insert_scan(&sample_scan()).unwrap();

        let finding = Finding {
            rule_id: "style.naming".into(),
            message: "Use snake_case".into(),
            severity: Severity::Info,
            file_path: "src/lib.rs".into(),
            start_line: 1,
            end_line: 1,
            snippet: "let myVar = 1;".into(),
            cwe: None,
            graph_context: None,
            llm_analysis: None,
            escalation_reasons: vec![],
            is_new: None,
            enclosing_context: None,
            suggested_fix: None,
            agent_prompt: None,
        };

        store.insert_findings(scan_id, &[finding]).unwrap();

        let stored = store.get_findings(scan_id).unwrap();
        assert_eq!(stored.len(), 1);
        let s = &stored[0];
        assert_eq!(s.severity, "info");
        assert!(s.cwe.is_none());
        assert!(s.graph_context_json.is_none());
        assert!(s.llm_analysis.is_none());
        assert!(s.escalation_reasons_json.is_none());
        assert!(s.enclosing_context.is_none());
        assert!(s.suggested_fix.is_none());
        assert!(s.agent_prompt.is_none());
    }

    #[test]
    fn store_open_file_creates_db() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");

        let store = Store::open(db_path.to_str().unwrap()).unwrap();
        let id = store.insert_scan(&sample_scan()).unwrap();
        assert!(id > 0);
        assert!(db_path.exists());
    }

    #[test]
    fn store_update_scan_stage() {
        let store = test_store();
        let scan_id = store.insert_scan(&sample_scan()).unwrap();

        store.update_scan_stage(scan_id, "enriched").unwrap();

        let scan = store.get_scan(scan_id).unwrap().unwrap();
        assert_eq!(scan.stage, "enriched");
    }

    #[test]
    fn store_mark_scan_failed_preserves_stage() {
        let store = test_store();
        let scan_id = store.insert_scan(&sample_scan()).unwrap();

        // Advance to enriched, then fail
        store.update_scan_stage(scan_id, "enriched").unwrap();
        store
            .mark_scan_failed(scan_id, "escalated", "opengrep timed out")
            .unwrap();

        let scan = store.get_scan(scan_id).unwrap().unwrap();
        // stage retains the last successful checkpoint
        assert_eq!(scan.stage, "enriched");
        assert_eq!(scan.failed_at_stage.as_deref(), Some("escalated"));
        assert_eq!(scan.error_message.as_deref(), Some("opengrep timed out"));
    }

    #[test]
    fn store_update_scan_findings_replaces() {
        let store = test_store();
        let scan_id = store.insert_scan(&sample_scan()).unwrap();

        // Insert initial findings
        let f1 = sample_finding();
        store.insert_findings(scan_id, &[f1]).unwrap();
        assert_eq!(store.get_findings(scan_id).unwrap().len(), 1);

        // Replace with two new findings (distinct file paths for deterministic ordering)
        let mut f2 = sample_finding();
        f2.rule_id = "new-rule-1".into();
        f2.snippet = "new code 1".into();
        f2.file_path = "src/a.rs".into();
        let mut f3 = sample_finding();
        f3.rule_id = "new-rule-2".into();
        f3.snippet = "new code 2".into();
        f3.file_path = "src/b.rs".into();

        store.update_scan_findings(scan_id, &[f2, f3]).unwrap();

        let stored = store.get_findings(scan_id).unwrap();
        assert_eq!(stored.len(), 2);
        assert_eq!(stored[0].rule_id, "new-rule-1");
        assert_eq!(stored[1].rule_id, "new-rule-2");

        // Verify finding_count was updated
        let scan = store.get_scan(scan_id).unwrap().unwrap();
        assert_eq!(scan.finding_count, 2);
    }

    #[test]
    fn store_get_scan_by_id() {
        let store = test_store();
        let scan_id = store.insert_scan(&sample_scan()).unwrap();

        let scan = store.get_scan(scan_id).unwrap();
        assert!(scan.is_some());
        assert_eq!(scan.unwrap().repo, "owner/repo");
    }

    #[test]
    fn store_get_scan_nonexistent() {
        let store = test_store();
        let scan = store.get_scan(999).unwrap();
        assert!(scan.is_none());
    }

    #[test]
    fn store_scan_stage_persisted_on_insert() {
        let store = test_store();
        let mut scan = sample_scan();
        scan.stage = "pending".into();
        let scan_id = store.insert_scan(&scan).unwrap();

        let stored = store.get_scan(scan_id).unwrap().unwrap();
        assert_eq!(stored.stage, "pending");
    }

    #[test]
    fn store_update_scan_findings_with_graph_context() {
        let store = test_store();
        let scan_id = store.insert_scan(&sample_scan()).unwrap();

        let mut finding = sample_finding();
        finding.graph_context = Some(GraphContext {
            symbol_name: Some("check".into()),
            callers: vec!["main".into()],
            blast_radius: 5,
            is_public_api: true,
            domain_tags: vec!["auth".into()],
        });
        finding.escalation_reasons = vec!["high blast radius".into()];

        store.update_scan_findings(scan_id, &[finding]).unwrap();

        let stored = store.get_findings(scan_id).unwrap();
        assert_eq!(stored.len(), 1);
        assert!(stored[0].graph_context_json.is_some());
        assert!(stored[0].escalation_reasons_json.is_some());

        let scan = store.get_scan(scan_id).unwrap().unwrap();
        assert_eq!(scan.finding_count, 1);
    }

    #[test]
    fn store_update_scan_findings_empty_clears() {
        let store = test_store();
        let scan_id = store.insert_scan(&sample_scan()).unwrap();

        store.insert_findings(scan_id, &[sample_finding()]).unwrap();
        assert_eq!(store.get_findings(scan_id).unwrap().len(), 1);

        store.update_scan_findings(scan_id, &[]).unwrap();
        assert_eq!(store.get_findings(scan_id).unwrap().len(), 0);

        let scan = store.get_scan(scan_id).unwrap().unwrap();
        assert_eq!(scan.finding_count, 0);
    }
}
