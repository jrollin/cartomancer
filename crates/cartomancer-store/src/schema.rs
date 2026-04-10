//! SQLite schema DDL and versioned migrations.
//!
//! Schema versioning uses `PRAGMA user_version` (TD-4). Each migration
//! function advances the schema by one version and is run sequentially.

use rusqlite::Connection;

/// Current schema version. Bump when adding new migrations.
pub const CURRENT_VERSION: i32 = 2;

/// Run all pending migrations to bring the database up to [`CURRENT_VERSION`].
///
/// Returns an error if the database was created by a newer version of cartomancer.
pub fn migrate(conn: &Connection) -> rusqlite::Result<()> {
    let version: i32 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;

    if version > CURRENT_VERSION {
        return Err(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_ERROR),
            Some(format!(
                "database schema version {version} is newer than supported version {CURRENT_VERSION}"
            )),
        ));
    }

    if version < 1 {
        migrate_v1(conn)?;
    }
    if version < 2 {
        migrate_v2(conn)?;
    }

    Ok(())
}

fn migrate_v1(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE scans (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            repo        TEXT NOT NULL,
            branch      TEXT NOT NULL,
            commit_sha  TEXT NOT NULL,
            command     TEXT NOT NULL,
            pr_number   INTEGER,
            finding_count INTEGER NOT NULL,
            summary     TEXT NOT NULL,
            created_at  TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE findings (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id     INTEGER NOT NULL REFERENCES scans(id),
            fingerprint TEXT NOT NULL,
            rule_id     TEXT NOT NULL,
            severity    TEXT NOT NULL,
            file_path   TEXT NOT NULL,
            start_line  INTEGER NOT NULL,
            end_line    INTEGER NOT NULL,
            message     TEXT NOT NULL,
            snippet     TEXT NOT NULL,
            cwe         TEXT,
            graph_context_json TEXT,
            llm_analysis TEXT,
            escalation_reasons_json TEXT
        );

        CREATE TABLE dismissals (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            fingerprint TEXT NOT NULL,
            rule_id     TEXT NOT NULL,
            file_path   TEXT NOT NULL,
            start_line  INTEGER NOT NULL,
            end_line    INTEGER NOT NULL,
            snippet_hash TEXT NOT NULL,
            reason      TEXT,
            created_at  TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE INDEX idx_scans_repo_branch ON scans(repo, branch);
        CREATE INDEX idx_findings_scan_id ON findings(scan_id);
        CREATE INDEX idx_findings_fingerprint ON findings(fingerprint);
        CREATE INDEX idx_dismissals_fingerprint ON dismissals(fingerprint);

        PRAGMA user_version = 1;
        ",
    )?;

    Ok(())
}

fn migrate_v2(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        ALTER TABLE findings ADD COLUMN enclosing_context TEXT;

        PRAGMA user_version = 2;
        ",
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    #[test]
    fn schema_migrate_creates_tables() {
        let conn = Connection::open_in_memory().unwrap();
        migrate(&conn).unwrap();

        // Verify tables exist by querying sqlite_master
        let tables: Vec<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();

        assert!(tables.contains(&"scans".to_string()));
        assert!(tables.contains(&"findings".to_string()));
        assert!(tables.contains(&"dismissals".to_string()));
    }

    #[test]
    fn schema_migrate_sets_user_version() {
        let conn = Connection::open_in_memory().unwrap();
        migrate(&conn).unwrap();

        let version: i32 = conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, CURRENT_VERSION);
    }

    #[test]
    fn schema_migrate_is_idempotent() {
        let conn = Connection::open_in_memory().unwrap();
        migrate(&conn).unwrap();
        // Running migrate again should not error
        migrate(&conn).unwrap();

        let version: i32 = conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, CURRENT_VERSION);
    }

    #[test]
    fn schema_indexes_exist() {
        let conn = Connection::open_in_memory().unwrap();
        migrate(&conn).unwrap();

        let indexes: Vec<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'idx_%' ORDER BY name")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();

        assert!(indexes.contains(&"idx_scans_repo_branch".to_string()));
        assert!(indexes.contains(&"idx_findings_scan_id".to_string()));
        assert!(indexes.contains(&"idx_findings_fingerprint".to_string()));
        assert!(indexes.contains(&"idx_dismissals_fingerprint".to_string()));
    }

    #[test]
    fn schema_scans_table_has_expected_columns() {
        let conn = Connection::open_in_memory().unwrap();
        migrate(&conn).unwrap();

        let columns: Vec<String> = conn
            .prepare("PRAGMA table_info(scans)")
            .unwrap()
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();

        let expected = vec![
            "id",
            "repo",
            "branch",
            "commit_sha",
            "command",
            "pr_number",
            "finding_count",
            "summary",
            "created_at",
        ];
        for col in expected {
            assert!(columns.contains(&col.to_string()), "missing column: {col}");
        }
    }

    #[test]
    fn schema_findings_table_has_expected_columns() {
        let conn = Connection::open_in_memory().unwrap();
        migrate(&conn).unwrap();

        let columns: Vec<String> = conn
            .prepare("PRAGMA table_info(findings)")
            .unwrap()
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();

        let expected = vec![
            "id",
            "scan_id",
            "fingerprint",
            "rule_id",
            "severity",
            "file_path",
            "start_line",
            "end_line",
            "message",
            "snippet",
            "cwe",
            "graph_context_json",
            "llm_analysis",
            "escalation_reasons_json",
            "enclosing_context",
        ];
        for col in expected {
            assert!(columns.contains(&col.to_string()), "missing column: {col}");
        }
    }

    #[test]
    fn schema_dismissals_table_has_expected_columns() {
        let conn = Connection::open_in_memory().unwrap();
        migrate(&conn).unwrap();

        let columns: Vec<String> = conn
            .prepare("PRAGMA table_info(dismissals)")
            .unwrap()
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();

        let expected = vec![
            "id",
            "fingerprint",
            "rule_id",
            "file_path",
            "start_line",
            "end_line",
            "snippet_hash",
            "reason",
            "created_at",
        ];
        for col in expected {
            assert!(columns.contains(&col.to_string()), "missing column: {col}");
        }
    }

    #[test]
    fn schema_migrate_rejects_future_version() {
        let conn = Connection::open_in_memory().unwrap();
        migrate(&conn).unwrap();

        // Simulate a newer binary having set a higher version
        conn.pragma_update(None, "user_version", CURRENT_VERSION + 1)
            .unwrap();

        let result = migrate(&conn);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("newer than supported"),
            "expected future-version error, got: {err_msg}"
        );
    }

    #[test]
    fn schema_fk_constraints_enforced() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
        migrate(&conn).unwrap();

        // Insert into findings with a non-existent scan_id should fail
        let result = conn.execute(
            "INSERT INTO findings (scan_id, fingerprint, rule_id, severity, file_path,
             start_line, end_line, message, snippet)
             VALUES (999, 'fp', 'rule', 'error', 'f.rs', 1, 1, 'msg', 'code')",
            [],
        );
        assert!(
            result.is_err(),
            "FK constraint should reject non-existent scan_id"
        );
    }
}
