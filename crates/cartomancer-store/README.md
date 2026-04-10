# cartomancer-store

SQLite persistence layer for the [Cartomancer](https://github.com/jrollin/cartomancer) PR review pipeline.

Stores scan results, findings, and dismissals. Enables regression detection (new vs. existing findings) and false positive suppression.

## Components

- `Store` — SQLite access: schema migrations, scan/finding CRUD, dismissal management, baseline fingerprint queries
- `fingerprint` — SHA-256 finding identity (`rule_id:file_path:snippet`), stable across scans
- `schema` — versioned DDL migrations via `PRAGMA user_version`
- `ScanRecord` / `StoredFinding` / `Dismissal` — persistence DTOs

## Schema

Three tables: `scans` (scan metadata), `findings` (per-finding data with fingerprint), `dismissals` (false positive suppression). Indexed on fingerprint columns for O(log n) lookups.

## Usage

This crate is used internally by the cartomancer binary. It is not intended for direct use.

## License

MIT
