# Cartomancer

PR review tool: opengrep + cartog blast radius + LLM deepening → GitHub comments.

## Documentation

- [docs/product.md](docs/product.md) — purpose, users, features
- [docs/tech.md](docs/tech.md) — stack, dependencies, constraints
- [docs/structure.md](docs/structure.md) — workspace layout, crate responsibilities
- [docs/architecture.md](docs/architecture.md) — pipeline stages, data flow, escalation rules

## Build & Test

```bash
cargo check --workspace          # type check
cargo test --workspace           # unit + integration tests
cargo clippy --all-targets       # lint (CI runs with -D warnings)
cargo fmt --check                # format check
```

## Architecture

```
cartomancer-server (binary)
├── cartomancer-core     — pure domain types (Finding, Severity, config)
├── cartomancer-graph    — cartog enricher + severity escalator
├── cartomancer-github   — GitHub API client + webhook types
└── cartomancer-store    — SQLite persistence (scans, findings, dismissals)
```

## Key Types

- `Finding` (core::finding) — opengrep finding + optional graph context + LLM analysis + suggested fix + agent prompt
- `GraphContext` (core::finding) — blast radius, callers, domain tags from cartog
- `Severity` (core::severity) — Info < Warning < Error < Critical
- `ReviewResult` (core::review) — final output posted to GitHub
- `PipelineStage` (core::review) — Pending → Scanned → Enriched → Escalated → Deepened → Completed / Failed
- `AppConfig` (core::config) — deserialized from `.cartomancer.toml`
- `ServeConfig` (core::config) — `max_concurrent_reviews` for webhook server
- `StorageConfig` (core::config) — `db_path` for finding persistence
- `LlmBackend` (core::config) — enum: Ollama or Anthropic (config selection)
- `KnowledgeConfig` (core::config) — knowledge file path, system prompt, max chars, per-rule overrides
- `RuleOverride` (core::config) — per-rule min/max severity and always_deepen flag
- `LlmProvider` (server::llm) — async trait with Ollama and Anthropic implementations; `create_provider` validates `max_tokens` (1..=128,000) for Anthropic and accepts optional system prompt; `AnthropicProvider::with_base_url` for test overrides
- `PrMetadata` (github::types) — PR head/base SHA, refs, title from GitHub API
- `ReviewComment` (github::types) — inline comment for PR Review API
- `CartogEnricher` (graph::enricher) — wraps cartog::db::Database
- `SeverityEscalator` (graph::escalator) — blast radius + domain → severity upgrade
- `Store` (store::store) — SQLite persistence: scan/finding CRUD, dismissals, baselines
- `ScanRecord` / `StoredFinding` / `Dismissal` (store::types) — persistence DTOs
- `CommentCategory` (server::comment) — Actionable or Nitpick (display concern, not on Finding)
- `PipelineResult` (server::pipeline) — ReviewResult + parsed diff + branch info + scan duration + rule count + temp dir handle

## CLI Commands

```
cartomancer scan <path> [--format text|json]
cartomancer review <owner/repo> <pr> [--work-dir <path>] [--dry-run] [--resume <scan-id>] [--format text|json]
cartomancer history [--branch <name>] [--format text|json]
cartomancer findings [<scan-id>] [--rule <pat>] [--severity <lvl>] [--file <pat>] [--branch <name>] [--format text|json]
cartomancer dismiss <scan-id> <finding-index> [--reason <text>]
cartomancer dismissed [--format text|json]
cartomancer undismiss <dismissal-id>
cartomancer serve [--port <n>]                    # webhook server for GitHub events
cartomancer doctor [--format text|json]           # check dependencies and config health
```

## Review Pipeline Stages

1. Resolve GitHub token (env `GITHUB_TOKEN` or config)
2. Fetch PR metadata (GitHub API → head SHA, base SHA)
3. Prepare work dir (clone to temp dir, or reuse `--work-dir`)
4. Fetch + parse unified diff (GitHub API → `PullRequestDiff`)
5. Opengrep scan (subprocess with `--baseline-commit base_sha`, `--exclude` patterns, auto-discovered custom rules from `rules_dir`)
6. Enrich with cartog (impact, refs, callers, domain detection)
7. Escalate severity (blast radius thresholds + domain tags + per-rule `min_severity`/`max_severity` overrides)
8. LLM deepen (conditional: severity >= threshold AND blast_radius > 3, or `always_deepen` rule override) — loads company knowledge file, injects context + system prompt — analysis + suggested fix + agent prompt
9. Regression check (compare fingerprints against base branch baseline)
10. Dismiss filter (remove dismissed findings by fingerprint)
11. Persist scan (write to `.cartomancer.db`, best-effort)
12. Post review (categorized inline comments on diff lines, off-diff with caution banners, summary with actionable counts)

`--dry-run` skips step 12, outputs ReviewResult to stdout.

## External Dependencies

- **Opengrep**: must be in PATH, invoked as subprocess. Supports opengrep-specific flags: `--taint-intrafile`, `--opengrep-ignore-pattern`, `--output-enclosing-context`, `--dynamic-timeout`. Custom rules auto-discovered from `.cartomancer/rules/` (configurable via `opengrep.rules_dir`)
- **Ollama**: optional, local LLM at `http://localhost:11434/api/chat`
- **Anthropic API**: optional, production LLM at `https://api.anthropic.com/v1/messages`
- **cartog**: compiled in as Rust crate, SQLite-based code graph

## Conventions

- Error handling: `thiserror` in core, `anyhow` elsewhere
- Tests: co-located `#[cfg(test)]` for unit, `tests/` for integration
- Config: `.cartomancer.toml` for defaults, env vars for secrets
- CI: check, fmt, clippy, test, coverage, audit, secrets scan, deny
- Release: `scripts/release.sh <major|minor|patch>` → bumps version, tags, pushes
- Publish: GitHub Actions on `v*` tag → build binaries, GitHub Release, crates.io (dependency order with 60s sleep)
