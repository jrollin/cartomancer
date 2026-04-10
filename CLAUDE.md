# Cartomancer

PR review tool: Semgrep + cartog blast radius + LLM deepening → GitHub comments.

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
└── cartomancer-github   — GitHub API client + webhook types
```

## Key Types

- `Finding` (core::finding) — Semgrep finding + optional graph context + LLM analysis
- `GraphContext` (core::finding) — blast radius, callers, domain tags from cartog
- `Severity` (core::severity) — Info < Warning < Error < Critical
- `ReviewResult` (core::review) — final output posted to GitHub
- `AppConfig` (core::config) — deserialized from `.cartomancer.toml`
- `LlmBackend` (core::config) — enum: Ollama or Anthropic (config selection)
- `LlmProvider` (server::llm) — async trait with Ollama and Anthropic implementations
- `PrMetadata` (github::types) — PR head/base SHA, refs, title from GitHub API
- `ReviewComment` (github::types) — inline comment for PR Review API
- `CartogEnricher` (graph::enricher) — wraps cartog::db::Database
- `SeverityEscalator` (graph::escalator) — blast radius + domain → severity upgrade
- `PipelineResult` (server::pipeline) — ReviewResult + parsed diff + temp dir handle

## CLI Commands

```
cartomancer scan <path> [--format text|json]
cartomancer review <owner/repo> <pr> [--work-dir <path>] [--dry-run] [--format text|json]
cartomancer serve [--port <n>]                    # not yet implemented
```

## Review Pipeline Stages

1. Resolve GitHub token (env `GITHUB_TOKEN` or config)
2. Fetch PR metadata (GitHub API → head SHA, base SHA)
3. Prepare work dir (clone to temp dir, or reuse `--work-dir`)
4. Fetch + parse unified diff (GitHub API → `PullRequestDiff`)
5. Semgrep scan (subprocess with `--baseline-commit base_sha`)
6. Enrich with cartog (impact, refs, callers, domain detection)
7. Escalate severity (blast radius thresholds + domain tags)
8. LLM deepen (conditional: severity >= threshold AND blast_radius > 3)
9. Post review (inline comments on diff lines, off-diff as regular comments)

`--dry-run` skips step 9, outputs ReviewResult to stdout.

## External Dependencies

- **Semgrep**: must be in PATH, invoked as subprocess
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
