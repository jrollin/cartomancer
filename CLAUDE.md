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
- `CartogEnricher` (graph::enricher) — wraps cartog::db::Database
- `SeverityEscalator` (graph::escalator) — blast radius + domain → severity upgrade

## Pipeline Stages

1. Fetch diff (GitHub API)
2. Semgrep scan (subprocess with `--baseline-commit`)
3. Enrich with cartog (impact, refs, callers, domain detection)
4. Escalate severity (blast radius thresholds + domain tags)
5. LLM deepen (conditional: severity >= threshold AND blast_radius > 3)
6. Post review comments (GitHub API)

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
