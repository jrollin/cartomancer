# Cartomancer — Technical Overview

## Language

Rust (single binary, performance, native cartog integration).

## Core Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| cartog | 0.10 | Code graph: blast radius, callers, impact, AST indexing |
| tokio | 1 | Async runtime (webhook server, subprocess, HTTP) |
| axum | 0.8 | Webhook HTTP server |
| reqwest | 0.12 | HTTP client (GitHub API, Ollama, Anthropic) |
| clap | 4 | CLI argument parsing |
| serde / serde_json / toml | 1 / 1 / 0.8 | Serialization (config TOML, API payloads, opengrep JSON) |
| tracing / tracing-subscriber | 0.1 / 0.3 | Structured logging |
| anyhow | 1 | Error propagation across the workspace |
| async-trait | 0.1 | Async trait for LLM provider abstraction |
| rusqlite | 0.39 | SQLite database access (finding persistence) |
| sha2 | 0.10 | SHA-256 fingerprint computation for finding identity |

## External Tools

| Tool | Integration | Required |
|------|------------|----------|
| Opengrep | Subprocess (`opengrep scan --json`). Opt-in features: `--taint-intrafile`, `--output-enclosing-context`, `--dynamic-timeout`, `--opengrep-ignore-pattern`. Custom rules auto-discovered from `.cartomancer/rules/` | Yes (must be in PATH) |
| Ollama | HTTP API (`/api/chat`) | Optional (default LLM for local dev) |
| Anthropic API | HTTP API (`/v1/messages`) | Optional (production LLM) |
| cartog | Rust crate (compiled in) | Built-in |

## Architecture Decisions

| Decision | Rationale |
|----------|-----------|
| Subprocess for opengrep | Opengrep is a mature binary; FFI would be fragile and unnecessary |
| Raw reqwest for GitHub API | Avoids octocrab dependency; GitHub REST API is simple enough |
| cartog from crates.io | Native Rust integration, no subprocess overhead for graph queries |
| LLM provider trait | Supports local Ollama for testing, Anthropic for production; response parsed for analysis + suggested fix; optional system prompt from config |
| rusqlite directly (no ORM) | Simple schema (4 tables), fast enough synchronous, already a transitive dep via cartog |
| PRAGMA user_version for schema migrations | Built-in SQLite integer, no extra migration table for a single-user embedded DB |
| axum for webhook | Lightweight, tokio-native, matches cartog conventions |
| Single binary | Simplifies deployment, air-gapped environments |

## Build Profiles

```toml
[profile.release]
lto = "thin"
strip = "debuginfo"

[profile.dev]
opt-level = 1  # tree-sitter C grammars via cartog compile slowly at level 0
```

## Constraints

- MSRV: 1.77
- No Python/Node runtime dependency
- Single binary deployment
- Opengrep must be installed separately (not bundled)
- Air-gap capable: cartog runs fully offline, only LLM calls require network

## Security

- **Path traversal protection**: user-supplied paths in config (`rules_dir`, `knowledge_file`) are validated to stay within the project directory. Symlinks, `../` escapes, and absolute paths outside the project are rejected.
- **Binary file detection**: knowledge files are checked for null bytes and rejected if they appear binary.
- **Prompt size bounds**: `max_knowledge_chars` limits the amount of knowledge file content injected into LLM prompts (default: 8000).

## Security Considerations

- Webhook secret validation (HMAC-SHA256) for GitHub events
- API keys via environment variables (not config file): `GITHUB_TOKEN`, `ANTHROPIC_API_KEY`
- `.cartomancer.local.toml` gitignored for local secrets
- No secrets in logs (tracing filters sensitive fields)
- cargo-audit and gitleaks in CI pipeline
