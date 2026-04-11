# Cartomancer — Project Structure

## Workspace Layout

```
cartomancer/
├── Cargo.toml                          # workspace root
├── .cartomancer.toml                   # example config
├── LICENSE                             # MIT license
├── deny.toml                           # cargo-deny policy
├── rustfmt.toml                        # format config
├── .gitignore
├── .github/workflows/
│   ├── ci.yml                          # CI pipeline
│   └── release.yml                     # build + publish on v* tags
├── scripts/
│   └── release.sh                      # version bump, tag, push
├── docs/
│   ├── product.md                      # purpose, users, features
│   ├── tech.md                         # stack, deps, constraints
│   ├── structure.md                    # this file
│   └── architecture.md                 # pipeline, data flow
├── crates/
│   ├── cartomancer-core/               # pure domain types
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── severity.rs
│   │       ├── finding.rs
│   │       ├── diff.rs
│   │       ├── review.rs
│   │       ├── config.rs
│   │       └── error.rs
│   ├── cartomancer-graph/              # cartog + escalation
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── enricher.rs
│   │       └── escalator.rs
│   ├── cartomancer-github/             # GitHub API
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── client.rs              # GitHubClient: fetch, post review/comment
│   │       ├── diff.rs                # parse_diff(), is_line_in_diff()
│   │       ├── types.rs               # PrMetadata, ReviewComment, API request types
│   │       └── webhook.rs
│   ├── cartomancer-store/              # SQLite persistence
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── schema.rs              # DDL, versioned migrations (PRAGMA user_version)
│   │       ├── fingerprint.rs         # SHA-256 finding identity (rule_id:file:snippet)
│   │       ├── store.rs               # Store: scan/finding CRUD, dismissals, baselines
│   │       └── types.rs               # ScanRecord, StoredFinding, Dismissal, filters
│   └── cartomancer-server/             # binary: pipeline + CLI
│       ├── src/
│       │   ├── main.rs                # entry point: cmd_scan, cmd_review, cmd_history, cmd_findings, cmd_dismiss
│       │   ├── cli.rs                 # clap: scan, review, history, findings, dismiss, dismissed, undismiss, serve
│       │   ├── comment.rs             # format_inline_comment, format_off_diff_comment, format_summary, classify_finding
│       │   ├── config.rs
│       │   ├── pipeline.rs            # run_pipeline, persist_scan, annotate_regression, filter_dismissed
│       │   ├── opengrep.rs
│       │   ├── webhook.rs
│       │   └── llm/
│       │       ├── mod.rs              # LlmProvider trait, parse_llm_response, build_agent_prompt
│       │       ├── ollama.rs           # local dev
│       │       └── anthropic.rs        # production
│       └── tests/
│           └── pipeline_integration.rs
├── README.md
└── CLAUDE.md
```

## Crate Responsibilities

| Crate | Type | Role | Key types |
|-------|------|------|-----------|
| `cartomancer-core` | lib | Pure domain model, no I/O | `Finding`, `GraphContext`, `Severity`, `AppConfig`, `StorageConfig`, `LlmBackend`, `ReviewResult` |
| `cartomancer-graph` | lib | cartog integration + severity escalation | `CartogEnricher`, `SeverityEscalator` |
| `cartomancer-github` | lib | GitHub REST API client + diff parser | `GitHubClient`, `PrMetadata`, `ReviewComment`, `parse_diff()`, `is_line_in_diff()` |
| `cartomancer-store` | lib | SQLite persistence for scan results | `Store`, `ScanRecord`, `StoredFinding`, `Dismissal`, `compute()`, `snippet_hash()` |
| `cartomancer-server` | bin | Pipeline orchestration, CLI, webhook | `Cli`, `LlmProvider`, `run_pipeline()`, `persist_scan()`, `annotate_regression()`, `filter_dismissed()` |

## Dependency Graph

```
cartomancer-server
├── cartomancer-core
├── cartomancer-graph
│   ├── cartomancer-core
│   └── cartog (external)
├── cartomancer-github
│   └── cartomancer-core
└── cartomancer-store
    ├── cartomancer-core
    └── rusqlite
```

## Module Boundaries in cartomancer-server

| Module | Responsibility | Dependencies |
|--------|---------------|--------------|
| `cli` | Clap argument parsing (scan, review, history, findings, dismiss, dismissed, undismiss, serve) | - |
| `comment` | Format categorized inline comments (Actionable/Nitpick, collapsible fix + agent prompt), off-diff caution comments, summary with actionable counts | cartomancer-core::finding |
| `config` | TOML config loading | cartomancer-core::config |
| `pipeline` | Review orchestration + persistence + regression + dismissal filtering | all other modules, cartomancer-store |
| `opengrep` | Subprocess runner + JSON parsing | cartomancer-core::finding |
| `llm/` | Provider trait + Ollama + Anthropic + response parsing (analysis/fix split) + agent prompt generation | cartomancer-core::finding |
| `webhook` | Axum HTTP handler | pipeline, cartomancer-github |

## Conventions

- **Error handling**: `thiserror` for domain errors in core, `anyhow` for application propagation elsewhere
- **Visibility**: `pub` items get doc comments, internal items do not
- **Tests**: co-located `#[cfg(test)] mod tests` for unit tests, `tests/` directory for integration tests
- **Naming**: kebab-case crate names, snake_case modules and functions
