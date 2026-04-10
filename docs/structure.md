# Cartomancer — Project Structure

## Workspace Layout

```
cartomancer/
├── Cargo.toml                          # workspace root
├── .cartomancer.yaml                   # example config
├── deny.toml                           # cargo-deny policy
├── rustfmt.toml                        # format config
├── .gitignore
├── .github/workflows/ci.yml            # CI pipeline
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
│   │       ├── client.rs
│   │       ├── diff.rs
│   │       └── webhook.rs
│   └── cartomancer-server/             # binary: pipeline + CLI
│       ├── src/
│       │   ├── main.rs
│       │   ├── cli.rs
│       │   ├── config.rs
│       │   ├── pipeline.rs
│       │   ├── semgrep.rs
│       │   ├── webhook.rs
│       │   └── llm/
│       │       ├── mod.rs              # LlmProvider trait
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
| `cartomancer-core` | lib | Pure domain model, no I/O | `Finding`, `GraphContext`, `Severity`, `AppConfig`, `ReviewResult` |
| `cartomancer-graph` | lib | cartog integration + severity escalation | `CartogEnricher`, `SeverityEscalator` |
| `cartomancer-github` | lib | GitHub REST API client | `GitHubClient`, `PullRequestEvent`, `parse_diff()` |
| `cartomancer-server` | bin | Pipeline orchestration, CLI, webhook | `Cli`, `LlmProvider`, `run_pipeline()`, `run_semgrep()` |

## Dependency Graph

```
cartomancer-server
├── cartomancer-core
├── cartomancer-graph
│   ├── cartomancer-core
│   └── cartog (external)
└── cartomancer-github
    └── cartomancer-core
```

## Module Boundaries in cartomancer-server

| Module | Responsibility | Dependencies |
|--------|---------------|--------------|
| `cli` | Clap argument parsing | - |
| `config` | YAML config loading | cartomancer-core::config |
| `pipeline` | Orchestration state machine | all other modules |
| `semgrep` | Subprocess runner + JSON parsing | cartomancer-core::finding |
| `llm/` | Provider trait + Ollama + Anthropic | cartomancer-core::finding |
| `webhook` | Axum HTTP handler | pipeline, cartomancer-github |

## Conventions

- **Error handling**: `thiserror` for domain errors in core, `anyhow` for application propagation elsewhere
- **Visibility**: `pub` items get doc comments, internal items do not
- **Tests**: co-located `#[cfg(test)] mod tests` for unit tests, `tests/` directory for integration tests
- **Naming**: kebab-case crate names, snake_case modules and functions
