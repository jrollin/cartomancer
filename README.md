# Cartomancer

[![CI](https://github.com/jrollin/cartomancer/actions/workflows/ci.yml/badge.svg)](https://github.com/jrollin/cartomancer/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/jrollin/cartomancer/branch/main/graph/badge.svg)](https://codecov.io/gh/jrollin/cartomancer)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

> PR review with blast radius awareness.

Cartomancer combines [opengrep](https://github.com/opengrep/opengrep) static analysis with [cartog](https://github.com/jrollin/cartog) code graph intelligence to produce severity-escalated, structurally-aware review comments on GitHub pull requests.

**The core idea**: a finding that touches your auth flow and has 30 downstream callers is not the same severity as the same finding in a dead utility function. Cartomancer knows the difference.

## Architecture

```text
GitHub webhook → fetch diff → opengrep scan → cartog enrich
  → escalate severity → LLM deepen (conditional: analysis + suggested fix + agent prompt)
  → regression check → dismiss filter → persist + post categorized comments
```

## Prerequisites

| Tool | Version | Required | Install |
|------|---------|----------|---------|
| Rust | 1.77+ | Yes | [rustup.rs](https://rustup.rs/) |
| Opengrep CLI | latest | Yes | [install script](https://github.com/opengrep/opengrep#install) or [GitHub releases](https://github.com/opengrep/opengrep/releases) |
| cartog | 0.10+ | Recommended | `cargo install cartog` (for graph enrichment) |
| Ollama | any | Optional | [ollama.com](https://ollama.com/) (for local LLM deepening) |

Opengrep must be in your `PATH`. Without it, Cartomancer cannot run.

## Quickstart

```bash
# Build
cargo build --release

# Check that all dependencies and config are healthy
cartomancer doctor

# Scan a local directory (no GitHub token needed)
cartomancer scan /path/to/project

# With cartog graph enrichment (recommended)
cd /path/to/project
cartog index .
cartomancer scan .

# With LLM deepening (Ollama, local)
ollama pull gemma4
cartomancer scan .  # critical findings get AI analysis

# Configure (for GitHub PR reviews)
cp .cartomancer.toml .cartomancer.local.toml
# Edit .cartomancer.local.toml with your GitHub token

# Review a PR (one-shot)
cartomancer review owner/repo 42

# Browse scan history
cartomancer history

# Browse findings from a scan
cartomancer findings 1

# Search findings across all scans
cartomancer findings --rule sql --severity error

# Dismiss a false positive (finding #3 from scan 1)
cartomancer dismiss 1 3 --reason "false positive"

# List and remove dismissals
cartomancer dismissed
cartomancer undismiss 1

# Start webhook server
cartomancer serve --port 3000
```

## Configuration

See [.cartomancer.toml](.cartomancer.toml) for the full config reference.

Key environment variables:
- `GITHUB_TOKEN` — GitHub API token
- `ANTHROPIC_API_KEY` — Anthropic API key (when using `provider = "anthropic"`)
- `CARTOMANCER_CONFIG` — Config file path (default: `.cartomancer.toml`)

## Crate Structure

| Crate | Role |
|-------|------|
| `cartomancer-core` | Domain model: Finding, Severity, GraphContext, config types |
| `cartomancer-graph` | cartog integration + severity escalation (the moat) |
| `cartomancer-github` | GitHub API: diff fetch, PR comments, webhook parsing |
| `cartomancer-store` | SQLite persistence: scan history, finding storage, dismissals |
| `cartomancer-server` | Binary: pipeline orchestration, CLI, webhook, LLM providers |

See [docs/structure.md](docs/structure.md) for the full layout.

## Development

```bash
cargo check --workspace          # type check
cargo test --workspace           # run tests
cargo clippy --all-targets       # lint
cargo fmt                        # format
```

## Documentation

- [docs/product.md](docs/product.md) — purpose, users, positioning
- [docs/tech.md](docs/tech.md) — stack, dependencies, constraints
- [docs/structure.md](docs/structure.md) — file organization, crate responsibilities
- [docs/architecture.md](docs/architecture.md) — pipeline, data flow, escalation rules

## License

MIT
