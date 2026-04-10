# Cartomancer

> PR review with blast radius awareness.

Cartomancer combines [Semgrep](https://semgrep.dev/) static analysis with [cartog](https://github.com/jrollin/cartog) code graph intelligence to produce severity-escalated, structurally-aware review comments on GitHub pull requests.

**The core idea**: a finding that touches your auth flow and has 30 downstream callers is not the same severity as the same finding in a dead utility function. Cartomancer knows the difference.

## Architecture

```
GitHub webhook → fetch diff → semgrep scan → cartog enrich
  → escalate severity → LLM deepen (conditional) → post comments
```

## Prerequisites

| Tool | Version | Required | Install |
|------|---------|----------|---------|
| Rust | 1.77+ | Yes | [rustup.rs](https://rustup.rs/) |
| Semgrep CLI | 1.x | Yes | `pip install semgrep` or `brew install semgrep` |
| cartog | 0.10+ | Recommended | `cargo install cartog` (for graph enrichment) |
| Ollama | any | Optional | [ollama.com](https://ollama.com/) (for local LLM deepening) |

Semgrep must be in your `PATH`. Without it, Cartomancer cannot run.

## Quickstart

```bash
# Build
cargo build --release

# Scan a local directory (no GitHub token needed)
cartomancer-server scan /path/to/project

# With cartog graph enrichment (recommended)
cd /path/to/project
cartog index .
cartomancer-server scan .

# With LLM deepening (Ollama, local)
ollama pull gemma4
cartomancer-server scan .  # critical findings get AI analysis

# Configure (for GitHub PR reviews)
cp .cartomancer.toml .cartomancer.local.toml
# Edit .cartomancer.local.toml with your GitHub token

# Review a PR (one-shot)
cartomancer-server review --repo owner/repo --pr 42

# Start webhook server
cartomancer-server serve --port 3000
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
