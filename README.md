# Cartomancer

[![CI](https://github.com/jrollin/cartomancer/actions/workflows/ci.yml/badge.svg)](https://github.com/jrollin/cartomancer/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/jrollin/cartomancer/branch/main/graph/badge.svg)](https://codecov.io/gh/jrollin/cartomancer)
[![crates.io](https://img.shields.io/crates/v/cartomancer.svg)](https://crates.io/crates/cartomancer)
[![MSRV](https://img.shields.io/badge/MSRV-1.77-blue.svg)](https://blog.rust-lang.org/2024/03/21/Rust-1.77.0.html)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**Static analysis finds bugs. Blast radius tells you which ones matter.**

A SQL injection in dead code is noise. A SQL injection reachable from 47 callers including your auth endpoint is critical. Cartomancer bridges "pattern matches" and "this actually matters" by combining [opengrep](https://github.com/opengrep/opengrep) static analysis with [cartog](https://github.com/jrollin/cartog) code graph intelligence.

Every finding gets enriched with caller count, transitive impact, and domain detection (auth, payment, data). Severity escalates automatically based on structural context — not just the rule that matched.

![cartomancer demo](docs/assets/demo.gif)

_Scan of a 6-file Flask fixture. Findings in `db.py` escalate to **Critical** because they're reachable from the auth and payment flows; the `pickle` warning in the uncalled `utils.py` stays **Warning**. Fixture, config, and tape live in [`examples/demo/`](examples/demo/)._

## What it does

```text
PR opened → opengrep scan (3000+ rules + your custom YAML)
  → cartog blast radius (callers, impact depth, domain tags)
  → severity escalation (Warning in auth flow → Critical)
  → LLM deepening (explain impact + suggest fix as diff)
  → regression check (new vs. existing findings)
  → post categorized comments to GitHub PR
```

**Example output on a PR:**

```
Finding 1/5  CRITICAL  sql-injection
  src/api/users.rs:47
  Blast radius: 23 callers (auth, payment)
  Escalated: Warning → Critical (auth domain, 23 callers)
  LLM: "Unsanitized user input reaches SQL query via
        authenticate() → fetch_user(). Affects all login
        flows and payment verification."
  Fix: suggested diff attached

Finding 2/5  INFO  unused-import
  src/utils.rs:3
  Blast radius: 0 callers
  Category: Nitpick

Review: 2 actionable, 3 nitpicks
```

## Quick start

```bash
# Install (from crates.io)
cargo install cartomancer

# Or download a pre-built binary (no Rust toolchain needed)
# macOS (Apple Silicon)
curl -L https://github.com/jrollin/cartomancer/releases/latest/download/cartomancer-aarch64-apple-darwin.tar.gz | tar xz
sudo mv cartomancer /usr/local/bin/
# All platforms: https://github.com/jrollin/cartomancer/releases/latest

# Scaffold a commented .cartomancer.toml
cartomancer init

# Check your setup (git, opengrep, cartog db, LLM provider, …)
cartomancer doctor

# Scan a local directory (no GitHub token needed)
cartomancer scan ./src

# Review a GitHub PR (dry run — prints to stdout)
export GITHUB_TOKEN=ghp_...
cartomancer review owner/repo 42 --dry-run

# Review and post comments to GitHub
cartomancer review owner/repo 42
```

**With graph enrichment** (recommended):

```bash
cargo install cartog
cd your-project && cartog index .
cartomancer scan .    # findings now include blast radius
```

**With LLM deepening** (optional):

```bash
# Local (Ollama)
ollama pull llama3.2
cartomancer scan .    # critical findings get AI analysis + fix

# Production (Claude)
export ANTHROPIC_API_KEY=sk-...
# Set [llm] provider = "anthropic" in .cartomancer.toml
```

## CLI commands

| Command | Purpose |
|---------|---------|
| `cartomancer init [--force]` | Scaffold a commented `.cartomancer.toml` |
| `cartomancer scan <path>` | Local scan — no GitHub, no PR |
| `cartomancer review <owner/repo> <pr> [--resume <scan-id>]` | Full pipeline → GitHub PR comments (resume a failed run from its last checkpoint) |
| `cartomancer history` | Browse past scan results |
| `cartomancer findings [<scan-id>]` | Search findings by rule, severity, file, branch |
| `cartomancer dismiss <scan-id> <index>` | Suppress a false positive by fingerprint |
| `cartomancer dismissed` | List active dismissals |
| `cartomancer undismiss <id>` | Remove a dismissal |
| `cartomancer serve` | Webhook server for automated PR reviews |
| `cartomancer doctor` | Validate dependencies and config |

All commands accept `--json` for machine-readable output. Empty results emit `[]` / `{}` so pipelines keep working. `scan --json` emits an envelope:

```json
{ "scan_id": 42, "findings": [...], "summary": { "total": 3, "critical": 1, "error": 1, "warning": 1, "info": 0 } }
```

## How severity escalation works

Findings auto-upgrade based on where they sit in your codebase:

| Condition | Effect |
|-----------|--------|
| Blast radius >= 4x threshold | **Critical** |
| Blast radius >= threshold | Error (minimum) |
| Domain: `auth` or `payment` | **Critical** |
| Callers >= 10 | Error (minimum) |
| Per-rule `min_severity` | Floor before escalation |
| Per-rule `max_severity` | Ceiling after escalation |

Default `blast_radius_threshold` = 5. Configurable in `.cartomancer.toml`.

## Configuration

Cartomancer works with zero configuration. Optionally, place `.cartomancer.toml` at your project root:

```toml
[opengrep]
rules_dir = ".cartomancer/rules"     # custom YAML rules
enclosing_context = true             # include function body in LLM prompt
taint_intrafile = true               # cross-function taint analysis

[llm]
provider = "ollama"                  # "ollama" or "anthropic"
deepening_threshold = "error"        # minimum severity for LLM

[graph]
blast_radius_threshold = 5

[knowledge]
file = ".cartomancer/knowledge.md"   # team context injected into LLM prompts
system_prompt = "You are reviewing a fintech codebase."

[knowledge.rules.sql-injection]
min_severity = "error"
always_deepen = true                 # always run LLM for this rule
```

Environment variables: `GITHUB_TOKEN`, `ANTHROPIC_API_KEY`, `RUST_LOG`.

## Architecture

```text
cartomancer-server (binary)
├── cartomancer-core     — domain types (Finding, Severity, config)
├── cartomancer-graph    — cartog enricher + severity escalator
├── cartomancer-github   — GitHub API client + webhook types
└── cartomancer-store    — SQLite persistence (scans, findings, dismissals)
```

## Development

```bash
cargo check --workspace          # type check
cargo test --workspace           # run tests
cargo clippy --all-targets       # lint
cargo fmt --check                # format check
```

## Documentation

- [Website](https://jrollin.github.io/cartomancer/) — landing page + full docs
- [docs/product.md](docs/product.md) — purpose, users, positioning
- [docs/tech.md](docs/tech.md) — stack, dependencies, constraints
- [docs/structure.md](docs/structure.md) — file organization, crate responsibilities
- [docs/architecture.md](docs/architecture.md) — pipeline, data flow, escalation rules

## License

MIT
