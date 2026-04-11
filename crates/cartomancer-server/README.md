# cartomancer

PR review tool with blast radius awareness — opengrep + cartog + LLM deepening.

Cartomancer bridges static analysis with code graph intelligence to produce structurally-aware, severity-escalated review comments on GitHub pull requests.

## Install

```bash
cargo install cartomancer
```

Requires [opengrep](https://github.com/opengrep/opengrep) in PATH.

## Usage

```bash
# Scan a local directory
cartomancer scan .

# Review a GitHub PR (requires GITHUB_TOKEN)
export GITHUB_TOKEN=ghp_...
cartomancer review owner/repo 42

# Dry run — output review JSON without posting
cartomancer review owner/repo 42 --dry-run

# Reuse an existing checkout
cartomancer review owner/repo 42 --work-dir /path/to/repo
```

## How it works

1. Fetch PR diff from GitHub
2. Run opengrep with `--baseline-commit` (only new findings)
3. Enrich with [cartog](https://crates.io/crates/cartog) blast radius and caller analysis
4. Escalate severity for findings in auth/payment flows or with large blast radius
5. Optionally deepen high-severity findings with LLM (Ollama or Anthropic), generating suggested fixes and AI agent prompts
6. Classify findings as Actionable or Nitpick
7. Post PR review with categorized inline comments (collapsible fixes + agent prompts), off-diff caution banners, and summary with actionable counts

## Configuration

Create `.cartomancer.toml` in your project root:

```toml
[opengrep]
rules = ["auto"]
timeout_seconds = 120
# taint_intrafile = false       # cross-function taint analysis
# enclosing_context = false     # surrounding function in findings (improves LLM deepening)
# ignore_pattern = "nosec"      # custom inline ignore annotation
# dynamic_timeout = false       # file-size-scaled timeouts

[llm]
provider = "ollama"
ollama_model = "gemma4"

[severity]
blast_radius_threshold = 5
llm_deepening_threshold = "error"
```

## License

MIT
