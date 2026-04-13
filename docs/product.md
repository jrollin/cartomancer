# Cartomancer — Product Overview

> Static analysis finds bugs. Blast radius tells you which ones matter.

## The Problem

Every PR review tool can tell you "this line matches a SQL injection pattern." None of them tell you _why that matters in your codebase_. A SQL injection in a dead utility is noise. A SQL injection reachable from 47 callers including your authentication endpoint is a production incident waiting to happen.

Developers waste time triaging findings that lack structural context. Security teams can't prioritize when every finding looks the same severity. The signal-to-noise ratio of static analysis tools is too low to be useful without manual triage.

## What Cartomancer Does

Cartomancer is an automated PR review tool that combines static analysis with code graph intelligence. For every finding, it answers: _how many callers does this affect? Does it touch auth or payment flows? How deep is the impact chain?_

Findings are automatically escalated (or capped) based on their structural context — not just the pattern that matched.

High-severity findings get explained by an LLM with your team's conventions injected as context. Each explanation includes a suggested fix as a unified diff and an AI agent prompt for automated remediation.

## Who It's For

- **Engineering teams** using GitHub PRs who want review comments that prioritize what matters
- **Security teams** wanting triage that accounts for code reachability, not just pattern matching
- **Open-source maintainers** reviewing contributions from external contributors
- **Solo developers** who want a second pair of eyes that understands blast radius

## Key Features

| Feature | What it does |
|---------|-------------|
| **Opengrep scanning** | 3000+ open rules + custom YAML rules from `.cartomancer/rules/` |
| **Blast radius** | Transitive impact analysis via cartog: caller count, impact depth, domain detection |
| **Severity escalation** | Auto-upgrade based on blast radius, domain tags (auth/payment), caller count |
| **Per-rule overrides** | `min_severity`, `max_severity`, `always_deepen` per rule ID |
| **LLM deepening** | Conditional: Ollama (local) or Claude (production). Analysis + fix + agent prompt |
| **Company knowledge** | Inject `.cartomancer/knowledge.md` into every LLM prompt |
| **Regression detection** | Fingerprint-based: distinguish new findings from pre-existing ones |
| **Finding dismissal** | Suppress false positives by fingerprint. Survives line shifts, reappears on code changes |
| **GitHub native** | Inline comments, off-diff caution banners, summary with actionable/nitpick counts |
| **Persistence** | SQLite: scan history, finding search, branch filtering |
| **Webhook server** | Automated reviews on every PR event. HMAC-validated, bounded concurrency |
| **Single binary** | Rust. No Python, no Docker. Air-gap capable with Ollama |

## Pipeline

```text
PR opened → fetch diff → opengrep scan (+ custom rules)
  → cartog enrich (callers, impact, domain)
  → escalate severity (+ per-rule overrides)
  → LLM deepen (+ company knowledge)
  → regression check → dismiss filter
  → persist + post categorized comments
```

## Positioning

| Tool | What it does well | Gap Cartomancer fills |
|------|-------------------|----------------------|
| CodeRabbit | LLM reviews + learning | No structural graph, no blast radius awareness |
| SonarQube | Taint analysis + rule library | No LLM, no graph context, no PR-native comments |
| Opengrep | Best open rule ecosystem | No blast radius, no severity escalation, no LLM |
| Claude Code review | Zero-setup LLM review | No persistent graph, no rule backbone |

Cartomancer is not a replacement for these tools. It adds the structural layer they don't have: blast-radius-aware severity escalation on top of opengrep findings, powered by cartog.

## Non-Goals

- Not a CI runner or test framework
- Not a code formatter or style enforcer
- Not a full SAST platform (no inter-file taint analysis in v1)
- Not a dashboard or metrics tool (v1 is CLI + webhook only)
- Not a retention/pruning system — all scan history is stored indefinitely
