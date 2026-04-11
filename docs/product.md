# Cartomancer — Product Overview

> PR review with blast radius awareness.

## Purpose

Cartomancer is an automated PR review tool that combines static analysis with code graph intelligence to produce structurally-aware, severity-escalated review comments on GitHub pull requests.

## Core Insight

Static analysis finds bugs. Blast radius tells you which bugs matter.

A SQL injection in a dead function is noise. A SQL injection reachable from 47 callers including your auth endpoint is critical. Cartomancer is the bridge between "this pattern matches" and "this matters because it affects your payment flow."

## Target Users

- **Engineering teams** using GitHub PRs who want automated review beyond linting
- **Security teams** wanting triage that accounts for code reachability
- **Open-source maintainers** reviewing contributions from external contributors

## Key Features

- **Opengrep integration**: 3000+ free rules, PR-aware via `--baseline-commit`, cross-function taint analysis, enclosing context for LLM deepening
- **Blast radius via cartog**: transitive impact analysis, caller graphs, domain detection
- **Severity escalation**: findings automatically upgraded when they touch auth/payment flows or have large blast radius
- **LLM deepening**: high-severity findings explained in context by Ollama (local) or Claude (production), with suggested fixes as unified diffs and AI agent prompts
- **Comment categories**: findings classified as Actionable (has fix or severity >= Error) or Nitpick, with collapsible sections for fixes and agent prompts
- **GitHub PR comments**: categorized inline comments, off-diff caution banners, summary with actionable counts
- **Finding persistence**: SQLite storage of scan results, regression detection (new vs. existing findings), and false positive dismissal

## Pipeline

```
GitHub webhook → fetch diff → opengrep scan → cartog enrich
  → escalate severity → LLM deepen (conditional)
  → regression check → dismiss filter → post comments + persist
```

## Positioning

| Tool | Strength | Gap Cartomancer fills |
|------|----------|----------------------|
| CodeRabbit | LLM reviews + learning | No structural graph, no blast radius |
| SonarQube | Taint analysis + rules | No LLM, no graph awareness, no PR-native |
| Opengrep | Best open rule ecosystem | No blast radius, no severity escalation |
| Claude Code review | Zero-setup LLM review | No persistent graph, no rule backbone |

Cartomancer is not a replacement for any of these. It adds blast-radius-aware severity escalation on top of opengrep findings, powered by cartog.

## Non-Goals

- Not a CI runner or test framework
- Not a code formatter or style enforcer
- Not a full SAST platform (no taint analysis in v1)
- Not a dashboard or metrics tool (v1 is CLI + webhook only)
- Not a retention/pruning system — all scan history is stored indefinitely
