# Cartomancer — Architecture

## Entry Points

```
cartomancer scan <path>                        Local scan, no GitHub
cartomancer review <owner/repo> <pr>           One-shot PR review via CLI
cartomancer serve                              Webhook server (not yet implemented)
```

## Pipeline Stages

```
1. Prepare       Clone repo or reuse --work-dir
2. Fetch Meta    GitHub API → PrMetadata (head SHA, base SHA)
3. Fetch Diff    GitHub API → raw unified diff → PullRequestDiff
4. Semgrep Scan  subprocess --baseline-commit → Vec<Finding>
5. Graph Enrich  cartog impact/refs → GraphContext per finding
6. Escalate      blast radius + domain → adjusted Severity
7. LLM Deepen    Ollama or Anthropic → analysis text (conditional)
8. Post          GitHub API → PR review (inline comments + summary)
```

Stages 4-7 are shared between `scan` and `review` commands.

## Data Flow

```
CLI: cartomancer review owner/repo 42
  │
  ├─▶ Resolve GITHUB_TOKEN (env var or config)
  │
  ▼ GitHubClient.fetch_pr_metadata()
PrMetadata { head_sha, base_sha, head_ref, base_ref }
  │
  ├─▶ prepare_work_dir (clone with token auth, or reuse --work-dir)
  │
  ▼ GitHubClient.fetch_diff() + parse_diff()
PullRequestDiff { chunks: Vec<DiffChunk>, files_changed }
  │
  ▼ semgrep::run_semgrep(--baseline-commit base_sha)
Vec<Finding> (new findings only, from diff)
  │
  ▼ CartogEnricher.enrich() per finding
Vec<Finding> (with GraphContext: blast_radius, callers, domain_tags, is_public_api)
  │
  ▼ SeverityEscalator.escalate_batch()
Vec<Finding> (severity adjusted based on graph context)
  │
  ▼ LlmProvider.deepen() — only if severity >= threshold AND blast_radius > 3
Vec<Finding> (with llm_analysis text)
  │
  ▼ Build ReviewResult + format comments
ReviewResult { findings, summary, head_sha }
  │
  ├─▶ --dry-run? → output JSON/text to stdout, skip posting
  │
  ▼ Post to GitHub
  ├── Inline findings: POST /repos/{repo}/pulls/{pr}/reviews (COMMENT event)
  ├── Off-diff findings: POST /repos/{repo}/issues/{pr}/comments
  └── Zero findings: POST summary comment ("no findings detected")
```

## Severity Escalation Matrix

| Base Severity | Blast Radius | Domain | Callers | Final Severity |
|--------------|-------------|--------|---------|---------------|
| any | >= threshold*4 | any | any | Critical |
| any | >= threshold | any | any | Error (minimum) |
| any | any | auth | any | Critical |
| any | any | payment | any | Critical |
| any | any | any | >= 10 | Error (minimum) |
| any | < threshold | none | < 10 | unchanged |

Default `blast_radius_threshold` = 5 (configurable in `.cartomancer.toml`).

## LLM Provider Architecture

```
LlmProvider (async trait)
  fn name() -> &str
  fn complete(prompt) -> Result<String>
  fn deepen(finding) -> Result<()>  // default impl builds prompt + calls complete
    │
    ├── OllamaProvider
    │     POST http://localhost:11434/api/chat
    │     No API key, stream: false
    │     Default for local development
    │
    └── AnthropicProvider
          POST https://api.anthropic.com/v1/messages
          x-api-key header, anthropic-version: 2023-06-01
          For production use
```

Provider selected via `llm.provider` in config. Factory: `create_provider(&LlmConfig)`.

## LLM Deepening

Triggered only when:
- Finding severity >= `llm_deepening_threshold` (default: Error)
- AND blast radius > 3

Prompt includes:
- Finding details (rule, message, severity, file, code snippet)
- Structural context from cartog (symbol name, blast radius, callers list, domain tags)
- Task: explain real-world impact in 2-3 sentences

## Sequence Diagram — Review Command

```
CLI ──parse args──▶ cmd_review()
                      │
                      ├─▶ Resolve GITHUB_TOKEN
                      │
                      ▼
                   pipeline::run_pipeline()
                      │
                      ├─▶ GitHubClient.fetch_pr_metadata()
                      │       └── GET /repos/:owner/:repo/pulls/:pr
                      │
                      ├─▶ prepare_work_dir()
                      │       ├── --work-dir + .git exists → reuse
                      │       ├── --work-dir + empty → clone (kept)
                      │       └── no --work-dir → clone to temp dir (cleaned up)
                      │
                      ├─▶ checkout_pr_head()
                      │       └── git fetch + checkout head SHA
                      │
                      ├─▶ GitHubClient.fetch_diff()
                      │       └── GET /repos/:owner/:repo/pulls/:pr
                      │           Accept: application/vnd.github.diff
                      │
                      ├─▶ parse_diff() → PullRequestDiff
                      │
                      ├─▶ semgrep::run_semgrep(--baseline-commit base_sha)
                      │       └── subprocess: semgrep scan --json
                      │
                      ├─▶ CartogEnricher.enrich() per finding
                      │       ├── db.outline()   → resolve symbol at line
                      │       ├── db.impact()    → blast radius
                      │       ├── db.refs()      → callers
                      │       └── detect_domain_tags() (symbol + callers)
                      │
                      ├─▶ SeverityEscalator.escalate_batch()
                      │       └── threshold checks → severity upgrade
                      │
                      ├─▶ LlmProvider.deepen() (conditional)
                      │       └── POST /api/chat or /v1/messages
                      │
                      └─▶ PipelineResult { review, diff, temp_dir }
                      │
                   cmd_review() continues:
                      │
                      ├─▶ --dry-run? → print ReviewResult, exit
                      │
                      ├─▶ zero findings? → post_comment(clean summary)
                      │
                      └─▶ findings:
                              ├── is_line_in_diff() → inline ReviewComment
                              ├── off-diff → post_comment() per finding
                              └── post_review(inline comments + summary)
```

## GitHub API Calls

| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/repos/{repo}/pulls/{pr}` | PR metadata (head/base SHA) |
| GET | `/repos/{repo}/pulls/{pr}` + `Accept: diff` | Raw unified diff |
| POST | `/repos/{repo}/pulls/{pr}/reviews` | Atomic review with inline comments (COMMENT event) |
| POST | `/repos/{repo}/issues/{pr}/comments` | Summary comment or off-diff findings |

All GET requests use single-retry with 1s delay on 5xx/network errors.

## Comment Formatting

| Function | Output |
|----------|--------|
| `format_inline_comment(finding)` | Severity badge, rule ID, message, snippet, blast radius, domain, escalation, LLM analysis, CWE |
| `format_summary(findings, duration, rules)` | Severity breakdown, top escalated findings, scan metadata |
| `format_clean_summary(duration, rules)` | "No findings detected" with scan metadata |

## Concurrency Model

- **tokio** async runtime for GitHub API calls and LLM calls
- **Subprocess** for Semgrep (tokio::process::Command)
- **Sync** git clone/checkout (std::process::Command, blocking)
- **Sync** cartog Database access (rusqlite is not Send; access from a single task)
- Findings enrichment runs sequentially per finding (cartog DB is single-connection)

## Error Handling Strategy

- **Per-finding errors**: logged and skipped (partial results are better than no results)
- **Pipeline-level errors**: fail before posting (clone, semgrep, GitHub API)
- **LLM errors**: logged and skipped (review still posts without LLM analysis)
- **Temp dir cleanup**: always cleaned up, even on failure (via TempDir Drop)

## Future Extensions

- Webhook server (`Command::Serve`) reusing `run_pipeline`
- Multiple LLM providers (OpenAI, local models via LM Studio)
- Custom rule YAML alongside Semgrep
- GitLab / Bitbucket support
- Slack/Teams notifications for Critical findings
- Dashboard with historical trends
- Feedback loop: learn from dismissed findings
