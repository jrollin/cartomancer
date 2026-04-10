# Cartomancer — Architecture

## Entry Points

```
cartomancer scan <path>                        Local scan, no GitHub
cartomancer review <owner/repo> <pr>           One-shot PR review via CLI
cartomancer history [--branch <name>]          Browse past scan results
cartomancer findings [<scan-id>] [filters]     Browse/search findings
cartomancer dismiss <scan-id> <index>          Dismiss a false positive
cartomancer dismissed                          List dismissed findings
cartomancer undismiss <dismissal-id>           Remove a dismissal
cartomancer serve                              Webhook server (not yet implemented)
```

## Pipeline Stages

```
 1. Prepare       Clone repo or reuse --work-dir
 2. Fetch Meta    GitHub API → PrMetadata (head SHA, base SHA)
 3. Fetch Diff    GitHub API → raw unified diff → PullRequestDiff
 4. Opengrep Scan  subprocess --baseline-commit → Vec<Finding>
 5. Graph Enrich  cartog impact/refs → GraphContext per finding
 6. Escalate      blast radius + domain → adjusted Severity
 7. LLM Deepen    Ollama or Anthropic → analysis text (conditional)
 8. Regression    Compare fingerprints against base branch baseline → new/existing
 9. Dismiss       Filter out dismissed findings by fingerprint match
10. Persist       Write scan record + findings to SQLite (best-effort)
11. Post          GitHub API → PR review (inline comments + summary)
```

Stages 4-7 are shared between `scan` and `review` commands.
Stages 8-9 are review-only. Stage 10 runs for both scan and review.

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
  ▼ opengrep::run_opengrep(--baseline-commit base_sha, --exclude patterns)
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
  ▼ annotate_regression(base_branch baseline fingerprints)
Vec<Finding> (each annotated is_new: true/false)
  │
  ▼ filter_dismissed(dismissed fingerprints from store)
Vec<Finding> (dismissed findings removed)
  │
  ▼ persist_scan() → SQLite .cartomancer.db (best-effort, never blocks)
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
                      ├─▶ opengrep::run_opengrep(--baseline-commit, --exclude)
                      │       └── subprocess: opengrep scan --json
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
                      └─▶ PipelineResult { review, diff, branch, base_branch, temp_dir }
                      │
                   cmd_review() continues:
                      │
                      ├─▶ annotate_regression(base_branch → baseline fingerprints)
                      ├─▶ filter_dismissed(dismissed fingerprints)
                      ├─▶ persist_scan(scan record + findings → SQLite)
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

## Finding Persistence

Scan and review results are persisted to a SQLite database (`.cartomancer.db` by default, configurable via `storage.db_path` in `.cartomancer.toml`).

**Schema** (3 tables): `scans` (scan metadata), `findings` (per-finding data with fingerprint), `dismissals` (false positive suppression). Schema version tracked via `PRAGMA user_version`.

**Fingerprint**: SHA-256 of `rule_id:file_path:snippet_content`. Stable across scans — used for regression detection and dismissal matching. Line numbers excluded because they shift with unrelated edits.

**Regression detection**: During `review`, each finding's fingerprint is compared against the latest scan on the base branch. Findings present in the baseline are marked `is_new: false`; new findings are marked `is_new: true`.

**Dismissal**: Dismissed findings are suppressed by fingerprint match. If the code at a dismissed location changes (different snippet), the fingerprint changes and the finding reappears.

**Best-effort**: All persistence operations are non-blocking. If the DB is unavailable, the pipeline continues and logs a warning (BR-3).

## Concurrency Model

- **tokio** async runtime for GitHub API calls and LLM calls
- **Subprocess** for opengrep (tokio::process::Command)
- **Sync** git clone/checkout (std::process::Command, blocking)
- **Sync** cartog Database access (rusqlite is not Send; access from a single task)
- **Sync** Store access (rusqlite, runs once after pipeline completes)
- Findings enrichment runs sequentially per finding (cartog DB is single-connection)

## Error Handling Strategy

- **Per-finding errors**: logged and skipped (partial results are better than no results)
- **Pipeline-level errors**: fail before posting (clone, opengrep, GitHub API)
- **LLM errors**: logged and skipped (review still posts without LLM analysis)
- **Temp dir cleanup**: always cleaned up, even on failure (via TempDir Drop)
- **Store errors**: logged and skipped — persistence never blocks the pipeline (BR-3)

## Future Extensions

- Webhook server (`Command::Serve`) reusing `run_pipeline`
- Multiple LLM providers (OpenAI, local models via LM Studio)
- Custom rule YAML alongside opengrep
- GitLab / Bitbucket support
- Slack/Teams notifications for Critical findings
- Dashboard / web UI for trend visualization over stored scan history
- Retention policies (pruning old scans)
- Feedback loop: learn from dismissed findings
