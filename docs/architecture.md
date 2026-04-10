# Cartomancer — Architecture

## Pipeline Stages

```
1. Fetch Diff       GitHub API → PullRequestDiff
2. Semgrep Scan     subprocess → Vec<Finding>
3. Graph Enrich     cartog impact/refs → GraphContext per finding
4. Escalate         blast radius + domain → adjusted Severity
5. LLM Deepen       Ollama or Anthropic → analysis text (conditional)
6. Post Comments    GitHub API → inline + summary comments
```

## Data Flow

```
PullRequestEvent (webhook payload)
  │
  ▼
PullRequestDiff (parsed unified diff)
  │
  ▼
Vec<Finding> (from semgrep --json --baseline-commit)
  │
  ▼ CartogEnricher.enrich_batch()
Vec<Finding> (with GraphContext: blast_radius, callers, domain_tags)
  │
  ▼ SeverityEscalator.escalate_batch()
Vec<Finding> (severity adjusted based on graph context)
  │
  ▼ LlmProvider.deepen() — only if severity >= threshold AND blast_radius > 3
Vec<Finding> (with llm_analysis text)
  │
  ▼
ReviewResult (findings + summary, ready for posting)
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

Default `blast_radius_threshold` = 5 (configurable in `.cartomancer.yaml`).

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

## Sequence Diagram

```
GitHub ──webhook──▶ Axum Server
                      │
                      ▼
                   pipeline::run_pipeline()
                      │
                      ├─▶ GitHubClient.fetch_diff()
                      │       └── GET /repos/:owner/:repo/pulls/:pr.diff
                      │
                      ├─▶ semgrep::run_semgrep()
                      │       └── subprocess: semgrep scan --json --baseline-commit
                      │
                      ├─▶ CartogEnricher.enrich_batch()
                      │       ├── db.outline()   → resolve symbol at line
                      │       ├── db.impact()    → blast radius
                      │       ├── db.refs()      → callers
                      │       └── detect_domain_tags()
                      │
                      ├─▶ SeverityEscalator.escalate_batch()
                      │       └── threshold checks → severity upgrade
                      │
                      ├─▶ LlmProvider.deepen() (conditional)
                      │       └── POST /api/chat or /v1/messages
                      │
                      └─▶ GitHubClient.post_review()
                              ├── POST inline comments
                              └── POST summary comment
```

## Concurrency Model

- **tokio** async runtime for HTTP server, GitHub API calls, and LLM calls
- **Subprocess** for Semgrep (tokio::process::Command)
- **Sync** cartog Database access (rusqlite is not Send; access from a single task)
- Findings enrichment runs sequentially per finding (cartog DB is single-connection)

## Error Handling Strategy

- **Per-finding errors**: logged and skipped (partial results are better than no results)
- **Pipeline-level errors**: fail the entire review (GitHub API down, semgrep binary missing)
- **LLM errors**: logged and skipped (review still posts without LLM analysis)

## Future Extensions

- Multiple LLM providers (OpenAI, local models via LM Studio)
- Custom rule YAML alongside Semgrep
- GitLab / Bitbucket support
- Slack/Teams notifications for Critical findings
- Dashboard with historical trends
- Feedback loop: learn from dismissed findings
