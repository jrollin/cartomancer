## [Unreleased]

### 🚀 Features

- *(llm)* LLM deepening now requests suggested fixes as ```diff blocks alongside impact analysis
- *(llm)* Add response parser (`parse_llm_response`) to split analysis from fix using fence detection
- *(llm)* Add agent prompt generation (`build_agent_prompt`) — self-contained instructions for AI tools
- *(llm)* Truncate enclosing context to 2000 chars (UTF-8 safe) to bound token usage
- *(comment)* Classify findings as Actionable (has fix OR severity >= Error) or Nitpick
- *(comment)* Inline comments include category label, collapsible suggested fix, and collapsible agent prompt
- *(comment)* Off-diff findings posted with `[!CAUTION]` banner and file:line location
- *(comment)* PR summary includes actionable count header, category breakdown, and collapsible off-diff listing
- *(comment)* Escape triple backticks in fenced code blocks to prevent markdown injection
- *(store)* v3 schema migration: `suggested_fix` and `agent_prompt` columns in findings table
- *(pipeline)* `PipelineResult` includes `scan_duration` and `rule_count` for summary regeneration
- *(server)* Extract `prepare_review_payload` for off-diff splitting and summary regeneration

## [0.4.0] - 2026-04-10

### 🚀 Features

- *(store)* Add cartomancer-store crate with SQLite persistence layer
- *(store)* Wire persistence, regression detection, and dismissal filtering into pipeline
- *(store)* Add CLI commands for history, findings, dismiss, and update docs
- *(opengrep)* Add taint analysis, enclosing context, dynamic timeout, and ignore pattern

### 🐛 Bug Fixes

- *(store)* Harden fingerprint hashing, schema migration, and error handling

### 🚜 Refactor

- *(scanner)* Replace Semgrep CLI with opengrep/opengrep

### 📚 Documentation

- *(store)* Add README for cartomancer-store crate
- *(readme)* Add CI, coverage, and license badges

### ⚙️ Miscellaneous Tasks

- Bump version to 0.4.0
## [0.3.2] - 2026-04-10

### 🚀 Features

- *(llm)* Add health check before pipeline runs
- *(llm)* Concurrent finding deepening with configurable concurrency

### ⚙️ Miscellaneous Tasks

- *(deps)* Add Dependabot for Cargo and GitHub Actions updates
- Bump version to 0.3.2
## [0.3.1] - 2026-04-10

### 🚀 Features

- *(semgrep)* Add exclude patterns config option
- *(cli)* Add --version flag
- *(semgrep)* Add jobs config option, refactor run_semgrep signature

### ⚙️ Miscellaneous Tasks

- Bump version to 0.3.1
## [0.3.0] - 2026-04-10

### ⚙️ Miscellaneous Tasks

- Rename binary crate to cartomancer, add crate READMEs
- Bump version to 0.3.0
## [0.2.0] - 2026-04-10

### 🚀 Features

- Bootstrap Cartomancer project with working scan pipeline
- *(review)* Implement PR review pipeline with GitHub API integration

### 🐛 Bug Fixes

- *(core)* Redact secrets in Debug/Serialize, fix arithmetic bug and CI versions

### 🚜 Refactor

- *(core)* Improve code quality, add tests, wire missing features

### 📚 Documentation

- Fix stale references and gitignore feature specs

### ⚙️ Miscellaneous Tasks

- *(release)* Add release script and publish workflow
- Bump version to 0.2.0
