## [0.8.0] - 2026-04-17

### 🚀 Features

- *(cli,doctor)* Replace --format with global --json flag, structured doctor report
- Cartomancer init, scan JSON envelope, expanded doctor checks (#17)

### 📚 Documentation

- Update docs and site for global --json flag and v0.7.0

### 🧪 Testing

- Raise patch coverage on init, emit_scan_output, persist_scan, doctor (#18)

### ⚙️ Miscellaneous Tasks

- Bump version to 0.8.0
## [0.7.0] - 2026-04-13

### 🚀 Features

- *(pipeline,graph)* Granular resume, batch enrichment, configurable cartog path

### 🐛 Bug Fixes

- *(graph,pipeline,config)* Address PR review findings

### 📚 Documentation

- Add GitHub Pages site and rewrite README for developer impact

### ⚙️ Miscellaneous Tasks

- Bump version to 0.7.0
## [0.6.0] - 2026-04-12

### 🚀 Features

- Add custom opengrep rules and company knowledge base for LLM deepening

### 🐛 Bug Fixes

- *(store,github,llm)* Replace panicking constructors with Result, add integration tests
- *(llm,test)* Log knowledge file read errors, use correct snippet_hash in test

### 📚 Documentation

- *(readme)* Add crates.io, docs.rs, and MSRV badges
- *(readme)* Remove docs.rs badge

### ⚙️ Miscellaneous Tasks

- Bump version to 0.6.0
## [0.5.0] - 2026-04-11

### 🚀 Features

- *(llm)* Add suggested fixes, agent prompts, and categorized review comments
- *(serve)* Add webhook server, config validation, and pipeline decomposition
- *(cli)* Add doctor command to check dependencies and config health

### 🐛 Bug Fixes

- *(llm)* Line-aware fence parsing, idempotent migration, and review parity
- *(review)* Address all PR review findings
- *(config)* Enforce Anthropic max_tokens upper bound (1..=128000)
- *(pipeline)* Persist failure metadata, defer completed, filter empty tokens
- *(pipeline)* Validate scan metadata before resuming
- *(doctor)* Address PR review findings, fix README binary name

### 📚 Documentation

- *(doctor)* Add docstrings to meet 80% coverage threshold

### 🧪 Testing

- *(coverage)* Add mock provider deepen test and resumable migration test
- *(llm)* Add wiremock HTTP tests, store round-trip, and max_tokens validation
- *(coverage)* Add tests for PipelineStage, stored_to_findings, and store methods
- *(coverage)* Add tests for prepare_review_payload, semaphore 503, schema v4

### ⚙️ Miscellaneous Tasks

- *(deps)* Bump codecov/codecov-action from 5 to 6
- *(deps)* Bump actions/download-artifact from 4 to 8
- *(deps)* Bump actions/upload-artifact from 4 to 7
- *(deps)* Bump actions/checkout from 5 to 6
- Bump version to 0.5.0
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
