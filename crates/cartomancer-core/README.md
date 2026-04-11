# cartomancer-core

Pure domain model types for the [Cartomancer](https://github.com/jrollin/cartomancer) PR review pipeline.

No I/O, no async — just types, validation, and serialization.

## Key Types

- `Finding` — opengrep finding with optional graph context, LLM analysis, suggested fix, and agent prompt
- `GraphContext` — blast radius, callers, domain tags from cartog
- `Severity` — Info < Warning < Error < Critical (with `Ord`, `Display`, `FromStr`)
- `AppConfig` — deserialized from `.cartomancer.toml`
- `ReviewResult` — final output posted to GitHub
- `DiffChunk` / `PullRequestDiff` — parsed unified diff representation

## Usage

This crate is used internally by the other cartomancer crates. It is not intended for direct use.

## License

MIT
