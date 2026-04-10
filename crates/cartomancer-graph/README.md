# cartomancer-graph

[cartog](https://crates.io/crates/cartog) integration and severity escalation for the [Cartomancer](https://github.com/jrollin/cartomancer) PR review pipeline.

## Components

- `CartogEnricher` — wraps cartog's SQLite database to enrich findings with blast radius, callers, domain tags, and public API visibility
- `SeverityEscalator` — escalates finding severity based on blast radius thresholds and domain detection (auth, payment flows)

## Usage

This crate is used internally by the cartomancer binary. It is not intended for direct use.

## License

MIT
