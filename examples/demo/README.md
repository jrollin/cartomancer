# Demo fixture

Small vulnerable Flask-style app used to record the README demo GIF.

## Contents

- `fixture/src/` — 5 Python files with seeded issues
- `fixture/.cartog.db` — pre-indexed code graph (regenerate with `cartog index`)
- `fixture/.cartomancer.toml` — minimal config (no LLM deepening)
- `demo.tape` — VHS recipe that produces `docs/assets/demo.gif`

## Regenerate

```bash
cargo build --release --bin cartomancer
cartog index --db examples/demo/fixture/.cartog.db examples/demo/fixture
vhs examples/demo/demo.tape
```
