# Contributing

## Issues, not pull requests (for now)

Bug reports and feature requests are welcome as issues; please use the templates.
**Pull requests are not accepted for now.** This may change; this file will say so when it does.
Security problems go through [SECURITY.md](SECURITY.md), not a public issue.

Support is best effort, with no SLA.

## Running the checks locally

This is useful when you work on a fork. You need Python 3.12 and [uv](https://docs.astral.sh/uv/).

```
uv venv --python 3.12
uv pip install -e ".[dev]"
ruff check .
ruff format --check .
mypy src
pytest -q --tb=short
```

All four must pass; CI runs the same commands. The tests use recorded scanner output in
`tests/fixtures/`, so they need no network access and no scanner binaries.

## Conventions

- Secret values are never logged, printed or stored; findings carry a masked prefix only.
- Scanner binaries are pinned by version and SHA-256.
- Every `uses:` in a workflow is pinned by full commit hash with a version comment.
