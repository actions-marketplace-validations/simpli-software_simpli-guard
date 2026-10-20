# Contributing

## Issues first, outside pull requests later

Bug reports and feature requests are welcome as issues; please use the templates. Security problems
go through [SECURITY.md](SECURITY.md), not a public issue.

**Launch policy.** This project went public on 2026-10-20. Until 2027-01-18 (90 days) it takes
issues only: outside pull requests are not accepted yet and may be closed without review.

**After that,** pull requests are accepted under the Developer Certificate of Origin (DCO). Sign off
every commit with `git commit -s`, which adds a `Signed-off-by: Your Name <your@email>` line. By
signing off you certify the terms at <https://developercertificate.org>. There is no CLA to sign.

**How outside pull requests are handled.** This action runs inside other people's CI with their API
keys, so contributions get extra care:

- CI on pull requests from forks runs on the `pull_request` event, without secrets.
- Workflows in this repository never use `pull_request_target`.
- A maintainer approves CI runs for first-time contributors before they start.
- Every outside pull request gets a senior security review before it is merged.

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
