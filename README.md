# simpli-guard

Security scanning for your own repositories and domains, run as a GitHub Action:
code (SAST), dependencies, secrets, IaC/config, GitHub Actions workflows, container images, licenses and the
live attack surface of your sites, with the noise taken out before anyone sees it.

It is built from free open-source scanners plus an optional Claude triage step, and
designed around one rule: a pull request is judged only on the findings it introduces.
[docs/HOW_IT_WORKS.md](docs/HOW_IT_WORKS.md) describes the pipeline, the noise-reduction
rules, and what is deliberately not built.

| Category | Scanner (pinned) | PR | Nightly |
|---|---|---|---|
| Code (SAST), Python + JS/TS security rules | Opengrep v1.30.1 + opengrep-rules | yes | yes |
| Dependencies (uv.lock, requirements*.txt, poetry.lock, package-lock.json, pnpm-lock.yaml) | osv-scanner v2.6.0 + CISA KEV | yes | yes |
| Secrets | gitleaks v8.30.1 | commits in the PR | full history |
| IaC / config (Dockerfile, compose, Kubernetes) | Trivy v0.75.0 `config` | yes | yes |
| GitHub Actions workflows (`.github/workflows`, `action.yml`): injection, `pull_request_target`, unpinned actions, `permissions`, credential persistence | zizmor v1.31.1, offline | yes | yes |
| Container images built from your Dockerfiles | Trivy `image` | - | yes |
| Licenses (strong copyleft) | Trivy `fs --scanners license` | - | yes |
| Live surface (TLS, headers, cookies, exposed files) | built-in, read-only | - | yes |

Scanner binaries are downloaded from their GitHub releases at the pinned version and
checked against a pinned SHA-256 before use. If one can't be fetched, that scanner is
skipped with a warning; the rest still run.

## Add it to a repository

1. Copy [`examples/security-scan.yml`](examples/security-scan.yml) to
   `.github/workflows/security-scan.yml`.
2. Optional: add the `ANTHROPIC_API_KEY` secret (repo or org) to turn on Claude triage.
3. Optional: add `.simpli-guard/config.json` - see
   [`examples/config/example.json`](examples/config/example.json) (it sets the live URLs for
   the surface checks).

In `examples/security-scan.yml` the action is referenced as
`<owner>/<repo>@<commit-sha> # v1.x`. That is a placeholder on purpose: replace it with the
repository that hosts this action and the full commit hash of the release you want, keeping the
tag in the comment. A tag or branch reference is flagged as unpinned by the workflow scan
(zizmor) this tool itself runs, and a commit hash cannot be moved after the fact.

The workflow checks out with `fetch-depth: 0`: PR mode checks the base commit out
into a temporary `git worktree` and scans it too, and nightly needs full history for
the secrets scan.

### Config (`.simpli-guard/config.json`, every key optional)

```json
{
  "name": "Security scan",
  "failOn": "high",
  "categories": {"license": false, "actions": true},
  "surface": {"urls": ["https://app.example.com"]},
  "ignore": [
    {"rule": "python.lang.security.audit.subprocess-shell-true", "reason": "fixed command list", "expires": "2027-01-31"},
    {"id": "3f1c0a9e2b7d4c55a1e0f2b3", "reason": "accepted: internal-only admin tool"},
    {"path": "scripts/**", "reason": "local dev scripts, never deployed"}
  ],
  "triage": {"enabled": true, "model": "claude-sonnet-5-5", "effort": "medium", "maxFindings": 60},
  "testPaths": ["qa/**"]
}
```

`name` is the heading on comments, issues and reports (no product name is hard-coded).

## Modes

**`pr`** (pull_request): runs SAST, dependencies, secrets (only the PR's commits) and
config and Actions workflows on the PR head and on the base commit. A finding is *new* when its fingerprint
is not on the base. Fingerprints never include line numbers, so moving code doesn't
make old findings look new. The job fails only when a new, unsuppressed finding is at
or above `failOn` (default `high`). One PR comment (updated in place) lists new
findings by severity with file:line links, the suppressed ones with their reasons
(collapsed), and a count of pre-existing findings; the same goes to the job summary.
With no new findings the comment shrinks to one line (or is never posted).

**`nightly`** (schedule / manual): everything above plus full-history secrets,
`docker build` + `trivy image` for each Dockerfile (a failed build is skipped),
licenses and the live surface checks. Writes `simpli-guard-report.json` and
`simpli-guard-report.md`, uploaded as the `simpli-guard-report` artifact. Each new
critical/high finding gets one issue labelled `security` (the label is created if
missing); when a finding disappears its issue gets a comment and is closed. State is
the issues themselves (a hidden fingerprint marker), nothing else.
Closing an issue as *not planned* means "accepted" - it is never reopened.

**`aggregate`** (optional, in a private repository of your own, daily): reads a `repos.json`
in the workspace (start from [`examples/repos.example.json`](examples/repos.example.json)),
downloads each repo's latest successful `simpli-guard-report` artifact and commits
`reports/README.md` (one overview table) and `reports/<repo>.md`. Copy
[`examples/aggregate.yml`](examples/aggregate.yml) to `.github/workflows/aggregate.yml` in that
repository. The reports list your security findings, so never run this mode in a public repository.

**`local --base <ref>`**: PR mode on your machine, printed to the terminal, no GitHub
calls. `simpli-guard local --base origin/main --no-triage`.

## The GUARD_READ_TOKEN (aggregate mode)

Create a fine-grained personal access token (GitHub > Settings > Developer settings >
Fine-grained tokens):

- Resource owner: the account that owns the scanned repos; Repository access: *Only select
  repositories* - the repos in your `repos.json`.
- Permissions: **Actions: Read-only**, **Contents: Read-only** (Metadata: Read-only is
  added automatically). Nothing else.
- Store it as the `GUARD_READ_TOKEN` secret in the repository that runs the aggregate workflow.
  The workflow pushes the reports with its own `GITHUB_TOKEN` (`contents: write` on that repo only).

## Ignoring a finding

In order of preference:

1. Fix it.
2. Inline, for a code finding: `# simpli-guard: ignore <rule_id> <reason>` (or `//`)
   on the flagged line or the line above. The rule id can be the full id or its tail
   (e.g. `eval-detected`). A comment without a reason is ignored.
3. In config: `ignore` by `id` (fingerprint, shown in reports and issues), `rule` or
   `path` glob, always with a `reason`, optionally `expires` (ISO date) - expired
   entries stop applying and the finding comes back.
4. For secrets, gitleaks' own `.gitleaksignore` / `.gitleaks.toml` in the repo are honoured.
5. For Actions workflow findings, zizmor's own `# zizmor: ignore[template-injection]` comment on
   the flagged line and a `zizmor.yml` / `.github/zizmor.yml` in the repo are honoured; config
   `ignore` entries work too (`"rule": "template-injection"`; the full id is `zizmor.template-injection`).

Suppressed findings are never dropped silently: reports list them with who suppressed
them (`rule`, `claude`) and why.

## Claude triage and cost

The scanners are free. Triage is optional (on when `ANTHROPIC_API_KEY` is set and
`triage.enabled` isn't false) and looks only at high/critical SAST and secret findings
that survived the rules above, at most 20 per run, in one request. Claude sees each
code finding with ~60 lines of context (credential-shaped strings scrubbed) and each
secret only as path + masked prefix + whether it's a test/fixture file - never the
value. It can suppress a finding only with `not_exploitable` at confidence 4-5, and the
reason is shown. If the API fails, every finding is kept. With the default
`claude-sonnet-5-5` at medium effort a run typically costs a few cents; token usage is
logged on every run.

## Privacy rules it follows

- Secret values are reduced to a masked prefix (`sk_l…`) the moment gitleaks' report is
  parsed; the raw report is deleted. No log, comment, issue, report or prompt contains more.
- Scanner stdout is discarded; only scrubbed last lines of stderr appear on failure.
- Surface checks send plain GETs with `User-Agent: simpli-guard`, no credentials, no
  cookies, sequentially, and never copy response bodies into findings.
- Only run it against repositories and domains you own.

## Development

```
uv venv --python 3.12 && uv pip install -e ".[dev]"
ruff check . && ruff format --check . && mypy src && pytest -q
```

## Compared with commercial scanners

Commercial application-security platforms usually combine several things this project does not:
a hosted dashboard and account system, runtime protection inside the running app, call-graph
reachability analysis, automatic fix pull requests, cloud-account posture checks and host
scanning. This project is none of those. It is a CI-side scanner:

| | This project |
|---|---|
| Where it runs | Your own GitHub Actions runners (and your machine, with `local`). No hosted service, no account. |
| What leaves your repository | Package names and versions from your lockfiles go to the public OSV API (osv-scanner's default online mode). With triage on, code excerpts (credential-shaped strings scrubbed) and masked secret prefixes go to the Anthropic API. Nothing else. Scanner binaries, rules, vulnerability databases and the CISA KEV feed are downloaded, not uploaded. |
| Scanners | Open-source tools pinned by version and SHA-256 (see [Third-party software](#third-party-software-and-licenses)). |
| Cost | The Actions minutes you already pay for, plus a few cents per run if you turn triage on. |
| Gating | A PR fails only for findings it introduced. Existing findings are reported, never blocking. |
| Not included | Runtime protection, reachability analysis, auto-fix PRs, cloud posture, host scanning, hosted dashboard. See [docs/HOW_IT_WORKS.md](docs/HOW_IT_WORKS.md#deliberately-not-built). |

## Third-party software and licenses

This repository contains only its own code, under the MIT license. It downloads the following
at run time and never vendors, bundles or redistributes any of it. Each one keeps its own license,
which you accept by running it. Licenses below were read from each project's `LICENSE` file at the
pinned version.

| Component | Pinned | License |
|---|---|---|
| [gitleaks](https://github.com/gitleaks/gitleaks) | v8.30.1 | MIT |
| [Trivy](https://github.com/aquasecurity/trivy) | v0.75.0 | Apache-2.0 |
| [osv-scanner](https://github.com/google/osv-scanner) | v2.6.0 | Apache-2.0 |
| [zizmor](https://github.com/zizmorcore/zizmor) | v1.31.1 | MIT |
| [Opengrep](https://github.com/opengrep/opengrep) | v1.30.1 | LGPL-2.1 |
| [opengrep-rules](https://github.com/opengrep/opengrep-rules) | commit `f1d2b562b414` | LGPL-2.1 with the Commons Clause License Condition v1.0 |

**About opengrep-rules.** Its `LICENSE` at the pinned commit applies LGPL-2.1 to the
semgrep-rules rule set (licensor: Semgrep, Inc.) together with the Commons Clause, which removes the
right to "Sell" the software. "Sell" is defined there as providing a third party, for a fee or other
consideration (including hosting, consulting or support fees), a product or service whose value
derives entirely or substantially from the rules' functionality. Running the rules in your own CI
against your own code is not that. Offering a paid scanning product or service built on those rules
may be, so read the license before doing so. This is not legal advice.

Only the Python, JavaScript and TypeScript rules in the `security` category are used. They are
fetched from the upstream repository at the pinned commit into a local cache on the machine that
runs the scan, with the rule ids rewritten to dotted paths; they are not stored in or published
from this repository.

The vulnerability data, the CISA Known Exploited Vulnerabilities catalogue and the Trivy
databases are fetched at run time from their publishers and are subject to their terms.

## Support

Best effort, no SLA. Issues are welcome (bug reports and feature requests, using the templates).
Pull requests are not accepted for now; see [CONTRIBUTING.md](CONTRIBUTING.md). To report a
vulnerability, see [SECURITY.md](SECURITY.md) and do not open a public issue.

## License

MIT, see [LICENSE](LICENSE). Built by Simpli Software.
