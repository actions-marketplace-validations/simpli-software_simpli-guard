> Part of **Simpli Gatehouse**, the review and security gates from Simpli Software.
> Its sibling, [simpli-software/simpli-review](https://github.com/simpli-software/simpli-review), reviews every pull request with whole-codebase context.

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

## Quick setup

From the root of the repository you want to scan:

```bash
pipx install git+https://github.com/simpli-software/simpli-guard
simpli-guard init
```

Prefer a form? The [Simpli Gatehouse config builder](https://simpli-software.github.io/simpli-gatehouse/) builds the same files in your browser, pinned to the latest release.

`init` asks a few questions (press Enter to accept each default) and then writes
`.github/workflows/security-scan.yml` and `.simpli-guard/config.json`. The config holds only the settings
you changed from the defaults, so a default setup writes `{}`. It looks up the latest release of this
project through the public GitHub API and pins the action to that release's commit hash with the tag in a
comment. If you are offline, or the lookup fails, it writes the `<commit-sha> # v1.x` placeholder and prints
how to fill it in. A token is sent to the API only if `GITHUB_TOKEN` or `GH_TOKEN` is set.

It asks for:

- the heading used on comments, issues and reports (default `Security scan`);
- the severity that fails a PR (`critical`, `high` or `medium`; default `high`);
- categories to turn off, including `actions` (zizmor);
- live-surface URLs to check nightly (optional, `https` only);
- whether to use Claude triage (default on; needs the `ANTHROPIC_API_KEY` secret) and which model;
- extra test paths, prefilled from test folders it finds that are not already recognised as tests;
- the nightly run time in UTC (default `03:17`);
- whether to also write the aggregate workflow (default no; it belongs in a private repository and needs
  a `repos.json` and the `GUARD_READ_TOKEN` secret, see [below](#the-guard_read_token-aggregate-mode)).

If triage is on and the GitHub CLI (`gh`) is installed, it checks that the `ANTHROPIC_API_KEY` secret exists
for the repository or its organization, by name only (it never reads or sets a value), and prints the
`gh secret set` command if it is missing. It ends with a checklist of next steps, including how to ignore a
finding.

| Flag | Effect |
|---|---|
| `--yes`, `--non-interactive` | Take every default, ask nothing. |
| `--force` | Overwrite files that already exist. Without it nothing is overwritten: a short diff is shown and the file is skipped. |
| `--dry-run` | Show what would be written; write nothing. |
| `--ref <owner/repo@sha>` | Pin this commit instead of looking up the latest release. Add `#<tag>` to set the comment. |
| `--root <dir>` | The repository root (default: the current directory). |

The files are written with LF line endings. Review them, commit them to the default branch, and open a
pull request to see the first scan.

## Add it to a repository (by hand)

1. Copy [`examples/security-scan.yml`](examples/security-scan.yml) to
   `.github/workflows/security-scan.yml`.
2. Optional: add the `ANTHROPIC_API_KEY` secret (repo or org) to turn on Claude triage.
3. Optional: add `.simpli-guard/config.json` - see
   [`examples/config/example.json`](examples/config/example.json) (it sets the live URLs for
   the surface checks).

In `examples/security-scan.yml` the action is referenced as
`simpli-software/simpli-guard@<commit-sha> # v1.x`. The hash is a placeholder on purpose: replace
`<commit-sha>` with the full commit hash of the release you want, keeping the tag in the comment. A tag or branch reference is flagged as unpinned by the workflow scan
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
  "testPaths": ["qa/**"],
  "overrideLabel": "security-override"
}
```

`overrideLabel` (default `security-override`) is the pull request label a maintainer sets to apply
suppressions the PR itself adds; see [Where settings come from](#where-settings-come-from).

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
It also lists the [suppressions the PR adds](#where-settings-come-from) and any change the PR makes to the
scan settings files.

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
calls. `simpli-guard local --base origin/main --no-triage`. It previews with the settings in your
working tree (CI reads them from the base branch) and has no labels, so a PR-added inline ignore on a
finding at or above `failOn` is reported as not applied.

## Where settings come from

A pull request must not be able to approve its own findings. In `pr` mode the settings that decide
what fails are therefore read from the **base commit** (the branch the PR targets), never from the PR:

| Setting | PR mode reads it from |
|---|---|
| `.simpli-guard/config.json` (`failOn`, `ignore`, `categories`, `testPaths`, `triage`, `overrideLabel`) | base commit |
| `.gitleaksignore`, `.gitleaks.toml` | base commit (gitleaks runs in the base checkout over the PR's commits) |
| Inline `# simpli-guard: ignore <rule> <reason>` comments | the PR head; only ignores that already exist on the base apply freely (below) |
| Inline `gitleaks:allow` comments | not honoured in PR scans unless the override label is set |
| Override label | the PR's labels (from the event payload); the label name comes from the base config |

If the base commit cannot be checked out (for example a shallow clone), the job **fails** with a clear
message instead of scanning with the PR's own settings. Use `fetch-depth: 0`. A repository with no config
on the base uses the defaults, so the PR that first adds `.simpli-guard/config.json` takes effect after
it merges. `nightly` and `aggregate` run on the default branch and read its files as before.

**Suppressions added in the PR.** An inline ignore counts as added by the PR when the PR head has more
copies of that exact comment (same file, same rule, same reason) than the base has, so copying an
existing comment onto a new line does not launder it. Such an ignore:

- does **not** suppress a finding at or above `failOn`; the finding still counts and fails the job, and
  the comment lists it under *Suppressions added in this PR (not applied)*;
- applies when a maintainer sets the override label (`security-override`, or `overrideLabel` in the base
  config). Only people with triage access can label a PR. The workflow must run on `labeled` and
  `unlabeled` (the [example](examples/security-scan.yml) does) so the scan re-runs when the label changes;
  a plain "re-run" reuses the old labels;
- applies normally below `failOn`, and is still listed (*applied*) so a reviewer sees it.

**Changes to the settings files.** If the PR changes `.simpli-guard/config.json`, `.gitleaksignore` or
`.gitleaks.toml`, the comment lists them and says they apply after merge. Add them to CODEOWNERS so a
maintainer reviews them.

**Not covered.** The other scanners' own ignore mechanisms (zizmor's `# zizmor: ignore` comments and
`zizmor.yml`, `# nosem`, `.trivyignore`, osv-scanner's config) are still read from the PR head. Protect
those paths with CODEOWNERS as well.

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
   (e.g. `eval-detected`). A comment without a reason is ignored. In a PR, an ignore the PR itself
   adds does not silence a finding at or above `failOn` (see
   [Where settings come from](#where-settings-come-from)).
3. In config: `ignore` by `id` (fingerprint, shown in reports and issues), `rule` or
   `path` glob, always with a `reason`, optionally `expires` (ISO date) - expired
   entries stop applying and the finding comes back.
4. For secrets, gitleaks' own `.gitleaksignore` / `.gitleaks.toml` in the repo are honoured (in PR
   scans, the base branch's copies).
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

Best effort, no SLA. Issues are welcome (bug reports and feature requests, using the templates). To
report a vulnerability, see [SECURITY.md](SECURITY.md) and do not open a public issue.

Pull requests: until 2027-01-18 (90 days after the 2026-10-20 public launch) this project takes issues only, and outside
pull requests are not accepted yet. After that they are accepted with a Developer Certificate of Origin
sign-off on every commit (`git commit -s`, see <https://developercertificate.org>) and no CLA. CI on fork
pull requests runs on `pull_request` without secrets, workflows never use `pull_request_target`, a
maintainer approves CI runs for first-time contributors, and every outside pull request gets a senior
security review before merge, because the action runs inside your CI with your API keys. Details are in
[CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT, see [LICENSE](LICENSE). Built by Simpli Software.
