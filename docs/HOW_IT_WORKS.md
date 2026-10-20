# How simpli-guard works

This page describes the pipeline, the rules that cut noise, what each scanner category covers, and
what is deliberately out of scope.

## Pipeline

```
scanners (pinned, checksum-verified)        noise reduction                      output
-----------------------------------         -----------------------------        ----------------------------
opengrep  -> SAST findings      \           1. severity rules                   pr:      new vs base -> one PR
osv       -> dependency vulns    \             test code -1, dev deps -1,                comment + exit code
gitleaks  -> secrets (masked)     >-------->   CISA KEV +1                       nightly: report artifact +
trivy     -> IaC, images, licenses           2. dedupe by fingerprint                    issues opened/closed
zizmor    -> Actions workflows
surface   -> TLS, headers, files  /         3. config ignores (reason, expiry)  aggregate: reports/ in your
                                            4. inline ignores                            own repo
                                            5. Claude triage (optional)
```

Every scanner output is parsed into one `Finding` model (`src/simpli_guard/models.py`).
Its `id` is a fingerprint with no line numbers:

- code, IaC, Actions workflows, secrets, surface: sha256(tool, rule id, path, whitespace-normalized snippet).
  For secrets the "snippet" is the masked prefix plus the value's length, never the value.
- dependencies and image packages: sha256(package, version, vulnerability id), with the id
  normalized to a CVE where one exists. Tool and lockfile path are left out on purpose, so
  osv-scanner and Trivy reporting the same advisory dedupe to one finding.

Because ids survive edits that move code, PR mode can compare head and base by id, and
nightly issues can follow a finding across commits.

### PR mode: "new" findings

The PR head is scanned in the workspace; the base commit is checked out with
`git worktree add --detach` and scanned with the same scanners (secrets excepted: gitleaks
only scans the PR's `base..head` commits, so everything it finds is new by definition).
New = head ids not present on the base. If a scanner ran on head but failed on the base,
its findings are listed as pre-existing (with a note) rather than failing the PR on
findings it may not have introduced. The job exits 1 only when a new, unsuppressed finding
is at or above `failOn`.

### Where settings come from

In PR mode the base commit is the trust anchor. `analyse_pr` is given the base checkout first and
everything that can suppress or relax a result is taken from it:

- `.simpli-guard/config.json` is loaded from the base checkout (`load_config(base_root)`). A missing file
  means defaults; an unreadable or invalid one stops the job. If the worktree cannot be created the job
  exits 2 before any scan: there is no fallback to the PR head.
- gitleaks runs with the base checkout as its working directory and the PR's commit range
  (`base..head`) as `--log-opts`. The range is resolved in the shared object store, while gitleaks
  discovers `.gitleaks.toml` and `.gitleaksignore` next to its working directory, so it only ever sees the
  base copies. `--ignore-gitleaks-allow` is passed unless the override label is set.
- Inline simpli-guard ignores are read from the head files, then each is compared with the same file on
  the base: the (rule, reason) pair is counted on both sides, and if the head has more copies than the base
  every finding relying on that pair is treated as added by the PR. An added ignore on a finding at or
  above `failOn` is left unapplied (the finding stays kept, with a note); with the override label it is
  applied; below `failOn` it is applied. All three cases are listed in the PR comment.
- The override label is matched (case-insensitively) against the labels in the `pull_request` event
  payload. Its name is the base config's `overrideLabel`, default `security-override`.
- `git diff --name-only base...head` over the three settings files produces the "Scan settings changed in
  this PR" notice.

`local` mode keeps reading the working tree's config (it is a preview, there is nothing to defend), and
`nightly` and `aggregate` read the default branch they run on. Scanner-native ignore mechanisms other than
gitleaks' are still read from the PR head; see the README for the CODEOWNERS advice.

### Nightly mode: issues as state

Each issue body carries `<!-- simpli-guard:finding:<id> tool=<tool> -->`. The nightly run
lists `security`-labelled issues and:

- opens an issue for each kept critical/high finding without an open one (max 20 per run);
- leaves issues a human closed as *not planned* alone (accepted risk);
- opens a fresh issue if a finding returns after its issue was closed as completed;
- comments on and closes open issues whose finding is gone - only when that finding's
  scanner actually ran this time, so a failed download never closes anything.

## What it covers

| Capability | How | Notes |
|---|---|---|
| Code scanning (SAST) | Opengrep + opengrep-rules (Python, JavaScript, TypeScript), security category only | Style/correctness rules are not loaded. Test code is one level lower. Inline and config ignores. |
| Dependency scanning | osv-scanner over lockfiles; fixed version shown | Severity from CVSS; dev-only deps one level lower. |
| Exploited-in-the-wild prioritisation | CISA KEV catalogue: +1 severity | Cached daily; failure means no bump, never a crash. |
| Secret detection | gitleaks; PR range or full history; repo's `.gitleaks.toml`/`.gitleaksignore` honoured | Values masked at parse time. |
| IaC / config scanning | `trivy config` (Dockerfile, compose, Kubernetes, Terraform if present) | |
| Workflow / CI security | zizmor v1.31.1, run `--offline` with no token over `.github/workflows`, `.github/actions` and `action.yml`; PR and nightly | High/medium/low map straight across, one level lower at low confidence. zizmor's `# zizmor: ignore[rule]` comments and `zizmor.yml` honoured. Fingerprint = job + flagged text, no line or step index. Not sent to Claude triage (the prompt is built for code and secrets). |
| Container image scanning | nightly `docker build` + `trivy image` per Dockerfile, incl. end-of-life base OS | Build failures are skipped. |
| License scanning | `trivy fs --scanners license`; strong copyleft (GPL/AGPL) medium, other restricted/reciprocal info | Permissive licenses are not findings. |
| Live surface monitoring (lightweight, read-only) | HTTPS, certificate validity and expiry (<21 days high, <7 critical), TLS >= 1.2, HTTP->HTTPS redirect, HSTS (>= 180 days), CSP, nosniff, framing protection, Referrer-Policy, cookie flags, version banners, exposed `.env`/`.git`/dumps/compose/server-status, public API docs | GET only, sequential, no credentials. A path counts as exposed only if the body looks like the real file, so SPA catch-alls don't trigger. |
| Noise reduction | rule-based reduction, then optional Claude triage of high/critical SAST + secrets | Suppresses only with confidence >= 4; reasons are shown; fails open. |
| Deduplication across scanners | fingerprint-based | |
| PR gating | `failOn` threshold on new findings only | Pre-existing debt never blocks a PR. |
| Issue tracker integration | GitHub issues, auto-closed when fixed | |
| Overview across repositories | `reports/README.md` overview committed daily by the aggregate workflow | Markdown in a private repository of your own, no hosted service. |

## Deliberately not built

| Feature | Why not |
|---|---|
| Runtime firewall (in-app WAF/RASP) | A runtime agent inside production apps is a different kind of product with its own failure modes (latency, blocking legitimate traffic). Out of scope for a CI scanner; the edge (CDN or reverse proxy) is the place for WAF rules. |
| Reachability analysis (call-graph) | Needs per-language call-graph engines and is expensive to keep accurate. Severity rules (dev deps lower, KEV higher) and the fixed-version hint give most of the prioritisation value cheaply. |
| AutoFix pull requests | Opening code-changing PRs automatically needs review and testing per repo; dependency bumps are already handled by Dependabot/Renovate. Reports show the fixed version to upgrade to. |
| Malware feed for packages | Requires a curated, constantly updated threat feed. OSV already includes the OpenSSF malicious-packages data that osv-scanner reports. |
| CSPM (cloud posture) | Needs read access to cloud accounts and per-provider checks; not a repository concern. Belongs with your cloud provider's security tooling instead. |
| VM / host scanning | Needs agents or SSH on servers. Container images built from the repository's Dockerfiles cover what the repository ships. |
| squawk (Postgres migration linter) | It reads raw SQL files; projects that write migrations in a migration framework's own language (for example Alembic Python) have nothing for it to read. Framework checks such as `alembic check`, plus review rules for migrations, cover the same ground. |
| hadolint (Dockerfile linter) | `trivy config` already checks Dockerfiles; a second linter would mostly repeat its findings as noise. |
| Live secret validation | Validating a key means sending the secret to a third party (the provider's API, or a third-party service) - exactly what this tool must never do. Treat every detected secret as live: rotate, then remove. |

## Data handling

- Findings hold only masked secret prefixes; gitleaks' raw report lives in a private temp
  directory and is deleted after one read.
- Scanner stdout is discarded. On failure only the last stderr line is shown, scrubbed of
  credential-shaped strings.
- Claude gets code excerpts with credential-shaped strings scrubbed, and for secrets only
  path, masked prefix and test/fixture flags. Token usage is logged; request bodies are not.
- The aggregate token is read-only on the target repos; reports are scrubbed again when
  rendered.
