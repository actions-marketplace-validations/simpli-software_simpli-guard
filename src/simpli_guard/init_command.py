"""`simpli-guard init`: one-command setup, run from the root of the repository being set up.

It asks a few questions (Enter accepts the default), then writes
`.github/workflows/security-scan.yml` and `.simpli-guard/config.json` (non-default fields only),
pins the action to the latest release commit, checks that the triage secret exists (names only,
never values) and prints the next steps. Standard library plus the package's own config model.
Network and `gh` access go through the injectable `Deps`, so tests never touch either.
"""

from __future__ import annotations

import argparse
import difflib
import json
import os
import re
import shutil
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TypeVar

from pydantic import ValidationError

from simpli_guard.config import CONFIG_PATH, GuardConfig, is_test_path
from simpli_guard.models import Category, Severity

T = TypeVar("T")

ACTION_REPO = "simpli-software/simpli-guard"
API_HOST = "api.github.com"
SCAN_WORKFLOW = ".github/workflows/security-scan.yml"
AGGREGATE_WORKFLOW = ".github/workflows/aggregate.yml"
SECRET_NAME = "ANTHROPIC_API_KEY"
PLACEHOLDER_USES = f"{ACTION_REPO}@<commit-sha> # v1.x"

_DEFAULTS = GuardConfig()
DEFAULT_NAME = _DEFAULTS.name
DEFAULT_FAIL_ON = _DEFAULTS.fail_on
DEFAULT_MODEL = _DEFAULTS.triage.model
DEFAULT_TIME = "03:17"  # UTC, as in examples/security-scan.yml
AGGREGATE_DELAY_MIN = 110  # examples/aggregate.yml runs at 05:07, after the 03:17 nightly scans

_SHA = re.compile(r"^[0-9a-f]{40}$")
_TAG = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/+-]{0,99}$")
_REF = re.compile(
    r"^([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)@([0-9a-fA-F]{40})(?:#([A-Za-z0-9][A-Za-z0-9._/+-]{0,99}))?$"
)
_MODEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,99}$")
_LOGIN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,38}$")
_TIME = re.compile(r"^([01]?\d|2[0-3]):([0-5]\d)$")
_USES = re.compile(r"^\s*(?:-\s+)?uses:\s*(\S+)(?:\s+#\s*(.*))?$")

CATEGORY_HELP: dict[Category, str] = {
    Category.SAST: "code (Opengrep)",
    Category.DEPENDENCY: "dependencies (osv-scanner)",
    Category.SECRET: "secrets (gitleaks)",
    Category.IAC: "IaC / config (Trivy)",
    Category.CONTAINER: "container images (Trivy, nightly)",
    Category.SURFACE: "live surface (nightly)",
    Category.LICENSE: "licenses (nightly)",
    Category.ACTIONS: "GitHub Actions workflows (zizmor)",
}

# ---------- workflow templates ----------
# The bodies below are examples/security-scan.yml and examples/aggregate.yml from the line that
# starts with `name:`. tests/test_init_command.py fails if they drift from those files.

SCAN_BODY = """\
name: Security scan

on:
  pull_request:
    types: [opened, synchronize, reopened, ready_for_review]
  schedule:
    - cron: "17 3 * * *" # nightly, 03:17 UTC
  workflow_dispatch:

permissions: {} # each job asks for exactly what it needs

jobs:
  pr:
    if: github.event_name == 'pull_request'
    # Job-level, so a newer push cancels the older scan of the same PR only.
    concurrency:
      group: security-scan-pr-${{ github.event.pull_request.number }}
      cancel-in-progress: true
    runs-on: ubuntu-latest
    timeout-minutes: 30
    permissions:
      contents: read
      pull-requests: write # the one summary comment
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          fetch-depth: 0 # the base commit is checked out into a worktree and scanned too
          persist-credentials: false
      - uses: simpli-software/simpli-guard@<commit-sha> # v1.x
        with:
          mode: pr
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}

  nightly:
    if: github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'
    concurrency:
      group: security-scan-nightly-${{ github.ref }}
      cancel-in-progress: false
    runs-on: ubuntu-latest
    timeout-minutes: 60
    permissions:
      contents: read
      issues: write # open/close one issue per critical/high finding
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          fetch-depth: 0 # full history for the secrets scan
          persist-credentials: false
      - uses: simpli-software/simpli-guard@<commit-sha> # v1.x
        with:
          mode: nightly
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
"""

AGGREGATE_BODY = """\
name: Aggregate security reports

on:
  schedule:
    - cron: "7 5 * * *" # 05:07 UTC, after the 03:17 nightly scans
  workflow_dispatch:

permissions:
  contents: write # commit the reports

concurrency:
  group: aggregate-reports
  cancel-in-progress: false

jobs:
  aggregate:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: simpli-software/simpli-guard@<commit-sha> # v1.x
        with:
          mode: aggregate
          guard-read-token: ${{ secrets.GUARD_READ_TOKEN }}
"""

_SCAN_CRON = '- cron: "17 3 * * *" # nightly, 03:17 UTC'
_AGG_CRON = '- cron: "7 5 * * *" # 05:07 UTC, after the 03:17 nightly scans'


class InitError(Exception):
    """A problem the user can act on; the message is safe to print."""


# ---------- pinning ----------


@dataclass(frozen=True)
class Pin:
    uses: str  # "owner/repo@<sha> # <tag>", or the placeholder
    resolved: bool
    reason: str = ""


Fetch = Callable[[str], Any]


class PinError(Exception):
    """Release lookup failed; the message is safe to print."""


class _SameHostRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow a redirect off the GitHub API host, so a token cannot travel elsewhere."""

    def redirect_request(
        self, req: urllib.request.Request, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> urllib.request.Request | None:
        u = urllib.parse.urlparse(newurl)
        if u.scheme != "https" or u.hostname != API_HOST:
            raise urllib.error.HTTPError(newurl, code, "redirect off the API host refused", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def default_fetch(url: str) -> Any:
    """GET a GitHub API URL. A token is sent only if GITHUB_TOKEN or GH_TOKEN is set."""
    u = urllib.parse.urlparse(url)
    if u.scheme != "https" or u.hostname != API_HOST:
        raise PinError("refusing a URL that is not the GitHub API")
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "simpli-guard-init",
    }
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    opener = urllib.request.build_opener(_SameHostRedirect)
    try:
        with opener.open(urllib.request.Request(url, headers=headers), timeout=10) as resp:
            return json.loads(resp.read(1_000_000))
    except urllib.error.HTTPError as e:
        raise PinError(f"GitHub API answered HTTP {e.code}") from None
    except (urllib.error.URLError, TimeoutError, OSError):
        raise PinError("could not reach the GitHub API") from None
    except ValueError:
        raise PinError("the GitHub API sent an unreadable answer") from None


def _obj(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise PinError("unexpected answer from the GitHub API")
    return data


def resolve_latest(fetch: Fetch, repo: str = ACTION_REPO) -> tuple[str, str]:
    """Latest release -> tag -> commit sha, dereferencing annotated tags. Returns (sha, tag)."""
    base = f"https://{API_HOST}/repos/{repo}"
    tag = _obj(fetch(f"{base}/releases/latest")).get("tag_name")
    if not isinstance(tag, str) or not _TAG.match(tag):
        raise PinError("the latest release has no usable tag")
    ref = _obj(fetch(f"{base}/git/ref/tags/{urllib.parse.quote(tag, safe='/')}"))
    target = _obj(ref.get("object"))
    for _ in range(5):  # annotated tags can nest; a real chain is one deep
        kind, sha = target.get("type"), target.get("sha")
        if not isinstance(sha, str) or not _SHA.match(sha):
            raise PinError("the tag points at an unreadable object")
        if kind == "commit":
            return sha, tag
        if kind != "tag":
            raise PinError(f"the tag points at a {kind}, not a commit")
        target = _obj(_obj(fetch(f"{base}/git/tags/{sha}")).get("object"))
    raise PinError("the tag chain is too deep")


def pin_from_ref(raw: str) -> Pin:
    m = _REF.match(raw.strip())
    if not m:
        raise InitError("--ref must look like owner/repo@<40-character commit sha> (optionally #<tag>)")
    repo, sha, tag = m.group(1), m.group(2).lower(), m.group(3)
    return Pin(f"{repo}@{sha} # {tag or 'pinned with --ref'}", True)


def resolve_pin(fetch: Fetch) -> Pin:
    try:
        sha, tag = resolve_latest(fetch)
    except PinError as e:
        return Pin(PLACEHOLDER_USES, False, str(e))
    return Pin(f"{ACTION_REPO}@{sha} # {tag}", True)


def placeholder_help() -> list[str]:
    return [
        "Could not pin the action automatically, so the workflow has a placeholder. To fill it in:",
        f"  1. gh release view --repo {ACTION_REPO} --json tagName --jq .tagName",
        f"  2. gh api repos/{ACTION_REPO}/commits/<that tag> --jq .sha",
        "  3. In the workflow, replace <commit-sha> with that hash and v1.x with the tag, on every",
        "     uses: line of the action.",
        f"  Or run again later: simpli-guard init --force --ref {ACTION_REPO}@<that hash>",
    ]


# ---------- answers and config ----------


@dataclass
class Answers:
    name: str = DEFAULT_NAME
    fail_on: Severity = DEFAULT_FAIL_ON
    disabled: list[Category] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    triage: bool = True
    model: str = DEFAULT_MODEL
    test_paths: list[str] = field(default_factory=list)
    nightly: str = DEFAULT_TIME
    aggregate: bool = False


def build_config(a: Answers) -> dict[str, Any]:
    """Only the fields that differ from the defaults, in the documented key order."""
    cfg: dict[str, Any] = {}
    if a.name != DEFAULT_NAME:
        cfg["name"] = a.name
    if a.fail_on != DEFAULT_FAIL_ON:
        cfg["failOn"] = a.fail_on.value
    if a.disabled:
        cfg["categories"] = {c.value: False for c in Category if c in a.disabled}
    if a.urls:
        cfg["surface"] = {"urls": list(a.urls)}
    triage: dict[str, Any] = {}
    if not a.triage:
        triage["enabled"] = False
    elif a.model != DEFAULT_MODEL:
        triage["model"] = a.model
    if triage:
        cfg["triage"] = triage
    if a.test_paths:
        cfg["testPaths"] = list(a.test_paths)
    return cfg


def render_config(a: Answers) -> str:
    return json.dumps(build_config(a), indent=2, ensure_ascii=False) + "\n"


def validate_config(text: str, a: Answers) -> None:
    """Parse the generated JSON back and load it through the real config model."""
    try:
        data = json.loads(text)
        cfg = GuardConfig.model_validate(data)
    except (ValueError, ValidationError) as e:
        raise InitError(f"generated {CONFIG_PATH} is not valid: {e}") from None
    ok = (
        data == build_config(a)
        and cfg.name == a.name
        and cfg.fail_on == a.fail_on
        and all(not cfg.enabled(c) for c in a.disabled)
        and all(cfg.enabled(c) for c in Category if c not in a.disabled)
        and cfg.surface.urls == a.urls
        and cfg.triage.enabled == a.triage
        and (not a.triage or cfg.triage.model == a.model)
        and cfg.test_paths == a.test_paths
    )
    if not ok:
        raise InitError(f"generated {CONFIG_PATH} does not match the answers given")


# ---------- workflows ----------


def _header(pin: Pin, extra: list[str]) -> str:
    lines = ["# Generated by `simpli-guard init`. Safe to edit.", *extra]
    if not pin.resolved:
        lines += [
            "# TODO: replace <commit-sha> with the full 40-character commit hash of the release you want,",
            "# and v1.x with its tag. The Actions scan flags a tag or branch reference as unpinned.",
        ]
    return "\n".join(lines) + "\n"


def parse_time(raw: str) -> str:
    m = _TIME.match(raw.strip())
    if not m:
        raise ValueError("use HH:MM in UTC, for example 03:17")
    return f"{int(m.group(1)):02d}:{m.group(2)}"


def render_scan_workflow(pin: Pin, nightly: str) -> str:
    hh, mm = (int(x) for x in nightly.split(":"))
    body = SCAN_BODY.replace(_SCAN_CRON, f'- cron: "{mm} {hh} * * *" # nightly, {nightly} UTC')
    body = body.replace(PLACEHOLDER_USES, pin.uses)
    head = _header(
        pin,
        [
            f"# Optional secret: {SECRET_NAME} (enables Claude triage; scanning works without it).",
            f"# Optional config: {CONFIG_PATH} (see the simpli-guard README).",
        ],
    )
    return head + body


def render_aggregate_workflow(pin: Pin, nightly: str) -> str:
    hh, mm = (int(x) for x in nightly.split(":"))
    total = (hh * 60 + mm + AGGREGATE_DELAY_MIN) % 1440
    ah, am = total // 60, total % 60
    line = f'- cron: "{am} {ah} * * *" # {ah:02d}:{am:02d} UTC, after the {nightly} nightly scans'
    body = AGGREGATE_BODY.replace(_AGG_CRON, line).replace(PLACEHOLDER_USES, pin.uses)
    head = _header(
        pin,
        [
            "# Overview of every repository's nightly report. Run it ONLY in a PRIVATE repository:",
            "# the reports list your security findings. Needs the secret GUARD_READ_TOKEN and a repos.json.",
        ],
    )
    return head + body


def validate_workflow(text: str) -> None:
    """Re-read the generated workflow: LF only, no tabs, every `uses:` pinned or the placeholder."""
    if "\r" in text or "\t" in text or not text.endswith("\n"):
        raise InitError("generated workflow has a CR, a tab or no final newline")
    code = [ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    if not code or not code[0].startswith("name: ") or "jobs:" not in code:
        raise InitError("generated workflow lost its top-level structure")
    uses = 0
    for ln in code:
        m = _USES.match(ln)
        if m:
            uses += 1
            if not (_SHA.match(m.group(1).rsplit("@", 1)[-1]) or m.group(1).endswith("@<commit-sha>")):
                raise InitError(f"generated workflow has an unpinned action: {m.group(1)}")
        if "cron:" in ln and not re.search(r'cron:\s*"\d{1,2} \d{1,2} \* \* \*"', ln):
            raise InitError("generated workflow has a malformed cron line")
    if not uses:
        raise InitError("generated workflow has no uses: lines")


# ---------- prompts ----------


@dataclass
class Console:
    input_fn: Callable[[str], str]
    out: Callable[[str], None]
    interactive: bool

    def say(self, text: str = "") -> None:
        self.out(text)

    def ask(self, label: str, default: str, parse: Callable[[str], T]) -> T:
        """Ask until `parse` accepts. Enter (or end of input) takes the default."""
        if not self.interactive:
            return parse(default)
        while True:
            try:
                raw = self.input_fn(f"{label} [{default or 'none'}]: ")
            except EOFError:
                raw = ""
            raw = raw.strip() or default
            try:
                return parse(raw)
            except ValueError as e:
                self.say(f"  {e}")


def _is_none(raw: str) -> bool:
    return raw.strip().lower() in ("", "none", "-")


def parse_heading(raw: str) -> str:
    s = raw.strip()
    if not s or len(s) > 80 or not s.isprintable():
        raise ValueError("use 1 to 80 printable characters")
    return s


def parse_fail_on(raw: str) -> Severity:
    s = raw.strip().lower()
    if s not in ("critical", "high", "medium"):
        raise ValueError("choose critical, high or medium")
    return Severity(s)


def parse_categories(raw: str) -> list[Category]:
    if _is_none(raw):
        return []
    order = list(Category)
    picked: set[Category] = set()
    for tok in re.split(r"[,\s]+", raw.strip().lower()):
        if not tok:
            continue
        if tok.isdigit() and 1 <= int(tok) <= len(order):
            picked.add(order[int(tok) - 1])
            continue
        try:
            picked.add(Category(tok))
        except ValueError:
            raise ValueError(f"unknown category {tok!r}; use the numbers or names shown") from None
    return [c for c in order if c in picked]


def parse_urls(raw: str) -> list[str]:
    if _is_none(raw):
        return []
    urls: list[str] = []
    for part in raw.split(","):
        url = part.strip()
        if not url:
            continue
        try:
            u = urllib.parse.urlparse(url)
            host = u.hostname
        except ValueError:
            raise ValueError("not a valid URL") from None
        if u.scheme != "https" or not host or any(ch.isspace() for ch in url):
            raise ValueError("every URL must start with https:// and name a host")
        if u.username or u.password:
            raise ValueError("a URL must not contain credentials")
        if url not in urls:
            urls.append(url)
    return urls


def parse_yes_no(raw: str) -> bool:
    s = raw.strip().lower()
    if s in ("y", "yes"):
        return True
    if s in ("n", "no"):
        return False
    raise ValueError("answer y or n")


def parse_model(raw: str) -> str:
    s = raw.strip()
    if not _MODEL.match(s):
        raise ValueError("a model id has letters, digits, '.', '_', '-' or ':' only")
    return s


def parse_paths(raw: str) -> list[str]:
    if _is_none(raw):
        return []
    out: list[str] = []
    for part in raw.split(","):
        p = part.strip().replace("\\", "/")
        if not p:
            continue
        if p.startswith("/") or ".." in p.split("/") or not p.isprintable() or '"' in p:
            raise ValueError("use repository-relative globs such as qa/** (no leading '/', no '..')")
        if p not in out:
            out.append(p)
    return out


# ---------- detection ----------

_SKIP_DIRS = {
    ".git", "node_modules", ".venv", "venv", "env", "__pycache__", "dist", "build", "vendor",
    "site-packages", ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache", "target", ".next",
    ".terraform", "coverage",
}  # fmt: skip
_EXTRA_TEST_DIRS = {
    "qa", "cypress", "playwright", "integration", "integration_tests", "integration-tests",
    "functional", "specs", "test_utils", "test-utils", "testutils",
}  # fmt: skip
_MAX_DEPTH = 4
_MAX_PATHS = 10


def _extra_test_name(name: str) -> bool:
    n = name.lower()
    return n in _EXTRA_TEST_DIRS or n.startswith(("test_", "test-")) or n.endswith(("_tests", "-tests"))


def detect_test_dirs(root: Path) -> tuple[list[str], list[str]]:
    """Return (suggested extra globs, folders the scanner already treats as tests)."""
    extra: list[str] = []
    builtin: list[str] = []
    for dirpath, dirnames, _files in os.walk(root):
        rel = Path(dirpath).relative_to(root)
        keep: list[str] = []
        for d in sorted(dirnames):
            if d in _SKIP_DIRS or len(rel.parts) >= _MAX_DEPTH:
                continue
            path = (rel / d).as_posix()
            if is_test_path(path + "/x"):
                builtin.append(path)
            elif _extra_test_name(d):
                extra.append(path + "/**")
            else:
                keep.append(d)
        dirnames[:] = keep
    return extra[:_MAX_PATHS], builtin[:_MAX_PATHS]


# ---------- files ----------


def _inside(root: Path, target: Path) -> bool:
    try:
        target.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def _short_diff(old: str, new: str, rel: str, limit: int = 14) -> list[str]:
    diff = list(
        difflib.unified_diff(
            old.splitlines(),
            new.splitlines(),
            f"a/{rel} (existing)",
            f"b/{rel} (generated)",
            n=1,
            lineterm="",
        )
    )
    if len(diff) > limit:
        return [*diff[:limit], f"... ({len(diff) - limit} more diff lines)"]
    return diff


def write_file(root: Path, rel: str, text: str, console: Console, *, force: bool, dry_run: bool) -> str:
    """Write one file. Returns created, overwritten, unchanged, skipped, or a dry-run 'would-' form."""
    if "\r" in text:
        raise InitError("internal error: CR in generated text")
    target = root / rel
    if not _inside(root, target):
        console.say(f"  skipped   {rel} (resolves outside the repository)")
        return "skipped"
    exists = target.is_file()
    if exists:
        old = target.read_text(encoding="utf-8", errors="replace").replace("\r\n", "\n")
        if old == text:
            console.say(f"  unchanged {rel}")
            return "unchanged"
        if not force:
            console.say(f"  skipped   {rel} exists and differs (use --force to overwrite):")
            for ln in _short_diff(old, text, rel):
                console.say(f"    {ln}")
            return "skipped"
    elif target.exists():
        console.say(f"  skipped   {rel} exists and is not a regular file")
        return "skipped"
    verb = "overwritten" if exists else "created"
    if dry_run:
        console.say(f"  would be {verb}: {rel}")
        return f"would-{verb}"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(text.encode("utf-8"))
    console.say(f"  {verb:<11} {rel}")
    return verb


# ---------- gh ----------


@dataclass(frozen=True)
class GhResult:
    rc: int
    out: str


GhRunner = Callable[[list[str]], GhResult]


def default_gh_runner(root: Path) -> GhRunner | None:
    exe = shutil.which("gh")
    if not exe:
        return None

    def run(args: list[str]) -> GhResult:
        env = {**os.environ, "GH_PROMPT_DISABLED": "1", "NO_COLOR": "1"}
        try:
            p = subprocess.run(
                [exe, *args], cwd=root, capture_output=True, text=True, timeout=30, check=False, env=env
            )
        except (OSError, subprocess.SubprocessError):
            return GhResult(-1, "")
        return GhResult(p.returncode, p.stdout)

    return run


@dataclass(frozen=True)
class SecretCheck:
    status: str  # found | missing | unknown | skipped
    where: str = ""


def _secret_names(res: GhResult) -> set[str] | None:
    """Names from `gh secret list` (NAME<TAB>updated). Values are never listed by gh and never read here."""
    if res.rc != 0:
        return None
    return {ln.split()[0] for ln in res.out.splitlines() if ln.strip()}


def check_secret(gh: GhRunner | None) -> SecretCheck:
    """Is ANTHROPIC_API_KEY listed for this repository or its organization?"""
    if gh is None:
        return SecretCheck("unknown", "gh is not installed")
    names = _secret_names(gh(["secret", "list"]))
    if names is None:
        return SecretCheck("unknown", "gh could not list the repository secrets")
    if SECRET_NAME in names:
        return SecretCheck("found", "repository")
    info = gh(["repo", "view", "--json", "owner,isInOrganization"])
    if info.rc != 0:
        return SecretCheck("unknown", "could not read the repository owner")
    try:
        data = json.loads(info.out)
        owner = data["owner"]["login"] if data.get("isInOrganization") else None
    except (ValueError, KeyError, TypeError, AttributeError):
        return SecretCheck("unknown", "could not read the repository owner")
    if not isinstance(owner, str) or not _LOGIN.match(owner):
        return SecretCheck("missing")
    org_names = _secret_names(gh(["secret", "list", "--org", owner]))
    if org_names is None:
        return SecretCheck("unknown", "gh could not list the organization secrets")
    if SECRET_NAME in org_names:
        return SecretCheck("found", "organization")
    return SecretCheck("missing")


def repo_is_public(gh: GhRunner | None) -> bool | None:
    if gh is None:
        return None
    res = gh(["repo", "view", "--json", "isPrivate", "--jq", ".isPrivate"])
    if res.rc != 0:
        return None
    return {"true": False, "false": True}.get(res.out.strip().lower())


# ---------- the command ----------


@dataclass
class Deps:
    fetch: Fetch = default_fetch
    input_fn: Callable[[str], str] = input
    out: Callable[[str], None] = print
    gh: Callable[[Path], GhRunner | None] = default_gh_runner


def gather_answers(console: Console, root: Path) -> Answers:
    a = Answers()
    if console.interactive:
        console.say("simpli-guard init: press Enter to accept the value in brackets.")
        console.say()
    a.name = console.ask("Report heading name", DEFAULT_NAME, parse_heading)
    a.fail_on = console.ask(
        "Fail PRs on new findings at or above (critical/high/medium)", "high", parse_fail_on
    )

    if console.interactive:
        console.say("Categories (all on). Enter the ones to turn OFF, as numbers or names:")
        for i, c in enumerate(Category, 1):
            console.say(f"  {i}) {c.value:<10} {CATEGORY_HELP[c]}")
    a.disabled = console.ask("Turn off", "none", parse_categories)

    a.urls = console.ask("Live-surface URLs to check nightly (comma-separated, https)", "none", parse_urls)
    if console.interactive:
        console.say(
            f"Claude triage drops false positives. It needs the {SECRET_NAME} secret; a few cents a run."
        )
    a.triage = console.ask("Turn Claude triage on", "y", parse_yes_no)
    if a.triage:
        a.model = console.ask("Triage model", DEFAULT_MODEL, parse_model)

    extra, builtin = detect_test_dirs(root)
    if console.interactive and builtin:
        console.say(f"Already treated as tests (built in): {', '.join(builtin)}")
    a.test_paths = console.ask("Extra test paths (globs from the repo root)", ", ".join(extra), parse_paths)
    a.nightly = console.ask("Nightly run time, UTC (HH:MM)", DEFAULT_TIME, parse_time)

    if console.interactive:
        console.say()
        console.say(
            "Optional extra: the aggregate workflow collects every repository's nightly report into one"
        )
        console.say(
            "overview. It belongs in a PRIVATE repository only (the reports list your findings), and needs"
        )
        console.say(
            "a repos.json plus a GUARD_READ_TOKEN secret (a fine-grained token with Actions: read and"
        )
        console.say("Contents: read on the scanned repositories). Most repositories do not want it.")
        a.aggregate = console.ask("Add the aggregate workflow", "n", parse_yes_no)
    return a


def _next_steps(
    a: Answers, pin: Pin, secret: SecretCheck, written: dict[str, str], dry_run: bool
) -> list[str]:
    steps: list[str] = []
    if dry_run:
        steps.append("Run again without --dry-run to write the files.")
    if not pin.resolved:
        steps.append("Fill in the <commit-sha> placeholder (see above).")
    new = [p for p in (SCAN_WORKFLOW, CONFIG_PATH) if written.get(p) in ("created", "overwritten")]
    if new:
        steps.append(f"Review, commit and push to the default branch: git add {' '.join(new)}")
    if a.triage and secret.status in ("missing", "unknown"):
        steps.append(
            f"Add the {SECRET_NAME} secret: gh secret set {SECRET_NAME}  (it prompts for the value)."
        )
    steps.append("Open a pull request: the PR scan comments on new findings only.")
    steps.append(
        "Actions > Security scan > Run workflow starts the nightly scan now; it also runs on its schedule."
    )
    if a.urls:
        steps.append("The live-surface checks send plain GET requests: only list domains you own.")
    if a.aggregate and written.get(AGGREGATE_WORKFLOW) in ("created", "overwritten"):
        steps.append(
            f"Aggregate: keep it in a private repository, add a repos.json (examples/repos.example.json in "
            f"{ACTION_REPO}) and the secret: gh secret set GUARD_READ_TOKEN"
        )
    steps.append(
        "To ignore a finding: fix it; or put '# simpli-guard: ignore <rule_id> <reason>' on the flagged "
        "line; or "
        f'add an entry with a reason to "ignore" in {CONFIG_PATH}. '
        f"Details: https://github.com/{ACTION_REPO}#ignoring-a-finding"
    )
    return steps


def run_init(args: argparse.Namespace, deps: Deps) -> int:
    root = Path(args.root).resolve()
    console = Console(deps.input_fn, deps.out, interactive=not args.yes)
    if not (root / ".git").exists():
        console.say(
            f"{root} is not the root of a git repository. Run this from the repository root, or pass --root."
        )
        return 2
    try:
        pin = pin_from_ref(args.ref) if args.ref else None
        answers = gather_answers(console, root)
        if pin is None:
            console.say("Looking up the latest release ...")
            pin = resolve_pin(deps.fetch)

        config_text = render_config(answers)
        validate_config(config_text, answers)
        files = [
            (SCAN_WORKFLOW, render_scan_workflow(pin, answers.nightly)),
            (CONFIG_PATH, config_text),
        ]
        gh = deps.gh(root)
        if answers.aggregate:
            if repo_is_public(gh):
                console.say(
                    "  skipped   aggregate workflow: this repository is public and the reports list findings."
                )
                answers.aggregate = False
            else:
                files.append((AGGREGATE_WORKFLOW, render_aggregate_workflow(pin, answers.nightly)))
        for rel, text in files:
            if rel.endswith(".yml"):
                validate_workflow(text)
    except InitError as e:
        console.say(str(e))
        return 2

    console.say()
    console.say("Dry run, nothing is written:" if args.dry_run else "Writing files:")
    written = {
        rel: write_file(root, rel, text, console, force=args.force, dry_run=args.dry_run)
        for rel, text in files
    }
    if args.dry_run:
        console.say(f"  {CONFIG_PATH} would contain:")
        for ln in config_text.splitlines():
            console.say(f"    {ln}")
        console.say(f"  uses: {pin.uses}")

    if not pin.resolved:
        console.say()
        if pin.reason:
            console.say(f"Release lookup failed: {pin.reason}.")
        for ln in placeholder_help():
            console.say(ln)

    secret = SecretCheck("skipped")
    if answers.triage:
        secret = check_secret(gh)
        console.say()
        if secret.status == "found":
            console.say(f"{SECRET_NAME} is set ({secret.where} secret).")
        else:
            state = "is not set" if secret.status == "missing" else f"could not be checked ({secret.where})"
            console.say(
                f"{SECRET_NAME} {state}. Without it triage stays off and scanning still works. Set it with:"
            )
            console.say(f"  gh secret set {SECRET_NAME}")
            console.say(
                f"  (whole organization: gh secret set {SECRET_NAME} --org <org> --repos <this-repo>)"
            )

    console.say()
    console.say("Next steps:")
    for i, step in enumerate(_next_steps(answers, pin, secret, written, args.dry_run), 1):
        console.say(f"  {i}. {step}")
    return 0


def add_parser(sub: Any) -> None:
    sp = sub.add_parser("init", help="set up simpli-guard in this repository")
    sp.add_argument("--root", default=".", help="repository root (default: current directory)")
    sp.add_argument(
        "--yes", "--non-interactive", dest="yes", action="store_true", help="accept every default"
    )
    sp.add_argument("--force", action="store_true", help="overwrite files that already exist")
    sp.add_argument("--dry-run", action="store_true", help="show what would be written; write nothing")
    sp.add_argument(
        "--ref", default="", metavar="OWNER/REPO@SHA", help="pin this commit, skip the release lookup"
    )


def cmd_init(args: argparse.Namespace) -> int:
    return run_init(args, Deps())
