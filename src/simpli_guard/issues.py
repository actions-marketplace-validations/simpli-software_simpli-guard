"""Nightly issue tracking. State lives only in the issues themselves: each
issue body carries a hidden marker with the finding's fingerprint and tool.

- A kept critical/high finding with no open issue gets one (label `security`).
- An issue a human closed as *not planned* means "accepted": never reopened.
- An issue closed as completed whose finding comes back gets a fresh issue
  (a regression).
- An open issue whose finding is gone is commented on and closed - but only
  when the scanner that produced it actually ran this time, so a scanner that
  failed to download never closes anything.
"""

from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Protocol

from simpli_guard.models import SEVERITY_ORDER, Category, Finding, Severity
from simpli_guard.render import FINDING_MARKER_RE, LinkContext, _esc, _loc, issue_body, issue_title

log = logging.getLogger(__name__)

LABEL = "security"
MAX_NEW_ISSUES = 20


class IssueAPI(Protocol):
    def ensure_label(self, name: str, color: str = ..., description: str = ...) -> None: ...
    def list_issues(self, label: str, state: str = ...) -> list[dict[str, Any]]: ...
    def create_issue(self, title: str, body: str, labels: list[str]) -> int: ...
    def create_comment(self, number: int, body: str) -> None: ...
    def close_issue(self, number: int, reason: str = ...) -> None: ...


@dataclass
class Tracked:
    number: int
    state: str
    state_reason: str | None
    tool: str


@dataclass
class ReconcileResult:
    opened: list[str] = field(default_factory=list)  # fingerprints
    closed: list[int] = field(default_factory=list)  # issue numbers
    still_open: int = 0
    capped: int = 0


IMAGE_TOOL = "trivy-image"
MAX_IMAGE_ROWS = 40


def image_group_id(path: str) -> str:
    return hashlib.sha256(f"image-group:{path}".encode()).hexdigest()[:24]


def image_issue_title(path: str, serious: list[Finding]) -> str:
    worst = "critical" if any(f.severity == Severity.CRITICAL for f in serious) else "high"
    return f"[security][{worst}] Container image from {path}: {len(serious)} fixable critical/high CVEs"[:240]


def image_issue_body(gid: str, path: str, serious: list[Finding], name: str) -> str:
    rows = sorted(serious, key=lambda f: (SEVERITY_ORDER.index(f.severity), f.package or ""))
    lines = [
        f"<!-- simpli-guard:finding:{gid} tool={IMAGE_TOOL} -->",
        f"**{name}** built the image from `{path}` and found **{len(serious)}** critical/high "
        "vulnerabilities in its OS packages that already have a fixed release.",
        "",
        "Usual fix: rebuild on a current base image (`docker build --pull`), or move to a newer or "
        "slimmer base tag. CVEs with no fixed release yet are listed in the nightly report only.",
        "",
        "| Severity | Package | Installed | Fixed in | Vulnerability |",
        "|---|---|---|---|---|",
    ]
    for f in rows[:MAX_IMAGE_ROWS]:
        lines.append(
            f"| {f.severity.value} | `{f.package}` | `{f.version or '?'}` | `{f.fixed_version}` | "
            f"{f.rule_id} |"
        )
    if len(rows) > MAX_IMAGE_ROWS:
        lines.append(f"\n…and {len(rows) - MAX_IMAGE_ROWS} more in the nightly report artifact.")
    lines += [
        "",
        "This issue closes itself when a nightly scan finds no fixable critical/high CVEs in this image.",
    ]
    return "\n".join(lines) + "\n"


MAX_GROUP_ROWS = 40


def group_id(kind: str, key: str) -> str:
    return hashlib.sha256(f"{kind}-group:{key}".encode()).hexdigest()[:24]


def _worst(fs: list[Finding]) -> Severity:
    return min((f.severity for f in fs), key=SEVERITY_ORDER.index)


def _tools(fs: list[Finding]) -> str:
    return "+".join(sorted({t for f in fs for t in f.tool.split("+")}))


def _version_key(v: str) -> tuple[int, ...]:
    return tuple(int(p) for p in re.findall(r"\d+", v)[:6])


def _is_version(v: str) -> bool:
    return bool(re.match(r"^v?\d+(\.\d+)*", v)) and not re.fullmatch(r"[0-9a-f]{12,40}", v)


def _more(rows: list[Finding]) -> list[str]:
    extra = len(rows) - MAX_GROUP_ROWS
    return [f"\n…and {extra} more in the nightly report artifact."] if extra > 0 else []


def rule_issue(gid: str, rule: str, fs: list[Finding], links: LinkContext, name: str) -> tuple[str, str]:
    sev = _worst(fs).value
    head = fs[0]
    where = f"{len(fs)} place" + ("s" if len(fs) != 1 else "")
    title = f"[security][{sev}] {head.title} ({where})"[:240]
    rows = sorted(fs, key=lambda f: (f.path, f.line or 0))
    lines = [
        f"<!-- simpli-guard:finding:{gid} tool={_tools(fs)} -->",
        f"**{name}** found **{len(fs)}** {sev}-or-higher code findings for rule `{rule}` that Claude "
        "triage did not rule out.",
        "",
        _esc(head.message),
        "",
        "| Severity | Where | Triage |",
        "|---|---|---|",
    ]
    for f in rows[:MAX_GROUP_ROWS]:
        note = _esc(f.triage.reason).replace("|", "\\|") if f.triage.reason else "not triaged"
        lines.append(f"| {f.severity.value} | {_loc(f, links)} | {note} |")
    lines += _more(rows)
    lines += [
        "",
        "Closes itself when a nightly scan no longer finds this rule at high or above. To accept a "
        "location, add `# simpli-guard: ignore <rule_id> <reason>` on or above the line.",
    ]
    return title, "\n".join(lines) + "\n"


def package_issue(gid: str, key: str, fs: list[Finding], links: LinkContext, name: str) -> tuple[str, str]:
    sev = _worst(fs).value
    # OSV sometimes gives a git commit as the fix for unreleased branches; only versions count here.
    fixes = sorted({v for f in fs if (v := f.fixed_version) and _is_version(v)}, key=_version_key)
    target = f"upgrade to {fixes[-1]}" if fixes else "no fixed release yet"
    title = (
        f"[security][{sev}] {key}: {len(fs)} known vulnerabilit{'ies' if len(fs) != 1 else 'y'} ({target})"
    )
    rows = sorted(fs, key=lambda f: (SEVERITY_ORDER.index(f.severity), f.rule_id))
    lines = [
        f"<!-- simpli-guard:finding:{gid} tool={_tools(fs)} -->",
        f"**{name}** found **{len(fs)}** high-or-critical advisories against `{key}` "
        f"(in `{fs[0].path}`). Usual fix: {target}.",
        "",
        "| Severity | Advisory | Fixed in | Summary |",
        "|---|---|---|---|",
    ]
    for f in rows[:MAX_GROUP_ROWS]:
        summary = _esc(f.title).replace("|", "\\|")[:120]
        lines.append(f"| {f.severity.value} | {f.rule_id} | `{f.fixed_version or '-'}` | {summary} |")
    lines += _more(rows)
    lines += ["", "Closes itself when a nightly scan no longer finds high-or-critical advisories here."]
    return title[:240], "\n".join(lines) + "\n"


def tracked_issues(issues: list[dict[str, Any]]) -> dict[str, Tracked]:
    out: dict[str, Tracked] = {}
    for i in issues:
        if "pull_request" in i:
            continue
        m = FINDING_MARKER_RE.search(i.get("body") or "")
        if not m:
            continue
        t = Tracked(int(i["number"]), str(i.get("state")), i.get("state_reason"), m.group(2) or "")
        prev = out.get(m.group(1))
        # An open issue wins over closed ones; otherwise the newest.
        if (
            prev is None
            or (t.state == "open" and prev.state != "open")
            or (t.state == prev.state and t.number > prev.number)
        ):
            out[m.group(1)] = t
    return out


def reconcile(
    gh: IssueAPI,
    findings: list[Finding],
    ran_tools: set[str],
    links: LinkContext,
    name: str,
    dry_run: bool = False,
) -> ReconcileResult:
    res = ReconcileResult()
    tracked = tracked_issues(gh.list_issues(LABEL, "all"))

    # Container OS-package CVEs come in hundreds per image and share one fix (rebuild on a
    # patched base), so they are tracked as ONE issue per image, not one per CVE.
    images: dict[str, list[Finding]] = {}
    for f in findings:
        if f.category == Category.CONTAINER and f.package and f.kept:
            images.setdefault(f.path, []).append(f)
    # Code findings are tracked per rule (one fix pattern, many places) and dependency
    # findings per package version (one upgrade fixes every advisory against it).
    by_rule: dict[str, list[Finding]] = {}
    by_package: dict[str, list[Finding]] = {}
    per_finding: list[Finding] = []
    for f in findings:
        if f.category == Category.CONTAINER and f.package:
            continue
        if f.category == Category.SAST:
            by_rule.setdefault(f.rule_id, []).append(f)
        elif f.category == Category.DEPENDENCY and f.package:
            by_package.setdefault(f"{f.package}@{f.version or '?'}", []).append(f)
        else:
            per_finding.append(f)

    current = {f.id for f in per_finding if f.kept}
    wanted: list[tuple[str, Severity, str, str, str]] = []  # id, severity, sort key, title, body
    for f in per_finding:
        if f.kept and f.severity.at_least(Severity.HIGH):
            wanted.append((f.id, f.severity, f.path, issue_title(f), issue_body(f, links, name)))
    for kind, groups in (("sast", by_rule), ("dependency", by_package)):
        for key, group in groups.items():
            serious = [f for f in group if f.kept and f.severity.at_least(Severity.HIGH)]
            if not serious:
                continue
            gid = group_id(kind, key)
            current.add(gid)
            sev = _worst(serious)
            build = rule_issue if kind == "sast" else package_issue
            title, body = build(gid, key, serious, links, name)
            wanted.append((gid, sev, key, title, body))
    for path, group in images.items():
        gid = image_group_id(path)
        serious = [f for f in group if f.severity.at_least(Severity.HIGH) and f.fixed_version]
        if not serious:
            continue
        current.add(gid)
        sev = Severity.CRITICAL if any(f.severity == Severity.CRITICAL for f in serious) else Severity.HIGH
        wanted.append(
            (gid, sev, path, image_issue_title(path, serious), image_issue_body(gid, path, serious, name))
        )
    wanted.sort(key=lambda w: (SEVERITY_ORDER.index(w[1]), w[2]))

    label_ready = False
    for fid, sev, _, title, body in wanted:
        t = tracked.get(fid)
        if t and t.state == "open":
            res.still_open += 1
            continue
        if t and t.state_reason == "not_planned":
            continue  # a human accepted this one
        if len(res.opened) >= MAX_NEW_ISSUES:
            res.capped += 1
            continue
        if dry_run:
            log.info("dry run: would open an issue for %s (%s)", fid, sev.value)
            res.opened.append(fid)
            continue
        if not label_ready:
            gh.ensure_label(LABEL, "b60205", "Opened by the nightly security scan")
            label_ready = True
        gh.create_issue(title, body, [LABEL])
        res.opened.append(fid)

    for fid, t in tracked.items():
        if t.state != "open" or fid in current:
            continue
        tools = set(t.tool.split("+")) if t.tool else set()
        if not tools & ran_tools:
            continue  # its scanner didn't run this time: absence proves nothing
        if dry_run:
            log.info("dry run: would close issue #%d", t.number)
        else:
            gh.create_comment(
                t.number,
                f"The nightly scan of `{links.sha[:12] or 'HEAD'}` no longer finds this. Closing.",
            )
            gh.close_issue(t.number, "completed")
        res.closed.append(t.number)
    if res.capped:
        log.warning(
            "%d further critical/high findings not opened as issues (cap %d)", res.capped, MAX_NEW_ISSUES
        )
    return res
