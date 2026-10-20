"""Markdown/JSON output: the PR comment, the step summary, the nightly report
and issue bodies. Only masked secret prefixes ever appear here, because the
finding model never holds more."""

from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from simpli_guard.models import SEVERITY_ORDER, Category, Finding

PR_MARKER = "<!-- simpli-guard:pr-comment -->"
FINDING_MARKER_RE = re.compile(r"<!-- simpli-guard:finding:([0-9a-f]{8,64})(?: tool=([\w+\-]+))? -->")
REPORT_SCHEMA = 1


@dataclass
class LinkContext:
    server: str = "https://github.com"
    repo: str = ""
    sha: str = ""

    def url(self, f: Finding) -> str | None:
        if f.category == Category.SURFACE or not f.path or not self.repo or not self.sha:
            return None
        anchor = f"#L{f.line}" if f.line else ""
        return f"{self.server}/{self.repo}/blob/{self.sha}/{f.path}{anchor}"


def finding_marker(f: Finding) -> str:
    return f"<!-- simpli-guard:finding:{f.id} tool={f.tool} -->"


def _loc(f: Finding, links: LinkContext) -> str:
    text = f"{f.path}:{f.line}" if f.line else (f.path or "-")
    url = links.url(f)
    return f"[`{text}`]({url})" if url else f"`{text}`"


def _pkg(f: Finding) -> str:
    if not f.package:
        return ""
    fix = f" -> fixed in **{f.fixed_version}**" if f.fixed_version else " (no fix released yet)"
    return f" `{f.package}@{f.version or '?'}`{fix}." if f.category != Category.LICENSE else ""


def _one(f: Finding, links: LinkContext) -> str:
    rule = f" `{f.rule_id}`" if f.rule_id else ""
    notes = f" _({'; '.join(f.notes)})_" if f.notes else ""
    line = f"- **{_esc(f.title)}** - {_loc(f, links)} - {f.tool}{rule}.{_pkg(f)}{notes}"
    if f.triage.reason and f.kept:
        line += f"\n  - {_esc(f.triage.reason)}"
    return line


def _esc(text: str) -> str:
    return text.replace("\r", " ").replace("\n", " ").replace("<!--", "&lt;!--")


def counts_line(findings: list[Finding]) -> str:
    c = Counter(f.severity.value for f in findings)
    parts = [f"{c[s.value]} {s.value}" for s in SEVERITY_ORDER if c[s.value]]
    return ", ".join(parts) or "none"


def by_severity(findings: list[Finding], links: LinkContext, heading: str = "###") -> list[str]:
    out: list[str] = []
    for sev in SEVERITY_ORDER:
        group = [f for f in findings if f.severity == sev]
        if not group:
            continue
        out.append(f"{heading} {sev.value.capitalize()} ({len(group)})")
        out += [_one(f, links) for f in sorted(group, key=lambda f: (f.path, f.line or 0))]
        out.append("")
    return out


def suppressed_block(findings: list[Finding], title: str) -> list[str]:
    sup = [f for f in findings if not f.kept]
    if not sup:
        return []
    out = [f"<details><summary>{title} ({len(sup)})</summary>", ""]
    for f in sup:
        loc = f"{f.path}:{f.line}" if f.line else f.path
        out.append(f"- {f.severity.value} - **{_esc(f.title)}** - `{loc}` - {_esc(f.triage.reason)}")
    out += ["", "</details>", ""]
    return out


# ---------- PR mode ----------


def pr_comment(
    name: str,
    new: list[Finding],
    existing: list[Finding],
    links: LinkContext,
    fail_on: str,
    failed: bool,
    tool_notes: list[str],
) -> str:
    kept_new = [f for f in new if f.kept]
    kept_existing = [f for f in existing if f.kept]
    lines = [PR_MARKER]
    if not kept_new:
        lines.append(f"### {name}: no new findings")
    else:
        verdict = f"fails (new findings at or above **{fail_on}**)" if failed else "passes"
        lines.append(f"### {name}: {len(kept_new)} new finding(s) - {verdict}")
        lines.append("")
        lines += by_severity(kept_new, links, heading="####")
    lines += suppressed_block(new, "New findings suppressed as noise")
    if kept_existing:
        lines.append(
            f"Pre-existing findings on the base branch (not introduced here): {counts_line(kept_existing)}."
        )
    if tool_notes:
        lines.append("")
        lines.append("_" + " ".join(tool_notes) + "_")
    return "\n".join(lines).strip() + "\n"


def no_new_findings(name: str, existing: list[Finding]) -> str:
    kept = [f for f in existing if f.kept]
    tail = f" Pre-existing: {counts_line(kept)}." if kept else ""
    return f"{PR_MARKER}\n### {name}: no new findings.{tail}\n"


# ---------- nightly report ----------


def report_json(
    findings: list[Finding], repo: str, sha: str, ref: str, tools: dict[str, dict[str, Any]], name: str
) -> str:
    data = {
        "schema": REPORT_SCHEMA,
        "name": name,
        "repo": repo,
        "sha": sha,
        "ref": ref,
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "counts": dict(Counter(f.severity.value for f in findings if f.kept)),
        "tools": tools,
        "findings": [f.model_dump(mode="json") for f in findings],
    }
    return json.dumps(data, indent=2, sort_keys=True)


def report_md(
    name: str, findings: list[Finding], links: LinkContext, tools: dict[str, dict[str, Any]]
) -> str:
    kept = [f for f in findings if f.kept]
    lines = [f"# {name} report", ""]
    if links.repo:
        lines.append(f"Repository `{links.repo}` at `{links.sha[:12]}`.")
    lines.append(f"Generated {datetime.now(UTC):%Y-%m-%d %H:%M} UTC. Open findings: {counts_line(kept)}.")
    lines += ["", "| Scanner | Status | Findings | Note |", "|---|---|---|---|"]
    for t, info in sorted(tools.items()):
        note = str(info.get("message", "")).replace("|", "\\|")
        lines.append(f"| {t} | {info.get('status')} | {info.get('count', 0)} | {note} |")
    lines.append("")
    lines += by_severity(kept, links, heading="##")
    lines += suppressed_block(findings, "Suppressed as noise")
    return "\n".join(lines).strip() + "\n"


def issue_title(f: Finding) -> str:
    return f"[security][{f.severity.value}] {f.title}"[:240]


def issue_body(f: Finding, links: LinkContext, name: str) -> str:
    lines = [
        finding_marker(f),
        f"**{name}** found a **{f.severity.value}** {f.category.value} issue.",
        "",
        f"- Where: {_loc(f, links)}",
        f"- Scanner: {f.tool}" + (f", rule `{f.rule_id}`" if f.rule_id else ""),
    ]
    if f.package:
        lines.append(f"- Package: `{f.package}@{f.version or '?'}`")
        if f.fixed_version:
            lines.append(f"- Fixed in: `{f.fixed_version}`")
    if f.notes:
        lines.append(f"- Severity notes: {'; '.join(f.notes)}")
    if f.triage.reason:
        lines.append(f"- Triage: {_esc(f.triage.reason)}")
    lines += ["", _esc(f.message)]
    if f.references:
        lines += ["", "References:"] + [f"- {r}" for r in f.references[:5]]
    lines += [
        "",
        f"Fingerprint `{f.id}`. This issue closes itself when a nightly scan no longer finds it. "
        "To accept the risk instead, add the fingerprint to `ignore` in `.simpli-guard/config.json` "
        "with a reason (and optionally `expires`), or close this issue as *not planned*.",
    ]
    return "\n".join(lines) + "\n"
