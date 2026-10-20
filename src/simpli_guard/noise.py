"""Noise reduction before anyone (or Claude) looks at a finding:

1. severity rules - test code and dev-only dependencies one level lower,
   CISA KEV vulnerabilities one level higher;
2. dedupe - the same fingerprint from two tools becomes one finding;
3. config ignores - by fingerprint id, rule id or path glob, each with a
   reason; expired entries stop applying;
4. inline ignores - `# simpli-guard: ignore <rule_id> <reason>` (or `//`) on
   the flagged line or the line above, for SAST findings.

Suppressed findings are kept (with the reason) for the report; they are just
not counted, posted or failed on.
"""

from __future__ import annotations

import logging
import re
from datetime import date
from pathlib import Path

from simpli_guard.config import GuardConfig, IgnoreRule, glob_match, is_test_path
from simpli_guard.models import Category, Finding, Severity, TriageBy
from simpli_guard.scanners.base import read_lines

log = logging.getLogger(__name__)


def apply_severity_rules(findings: list[Finding], kev: set[str], test_globs: list[str]) -> None:
    for f in findings:
        if f.category == Category.SAST and is_test_path(f.path, test_globs):
            f.severity = f.severity.lower()
            f.notes.append("lowered: test code")
        if f.category == Category.DEPENDENCY and f.dev_only:
            f.severity = f.severity.lower()
            f.notes.append("lowered: dev-only dependency")
        # An OS package CVE with no fixed release: nothing to do until the distro ships one,
        # so it informs the report but never pages anyone (KEV can still raise it).
        unfixed_os_cve = f.category == Category.CONTAINER and f.package and not f.fixed_version
        if unfixed_os_cve and f.severity.rank > Severity.LOW.rank:
            f.severity = Severity.LOW
            f.notes.append("lowered: no fixed package released yet")
        if f.category in (Category.DEPENDENCY, Category.CONTAINER) and kev:
            ids = {f.rule_id.upper(), *(a.upper() for a in f.aliases)}
            if ids & kev:
                f.severity = f.severity.raise_()
                f.notes.append("raised: in CISA KEV (exploited in the wild)")


def dedupe(findings: list[Finding]) -> list[Finding]:
    by_id: dict[str, Finding] = {}
    for f in findings:
        seen = by_id.get(f.id)
        if seen is None:
            by_id[f.id] = f
            continue
        winner, other = (f, seen) if f.severity.rank > seen.severity.rank else (seen, f)
        tools = sorted({*winner.tool.split("+"), *other.tool.split("+")})
        winner.tool = "+".join(tools)
        winner.references = list(dict.fromkeys([*winner.references, *other.references]))
        winner.aliases = sorted({*winner.aliases, *other.aliases})
        winner.fixed_version = winner.fixed_version or other.fixed_version
        by_id[f.id] = winner
    return list(by_id.values())


def _rule_matches(selector: str, rule_id: str) -> bool:
    return rule_id == selector or rule_id.endswith("." + selector)


def ignore_matches(rule: IgnoreRule, f: Finding) -> bool:
    if rule.id and rule.id != f.id:
        return False
    if rule.rule and not _rule_matches(rule.rule, f.rule_id):
        return False
    return not (rule.path and not glob_match(f.path, rule.path))


def apply_ignores(findings: list[Finding], config: GuardConfig, today: date | None = None) -> None:
    active: list[IgnoreRule] = []
    for r in config.ignore:
        if r.expired(today):
            log.warning("ignore entry expired on %s; no longer applied: %s", r.expires, r.reason[:80])
        else:
            active.append(r)
    for f in findings:
        if not f.kept:
            continue
        for r in active:
            if ignore_matches(r, f):
                f.suppress(f"ignored in config: {r.reason}", TriageBy.RULE)
                break


INLINE = re.compile(r"(?:#|//|/\*|--)\s*simpli-guard:\s*ignore\s+(\S+)(?:\s+(.*?))?\s*(?:\*/)?\s*$")


def apply_inline_ignores(findings: list[Finding], root: Path) -> None:
    cache: dict[str, list[str]] = {}
    for f in findings:
        if not f.kept or f.category != Category.SAST or not f.line:
            continue
        lines = cache.setdefault(f.path, read_lines(root, f.path))
        for ln in (f.line, f.line - 1):
            if not 1 <= ln <= len(lines):
                continue
            m = INLINE.search(lines[ln - 1])
            if not m or not _rule_matches(m.group(1), f.rule_id):
                continue
            reason = (m.group(2) or "").strip()
            if not reason:
                log.warning("inline ignore at %s:%d has no reason; not applied", f.path, ln)
                continue
            f.suppress(f"inline ignore: {reason}", TriageBy.RULE)
            break


def reduce(
    findings: list[Finding], config: GuardConfig, root: Path, kev: set[str], today: date | None = None
) -> list[Finding]:
    apply_severity_rules(findings, kev, config.test_paths)
    out = dedupe(findings)
    apply_ignores(out, config, today)
    apply_inline_ignores(out, root)
    return out
