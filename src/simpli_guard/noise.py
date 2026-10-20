"""Noise reduction before anyone (or Claude) looks at a finding:

1. severity rules - test code and dev-only dependencies one level lower,
   CISA KEV vulnerabilities one level higher;
2. dedupe - the same fingerprint from two tools becomes one finding;
3. config ignores - by fingerprint id, rule id or path glob, each with a
   reason; expired entries stop applying;
4. inline ignores - `# simpli-guard: ignore <rule_id> <reason>` (or `//`) on
   the flagged line or the line above, for SAST findings. In PR mode an ignore the PR
   itself adds does not suppress a finding at or above failOn (see PrScope).

Suppressed findings are kept (with the reason) for the report; they are just
not counted, posted or failed on.
"""

from __future__ import annotations

import logging
import re
from collections import Counter
from dataclasses import dataclass
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

# (rule selector, reason) as written in an ignore comment; the file is the dict key it lives under.
InlineKey = tuple[str, str]


def inline_ignore_counts(lines: list[str]) -> Counter[InlineKey]:
    """Every well-formed ignore comment in a file, counted by (rule, reason)."""
    counts: Counter[InlineKey] = Counter()
    for text in lines:
        m = INLINE.search(text)
        if m and (m.group(2) or "").strip():
            counts[(m.group(1), (m.group(2) or "").strip())] += 1
    return counts


@dataclass
class AddedSuppression:
    """An inline ignore that exists on the PR head but not on the base commit."""

    finding: Finding
    selector: str
    reason: str
    applied: bool
    via_override: bool = False


@dataclass
class PrScope:
    """What `apply_inline_ignores` needs to tell the PR's own ignores from the base's.

    `base_root` is the base commit's checkout. An ignore counts as added by the PR when the
    PR head has more copies of the same (file, rule, reason) comment than the base has. When it
    has more, every finding relying on that (file, rule, reason) is treated as PR-added, so a
    copied comment cannot launder a new finding."""

    base_root: Path
    fail_on: Severity
    override: bool = False
    override_label: str = ""


def apply_inline_ignores(
    findings: list[Finding], root: Path, pr: PrScope | None = None
) -> list[AddedSuppression]:
    """Apply inline ignores; with `pr`, return the ones the PR added and say whether each applied."""
    cache: dict[str, list[str]] = {}
    base_counts: dict[str, Counter[InlineKey]] = {}
    head_counts: dict[str, Counter[InlineKey]] = {}
    added: list[AddedSuppression] = []
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
            key = (m.group(1), reason)
            if pr is not None and _added_by_pr(f.path, key, lines, pr, base_counts, head_counts):
                added.append(_decide_added(f, key, pr))
            else:
                f.suppress(f"inline ignore: {reason}", TriageBy.RULE)
            break
    return added


def _added_by_pr(
    path: str,
    key: InlineKey,
    head_lines: list[str],
    pr: PrScope,
    base_counts: dict[str, Counter[InlineKey]],
    head_counts: dict[str, Counter[InlineKey]],
) -> bool:
    if path not in base_counts:
        base_counts[path] = inline_ignore_counts(read_lines(pr.base_root, path))
        head_counts[path] = inline_ignore_counts(head_lines)
    return head_counts[path][key] > base_counts[path][key]


def _decide_added(f: Finding, key: InlineKey, pr: PrScope) -> AddedSuppression:
    selector, reason = key
    if pr.override:
        f.suppress(
            f"inline ignore added in this PR, applied by the {pr.override_label} label: {reason}",
            TriageBy.RULE,
        )
        return AddedSuppression(f, selector, reason, applied=True, via_override=True)
    if f.severity.at_least(pr.fail_on):
        f.notes.append("an ignore comment added in this PR was not applied")
        return AddedSuppression(f, selector, reason, applied=False)
    f.suppress(f"inline ignore added in this PR: {reason}", TriageBy.RULE)
    return AddedSuppression(f, selector, reason, applied=True)


def reduce_with_suppressions(
    findings: list[Finding],
    config: GuardConfig,
    root: Path,
    kev: set[str],
    today: date | None = None,
    pr: PrScope | None = None,
) -> tuple[list[Finding], list[AddedSuppression]]:
    apply_severity_rules(findings, kev, config.test_paths)
    out = dedupe(findings)
    apply_ignores(out, config, today)
    return out, apply_inline_ignores(out, root, pr)


def reduce(
    findings: list[Finding], config: GuardConfig, root: Path, kev: set[str], today: date | None = None
) -> list[Finding]:
    return reduce_with_suppressions(findings, config, root, kev, today)[0]
