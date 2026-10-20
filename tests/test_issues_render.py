from __future__ import annotations

import json
import logging
from typing import Any

import pytest

from simpli_guard.issues import reconcile, tracked_issues
from simpli_guard.models import Category, Severity, TriageBy
from simpli_guard.render import (
    PR_MARKER,
    LinkContext,
    finding_marker,
    issue_body,
    no_new_findings,
    pr_comment,
    report_json,
    report_md,
)
from simpli_guard.scan import split_new
from simpli_guard.scanners import gitleaks
from simpli_guard.scanners.base import ScanResult

from .conftest import FIXTURE_SECRETS, load, make_finding

LINKS = LinkContext("https://github.com", "Owner/app", "abc123def4567890")


class FakeIssues:
    def __init__(self, issues: list[dict[str, Any]]) -> None:
        self.issues = issues
        self.created: list[dict[str, Any]] = []
        self.comments: list[tuple[int, str]] = []
        self.closed: list[tuple[int, str]] = []
        self.labels: list[str] = []

    def ensure_label(self, name: str, color: str = "", description: str = "") -> None:
        self.labels.append(name)

    def list_issues(self, label: str, state: str = "all") -> list[dict[str, Any]]:
        return self.issues

    def create_issue(self, title: str, body: str, labels: list[str]) -> int:
        self.created.append({"title": title, "body": body, "labels": labels})
        return 100 + len(self.created)

    def create_comment(self, number: int, body: str) -> None:
        self.comments.append((number, body))

    def close_issue(self, number: int, reason: str = "completed") -> None:
        self.closed.append((number, reason))


def issue(n: int, f: Any, state: str = "open", reason: str | None = None) -> dict[str, Any]:
    return {"number": n, "state": state, "state_reason": reason, "body": finding_marker(f) + "\nbody"}


def test_reconcile_opens_skips_and_closes() -> None:
    tracked = make_finding(
        tool="trivy-config", category=Category.IAC, snippet="tracked", severity=Severity.CRITICAL
    )
    fresh = make_finding(tool="trivy-config", category=Category.IAC, snippet="fresh", severity=Severity.HIGH)
    accepted = make_finding(
        tool="trivy-config", category=Category.IAC, snippet="accepted", severity=Severity.HIGH
    )
    regressed = make_finding(
        tool="trivy-config", category=Category.IAC, snippet="regressed", severity=Severity.HIGH
    )
    medium = make_finding(
        tool="trivy-config", category=Category.IAC, snippet="medium", severity=Severity.MEDIUM
    )
    gone = make_finding(tool="trivy-config", category=Category.IAC, snippet="gone")
    gone_other_tool = make_finding(snippet="gone2", tool="osv-scanner", category=Category.DEPENDENCY)
    suppressed = make_finding(tool="trivy-config", category=Category.IAC, snippet="suppressed")
    suppressed.suppress("ignored in config: x", TriageBy.RULE)
    gh = FakeIssues(
        [
            issue(1, tracked),
            issue(2, accepted, "closed", "not_planned"),
            issue(3, regressed, "closed", "completed"),
            issue(4, gone),
            issue(5, gone_other_tool),  # osv-scanner didn't run: must stay open
            issue(6, suppressed),  # now ignored -> closes
            {"number": 7, "state": "open", "body": "unrelated issue"},
            {"number": 8, "state": "open", "body": finding_marker(fresh), "pull_request": {}},
        ]
    )
    res = reconcile(
        gh, [tracked, fresh, accepted, regressed, medium, suppressed], {"trivy-config"}, LINKS, "Scan"
    )
    assert sorted(res.opened) == sorted([fresh.id, regressed.id])
    assert res.still_open == 1
    assert sorted(n for n, _ in gh.closed) == [4, 6]
    assert {n for n, _ in gh.comments} == {4, 6}
    assert gh.labels == ["security"]
    assert all(c["labels"] == ["security"] for c in gh.created)
    assert all(
        finding_marker(fresh) in c["body"] or finding_marker(regressed) in c["body"] for c in gh.created
    )


def test_reconcile_dry_run_writes_nothing() -> None:
    f = make_finding(tool="trivy-config", category=Category.IAC)
    gh = FakeIssues([issue(9, make_finding(tool="trivy-config", category=Category.IAC, snippet="old"))])
    res = reconcile(gh, [f], {"trivy-config"}, LINKS, "Scan", dry_run=True)
    assert res.opened == [f.id] and res.closed == [9]
    assert not gh.created and not gh.closed and not gh.comments


def test_tracked_prefers_open() -> None:
    f = make_finding()
    t = tracked_issues([issue(1, f, "closed", "completed"), issue(2, f), issue(3, f, "closed", "completed")])
    assert t[f.id].number == 2 and t[f.id].tool == "opengrep"


def test_split_new_and_comment() -> None:
    old = make_finding(snippet="old", severity=Severity.HIGH, path="app/a.py")
    new = make_finding(snippet="new", severity=Severity.CRITICAL, path="app/b.py", line=12)
    dep = make_finding(snippet="dep", tool="osv-scanner", category=Category.DEPENDENCY)
    noisy = make_finding(snippet="noisy", severity=Severity.HIGH)
    noisy.suppress("Claude: not exploitable (5/5): constant input", TriageBy.CLAUDE)
    base = [ScanResult("opengrep", "ran", [old.model_copy()]), ScanResult("osv-scanner", "failed")]
    diff = split_new([old, new, dep, noisy], base, {"opengrep", "osv-scanner"})
    assert [f.id for f in diff.new] == [new.id, noisy.id]
    assert {f.id for f in diff.existing} == {old.id, dep.id}  # osv couldn't be diffed
    body = pr_comment("Scan", diff.new, diff.existing, LINKS, "high", True, ["note."])
    assert body.startswith(PR_MARKER)
    assert "1 new finding(s) - fails" in body
    assert "https://github.com/Owner/app/blob/abc123def4567890/app/b.py#L12" in body
    assert "<details><summary>New findings suppressed as noise (1)</summary>" in body
    assert "constant input" in body
    assert "Pre-existing findings" in body
    short = no_new_findings("Scan", diff.existing)
    assert short.startswith(PR_MARKER) and "no new findings" in short


def test_secret_values_never_in_any_output(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.DEBUG):
        secrets = gitleaks.parse(load("gitleaks.json"))
        body = pr_comment("Scan", secrets, [], LINKS, "high", True, [])
        issue_bodies = [issue_body(f, LINKS, "Scan") for f in secrets]
        tools = {"gitleaks": {"status": "ran", "count": 2, "message": ""}}
        rj = report_json(secrets, "Owner/app", "abc", "refs/heads/main", tools, "Scan")
        rm = report_md("Scan", secrets, LINKS, tools)
        gh = FakeIssues([])
        reconcile(gh, secrets, {"gitleaks"}, LINKS, "Scan")
    created = json.dumps(gh.created)
    for out in [body, *issue_bodies, rj, rm, created, caplog.text]:
        for s in FIXTURE_SECRETS:
            assert s not in out
            assert s[6:] not in out  # nor any long tail of it
    assert "sk_l…" in body
    data = json.loads(rj)
    assert data["counts"] == {"critical": 1, "high": 1}
    assert data["findings"][0]["masked"] == "sk_l…"


def _image_cve(pkg: str, sev: Severity, fixed: str | None, cve: str) -> Any:
    f = make_finding(tool="trivy-image", category=Category.CONTAINER, severity=sev, path="Dockerfile",
                     line=None, rule_id=cve, snippet=pkg)  # fmt: skip
    f.package, f.version, f.fixed_version = pkg, "1.0", fixed
    return f


def test_container_cves_become_one_issue_per_image() -> None:
    from simpli_guard.issues import image_group_id

    cves = [_image_cve(f"lib{i}", Severity.HIGH, "1.1", f"CVE-2026-{i:04d}") for i in range(30)]
    cves.append(_image_cve("zlib", Severity.CRITICAL, "2.0", "CVE-2026-9999"))
    cves.append(_image_cve("perl", Severity.HIGH, None, "CVE-2026-8888"))  # unfixed: not listed
    sast = make_finding(snippet="sql", severity=Severity.HIGH)
    gh = FakeIssues([])
    res = reconcile(gh, [*cves, sast], {"trivy-image", "opengrep"}, LINKS, "Scan")
    assert len(gh.created) == 2 and res.capped == 0
    image = next(c for c in gh.created if "Container image" in c["title"])
    assert image["title"].startswith("[security][critical] Container image from Dockerfile: 31 fixable")
    assert "CVE-2026-9999" in image["body"] and "CVE-2026-8888" not in image["body"]
    assert image_group_id("Dockerfile") in image["body"]


def test_image_issue_closes_when_no_fixable_cves_remain() -> None:
    from simpli_guard.issues import image_group_id

    marker = f"<!-- simpli-guard:finding:{image_group_id('Dockerfile')} tool=trivy-image -->"
    gh = FakeIssues([{"number": 7, "state": "open", "state_reason": None, "body": marker}])
    only_unfixed = [_image_cve("perl", Severity.HIGH, None, "CVE-2026-8888")]
    res = reconcile(gh, only_unfixed, {"trivy-image"}, LINKS, "Scan")
    assert res.closed == [7] and gh.created == []


def test_sast_and_dependency_findings_group_into_one_issue_each() -> None:
    sql = [make_finding(snippet=f"q{i}", path=f"app/r{i}.py") for i in range(12)]
    dep = []
    for i, fixed in enumerate(["1.3.1", "1.10.0", "0.9"]):
        d = make_finding(tool="osv-scanner", category=Category.DEPENDENCY, rule_id=f"CVE-2026-{i}",
                         snippet=f"d{i}", path="uv.lock")  # fmt: skip
        d.package, d.version, d.fixed_version = "starlette", "0.38.6", fixed
        dep.append(d)
    gh = FakeIssues([])
    reconcile(gh, [*sql, *dep], {"opengrep", "osv-scanner"}, LINKS, "Scan")
    titles = sorted(c["title"] for c in gh.created)
    assert len(gh.created) == 2
    assert titles[0].endswith("(12 places)")
    assert "starlette@0.38.6: 3 known vulnerabilities (upgrade to 1.10.0)" in titles[1]


def test_commit_hash_is_not_offered_as_the_upgrade_target() -> None:
    from simpli_guard.issues import package_issue

    fs = []
    for i, fixed in enumerate(["644124ecd0b6e417c527191f866daa05a5a2056d", "2.5.0"]):
        d = make_finding(
            tool="osv-scanner", category=Category.DEPENDENCY, rule_id=f"CVE-1-{i}", snippet=f"u{i}"
        )
        d.package, d.version, d.fixed_version = "urllib3", "1.26.9", fixed
        fs.append(d)
    title, _ = package_issue("g", "urllib3@1.26.9", fs, LINKS, "Scan")
    assert "(upgrade to 2.5.0)" in title
