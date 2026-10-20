from __future__ import annotations

from datetime import date
from pathlib import Path

from simpli_guard import noise
from simpli_guard.config import GuardConfig, IgnoreRule
from simpli_guard.models import Category, Severity, TriageBy
from simpli_guard.scanners import osv, trivy

from .conftest import load, make_finding


def test_test_code_is_lowered() -> None:
    f = make_finding(path="tests/test_api.py", severity=Severity.HIGH)
    g = make_finding(path="app/api.py", severity=Severity.HIGH, snippet="y()")
    noise.apply_severity_rules([f, g], set(), [])
    assert f.severity == Severity.MEDIUM and "test code" in f.notes[0]
    assert g.severity == Severity.HIGH


def test_dev_deps_lowered_and_kev_raised() -> None:
    findings = osv.parse(load("osv.json"))
    noise.apply_severity_rules(findings, {"CVE-2099-0001"}, [])
    by = {f.package: f for f in findings}
    assert by["pytest"].severity == Severity.MEDIUM
    assert by["requests"].severity == Severity.CRITICAL and "KEV" in by["requests"].notes[0]
    assert by["jinja2"].severity == Severity.MEDIUM


def test_dedupe_across_tools_keeps_highest() -> None:
    merged = noise.dedupe(
        osv.parse(load("osv.json")) + trivy.parse_image(load("trivy-image.json"), "Dockerfile")
    )
    jinja = [f for f in merged if f.rule_id == "CVE-2024-22195"]
    assert len(jinja) == 1
    assert jinja[0].tool == "osv-scanner+trivy-image"
    assert jinja[0].fixed_version == "3.1.3"


def test_config_ignores_by_id_rule_path_and_expiry() -> None:
    a = make_finding(rule_id="python.lang.security.audit.eval-detected.eval-detected", snippet="a")
    b = make_finding(path="scripts/one.py", snippet="b")
    c = make_finding(snippet="c")
    d = make_finding(snippet="d", rule_id="python.lang.security.audit.other")
    cfg = GuardConfig(
        ignore=[
            IgnoreRule(rule="eval-detected", reason="sandboxed"),
            IgnoreRule(path="scripts/**", reason="dev scripts"),
            IgnoreRule(id=c.id, reason="accepted risk"),
            IgnoreRule(rule="python.lang.security.audit.other", reason="old", expires=date(2026, 1, 1)),
        ]
    )
    noise.apply_ignores([a, b, c, d], cfg, today=date(2026, 6, 1))
    assert not a.kept and a.triage.by == TriageBy.RULE and "sandboxed" in a.triage.reason
    assert not b.kept and not c.kept
    assert d.kept  # expired entry no longer applies


def test_inline_ignore(tmp_path: Path) -> None:
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "x.py").write_text(
        "# simpli-guard: ignore audit.x constant input only\n"
        "x()\n"
        "y()  # simpli-guard: ignore audit.x\n"
        "z()  // simpli-guard: ignore other.rule because\n"
    )
    a = make_finding(line=2, rule_id="python.lang.security.audit.x", snippet="a")
    b = make_finding(line=3, rule_id="python.lang.security.audit.x", snippet="b")  # no reason
    c = make_finding(line=4, rule_id="python.lang.security.audit.x", snippet="c")  # other rule
    d = make_finding(
        line=2, rule_id="python.lang.security.audit.x", snippet="d", category=Category.DEPENDENCY
    )
    noise.apply_inline_ignores([a, b, c, d], tmp_path)
    assert not a.kept and a.triage.reason == "inline ignore: constant input only"
    assert b.kept and c.kept and d.kept


def test_reduce_end_to_end(tmp_path: Path) -> None:
    f = make_finding(path="tests/test_a.py")
    out = noise.reduce([f, f.model_copy(deep=True)], GuardConfig(), tmp_path, set())
    assert len(out) == 1 and out[0].severity == Severity.MEDIUM


def test_unfixed_container_cve_is_lowered_to_low() -> None:
    from .conftest import make_finding

    f = make_finding(tool="trivy-image", category=Category.CONTAINER, severity=Severity.CRITICAL)
    f.package, f.fixed_version = "perl-base", None
    g = make_finding(tool="trivy-image", category=Category.CONTAINER, severity=Severity.HIGH, snippet="z")
    g.package, g.fixed_version = "zlib1g", "1:1.3"
    noise.apply_severity_rules([f, g], set(), [])
    assert f.severity == Severity.LOW and "no fixed package" in f.notes[-1]
    assert g.severity == Severity.HIGH
