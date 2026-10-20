from __future__ import annotations

from pathlib import Path

from simpli_guard.models import Category, Severity
from simpli_guard.scanners import gitleaks, opengrep, osv, trivy
from simpli_guard.scanners.kev import parse_kev

from .conftest import FIXTURE_SECRETS, load


def test_opengrep_keeps_only_security_rules_and_normalizes_ids(tmp_path: Path) -> None:
    findings = opengrep.parse(load("opengrep.json"), tmp_path)
    assert [f.path for f in findings] == ["app/db.py", "tests/test_eval.py"]
    sql = findings[0]
    assert sql.rule_id == "python.lang.security.audit.formatted-sql-query.formatted-sql-query"
    assert sql.severity == Severity.HIGH and sql.category == Category.SAST
    assert sql.line == 4
    assert sql.title == "Detected possible formatted SQL query"
    assert any("CWE-89" in r for r in sql.references)
    assert findings[1].severity == Severity.MEDIUM
    assert findings[1].references == ["https://docs.python.org/3/library/functions.html#eval"]


def test_osv_parses_cvss_fix_and_dev_groups() -> None:
    findings = {f.package: f for f in osv.parse(load("osv.json"))}
    jinja = findings["jinja2"]
    assert jinja.rule_id == "CVE-2024-22195"
    assert jinja.severity == Severity.MEDIUM  # CVSS 5.4
    assert jinja.fixed_version == "3.1.3"
    assert jinja.path == "uv.lock" and not jinja.dev_only
    assert "GHSA-h5c8-rqwp-cp95" in jinja.aliases
    pytest_f = findings["pytest"]
    assert pytest_f.dev_only and pytest_f.severity == Severity.HIGH  # label fallback; lowered later
    assert findings["requests"].severity == Severity.HIGH
    assert findings["requests"].fixed_version == "2.32.0"


def test_osv_and_trivy_share_dependency_fingerprints() -> None:
    o = {f.rule_id: f.id for f in osv.parse(load("osv.json"))}
    t = {f.rule_id: f.id for f in trivy.parse_image(load("trivy-image.json"), "Dockerfile")}
    assert o["CVE-2024-22195"] == t["CVE-2024-22195"]


def test_gitleaks_masks_and_drops_values() -> None:
    findings = gitleaks.parse(load("gitleaks.json"))
    assert len(findings) == 2
    stripe = findings[0]
    assert stripe.masked == "sk_l…"
    assert stripe.severity == Severity.CRITICAL and stripe.category == Category.SECRET
    assert stripe.line == 3 and stripe.path == "config/settings.py"
    assert findings[1].severity == Severity.HIGH
    blob = "".join(f.model_dump_json() for f in findings)
    for s in FIXTURE_SECRETS:
        assert s not in blob
        assert s[:12] not in blob


def test_gitleaks_fingerprint_stable_across_commits_and_lines() -> None:
    a = load("gitleaks.json")
    b = load("gitleaks.json")
    b[0]["StartLine"] = 40
    b[0]["Commit"] = "ffff"
    assert gitleaks.parse(a)[0].id == gitleaks.parse(b)[0].id


def test_trivy_config_only_failures() -> None:
    findings = trivy.parse_config(load("trivy-config.json"))
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "AVD-DS-0002" and f.severity == Severity.HIGH and f.category == Category.IAC
    assert f.path == "Dockerfile" and f.line == 1 and f.tool == "trivy-config"


def test_trivy_image_eol_and_vulns() -> None:
    findings = trivy.parse_image(load("trivy-image.json"), "Dockerfile")
    eol = [f for f in findings if f.rule_id == "eol-base-image"]
    assert len(eol) == 1 and eol[0].severity == Severity.HIGH and "debian 9.13" in eol[0].title
    libc = next(f for f in findings if f.package == "libc6")
    assert libc.category == Category.CONTAINER and libc.fixed_version is None


def test_trivy_licenses() -> None:
    findings = {f.package: f for f in trivy.parse_licenses(load("trivy-license.json"))}
    assert findings["some-gpl-lib"].severity == Severity.MEDIUM
    assert findings["agpl-thing"].severity == Severity.MEDIUM
    assert findings["mpl-lib"].severity == Severity.INFO
    assert findings["lgpl-lib"].severity == Severity.INFO
    assert "mit-lib" not in findings


def test_kev_parse() -> None:
    assert parse_kev({"vulnerabilities": [{"cveID": "cve-2099-0001"}, {"x": 1}]}) == {"CVE-2099-0001"}
    assert parse_kev([]) == set()


def test_lockfile_discovery(tmp_path: Path) -> None:
    for p in [
        "uv.lock",
        "web/package-lock.json",
        "requirements-dev.txt",
        "node_modules/x/package-lock.json",
        "api/poetry.lock",
        "web/pnpm-lock.yaml",
        "README.md",
    ]:
        (tmp_path / p).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / p).write_text("")
    assert osv.find_lockfiles(tmp_path) == [
        "requirements-dev.txt",
        "uv.lock",
        "api/poetry.lock",
        "web/package-lock.json",
        "web/pnpm-lock.yaml",
    ]


def _rules_tarball() -> bytes:
    import io
    import tarfile

    files = {
        "opengrep-rules-abc/python/lang/security/audit/eval-detected.yaml": (
            "rules:\n  - id: eval-detected\n    metadata:\n      category: security\n"
        ),
        "opengrep-rules-abc/python/lang/best-practice/open-never-closed.yaml": (
            "rules:\n  - id: open-never-closed\n    metadata:\n      category: best-practice\n"
        ),
        "opengrep-rules-abc/python/lang/security/audit/eval-detected.test.yaml": "x: 1\n",
        # wrong language: dropped
        "opengrep-rules-abc/go/lang/security/x.yaml": "rules:\n  - id: x\n"
        "    metadata:\n      category: security\n",
    }
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        for name, text in files.items():
            data = text.encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def test_rules_extraction_keeps_security_and_rewrites_ids() -> None:
    rules = opengrep.extract_rules(_rules_tarball())
    assert len(rules) == 1
    assert "- id: python.lang.security.audit.eval-detected.eval-detected" in rules[0]
    assert (
        opengrep.normalize_rule_id(
            "tmp.cache.sgrules.r0001.python.lang.security.audit.eval-detected.eval-detected"
        )
        == "python.lang.security.audit.eval-detected.eval-detected"
    )
