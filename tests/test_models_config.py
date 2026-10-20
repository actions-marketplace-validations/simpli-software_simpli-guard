from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import pytest

from simpli_guard.config import GuardConfig, IgnoreRule, is_example_path, is_test_path, load_config
from simpli_guard.models import Severity, code_fingerprint, package_fingerprint, preferred_vuln_id
from simpli_guard.scanners import opengrep


def test_fingerprint_ignores_line_shift(tmp_path: Path) -> None:
    data = json.loads((Path(__file__).parent / "fixtures" / "opengrep.json").read_text())
    src = 'import db\n\ndef get(user_id):\n    cur.execute("SELECT * FROM users WHERE id = %s" % user_id)\n'
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "db.py").write_text(src)
    before = opengrep.parse(data, tmp_path)[0]

    # Ten new lines above, re-indented: same finding, same id, new line number.
    (tmp_path / "app" / "db.py").write_text("\n" * 10 + src.replace("    cur", "        cur"))
    data["results"][0]["start"]["line"] = 14
    data["results"][0]["end"]["line"] = 14
    after = opengrep.parse(data, tmp_path)[0]
    assert before.id == after.id
    assert (before.line, after.line) == (4, 14)


def test_fingerprint_changes_with_content() -> None:
    a = code_fingerprint("opengrep", "r", "a.py", "eval(x)")
    assert a != code_fingerprint("opengrep", "r", "a.py", "eval(y)")
    assert a != code_fingerprint("opengrep", "r", "b.py", "eval(x)")
    assert a == code_fingerprint("opengrep", "r", "a.py", "  eval(x)   ")


def test_package_fingerprint_is_tool_independent() -> None:
    assert package_fingerprint("Jinja2", "3.1.2", "cve-2024-22195") == package_fingerprint(
        "jinja2", "3.1.2", "CVE-2024-22195"
    )
    assert preferred_vuln_id("GHSA-x", ["PYSEC-1", "CVE-2024-2", "CVE-2024-1"]) == "CVE-2024-1"
    assert preferred_vuln_id("GHSA-x", []) == "GHSA-X"


def test_severity_steps() -> None:
    assert Severity.HIGH.lower() == Severity.MEDIUM
    assert Severity.INFO.lower() == Severity.INFO
    assert Severity.HIGH.raise_() == Severity.CRITICAL
    assert Severity.CRITICAL.raise_() == Severity.CRITICAL
    assert Severity.HIGH.at_least(Severity.HIGH) and not Severity.MEDIUM.at_least(Severity.HIGH)


@pytest.mark.parametrize(
    "path",
    [
        "tests/test_a.py",
        "app/tests/x.py",
        "x_test.py",
        "test_y.py",
        "web/a.test.tsx",
        "e2e/login.ts",
        "src/__tests__/a.js",
        "pkg/conftest.py",
    ],
)
def test_test_paths(path: str) -> None:
    assert is_test_path(path)


@pytest.mark.parametrize("path", ["app/main.py", "src/testing_utils_prod.py", "contest.py", "web/latest.ts"])
def test_non_test_paths(path: str) -> None:
    assert not is_test_path(path)


def test_extra_test_globs_and_examples() -> None:
    assert is_test_path("qa/smoke/run.py", ["qa/**"])
    assert is_example_path("tests/fixtures/sample.env")
    assert is_example_path(".env.example")
    assert not is_example_path("config/settings.py")


def test_config_defaults_and_aliases(tmp_path: Path) -> None:
    assert load_config(tmp_path) == GuardConfig()
    (tmp_path / ".simpli-guard").mkdir()
    (tmp_path / ".simpli-guard" / "config.json").write_text(
        json.dumps(
            {
                "failOn": "critical",
                "categories": {"license": False},
                "surface": {"urls": ["https://app.example.com"]},
                "triage": {"maxFindings": 5, "model": "claude-opus-5-5"},
                "testPaths": ["qa/**"],
                "ignore": [{"rule": "x", "reason": "accepted", "expires": "2030-01-01"}],
            }
        )
    )
    c = load_config(tmp_path)
    assert c.fail_on == Severity.CRITICAL
    assert not c.enabled("license") and c.enabled("sast")  # type: ignore[arg-type]
    assert c.triage.max_findings == 5 and c.triage.model == "claude-opus-5-5"
    assert c.ignore[0].expires == date(2030, 1, 1)


def test_ignore_requires_reason_and_selector(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        IgnoreRule.model_validate({"rule": "x", "reason": "  "})
    with pytest.raises(ValueError):
        IgnoreRule.model_validate({"reason": "why"})
    (tmp_path / ".simpli-guard").mkdir()
    (tmp_path / ".simpli-guard" / "config.json").write_text('{"ignore": [{"rule": "x"}]}')
    with pytest.raises(SystemExit):
        load_config(tmp_path)
