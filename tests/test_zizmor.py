from __future__ import annotations

import copy
import sys
from pathlib import Path
from typing import Any

import pytest

from simpli_guard.config import GuardConfig
from simpli_guard.models import Category, Severity
from simpli_guard.noise import reduce
from simpli_guard.scan import Plan
from simpli_guard.scanners import base, zizmor
from simpli_guard.scanners.base import ScanResult

from .conftest import load


def test_parse_sample_output() -> None:
    findings = zizmor.parse(load("zizmor.json"))
    by_rule: dict[str, list[Any]] = {}
    for f in findings:
        by_rule.setdefault(f.rule_id, []).append(f)
    assert sorted(by_rule) == [
        "zizmor.artipacked",
        "zizmor.dangerous-triggers",
        "zizmor.template-injection",
        "zizmor.unpinned-uses",
    ]
    assert len(findings) == 6
    inj = next(f for f in by_rule["zizmor.template-injection"] if f.path == ".github/workflows/pr.yml")
    assert inj.category == Category.ACTIONS and inj.tool == "zizmor"
    assert inj.severity == Severity.HIGH
    assert inj.line == 14  # zizmor rows are 0-based
    assert inj.path == ".github/workflows/pr.yml"  # Windows separators normalised
    assert inj.title == "Code injection via template expansion (template-injection)"
    assert "attacker-controllable" in inj.message
    assert inj.references == ["https://docs.zizmor.sh/audits/#template-injection"]
    assert any(f.path == "action.yml" for f in by_rule["zizmor.template-injection"])


def test_low_confidence_drops_one_level() -> None:
    art = next(f for f in zizmor.parse(load("zizmor.json")) if f.rule_id == "zizmor.artipacked")
    assert art.severity == Severity.LOW  # medium severity, low confidence
    assert art.notes == ["lowered: zizmor reports low confidence"]


@pytest.mark.parametrize(
    ("severity", "confidence", "expected"),
    [
        ("High", "High", Severity.HIGH),
        ("High", "Medium", Severity.HIGH),
        ("High", "Low", Severity.MEDIUM),
        ("Medium", "High", Severity.MEDIUM),
        ("Medium", "Low", Severity.LOW),
        ("Low", "High", Severity.LOW),
        ("Low", "Low", Severity.INFO),
        ("Informational", "High", Severity.LOW),
        ("Informational", "Low", Severity.INFO),
        ("Unknown", "High", Severity.MEDIUM),
    ],
)
def test_severity_mapping(severity: str, confidence: str, expected: Severity) -> None:
    assert zizmor.map_severity(severity, confidence)[0] == expected


def _shift(data: list[dict[str, Any]], rows: int) -> list[dict[str, Any]]:
    out = copy.deepcopy(data)
    for f in out:
        for loc in f["locations"]:
            pt = loc["concrete"]["location"]
            pt["start_point"]["row"] += rows
            pt["end_point"]["row"] += rows
            pt["offset_span"]["start"] += 100 * rows
    return out


def test_fingerprint_stable_across_line_and_step_index_shifts() -> None:
    a = zizmor.parse(load("zizmor.json"))
    shifted = _shift(load("zizmor.json"), 7)
    for f in shifted:  # a step inserted above: every step index moves by one
        for loc in f["locations"]:
            for part in loc["symbolic"]["route"]["route"]:
                if "Index" in part:
                    part["Index"] += 1
    b = zizmor.parse(shifted)
    assert [x.id for x in a] == [x.id for x in b]
    assert [x.line for x in a] != [x.line for x in b]


def test_fingerprints_distinguish_findings() -> None:
    findings = zizmor.parse(load("zizmor.json"))
    assert len({f.id for f in findings}) == len(findings)  # two unpinned-uses differ by action
    changed = load("zizmor.json")
    for f in changed:
        if f["ident"] == "template-injection":
            f["locations"][1]["concrete"]["feature"] = "echo something else"
    assert {f.id for f in zizmor.parse(changed)} != {f.id for f in findings}


def test_ignored_and_remote_findings_are_dropped() -> None:
    data = load("zizmor.json")
    data[0]["ignored"] = True
    for loc in data[1]["locations"]:
        loc["symbolic"]["key"] = {"Remote": {"slug": "o/r"}}
    assert len(zizmor.parse(data)) == len(load("zizmor.json")) - 2


def test_config_ignore_by_rule_tail(tmp_path: Path) -> None:
    findings = zizmor.parse(load("zizmor.json"))
    config = GuardConfig.model_validate({"ignore": [{"rule": "unpinned-uses", "reason": "tags are fine"}]})
    out = reduce(findings, config, tmp_path, set())
    unpinned = [f for f in out if f.rule_id == "zizmor.unpinned-uses"]
    assert unpinned and not any(f.kept for f in unpinned)
    assert all(f.kept for f in out if f.rule_id != "zizmor.unpinned-uses")


def test_plan_category_toggle() -> None:
    assert Plan.pr(GuardConfig(), "a..b").actions
    assert Plan.nightly(GuardConfig()).actions
    off = GuardConfig.model_validate({"categories": {"actions": False}})
    assert not Plan.pr(off, "a..b").actions and not Plan.base(off).actions
    assert not Plan.nightly(off).actions


def test_inputs_for(tmp_path: Path) -> None:
    assert zizmor.inputs_for(tmp_path) == []
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    (tmp_path / "action.yaml").write_text("name: x\n")
    assert zizmor.inputs_for(tmp_path) == [".github/workflows", "action.yaml"]


def test_no_workflows_means_nothing_to_scan_and_no_download(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(url: str, timeout: float = 300) -> bytes:
        raise AssertionError("must not download")

    monkeypatch.setattr(base, "_download", boom)
    r = zizmor.scan(tmp_path, tmp_path)
    assert r.status == "ran" and r.findings == []


def test_skipped_when_fetch_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / ".github" / "workflows").mkdir(parents=True)

    def fail(url: str, timeout: float = 300) -> bytes:
        raise OSError("offline")

    monkeypatch.setattr(base, "_download", fail)
    monkeypatch.setattr("shutil.which", lambda exe: None)
    r = zizmor.scan(tmp_path, tmp_path)
    assert r == ScanResult("zizmor", "skipped", [], "zizmor unavailable")


def test_pinned_release_assets() -> None:
    spec = zizmor.SPEC
    assert spec.tag == "v1.31.1"
    for key in ("linux-x64", "windows-x64"):
        asset = spec.assets[key]
        assert len(asset.sha256) == 64 and asset.member
    assert spec.assets["linux-x64"].name == "zizmor-x86_64-unknown-linux-gnu.tar.gz"


def test_scan_runs_offline_without_token(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    monkeypatch.setattr(zizmor, "install", lambda spec: Path("zizmor-fake"))
    seen: dict[str, Any] = {}

    def fake_run(args: list[str], cwd: Path, **kw: Any) -> base.Proc:
        seen.update(args=args, cwd=cwd, **kw)
        kw["stdout_file"].write_text("[]")
        return base.Proc(0, "")

    monkeypatch.setattr(zizmor, "run", fake_run)
    r = zizmor.scan(tmp_path, tmp_path)
    assert r.status == "ran" and r.findings == []
    assert "--offline" in seen["args"] and "--no-exit-codes" in seen["args"]
    assert ".github/workflows" in seen["args"]
    assert not any("token" in a.lower() for a in seen["args"])
    assert seen["env"]["GITHUB_TOKEN"] is None and seen["env"]["GH_TOKEN"] is None


def test_scan_reports_failure_on_garbage_output(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    monkeypatch.setattr(zizmor, "install", lambda spec: Path("zizmor-fake"))

    def fake_run(args: list[str], cwd: Path, **kw: Any) -> base.Proc:
        kw["stdout_file"].write_text("not json")
        return base.Proc(0, "")

    monkeypatch.setattr(zizmor, "run", fake_run)
    assert zizmor.scan(tmp_path, tmp_path).status == "failed"


def test_run_can_capture_stdout(tmp_path: Path) -> None:
    out = tmp_path / "o.txt"
    proc = base.run([sys.executable, "-c", "print('hi')"], tmp_path, stdout_file=out)
    assert proc.code == 0 and out.read_text().strip() == "hi"
    assert base.run([sys.executable, "-c", "print('x')"], tmp_path).code == 0  # default still discards


def test_run_env_none_removes_a_variable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "t-not-real")
    out = tmp_path / "o.txt"
    code = "import os,sys; sys.stdout.write(repr(os.environ.get('GITHUB_TOKEN')))"
    base.run([sys.executable, "-c", code], tmp_path, env={"GITHUB_TOKEN": None}, stdout_file=out)
    assert out.read_text() == "None"
