from __future__ import annotations

import io
import json
import subprocess
import zipfile
from pathlib import Path
from typing import Any

import pytest

from simpli_guard import aggregate as agg
from simpli_guard import cli
from simpli_guard.config import GuardConfig
from simpli_guard.models import Severity
from simpli_guard.render import LinkContext, report_json
from simpli_guard.scanners import gitleaks
from simpli_guard.scanners.base import ScanResult

from .conftest import FIXTURE_SECRETS, load, make_finding


def report_zip(findings: list[Any]) -> bytes:
    tools = {"opengrep": {"status": "ran", "count": len(findings), "message": ""}}
    body = report_json(findings, "example-org/app", "abcdef1234567890", "refs/heads/main", tools, "Scan")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(agg.REPORT_FILE, body)
    return buf.getvalue()


class FakeArtifacts:
    def __init__(
        self, artifacts: list[dict[str, Any]], runs: dict[int, dict[str, Any]], blobs: dict[int, bytes]
    ):
        self.artifacts, self.runs, self.blobs = artifacts, runs, blobs
        self.downloaded: list[int] = []

    def list_artifacts(self, name: str) -> list[dict[str, Any]]:
        assert name == "simpli-guard-report"
        return self.artifacts

    def workflow_run(self, run_id: int) -> dict[str, Any]:
        return self.runs[run_id]

    def download_artifact(self, artifact_id: int) -> bytes:
        self.downloaded.append(artifact_id)
        return self.blobs[artifact_id]


class Broken(FakeArtifacts):
    def list_artifacts(self, name: str) -> list[dict[str, Any]]:
        raise RuntimeError("403")


def test_fetch_uses_latest_successful_run_and_renders() -> None:
    crit = make_finding(
        snippet="c", severity=Severity.CRITICAL, path="app/x.py", line=7, title="SQL injection"
    )
    secrets = gitleaks.parse(load("gitleaks.json"))
    good = report_zip([crit, *secrets, make_finding(snippet="m", severity=Severity.MEDIUM)])
    api = FakeArtifacts(
        artifacts=[
            {"id": 2, "workflow_run": {"id": 20}, "created_at": "2026-10-14T03:30:00Z"},
            {"id": 1, "workflow_run": {"id": 10}, "created_at": "2026-10-13T03:30:00Z"},
            {"id": 0, "workflow_run": {"id": 5}, "expired": True},
        ],
        runs={20: {"conclusion": "failure"}, 10: {"conclusion": "success", "html_url": "https://run/10"}},
        blobs={1: good},
    )
    r = agg.fetch_report(api, "app")
    assert r.status == "ok" and api.downloaded == [1]
    assert r.counts == {"critical": 2, "high": 1, "medium": 1}
    assert len(r.top()) == 3

    empty = agg.fetch_report(FakeArtifacts([], {}, {}), "new-repo")
    assert empty.status == "no-artifact"
    broken = agg.fetch_report(Broken([], {}, {}), "locked")
    assert broken.status == "error"

    cfg = agg.ReposFile(owner="example-org", repos=["app", "new-repo", "locked"])
    overview = agg.render_overview(cfg, [r, empty, broken])
    assert "| [app](app.md) | 2026-" in overview
    assert "| [new-repo](new-repo.md) | no successful scan yet |" in overview
    assert "https://github.com/example-org/app/blob/abcdef1234567890/app/x.py#L7" in overview
    page = agg.render_repo(cfg, r)
    assert "## Critical (2)" in page and "SQL injection" in page
    assert "No report available" in agg.render_repo(cfg, empty)
    for text in (overview, page):
        for s in FIXTURE_SECRETS:
            assert s not in text


def test_write_reports_and_commit_dry_run(tmp_path: Path) -> None:
    subprocess.run(["git", "init", "-q", "-b", "main", str(tmp_path)], check=True)
    cfg = agg.ReposFile(owner="o", repos=["a"])
    written = agg.write_reports(
        tmp_path / "reports", cfg, [agg.RepoReport("a", "no-artifact")], "https://github.com"
    )
    assert [p.name for p in written] == ["README.md", "a.md"]
    assert agg.commit_and_push(tmp_path, written, dry_run=True) is False
    status = subprocess.run(["git", "status", "--porcelain"], cwd=tmp_path, capture_output=True, text=True)
    assert "?? reports/" in status.stdout  # left unstaged, nothing committed


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def test_local_pr_flow_new_vs_existing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    (repo / "a.py").write_text("x = 1\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "base")
    (repo / "b.py").write_text("y = 2\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "head")

    old = make_finding(snippet="old", path="a.py", severity=Severity.HIGH)
    new = make_finding(snippet="new", path="b.py", severity=Severity.HIGH)
    seen_roots: list[Path] = []

    def fake_run_plan(root: Path, plan: Any, config: GuardConfig) -> list[ScanResult]:
        seen_roots.append(root)
        is_base = (root / "b.py").exists() is False
        assert plan.secrets is (not is_base)
        if is_base:
            return [ScanResult("opengrep", "ran", [old.model_copy(deep=True)])]
        assert plan.secrets_range and plan.secrets_range.endswith(_git(repo, "rev-parse", "HEAD"))
        return [ScanResult("opengrep", "ran", [old.model_copy(deep=True), new.model_copy(deep=True)])]

    monkeypatch.setattr(cli, "run_plan", fake_run_plan)
    code = cli.main(["local", "--root", str(repo), "--base", "HEAD~1", "--no-triage"])
    out = capsys.readouterr().out
    assert code == 1  # one new HIGH finding, failOn high
    assert "1 new finding(s)" in out and "b.py" in out
    assert "Pre-existing findings on the base branch" in out
    assert len(seen_roots) == 2 and seen_roots[0] == repo.resolve()
    assert _git(repo, "worktree", "list").count("\n") == 0  # base worktree cleaned up

    # Raise the bar: the same PR passes with failOn critical.
    (repo / ".simpli-guard").mkdir()
    (repo / ".simpli-guard" / "config.json").write_text(json.dumps({"failOn": "critical"}))
    assert cli.main(["local", "--root", str(repo), "--base", "HEAD~1", "--no-triage"]) == 0


def test_link_context_skips_surface() -> None:
    f = make_finding()
    assert (
        LinkContext("https://github.com", "o/r", "sha").url(f)
        == "https://github.com/o/r/blob/sha/app/x.py#L3"
    )
    assert LinkContext().url(f) is None
