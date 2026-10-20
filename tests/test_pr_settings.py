"""PR mode takes its settings from the base commit and never lets a PR approve its own suppression."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from simpli_guard import cli
from simpli_guard.config import DEFAULT_OVERRIDE_LABEL, GuardConfig, load_config
from simpli_guard.models import Category, Finding, Severity, code_fingerprint
from simpli_guard.scan import Plan
from simpli_guard.scanners import base as scanner_base
from simpli_guard.scanners import gitleaks
from simpli_guard.scanners.base import ScanResult

SECRET_MARK = "SECRETVALUE"
INLINE_HIGH = "# simpli-guard: ignore eval-detected reviewed, input is constant\nresult = eval(expr)\n"
INLINE_MED = "# simpli-guard: ignore exec-detected reviewed, input is constant\nexec(code)\n"


def git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def commit(root: Path, files: dict[str, str], msg: str) -> str:
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", msg)
    return git(root, "rev-parse", "HEAD")


def fake_scanners(root: Path, plan: Plan, config: GuardConfig) -> list[ScanResult]:
    """Stands in for the scanners. `eval(` is a high SAST finding and `exec(` a medium one. A
    `*.env` file holding SECRETVALUE is a secret, hidden only by the `.gitleaksignore` found in the
    directory gitleaks is told to run from (which is where the real gitleaks reads it)."""
    findings: list[Finding] = []
    for p in sorted(root.rglob("*.py")):
        rel = p.relative_to(root).as_posix()
        for n, text in enumerate(p.read_text(encoding="utf-8").splitlines(), start=1):
            for needle, sev in (("eval(", Severity.HIGH), ("exec(", Severity.MEDIUM)):
                if needle in text and "simpli-guard:" not in text:
                    rule = f"python.lang.security.audit.{needle[:-1]}-detected"
                    findings.append(
                        Finding(
                            id=code_fingerprint("opengrep", rule, rel, text),
                            tool="opengrep",
                            category=Category.SAST,
                            severity=sev,
                            title=f"{needle} used",
                            path=rel,
                            line=n,
                            rule_id=rule,
                        )
                    )
    results = [ScanResult("opengrep", "ran", findings)]
    if plan.secrets:
        ignore_file = (plan.secrets_root or root) / ".gitleaksignore"
        ignored = ignore_file.read_text(encoding="utf-8").split() if ignore_file.is_file() else []
        secrets: list[Finding] = []
        for p in sorted(root.rglob("*.env")):
            rel = p.relative_to(root).as_posix()
            if SECRET_MARK in p.read_text(encoding="utf-8") and rel not in ignored:
                secrets.append(
                    Finding(
                        id=code_fingerprint("gitleaks", "generic-api-key", rel, "sk_l:30"),
                        tool="gitleaks",
                        category=Category.SECRET,
                        severity=Severity.HIGH,
                        title="API key (sk_l)",
                        path=rel,
                        rule_id="generic-api-key",
                        masked="sk_l",
                    )
                )
        results.append(ScanResult("gitleaks", "ran", secrets))
    return results


class Repo:
    def __init__(self, tmp: Path, base_files: dict[str, str]) -> None:
        self.tmp = tmp
        self.root = tmp / "repo"
        self.root.mkdir()
        git(self.root, "init", "-q", "-b", "main")
        self.base = commit(self.root, {"README.md": "x\n", **base_files}, "base")
        self.head = ""

    def pr(self, files: dict[str, str]) -> None:
        self.head = commit(self.root, files, "pr")

    def write_event(self, labels: tuple[str, ...], base: str | None) -> None:
        event = {
            "pull_request": {
                "number": 7,
                "base": {"sha": base or self.base},
                "head": {"sha": self.head},
                "labels": [{"name": n} for n in labels],
            }
        }
        path = self.tmp / "event.json"
        path.write_text(json.dumps(event), encoding="utf-8")
        self.event_path = str(path)


def run_pr(
    repo: Repo,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    labels: tuple[str, ...] = (),
) -> tuple[int, str]:
    repo.write_event(labels, None)
    monkeypatch.setenv("GITHUB_EVENT_PATH", repo.event_path)
    monkeypatch.setattr(cli, "run_plan", fake_scanners)
    capsys.readouterr()
    code = cli.main(["pr", "--root", str(repo.root), "--dry-run", "--no-triage"])
    return code, capsys.readouterr().out


def test_config_ignore_added_by_the_pr_does_not_silence_its_own_finding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    repo = Repo(tmp_path, {"app.py": "x = 1\n"})
    cfg = {"ignore": [{"rule": "eval-detected", "reason": "trust me"}], "failOn": "critical"}
    repo.pr({"app.py": "x = eval(y)\n", ".simpli-guard/config.json": json.dumps(cfg)})
    code, out = run_pr(repo, monkeypatch, capsys)
    assert code == 1
    assert "eval( used" in out
    assert "Scan settings changed in this PR" in out and ".simpli-guard/config.json" in out
    assert "apply after merge" in out


def test_inline_ignore_added_by_the_pr_fails_without_the_label_and_passes_with_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    repo = Repo(tmp_path, {"app.py": "x = 1\n"})
    repo.pr({"app.py": "x = 1\n" + INLINE_HIGH})
    code, out = run_pr(repo, monkeypatch, capsys)
    assert code == 1
    assert "Suppressions added in this PR (not applied)" in out
    assert "reviewed, input is constant" in out
    assert f"`{DEFAULT_OVERRIDE_LABEL}`" in out

    code, out = run_pr(repo, monkeypatch, capsys, labels=("bug", "Security-Override"))
    assert code == 0
    assert "Suppressions added in this PR (applied)" in out
    assert "(not applied)" not in out
    assert "label is set" in out


def test_override_label_name_comes_from_the_base_config_not_the_pr(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    base_cfg = json.dumps({"overrideLabel": "sec-approved"})
    repo = Repo(tmp_path, {"app.py": "x = 1\n", ".simpli-guard/config.json": base_cfg})
    pr_cfg = json.dumps({"overrideLabel": "bug"})  # the PR tries to name an ordinary label
    repo.pr({"app.py": "x = 1\n" + INLINE_HIGH, ".simpli-guard/config.json": pr_cfg})
    assert run_pr(repo, monkeypatch, capsys, labels=("bug",))[0] == 1
    assert run_pr(repo, monkeypatch, capsys, labels=("security-override",))[0] == 1
    assert run_pr(repo, monkeypatch, capsys, labels=("sec-approved",))[0] == 0


def test_copying_an_existing_ignore_comment_does_not_launder_a_new_finding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    repo = Repo(tmp_path, {"app.py": INLINE_HIGH})  # one reviewed eval is already on the base
    repo.pr({"app.py": INLINE_HIGH + INLINE_HIGH.replace("expr", "other")})
    code, out = run_pr(repo, monkeypatch, capsys)
    assert code == 1
    assert "(not applied)" in out


def test_gitleaksignore_added_by_the_pr_does_not_hide_its_secret(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    repo = Repo(tmp_path, {"app.py": "x = 1\n"})
    repo.pr({"prod.env": f"KEY={SECRET_MARK}\n", ".gitleaksignore": "prod.env\n"})
    code, out = run_pr(repo, monkeypatch, capsys)
    assert code == 1
    assert "API key" in out
    assert "`.gitleaksignore`" in out and "apply after merge" in out


def test_gitleaksignore_on_the_base_keeps_working(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    repo = Repo(tmp_path, {"app.py": "x = 1\n", ".gitleaksignore": "known.env\n"})
    repo.pr({"known.env": f"KEY={SECRET_MARK}\n"})
    code, out = run_pr(repo, monkeypatch, capsys)
    assert code == 0
    assert "no new findings" in out


def test_medium_finding_with_a_pr_added_ignore_is_suppressed_but_listed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    repo = Repo(tmp_path, {"app.py": "x = 1\n"})
    repo.pr({"app.py": "x = 1\n" + INLINE_MED})
    code, out = run_pr(repo, monkeypatch, capsys)
    assert code == 0
    assert "Suppressions added in this PR (applied)" in out
    assert "below **high**" in out
    assert "(not applied)" not in out
    assert "exec( used" in out


def test_ignores_already_on_the_base_keep_working(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    cfg = json.dumps({"ignore": [{"path": "scripts/**", "reason": "build helpers"}]})
    repo = Repo(tmp_path, {"app.py": INLINE_HIGH, ".simpli-guard/config.json": cfg})
    repo.pr({"app.py": "y = 2\n" + INLINE_HIGH, "scripts/gen.py": "eval(spec)\n"})
    code, out = run_pr(repo, monkeypatch, capsys)
    assert code == 0
    assert "Suppressions added" not in out
    assert "Scan settings changed" not in out


def test_fail_on_from_the_base_cannot_be_lowered_by_the_pr(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    repo = Repo(tmp_path, {"app.py": "x = 1\n", ".simpli-guard/config.json": json.dumps({"failOn": "high"})})
    repo.pr({"app.py": "eval(y)\n", ".simpli-guard/config.json": json.dumps({"failOn": "critical"})})
    assert run_pr(repo, monkeypatch, capsys)[0] == 1


def test_unreadable_base_fails_closed_without_scanning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = Repo(tmp_path, {"app.py": "x = 1\n"})
    repo.pr({"app.py": "eval(y)\n", ".simpli-guard/config.json": json.dumps({"failOn": "critical"})})
    scans: list[Path] = []

    def spy(root: Path, plan: Plan, config: GuardConfig) -> list[ScanResult]:
        scans.append(root)
        return []

    monkeypatch.setattr(cli, "run_plan", spy)
    repo.write_event((), "0" * 40)  # a base commit that is not in the checkout
    monkeypatch.setenv("GITHUB_EVENT_PATH", repo.event_path)
    assert cli.main(["pr", "--root", str(repo.root), "--dry-run", "--no-triage"]) == 2
    assert scans == []  # nothing was scanned with the PR's own settings


def test_invalid_base_config_fails_and_names_the_base(tmp_path: Path) -> None:
    (tmp_path / ".simpli-guard").mkdir()
    (tmp_path / ".simpli-guard" / "config.json").write_text("{not json")
    with pytest.raises(SystemExit) as e:
        load_config(tmp_path, "the base commit")
    assert "the base commit" in str(e.value)


def test_override_label_config() -> None:
    assert GuardConfig().override_label == "security-override"
    assert GuardConfig.model_validate({"overrideLabel": " ok "}).override_label == "ok"
    with pytest.raises(ValueError, match="overrideLabel"):
        GuardConfig.model_validate({"overrideLabel": "  "})


# ---------- gitleaks wiring ----------


def _capture_gitleaks(monkeypatch: pytest.MonkeyPatch) -> list[tuple[list[str], Path]]:
    calls: list[tuple[list[str], Path]] = []
    monkeypatch.setattr(gitleaks, "install", lambda spec: Path("gitleaks-fake"))

    def fake_run(args: list[str], cwd: Path, **kw: Any) -> scanner_base.Proc:
        calls.append((args, cwd))
        Path(args[args.index("--report-path") + 1]).write_text("[]")
        return scanner_base.Proc(0, "")

    monkeypatch.setattr(gitleaks, "run", fake_run)
    return calls


def test_gitleaks_runs_from_the_given_root_and_can_ignore_allow_comments(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = _capture_gitleaks(monkeypatch)
    (tmp_path / ".gitleaks.toml").write_text("")
    gitleaks.scan(tmp_path, tmp_path, "a..b", ignore_allow=True)
    args, cwd = calls[0]
    assert cwd == tmp_path and "--ignore-gitleaks-allow" in args
    assert args[args.index("--config") + 1] == str(tmp_path / ".gitleaks.toml")
    gitleaks.scan(tmp_path, tmp_path, "a..b")
    assert "--ignore-gitleaks-allow" not in calls[1][0]


def test_pr_plan_scans_secrets_in_the_base_checkout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = Repo(tmp_path, {"app.py": "x = 1\n"})
    repo.pr({"app.py": "x = 2\n"})
    plans: list[tuple[Path, Plan]] = []

    def spy(root: Path, plan: Plan, config: GuardConfig) -> list[ScanResult]:
        plans.append((root, plan))
        return []

    repo.write_event((), None)
    monkeypatch.setenv("GITHUB_EVENT_PATH", repo.event_path)
    monkeypatch.setattr(cli, "run_plan", spy)
    assert cli.main(["pr", "--root", str(repo.root), "--dry-run", "--no-triage"]) == 0
    head_root, head_plan = plans[0]
    assert head_root == repo.root.resolve()
    assert head_plan.secrets_root is not None and head_plan.secrets_root != head_root
    assert head_plan.ignore_gitleaks_allow is True
    assert plans[1][0] == head_plan.secrets_root  # the base checkout
