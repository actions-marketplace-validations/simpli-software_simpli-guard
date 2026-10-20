"""Cross-repo overview, run in the simpli-guard repository itself.

For each repository in `repos.json` it downloads the newest
`simpli-guard-report` artifact from a successful run, then writes
`reports/README.md` (one table for all repos) and `reports/<repo>.md`, and
commits them. Reports only ever contain masked secret prefixes; text is
scrubbed again here as a second line of defence.
"""

from __future__ import annotations

import io
import json
import logging
import subprocess
import zipfile
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from pydantic import BaseModel, Field

from simpli_guard.masking import scrub
from simpli_guard.models import SEVERITY_ORDER

log = logging.getLogger(__name__)

ARTIFACT = "simpli-guard-report"
REPORT_FILE = "simpli-guard-report.json"
MAX_ARTIFACTS_CHECKED = 10
BOT_NAME = "github-actions[bot]"
BOT_EMAIL = "41898282+github-actions[bot]@users.noreply.github.com"


class ReposFile(BaseModel):
    owner: str
    repos: list[str] = Field(default_factory=list)
    title: str = "Security overview"


class ArtifactAPI(Protocol):
    def list_artifacts(self, name: str) -> list[dict[str, Any]]: ...
    def workflow_run(self, run_id: int) -> dict[str, Any]: ...
    def download_artifact(self, artifact_id: int) -> bytes: ...


@dataclass
class RepoReport:
    repo: str
    status: str  # ok | no-artifact | error
    scanned_at: str | None = None
    sha: str = ""
    run_url: str = ""
    counts: dict[str, int] = field(default_factory=dict)
    findings: list[dict[str, Any]] = field(default_factory=list)
    message: str = ""

    def open_findings(self) -> list[dict[str, Any]]:
        return [f for f in self.findings if (f.get("triage") or {}).get("status", "kept") == "kept"]

    def top(self, n: int = 5) -> list[dict[str, Any]]:
        sev_rank = {s.value: i for i, s in enumerate(SEVERITY_ORDER)}
        hot = [f for f in self.open_findings() if f.get("severity") in ("critical", "high")]
        hot.sort(key=lambda f: (sev_rank.get(str(f.get("severity")), 9), str(f.get("path"))))
        return hot[:n]


def load_repos(path: Path) -> ReposFile:
    return ReposFile.model_validate(json.loads(path.read_text(encoding="utf-8")))


def _read_zip(blob: bytes) -> dict[str, Any]:
    with zipfile.ZipFile(io.BytesIO(blob)) as z:
        data: dict[str, Any] = json.loads(z.read(REPORT_FILE).decode("utf-8"))
        return data


def fetch_report(gh: ArtifactAPI, repo: str) -> RepoReport:
    try:
        arts = [a for a in gh.list_artifacts(ARTIFACT) if not a.get("expired")]
        for a in arts[:MAX_ARTIFACTS_CHECKED]:
            run_id = (a.get("workflow_run") or {}).get("id")
            if not run_id:
                continue
            run = gh.workflow_run(int(run_id))
            if run.get("conclusion") != "success":
                continue
            data = _read_zip(gh.download_artifact(int(a["id"])))
            counts = {str(k): int(v) for k, v in (data.get("counts") or {}).items()}
            return RepoReport(
                repo=repo,
                status="ok",
                scanned_at=str(data.get("generated_at") or a.get("created_at") or ""),
                sha=str(data.get("sha", "")),
                run_url=str(run.get("html_url", "")),
                counts=counts,
                findings=list(data.get("findings") or []),
            )
        return RepoReport(repo=repo, status="no-artifact", message="no successful scan yet")
    except Exception as e:  # one repo's failure must not stop the overview
        log.warning("%s: could not fetch report (%s)", repo, type(e).__name__)
        return RepoReport(repo=repo, status="error", message=type(e).__name__)


def _link(owner: str, r: RepoReport, f: dict[str, Any], server: str) -> str:
    path, line = str(f.get("path") or ""), f.get("line")
    text = f"{path}:{line}" if line else path
    if f.get("category") == "surface" or not r.sha or not path:
        return f"`{scrub(text)}`"
    anchor = f"#L{line}" if line else ""
    return f"[`{text}`]({server}/{owner}/{r.repo}/blob/{r.sha}/{path}{anchor})"


def _cell(text: str) -> str:
    return scrub(text).replace("|", "\\|").replace("\n", " ")


def render_overview(cfg: ReposFile, reports: list[RepoReport], server: str = "https://github.com") -> str:
    now = datetime.now(UTC)
    lines = [
        f"# {cfg.title}",
        "",
        f"Updated {now:%Y-%m-%d %H:%M} UTC from each repository's latest successful nightly scan.",
        "",
        "| Repository | Last scan | Critical | High | Medium | Low | Top open critical/high |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in reports:
        name = f"[{r.repo}]({r.repo}.md)"
        if r.status != "ok":
            lines.append(f"| {name} | {r.message or r.status} | - | - | - | - | |")
            continue
        top = "<br>".join(
            f"{f.get('severity')}: {_cell(str(f.get('title', '')))[:80]} {_link(cfg.owner, r, f, server)}"
            for f in r.top()
        )
        c = r.counts
        when = (r.scanned_at or "")[:16].replace("T", " ")
        lines.append(
            f"| {name} | {when} | {c.get('critical', 0)} | {c.get('high', 0)} | {c.get('medium', 0)} "
            f"| {c.get('low', 0)} | {top} |"
        )
    return "\n".join(lines) + "\n"


def render_repo(cfg: ReposFile, r: RepoReport, server: str = "https://github.com") -> str:
    lines = [f"# {cfg.owner}/{r.repo}", "", "[Back to overview](README.md)", ""]
    if r.status != "ok":
        lines.append(f"No report available: {r.message or r.status}.")
        return "\n".join(lines) + "\n"
    lines.append(
        f"Last scan {r.scanned_at} at `{r.sha[:12]}`" + (f" ([run]({r.run_url}))." if r.run_url else ".")
    )
    lines.append("")
    open_f = r.open_findings()
    for sev in SEVERITY_ORDER:
        group = [f for f in open_f if f.get("severity") == sev.value]
        if not group:
            continue
        lines.append(f"## {sev.value.capitalize()} ({len(group)})")
        for f in group:
            pkg = f" `{f.get('package')}@{f.get('version')}`" if f.get("package") else ""
            fix = f" -> {f.get('fixed_version')}" if f.get("fixed_version") else ""
            lines.append(
                f"- **{_cell(str(f.get('title', '')))}** - {_link(cfg.owner, r, f, server)} - "
                f"{f.get('tool')}{pkg}{fix}"
            )
        lines.append("")
    suppressed = len(r.findings) - len(open_f)
    if suppressed:
        lines.append(f"{suppressed} further finding(s) suppressed as noise (see the run's report artifact).")
    return "\n".join(lines).strip() + "\n"


def write_reports(out_dir: Path, cfg: ReposFile, reports: list[RepoReport], server: str) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    written = [out_dir / "README.md"]
    written[0].write_text(render_overview(cfg, reports, server), encoding="utf-8")
    for r in reports:
        p = out_dir / f"{r.repo}.md"
        p.write_text(render_repo(cfg, r, server), encoding="utf-8")
        written.append(p)
    return written


def commit_and_push(root: Path, paths: list[Path], dry_run: bool) -> bool:
    ident = ["-c", f"user.name={BOT_NAME}", "-c", f"user.email={BOT_EMAIL}"]

    def git(*args: str) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(["git", *ident, *args], cwd=root, check=False, capture_output=True, timeout=300)

    git("add", "--", *[str(p.relative_to(root)) for p in paths])
    if git("diff", "--cached", "--quiet").returncode == 0:
        log.info("reports unchanged; nothing to commit")
        return False
    if dry_run:
        log.info("dry run: reports written, not committed")
        git("reset", "-q", "--", *[str(p.relative_to(root)) for p in paths])
        return False
    if git("commit", "-q", "-m", "reports: update security overview").returncode != 0:
        log.warning("git commit failed")
        return False
    if git("push", "-q").returncode != 0:
        log.warning("git push failed")
        return False
    return True
