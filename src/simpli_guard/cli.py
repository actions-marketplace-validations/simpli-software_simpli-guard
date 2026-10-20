"""Console entry point: `simpli-guard pr | nightly | aggregate | local`."""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from simpli_guard import aggregate as agg
from simpli_guard import noise
from simpli_guard.config import GuardConfig, load_config
from simpli_guard.github import GitHub, GitHubError
from simpli_guard.issues import reconcile
from simpli_guard.models import Category, Finding
from simpli_guard.render import (
    PR_MARKER,
    LinkContext,
    counts_line,
    no_new_findings,
    pr_comment,
    report_json,
    report_md,
)
from simpli_guard.scan import Diff, Plan, git, run_plan, split_new, worktree
from simpli_guard.scanners.base import ScanResult
from simpli_guard.scanners.kev import load_kev
from simpli_guard.triage import TriageSettings, TriageStats, triage

log = logging.getLogger("simpli_guard")

REPORT_JSON = "simpli-guard-report.json"
REPORT_MD = "simpli-guard-report.md"


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


def _summary(text: str) -> None:
    path = _env("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(text + "\n")


def _triage_client(config: GuardConfig, disabled: bool) -> Any | None:
    if disabled or not config.triage.enabled or not _env("ANTHROPIC_API_KEY"):
        return None
    import anthropic

    return anthropic.Anthropic()


def _run_triage(client: Any | None, config: GuardConfig, findings: list[Finding], root: Path) -> TriageStats:
    if client is None:
        return TriageStats()
    settings = TriageSettings(
        model=config.triage.model, effort=config.triage.effort, max_findings=config.triage.max_findings
    )
    return triage(client, settings, findings, root, config.test_paths)


def _all(results: list[ScanResult]) -> list[Finding]:
    return [f for r in results for f in r.findings]


def _kev_if_needed(findings: list[Finding]) -> set[str]:
    if any(f.category in (Category.DEPENDENCY, Category.CONTAINER) for f in findings):
        return load_kev()
    return set()


# ---------- PR / local ----------


@dataclass
class PrOutcome:
    diff: Diff
    failed: bool
    body: str
    tool_notes: list[str]


def analyse_pr(
    root: Path, base_sha: str, head_sha: str, config: GuardConfig, client: Any | None, links: LinkContext
) -> PrOutcome:
    head_results = run_plan(root, Plan.pr(config, f"{base_sha}..{head_sha}"), config)
    with worktree(root, base_sha) as base_root:
        base_results = run_plan(base_root, Plan.base(config), config)
    raw = _all(head_results)
    findings = noise.reduce(raw, config, root, _kev_if_needed(raw))
    head_tools = {r.tool for r in head_results if r.status == "ran"}
    diff = split_new(findings, base_results, head_tools)
    _run_triage(client, config, diff.new, root)
    failed = any(f.kept and f.severity.at_least(config.fail_on) for f in diff.new)

    notes = [f"{r.tool} {r.status} ({r.message})." for r in head_results if r.status != "ran"]
    if diff.undiffable_tools:
        notes.append(
            f"Could not scan the base with {', '.join(sorted(diff.undiffable_tools))}; "
            "their findings are listed as pre-existing."
        )
    body = pr_comment(config.name, diff.new, diff.existing, links, config.fail_on.value, failed, notes)
    return PrOutcome(diff, failed, body, notes)


def cmd_pr(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    config = load_config(root)
    event = json.loads(Path(_env("GITHUB_EVENT_PATH")).read_text(encoding="utf-8"))
    pr = event.get("pull_request")
    if not pr:
        log.error("pr mode needs a pull_request event")
        return 2
    number = int(pr["number"])
    base_sha, head_sha = pr["base"]["sha"], pr["head"]["sha"]
    repo = _env("GITHUB_REPOSITORY")
    links = LinkContext(_env("GITHUB_SERVER_URL", "https://github.com"), repo, head_sha)
    out = analyse_pr(root, base_sha, head_sha, config, _triage_client(config, args.no_triage), links)
    _summary(out.body)
    kept_new = [f for f in out.diff.new if f.kept]
    if args.dry_run:
        print(out.body)
    else:
        try:
            gh = GitHub(_env("GITHUB_TOKEN"), repo)
            existing = gh.find_comment(number, PR_MARKER)
            if kept_new or [f for f in out.diff.new if not f.kept]:
                if existing:
                    gh.update_comment(existing, out.body)
                else:
                    gh.create_comment(number, out.body)
            elif existing:
                gh.update_comment(existing, no_new_findings(config.name, out.diff.existing))
        except GitHubError as e:
            log.warning("could not post the PR comment (%s)", e.status)
    log.info("new findings: %s; pre-existing: %s", counts_line(kept_new), counts_line(out.diff.existing))
    return 1 if out.failed else 0


def cmd_local(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    config = load_config(root)
    base_sha = git(root, "rev-parse", "--verify", args.base + "^{commit}")
    head_sha = git(root, "rev-parse", "HEAD")
    out = analyse_pr(root, base_sha, head_sha, config, _triage_client(config, args.no_triage), LinkContext())
    print(out.body)
    return 1 if out.failed else 0


# ---------- nightly ----------


def cmd_nightly(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    config = load_config(root)
    results = run_plan(root, Plan.nightly(config), config)
    raw = _all(results)
    findings = noise.reduce(raw, config, root, _kev_if_needed(raw))
    stats = _run_triage(_triage_client(config, args.no_triage), config, findings, root)

    repo = _env("GITHUB_REPOSITORY")
    sha = _env("GITHUB_SHA") or git(root, "rev-parse", "HEAD")
    links = LinkContext(_env("GITHUB_SERVER_URL", "https://github.com"), repo, sha)
    tools = {r.tool: {"status": r.status, "count": len(r.findings), "message": r.message} for r in results}
    if stats.asked:
        tools["claude-triage"] = {
            "status": "failed" if stats.failed else "ran",
            "count": stats.suppressed,
            "message": f"{stats.asked} reviewed, {stats.suppressed} suppressed",
        }
    out_dir = Path(args.out).resolve() if args.out else root
    (out_dir / REPORT_JSON).write_text(
        report_json(findings, repo, sha, _env("GITHUB_REF"), tools, config.name), encoding="utf-8"
    )
    md = report_md(config.name, findings, links, tools)
    (out_dir / REPORT_MD).write_text(md, encoding="utf-8")
    _summary(md)

    ran = {r.tool for r in results if r.status == "ran"}
    if repo and _env("GITHUB_TOKEN"):
        try:
            gh = GitHub(_env("GITHUB_TOKEN"), repo)
            res = reconcile(gh, findings, ran, links, config.name, dry_run=args.dry_run)
            log.info(
                "issues: %d opened, %d closed, %d still open",
                len(res.opened),
                len(res.closed),
                res.still_open,
            )
        except GitHubError as e:
            log.warning("issue sync failed (%s)", e.status)
    kept = [f for f in findings if f.kept]
    log.info("open findings: %s", counts_line(kept))
    return 0


# ---------- aggregate ----------


def cmd_aggregate(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    token = _env("GUARD_READ_TOKEN")
    if not token:
        log.error("aggregate mode needs GUARD_READ_TOKEN")
        return 2
    cfg = agg.load_repos(root / args.repos)
    reports = [agg.fetch_report(GitHub(token, f"{cfg.owner}/{name}"), name) for name in cfg.repos]
    server = _env("GITHUB_SERVER_URL", "https://github.com")
    written = agg.write_reports(root / "reports", cfg, reports, server)
    agg.commit_and_push(root, written, args.dry_run)
    for r in reports:
        log.info("%s: %s %s", r.repo, r.status, json.dumps(r.counts, sort_keys=True))
    return 0


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)  # request URLs only at debug
    p = argparse.ArgumentParser(prog="simpli-guard")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("pr", "nightly", "aggregate", "local"):
        sp = sub.add_parser(name)
        sp.add_argument("--root", default=".", help="repository root (default: current directory)")
        sp.add_argument("--dry-run", action="store_true", help="no comments, issues or commits")
        sp.add_argument("--no-triage", action="store_true", help="skip Claude triage")
        if name == "local":
            sp.add_argument("--base", required=True, help="git ref to diff against, e.g. origin/main")
        if name == "nightly":
            sp.add_argument("--out", default="", help="directory for the report files (default: root)")
        if name == "aggregate":
            sp.add_argument("--repos", default="repos.json")
    args = p.parse_args(argv)
    handlers = {"pr": cmd_pr, "nightly": cmd_nightly, "aggregate": cmd_aggregate, "local": cmd_local}
    return handlers[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
