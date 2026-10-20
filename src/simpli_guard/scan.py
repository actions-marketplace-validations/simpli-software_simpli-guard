"""Running the scanners and working out which findings a change introduced."""

from __future__ import annotations

import logging
import shutil
import subprocess
import tempfile
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from simpli_guard.config import CONFIG_PATH, GuardConfig
from simpli_guard.models import Category, Finding
from simpli_guard.scanners import gitleaks, opengrep, osv, surface, trivy, zizmor
from simpli_guard.scanners.base import ScanResult

log = logging.getLogger(__name__)


@dataclass
class Plan:
    sast: bool = True
    deps: bool = True
    secrets: bool = True
    secrets_range: str | None = None  # None = full history
    # Where gitleaks runs. PR mode points this at the base checkout so the PR's own
    # .gitleaks.toml / .gitleaksignore are never read. None = the scanned root.
    secrets_root: Path | None = None
    ignore_gitleaks_allow: bool = False
    iac: bool = True
    actions: bool = True
    images: bool = False
    licenses: bool = False
    surface: bool = False

    @classmethod
    def pr(cls, config: GuardConfig, log_range: str) -> Plan:
        return cls(
            sast=config.enabled(Category.SAST),
            deps=config.enabled(Category.DEPENDENCY),
            secrets=config.enabled(Category.SECRET),
            secrets_range=log_range,
            iac=config.enabled(Category.IAC),
            actions=config.enabled(Category.ACTIONS),
        )

    @classmethod
    def base(cls, config: GuardConfig) -> Plan:
        """The base side of a PR diff: secrets are range-scanned on head only."""
        p = cls.pr(config, "")
        p.secrets = False
        return p

    @classmethod
    def nightly(cls, config: GuardConfig) -> Plan:
        return cls(
            sast=config.enabled(Category.SAST),
            deps=config.enabled(Category.DEPENDENCY),
            secrets=config.enabled(Category.SECRET),
            secrets_range=None,
            iac=config.enabled(Category.IAC),
            actions=config.enabled(Category.ACTIONS),
            images=config.enabled(Category.CONTAINER),
            licenses=config.enabled(Category.LICENSE),
            surface=config.enabled(Category.SURFACE) and bool(config.surface.urls),
        )


Step = Callable[[], ScanResult]


def run_plan(root: Path, plan: Plan, config: GuardConfig) -> list[ScanResult]:
    results: list[ScanResult] = []
    with tempfile.TemporaryDirectory(prefix="simpli-guard-") as tmp:
        work = Path(tmp)
        steps: list[tuple[bool, Step]] = [
            (plan.sast, lambda: opengrep.scan(root, work)),
            (plan.deps, lambda: osv.scan(root, work)),
            (
                plan.secrets,
                lambda: gitleaks.scan(
                    plan.secrets_root or root, work, plan.secrets_range, plan.ignore_gitleaks_allow
                ),
            ),
            (plan.iac, lambda: trivy.scan_config(root, work)),
            (plan.actions, lambda: zizmor.scan(root, work)),
            (plan.images, lambda: trivy.scan_images(root, work)),
            (plan.licenses, lambda: trivy.scan_licenses(root, work)),
            (plan.surface, lambda: surface.scan(config.surface.urls)),
        ]
        for enabled, step in steps:
            if not enabled:
                continue
            try:
                r = step()
            except Exception as e:  # one broken scanner must not lose the others' results
                log.warning("scanner crashed (%s)", type(e).__name__)
                continue
            level = logging.INFO if r.status == "ran" else logging.WARNING
            log.log(level, "%s: %s, %d findings %s", r.tool, r.status, len(r.findings), r.message)
            results.append(r)
    return results


def git(root: Path, *args: str) -> str:
    out = subprocess.run(["git", *args], cwd=root, check=True, capture_output=True, timeout=600)
    return out.stdout.decode("utf-8", "replace").strip()


@contextmanager
def worktree(root: Path, sha: str) -> Iterator[Path]:
    """Check the base commit out next to the repo (needs fetch-depth: 0)."""
    tmp = Path(tempfile.mkdtemp(prefix="simpli-guard-base-"))
    path = tmp / "base"
    git(root, "worktree", "add", "--detach", str(path), sha)
    try:
        yield path
    finally:
        try:
            git(root, "worktree", "remove", "--force", str(path))
        except subprocess.CalledProcessError:
            log.warning("could not remove the base worktree")
        shutil.rmtree(tmp, ignore_errors=True)


# Files that change what the scan reports. In PR mode they are read from the base commit.
SETTINGS_FILES = (CONFIG_PATH, ".gitleaksignore", ".gitleaks.toml")


def changed_settings(root: Path, base_sha: str, head_sha: str) -> list[str]:
    """Settings files the PR changes (merge-base diff, so base-branch movement is not counted)."""
    out = git(root, "diff", "--name-only", f"{base_sha}...{head_sha}", "--", *SETTINGS_FILES)
    return sorted(line.strip() for line in out.splitlines() if line.strip())


@dataclass
class Diff:
    new: list[Finding]
    existing: list[Finding]
    undiffable_tools: set[str]


def split_new(head: list[Finding], base_results: list[ScanResult], head_tools: set[str]) -> Diff:
    """New = on head, fingerprint absent on base. A tool that ran on head but
    not on base can't be diffed; its findings count as pre-existing rather
    than failing the PR on findings it may not have introduced."""
    base_ids = {f.id for r in base_results for f in r.findings}
    base_ran = {r.tool for r in base_results if r.status == "ran"}
    undiffable = {t for t in head_tools if t not in base_ran and t != gitleaks.TOOL}
    new: list[Finding] = []
    existing: list[Finding] = []
    for f in head:
        tools = set(f.tool.split("+"))
        if f.id in base_ids or (tools and tools <= undiffable):
            existing.append(f)
        else:
            new.append(f)
    return Diff(new, existing, undiffable)
