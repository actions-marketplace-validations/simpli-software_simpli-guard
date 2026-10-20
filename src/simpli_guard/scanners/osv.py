"""Dependency vulnerabilities with osv-scanner over the repository's lockfiles.

Severity comes from the advisory's CVSS score (osv-scanner's per-group
`max_severity`), falling back to the advisory's own label. Dev-only
dependencies (when the lockfile records it) are lowered one level and CISA
KEV entries raised one level by the noise stage.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

from simpli_guard.models import Category, Finding, Severity, package_fingerprint, preferred_vuln_id
from simpli_guard.scanners.base import Asset, ScanResult, ToolSpec, install, run

log = logging.getLogger(__name__)

TOOL = "osv-scanner"
SPEC = ToolSpec(
    name=TOOL,
    repo="google/osv-scanner",
    tag="v2.6.0",
    exe="osv-scanner",
    assets={
        "linux-x64": Asset(
            "osv-scanner_linux_amd64", "ca69b3d3cd08f889a49dc0a383122f71cc528b83803671df5fd874d97485b108"
        ),
        "windows-x64": Asset(
            "osv-scanner_windows_amd64.exe",
            "e0ed7644118b717b028c249ee9d3515024e55e8510747ca08906eb96765354d6",
        ),
        "darwin-arm64": Asset(
            "osv-scanner_darwin_arm64", "98c460dcd37de25819babd757d04542045b6243113e209edcd4d89fedb0256b4"
        ),
    },
)

LOCKFILE_NAMES = {"uv.lock", "poetry.lock", "package-lock.json", "pnpm-lock.yaml"}
SKIP_DIRS = {"node_modules", ".venv", "venv", ".git", "dist", "build", "__pycache__", ".tox"}


def find_lockfiles(root: Path) -> list[str]:
    found: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".simpli"))
        for f in sorted(filenames):
            if f in LOCKFILE_NAMES or (f.startswith("requirements") and f.endswith(".txt")):
                found.append(Path(dirpath, f).relative_to(root).as_posix())
    return found


def scan(root: Path, workdir: Path) -> ScanResult:
    lockfiles = find_lockfiles(root)
    if not lockfiles:
        return ScanResult(TOOL, "ran", message="no lockfiles")
    exe = install(SPEC)
    if exe is None:
        return ScanResult(TOOL, "skipped", message="osv-scanner unavailable")
    out = workdir / "osv.json"
    args = [str(exe), "scan", "source", "--format", "json", "--output", str(out)]
    for lf in lockfiles:
        args += ["-L", lf]
    proc = run(args, cwd=root)
    if proc.code not in (0, 1) or not out.is_file():
        return ScanResult(TOOL, "failed", message=f"exit {proc.code}: {proc.tail}")
    data = json.loads(out.read_text(encoding="utf-8") or "{}")
    out.unlink(missing_ok=True)
    return ScanResult(TOOL, "ran", parse(data, root))


def cvss_severity(score: float | None) -> Severity | None:
    if score is None:
        return None
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0:
        return Severity.LOW
    return None


_LABELS = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


def _score(raw: object) -> float | None:
    if raw in (None, ""):
        return None
    try:
        return float(str(raw))
    except ValueError:
        return None


def _fixed_version(vuln: dict[str, Any], name: str) -> str | None:
    for aff in vuln.get("affected", []) or []:
        pkg = aff.get("package") or {}
        if pkg.get("name", "").lower() != name.lower():
            continue
        for rng in aff.get("ranges", []) or []:
            for ev in rng.get("events", []) or []:
                if ev.get("fixed"):
                    return str(ev["fixed"])
    return None


def _rel(path: str, root: Path | None) -> str:
    p = path.replace("\\", "/")
    if root is not None:
        try:
            return Path(path).resolve().relative_to(root.resolve()).as_posix()
        except ValueError:
            pass
    return p.removeprefix("./")


def parse(data: dict[str, Any], root: Path | None = None) -> list[Finding]:
    findings: list[Finding] = []
    for res in data.get("results", []) or []:
        lockfile = _rel(str((res.get("source") or {}).get("path", "")), root)
        for pv in res.get("packages", []) or []:
            pkg = pv.get("package") or {}
            name, version = str(pkg.get("name", "")), str(pkg.get("version", ""))
            ecosystem = str(pkg.get("ecosystem", ""))
            groups_dev = [str(g).lower() for g in pv.get("dependency_groups", []) or []]
            dev_only = bool(groups_dev) and all(g in ("dev", "development", "optional") for g in groups_dev)
            vulns = {v.get("id"): v for v in pv.get("vulnerabilities", []) or []}
            groups = pv.get("groups") or [{"ids": [i], "aliases": [i]} for i in vulns]
            for g in groups:
                ids = [i for i in g.get("ids", []) if i in vulns]
                if not ids:
                    continue
                vuln = vulns[ids[0]]
                aliases = sorted({*g.get("aliases", []), *ids, *(vuln.get("aliases") or [])})
                vid = preferred_vuln_id(str(ids[0]), aliases)
                score = _score(g.get("max_severity"))
                label = str((vuln.get("database_specific") or {}).get("severity", "")).upper()
                sev = cvss_severity(score) or _LABELS.get(label, Severity.MEDIUM)
                summary = str(vuln.get("summary") or vuln.get("details", "")[:200] or vid)
                findings.append(
                    Finding(
                        id=package_fingerprint(name, version, vid),
                        tool=TOOL,
                        category=Category.DEPENDENCY,
                        severity=sev,
                        title=f"{name} {version}: {summary}"[:200],
                        path=lockfile,
                        rule_id=vid,
                        package=name,
                        version=version,
                        fixed_version=_fixed_version(vuln, name),
                        message=f"{ecosystem} package {name}@{version} is affected by {vid}.",
                        references=[f"https://osv.dev/vulnerability/{ids[0]}"],
                        aliases=aliases,
                        dev_only=dev_only,
                    )
                )
    return findings
