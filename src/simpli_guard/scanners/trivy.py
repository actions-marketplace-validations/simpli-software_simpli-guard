"""Trivy: IaC/config misconfigurations (Dockerfiles, compose, Kubernetes),
container images built from the repo's Dockerfiles (nightly), and licenses.
"""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
from pathlib import Path
from typing import Any

from simpli_guard.models import (
    Category,
    Finding,
    Severity,
    code_fingerprint,
    package_fingerprint,
    preferred_vuln_id,
)
from simpli_guard.scanners.base import Asset, ScanResult, ToolSpec, install, run, tool_cache_dir

log = logging.getLogger(__name__)

TOOL = "trivy"
SPEC = ToolSpec(
    name=TOOL,
    repo="aquasecurity/trivy",
    tag="v0.75.0",
    exe="trivy",
    assets={
        "linux-x64": Asset(
            "trivy_0.75.0_Linux-64bit.tar.gz",
            "c6e65abddb348e25f10549df887045629cf28cc72453cd1c63acb717316b3f3f",
            member="trivy",
        ),
        "windows-x64": Asset(
            "trivy_0.75.0_windows-64bit.zip",
            "4e43bd71a30f51aee39525f60f2b47043af77eb8df8fe082aae4372b69c6660f",
            member="trivy.exe",
        ),
        "darwin-arm64": Asset(
            "trivy_0.75.0_macOS-ARM64.tar.gz",
            "4a77108cccf8e55c8d6823e1e759939a622277e66cd0daa3c1fc621ed69e4568",
            member="trivy",
        ),
    },
)

_SEVERITY = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNKNOWN": Severity.INFO,
}
SKIP_DIRS = ["node_modules", ".venv", "venv", ".git", "dist", "build"]


def _flags(out: Path) -> list[str]:
    cache = tool_cache_dir() / "trivy-cache"
    return ["--cache-dir", str(cache), "--quiet", "--format", "json", "--output", str(out)]


def _skip_dirs() -> list[str]:
    args: list[str] = []
    for d in SKIP_DIRS:
        args += ["--skip-dirs", f"**/{d}"]
    return args


def _run_json(args: list[str], cwd: Path, out: Path) -> tuple[dict[str, Any] | None, str]:
    proc = run(args, cwd=cwd)
    if proc.code != 0 or not out.is_file():
        return None, f"exit {proc.code}: {proc.tail}"
    try:
        data = json.loads(out.read_text(encoding="utf-8") or "{}")
    finally:
        out.unlink(missing_ok=True)
    return data, ""


# ---------- config (IaC) ----------


def scan_config(root: Path, workdir: Path) -> ScanResult:
    exe = install(SPEC)
    if exe is None:
        return ScanResult(f"{TOOL}-config", "skipped", message="trivy unavailable")
    out = workdir / "trivy-config.json"
    args = [str(exe), "config", *_flags(out), *_skip_dirs(), "."]
    data, err = _run_json(args, root, out)
    if data is None:
        return ScanResult(f"{TOOL}-config", "failed", message=err)
    return ScanResult(f"{TOOL}-config", "ran", parse_config(data))


def parse_config(data: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for res in data.get("Results", []) or []:
        target = str(res.get("Target", "")).replace("\\", "/").removeprefix("./")
        for m in res.get("Misconfigurations", []) or []:
            if m.get("Status", "FAIL") != "FAIL":
                continue
            rule = str(m.get("AVDID") or m.get("ID") or "")
            cause = m.get("CauseMetadata") or {}
            code_lines = ((cause.get("Code") or {}).get("Lines")) or []
            snippet = "\n".join(str(ln.get("Content", "")) for ln in code_lines) or str(m.get("Message", ""))
            findings.append(
                Finding(
                    id=code_fingerprint(TOOL, rule, target, snippet),
                    tool=f"{TOOL}-config",
                    category=Category.IAC,
                    severity=_SEVERITY.get(str(m.get("Severity", "")).upper(), Severity.MEDIUM),
                    title=str(m.get("Title") or rule),
                    path=target,
                    line=int(cause.get("StartLine") or 0) or None,
                    rule_id=rule,
                    message=" ".join(
                        x for x in [str(m.get("Message", "")), str(m.get("Resolution", ""))] if x
                    )[:2000],
                    references=[str(r) for r in (m.get("References") or [])][:5],
                )
            )
    return findings


# ---------- images (nightly) ----------


def find_dockerfiles(root: Path) -> list[str]:
    found: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".simpli"))
        for f in sorted(filenames):
            if f == "Dockerfile" or f.startswith("Dockerfile.") or f.endswith(".Dockerfile"):
                found.append(Path(dirpath, f).relative_to(root).as_posix())
    return found


def _docker_build(root: Path, dockerfile: str, tag: str) -> bool:
    ctx_candidates = [str(Path(dockerfile).parent) or ".", "."]
    for ctx in dict.fromkeys(ctx_candidates):
        try:
            r = subprocess.run(
                ["docker", "build", "-q", "-f", dockerfile, "-t", tag, ctx],
                cwd=root,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=1800,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return False
        if r.returncode == 0:
            return True
    return False


def scan_images(root: Path, workdir: Path) -> ScanResult:
    dockerfiles = find_dockerfiles(root)
    if not dockerfiles:
        return ScanResult(f"{TOOL}-image", "ran", message="no Dockerfiles")
    exe = install(SPEC)
    if exe is None:
        return ScanResult(f"{TOOL}-image", "skipped", message="trivy unavailable")
    findings: list[Finding] = []
    skipped: list[str] = []
    for df in dockerfiles:
        tag = "simpli-guard-scan/" + re.sub(r"[^a-z0-9]+", "-", df.lower()).strip("-") + ":scan"
        if not _docker_build(root, df, tag):
            log.warning("trivy-image: docker build failed for %s; skipped", df)
            skipped.append(df)
            continue
        out = workdir / "trivy-image.json"
        args = [str(exe), "image", *_flags(out), "--scanners", "vuln", tag]
        data, err = _run_json(args, root, out)
        if data is None:
            log.warning("trivy-image: scan failed for %s (%s)", df, err)
            skipped.append(df)
            continue
        findings += parse_image(data, df)
    status = "ran" if len(skipped) < len(dockerfiles) else "failed"
    msg = f"skipped: {', '.join(skipped)}" if skipped else ""
    return ScanResult(f"{TOOL}-image", status, findings, msg)


def parse_image(data: dict[str, Any], dockerfile: str) -> list[Finding]:
    findings: list[Finding] = []
    os_meta = (data.get("Metadata") or {}).get("OS") or {}
    if os_meta.get("EOSL"):
        name = f"{os_meta.get('Family', '')} {os_meta.get('Name', '')}".strip()
        findings.append(
            Finding(
                id=code_fingerprint(TOOL, "eol-base-image", dockerfile, name),
                tool=f"{TOOL}-image",
                category=Category.CONTAINER,
                severity=Severity.HIGH,
                title=f"End-of-life base image OS ({name})",
                path=dockerfile,
                rule_id="eol-base-image",
                message=f"The image built from {dockerfile} runs {name}, which no longer receives "
                "security updates. Move to a supported base image.",
            )
        )
    for res in data.get("Results", []) or []:
        for v in res.get("Vulnerabilities", []) or []:
            vid = preferred_vuln_id(str(v.get("VulnerabilityID", "")), v.get("VendorIDs") or [])
            pkg, ver = str(v.get("PkgName", "")), str(v.get("InstalledVersion", ""))
            findings.append(
                Finding(
                    id=package_fingerprint(pkg, ver, vid),
                    tool=f"{TOOL}-image",
                    category=Category.CONTAINER,
                    severity=_SEVERITY.get(str(v.get("Severity", "")).upper(), Severity.MEDIUM),
                    title=f"{pkg} {ver}: {v.get('Title') or vid}"[:200],
                    path=dockerfile,
                    rule_id=vid,
                    package=pkg,
                    version=ver,
                    fixed_version=v.get("FixedVersion") or None,
                    message=f"{res.get('Target', '')}: {pkg}@{ver} is affected by {vid}.",
                    references=[str(v["PrimaryURL"])] if v.get("PrimaryURL") else [],
                    aliases=[vid],
                )
            )
    return findings


# ---------- licenses ----------

_STRONG_COPYLEFT = re.compile(r"^(A?GPL)(-|$)|^(AGPL|GPL)[\d.\-]", re.IGNORECASE)


def scan_licenses(root: Path, workdir: Path) -> ScanResult:
    exe = install(SPEC)
    if exe is None:
        return ScanResult(f"{TOOL}-license", "skipped", message="trivy unavailable")
    out = workdir / "trivy-license.json"
    args = [str(exe), "fs", *_flags(out), "--scanners", "license", *_skip_dirs(), "."]
    data, err = _run_json(args, root, out)
    if data is None:
        return ScanResult(f"{TOOL}-license", "failed", message=err)
    return ScanResult(f"{TOOL}-license", "ran", parse_licenses(data))


def parse_licenses(data: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for res in data.get("Results", []) or []:
        target = str(res.get("Target", "")).replace("\\", "/").removeprefix("./")
        for lic in res.get("Licenses", []) or []:
            name = str(lic.get("Name", ""))
            category = str(lic.get("Category", "")).lower()
            strong = bool(_STRONG_COPYLEFT.match(name)) and not name.upper().startswith("LGPL")
            if not strong and category not in ("restricted", "forbidden", "reciprocal"):
                continue  # permissive / notice licenses are not findings
            pkg = str(lic.get("PkgName", "")) or str(lic.get("FilePath", ""))
            path = str(lic.get("FilePath") or target).replace("\\", "/")
            findings.append(
                Finding(
                    id=code_fingerprint(TOOL, f"license:{name}", target, pkg),
                    tool=f"{TOOL}-license",
                    category=Category.LICENSE,
                    severity=Severity.MEDIUM if strong else Severity.INFO,
                    title=f"{pkg}: {name} license",
                    path=path,
                    rule_id=f"license:{name}",
                    package=pkg or None,
                    message=(
                        f"{pkg} is licensed {name} (strong copyleft) and is a production dependency. "
                        "Check this is compatible with how you distribute the software."
                        if strong
                        else f"{pkg} is licensed {name} ({category})."
                    ),
                )
            )
    return findings
