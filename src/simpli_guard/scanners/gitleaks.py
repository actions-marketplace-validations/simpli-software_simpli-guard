"""Secrets with gitleaks.

PR mode scans only the commits in the PR (`base..head`); nightly scans the
full history. The repository's own `.gitleaks.toml` and `.gitleaksignore` are
honoured. The raw report is written to a private temp dir, read once, and
deleted; each secret is reduced to a masked prefix (`sk_l…`) at parse time
and the raw value is dropped immediately.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from simpli_guard.masking import mask_secret
from simpli_guard.models import Category, Finding, Severity, code_fingerprint
from simpli_guard.scanners.base import Asset, ScanResult, ToolSpec, install, run

log = logging.getLogger(__name__)

TOOL = "gitleaks"
SPEC = ToolSpec(
    name=TOOL,
    repo="gitleaks/gitleaks",
    tag="v8.30.1",
    exe="gitleaks",
    assets={
        "linux-x64": Asset(
            "gitleaks_8.30.1_linux_x64.tar.gz",
            "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb",
            member="gitleaks",
        ),
        "windows-x64": Asset(
            "gitleaks_8.30.1_windows_x64.zip",
            "d29144deff3a68aa93ced33dddf84b7fdc26070add4aa0f4513094c8332afc4e",
            member="gitleaks.exe",
        ),
        "darwin-arm64": Asset(
            "gitleaks_8.30.1_darwin_arm64.tar.gz",
            "b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5",
            member="gitleaks",
        ),
    },
)

_CRITICAL_RULES = ("private-key", "aws-access-token", "stripe", "github-pat", "github-fine-grained", "gcp")


def scan(root: Path, workdir: Path, log_range: str | None) -> ScanResult:
    """`log_range` like "base..head" for PR mode; None = full history."""
    exe = install(SPEC)
    if exe is None:
        return ScanResult(TOOL, "skipped", message="gitleaks unavailable")
    out = workdir / "gitleaks.json"
    args = [
        str(exe),
        "git",
        "--no-banner",
        "--report-format",
        "json",
        "--report-path",
        str(out),
        "--exit-code",
        "0",
    ]
    if log_range:
        args += ["--log-opts", log_range]
    if (root / ".gitleaks.toml").is_file():
        args += ["--config", str(root / ".gitleaks.toml")]
    if (root / ".gitleaksignore").is_file():
        args += ["--gitleaks-ignore-path", str(root / ".gitleaksignore")]
    proc = run([*args, "."], cwd=root)
    try:
        if proc.code != 0 or not out.is_file():
            return ScanResult(TOOL, "failed", message=f"exit {proc.code}: {proc.tail}")
        data = json.loads(out.read_text(encoding="utf-8") or "[]")
        return ScanResult(TOOL, "ran", parse(data))
    finally:
        out.unlink(missing_ok=True)


def parse(data: list[dict[str, Any]]) -> list[Finding]:
    findings: list[Finding] = []
    for leak in data or []:
        secret = str(leak.pop("Secret", "") or "")
        # Drop every field that can carry the value before anything else touches it.
        for k in ("Match", "Line"):
            leak.pop(k, None)
        masked = mask_secret(secret)
        length = len(secret)
        del secret
        rule = str(leak.get("RuleID", "generic"))
        path = str(leak.get("File", "")).replace("\\", "/").removeprefix("./")
        commit = str(leak.get("Commit", ""))[:12]
        sev = Severity.CRITICAL if any(r in rule.lower() for r in _CRITICAL_RULES) else Severity.HIGH
        desc = str(leak.get("Description") or rule)
        where = f" (commit {commit})" if commit else ""
        findings.append(
            Finding(
                id=code_fingerprint(TOOL, rule, path, f"{masked}:{length}"),
                tool=TOOL,
                category=Category.SECRET,
                severity=sev,
                title=f"{desc} ({masked})",
                path=path,
                line=int(leak.get("StartLine") or 0) or None,
                rule_id=rule,
                message=f"Possible {desc} committed{where}. Value masked as {masked}. "
                "Rotate it if real, then remove it from the code.",
                masked=masked,
            )
        )
    return findings
