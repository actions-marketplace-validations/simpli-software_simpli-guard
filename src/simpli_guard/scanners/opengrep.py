"""SAST with Opengrep (the open-source Semgrep fork) and the community
security rules for Python and JavaScript/TypeScript.

Only rules whose metadata says `category: security` run; style, correctness
and best-practice rules are dropped before the scan. Findings in test code are
lowered one severity level by the noise stage.
"""

from __future__ import annotations

import io
import json
import logging
import re
import shutil
import tarfile
from pathlib import Path
from typing import Any

import httpx

from simpli_guard.models import Category, Finding, Severity, code_fingerprint
from simpli_guard.scanners import base
from simpli_guard.scanners.base import Asset, ScanResult, ToolSpec, install, read_lines, run, tool_cache_dir

log = logging.getLogger(__name__)

TOOL = "opengrep"
SPEC = ToolSpec(
    name=TOOL,
    repo="opengrep/opengrep",
    tag="v1.30.1",
    exe="opengrep",
    assets={
        "linux-x64": Asset(
            "opengrep_manylinux_x86", "d3195b9d8d5ae93179f6aa5f5daaba6a920a5a09d38c5d5ae5e60924050210c4"
        ),
        "windows-x64": Asset(
            "opengrep_windows_x86.exe", "d3a45326ff63cabe90d94ebc679fcd4302440178a0e5bf0248a6f7b610db3b53"
        ),
        "darwin-arm64": Asset(
            "opengrep_osx_arm64", "7b788794e111ce3fb83f0aa52c100a3b85d37d8b59482262109031f50d4a8d91"
        ),
    },
)
# Rules are pinned by commit (immutable content).
RULES_REPO = "opengrep/opengrep-rules"
RULES_COMMIT = "f1d2b562b414783763fd02a6ed2736eaed622efa"
RULES_LANGS = ("python", "javascript", "typescript")
RULES_DIR_NAME = "sgrules"  # check_ids are prefixed with the config path; we cut at this name
_RULE_ID_LINE = re.compile(r"^(\s*-\s*id:\s*)([\w.\-]+)\s*$", re.MULTILINE)

EXCLUDES = ["node_modules", ".venv", "venv", "dist", "build", ".git", "vendor", "__pycache__", "*.min.js"]

_SEVERITY = {
    "ERROR": Severity.HIGH,
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "INFO": Severity.LOW,
    "LOW": Severity.LOW,
}


def ensure_rules() -> Path | None:
    root = tool_cache_dir() / "opengrep-rules" / RULES_COMMIT[:12] / RULES_DIR_NAME
    if root.is_dir() and any(root.glob("*.yaml")):
        return root
    url = f"https://codeload.github.com/{RULES_REPO}/tar.gz/{RULES_COMMIT}"
    try:
        rules = extract_rules(base._download(url, timeout=120))
        if not rules:
            return None
        staging = root.with_name(RULES_DIR_NAME + ".tmp")
        shutil.rmtree(staging, ignore_errors=True)
        staging.mkdir(parents=True)
        for i, text in enumerate(rules, 1):
            (staging / f"r{i:04d}.yaml").write_text(text, encoding="utf-8")
        shutil.rmtree(root, ignore_errors=True)
        staging.rename(root)  # all or nothing: a half-written rules dir is never used
        log.info("opengrep rules: %d security rule files", len(rules))
        return root
    except (httpx.HTTPError, OSError, tarfile.TarError) as e:
        log.warning("opengrep: could not fetch rules (%s)", type(e).__name__)
        return None


def extract_rules(tarball: bytes) -> list[str]:
    """Security rule files for our languages, with ids rewritten to the
    registry-style dotted path (python.lang.security.audit.eval-detected.eval-detected).
    They are stored flat under short names because the deep rule paths break
    the Windows path-length limit."""
    out: list[str] = []
    with tarfile.open(fileobj=io.BytesIO(tarball), mode="r:gz") as t:
        for m in t.getmembers():
            parts = m.name.split("/")
            if (
                not m.isfile()
                or len(parts) < 3
                or parts[1] not in RULES_LANGS
                or not m.name.endswith((".yaml", ".yml"))
                or m.name.endswith((".test.yaml", ".test.yml"))
                or ".." in parts
            ):
                continue
            f = t.extractfile(m)
            if f is None:
                continue
            text = f.read().decode("utf-8", "replace")
            if "category: security" not in text:
                continue  # style / correctness / best-practice rules are noise here
            dotted = ".".join([*parts[1:-1], Path(parts[-1]).stem])
            out.append(_RULE_ID_LINE.sub(r"\g<1>" + dotted + r".\g<2>", text))
    return out


def scan(root: Path, workdir: Path) -> ScanResult:
    exe = install(SPEC)
    rules = ensure_rules() if exe else None
    if exe is None or rules is None:
        return ScanResult(TOOL, "skipped", message="opengrep or its rules unavailable")
    out = workdir / "opengrep.json"
    args = [str(exe), "scan", "--config", str(rules), "--json", "--output", str(out), "--quiet"]
    for e in EXCLUDES:
        args += ["--exclude", e]
    proc = run([*args, "."], cwd=root)
    if not out.is_file():
        return ScanResult(TOOL, "failed", message=f"exit {proc.code}: {proc.tail}")
    data = json.loads(out.read_text(encoding="utf-8"))
    out.unlink(missing_ok=True)
    return ScanResult(TOOL, "ran", parse(data, root))


def normalize_rule_id(check_id: str) -> str:
    """`<config path>.sgrules.r0042.python.lang...` -> `python.lang...`."""
    marker = RULES_DIR_NAME + "."
    i = check_id.find(marker)
    if i < 0:
        return check_id
    rest = check_id[i + len(marker) :]
    head, _, tail = rest.partition(".")
    return tail if re.fullmatch(r"r\d{4}", head) and tail else rest


def parse(data: dict[str, Any], root: Path | None = None) -> list[Finding]:
    findings: list[Finding] = []
    for r in data.get("results", []):
        extra = r.get("extra") or {}
        meta = extra.get("metadata") or {}
        if str(meta.get("category", "")).lower() != "security":
            continue
        path = str(r.get("path", "")).replace("\\", "/").removeprefix("./")
        start = int((r.get("start") or {}).get("line") or 0)
        end = int((r.get("end") or {}).get("line") or start)
        lines = read_lines(root, path) if root else []
        snippet = "\n".join(lines[start - 1 : end]) if lines and start else str(extra.get("lines", ""))
        rule_id = normalize_rule_id(str(r.get("check_id", "")))
        refs = meta.get("references") or []
        if isinstance(refs, str):
            refs = [refs]
        cwe = meta.get("cwe") or []
        if isinstance(cwe, str):
            cwe = [cwe]
        message = " ".join(str(extra.get("message", "")).split())
        findings.append(
            Finding(
                id=code_fingerprint(TOOL, rule_id, path, snippet),
                tool=TOOL,
                category=Category.SAST,
                severity=_SEVERITY.get(str(extra.get("severity", "")).upper(), Severity.MEDIUM),
                title=_title(rule_id, message),
                path=path,
                line=start or None,
                rule_id=rule_id,
                message=message[:2000],
                references=[str(x) for x in [*cwe, *refs]][:8],
            )
        )
    return findings


def _title(rule_id: str, message: str) -> str:
    first = message.split(". ")[0].strip()
    if 10 <= len(first) <= 140:
        return first.rstrip(".")
    return rule_id.rsplit(".", 1)[-1].replace("-", " ").capitalize()
