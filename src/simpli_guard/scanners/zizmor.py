"""GitHub Actions workflow security with zizmor.

Audits `.github/workflows/`, local composite actions under `.github/actions/`
and a root `action.yml` / `action.yaml`: template/script injection from
untrusted event fields, `pull_request_target` misuse, unpinned third-party
actions, excessive `permissions`, `persist-credentials` leaks, cache
poisoning and so on.

zizmor is run strictly offline (`--offline`, no GitHub token in its
environment), so its online-only audits are off and nothing about the
repository is sent anywhere. Its own `# zizmor: ignore[rule]` comments and a
`zizmor.yml` in the repository are honoured by zizmor itself; ignored findings
never reach us. Results come from `--format json-v1` on stdout, redirected to a
file in the private work directory.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from simpli_guard.models import Category, Finding, Severity, code_fingerprint
from simpli_guard.scanners.base import Asset, ScanResult, ToolSpec, install, run

log = logging.getLogger(__name__)

TOOL = "zizmor"
SPEC = ToolSpec(
    name=TOOL,
    repo="zizmorcore/zizmor",
    tag="v1.31.1",
    exe="zizmor",
    assets={
        "linux-x64": Asset(
            "zizmor-x86_64-unknown-linux-gnu.tar.gz",
            "d185f726bdaf92df78273217dfdd24ebcd6b0ef48cf3ce776ff5762b6e138c99",
            member="zizmor",
        ),
        "windows-x64": Asset(
            "zizmor-x86_64-pc-windows-msvc.zip",
            "4de30371c8a3b483aecbcf0dec1fd6a2b6aae65051ca226b4f6527baac6a8c7a",
            member="zizmor.exe",
        ),
        "darwin-arm64": Asset(
            "zizmor-aarch64-apple-darwin.tar.gz",
            "ad5aa633cd56215b11e6c51d51f90c7e6b22904a75047d1215abbd422f61d698",
            member="zizmor",
        ),
    },
)

# zizmor severity -> ours. Informational is the floor of "low".
_SEVERITY = {
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFORMATIONAL": Severity.LOW,
}
_DEFAULT_SEVERITY = Severity.MEDIUM  # "Unknown"
# A token must not reach zizmor even by accident: online audits use it.
_NO_TOKEN_ENV: dict[str, str | None] = {
    "GH_TOKEN": None,
    "GITHUB_TOKEN": None,
    "ZIZMOR_GITHUB_TOKEN": None,
    "ZIZMOR_OFFLINE": "1",
}


def inputs_for(root: Path) -> list[str]:
    """What to audit, relative to `root`: workflows, local composite actions, root action."""
    found: list[str] = []
    for d in (".github/workflows", ".github/actions"):
        if (root / d).is_dir():
            found.append(d)
    for name in ("action.yml", "action.yaml"):
        if (root / name).is_file():
            found.append(name)
    return found


def scan(root: Path, workdir: Path) -> ScanResult:
    targets = inputs_for(root)
    if not targets:
        return ScanResult(TOOL, "ran", [], "no workflows or action definitions")
    exe = install(SPEC)
    if exe is None:
        return ScanResult(TOOL, "skipped", message="zizmor unavailable")
    out = workdir / "zizmor.json"
    args = [str(exe), "--offline", "--no-progress", "--no-exit-codes", "--format", "json-v1", *targets]
    proc = run(args, cwd=root, env=_NO_TOKEN_ENV, stdout_file=out)
    try:
        if proc.code != 0 or not out.is_file():
            return ScanResult(TOOL, "failed", message=f"exit {proc.code}: {proc.tail}")
        try:
            data = json.loads(out.read_text(encoding="utf-8") or "[]")
        except ValueError:
            return ScanResult(TOOL, "failed", message="unreadable output")
        return ScanResult(TOOL, "ran", parse(data))
    finally:
        out.unlink(missing_ok=True)


def map_severity(severity: str, confidence: str) -> tuple[Severity, str | None]:
    """zizmor severity, one level lower when zizmor itself has low confidence."""
    sev = _SEVERITY.get(severity.upper(), _DEFAULT_SEVERITY)
    if confidence.upper() == "LOW":
        return sev.lower(), "lowered: zizmor reports low confidence"
    return sev, None


def _route_job(route: list[dict[str, Any]]) -> str:
    """The job id from a route like [jobs, <id>, steps, 3, ...]. Step indexes are left out
    on purpose: inserting a step must not change the fingerprint of the ones after it."""
    keys = [next(iter(part.values())) for part in route if part]
    return str(keys[1]) if len(keys) > 1 and keys[0] == "jobs" else ""


def _fragment(feature_kind: Any) -> str:
    if isinstance(feature_kind, dict):
        frag = (feature_kind.get("Subfeature") or {}).get("fragment") or {}
        return str(next(iter(frag.values()), ""))
    return ""


def parse(data: list[dict[str, Any]]) -> list[Finding]:
    findings: list[Finding] = []
    for r in data or []:
        if r.get("ignored"):
            continue
        primary = next(
            (
                loc
                for loc in r.get("locations") or []
                if (loc.get("symbolic") or {}).get("kind") == "Primary"
                and ((loc["symbolic"].get("key") or {}).get("Local") or {}).get("verbatim_path")
            ),
            None,
        )
        if primary is None:  # a remote input; we only audit the working tree
            continue
        sym, conc = primary["symbolic"], primary.get("concrete") or {}
        path = str(sym["key"]["Local"]["verbatim_path"]).replace("\\", "/").removeprefix("./")
        ident = str(r.get("ident", "unknown"))
        rule = f"zizmor.{ident}"
        row = int(((conc.get("location") or {}).get("start_point") or {}).get("row", -1))
        det = r.get("determinations") or {}
        severity, note = map_severity(str(det.get("severity", "")), str(det.get("confidence", "")))
        route = [p for p in ((sym.get("route") or {}).get("route") or []) if isinstance(p, dict)]
        # What was flagged, not where: job id + flagged text + expression fragment.
        snippet = "\x1e".join(
            [_route_job(route), str(conc.get("feature", "")), _fragment(sym.get("feature_kind"))]
        )
        desc = str(r.get("desc") or ident)
        annotation = str(sym.get("annotation") or "").strip()
        message = f"{desc}: {annotation}." if annotation else f"{desc}."
        url = str(r.get("url") or "")
        findings.append(
            Finding(
                id=code_fingerprint(TOOL, rule, path, snippet),
                tool=TOOL,
                category=Category.ACTIONS,
                severity=severity,
                title=f"{desc[:1].upper()}{desc[1:]} ({ident})",
                path=path,
                line=row + 1 if row >= 0 else None,
                rule_id=rule,
                message=message[:2000],
                references=[url] if url else [],
                notes=[note] if note else [],
            )
        )
    return findings
