"""The normalized finding every scanner is parsed into.

Fingerprints never include line numbers, so a finding keeps its id when
unrelated edits shift it up or down the file. That id is what PR mode diffs
against the base branch, what ignore rules match, and what issue markers carry.
"""

from __future__ import annotations

import hashlib
import re
from enum import StrEnum

from pydantic import BaseModel, Field


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return _RANK[self]

    def lower(self, steps: int = 1) -> Severity:
        return _BY_RANK[max(0, self.rank - steps)]

    def raise_(self, steps: int = 1) -> Severity:
        return _BY_RANK[min(4, self.rank + steps)]

    def at_least(self, other: Severity) -> bool:
        return self.rank >= other.rank


_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}
_BY_RANK = {v: k for k, v in _RANK.items()}
SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


class Category(StrEnum):
    SAST = "sast"
    DEPENDENCY = "dependency"
    SECRET = "secret"
    IAC = "iac"
    CONTAINER = "container"
    SURFACE = "surface"
    LICENSE = "license"
    ACTIONS = "actions"


class TriageStatus(StrEnum):
    KEPT = "kept"
    SUPPRESSED = "suppressed"


class TriageBy(StrEnum):
    SCANNER = "scanner"
    RULE = "rule"
    CLAUDE = "claude"


class Triage(BaseModel):
    status: TriageStatus = TriageStatus.KEPT
    reason: str = ""
    by: TriageBy = TriageBy.SCANNER
    verdict: str | None = None  # Claude's verdict when Claude looked at it
    confidence: int | None = None


class Finding(BaseModel):
    id: str
    tool: str
    category: Category
    severity: Severity
    title: str
    path: str = ""
    line: int | None = None
    rule_id: str = ""
    package: str | None = None
    version: str | None = None
    fixed_version: str | None = None
    message: str = ""
    references: list[str] = Field(default_factory=list)
    aliases: list[str] = Field(default_factory=list)  # advisory ids (CVE/GHSA/...) for KEV lookups
    dev_only: bool = False  # dependency used only in development, per the lockfile
    triage: Triage = Field(default_factory=Triage)
    # Secrets only: the masked prefix (e.g. "sk_l…"). The raw value is never stored.
    masked: str | None = None
    notes: list[str] = Field(default_factory=list)  # severity adjustments, for the report

    @property
    def kept(self) -> bool:
        return self.triage.status == TriageStatus.KEPT

    def suppress(self, reason: str, by: TriageBy) -> None:
        self.triage = self.triage.model_copy(
            update={"status": TriageStatus.SUPPRESSED, "reason": reason, "by": by}
        )


_WS = re.compile(r"\s+")


def normalize_snippet(snippet: str) -> str:
    """Whitespace- and indentation-insensitive, so reformatting doesn't churn ids."""
    return _WS.sub(" ", snippet).strip()


def _digest(*parts: str) -> str:
    h = hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()
    return h[:24]


def code_fingerprint(tool: str, rule_id: str, path: str, snippet: str) -> str:
    """SAST / IaC / secrets / surface / Actions workflows: tool + rule + path + normalized snippet."""
    return _digest(tool, rule_id, path.replace("\\", "/"), normalize_snippet(snippet))


def package_fingerprint(package: str, version: str, vuln_id: str) -> str:
    """Dependencies and image packages: package@version + vulnerability id.

    The tool and the lockfile path are deliberately left out so the same
    advisory reported by osv-scanner and by Trivy dedupes to one finding.
    """
    return _digest("pkg", package.lower(), version, vuln_id.upper())


def preferred_vuln_id(vuln_id: str, aliases: list[str] | None = None) -> str:
    """Normalize to a CVE id when one exists so tools that key on GHSA/PYSEC
    and tools that key on CVE agree."""
    if vuln_id.upper().startswith("CVE-"):
        return vuln_id.upper()
    cves = sorted(a.upper() for a in aliases or [] if a.upper().startswith("CVE-"))
    return cves[0] if cves else vuln_id.upper()
