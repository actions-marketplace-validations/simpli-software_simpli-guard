"""Secret masking. A secret value is reduced to a short prefix the moment it is
parsed; nothing downstream (logs, comments, issues, reports, Claude) ever sees
more than that prefix."""

from __future__ import annotations

import re

ELLIPSIS = "…"


def mask_secret(value: str, keep: int = 4) -> str:
    """`sk_live_abc...` -> `sk_l…`. Short values keep less, so a mask never
    reveals more than about a third of the secret."""
    value = value.strip()
    if not value:
        return ELLIPSIS
    keep = min(keep, len(value) // 3)
    return value[:keep] + ELLIPSIS


# Well-known credential shapes, scrubbed from any code excerpt before it
# leaves the runner (defence in depth for the Claude triage prompt).
_PATTERNS = [
    re.compile(r"\b(sk|rk|pk)_(live|test)_[A-Za-z0-9]{8,}"),
    re.compile(r"\bsk-(ant-)?[A-Za-z0-9_\-]{16,}"),
    re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"\bAIza[0-9A-Za-z_\-]{30,}"),
    re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----|$)"),
    re.compile(
        r"(?i)((?:password|passwd|secret|token|api[_-]?key|private[_-]?key)\s*[:=]\s*)"
        r"(['\"]?)[^\s'\"]{6,}\2"
    ),
]


def scrub(text: str, known: list[str] | None = None) -> str:
    """Replace known secret values and common credential shapes with masks."""
    for value in known or []:
        if value:
            text = text.replace(value, mask_secret(value))
    for pat in _PATTERNS[:-1]:
        text = pat.sub(lambda m: mask_secret(m.group(0)), text)
    return _PATTERNS[-1].sub(lambda m: f"{m.group(1)}{m.group(2)}<redacted>{m.group(2)}", text)
