"""Optional Claude triage of the findings most likely to be false positives:
high/critical SAST and secret findings that survived the rule-based noise
reduction (at most 20 per run).

Claude gets each SAST finding with ~60 lines of surrounding code (scrubbed of
anything credential-shaped), and each secret finding with only its path, its
masked prefix and whether the file is test/fixture/example code - never the
value. It answers through the `submit_triage` tool. A finding is suppressed
only for `not_exploitable` with confidence >= 4, and the reason is shown in
reports. Any API or protocol failure keeps every finding (fail open).
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

from pydantic import BaseModel, Field, ValidationError

from simpli_guard.config import is_example_path, is_test_path
from simpli_guard.masking import scrub
from simpli_guard.models import SEVERITY_ORDER, Category, Finding, Severity, TriageBy
from simpli_guard.scanners.base import read_lines

if TYPE_CHECKING:  # the SDK is slow to import; only the CLI loads it, and only when triage runs
    import anthropic

log = logging.getLogger(__name__)

CONTEXT_LINES = 30  # either side -> ~60 lines
SUPPRESS_CONFIDENCE = 4
MAX_ATTEMPTS = 3
FALLBACK_BETA = "server-side-fallback-2026-07-01"

SYSTEM_PROMPT = """\
You triage findings from security scanners (Opengrep SAST rules and gitleaks secret detection) \
for the team that owns the code. Scanners are noisy; your job is to say, for each finding, \
whether it is a real, exploitable problem in this code.

For a SAST finding you get the rule, the scanner's message and the surrounding code. Decide \
whether attacker-controlled input can actually reach the flagged sink in a way that matters, \
taking into account validation, constant arguments, framework protections, and whether the \
code is test-only. For a secret finding you get only the file path, a masked prefix of the \
value and whether the file is test, fixture or example code - never the value itself. A \
secret in a test fixture with an obviously fake prefix (e.g. "test", "fake", "xxxx", \
"example") is usually not exploitable; a live-looking key prefix in application code is.

Verdicts: "exploitable" (a real issue), "not_exploitable" (a false positive or harmless here), \
"uncertain" (you cannot tell from what you see). Confidence is 1-5; use 4 or 5 only when the \
evidence in front of you settles it. Keep each reason to one or two sentences that a developer \
can check, citing the line or detail that decided it.

Call submit_triage exactly once with a verdict for every finding id you were given. Do not \
answer in plain text."""

SUBMIT_TOOL: dict[str, Any] = {
    "name": "submit_triage",
    "description": "Submit a verdict for every finding you were given.",
    "input_schema": {
        "type": "object",
        "properties": {
            "results": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "string"},
                        "verdict": {
                            "type": "string",
                            "enum": ["exploitable", "not_exploitable", "uncertain"],
                        },
                        "confidence": {"type": "integer", "minimum": 1, "maximum": 5},
                        "reason": {"type": "string"},
                    },
                    "required": ["id", "verdict", "confidence", "reason"],
                    "additionalProperties": False,
                },
            }
        },
        "required": ["results"],
        "additionalProperties": False,
    },
}


class Verdict(BaseModel):
    id: str
    verdict: Literal["exploitable", "not_exploitable", "uncertain"]
    confidence: int = Field(ge=1, le=5)
    reason: str = Field(min_length=1, max_length=1000)


class Submission(BaseModel):
    results: list[Verdict]


@dataclass
class TriageSettings:
    model: str = "claude-sonnet-5-5"
    effort: str = "medium"
    max_findings: int = 60
    max_tokens: int = 16_000
    use_fallbacks: bool = True


@dataclass
class TriageStats:
    asked: int = 0
    suppressed: int = 0
    failed: bool = False
    usage: dict[str, int] = field(default_factory=dict)


class TriageFailed(Exception):
    pass


BATCH_SIZE = 20


def candidates(findings: list[Finding], limit: int) -> list[Finding]:
    pool = [
        f
        for f in findings
        if f.kept
        and f.category in (Category.SAST, Category.SECRET)
        and f.severity.at_least(Severity.HIGH)
        and f.triage.verdict is None
    ]
    pool.sort(key=lambda f: (SEVERITY_ORDER.index(f.severity), f.path, f.line or 0))
    return pool[:limit]


def build_items(cands: list[Finding], root: Path, test_globs: list[str]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for f in cands:
        if f.category == Category.SECRET:
            items.append(
                {
                    "id": f.id,
                    "kind": "secret",
                    "rule_id": f.rule_id,
                    "path": f.path,
                    "masked_value": f.masked or "…",
                    "is_test_file": is_test_path(f.path, test_globs),
                    "is_fixture_or_example": is_example_path(f.path),
                }
            )
            continue
        lines = read_lines(root, f.path)
        ln = f.line or 1
        lo, hi = max(1, ln - CONTEXT_LINES), min(len(lines), ln + CONTEXT_LINES)
        code = "\n".join(f"{i:>5}{'>' if i == ln else ' '} {lines[i - 1]}" for i in range(lo, hi + 1))
        items.append(
            {
                "id": f.id,
                "kind": "sast",
                "rule_id": f.rule_id,
                "severity": f.severity.value,
                "title": scrub(f.title),
                "message": scrub(f.message),
                "path": f.path,
                "line": f.line,
                "is_test_file": is_test_path(f.path, test_globs),
                "code": scrub(code) if code else "(file not available)",
            }
        )
    return items


def ask_claude(
    client: anthropic.Anthropic, settings: TriageSettings, items: list[dict[str, Any]]
) -> tuple[list[Verdict], dict[str, int]]:
    user_text = "Triage these findings. Every id below needs exactly one verdict.\n\n" + json.dumps(
        items, indent=1, sort_keys=True, ensure_ascii=False
    )
    messages: list[dict[str, Any]] = [{"role": "user", "content": user_text}]
    usage = {"input": 0, "output": 0, "cache_read": 0, "cache_write": 0}
    extra: dict[str, Any] = {}
    if settings.use_fallbacks:
        extra = {"betas": [FALLBACK_BETA], "extra_body": {"fallbacks": "default"}}
    tools = [{**SUBMIT_TOOL, "eager_input_streaming": True}]

    for _attempt in range(MAX_ATTEMPTS):
        try:
            with client.beta.messages.stream(
                model=settings.model,
                max_tokens=settings.max_tokens,
                system=SYSTEM_PROMPT,
                tools=tools,  # type: ignore[arg-type]
                tool_choice={"type": "auto"},
                messages=messages,  # type: ignore[arg-type]
                output_config={"effort": settings.effort},  # type: ignore[arg-type]
                cache_control={"type": "ephemeral"},
                **extra,
            ) as stream:
                response = stream.get_final_message()
        except ValueError:
            continue  # tool input the SDK could not parse at all: re-issue the turn

        u = response.usage
        usage["input"] += u.input_tokens or 0
        usage["output"] += u.output_tokens or 0
        usage["cache_read"] += getattr(u, "cache_read_input_tokens", 0) or 0
        usage["cache_write"] += getattr(u, "cache_creation_input_tokens", 0) or 0

        if response.stop_reason == "refusal":
            raise TriageFailed("the model declined to triage")
        if response.stop_reason == "max_tokens":
            raise TriageFailed("the response hit max_tokens")
        messages.append({"role": "assistant", "content": response.content})
        tool_uses = [b for b in response.content if b.type == "tool_use"]
        if not tool_uses:
            messages.append({"role": "user", "content": "Call submit_triage now with every verdict."})
            continue

        results: list[dict[str, Any]] = []
        submitted: Submission | None = None
        for b in tool_uses:
            if b.name != "submit_triage":
                results.append(
                    {"type": "tool_result", "tool_use_id": b.id, "is_error": True, "content": "Unknown tool."}
                )
                continue
            try:
                # With eager input streaming the server does not validate: we do.
                submitted = Submission.model_validate(b.input)
                results.append({"type": "tool_result", "tool_use_id": b.id, "content": "Received."})
            except ValidationError as e:
                results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": b.id,
                        "is_error": True,
                        "content": f"Input did not match the schema: {e.errors(include_input=False)}",
                    }
                )
        if submitted is not None:
            return submitted.results, usage
        messages.append({"role": "user", "content": results})
    raise TriageFailed(f"no valid submit_triage call after {MAX_ATTEMPTS} attempts")


def apply_verdicts(findings: list[Finding], verdicts: list[Verdict]) -> int:
    by_id = {f.id: f for f in findings}
    suppressed = 0
    for v in verdicts:
        f = by_id.get(v.id)
        if f is None:
            continue
        reason = " ".join(v.reason.split())[:500]
        f.triage = f.triage.model_copy(update={"verdict": v.verdict, "confidence": v.confidence})
        if v.verdict == "not_exploitable" and v.confidence >= SUPPRESS_CONFIDENCE:
            f.suppress(f"Claude: not exploitable ({v.confidence}/5): {reason}", TriageBy.CLAUDE)
            suppressed += 1
        else:
            f.triage = f.triage.model_copy(
                update={"reason": f"Claude: {v.verdict.replace('_', ' ')} ({v.confidence}/5): {reason}"}
            )
    return suppressed


def triage(
    client: anthropic.Anthropic,
    settings: TriageSettings,
    findings: list[Finding],
    root: Path,
    test_globs: list[str],
) -> TriageStats:
    stats = TriageStats()
    cands = candidates(findings, settings.max_findings)
    if not cands:
        return stats
    stats.asked = len(cands)
    for start in range(0, len(cands), BATCH_SIZE):  # one request per batch keeps each prompt small
        batch = cands[start : start + BATCH_SIZE]
        try:
            verdicts, usage = ask_claude(client, settings, build_items(batch, root, test_globs))
        except Exception as e:  # fail open: triage can only remove noise, never findings
            stats.failed = True
            log.warning("triage failed (%s); keeping the remaining findings", type(e).__name__)
            break
        for k, v in usage.items():
            stats.usage[k] = stats.usage.get(k, 0) + v
        stats.suppressed += apply_verdicts(batch, verdicts)
    log.info(
        "triage: %d findings, %d suppressed; tokens in=%d out=%d cache_read=%d cache_write=%d",
        stats.asked,
        stats.suppressed,
        stats.usage.get("input", 0),
        stats.usage.get("output", 0),
        stats.usage.get("cache_read", 0),
        stats.usage.get("cache_write", 0),
    )
    return stats
