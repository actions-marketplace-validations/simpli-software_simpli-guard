from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from simpli_guard.models import Category, Finding, Severity, code_fingerprint

FIXTURES = Path(__file__).parent / "fixtures"
# The fixture secret values. No output of simpli-guard may ever contain them.
FIXTURE_SECRETS = ["sk_live_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "fixtureapikeyvalue987654321"]


def load(name: str) -> Any:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def make_finding(
    *,
    tool: str = "opengrep",
    category: Category = Category.SAST,
    severity: Severity = Severity.HIGH,
    path: str = "app/x.py",
    line: int | None = 3,
    rule_id: str = "python.lang.security.audit.x",
    snippet: str = "x()",
    title: str = "Something risky",
) -> Finding:
    return Finding(
        id=code_fingerprint(tool, rule_id, path, snippet),
        tool=tool,
        category=category,
        severity=severity,
        title=title,
        path=path,
        line=line,
        rule_id=rule_id,
        message="message",
    )


@pytest.fixture(autouse=True)
def _isolated_tool_cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SIMPLI_GUARD_TOOL_CACHE", str(tmp_path / "toolcache"))
