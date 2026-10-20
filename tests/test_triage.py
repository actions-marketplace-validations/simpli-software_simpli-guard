from __future__ import annotations

import json
import logging
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from simpli_guard.models import Category, Severity, TriageBy
from simpli_guard.scanners import gitleaks
from simpli_guard.triage import TriageSettings, candidates, triage

from .conftest import FIXTURE_SECRETS, load, make_finding


def response(*blocks: Any, stop: str = "tool_use") -> SimpleNamespace:
    return SimpleNamespace(
        content=list(blocks),
        stop_reason=stop,
        usage=SimpleNamespace(
            input_tokens=1200, output_tokens=300, cache_read_input_tokens=0, cache_creation_input_tokens=1000
        ),
    )


def submit(results: list[dict[str, Any]], block_id: str = "toolu_1") -> SimpleNamespace:
    return SimpleNamespace(type="tool_use", id=block_id, name="submit_triage", input={"results": results})


class FakeStream:
    def __init__(self, item: Any) -> None:
        self.item = item

    def __enter__(self) -> FakeStream:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def get_final_message(self) -> Any:
        if isinstance(self.item, BaseException):
            raise self.item
        return self.item


class FakeMessages:
    def __init__(self, script: list[Any]) -> None:
        self.script = list(script)
        self.calls: list[dict[str, Any]] = []

    def stream(self, **kw: Any) -> FakeStream:
        self.calls.append({**kw, "messages": list(kw["messages"])})  # snapshot
        return FakeStream(self.script.pop(0))


def fake_client(script: list[Any]) -> Any:
    return SimpleNamespace(beta=SimpleNamespace(messages=FakeMessages(script)))


def calls_text(client: Any) -> str:
    return json.dumps(client.beta.messages.calls, default=lambda o: getattr(o, "__dict__", str(o)))


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "settings.py").write_text(
        'import os\n\nSTRIPE_KEY = "sk_live_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"\n'
        "api_key = 'fixtureapikeyvalue987654321'\n"
        "def run(q):\n    return db.execute('SELECT ' + q)\n"
    )
    return tmp_path


def three() -> list[Any]:
    return [
        make_finding(path="config/settings.py", line=6, snippet="a", severity=Severity.CRITICAL),
        make_finding(path="config/settings.py", line=6, snippet="b"),
        make_finding(path="config/settings.py", line=6, snippet="c"),
    ]


def test_suppression_threshold(repo: Path, caplog: pytest.LogCaptureFixture) -> None:
    fs = three()
    client = fake_client(
        [
            response(
                submit(
                    [
                        {
                            "id": fs[0].id,
                            "verdict": "not_exploitable",
                            "confidence": 4,
                            "reason": "q is a constant",
                        },
                        {
                            "id": fs[1].id,
                            "verdict": "not_exploitable",
                            "confidence": 3,
                            "reason": "probably fine",
                        },
                        {"id": fs[2].id, "verdict": "exploitable", "confidence": 5, "reason": "user input"},
                        {"id": "unknown", "verdict": "exploitable", "confidence": 5, "reason": "ignored"},
                    ]
                )
            )
        ]
    )
    with caplog.at_level(logging.INFO):
        stats = triage(client, TriageSettings(), fs, repo, [])
    assert stats.asked == 3 and stats.suppressed == 1 and not stats.failed
    assert not fs[0].kept and fs[0].triage.by == TriageBy.CLAUDE
    assert "q is a constant" in fs[0].triage.reason
    assert fs[1].kept and "probably fine" in fs[1].triage.reason and fs[1].triage.confidence == 3
    assert fs[2].kept and fs[2].triage.verdict == "exploitable"
    assert "tokens in=1200 out=300" in caplog.text

    kw = client.beta.messages.calls[0]
    assert kw["model"] == "claude-sonnet-5-5"
    assert kw["output_config"] == {"effort": "medium"}
    assert kw["tool_choice"] == {"type": "auto"}
    assert kw["cache_control"] == {"type": "ephemeral"}
    assert kw["tools"][0]["name"] == "submit_triage" and kw["tools"][0]["eager_input_streaming"] is True


def test_fail_open_on_api_error_and_refusal(repo: Path) -> None:
    for script in ([RuntimeError("api down")], [response(stop="refusal")]):
        fs = three()
        stats = triage(fake_client(script), TriageSettings(), fs, repo, [])
        assert stats.failed and all(f.kept for f in fs)


def test_invalid_tool_input_is_answered_with_an_error_then_retried(repo: Path) -> None:
    fs = three()[:1]
    bad = submit(
        [{"id": fs[0].id, "verdict": "not_exploitable", "confidence": 9, "reason": "x"}], "toolu_bad"
    )
    good = submit([{"id": fs[0].id, "verdict": "not_exploitable", "confidence": 5, "reason": "constant"}])
    client = fake_client([response(bad), response(good)])
    stats = triage(client, TriageSettings(), fs, repo, [])
    assert stats.suppressed == 1
    second = client.beta.messages.calls[1]["messages"]
    err = second[-1]["content"][0]
    assert err["tool_use_id"] == "toolu_bad" and err["is_error"] is True


def test_no_tool_call_is_nudged_then_fails_open(repo: Path) -> None:
    text = SimpleNamespace(type="text", text="I think they are fine")
    fs = three()
    stats = triage(fake_client([response(text, stop="end_turn")] * 3), TriageSettings(), fs, repo, [])
    assert stats.failed and all(f.kept for f in fs)


def test_secret_values_never_reach_claude(repo: Path, caplog: pytest.LogCaptureFixture) -> None:
    secrets = gitleaks.parse(load("gitleaks.json"))
    sast = make_finding(path="config/settings.py", line=6, snippet="sql")
    findings = [*secrets, sast]
    verdicts = [
        {"id": f.id, "verdict": "uncertain", "confidence": 2, "reason": "can't tell"} for f in findings
    ]
    client = fake_client([response(submit(verdicts))])
    with caplog.at_level(logging.DEBUG):
        triage(client, TriageSettings(), findings, repo, [])
    sent = calls_text(client)
    assert "sk_l…" in sent or "sk_l\\u2026" in sent  # the masked prefix is what Claude sees
    assert "is_fixture_or_example" in sent
    for s in FIXTURE_SECRETS:
        assert s not in sent
        assert s not in caplog.text


def test_candidates_scope_and_cap() -> None:
    fs = [make_finding(snippet=str(i)) for i in range(30)]
    fs.append(make_finding(snippet="low", severity=Severity.MEDIUM))
    fs.append(make_finding(snippet="dep", category=Category.DEPENDENCY))
    picked = candidates(fs, 20)
    assert len(picked) == 20
    assert all(f.category == Category.SAST and f.severity == Severity.HIGH for f in picked)
