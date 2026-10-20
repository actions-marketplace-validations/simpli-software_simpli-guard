from __future__ import annotations

import hashlib
import io
import tarfile
from pathlib import Path

import pytest

from simpli_guard.scanners import base
from simpli_guard.scanners.base import Asset, ToolSpec


def _tgz(member: str, data: bytes) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        info = tarfile.TarInfo(member)
        info.size = len(data)
        t.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def spec(blob: bytes, digest: str | None = None) -> ToolSpec:
    asset = Asset("tool.tar.gz", digest or hashlib.sha256(blob).hexdigest(), member="tool")
    return ToolSpec("faketool", "o/r", "v1.0.0", "faketool-not-on-path", {base.platform_key(): asset})


def test_install_verifies_checksum_and_caches(monkeypatch: pytest.MonkeyPatch) -> None:
    blob = _tgz("tool", b"#!/bin/sh\necho hi\n")
    calls: list[str] = []
    monkeypatch.setattr(base, "_download", lambda url, timeout=300: calls.append(url) or blob)
    path = base.install(spec(blob))
    assert path is not None and path.read_bytes() == b"#!/bin/sh\necho hi\n"
    assert calls == ["https://github.com/o/r/releases/download/v1.0.0/tool.tar.gz"]
    assert base.install(spec(blob)) == path and len(calls) == 1  # cached


def test_install_rejects_bad_checksum(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    blob = _tgz("tool", b"evil")
    monkeypatch.setattr(base, "_download", lambda url, timeout=300: blob)
    assert base.install(spec(blob, digest="0" * 64)) is None
    assert "checksum mismatch" in caplog.text


def test_install_skips_when_download_fails(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    def fail(url: str, timeout: float = 300) -> bytes:
        raise OSError("offline")

    monkeypatch.setattr(base, "_download", fail)
    assert base.install(spec(b"x")) is None
    assert "skipping this scanner" in caplog.text


def test_tool_cache_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SIMPLI_GUARD_TOOL_CACHE", str(tmp_path))
    assert base.tool_cache_dir() == tmp_path
