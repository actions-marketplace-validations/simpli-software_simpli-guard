"""Shared scanner plumbing: pinned binary install, subprocess runs, results.

Binaries are downloaded from the scanner's GitHub release at a pinned
version, verified against a pinned SHA-256, and cached. If a download or
verification fails, a binary already on PATH is used with a warning; if
there is none, the scanner is skipped with a warning (never a crash).
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import logging
import os
import platform
import shutil
import stat
import subprocess
import tarfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from simpli_guard.masking import scrub
from simpli_guard.models import Finding

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class Asset:
    name: str
    sha256: str
    member: str | None = None  # binary inside an archive; None = the asset is the binary


@dataclass(frozen=True)
class ToolSpec:
    name: str
    repo: str
    tag: str
    exe: str  # name on PATH
    assets: dict[str, Asset]


@dataclass
class ScanResult:
    tool: str
    status: str  # ran | skipped | failed
    findings: list[Finding] = field(default_factory=list)
    message: str = ""


def platform_key() -> str:
    system = platform.system().lower()
    machine = platform.machine().lower()
    arch = "arm64" if machine in ("arm64", "aarch64") else "x64"
    return f"{system}-{arch}"


def tool_cache_dir() -> Path:
    env = os.environ.get("SIMPLI_GUARD_TOOL_CACHE")
    if env:
        return Path(env)
    runner = os.environ.get("RUNNER_TOOL_CACHE")
    if runner:
        return Path(runner) / "simpli-guard"
    return Path.home() / ".cache" / "simpli-guard" / "tools"


def _download(url: str, timeout: float = 300) -> bytes:
    with httpx.Client(follow_redirects=True, timeout=timeout) as c:
        r = c.get(url, headers={"User-Agent": "simpli-guard"})
        r.raise_for_status()
        return r.content


def install(spec: ToolSpec) -> Path | None:
    """Return a runnable path for the tool, or None (caller skips the scanner)."""
    key = platform_key()
    asset = spec.assets.get(key)
    exe_name = spec.exe + (".exe" if key.startswith("windows") else "")
    target = tool_cache_dir() / spec.name / spec.tag / exe_name
    if target.is_file():
        return target
    if asset is None:
        log.warning("%s: no pinned release build for %s", spec.name, key)
        return _from_path(spec)
    url = f"https://github.com/{spec.repo}/releases/download/{spec.tag}/{asset.name}"
    try:
        data = _download(url)
        digest = hashlib.sha256(data).hexdigest()
        if digest != asset.sha256:
            log.warning("%s: checksum mismatch for %s; refusing to use it", spec.name, asset.name)
            return _from_path(spec)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(_extract(data, asset))
        target.chmod(target.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        log.info("%s %s installed", spec.name, spec.tag)
        return target
    except (httpx.HTTPError, OSError, KeyError, tarfile.TarError, zipfile.BadZipFile) as e:
        log.warning("%s: could not fetch %s (%s)", spec.name, spec.tag, type(e).__name__)
        return _from_path(spec)


def _extract(data: bytes, asset: Asset) -> bytes:
    if asset.member is None:
        return data
    if asset.name.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            return z.read(asset.member)
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as t:
        f = t.extractfile(asset.member)
        if f is None:
            raise KeyError(asset.member)
        return f.read()


def _from_path(spec: ToolSpec) -> Path | None:
    found = shutil.which(spec.exe)
    if found:
        log.warning("%s: using %s from PATH (version not pinned)", spec.name, found)
        return Path(found)
    log.warning("%s: not available; skipping this scanner", spec.name)
    return None


def _child_env(extra: dict[str, str | None] | None) -> dict[str, str]:
    """The parent environment plus `extra`; a value of None removes the variable."""
    merged: dict[str, str | None] = {**os.environ, **(extra or {})}
    return {k: v for k, v in merged.items() if v is not None}


@dataclass
class Proc:
    code: int
    tail: str  # last stderr line, scrubbed; only for diagnosing a failed run


def run(
    args: list[str],
    cwd: Path,
    timeout: int = 1800,
    env: dict[str, str | None] | None = None,
    stdout_file: Path | None = None,
) -> Proc:
    """Run a scanner. Stdout is discarded (or written to `stdout_file` for a scanner
    that has no report-file flag) and stderr is never logged in full: scanner output
    can contain secret values and source code. Results are always read from a report
    file, never from the process output."""
    try:
        with contextlib.ExitStack() as stack:
            sink = stack.enter_context(stdout_file.open("wb")) if stdout_file else subprocess.DEVNULL
            proc = subprocess.run(
                args,
                cwd=cwd,
                stdout=sink,
                stderr=subprocess.PIPE,
                timeout=timeout,
                check=False,
                env=_child_env(env),
            )
    except (OSError, subprocess.TimeoutExpired) as e:
        log.warning("%s could not run (%s)", Path(args[0]).name, type(e).__name__)
        return Proc(-1, "")
    lines = [ln for ln in proc.stderr.decode("utf-8", "replace").splitlines() if ln.strip()]
    tail = scrub(lines[-1])[:300] if lines else ""
    return Proc(proc.returncode, tail)


def read_lines(root: Path, rel: str) -> list[str]:
    try:
        return (root / rel).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
