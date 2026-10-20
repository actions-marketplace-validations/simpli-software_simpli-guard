"""`.simpli-guard/config.json` in the scanned repository. Every key is optional.

{
  "name": "Security scan",                  // heading on comments/issues/reports
  "failOn": "high",                          // PR mode: fail on NEW findings at/above this
  "categories": {"sast": true, "dependency": true, "secret": true, "iac": true,
                 "container": true, "license": true, "surface": true, "actions": true},
  "surface": {"urls": ["https://app.example.com"]},
  "ignore": [{"rule": "python.lang.security.audit.eval-detected", "reason": "...",
              "expires": "2026-12-31"},
             {"id": "<fingerprint>", "reason": "..."},
             {"path": "scripts/**", "reason": "..."}],
  "triage": {"enabled": true, "model": "claude-sonnet-5-5", "effort": "medium", "maxFindings": 60},
  "testPaths": ["qa/**"]
}
"""

from __future__ import annotations

import fnmatch
import json
import logging
from datetime import UTC, date, datetime
from pathlib import Path, PurePosixPath

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from simpli_guard.models import Category, Severity

log = logging.getLogger(__name__)

CONFIG_PATH = ".simpli-guard/config.json"


class _Model(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="ignore")


class IgnoreRule(_Model):
    id: str | None = None
    rule: str | None = None
    path: str | None = None
    reason: str
    expires: date | None = None

    @field_validator("reason")
    @classmethod
    def _reason_required(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("an ignore entry needs a non-empty reason")
        return v.strip()

    @model_validator(mode="after")
    def _has_selector(self) -> IgnoreRule:
        if not (self.id or self.rule or self.path):
            raise ValueError("an ignore entry needs at least one of id, rule, path")
        return self

    def expired(self, today: date | None = None) -> bool:
        return self.expires is not None and (today or datetime.now(UTC).date()) > self.expires


class SurfaceConfig(_Model):
    urls: list[str] = Field(default_factory=list)


class TriageConfig(_Model):
    enabled: bool = True
    model: str = "claude-sonnet-5-5"
    effort: str = "medium"
    max_findings: int = Field(default=60, alias="maxFindings", ge=0, le=100)


class GuardConfig(_Model):
    name: str = "Security scan"
    fail_on: Severity = Field(default=Severity.HIGH, alias="failOn")
    categories: dict[Category, bool] = Field(default_factory=dict)
    surface: SurfaceConfig = Field(default_factory=SurfaceConfig)
    ignore: list[IgnoreRule] = Field(default_factory=list)
    triage: TriageConfig = Field(default_factory=TriageConfig)
    test_paths: list[str] = Field(default_factory=list, alias="testPaths")

    def enabled(self, category: Category) -> bool:
        return self.categories.get(category, True)


def load_config(repo_root: Path) -> GuardConfig:
    path = repo_root / CONFIG_PATH
    if not path.is_file():
        return GuardConfig()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return GuardConfig.model_validate(data)
    except (OSError, ValueError, ValidationError) as e:
        # A broken config must not silently disable scanning: fail loudly.
        raise SystemExit(f"invalid {CONFIG_PATH}: {e}") from None


# ---------- path classification ----------

_TEST_DIRS = {"tests", "test", "__tests__", "e2e", "spec", "testing"}
_TEST_FILES = [
    "test_*.py",
    "*_test.py",
    "conftest.py",
    "*.test.ts",
    "*.test.tsx",
    "*.test.js",
    "*.test.jsx",
    "*.spec.ts",
    "*.spec.tsx",
    "*.spec.js",
    "*.spec.jsx",
    "*_test.go",
]
_EXAMPLE_DIRS = {"fixtures", "fixture", "examples", "example", "samples", "sample", "testdata", "mocks"}
_EXAMPLE_MARKERS = (".example", ".sample", ".template", ".dist")


def glob_match(path: str, pattern: str) -> bool:
    """fnmatch where `**/` may also match zero directories."""
    p = path.replace("\\", "/").removeprefix("./")
    if fnmatch.fnmatchcase(p, pattern):
        return True
    return pattern.startswith("**/") and fnmatch.fnmatchcase(p, pattern[3:])


def is_test_path(path: str, extra_globs: list[str] | None = None) -> bool:
    pp = PurePosixPath(path.replace("\\", "/"))
    if any(part.lower() in _TEST_DIRS for part in pp.parts[:-1]):
        return True
    if any(fnmatch.fnmatchcase(pp.name, g) for g in _TEST_FILES):
        return True
    return any(glob_match(str(pp), g) for g in extra_globs or [])


def is_example_path(path: str) -> bool:
    pp = PurePosixPath(path.replace("\\", "/"))
    if any(part.lower() in _EXAMPLE_DIRS for part in pp.parts[:-1]):
        return True
    return any(m in pp.name.lower() for m in _EXAMPLE_MARKERS)
