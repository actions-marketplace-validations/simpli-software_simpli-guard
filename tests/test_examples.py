from __future__ import annotations

import json
import shutil
from pathlib import Path

from simpli_guard import aggregate as agg
from simpli_guard.config import CONFIG_PATH, load_config

EXAMPLES = Path(__file__).parent.parent / "examples"


def test_example_config_loads(tmp_path: Path) -> None:
    target = tmp_path / CONFIG_PATH
    target.parent.mkdir(parents=True)
    shutil.copy(EXAMPLES / "config" / "example.json", target)
    cfg = load_config(tmp_path)
    assert cfg.surface.urls == ["https://app.example.com", "https://api.example.com"]


def test_example_repos_file_loads() -> None:
    cfg = agg.load_repos(EXAMPLES / "repos.example.json")
    assert cfg.owner == "example-org"
    assert cfg.repos


def test_example_workflows_are_pinned_or_placeholder() -> None:
    for name in ("security-scan.yml", "aggregate.yml"):
        for line in (EXAMPLES / name).read_text(encoding="utf-8").splitlines():
            if "uses:" not in line or line.lstrip().startswith("#"):
                continue
            ref = line.split("uses:", 1)[1].split("#", 1)[0].strip()
            assert "@<commit-sha>" in ref or len(ref.rsplit("@", 1)[-1]) == 40, (name, line)


def test_example_json_is_valid() -> None:
    for p in EXAMPLES.rglob("*.json"):
        json.loads(p.read_text(encoding="utf-8"))
