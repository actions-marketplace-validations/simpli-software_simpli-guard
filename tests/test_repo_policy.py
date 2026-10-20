"""Repository policy: public-launch branding, owner and workflow safety."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).parent.parent
REPO = "simpli-software/simpli-guard"
TEXT_FILES = [
    ROOT / ".github/ISSUE_TEMPLATE/config.yml",
    ROOT / "README.md",
    *sorted((ROOT / "examples").glob("*.yml")),
]


def test_action_has_the_marketplace_display_name() -> None:
    lines = (ROOT / "action.yml").read_text(encoding="utf-8").splitlines()
    assert lines[0] == "name: Simpli Gatehouse Guard"
    assert lines[1].startswith('description: "Gatehouse ')


def test_no_owner_placeholders_remain() -> None:
    for path in TEXT_FILES:
        text = path.read_text(encoding="utf-8")
        assert not re.search(r"OWNER/REPO|<owner>", text), path.name


def test_examples_reference_the_real_repo_with_a_hash_placeholder() -> None:
    found = 0
    for path in sorted((ROOT / "examples").glob("*.yml")):
        for line in path.read_text(encoding="utf-8").splitlines():
            if "simpli-guard@" in line and "uses:" in line and not line.lstrip().startswith("#"):
                found += 1
                assert re.search(r"uses: " + re.escape(REPO) + r"@<commit-sha> # v1\.x$", line), line
    assert found >= 1
    assert REPO in (ROOT / ".github/ISSUE_TEMPLATE/config.yml").read_text(encoding="utf-8")


def test_pyproject_urls_point_at_the_real_repo() -> None:
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "[project.urls]" in text
    for key, suffix in (("Homepage", ""), ("Issues", "/issues"), ("Source", "")):
        assert f'{key} = "https://github.com/{REPO}{suffix}"' in text


def test_workflows_never_use_pull_request_target_or_expose_secrets_to_pull_requests() -> None:
    for path in sorted((ROOT / ".github/workflows").glob("*.yml")):
        text = path.read_text(encoding="utf-8")
        assert "pull_request_target" not in text, path.name
        if re.search(r"^  pull_request:", text, re.M):
            secrets = set(re.findall(r"secrets\.(\w+)", text))
            assert secrets <= {"GITHUB_TOKEN"}, (path.name, secrets)


def test_contributing_states_the_launch_policy_and_the_guardrails() -> None:
    for name in ("CONTRIBUTING.md", ".github/pull_request_template.md", "README.md"):
        text = (ROOT / name).read_text(encoding="utf-8")
        assert "90 days" in text, name
        assert "https://developercertificate.org" in text, name
        assert "Signed-off-by" in text or "git commit -s" in text, name
    contributing = (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
    for needle in ("no CLA", "pull_request_target", "without secrets", "senior security review"):
        assert needle.lower() in contributing.lower(), needle
