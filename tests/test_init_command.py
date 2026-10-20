from __future__ import annotations

import argparse
import json
import shutil
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
import yaml

from simpli_guard import cli, init_command
from simpli_guard.config import CONFIG_PATH, load_config
from simpli_guard.init_command import (
    ACTION_REPO,
    AGGREGATE_WORKFLOW,
    PLACEHOLDER_USES,
    SCAN_WORKFLOW,
    Deps,
    GhResult,
    GhRunner,
    Pin,
    PinError,
)
from simpli_guard.models import Category, Severity

EXAMPLES = Path(__file__).parent.parent / "examples"
API = "https://api.github.com/repos/" + ACTION_REPO
COMMIT = "a" * 39 + "1"
TAG_OBJ = "b" * 39 + "2"
# A sentinel string, not a credential. Used only to prove no output ever contains the env token.
SENTINEL_TOKEN = "sentinel-env-token-must-never-be-printed"


# ---------- helpers ----------


def fake_fetch(routes: dict[str, Any], calls: list[str] | None = None) -> Callable[[str], Any]:
    def fetch(url: str) -> Any:
        if calls is not None:
            calls.append(url)
        if url not in routes:
            raise PinError("not found")
        value = routes[url]
        if isinstance(value, Exception):
            raise value
        return value

    return fetch


def annotated_routes(tag: str = "v1.2.3") -> dict[str, Any]:
    return {
        f"{API}/releases/latest": {"tag_name": tag},
        f"{API}/git/ref/tags/{tag}": {"object": {"type": "tag", "sha": TAG_OBJ}},
        f"{API}/git/tags/{TAG_OBJ}": {"object": {"type": "commit", "sha": COMMIT}},
    }


def lightweight_routes(tag: str = "v1.2.3") -> dict[str, Any]:
    return {
        f"{API}/releases/latest": {"tag_name": tag},
        f"{API}/git/ref/tags/{tag}": {"object": {"type": "commit", "sha": COMMIT}},
    }


class FakeGh:
    """Stands in for `gh`. Records every call; answers from canned responses."""

    def __init__(
        self,
        repo_secrets: str = "",
        org: str | None = None,
        org_secrets: str = "",
        private: bool | None = True,
        fail_list: bool = False,
        fail_org_list: bool = False,
    ) -> None:
        self.calls: list[list[str]] = []
        self.repo_secrets, self.org, self.org_secrets = repo_secrets, org, org_secrets
        self.private, self.fail_list, self.fail_org_list = private, fail_list, fail_org_list

    def __call__(self, args: list[str]) -> GhResult:
        self.calls.append(args)
        if args[:2] == ["secret", "list"]:
            if "--org" in args:
                return GhResult(1, "") if self.fail_org_list else GhResult(0, self.org_secrets)
            return GhResult(1, "") if self.fail_list else GhResult(0, self.repo_secrets)
        if args[:2] == ["repo", "view"] and "isPrivate" in args[3]:
            if self.private is None:
                return GhResult(1, "")
            return GhResult(0, "true\n" if self.private else "false\n")
        if args[:2] == ["repo", "view"]:
            owner = {"login": self.org or "someone"}
            return GhResult(0, json.dumps({"owner": owner, "isInOrganization": self.org is not None}))
        return GhResult(1, "")


class Session:
    def __init__(
        self, root: Path, fetch: Callable[[str], Any], gh: GhRunner | None, inputs: list[str]
    ) -> None:
        self.root, self.fetch, self.gh = root, fetch, gh
        self.inputs = list(inputs)
        self.prompts: list[str] = []
        self.lines: list[str] = []

    def input_fn(self, prompt: str) -> str:
        self.prompts.append(prompt)
        if not self.inputs:
            raise EOFError
        return self.inputs.pop(0)

    @property
    def text(self) -> str:
        return "\n".join(self.lines)

    def run(self, *argv: str) -> int:
        p = argparse.ArgumentParser()
        init_command.add_parser(p.add_subparsers(dest="cmd"))
        args = p.parse_args(["init", "--root", str(self.root), *argv])
        deps = Deps(fetch=self.fetch, input_fn=self.input_fn, out=self.lines.append, gh=lambda _root: self.gh)
        return init_command.run_init(args, deps)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    (tmp_path / ".git").mkdir()
    return tmp_path


def session(
    repo: Path, inputs: list[str] | None = None, gh: GhRunner | None = None, **routes: Any
) -> Session:
    fetch = fake_fetch(routes or annotated_routes())
    return Session(repo, fetch, gh or FakeGh(repo_secrets="ANTHROPIC_API_KEY\t2026-10-01"), inputs or [])


def read(repo: Path, rel: str) -> str:
    data = (repo / rel).read_bytes()
    assert b"\r" not in data, f"{rel} has CR line endings"
    return data.decode("utf-8")


def body_of(path: Path) -> str:
    text = path.read_text(encoding="utf-8").replace("\r\n", "\n")
    return text[text.index("\nname: ") + 1 :]


def answers(*given: str) -> list[str]:
    """Inputs for all nine prompts, with blanks (= defaults) for any not given."""
    base = [""] * 9
    for i, v in enumerate(given):
        base[i] = v
    return base


# ---------- templates stay in sync with the examples ----------


def test_scan_template_matches_example() -> None:
    out = init_command.render_scan_workflow(Pin(PLACEHOLDER_USES, False), "03:17")
    assert out.endswith(body_of(EXAMPLES / "security-scan.yml"))


def test_aggregate_template_matches_example() -> None:
    out = init_command.render_aggregate_workflow(Pin(PLACEHOLDER_USES, False), "03:17")
    assert out.endswith(body_of(EXAMPLES / "aggregate.yml"))


# ---------- defaults run ----------


def test_defaults_write_both_files_pinned(repo: Path) -> None:
    s = session(repo)
    assert s.run("--yes") == 0
    assert s.prompts == []  # --yes asks nothing
    wf = read(repo, SCAN_WORKFLOW)
    assert wf.count(f"uses: {ACTION_REPO}@{COMMIT} # v1.2.3") == 2
    assert PLACEHOLDER_USES not in wf
    assert "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1" in wf  # third party kept
    doc = yaml.safe_load(wf)
    assert doc["name"] == "Security scan"
    assert doc[True]["schedule"] == [{"cron": "17 3 * * *"}]  # PyYAML reads `on:` as the key True
    assert set(doc["jobs"]) == {"pr", "nightly"}
    assert json.loads(read(repo, CONFIG_PATH)) == {}
    assert not (repo / AGGREGATE_WORKFLOW).exists()
    load_config(repo)  # the real loader accepts what was written


def test_every_uses_line_is_pinned_by_full_hash(repo: Path) -> None:
    session(repo).run("--yes")
    seen = 0
    for line in read(repo, SCAN_WORKFLOW).splitlines():
        if "uses:" in line and not line.lstrip().startswith("#"):
            ref = line.split("uses:", 1)[1].split("#", 1)[0].strip()
            assert len(ref.rsplit("@", 1)[-1]) == 40, line
            assert " # v" in line
            seen += 1
    assert seen == 4


def test_lightweight_tag_resolves(repo: Path) -> None:
    session(repo, **lightweight_routes("v1.0.0")).run("--yes")
    assert f"{ACTION_REPO}@{COMMIT} # v1.0.0" in read(repo, SCAN_WORKFLOW)


def test_annotated_tag_is_dereferenced_to_the_commit(repo: Path) -> None:
    session(repo).run("--yes")
    wf = read(repo, SCAN_WORKFLOW)
    assert TAG_OBJ not in wf and COMMIT in wf


def test_detected_test_folders_prefill_the_config(repo: Path) -> None:
    for d in ("qa", "tests", "apps/web/cypress", "node_modules/qa"):
        (repo / d).mkdir(parents=True)
    session(repo).run("--yes")
    assert json.loads(read(repo, CONFIG_PATH)) == {"testPaths": ["qa/**", "apps/web/cypress/**"]}


def test_detect_test_dirs_separates_builtin_from_extra(repo: Path) -> None:
    for d in ("tests", "src/__tests__", "playwright", "unit_tests", "src/app"):
        (repo / d).mkdir(parents=True)
    extra, builtin = init_command.detect_test_dirs(repo)
    assert extra == ["playwright/**", "unit_tests/**"]
    assert set(builtin) == {"tests", "src/__tests__"}


# ---------- pinning failures ----------


def test_offline_writes_placeholder_and_prints_help(repo: Path) -> None:
    s = session(repo, **{f"{API}/releases/latest": PinError("could not reach the GitHub API")})
    assert s.run("--yes") == 0
    wf = read(repo, SCAN_WORKFLOW)
    assert wf.count(PLACEHOLDER_USES) == 2
    assert "TODO: replace <commit-sha>" in wf
    assert yaml.safe_load(wf)["name"] == "Security scan"  # still valid YAML
    assert "could not reach the GitHub API" in s.text
    assert f"gh api repos/{ACTION_REPO}/commits/<that tag> --jq .sha" in s.text
    assert "Fill in the <commit-sha> placeholder" in s.text


@pytest.mark.parametrize(
    "routes",
    [
        {f"{API}/releases/latest": {"tag_name": "bad tag; rm -rf"}},
        {f"{API}/releases/latest": ["not", "an", "object"]},
        {**lightweight_routes(), f"{API}/git/ref/tags/v1.2.3": {"object": {"type": "commit", "sha": "xyz"}}},
        {**lightweight_routes(), f"{API}/git/ref/tags/v1.2.3": {"object": {"type": "tree", "sha": COMMIT}}},
    ],
)
def test_malformed_api_answers_fall_back_to_placeholder(repo: Path, routes: dict[str, Any]) -> None:
    assert session(repo, **routes).run("--yes") == 0
    assert PLACEHOLDER_USES in read(repo, SCAN_WORKFLOW)


def test_tag_chain_loop_is_bounded() -> None:
    routes = annotated_routes()
    routes[f"{API}/git/tags/{TAG_OBJ}"] = {"object": {"type": "tag", "sha": TAG_OBJ}}  # points at itself
    calls: list[str] = []
    with pytest.raises(PinError):
        init_command.resolve_latest(fake_fetch(routes, calls))
    assert len(calls) < 10


def test_ref_flag_pins_without_any_lookup(repo: Path) -> None:
    calls: list[str] = []
    s = Session(repo, fake_fetch({}, calls), FakeGh(repo_secrets="ANTHROPIC_API_KEY"), [])
    sha = "c" * 40
    assert s.run("--yes", "--ref", f"{ACTION_REPO}@{sha.upper()}#v9.9.9") == 0
    assert calls == []
    assert f"uses: {ACTION_REPO}@{sha} # v9.9.9" in read(repo, SCAN_WORKFLOW)


@pytest.mark.parametrize(
    "ref", ["owner/repo@main", "owner/repo", "owner/repo@abc123", "@" + "a" * 40, "a/b@" + "g" * 40]
)
def test_bad_ref_is_rejected(repo: Path, ref: str) -> None:
    s = session(repo)
    assert s.run("--yes", "--ref", ref) == 2
    assert not (repo / SCAN_WORKFLOW).exists()
    assert "--ref must look like" in s.text


# ---------- the real fetcher: token handling ----------


class _FakeResponse:
    def __init__(self, payload: Any) -> None:
        self._data = json.dumps(payload).encode()

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def read(self, _n: int = -1) -> bytes:
        return self._data


class _FakeOpener:
    def __init__(self, sink: list[urllib.request.Request], error: Exception | None = None) -> None:
        self.sink, self.error = sink, error

    def open(self, req: urllib.request.Request, timeout: float = 0) -> _FakeResponse:
        self.sink.append(req)
        if self.error:
            raise self.error
        assert timeout > 0
        return _FakeResponse({"tag_name": "v1.0.0"})


def patch_opener(
    monkeypatch: pytest.MonkeyPatch, error: Exception | None = None
) -> list[urllib.request.Request]:
    sent: list[urllib.request.Request] = []
    monkeypatch.setattr(urllib.request, "build_opener", lambda *_h: _FakeOpener(sent, error))
    return sent


def test_no_token_sent_unless_env_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GH_TOKEN", raising=False)
    sent = patch_opener(monkeypatch)
    assert init_command.default_fetch(f"{API}/releases/latest") == {"tag_name": "v1.0.0"}
    assert not any(k.lower() == "authorization" for k in sent[0].headers)


@pytest.mark.parametrize("var", ["GITHUB_TOKEN", "GH_TOKEN"])
def test_token_sent_when_env_set(monkeypatch: pytest.MonkeyPatch, var: str) -> None:
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GH_TOKEN", raising=False)
    monkeypatch.setenv(var, SENTINEL_TOKEN)
    sent = patch_opener(monkeypatch)
    init_command.default_fetch(f"{API}/releases/latest")
    assert sent[0].get_header("Authorization") == f"Bearer {SENTINEL_TOKEN}"


def test_fetch_refuses_other_hosts(monkeypatch: pytest.MonkeyPatch) -> None:
    sent = patch_opener(monkeypatch)
    for url in ("https://example.com/x", "http://api.github.com/x", "https://api.github.com.evil.test/x"):
        with pytest.raises(PinError):
            init_command.default_fetch(url)
    assert sent == []


def test_redirect_off_the_api_host_is_refused() -> None:
    h = init_command._SameHostRedirect()
    req = urllib.request.Request(f"{API}/releases/latest", headers={"Authorization": "Bearer x"})
    with pytest.raises(urllib.error.HTTPError):
        h.redirect_request(req, None, 302, "Found", {}, "https://example.com/elsewhere")  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "error",
    [
        urllib.error.HTTPError("u", 403, "rate limited", {}, None),  # type: ignore[arg-type]
        urllib.error.URLError("offline"),
        TimeoutError(),
    ],
)
def test_fetch_errors_become_pin_errors_without_leaking(
    monkeypatch: pytest.MonkeyPatch, error: Exception
) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", SENTINEL_TOKEN)
    patch_opener(monkeypatch, error)
    with pytest.raises(PinError) as e:
        init_command.default_fetch(f"{API}/releases/latest")
    assert SENTINEL_TOKEN not in str(e.value)


def test_token_never_reaches_output(repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", SENTINEL_TOKEN)
    s = session(repo)
    s.run("--yes")
    assert SENTINEL_TOKEN not in s.text + read(repo, SCAN_WORKFLOW) + read(repo, CONFIG_PATH)


# ---------- questions ----------


def test_interactive_answers_flow_into_the_files(repo: Path) -> None:
    s = session(
        repo,
        inputs=[
            "Acme scan",  # heading
            "medium",  # failOn
            "license, 8",  # off: license and actions (by name and by number)
            "https://app.acme.test, https://api.acme.test",
            "y",  # triage
            "claude-test-model",  # model
            "e2e/**, qa/**",  # test paths
            "05:30",  # time
            "n",  # aggregate
        ],
    )
    assert s.run() == 0
    assert json.loads(read(repo, CONFIG_PATH)) == {
        "name": "Acme scan",
        "failOn": "medium",
        "categories": {"license": False, "actions": False},
        "surface": {"urls": ["https://app.acme.test", "https://api.acme.test"]},
        "triage": {"model": "claude-test-model"},
        "testPaths": ["e2e/**", "qa/**"],
    }
    loaded = load_config(repo)
    assert loaded.fail_on is Severity.MEDIUM and not loaded.enabled(Category.ACTIONS)
    wf = read(repo, SCAN_WORKFLOW)
    assert 'cron: "30 5 * * *" # nightly, 05:30 UTC' in wf
    assert yaml.safe_load(wf)[True]["schedule"] == [{"cron": "30 5 * * *"}]


def test_prompts_show_defaults_and_the_triage_note(repo: Path) -> None:
    s = session(repo, inputs=answers())
    s.run()
    joined = "\n".join(s.prompts)
    assert "[Security scan]" in joined
    assert "[high]" in joined
    assert "[claude-sonnet-5-5]" in joined  # the default in config.py
    assert "[03:17]" in joined
    assert "ANTHROPIC_API_KEY" in s.text
    assert "8) actions" in s.text  # the zizmor category is offered
    assert json.loads(read(repo, CONFIG_PATH)) == {}


def test_enter_everywhere_equals_yes(repo: Path, tmp_path_factory: pytest.TempPathFactory) -> None:
    other = tmp_path_factory.mktemp("other")
    (other / ".git").mkdir()
    session(repo, inputs=answers()).run()
    session(other).run("--yes")
    assert read(repo, SCAN_WORKFLOW) == read(other, SCAN_WORKFLOW)
    assert read(repo, CONFIG_PATH) == read(other, CONFIG_PATH)


def test_end_of_input_takes_defaults(repo: Path) -> None:
    assert session(repo, inputs=[]).run() == 0
    assert json.loads(read(repo, CONFIG_PATH)) == {}


def test_invalid_answers_are_asked_again(repo: Path) -> None:
    s = session(
        repo,
        inputs=[
            "",
            "low",  # not allowed, asks again
            "critical",
            "",
            "http://insecure.test, https://ok.test",  # http rejected
            "https://user:pw@ok.test",  # credentials rejected
            "https://ok.test",
            "",
            "",
            "",
            "25:99",  # bad time
            "06:05",
            "",
        ],
    )
    s.run()
    assert "choose critical, high or medium" in s.text
    assert "every URL must start with https://" in s.text
    assert "must not contain credentials" in s.text
    assert "use HH:MM" in s.text
    cfg = json.loads(read(repo, CONFIG_PATH))
    assert cfg["failOn"] == "critical" and cfg["surface"] == {"urls": ["https://ok.test"]}
    assert 'cron: "5 6 * * *"' in read(repo, SCAN_WORKFLOW)


def test_triage_off_skips_model_and_secret_check(repo: Path) -> None:
    gh = FakeGh()
    s = session(repo, inputs=["", "", "", "", "n"], gh=gh)
    s.run()
    assert json.loads(read(repo, CONFIG_PATH)) == {"triage": {"enabled": False}}
    assert not any("Triage model" in p for p in s.prompts)
    assert gh.calls == []
    assert "gh secret set" not in s.text


def test_parsers() -> None:
    p = init_command
    assert p.parse_categories("none") == [] and p.parse_categories("") == []
    assert p.parse_categories("8 1 sast") == [Category.SAST, Category.ACTIONS]
    with pytest.raises(ValueError):
        p.parse_categories("nope")
    with pytest.raises(ValueError):
        p.parse_categories("9")
    assert p.parse_time("3:07") == "03:07"
    assert p.parse_paths("a/**, b\\c/**") == ["a/**", "b/c/**"]
    for bad in ("/abs/**", "../up/**", 'q"uote'):
        with pytest.raises(ValueError):
            p.parse_paths(bad)
    for bad in ("", "x" * 81, "line\nbreak"):
        with pytest.raises(ValueError):
            p.parse_heading(bad)
    with pytest.raises(ValueError):
        p.parse_model("bad model!")
    with pytest.raises(ValueError):
        p.parse_yes_no("maybe")


# ---------- writing files ----------


def test_existing_files_are_never_overwritten_without_force(repo: Path) -> None:
    wf = repo / SCAN_WORKFLOW
    wf.parent.mkdir(parents=True)
    wf.write_text("name: mine\njobs: {}\n", encoding="utf-8")
    s = session(repo)
    assert s.run("--yes") == 0
    assert wf.read_text(encoding="utf-8") == "name: mine\njobs: {}\n"
    assert "exists and differs (use --force to overwrite)" in s.text
    assert "-name: mine" in s.text and "+name: Security scan" in s.text  # the short diff
    assert (repo / CONFIG_PATH).exists()  # the other file is still written
    git_add = next(ln for ln in s.lines if "git add" in ln)
    assert ".simpli-guard/config.json" in git_add and SCAN_WORKFLOW not in git_add


def test_force_overwrites(repo: Path) -> None:
    wf = repo / SCAN_WORKFLOW
    wf.parent.mkdir(parents=True)
    wf.write_text("name: mine\n", encoding="utf-8")
    s = session(repo)
    s.run("--yes", "--force")
    assert read(repo, SCAN_WORKFLOW).startswith("# Generated by `simpli-guard init`")
    assert "overwritten" in s.text


def test_rerun_is_idempotent(repo: Path) -> None:
    session(repo).run("--yes")
    first = read(repo, SCAN_WORKFLOW), read(repo, CONFIG_PATH)
    s = session(repo)
    s.run("--yes")
    assert (read(repo, SCAN_WORKFLOW), read(repo, CONFIG_PATH)) == first
    assert s.text.count("unchanged") == 2


def test_crlf_existing_copy_counts_as_unchanged(repo: Path) -> None:
    session(repo).run("--yes")
    wf = repo / SCAN_WORKFLOW
    wf.write_bytes(wf.read_bytes().replace(b"\n", b"\r\n"))
    s = session(repo)
    s.run("--yes")
    assert "unchanged" in s.text and b"\r\n" in wf.read_bytes()  # left alone, not rewritten


def test_dry_run_writes_nothing(repo: Path) -> None:
    s = session(repo)
    assert s.run("--yes", "--dry-run") == 0
    assert not (repo / ".github").exists() and not (repo / ".simpli-guard").exists()
    assert "would be created: .github/workflows/security-scan.yml" in s.text
    assert f"uses: {ACTION_REPO}@{COMMIT} # v1.2.3" in s.text
    assert "Run again without --dry-run" in s.text


def test_dry_run_with_existing_file_shows_diff_and_keeps_it(repo: Path) -> None:
    cfg = repo / CONFIG_PATH
    cfg.parent.mkdir(parents=True)
    cfg.write_text('{"failOn": "critical"}\n', encoding="utf-8")
    s = session(repo)
    s.run("--yes", "--dry-run")
    assert cfg.read_text(encoding="utf-8") == '{"failOn": "critical"}\n'
    assert "exists and differs" in s.text


def test_dry_run_force_reports_overwrite_but_touches_nothing(repo: Path) -> None:
    cfg = repo / CONFIG_PATH
    cfg.parent.mkdir(parents=True)
    cfg.write_text('{"failOn": "critical"}\n', encoding="utf-8")
    s = session(repo)
    s.run("--yes", "--dry-run", "--force")
    assert "would be overwritten" in s.text
    assert cfg.read_text(encoding="utf-8") == '{"failOn": "critical"}\n'


def test_refuses_outside_a_git_root(tmp_path: Path) -> None:
    s = session(tmp_path)
    assert s.run("--yes") == 2
    assert not (tmp_path / ".github").exists()
    assert "not the root of a git repository" in s.text


def test_refuses_to_write_through_a_symlink_out_of_the_repo(
    repo: Path, tmp_path_factory: pytest.TempPathFactory
) -> None:
    outside = tmp_path_factory.mktemp("outside")
    try:
        (repo / ".github").symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not available")
    s = session(repo)
    s.run("--yes")
    assert not list(outside.rglob("*.yml"))
    assert "resolves outside the repository" in s.text


# ---------- the aggregate extra ----------

AGG_ANSWERS = ["", "", "", "", "", "", "", "", "y"]


def test_aggregate_is_off_by_default_and_explained(repo: Path) -> None:
    s = session(repo, inputs=answers())
    s.run()
    assert not (repo / AGGREGATE_WORKFLOW).exists()
    assert "GUARD_READ_TOKEN" in s.text and "PRIVATE repository" in s.text


def test_aggregate_written_when_chosen(repo: Path) -> None:
    s = session(repo, inputs=AGG_ANSWERS, gh=FakeGh(repo_secrets="ANTHROPIC_API_KEY", private=True))
    s.run()
    wf = read(repo, AGGREGATE_WORKFLOW)
    assert f"uses: {ACTION_REPO}@{COMMIT} # v1.2.3" in wf
    assert 'cron: "7 5 * * *" # 05:07 UTC, after the 03:17 nightly scans' in wf  # the example's own time
    assert yaml.safe_load(wf)["jobs"]["aggregate"]["steps"][1]["with"]["mode"] == "aggregate"
    assert "gh secret set GUARD_READ_TOKEN" in s.text


def test_aggregate_follows_a_custom_nightly_time(repo: Path) -> None:
    inputs = ["", "", "", "", "", "", "", "23:30", "y"]
    s = session(repo, inputs=inputs, gh=FakeGh(repo_secrets="ANTHROPIC_API_KEY"))
    s.run()
    wf = read(repo, AGGREGATE_WORKFLOW)
    assert 'cron: "20 1 * * *" # 01:20 UTC, after the 23:30 nightly scans' in wf


def test_aggregate_refused_in_a_public_repository(repo: Path) -> None:
    s = session(repo, inputs=AGG_ANSWERS, gh=FakeGh(repo_secrets="ANTHROPIC_API_KEY", private=False))
    s.run()
    assert not (repo / AGGREGATE_WORKFLOW).exists()
    assert "this repository is public" in s.text


def test_yes_never_writes_the_aggregate(repo: Path) -> None:
    session(repo).run("--yes")
    assert not (repo / AGGREGATE_WORKFLOW).exists()


# ---------- the secret check ----------


def test_secret_found_in_repo(repo: Path) -> None:
    gh = FakeGh(repo_secrets="OTHER\t2026-01-01\nANTHROPIC_API_KEY\t2026-10-01\n")
    s = session(repo, gh=gh)
    s.run("--yes")
    assert "ANTHROPIC_API_KEY is set (repository secret)" in s.text
    assert "gh secret set" not in s.text


def test_secret_found_in_org(repo: Path) -> None:
    gh = FakeGh(repo_secrets="OTHER\tx", org="acme-co", org_secrets="ANTHROPIC_API_KEY\tx")
    s = session(repo, gh=gh)
    s.run("--yes")
    assert "is set (organization secret)" in s.text
    assert ["secret", "list", "--org", "acme-co"] in gh.calls


def test_secret_missing_prints_the_set_command(repo: Path) -> None:
    gh = FakeGh(repo_secrets="OTHER\tx", org="acme-co", org_secrets="ELSE\tx")
    s = session(repo, gh=gh)
    s.run("--yes")
    assert "ANTHROPIC_API_KEY is not set" in s.text
    assert "gh secret set ANTHROPIC_API_KEY" in s.text
    assert "Add the ANTHROPIC_API_KEY secret" in s.text


def test_secret_missing_for_a_personal_repo_does_not_query_an_org(repo: Path) -> None:
    gh = FakeGh(repo_secrets="")
    session(repo, gh=gh).run("--yes")
    assert not any("--org" in c for c in gh.calls)


def test_gh_failures_say_could_not_check(repo: Path) -> None:
    for gh in (FakeGh(fail_list=True), FakeGh(org="acme-co", fail_org_list=True)):
        s = session(repo, gh=gh)
        s.run("--yes", "--force")
        assert "could not be checked" in s.text


def test_gh_not_installed(repo: Path) -> None:
    s = Session(repo, fake_fetch(annotated_routes()), None, [])
    assert s.run("--yes") == 0
    assert "could not be checked (gh is not installed)" in s.text
    assert "gh secret set ANTHROPIC_API_KEY" in s.text


def test_gh_only_ever_lists_never_reads_or_sets_a_value(repo: Path) -> None:
    gh = FakeGh(repo_secrets="", org="acme-co")
    session(repo, gh=gh).run("--yes")
    for call in gh.calls:
        assert call[:2] in (["secret", "list"], ["repo", "view"])
        assert not {"set", "delete", "--body", "-b"} & set(call)


def test_default_gh_runner_absent_when_gh_missing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    assert init_command.default_gh_runner(tmp_path) is None


def test_org_name_from_gh_is_validated_before_use() -> None:
    def odd(args: list[str]) -> GhResult:
        if args[:2] == ["secret", "list"]:
            return GhResult(0, "")
        return GhResult(0, json.dumps({"owner": {"login": "--evil flag"}, "isInOrganization": True}))

    assert init_command.check_secret(odd).status == "missing"


# ---------- validation of generated output ----------


def test_validate_workflow_rejects_unpinned_and_crlf() -> None:
    good = init_command.render_scan_workflow(Pin(PLACEHOLDER_USES, False), "03:17")
    init_command.validate_workflow(good)
    for bad in (
        good.replace("\n", "\r\n"),
        good.replace("\n", "\n\t", 1),
        good.replace("<commit-sha> # v1.x", "v1", 1),
        good.replace('"17 3 * * *"', '"not cron"'),
    ):
        with pytest.raises(init_command.InitError):
            init_command.validate_workflow(bad)


def test_validate_config_detects_a_mismatch() -> None:
    a = init_command.Answers(fail_on=Severity.CRITICAL)
    with pytest.raises(init_command.InitError):
        init_command.validate_config("{}\n", a)
    with pytest.raises(init_command.InitError):
        init_command.validate_config("{not json", a)


def test_config_contains_only_non_default_fields() -> None:
    assert init_command.build_config(init_command.Answers()) == {}
    a = init_command.Answers(triage=False, model="anything-ignored-when-off")
    assert init_command.build_config(a) == {"triage": {"enabled": False}}


def test_output_names_only_the_public_action_repo() -> None:
    blob = (
        init_command.render_scan_workflow(Pin(PLACEHOLDER_USES, False), "03:17")
        + init_command.render_aggregate_workflow(Pin(PLACEHOLDER_USES, False), "03:17")
        + "\n".join(init_command.placeholder_help())
    ).lower()
    rest = blob.replace(ACTION_REPO, "").replace("simpli-guard", "")
    assert "simpli" not in rest  # no other product, domain or account name


# ---------- wiring into the existing CLI ----------


def test_cli_subcommand_is_wired(
    repo: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(shutil, "which", lambda _name: None)  # no gh on PATH, no network
    sha = "d" * 40
    rc = cli.main(["init", "--root", str(repo), "--yes", "--ref", f"{ACTION_REPO}@{sha}"])
    assert rc == 0
    assert f"uses: {ACTION_REPO}@{sha}" in read(repo, SCAN_WORKFLOW)
    assert "Next steps:" in capsys.readouterr().out


def test_cli_accepts_non_interactive_alias(repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    ref = f"{ACTION_REPO}@{'e' * 40}"
    assert cli.main(["init", "--root", str(repo), "--non-interactive", "--dry-run", "--ref", ref]) == 0
    assert not (repo / ".github").exists()
