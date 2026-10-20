"""The GitHub REST calls simpli-guard needs, and nothing else.

Request and response bodies are never logged; errors carry only the status
code and GitHub's short message.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

log = logging.getLogger(__name__)

API = "https://api.github.com"


class GitHubError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(f"GitHub API {status}: {message}")
        self.status = status


class GitHub:
    def __init__(self, token: str, repo: str, api: str = API, client: httpx.Client | None = None) -> None:
        self.repo = repo
        self.http = client or httpx.Client(
            base_url=api,
            timeout=60,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "simpli-guard",
            },
        )

    # ---------- plumbing ----------

    def _req(self, method: str, path: str, **kw: Any) -> Any:
        r = self.http.request(method, path, **kw)
        if r.status_code >= 400:
            try:
                msg = r.json().get("message", r.reason_phrase)
            except ValueError:
                msg = r.reason_phrase
            raise GitHubError(r.status_code, str(msg)[:200])
        return r.json() if r.content else None

    def _paged(self, path: str, limit: int, **params: Any) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        page = 1
        while len(out) < limit:
            batch = self._req("GET", path, params={**params, "per_page": 100, "page": page})
            if not batch:
                break
            out.extend(batch)
            if len(batch) < 100:
                break
            page += 1
        return out[:limit]

    # ---------- PR comment ----------

    def issue_comments(self, number: int) -> list[dict[str, Any]]:
        return self._paged(f"/repos/{self.repo}/issues/{number}/comments", limit=3000)

    def find_comment(self, number: int, marker: str) -> int | None:
        for c in self.issue_comments(number):
            if marker in (c.get("body") or ""):
                return int(c["id"])
        return None

    def update_comment(self, comment_id: int, body: str) -> None:
        self._req("PATCH", f"/repos/{self.repo}/issues/comments/{comment_id}", json={"body": body})

    def create_comment(self, number: int, body: str) -> None:
        self._req("POST", f"/repos/{self.repo}/issues/{number}/comments", json={"body": body})

    # ---------- issues ----------

    def ensure_label(self, name: str, color: str = "b60205", description: str = "") -> None:
        try:
            self._req("GET", f"/repos/{self.repo}/labels/{name}")
        except GitHubError as e:
            if e.status != 404:
                raise
            self._req(
                "POST",
                f"/repos/{self.repo}/labels",
                json={"name": name, "color": color, "description": description},
            )

    def list_issues(self, label: str, state: str = "all") -> list[dict[str, Any]]:
        items = self._paged(f"/repos/{self.repo}/issues", limit=5000, labels=label, state=state)
        return [i for i in items if "pull_request" not in i]

    def create_issue(self, title: str, body: str, labels: list[str]) -> int:
        r = self._req(
            "POST", f"/repos/{self.repo}/issues", json={"title": title, "body": body, "labels": labels}
        )
        return int(r["number"])

    def close_issue(self, number: int, reason: str = "completed") -> None:
        self._req(
            "PATCH", f"/repos/{self.repo}/issues/{number}", json={"state": "closed", "state_reason": reason}
        )

    # ---------- artifacts (aggregate mode) ----------

    def list_artifacts(self, name: str) -> list[dict[str, Any]]:
        r = self._req("GET", f"/repos/{self.repo}/actions/artifacts", params={"name": name, "per_page": 30})
        arts: list[dict[str, Any]] = (r or {}).get("artifacts", [])
        return sorted(arts, key=lambda a: str(a.get("created_at", "")), reverse=True)

    def workflow_run(self, run_id: int) -> dict[str, Any]:
        result: dict[str, Any] = self._req("GET", f"/repos/{self.repo}/actions/runs/{run_id}")
        return result

    def download_artifact(self, artifact_id: int) -> bytes:
        # GitHub answers with a redirect to blob storage; httpx drops the
        # Authorization header on the cross-origin hop.
        r = self.http.get(
            f"/repos/{self.repo}/actions/artifacts/{artifact_id}/zip", follow_redirects=True, timeout=120
        )
        if r.status_code >= 400:
            raise GitHubError(r.status_code, "artifact download failed")
        return r.content
