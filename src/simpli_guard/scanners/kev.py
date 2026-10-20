"""CISA Known Exploited Vulnerabilities catalogue: a CVE on this list is
exploited in the wild, so its finding is raised one severity level.

Fetched once per day into the tool cache; any failure means "no KEV data"
(the scan carries on with unbumped severities)."""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path

import httpx

from simpli_guard.scanners.base import tool_cache_dir

log = logging.getLogger(__name__)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
MAX_AGE = 24 * 3600


def parse_kev(data: object) -> set[str]:
    if not isinstance(data, dict):
        return set()
    return {
        str(v.get("cveID", "")).upper()
        for v in data.get("vulnerabilities", [])
        if isinstance(v, dict) and v.get("cveID")
    }


def load_kev(cache: Path | None = None, client: httpx.Client | None = None) -> set[str]:
    path = (cache or tool_cache_dir()) / "kev.json"
    try:
        if path.is_file() and time.time() - path.stat().st_mtime < MAX_AGE:
            return parse_kev(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, ValueError):
        pass
    try:
        c = client or httpx.Client(timeout=30, follow_redirects=True)
        r = c.get(KEV_URL, headers={"User-Agent": "simpli-guard"})
        r.raise_for_status()
        data = r.json()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data), encoding="utf-8")
        return parse_kev(data)
    except (httpx.HTTPError, OSError, ValueError) as e:
        log.warning("KEV catalogue unavailable (%s); severities not bumped", type(e).__name__)
        try:
            return parse_kev(json.loads(path.read_text(encoding="utf-8")))  # stale beats nothing
        except (OSError, ValueError):
            return set()
