from __future__ import annotations

from datetime import UTC, datetime, timedelta

import httpx

from simpli_guard.models import Severity
from simpli_guard.scanners import surface

NOW = datetime(2026, 10, 14, tzinfo=UTC)
INDEX = "<!doctype html><html><head><title>App</title></head><body><div id=root></div></body></html>"
GOOD_HEADERS = {
    "content-type": "text/html; charset=utf-8",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
    "server": "cloudflare",
}


def good_tls(host: str, port: int) -> surface.TlsInfo:
    return surface.TlsInfo(ok=True, protocol="TLSv1.3", not_after=NOW + timedelta(days=80))


class Recorder:
    def __init__(self, routes: dict[str, httpx.Response], fallback: httpx.Response | None = None) -> None:
        self.routes = routes
        self.fallback = fallback or httpx.Response(404)
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        key = f"{request.url.scheme}://{request.url.host}{request.url.path}"
        return self.routes.get(key, self.fallback)


def run(routes: dict[str, httpx.Response], fallback: httpx.Response | None = None, tls=good_tls):  # type: ignore[no-untyped-def]
    rec = Recorder(routes, fallback)
    client = surface.make_client(httpx.MockTransport(rec))
    with client:
        findings = surface.check_url("https://app.example.com", client, tls, now=NOW)
    return findings, rec


def test_hardened_spa_has_no_findings_and_catch_all_is_not_exposure() -> None:
    routes = {
        "http://app.example.com/": httpx.Response(301, headers={"location": "https://app.example.com/"}),
        "https://app.example.com/": httpx.Response(200, headers=GOOD_HEADERS, text=INDEX),
    }
    # SPA catch-all: every other path (/.env, /.git/HEAD, /docs ...) returns index.html with 200.
    findings, rec = run(routes, fallback=httpx.Response(200, headers=GOOD_HEADERS, text=INDEX))
    assert findings == []
    assert any(r.url.path == "/.env" for r in rec.requests)
    for r in rec.requests:
        assert r.method == "GET"
        assert r.headers["user-agent"] == "simpli-guard"
        assert "authorization" not in r.headers and "cookie" not in r.headers


def test_real_exposures_are_flagged_without_copying_content() -> None:
    env_body = "DATABASE_URL=postgres://u:supersecretpw@db/x\nSTRIPE_KEY=sk_live_AAAAAAAAAAAAAAAA\n"
    routes = {
        "http://app.example.com/": httpx.Response(200, text="plain"),
        "https://app.example.com/": httpx.Response(
            200,
            headers={"content-type": "text/html", "server": "nginx/1.18.0", "x-powered-by": "Express"},
            text=INDEX,
        ),
        "https://app.example.com/.env": httpx.Response(200, text=env_body),
        "https://app.example.com/.git/HEAD": httpx.Response(200, text="ref: refs/heads/main\n"),
        "https://app.example.com/openapi.json": httpx.Response(200, json={"openapi": "3.1.0", "paths": {}}),
        "https://app.example.com/docs": httpx.Response(200, text="<html><div id='swagger-ui'></div></html>"),
    }
    findings, _ = run(routes)
    by_rule = {f.rule_id: f for f in findings}
    assert by_rule["exposed:/.env"].severity == Severity.CRITICAL
    assert by_rule["exposed:/.git/HEAD"].severity == Severity.CRITICAL
    assert by_rule["exposed:/openapi.json"].severity == Severity.LOW
    assert by_rule["exposed:/docs"].severity == Severity.INFO
    assert "exposed:/.git/config" not in by_rule  # 404
    for rule in ("http-redirect", "hsts-missing", "csp-missing", "nosniff-missing", "framing-allowed",
                 "referrer-policy-missing", "server-banner", "x-powered-by"):  # fmt: skip
        assert rule in by_rule, rule
    assert by_rule["csp-missing"].severity == Severity.MEDIUM  # HTML page
    blob = " ".join(f.model_dump_json() for f in findings)
    assert "supersecretpw" not in blob and "sk_live_AAAAAAAAAAAAAAAA" not in blob


def test_env_lookalike_html_not_flagged() -> None:
    routes = {
        "https://app.example.com/": httpx.Response(200, headers=GOOD_HEADERS, text=INDEX),
        "https://app.example.com/.env": httpx.Response(200, text="<html><body>API_KEY=nope</body></html>"),
    }
    findings, _ = run(routes)
    assert not [f for f in findings if f.rule_id.startswith("exposed:")]


def test_cookie_flags_and_short_hsts() -> None:
    headers = [
        *{**GOOD_HEADERS, "strict-transport-security": "max-age=86400"}.items(),
        ("set-cookie", "sessionid=abc; Path=/"),
        ("set-cookie", "theme=dark; Secure; SameSite=Lax"),
    ]
    routes = {
        "http://app.example.com/": httpx.Response(308, headers={"location": "https://app.example.com/"}),
        "https://app.example.com/": httpx.Response(200, headers=headers, text=INDEX),
    }
    findings, rec = run(routes)
    rules = sorted(f.rule_id for f in findings)
    assert rules == ["cookie-httponly", "cookie-samesite", "cookie-secure", "hsts-short"]
    assert all("cookie" not in r.headers for r in rec.requests)  # cookies never sent back


def test_tls_expiry_thresholds_and_bad_cert() -> None:
    def expiring(days: int):  # type: ignore[no-untyped-def]
        return lambda h, p: surface.TlsInfo(ok=True, protocol="TLSv1.2", not_after=NOW + timedelta(days=days))

    routes = {"https://app.example.com/": httpx.Response(200, headers=GOOD_HEADERS, text=INDEX)}
    f20, _ = run(routes, tls=expiring(20))
    f5, _ = run(routes, tls=expiring(5))
    f30, _ = run(routes, tls=expiring(30))
    assert [f.severity for f in f20 if f.rule_id == "tls-expiry"] == [Severity.HIGH]
    assert [f.severity for f in f5 if f.rule_id == "tls-expiry"] == [Severity.CRITICAL]
    assert not [f for f in f30 if f.rule_id == "tls-expiry"]

    def old(h: str, p: int) -> surface.TlsInfo:
        return surface.TlsInfo(
            ok=True, protocol="TLSv1.1", not_after=NOW + timedelta(days=90), legacy_accepted=True
        )

    fo, _ = run(routes, tls=old)
    assert {"tls-protocol", "tls-legacy-accepted"} <= {f.rule_id for f in fo}

    def bad(h: str, p: int) -> surface.TlsInfo:
        return surface.TlsInfo(ok=False, error="certificate has expired")

    fb, rec = run(routes, tls=bad)
    assert sorted(f.rule_id for f in fb) == ["http-redirect", "tls-invalid"]
    assert next(f for f in fb if f.rule_id == "tls-invalid").severity == Severity.CRITICAL
    assert all(r.url.scheme == "http" for r in rec.requests)  # no HTTPS requests over a broken cert


def test_scan_survives_one_broken_url() -> None:
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down")

    client = surface.make_client(httpx.MockTransport(boom))
    res = surface.scan(["https://a.example.com", "https://b.example.com"], client, good_tls)
    assert res.status == "ran"
    assert {f.rule_id for f in res.findings} == {"unreachable"}
    assert surface.scan([]).message == "no URLs configured"
