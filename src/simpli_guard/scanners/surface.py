"""Live surface checks against the owner's own URLs (nightly only).

Read-only and polite: sequential GET requests, a short timeout, User-Agent
"simpli-guard", no credentials and no cookies sent. Response bodies are
inspected in memory (first 64 KB) and never logged or copied into findings.

An "exposed path" only counts when the status is 200 AND the body looks like
the real file - an SPA that answers every path with index.html is not
flagged.
"""

from __future__ import annotations

import json
import logging
import re
import socket
import ssl
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.parse import urlsplit

import httpx

from simpli_guard.models import Category, Finding, Severity, code_fingerprint
from simpli_guard.scanners.base import ScanResult

log = logging.getLogger(__name__)

TOOL = "surface"
USER_AGENT = "simpli-guard"
TIMEOUT = 10.0
MAX_BODY = 65_536
HSTS_MIN = 15_552_000  # 180 days


@dataclass
class TlsInfo:
    ok: bool
    error: str | None = None
    protocol: str | None = None  # e.g. "TLSv1.3"
    not_after: datetime | None = None
    legacy_accepted: bool = False  # server still completes a TLS 1.0/1.1 handshake


TlsProbe = Callable[[str, int], TlsInfo]


def probe_tls(host: str, port: int = 443) -> TlsInfo:
    ctx = ssl.create_default_context()
    try:
        with (
            socket.create_connection((host, port), timeout=TIMEOUT) as sock,
            ctx.wrap_socket(sock, server_hostname=host) as s,
        ):
            cert = s.getpeercert() or {}
            proto = s.version()
        not_after_raw = cert.get("notAfter")
        not_after = (
            datetime.fromtimestamp(ssl.cert_time_to_seconds(str(not_after_raw)), UTC)
            if not_after_raw
            else None
        )
        info = TlsInfo(ok=True, protocol=proto, not_after=not_after)
    except ssl.SSLCertVerificationError as e:
        return TlsInfo(ok=False, error=str(e.verify_message or "certificate verification failed"))
    except (OSError, ssl.SSLError) as e:
        return TlsInfo(ok=False, error=f"TLS connection failed ({type(e).__name__})")
    info.legacy_accepted = _accepts_legacy(host, port)
    return info


def _accepts_legacy(host: str, port: int) -> bool:
    """Best effort: if the local OpenSSL refuses to offer TLS < 1.2 at all this
    returns False (a missed finding, never a false one)."""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1
        ctx.maximum_version = ssl.TLSVersion.TLSv1_1
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
        with (
            socket.create_connection((host, port), timeout=TIMEOUT) as sock,
            ctx.wrap_socket(sock, server_hostname=host) as s,
        ):
            return s.version() in ("TLSv1", "TLSv1.1")
    except (OSError, ssl.SSLError, ValueError):
        return False


# ---------- exposed paths ----------


def _not_html(body: str) -> bool:
    head = body.lstrip()[:200].lower()
    return not (head.startswith("<!doctype") or head.startswith("<html") or "<head" in head)


_ENV_LINE = re.compile(r"^\s*(export\s+)?[A-Z_][A-Z0-9_]*\s*=", re.MULTILINE)


def _looks_env(body: str) -> bool:
    return _not_html(body) and len(_ENV_LINE.findall(body)) >= 1


def _looks_git_head(body: str) -> bool:
    b = body.strip()
    return b.startswith("ref:") or bool(re.fullmatch(r"[0-9a-f]{40}", b))


def _looks_openapi(body: str) -> bool:
    try:
        data = json.loads(body)
    except ValueError:
        return False
    return isinstance(data, dict) and ("openapi" in data or "swagger" in data)


@dataclass(frozen=True)
class ExposedPath:
    path: str
    looks_real: Callable[[str], bool]
    severity: Severity
    title: str


EXPOSED_PATHS = [
    ExposedPath("/.env", _looks_env, Severity.CRITICAL, "Environment file publicly readable"),
    ExposedPath(
        "/.git/config",
        lambda b: _not_html(b) and "[core]" in b,
        Severity.CRITICAL,
        "Git config publicly readable",
    ),
    ExposedPath("/.git/HEAD", _looks_git_head, Severity.CRITICAL, "Git repository publicly readable"),
    ExposedPath(
        "/backup.sql",
        lambda b: (
            _not_html(b)
            and bool(re.search(r"CREATE TABLE|INSERT INTO|-- (MySQL|PostgreSQL) (database )?dump", b, re.I))
        ),
        Severity.CRITICAL,
        "Database dump publicly readable",
    ),
    ExposedPath(
        "/docker-compose.yml",
        lambda b: _not_html(b) and bool(re.search(r"^services:\s*$", b, re.MULTILINE)),
        Severity.MEDIUM,
        "docker-compose.yml publicly readable",
    ),
    ExposedPath(
        "/server-status",
        lambda b: "Apache Server Status" in b,
        Severity.MEDIUM,
        "Apache server-status page public",
    ),
    ExposedPath("/openapi.json", _looks_openapi, Severity.LOW, "API docs public (openapi.json)"),
    ExposedPath("/docs", lambda b: "swagger-ui" in b.lower(), Severity.INFO, "API docs public (/docs)"),
    ExposedPath("/redoc", lambda b: "redoc" in b.lower(), Severity.INFO, "API docs public (/redoc)"),
]


# ---------- the checks ----------


def _finding(origin: str, check: str, severity: Severity, title: str, message: str, key: str = "") -> Finding:
    return Finding(
        id=code_fingerprint(TOOL, check, origin, key),
        tool=TOOL,
        category=Category.SURFACE,
        severity=severity,
        title=title,
        path=origin,
        rule_id=check,
        message=message,
    )


def _get(client: httpx.Client, url: str, follow: bool) -> tuple[httpx.Response, str] | None:
    try:
        with client.stream("GET", url, follow_redirects=follow) as r:
            chunks: list[bytes] = []
            size = 0
            for chunk in r.iter_bytes():
                chunks.append(chunk)
                size += len(chunk)
                if size >= MAX_BODY:
                    break
            body = b"".join(chunks)[:MAX_BODY].decode("utf-8", "replace")
        return r, body
    except httpx.HTTPError:
        return None
    finally:
        client.cookies.clear()  # never send back cookies a site set


def check_url(
    url: str, client: httpx.Client, tls_probe: TlsProbe = probe_tls, now: datetime | None = None
) -> list[Finding]:
    now = now or datetime.now(UTC)
    parts = urlsplit(url)
    host = parts.hostname or ""
    origin = f"https://{parts.netloc}"
    out: list[Finding] = []

    if parts.scheme != "https":
        out.append(
            _finding(
                origin, "no-https", Severity.HIGH, "Configured URL is not HTTPS", f"{url} is plain HTTP."
            )
        )

    # TLS certificate and protocol
    tls = tls_probe(host, parts.port or 443)
    if not tls.ok:
        out.append(
            _finding(
                origin,
                "tls-invalid",
                Severity.CRITICAL,
                "TLS certificate invalid or HTTPS unreachable",
                f"{origin}: {tls.error}",
            )
        )
    else:
        if tls.not_after is not None:
            days = (tls.not_after - now).days
            if days < 21:
                sev = Severity.CRITICAL if days < 7 else Severity.HIGH
                out.append(
                    _finding(
                        origin,
                        "tls-expiry",
                        sev,
                        f"TLS certificate expires in {days} days",
                        f"{origin}: certificate expires {tls.not_after:%Y-%m-%d}. Check auto-renewal.",
                    )
                )
        if tls.protocol in ("TLSv1", "TLSv1.1", "SSLv3"):
            out.append(
                _finding(
                    origin,
                    "tls-protocol",
                    Severity.HIGH,
                    f"Negotiated {tls.protocol}",
                    f"{origin} negotiated {tls.protocol}; TLS 1.2 or newer is required.",
                )
            )
        if tls.legacy_accepted:
            out.append(
                _finding(
                    origin,
                    "tls-legacy-accepted",
                    Severity.MEDIUM,
                    "Server accepts TLS 1.0/1.1",
                    f"{origin} still completes a TLS 1.0/1.1 handshake. Disable protocols below TLS 1.2.",
                )
            )

    # HTTP -> HTTPS redirect
    plain = _get(client, f"http://{parts.netloc}/", follow=False)
    if plain is not None:
        r, _ = plain
        loc = r.headers.get("location", "")
        if not (r.status_code in (301, 302, 307, 308) and loc.lower().startswith("https://")):
            out.append(
                _finding(
                    origin,
                    "http-redirect",
                    Severity.MEDIUM,
                    "HTTP does not redirect to HTTPS",
                    f"http://{parts.netloc}/ answered {r.status_code} without redirecting to HTTPS.",
                )
            )

    if not tls.ok:
        return out  # header checks over a broken TLS connection would be noise

    main = _get(client, url, follow=True)
    if main is None:
        out.append(
            _finding(
                origin, "unreachable", Severity.MEDIUM, "URL unreachable", f"{url} did not answer over HTTPS."
            )
        )
        return out
    resp, _ = main
    out += _header_findings(origin, resp)
    out += _exposed_path_findings(origin, client)
    return out


def _header_findings(origin: str, r: httpx.Response) -> list[Finding]:
    out: list[Finding] = []
    h = r.headers
    html = "html" in h.get("content-type", "").lower()

    hsts = h.get("strict-transport-security")
    if not hsts:
        out.append(
            _finding(
                origin,
                "hsts-missing",
                Severity.MEDIUM,
                "HSTS header missing",
                "Add Strict-Transport-Security: max-age=31536000; includeSubDomains.",
            )
        )
    else:
        m = re.search(r"max-age\s*=\s*\"?(\d+)", hsts, re.I)
        if not m or int(m.group(1)) < HSTS_MIN:
            out.append(
                _finding(
                    origin,
                    "hsts-short",
                    Severity.LOW,
                    "HSTS max-age below 180 days",
                    f"Strict-Transport-Security max-age should be at least {HSTS_MIN}.",
                )
            )

    csp = h.get("content-security-policy", "")
    if not csp:
        out.append(
            _finding(
                origin,
                "csp-missing",
                Severity.MEDIUM if html else Severity.LOW,
                "Content-Security-Policy missing",
                "Add a Content-Security-Policy header.",
            )
        )
    if h.get("x-content-type-options", "").strip().lower() != "nosniff":
        out.append(
            _finding(
                origin,
                "nosniff-missing",
                Severity.LOW,
                "X-Content-Type-Options: nosniff missing",
                "Add X-Content-Type-Options: nosniff.",
            )
        )
    if "frame-ancestors" not in csp.lower() and not h.get("x-frame-options"):
        out.append(
            _finding(
                origin,
                "framing-allowed",
                Severity.MEDIUM if html else Severity.LOW,
                "Page can be framed (clickjacking)",
                "Add CSP frame-ancestors 'none' (or 'self'), or X-Frame-Options: DENY.",
            )
        )
    if not h.get("referrer-policy"):
        out.append(
            _finding(
                origin,
                "referrer-policy-missing",
                Severity.LOW,
                "Referrer-Policy missing",
                "Add Referrer-Policy: strict-origin-when-cross-origin.",
            )
        )

    server = h.get("server", "")
    if re.search(r"\d+\.\d+", server):
        out.append(
            _finding(
                origin,
                "server-banner",
                Severity.LOW,
                "Server version disclosed",
                "The Server header discloses a software version.",
                key=server.split("/")[0],
            )
        )
    if h.get("x-powered-by"):
        out.append(
            _finding(
                origin,
                "x-powered-by",
                Severity.LOW,
                "X-Powered-By header present",
                "Remove the X-Powered-By header.",
            )
        )

    for raw in h.get_list("set-cookie"):
        out += _cookie_findings(origin, raw)
    return out


_SESSIONISH = re.compile(r"sess|sid|auth|token|jwt|login|remember", re.I)


def _cookie_findings(origin: str, raw: str) -> list[Finding]:
    name = raw.split("=", 1)[0].strip()
    attrs = {a.strip().split("=", 1)[0].lower() for a in raw.split(";")[1:]}
    sensitive = bool(_SESSIONISH.search(name))
    out: list[Finding] = []
    if "secure" not in attrs:
        out.append(
            _finding(
                origin,
                "cookie-secure",
                Severity.MEDIUM,
                f"Cookie {name} without Secure",
                f"Set the Secure flag on cookie {name}.",
                key=name,
            )
        )
    if "httponly" not in attrs and sensitive:
        out.append(
            _finding(
                origin,
                "cookie-httponly",
                Severity.MEDIUM,
                f"Session cookie {name} without HttpOnly",
                f"Set HttpOnly on cookie {name} so scripts cannot read it.",
                key=name,
            )
        )
    if "samesite" not in attrs:
        out.append(
            _finding(
                origin,
                "cookie-samesite",
                Severity.LOW,
                f"Cookie {name} without SameSite",
                f"Set SameSite=Lax (or Strict) on cookie {name}.",
                key=name,
            )
        )
    return out


def _exposed_path_findings(origin: str, client: httpx.Client) -> list[Finding]:
    out: list[Finding] = []
    for ep in EXPOSED_PATHS:
        got = _get(client, origin + ep.path, follow=False)
        if got is None:
            continue
        r, body = got
        if r.status_code == 200 and ep.looks_real(body):
            out.append(
                _finding(
                    origin,
                    f"exposed:{ep.path}",
                    ep.severity,
                    f"{ep.title}: {ep.path}",
                    f"{origin}{ep.path} returned 200 with content that looks like the real file. "
                    "Block it at the web server / proxy.",
                    key=ep.path,
                )
            )
    return out


def make_client(transport: httpx.BaseTransport | None = None) -> httpx.Client:
    return httpx.Client(
        timeout=TIMEOUT,
        headers={"User-Agent": USER_AGENT},
        transport=transport,
        trust_env=False,  # never pick up proxy credentials or .netrc
    )


def scan(urls: list[str], client: httpx.Client | None = None, tls_probe: TlsProbe = probe_tls) -> ScanResult:
    if not urls:
        return ScanResult(TOOL, "ran", message="no URLs configured")
    findings: list[Finding] = []
    with client or make_client() as c:
        for url in urls:
            try:
                findings += check_url(url, c, tls_probe)
            except Exception as e:  # one bad URL must not stop the others
                log.warning("surface: %s check failed (%s)", urlsplit(url).netloc, type(e).__name__)
    return ScanResult(TOOL, "ran", findings)
