"""Session-fixation scanner - CWE-384.

Session fixation lets an attacker pin a known session identifier into a victim's
browser (a crafted link, a cookie-setting injection) and then ride the victim's
authenticated session, because the application never regenerates the session id
when the user logs in. It is the mechanism behind the session-hijacking threat.

A black-box DAST cannot log in for the operator, so this scanner reports the two
things it *can* observe without credentials:

* **Session id in the URL** (passive, FIRM) - a session token carried in a path
  matrix param (`;jsessionid=...`) or query string is directly fixable via a link
  and leaks through Referer headers, browser history and proxy/server logs.
* **Adopts an externally-supplied session id** (active, NORMAL+, TENTATIVE) -
  the server issues a session cookie, yet when a *forged* value it never issued is
  presented it neither regenerates nor rejects it. That is the fixation
  precondition (e.g. PHP `session.use_strict_mode=0`). It is reported TENTATIVE
  with an explicit note that login-time rotation was not verified - the operator
  confirms it by fixing the cookie, logging in, and checking it stays valid.

The verdict logic is pure and unit-tested; the active probe uses a dedicated
jar-free client (like ``authz_matrix``) so the two requests do not share cookies,
and every URL is scope-checked first.
"""

from __future__ import annotations

import secrets
from collections.abc import AsyncIterator
from urllib.parse import parse_qsl, urlsplit

import httpx

from orthrus.core.context import ScanContext
from orthrus.core.schemas import Aggressiveness, Confidence, Evidence, Finding, Severity
from orthrus.scanners.base_scanner import BaseScanner
from orthrus.scanners.registry import register
from orthrus.utils.logger import get_logger
from orthrus.utils.scope import ScopeViolation

logger = get_logger("scanner.session-fixation")

SCANNER_NAME = "session-fixation"
MAX_URLS = 300
MAX_PROBE_CANDIDATES = 3
_MIN_TOKEN_LEN = 8

# Server-issued session cookie / URL token names we recognise with high confidence.
SESSION_NAMES = frozenset({
    "phpsessid", "jsessionid", "jsession", "asp.net_sessionid", "aspxauth", ".aspxauth",
    "connect.sid", "sessionid", "session", "sid", "session_id", "laravel_session",
    "ci_session", "_session_id", "rack.session", "symfony", "cfid", "cftoken",
    "sessionkey", "session_token", "sessiontoken",
})


def looks_like_session_name(name: str) -> bool:
    """True if a cookie/URL parameter name denotes a session identifier."""
    n = name.strip().lower()
    if n in SESSION_NAMES:
        return True
    return "session" in n or n == "sid" or n.endswith("_sid") or n.endswith("sessionid")


def _is_token(value: str) -> bool:
    v = value or ""
    return len(v) >= _MIN_TOKEN_LEN and all(c.isalnum() or c in "._%-" for c in v)


def session_token_in_url(url: str) -> tuple[str, str] | None:
    """Detect a session identifier carried in the URL.

    Returns ``(param_name, location)`` where location is ``"path"`` (a
    ``;name=value`` matrix parameter) or ``"query"``, else ``None``.
    """
    parts = urlsplit(url)
    for segment in parts.path.split("/"):
        if ";" not in segment:
            continue
        for matrix in segment.split(";")[1:]:
            name, _, value = matrix.partition("=")
            if looks_like_session_name(name) and _is_token(value):
                return name, "path"
    for name, value in parse_qsl(parts.query, keep_blank_values=True):
        if looks_like_session_name(name) and _is_token(value):
            return name, "query"
    return None


def _set_cookie_lines(resp: httpx.Response) -> list[str]:
    try:
        return list(resp.headers.get_list("set-cookie"))
    except Exception:
        return [v for k, v in resp.headers.multi_items() if k.lower() == "set-cookie"]


def _set_cookie_pairs(set_cookie_lines: list[str]) -> dict[str, str]:
    """Map cookie name (lower-cased) -> value from Set-Cookie header lines."""
    out: dict[str, str] = {}
    for line in set_cookie_lines:
        first = line.split(";", 1)[0]
        name, sep, value = first.partition("=")
        if sep:
            out[name.strip().lower()] = value.strip()
    return out


def issued_session_cookies(set_cookie_lines: list[str]) -> dict[str, str]:
    """Session cookies (name->value) the server set in a response."""
    return {n: v for n, v in _set_cookie_pairs(set_cookie_lines).items() if looks_like_session_name(n)}


def accepts_forged_session(name: str, forged_value: str, followup_set_cookie: list[str]) -> bool:
    """True if the server adopted an attacker-supplied session id (no regeneration).

    After a forged value for ``name`` is presented, a safe server re-issues
    ``name`` with a *different*, server-generated value (regeneration). If it does
    not re-issue the cookie at all, or echoes our forged value straight back, it
    accepted an identifier it never issued - the session-fixation precondition.
    """
    pairs = _set_cookie_pairs(followup_set_cookie)
    n = name.lower()
    if n not in pairs:
        return True  # kept our value - no regeneration
    return pairs[n] == forged_value  # echoed our value back


@register
class SessionFixationScanner(BaseScanner):
    name = SCANNER_NAME
    vuln_type = "session-fixation"
    min_aggressiveness = Aggressiveness.PASSIVE

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        emitted: set[tuple[str, ...]] = set()

        # --- Check 1 (passive): session identifier carried in a URL ---
        for url in self._urls(ctx):
            hit = session_token_in_url(url)
            if hit is None:
                continue
            pname, location = hit
            key = ("url", urlsplit(url).path, pname.lower())
            if key in emitted:
                continue
            emitted.add(key)
            yield self._url_finding(url, pname, location)

        # --- Check 2 (active, NORMAL+): server adopts a forged session id ---
        if ctx.config.aggressiveness == Aggressiveness.PASSIVE:
            return
        async for finding in self._probe_fixation(ctx, emitted):
            yield finding

    def _urls(self, ctx: ScanContext) -> list[str]:
        urls: list[str] = []
        seen: set[tuple[str, str]] = set()
        for candidate in (ctx.config.target, *[ep.url for ep in ctx.endpoints]):
            parts = urlsplit(candidate)
            key = (parts.netloc, parts.path)
            if key in seen:
                continue
            seen.add(key)
            urls.append(candidate)
        return urls[:MAX_URLS]

    def _candidates(self, ctx: ScanContext) -> list[str]:
        """URLs likely to issue a session cookie: those seen setting one, then root."""
        urls: list[str] = []
        seen: set[str] = set()
        for ep in ctx.endpoints:
            cookies = getattr(ep, "set_cookies", None)
            if cookies and issued_session_cookies(cookies):
                path = urlsplit(ep.url).path
                if path not in seen and ctx.scope.is_allowed(ep.url):
                    seen.add(path)
                    urls.append(ep.url)
        if ctx.config.target not in urls and ctx.scope.is_allowed(ctx.config.target):
            urls.append(ctx.config.target)
        return urls[:MAX_PROBE_CANDIDATES]

    async def _probe_fixation(self, ctx: ScanContext, emitted: set) -> AsyncIterator[Finding]:
        timeout = getattr(ctx.config, "timeout", 30.0)
        for url in self._candidates(ctx):
            host = urlsplit(url).netloc
            if ("fixation", host) in emitted:
                break
            issued = await self._issued_session(url, timeout)
            if not issued:
                continue  # no session cookie here - nothing to fix
            name = next(iter(issued))
            forged = "orthrusfx" + secrets.token_hex(8)
            followup = await self._followup_set_cookie(url, name, forged, timeout)
            if followup is None:
                continue
            if accepts_forged_session(name, forged, followup):
                emitted.add(("fixation", host))
                yield self._fixation_finding(url, name)
            break  # one representative session-bearing endpoint is enough

    async def _issued_session(self, url: str, client_timeout: float) -> dict[str, str]:
        try:
            async with httpx.AsyncClient(
                verify=False, timeout=client_timeout, follow_redirects=False
            ) as c:
                resp = await c.get(url)
                return issued_session_cookies(_set_cookie_lines(resp))
        except (ScopeViolation, httpx.HTTPError, httpx.InvalidURL) as exc:
            logger.debug("session-fixation baseline failed for %s: %s", url, exc)
            return {}

    async def _followup_set_cookie(
        self, url: str, name: str, forged: str, client_timeout: float
    ) -> list[str] | None:
        try:
            async with httpx.AsyncClient(
                verify=False, timeout=client_timeout, follow_redirects=False, cookies={name: forged}
            ) as c:
                resp = await c.get(url)
                return _set_cookie_lines(resp)
        except (ScopeViolation, httpx.HTTPError, httpx.InvalidURL) as exc:
            logger.debug("session-fixation follow-up failed for %s: %s", url, exc)
            return None

    def _url_finding(self, url: str, name: str, location: str) -> Finding:
        where = "path (matrix parameter)" if location == "path" else "query string"
        return Finding(
            vuln_type="session-fixation",
            title=f"Session identifier exposed in the URL ('{name}')",
            severity=Severity.MEDIUM,
            confidence=Confidence.FIRM,
            url=url,
            description=(
                f"The session identifier '{name}' is carried in the URL {where}. An attacker can "
                "fix a victim's session by sending a crafted link containing a known identifier; "
                "if the session is not regenerated at login the attacker then shares the victim's "
                "authenticated session. The identifier also leaks to third parties through the "
                "Referer header, browser history, and proxy/server logs."
            ),
            remediation=(
                "Never transmit session identifiers in the URL. Keep them in cookies marked "
                "HttpOnly, Secure and SameSite, and regenerate the session id on every login / "
                "privilege change."
            ),
            cwe="CWE-384",
            scanner=SCANNER_NAME,
            evidence=Evidence(matched_at=name, notes=f"session token in URL {location}"),
        )

    def _fixation_finding(self, url: str, name: str) -> Finding:
        return Finding(
            vuln_type="session-fixation",
            title=f"Application accepts an externally-supplied session id ('{name}')",
            severity=Severity.LOW,
            confidence=Confidence.TENTATIVE,
            url=url,
            description=(
                f"The application issued a session cookie '{name}' but, when presented with a value "
                "it never issued, neither regenerated nor rejected it (it retained the "
                "attacker-supplied identifier). That is the precondition for session fixation "
                "(e.g. PHP session.use_strict_mode=0). If the session id is likewise not rotated "
                "when a user authenticates, an attacker who fixes this value in a victim's browser "
                "can hijack the victim's session after they log in. Login-time rotation was not "
                "verified automatically - confirm by fixing this cookie, logging in as a test user, "
                "and checking the identifier remains valid."
            ),
            remediation=(
                "Reject session identifiers the server did not issue (e.g. PHP "
                "session.use_strict_mode=1) and regenerate the session id on every login / "
                "privilege change so a pre-set identifier cannot survive authentication."
            ),
            cwe="CWE-384",
            scanner=SCANNER_NAME,
            evidence=Evidence(
                matched_at=name,
                notes="server retained an attacker-supplied session id without regeneration",
            ),
        )


__all__ = [
    "SessionFixationScanner",
    "looks_like_session_name",
    "session_token_in_url",
    "issued_session_cookies",
    "accepts_forged_session",
]
