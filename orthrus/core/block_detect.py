"""WAF / anti-automation block detection (PRD §12 evasion, §5.3 WAF).

``recon.waf_detect`` *fingerprints* the WAF fronting a target from its seed
page. This module answers a different, per-response question: **is this specific
response a block or a challenge** (rather than a genuine application reply)?
That signal drives two things in the HTTP client:

* an adaptive reaction - rotate request identity and retry once when blocked;
* a scan-reliability metric - if a large fraction of requests are blocked, the
  findings are likely incomplete and the operator must be told.

Detection is deliberately conservative: a plain ``403``/``401`` from the
application (ordinary authorization) is **not** a block. We only flag a block on
an explicit rate-limit (``429``), an interstitial JS/CAPTCHA challenge, or a
strong vendor block-page signature. Vendor attribution is best-effort and
informational; it never, on its own, turns a successful response into a block.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Statuses a WAF commonly uses to deny/throttle. Used only to corroborate a
# block-page body - never to classify a response as blocked by itself.
_BLOCK_STATUSES = frozenset({403, 406, 429, 503})

# Interstitial "prove you're human / running JS" pages (the request was held,
# not necessarily denied) - Cloudflare/Akamai/DataDome/PerimeterX/CAPTCHA.
_CHALLENGE_BODY = re.compile(
    r"just a moment\.\.\.|checking your browser before accessing|cf-browser-verification|"
    r"challenge-platform|enable javascript and cookies to continue|"
    r"attention required! \| cloudflare|"
    r"verify you are (a )?human|are you a robot|complete the security check|"
    r"hcaptcha|g-recaptcha|/recaptcha/|press & hold|"
    r"ddos protection by|bot ?management|please enable js and disable any ad ?blocker",
    re.IGNORECASE,
)

# Hard block pages - the request was refused by the WAF.
_BLOCK_BODY = re.compile(
    r"you have been blocked|sorry, you have been blocked|"
    r"this request has been blocked|your request has been blocked|"
    r"request unsuccessful\.?\s*incapsula|incapsula incident id|"
    r"sucuri website firewall|access denied|"
    r"the requested url was rejected\. please consult with your administrator|"
    r"reference #\d|error code: 102\d|"
    r"unusual traffic from your (computer|network)",
    re.IGNORECASE,
)

_HEADER_VENDOR: tuple[tuple[str, str], ...] = (
    ("cf-mitigated", "Cloudflare"),
    ("cf-ray", "Cloudflare"),
    ("x-iinfo", "Imperva Incapsula"),
    ("x-cdn", "Imperva Incapsula"),
    ("x-sucuri-id", "Sucuri"),
    ("x-sucuri-block", "Sucuri"),
    ("x-akamai-transformed", "Akamai"),
    ("akamai-grn", "Akamai"),
    ("x-datadome", "DataDome"),
    ("x-datadome-cid", "DataDome"),
)
_SERVER_VENDOR: tuple[tuple[str, str], ...] = (
    ("cloudflare", "Cloudflare"),
    ("akamaighost", "Akamai"),
    ("sucuri", "Sucuri"),
    ("mod_security", "ModSecurity"),
    ("big-ip", "F5 BIG-IP"),
    ("awselb", "AWS WAF/ELB"),
)
_BODY_VENDOR: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"cloudflare", re.I), "Cloudflare"),
    (re.compile(r"incapsula", re.I), "Imperva Incapsula"),
    (re.compile(r"sucuri", re.I), "Sucuri"),
    (re.compile(r"akamai|reference #\d", re.I), "Akamai"),
    (re.compile(r"the requested url was rejected", re.I), "F5 BIG-IP"),
)


@dataclass(frozen=True)
class BlockVerdict:
    """Outcome of inspecting one response for WAF/anti-automation interference."""

    blocked: bool
    vendor: str | None = None
    reason: str = ""
    challenge: bool = False  # held by a JS/CAPTCHA interstitial vs hard-denied
    # "rate_limit" (429 - defer to the rate limiter's backoff), "challenge"
    # (JS/CAPTCHA interstitial), or "block" (hard deny). Identity rotation is
    # worthwhile for challenge/block, but not for a rate-limit.
    kind: str = "block"


def _vendor(lower_headers: dict[str, str], body: str) -> str | None:
    for name, vendor in _HEADER_VENDOR:
        if name in lower_headers:
            return vendor
    server = lower_headers.get("server", "")
    for needle, vendor in _SERVER_VENDOR:
        if needle in server:
            return vendor
    for pat, vendor in _BODY_VENDOR:
        if pat.search(body):
            return vendor
    return None


def detect_block(status: int, headers: dict[str, str], body: str) -> BlockVerdict | None:
    """Classify a response as a WAF block/challenge, or ``None`` if it looks genuine.

    ``headers`` may be any mapping (a plain dict or ``httpx.Headers``); only
    the lower-cased names are consulted. ``body`` should be the (possibly
    truncated) decoded response text.
    """
    lower = {str(k).lower(): str(v or "") for k, v in headers.items()}
    text = body or ""
    vendor = _vendor(lower, text)
    cf_mitigated = "cf-mitigated" in lower
    suffix = f" [{vendor}]" if vendor else ""

    if status == 429:
        return BlockVerdict(True, vendor, f"rate-limited (HTTP 429){suffix}",
                            challenge=False, kind="rate_limit")

    if cf_mitigated or _CHALLENGE_BODY.search(text):
        return BlockVerdict(True, vendor, f"interstitial challenge (HTTP {status}){suffix}",
                            challenge=True, kind="challenge")

    if _BLOCK_BODY.search(text) and (status in _BLOCK_STATUSES or vendor is not None):
        return BlockVerdict(True, vendor, f"request blocked (HTTP {status}){suffix}",
                            challenge=False, kind="block")

    return None


class BlockMonitor:
    """Per-host tally of WAF blocks across a scan - the reliability signal.

    Cheap and synchronous so the HTTP client can update it on every response.
    ``degraded()`` is true once enough of the run is being blocked that findings
    should be treated as incomplete.
    """

    def __init__(self) -> None:
        self.total = 0
        self.blocked = 0
        self.challenges = 0
        self.vendors: set[str] = set()
        self.per_host: dict[str, list[int]] = {}  # host -> [total, blocked]

    def record(self, host: str, verdict: BlockVerdict | None) -> None:
        self.total += 1
        tally = self.per_host.setdefault(host or "", [0, 0])
        tally[0] += 1
        if verdict and verdict.blocked:
            self.blocked += 1
            tally[1] += 1
            if verdict.challenge:
                self.challenges += 1
            if verdict.vendor:
                self.vendors.add(verdict.vendor)

    def block_rate(self, host: str | None = None) -> float:
        if host is None:
            return self.blocked / self.total if self.total else 0.0
        tally = self.per_host.get(host)
        return tally[1] / tally[0] if tally and tally[0] else 0.0

    def degraded(self, *, min_requests: int = 8, threshold: float = 0.25) -> bool:
        return self.total >= min_requests and self.block_rate() >= threshold

    def summary(self) -> dict[str, object]:
        return {
            "total": self.total,
            "blocked": self.blocked,
            "challenges": self.challenges,
            "block_rate": round(self.block_rate(), 3),
            "vendors": sorted(self.vendors),
        }


__all__ = ["BlockVerdict", "BlockMonitor", "detect_block"]
