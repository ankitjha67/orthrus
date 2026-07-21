"""Finding triage - turn a raw finding list into a high-signal, deduplicated view.

A scanner that crawls a real app reports the *same* issue many times: reflected
XSS on 50 product pages, IDOR on ``/order/1``…``/order/999``, a missing security
header on every route. A flat list of 600 findings hides the 12 real problems.

This layer collapses that noise deterministically:

* **URL templating** - id-like path segments (``/order/8412`` → ``/order/{id}``)
  are normalised so the same bug at many ids folds into one cluster.
* **Clustering** - findings group by (vuln_type, templated-url, parameter); each
  cluster keeps its highest-severity representative, a count, and the affected
  URLs.

That core is pure and offline. On top of it sits an **optional** LLM judge that
assesses each cluster's false-positive likelihood - the prompt builder and the
response parser are pure (and unit-tested); the network call is opt-in and
no-ops cleanly when no API key is configured, so triage always works without it.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from orthrus.intel.cve_intel import epss_for_text

_SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# A path segment that is an opaque identifier rather than a route name: a pure
# number, a long hex/uuid blob, or a long opaque token. Folded to ``{id}``.
_ID_SEGMENT = re.compile(
    r"^(?:\d+|[0-9a-fA-F]{8,}|[0-9a-fA-F-]{16,}|[A-Za-z0-9_-]{20,})$"
)


def _sev_str(finding) -> str:
    sev = getattr(finding, "severity", "info")
    return (sev.value if hasattr(sev, "value") else str(sev)).lower()


def template_url(url: str) -> str:
    """Normalise id-like path segments to ``{id}`` (query dropped) for dedup."""
    parts = urlsplit(url if "://" in url else f"//{url}")
    segments = [("{id}" if _ID_SEGMENT.match(s) else s) for s in (parts.path or "/").split("/")]
    path = "/".join(segments)
    host = parts.netloc or ""
    return f"{parts.scheme}://{host}{path}" if parts.scheme else f"{host}{path}"


def dedup_key(finding) -> tuple[str, str, str]:
    return (
        getattr(finding, "vuln_type", ""),
        template_url(getattr(finding, "url", "")),
        getattr(finding, "parameter", None) or "",
    )


@dataclass
class Cluster:
    vuln_type: str
    template: str
    parameter: str
    severity: str
    count: int
    urls: list[str] = field(default_factory=list)
    representative: object = None

    def to_dict(self) -> dict:
        return {
            "vuln_type": self.vuln_type,
            "template": self.template,
            "parameter": self.parameter or None,
            "severity": self.severity,
            "count": self.count,
            "urls": self.urls[:25],
        }


@dataclass
class TriageReport:
    clusters: list[Cluster]
    total: int

    @property
    def unique(self) -> int:
        return len(self.clusters)

    @property
    def collapsed(self) -> int:
        return self.total - self.unique

    def summary(self) -> str:
        return (
            f"{self.total} finding(s) → {self.unique} unique issue(s) "
            f"({self.collapsed} duplicate(s) folded)"
        )

    def to_dict(self) -> dict:
        return {
            "summary": self.summary(),
            "total": self.total,
            "unique": self.unique,
            "collapsed": self.collapsed,
            "clusters": [c.to_dict() for c in self.clusters],
        }


def triage_findings(findings: list) -> TriageReport:
    """Deduplicate + cluster findings into one entry per distinct issue."""
    groups: dict[tuple[str, str, str], list] = {}
    for f in findings:
        groups.setdefault(dedup_key(f), []).append(f)

    clusters: list[Cluster] = []
    for (vuln_type, template, parameter), items in groups.items():
        rep = max(items, key=lambda x: _SEV_ORDER.get(_sev_str(x), 0))
        urls = sorted({getattr(x, "url", "") for x in items if getattr(x, "url", "")})
        clusters.append(Cluster(
            vuln_type=vuln_type, template=template, parameter=parameter,
            severity=_sev_str(rep), count=len(items), urls=urls, representative=rep,
        ))
    clusters.sort(
        key=lambda c: (
            -_SEV_ORDER.get(c.severity, 0),
            -(_cluster_epss(c) or 0.0),  # actively-exploitable CVEs rank first in their tier
            c.vuln_type,
            c.template,
        )
    )
    return TriageReport(clusters=clusters, total=len(findings))


def _cluster_epss(cluster: object) -> float | None:
    """Highest EPSS among the CVE ids in a cluster's representative finding."""
    rep = getattr(cluster, "representative", None)
    text = f"{getattr(rep, 'title', '')} {getattr(rep, 'description', '')}"
    return epss_for_text(text)


# --------------------------------------------------------------- LLM judge
@dataclass
class Verdict:
    is_false_positive: bool
    confidence: str  # high / medium / low
    rationale: str


ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
DEFAULT_MODEL = "claude-3-5-haiku-latest"

_JUDGE_INSTRUCTION = (
    "You are a senior application-security engineer triaging an automated "
    "scanner's finding. Decide whether it is a likely FALSE POSITIVE. Respond "
    "with ONLY a compact JSON object: "
    '{"false_positive": true|false, "confidence": "high|medium|low", '
    '"rationale": "one sentence"}.'
)


def build_triage_prompt(cluster: Cluster) -> str:
    """Compose the user prompt for judging a finding cluster (pure)."""
    rep = cluster.representative
    title = getattr(rep, "title", cluster.vuln_type)
    evidence = ""
    ev = getattr(rep, "evidence", None)
    if ev is not None:
        evidence = getattr(ev, "notes", "") or ""
    return (
        f"{_JUDGE_INSTRUCTION}\n\n"
        f"Vulnerability type: {cluster.vuln_type}\n"
        f"Title: {title}\n"
        f"Severity (scanner): {cluster.severity}\n"
        f"Affected pattern: {cluster.template} (x{cluster.count})\n"
        f"Parameter: {cluster.parameter or '(none)'}\n"
        f"Evidence: {evidence[:600] or '(none)'}\n"
    )


def parse_judge_response(text: str) -> Verdict | None:
    """Parse the model's JSON verdict (tolerant of surrounding prose)."""
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        return None
    try:
        data = json.loads(match.group(0))
    except (ValueError, TypeError):
        return None
    if "false_positive" not in data:
        return None
    conf = str(data.get("confidence", "low")).lower()
    return Verdict(
        is_false_positive=bool(data["false_positive"]),
        confidence=conf if conf in {"high", "medium", "low"} else "low",
        rationale=str(data.get("rationale", ""))[:300],
    )


def llm_available(api_key: str | None) -> bool:
    return bool(api_key)


async def llm_assess(cluster: Cluster, api_key: str, *, model: str = DEFAULT_MODEL) -> Verdict | None:
    """Ask an Anthropic model whether a cluster is a likely false positive.

    Opt-in and best-effort: returns ``None`` on any error so triage never breaks
    on a flaky/absent API. The prompt/parse helpers above are what's unit-tested.
    """
    import httpx

    payload = {
        "model": model,
        "max_tokens": 200,
        "messages": [{"role": "user", "content": build_triage_prompt(cluster)}],
    }
    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(ANTHROPIC_URL, json=payload, headers=headers)
        if resp.status_code != 200:
            return None
        blocks = resp.json().get("content", [])
        text = "".join(b.get("text", "") for b in blocks if b.get("type") == "text")
        return parse_judge_response(text)
    except Exception:
        return None


__all__ = [
    "template_url",
    "dedup_key",
    "Cluster",
    "TriageReport",
    "triage_findings",
    "Verdict",
    "build_triage_prompt",
    "parse_judge_response",
    "llm_available",
    "llm_assess",
    "DEFAULT_MODEL",
]
