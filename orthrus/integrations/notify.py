"""Push high-severity findings to chat / ticketing (Slack, Jira).

Both Trident and Strix surface findings into Slack + Jira; this is the same push
- webhook (Slack) / REST create-issue (Jira), over the existing httpx dependency,
no new packages. The payload *builders* are pure and unit-tested; the senders are
thin and defensive. `orthrus notify` drives them (with a `--dry-run` that prints
the payloads instead of sending, so nothing leaves the host without intent).
"""

from __future__ import annotations

import base64

import httpx

from orthrus.utils.logger import get_logger

logger = get_logger("integrations.notify")

_SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
_SEV_EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
# Severity → Jira priority name (standard Jira scheme).
_JIRA_PRIORITY = {
    "critical": "Highest", "high": "High", "medium": "Medium", "low": "Low", "info": "Lowest"
}


def _sev(row: object) -> str:
    s = getattr(row, "severity", "info")
    return getattr(s, "value", s) or "info"


def at_or_above(rows: list, min_severity: str) -> list:
    """Rows at/above ``min_severity``, worst-first (stable within a severity)."""
    floor = _SEV_ORDER.get(min_severity.lower(), 0)
    kept = [r for r in rows if _SEV_ORDER.get(_sev(r), 0) >= floor]
    return sorted(kept, key=lambda r: -_SEV_ORDER.get(_sev(r), 0))


def _counts(rows: list) -> dict[str, int]:
    out: dict[str, int] = {}
    for r in rows:
        out[_sev(r)] = out.get(_sev(r), 0) + 1
    return out


def slack_message(
    scan_id: str, target: str | None, rows: list, min_severity: str = "high", max_items: int = 20
) -> dict:
    """Build a Slack incoming-webhook payload summarising the top findings."""
    selected = at_or_above(rows, min_severity)
    counts = _counts(rows)
    tallies = " · ".join(
        f"{_SEV_EMOJI.get(s, '')} {counts[s]} {s}"
        for s in ("critical", "high", "medium", "low", "info")
        if counts.get(s)
    )
    lines = [
        f"*ORTHRUS scan `{scan_id}`* - {target or 'target'}",
        f"{len(rows)} findings ({tallies or 'none'}); "
        f"{len(selected)} at or above *{min_severity}*:",
    ]
    for r in selected[:max_items]:
        emoji = _SEV_EMOJI.get(_sev(r), "")
        title = getattr(r, "title", getattr(r, "vuln_type", "finding"))
        url = getattr(r, "url", "")
        lines.append(f"{emoji} *{_sev(r).upper()}* - {title}  `{url}`")
    if len(selected) > max_items:
        lines.append(f"…and {len(selected) - max_items} more.")
    return {"text": "\n".join(lines)}


def jira_issue(row: object, project_key: str, scan_id: str) -> dict:
    """Build a Jira create-issue REST payload for one finding."""
    sev = _sev(row)
    title = getattr(row, "title", getattr(row, "vuln_type", "Security finding"))
    url = getattr(row, "url", "")
    cwe = getattr(row, "cwe", None)
    desc = (
        f"*Severity:* {sev.upper()}\n"
        f"*Type:* {getattr(row, 'vuln_type', '')}\n"
        f"*URL:* {url}\n"
        f"*CWE:* {cwe or '-'}\n"
        f"*Scan:* {scan_id}\n\n"
        f"{getattr(row, 'description', '') or ''}\n\n"
        f"*Remediation:* {getattr(row, 'remediation', '') or '-'}"
    )
    labels = ["orthrus", f"sev-{sev}"]
    vt = getattr(row, "vuln_type", "")
    if vt:
        labels.append(vt)
    return {
        "fields": {
            "project": {"key": project_key},
            "summary": f"[ORTHRUS] {title}"[:250],
            "description": desc,
            "issuetype": {"name": "Bug"},
            "priority": {"name": _JIRA_PRIORITY.get(sev, "Medium")},
            "labels": labels,
        }
    }


async def send_slack(webhook_url: str, payload: dict, *, timeout_s: float = 15.0) -> bool:
    """POST a payload to a Slack incoming webhook. Returns success."""
    try:
        async with httpx.AsyncClient(timeout=timeout_s) as client:
            resp = await client.post(webhook_url, json=payload)
            resp.raise_for_status()
        return True
    except httpx.HTTPError as exc:
        logger.error("Slack notify failed: %s", exc)
        return False


async def send_discord(webhook_url: str, content: str, *, timeout_s: float = 15.0) -> bool:
    """POST a plain message to a Discord webhook (2000-char cap). Returns success."""
    try:
        async with httpx.AsyncClient(timeout=timeout_s) as client:
            resp = await client.post(webhook_url, json={"content": content[:1900]})
            resp.raise_for_status()
        return True
    except httpx.HTTPError as exc:
        logger.error("Discord notify failed: %s", exc)
        return False


async def create_jira_issues(
    base_url: str,
    email: str,
    token: str,
    project_key: str,
    rows: list,
    scan_id: str,
    *,
    max_issues: int = 50,
    timeout_s: float = 20.0,
) -> list[str]:
    """Create one Jira issue per finding (bounded). Returns the created issue keys."""
    auth = base64.b64encode(f"{email}:{token}".encode()).decode()
    headers = {"Authorization": f"Basic {auth}", "Content-Type": "application/json"}
    endpoint = base_url.rstrip("/") + "/rest/api/2/issue"
    created: list[str] = []
    async with httpx.AsyncClient(timeout=timeout_s, headers=headers) as client:
        for row in rows[:max_issues]:
            try:
                resp = await client.post(endpoint, json=jira_issue(row, project_key, scan_id))
                resp.raise_for_status()
                created.append(resp.json().get("key", "?"))
            except (httpx.HTTPError, ValueError) as exc:
                logger.error("Jira issue create failed: %s", exc)
    return created


__all__ = [
    "at_or_above",
    "slack_message",
    "jira_issue",
    "send_slack",
    "create_jira_issues",
]
