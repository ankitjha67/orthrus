"""Parse a HAR 1.2 archive into CapturedRequests.

HAR (HTTP Archive) is the universal interchange format - browsers' devtools,
Caido, mitmproxy, and Burp (via extensions) all export it - so a HAR importer
covers every source that isn't natively Burp-XML or Caido-JSON. The spec is
precise, so this reads the documented ``log.entries[].request/response`` shape
directly (``queryString``/``postData.params`` give param names for free).
"""

from __future__ import annotations

import json
from urllib.parse import urlsplit

from orthrus.bridges.base import CapturedRequest


def _names(items) -> list[str]:
    """Param names from a HAR name/value list (queryString or postData.params)."""
    if not isinstance(items, list):
        return []
    return sorted({str(p["name"]) for p in items
                   if isinstance(p, dict) and p.get("name")})


def parse_har(har_text: str) -> list[CapturedRequest]:
    """Map a HAR archive to CapturedRequests (pure; tolerant of garbage)."""
    if not (har_text or "").strip():
        return []
    try:
        data = json.loads(har_text)
    except ValueError:
        return []
    entries = (((data or {}).get("log") or {}).get("entries")) if isinstance(data, dict) else None
    if not isinstance(entries, list):
        return []

    out: list[CapturedRequest] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        req = entry.get("request") or {}
        resp = entry.get("response") or {}
        url = str(req.get("url") or "")
        split = urlsplit(url)
        host = (split.hostname or "").lower()
        if not host:
            continue

        query_params = _names(req.get("queryString"))
        post = req.get("postData") or {}
        body_params = _names(post.get("params"))
        if not body_params and isinstance(post.get("text"), str) and "=" in post["text"] \
                and post.get("text")[:1] not in "{[":
            body_params = sorted({p.split("=", 1)[0] for p in post["text"].split("&")
                                  if p.split("=", 1)[0]})

        content = resp.get("content") or {}
        status = resp.get("status")
        size = content.get("size")
        out.append(
            CapturedRequest(
                method=str(req.get("method") or "GET").upper(),
                host=host,
                path=split.path or "/",
                scheme=(split.scheme or "https").lower(),
                port=split.port,
                query_params=query_params,
                body_params=body_params,
                status=int(status) if isinstance(status, int) and status > 0 else None,
                content_type=(content.get("mimeType") or None),
                response_size=int(size) if isinstance(size, int) and size >= 0 else None,
            )
        )
    return out


__all__ = ["parse_har"]
