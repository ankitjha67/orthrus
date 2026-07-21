"""Parse a Burp Suite "Save items" XML export into CapturedRequests.

Burp's proxy-history export wraps each transaction in ``<item>`` with dedicated
``<host>``/``<method>``/``<path>``/``<status>`` tags plus a base64 ``<request>``
blob. We pull request identity from the tags and mine body-param names from the
decoded request so imported routes carry real input vectors for triage.

XXE-safety: Burp emits an internal DTD (ELEMENT/ATTLIST only, no entities), so we
refuse any ``<!ENTITY``/``SYSTEM``/``PUBLIC`` token — blocking both billion-laughs
and external-entity attacks — before handing the document to the stdlib parser.
"""

from __future__ import annotations

import base64
import binascii
import re
import xml.etree.ElementTree as ET
from urllib.parse import parse_qs, urlsplit

from orthrus.bridges.base import CapturedRequest

# any of these in the raw bytes means a DTD that could define/pull entities → refuse.
_XXE_TOKENS = re.compile(rb"<!ENTITY|\bSYSTEM\b|\bPUBLIC\b", re.IGNORECASE)


class UnsafeXmlError(ValueError):
    """Raised when an import document declares entities / external references."""


def _text(item: ET.Element, tag: str) -> str:
    el = item.find(tag)
    return (el.text or "").strip() if el is not None and el.text else ""


def _is_base64_true(item: ET.Element, tag: str) -> bool:
    el = item.find(tag)
    return el is not None and (el.get("base64") or "").lower() == "true"


def _body_param_names(raw_request: bytes) -> list[str]:
    """Extract form/JSON body param names from a decoded raw HTTP request."""
    sep = b"\r\n\r\n" if b"\r\n\r\n" in raw_request else b"\n\n"
    body = raw_request.split(sep, 1)[1] if sep in raw_request else b""
    body = body.strip()
    if not body:
        return []
    text = body.decode("utf-8", "replace")
    if text[:1] in "{[":
        import json
        try:
            obj = json.loads(text)
        except ValueError:
            return []
        return sorted(obj.keys()) if isinstance(obj, dict) else []
    # form-encoded: a=1&b=2
    if "=" in text:
        return sorted({p.split("=", 1)[0] for p in text.split("&") if p.split("=", 1)[0]})
    return []


def parse_burp_xml(xml_text: str) -> list[CapturedRequest]:
    """Map a Burp items XML export to CapturedRequests (pure; tolerant of garbage)."""
    if not (xml_text or "").strip():
        return []
    raw = xml_text.encode("utf-8", "replace") if isinstance(xml_text, str) else xml_text
    if _XXE_TOKENS.search(raw):
        raise UnsafeXmlError(
            "refusing Burp XML that declares entities or external references "
            "(possible XXE); re-export without a custom DOCTYPE.")
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []

    out: list[CapturedRequest] = []
    for item in root.iter("item"):
        host = _text(item, "host")
        if not host:
            # fall back to the URL's host
            host = (urlsplit(_text(item, "url")).hostname or "")
        if not host:
            continue
        raw_path = _text(item, "path") or (urlsplit(_text(item, "url")).path or "/")
        split = urlsplit(raw_path if raw_path.startswith("/") else "/" + raw_path)
        query_params = sorted(parse_qs(split.query).keys())

        method = (_text(item, "method") or "GET").upper()
        body_params: list[str] = []
        if _is_base64_true(item, "request"):
            try:
                raw_req = base64.b64decode(_text(item, "request"), validate=False)
                body_params = _body_param_names(raw_req)
            except (binascii.Error, ValueError):
                body_params = []

        status = _text(item, "status")
        length = _text(item, "responselength")
        port = _text(item, "port")
        out.append(
            CapturedRequest(
                method=method,
                host=host,
                path=split.path or "/",
                scheme=(_text(item, "protocol") or "https").lower(),
                port=int(port) if port.isdigit() else None,
                query_params=query_params,
                body_params=body_params,
                status=int(status) if status.isdigit() else None,
                content_type=(_text(item, "mimetype") or None),
                response_size=int(length) if length.isdigit() else None,
            )
        )
    return out


__all__ = ["parse_burp_xml", "UnsafeXmlError"]
