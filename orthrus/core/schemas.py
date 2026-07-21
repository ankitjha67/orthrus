"""Shared runtime data models passed between ORTHRUS phases.

These pydantic models are the in-memory contract between recon, scanning,
exploitation, and reporting. Persistence is handled separately by the
SQLAlchemy ORM in ``orthrus.db.models``; these are intentionally decoupled so
modules can be unit-tested without a database.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from uuid import uuid4

from pydantic import BaseModel, Field


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _short_id() -> str:
    return uuid4().hex[:12]


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }[self]


class Confidence(StrEnum):
    """How sure a scanner is. CONFIRMED is reserved for the exploitation phase."""

    TENTATIVE = "tentative"
    FIRM = "firm"
    CONFIRMED = "confirmed"


class HttpMethod(StrEnum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"


class ParamLocation(StrEnum):
    """Where an injectable parameter lives - drives scanner injection logic."""

    QUERY = "query"
    BODY = "body"
    JSON = "json"
    HEADER = "header"
    COOKIE = "cookie"
    PATH = "path"
    XML = "xml"


class Aggressiveness(StrEnum):
    PASSIVE = "passive"
    NORMAL = "normal"
    AGGRESSIVE = "aggressive"


class Technology(BaseModel):
    name: str
    version: str | None = None
    category: str | None = None  # e.g. "server", "framework", "cms", "js-library"
    confidence: Confidence = Confidence.FIRM


class IpIntel(BaseModel):
    """Network-infrastructure intelligence for a single resolved IP address.

    Built from passive sources (reverse DNS + Team Cymru's IP-to-ASN service
    over DNS), so enriching a target never touches the target host itself. The
    ``country`` is the registry's *allocation* country, not a precise geo-fix.
    """

    ip: str
    ptr: list[str] = Field(default_factory=list)  # reverse-DNS hostname(s)
    asn: str | None = None  # e.g. "AS15169"
    as_org: str | None = None  # e.g. "GOOGLE - Google LLC, US"
    network: str | None = None  # announced BGP prefix, e.g. "8.8.8.0/24"
    country: str | None = None  # registry allocation country code
    registry: str | None = None  # arin / ripe / apnic / lacnic / afrinic
    allocated: str | None = None  # allocation date (ISO)
    cloud_provider: str | None = None  # attributed hosting/cloud, e.g. "AWS"


class Asset(BaseModel):
    """A discovered host: subdomain, virtual host, or IP-backed service."""

    id: str = Field(default_factory=_short_id)
    fqdn: str
    ips: list[str] = Field(default_factory=list)
    cname_chain: list[str] = Field(default_factory=list)
    ports: list[int] = Field(default_factory=list)
    discovery_method: str = "unknown"
    http_available: bool = False
    https_available: bool = False
    status_code: int | None = None
    title: str | None = None
    technologies: list[Technology] = Field(default_factory=list)
    ip_intel: IpIntel | None = None  # network intel for the primary resolved IP
    discovered_at: datetime = Field(default_factory=_utcnow)


class Param(BaseModel):
    name: str
    location: ParamLocation
    value: str | None = None


class Endpoint(BaseModel):
    """A discovered URL plus the input vectors attached to it."""

    id: str = Field(default_factory=_short_id)
    url: str
    method: HttpMethod = HttpMethod.GET
    params: list[Param] = Field(default_factory=list)
    headers: dict[str, str] = Field(default_factory=dict)
    cookies: dict[str, str] = Field(default_factory=dict)
    response_status: int | None = None
    response_headers: dict[str, str] = Field(default_factory=dict)
    set_cookies: list[str] = Field(default_factory=list)
    content_type: str | None = None
    content_length: int | None = None
    content_hash: str | None = None
    source: str = "crawler"  # how the endpoint was discovered
    discovered_at: datetime = Field(default_factory=_utcnow)


class Evidence(BaseModel):
    """Captured proof attached to a finding or exploitation."""

    request_raw: str | None = None
    response_raw: str | None = None
    matched_at: str | None = None  # the substring / location proving the issue
    screenshot_path: str | None = None
    notes: str | None = None
    extra: dict[str, str] = Field(default_factory=dict)


class Finding(BaseModel):
    """A detected (not necessarily confirmed) vulnerability."""

    id: str = Field(default_factory=_short_id)
    vuln_type: str  # e.g. "sqli", "xss", "security-headers"
    title: str
    severity: Severity
    confidence: Confidence = Confidence.TENTATIVE
    url: str
    parameter: str | None = None
    param_location: ParamLocation | None = None
    description: str = ""
    remediation: str = ""
    cwe: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    scanner: str = "unknown"
    evidence: Evidence = Field(default_factory=Evidence)
    created_at: datetime = Field(default_factory=_utcnow)
    # Post-scan triage lifecycle (set via `orthrus finding …`, not by scanners).
    status: str = "open"
    owner: str | None = None


# Allowed triage statuses for a finding's lifecycle.
FINDING_STATUSES: tuple[str, ...] = (
    "open",
    "triaged",
    "in-progress",
    "resolved",
    "accepted-risk",
    "false-positive",
)


class ExploitResult(BaseModel):
    """Outcome of an exploitation-confirmation attempt against a finding."""

    id: str = Field(default_factory=_short_id)
    finding_id: str
    technique: str
    success: bool
    extracted_data: str | None = None
    callback_id: str | None = None
    evidence: Evidence = Field(default_factory=Evidence)
    created_at: datetime = Field(default_factory=_utcnow)


__all__ = [
    "Severity",
    "Confidence",
    "HttpMethod",
    "ParamLocation",
    "Aggressiveness",
    "Technology",
    "IpIntel",
    "Asset",
    "Param",
    "Endpoint",
    "Evidence",
    "Finding",
    "ExploitResult",
]
