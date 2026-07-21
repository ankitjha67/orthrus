"""Operator-graph ORM entities (PRD §6.1).

Phase 0 lands the authorization anchor: :class:`Program` (every asset, scan, and
finding traces back to one, and nothing runs without a valid
``authorization_source``) and :class:`ScopeEntry` (in/out-of-scope entries,
port/protocol-constrained). Later Phase-0 work adds the polymorphic Asset graph,
scan_runs, evidence, audit log, and cost ledger on the same Base.

JSON columns are used for flexible sub-structures (reward tiers, tags, ports) so
the schema is portable between SQLite (dev) and PostgreSQL (prod), matching the
v0.1 models' approach.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

# Share the v0.1 Base so the operator graph and scan artifacts live in one DB and
# are created together by ``Store.init()`` / Alembic.
from orthrus.db.models import Base

# --- controlled vocabularies (validated at the DAL/API boundary) -----------------
# authorization platforms an engagement can be tied to (PRD §6.1, §2.3)
PLATFORMS = ("h1", "bc", "int", "ywh", "im", "self", "direct")
SCOPE_ENTRY_TYPES = ("in", "out")
# polymorphic scope kinds — web, API, mobile, web3, LLM, source (PRD §2.1 multi-domain)
SCOPE_KINDS = (
    "domain", "ip_cidr", "url", "mobile_app", "graphql", "grpc",
    "contract", "llm", "repo", "publisher_id",
)
# polymorphic asset kinds recon discovers (PRD §6.1)
ASSET_KINDS = (
    "subdomain", "host", "ip", "url", "endpoint", "s3_bucket", "github_repo",
    "apk", "ipa", "contract", "graphql_op", "api_route", "llm_endpoint",
)
SCAN_RUN_STATUSES = ("running", "completed", "failed", "cancelled", "paused")
# finding lifecycle + confidence + attack-chain vocabularies (PRD §6.1)
FINDING_STATUSES = (
    "new", "triaging", "confirmed", "duplicate", "not_reproducible", "filed",
    "accepted", "rewarded", "closed", "verified_fixed", "regressed", "out_of_scope",
)
FINDING_CONFIDENCES = (
    "tentative", "firm", "confirmed", "flappy", "waf_blocked", "pending_confirmation",
)
CHAIN_RELATIONSHIPS = ("enables", "amplifies", "persists", "escalates_via", "exfiltrates_via")
EVIDENCE_KINDS = (
    "request", "response", "screenshot", "dom_snapshot", "har", "video", "log",
    "network_trace", "replay_bundle", "oast_callback",
)


def _utcnow() -> datetime:
    return datetime.now(UTC)


def new_id() -> str:
    """A short unique id for operator-graph rows (ULID-shaped is a later upgrade)."""
    return uuid.uuid4().hex


class Program(Base):
    """A bug-bounty program: the anchor of authorization (PRD §6.2).

    Every asset/scan/finding in the operator graph references a Program, and a
    Program must carry a valid ``authorization_source`` — a platform policy URL,
    ``signed:<hash>``, ``direct:<note>``, or ``self-owned-lab``. Deny-by-default.
    """

    __tablename__ = "programs"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(255), index=True)
    platform: Mapped[str] = mapped_column(String(16), default="direct")
    authorization_source: Mapped[str] = mapped_column(Text)
    policy_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    authorized_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    reward_range: Mapped[dict] = mapped_column(JSON, default=dict)      # {"critical": [1000,10000], ...}
    rules_of_engagement_md: Mapped[str | None] = mapped_column(Text, nullable=True)
    rate_limit_hint: Mapped[dict] = mapped_column(JSON, default=dict)   # {"rps_per_host": 10, ...}
    contact_email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    notes_md: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_paused: Mapped[bool] = mapped_column(Boolean, default=False)
    is_read_only: Mapped[bool] = mapped_column(Boolean, default=False)
    priority: Mapped[int] = mapped_column(Integer, default=3)           # 1-5 for user sort
    tags: Mapped[list] = mapped_column(JSON, default=list)
    jurisdiction: Mapped[str | None] = mapped_column(String(8), nullable=True)  # ISO country
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )

    scope_entries: Mapped[list[ScopeEntry]] = relationship(
        back_populates="program", cascade="all, delete-orphan"
    )


class ScopeEntry(Base):
    """One in-scope or out-of-scope entry for a Program (PRD §6.1).

    Modeled as a row (not JSON on Program) so wildcard-in / subdomain-out is an
    intersection query, and so entries can be port/protocol/kind-constrained.
    """

    __tablename__ = "scope_entries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    program_id: Mapped[str] = mapped_column(
        ForeignKey("programs.id", ondelete="CASCADE"), index=True
    )
    entry_type: Mapped[str] = mapped_column(String(4), default="in")     # 'in' | 'out'
    kind: Mapped[str] = mapped_column(String(24), default="domain")
    value: Mapped[str] = mapped_column(Text)                             # glob-supported for domains
    ports: Mapped[list | None] = mapped_column(JSON, nullable=True)       # null = all ports
    protocols: Mapped[list | None] = mapped_column(JSON, nullable=True)   # ['http','https','grpc']
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    added_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    program: Mapped[Program] = relationship(back_populates="scope_entries")


class ProgramAsset(Base):
    """A polymorphic thing recon finds, program-scoped and persistent (PRD §6.1).

    Keyed by ``(program_id, kind, canonical_value)`` for cross-run dedup. Carries
    the four honest noise signals (``is_historical``, ``is_ephemeral``,
    ``is_wildcard_noise``, ``trust_score``) and first/last-seen so continuous
    recon can diff what actually changed. Class + table names are distinct from
    the v0.1 scan-scoped ``Asset``/``assets`` so both live on one registry.
    """

    __tablename__ = "program_assets"
    __table_args__ = (
        UniqueConstraint("program_id", "kind", "canonical_value", name="uq_asset_identity"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    program_id: Mapped[str] = mapped_column(
        ForeignKey("programs.id", ondelete="CASCADE"), index=True
    )
    scope_entry_id: Mapped[int | None] = mapped_column(
        ForeignKey("scope_entries.id", ondelete="SET NULL"), nullable=True
    )
    kind: Mapped[str] = mapped_column(String(24), index=True)
    canonical_value: Mapped[str] = mapped_column(Text, index=True)   # normalized for dedup
    display_value: Mapped[str] = mapped_column(Text)                 # as discovered
    parent_asset_id: Mapped[str | None] = mapped_column(
        ForeignKey("program_assets.id", ondelete="SET NULL"), nullable=True
    )
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    last_alive_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    is_alive: Mapped[bool] = mapped_column(Boolean, default=True)
    is_historical: Mapped[bool] = mapped_column(Boolean, default=False)   # known only from Wayback/CT
    is_ephemeral: Mapped[bool] = mapped_column(Boolean, default=False)    # rotates often
    is_wildcard_noise: Mapped[bool] = mapped_column(Boolean, default=False)
    fingerprint: Mapped[dict] = mapped_column(JSON, default=dict)         # tech, TLS, JARM, favicon
    screenshot_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    response_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    dom_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict)       # cnames, ips, asn, geo
    discovered_by: Mapped[str | None] = mapped_column(String(64), nullable=True)  # adapter name
    trust_score: Mapped[float] = mapped_column(Float, default=1.0)        # 0-1, decays noisy sources

    endpoints: Mapped[list[ProgramEndpoint]] = relationship(
        back_populates="asset", cascade="all, delete-orphan"
    )


class ProgramEndpoint(Base):
    """A specialized HTTP-route asset (PRD §6.1). Class/table distinct from v0.1's."""

    __tablename__ = "program_endpoints"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    asset_id: Mapped[str] = mapped_column(
        ForeignKey("program_assets.id", ondelete="CASCADE"), index=True
    )
    method: Mapped[str] = mapped_column(String(8), default="GET")
    path: Mapped[str] = mapped_column(Text)
    query_params: Mapped[list] = mapped_column(JSON, default=list)
    body_params: Mapped[list] = mapped_column(JSON, default=list)
    response_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    response_content_type: Mapped[str | None] = mapped_column(String(128), nullable=True)
    response_size: Mapped[int | None] = mapped_column(Integer, nullable=True)
    is_authenticated: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    requires_csrf: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    auth_scheme: Mapped[str | None] = mapped_column(String(16), nullable=True)
    juicy_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    last_probed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    probe_count: Mapped[int] = mapped_column(Integer, default=0)

    asset: Mapped[ProgramAsset] = relationship(back_populates="endpoints")


class ScanRun(Base):
    """A program-scoped execution of a scan/recon workflow (PRD §6.1).

    Snapshots its config so a finding from months ago is reproducible with the
    exact settings even after config schema evolves. Distinct from v0.1 ``scans``.
    """

    __tablename__ = "scan_runs"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    program_id: Mapped[str] = mapped_column(
        ForeignKey("programs.id", ondelete="CASCADE"), index=True
    )
    workflow_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="running", index=True)
    config_snapshot: Mapped[dict] = mapped_column(JSON, default=dict)
    stats: Mapped[dict] = mapped_column(JSON, default=dict)   # assets_seen, findings_new, cost_usd
    triggered_by: Mapped[str] = mapped_column(String(24), default="manual")  # cron|manual|new_asset
    triggered_by_user: Mapped[str | None] = mapped_column(String(128), nullable=True)
    error_summary: Mapped[str | None] = mapped_column(Text, nullable=True)


class ProgramFinding(Base):
    """A program-anchored, deduped finding (PRD §6.1) — the triage/report unit.

    Distinct from v0.1's scan-scoped ``Finding``: this is the persistent operator
    finding a scan promotes into, carrying dedup ``signature``, cross-tool
    ``duplicate_of``, full enrichment (both CVSS versions, EPSS/KEV, CWE/OWASP/
    ATT&CK), a composite ``priority_score``, and the full status lifecycle.
    """

    __tablename__ = "program_findings"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    program_id: Mapped[str] = mapped_column(
        ForeignKey("programs.id", ondelete="CASCADE"), index=True
    )
    asset_id: Mapped[str | None] = mapped_column(
        ForeignKey("program_assets.id", ondelete="SET NULL"), nullable=True
    )
    endpoint_id: Mapped[str | None] = mapped_column(
        ForeignKey("program_endpoints.id", ondelete="SET NULL"), nullable=True
    )
    scan_run_id: Mapped[str | None] = mapped_column(
        ForeignKey("scan_runs.id", ondelete="SET NULL"), nullable=True
    )
    parent_finding_id: Mapped[str | None] = mapped_column(String(32), nullable=True)  # rollup
    duplicate_of: Mapped[str | None] = mapped_column(String(32), nullable=True)        # cross-tool
    vuln_class: Mapped[str] = mapped_column(String(64), index=True)   # ontology key (Appendix B)
    title: Mapped[str] = mapped_column(Text)
    description_md: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(16), index=True)
    confidence: Mapped[str] = mapped_column(String(24), default="tentative")
    signature: Mapped[str] = mapped_column(String(255), index=True)   # normalized dedup key
    cvss_v3_vector: Mapped[str | None] = mapped_column(String(128), nullable=True)
    cvss_v3_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_v4_vector: Mapped[str | None] = mapped_column(String(160), nullable=True)
    cvss_v4_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    epss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    kev_flag: Mapped[bool] = mapped_column(Boolean, default=False)
    cwe_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    owasp_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    capec_ids: Mapped[list] = mapped_column(JSON, default=list)
    mitre_attack_ids: Mapped[list] = mapped_column(JSON, default=list)
    mitre_d3fend_ids: Mapped[list] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(24), default="new", index=True)
    priority_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    llm_fp_confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    confirmed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    filed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    rewarded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    found_by_tool: Mapped[str] = mapped_column(String(64), default="unknown")
    bounty_amount: Mapped[float | None] = mapped_column(Float, nullable=True)
    currency: Mapped[str | None] = mapped_column(String(8), nullable=True)
    hunter_notes_md: Mapped[str | None] = mapped_column(Text, nullable=True)
    assigned_to: Mapped[str | None] = mapped_column(String(128), nullable=True)

    evidence: Mapped[list[Evidence]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )


class Evidence(Base):
    """Content-addressable evidence blob (PRD §6.1).

    ``content_hash`` (SHA-256) makes evidence deduplicatable and integrity-checkable
    — the same blob referenced by two findings stores once.
    """

    __tablename__ = "evidence"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    finding_id: Mapped[str] = mapped_column(
        ForeignKey("program_findings.id", ondelete="CASCADE"), index=True
    )
    kind: Mapped[str] = mapped_column(String(24))
    content_ref: Mapped[str] = mapped_column(Text)          # S3 key or local path
    content_hash: Mapped[str] = mapped_column(String(64), index=True)
    captured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    is_redacted: Mapped[bool] = mapped_column(Boolean, default=False)
    redaction_map: Mapped[dict] = mapped_column(JSON, default=dict)
    size_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    mime_type: Mapped[str | None] = mapped_column(String(128), nullable=True)

    finding: Mapped[ProgramFinding] = relationship(back_populates="evidence")


class FindingChain(Base):
    """A directed edge in the attack graph (PRD §6.1/§7.8)."""

    __tablename__ = "finding_chains"
    __table_args__ = (
        UniqueConstraint("from_finding_id", "to_finding_id", "relationship",
                         name="uq_chain_edge"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    from_finding_id: Mapped[str] = mapped_column(
        ForeignKey("program_findings.id", ondelete="CASCADE"), index=True
    )
    to_finding_id: Mapped[str] = mapped_column(
        ForeignKey("program_findings.id", ondelete="CASCADE"), index=True
    )
    relationship: Mapped[str] = mapped_column(String(24))
    narrative_md: Mapped[str | None] = mapped_column(Text, nullable=True)
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    proposed_by: Mapped[str] = mapped_column(String(16), default="rules")  # rules|llm|user
    accepted_by_user: Mapped[bool] = mapped_column(Boolean, default=False)


class AuditLogRow(Base):
    """Append-only, hash-chained audit row (PRD §6.1/§8.5). Tamper-evident."""

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_type: Mapped[str] = mapped_column(String(64))
    subject_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    subject_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    actor: Mapped[str] = mapped_column(String(128), default="system")
    action: Mapped[str] = mapped_column(String(64))
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    prev_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    row_hash: Mapped[str] = mapped_column(String(64))


class Note(Base):
    """Operator knowledge-base note, optionally tied to a program/asset/finding (PRD §6.1/§7.13)."""

    __tablename__ = "notes"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    program_id: Mapped[str | None] = mapped_column(
        ForeignKey("programs.id", ondelete="CASCADE"), nullable=True, index=True
    )
    asset_id: Mapped[str | None] = mapped_column(
        ForeignKey("program_assets.id", ondelete="SET NULL"), nullable=True
    )
    finding_id: Mapped[str | None] = mapped_column(
        ForeignKey("program_findings.id", ondelete="SET NULL"), nullable=True
    )
    title: Mapped[str] = mapped_column(Text)
    markdown: Mapped[str] = mapped_column(Text, default="")
    tags: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )
    created_by: Mapped[str | None] = mapped_column(String(128), nullable=True)


class CostLedgerRow(Base):
    """One spend line — LLM/STT/OAST/compute/API (PRD §6.1/§10)."""

    __tablename__ = "cost_ledger"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    program_id: Mapped[str | None] = mapped_column(
        ForeignKey("programs.id", ondelete="SET NULL"), nullable=True, index=True
    )
    scan_run_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    category: Mapped[str] = mapped_column(String(24))     # llm|stt|oast|compute|api
    provider: Mapped[str] = mapped_column(String(64))
    quantity: Mapped[float] = mapped_column(Float, default=0.0)
    unit: Mapped[str] = mapped_column(String(16), default="tokens")
    cost_usd: Mapped[float] = mapped_column(Float, default=0.0)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


__all__ = [
    "Program",
    "ScopeEntry",
    "ProgramAsset",
    "ProgramEndpoint",
    "ScanRun",
    "ProgramFinding",
    "Evidence",
    "FindingChain",
    "AuditLogRow",
    "CostLedgerRow",
    "Note",
    "PLATFORMS",
    "SCOPE_ENTRY_TYPES",
    "SCOPE_KINDS",
    "ASSET_KINDS",
    "SCAN_RUN_STATUSES",
    "FINDING_STATUSES",
    "FINDING_CONFIDENCES",
    "CHAIN_RELATIONSHIPS",
    "EVIDENCE_KINDS",
    "new_id",
]
