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


__all__ = [
    "Program",
    "ScopeEntry",
    "ProgramAsset",
    "ProgramEndpoint",
    "ScanRun",
    "PLATFORMS",
    "SCOPE_ENTRY_TYPES",
    "SCOPE_KINDS",
    "ASSET_KINDS",
    "SCAN_RUN_STATUSES",
    "new_id",
]
