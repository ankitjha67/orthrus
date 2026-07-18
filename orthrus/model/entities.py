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
    ForeignKey,
    Integer,
    String,
    Text,
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


__all__ = [
    "Program",
    "ScopeEntry",
    "PLATFORMS",
    "SCOPE_ENTRY_TYPES",
    "SCOPE_KINDS",
    "new_id",
]
