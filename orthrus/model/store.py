"""Async data-access layer for the operator graph (PRD §6, Phase 0).

A thin async repository over the unified-domain ORM entities, sharing the same
engine/schema as the v0.1 :class:`orthrus.db.store.Store`. Phase 0 covers Program
+ ScopeEntry CRUD; the Asset graph, scan_runs, evidence, audit and cost tables
land on the same class as they're built.

Deny-by-default is enforced at creation: a Program cannot be persisted without a
non-empty ``authorization_source`` (PRD §2.3) — the DB-level guarantee behind the
scope enforcer.
"""

from __future__ import annotations

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from orthrus.db.models import Base
from orthrus.model.entities import (
    PLATFORMS,
    SCOPE_ENTRY_TYPES,
    SCOPE_KINDS,
    Program,
    ScopeEntry,
)


class ProgramGraph:
    """Repository for Programs and their scope entries."""

    def __init__(self, db_url: str) -> None:
        self.engine = create_async_engine(db_url, future=True)
        self._session = async_sessionmaker(
            self.engine, expire_on_commit=False, class_=AsyncSession
        )

    async def init(self) -> None:
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    async def close(self) -> None:
        await self.engine.dispose()

    # ---------------------------------------------------------------- programs
    async def create_program(
        self,
        name: str,
        authorization_source: str,
        *,
        platform: str = "direct",
        policy_url: str | None = None,
        jurisdiction: str | None = None,
        priority: int = 3,
        reward_range: dict | None = None,
        rate_limit_hint: dict | None = None,
        contact_email: str | None = None,
        tags: list | None = None,
    ) -> Program:
        if not (name or "").strip():
            raise ValueError("program name is required")
        if not (authorization_source or "").strip():
            # Deny-by-default: no engagement without a declared authorization source.
            raise ValueError(
                "authorization_source is required (a platform URL, 'signed:<hash>', "
                "'direct:<note>', or 'self-owned-lab') — ORTHRUS will not create an "
                "unauthorized program"
            )
        if platform not in PLATFORMS:
            raise ValueError(f"platform must be one of {PLATFORMS}, got {platform!r}")
        program = Program(
            name=name.strip(),
            authorization_source=authorization_source.strip(),
            platform=platform,
            policy_url=policy_url,
            jurisdiction=jurisdiction,
            priority=priority,
            reward_range=reward_range or {},
            rate_limit_hint=rate_limit_hint or {},
            contact_email=contact_email,
            tags=tags or [],
        )
        async with self._session() as session:
            session.add(program)
            await session.commit()
            await session.refresh(program)
        return program

    async def get_program(self, program_id: str) -> Program | None:
        async with self._session() as session:
            return await session.get(Program, program_id)

    async def get_program_by_name(self, name: str) -> Program | None:
        async with self._session() as session:
            result = await session.execute(
                select(Program).where(Program.name == name).limit(1)
            )
            return result.scalar_one_or_none()

    async def list_programs(self) -> list[Program]:
        async with self._session() as session:
            result = await session.execute(select(Program).order_by(Program.name))
            return list(result.scalars().all())

    async def update_program(self, program_id: str, **fields) -> Program | None:
        allowed = {
            "name", "platform", "authorization_source", "policy_url", "expires_at",
            "reward_range", "rules_of_engagement_md", "rate_limit_hint", "contact_email",
            "notes_md", "is_paused", "is_read_only", "priority", "tags", "jurisdiction",
        }
        if "platform" in fields and fields["platform"] not in PLATFORMS:
            raise ValueError(f"platform must be one of {PLATFORMS}")
        if "authorization_source" in fields and not (fields["authorization_source"] or "").strip():
            raise ValueError("authorization_source cannot be cleared")
        async with self._session() as session:
            program = await session.get(Program, program_id)
            if program is None:
                return None
            for key, value in fields.items():
                if key in allowed:
                    setattr(program, key, value)
            await session.commit()
            await session.refresh(program)
        return program

    async def delete_program(self, program_id: str) -> bool:
        # Explicit bulk deletes (child first) so we never depend on ORM relationship
        # cascade — which would lazy-load under async and raise MissingGreenlet.
        async with self._session() as session:
            await session.execute(
                delete(ScopeEntry).where(ScopeEntry.program_id == program_id)
            )
            result = await session.execute(delete(Program).where(Program.id == program_id))
            await session.commit()
        return (result.rowcount or 0) > 0

    # ------------------------------------------------------------ scope entries
    async def add_scope_entry(
        self,
        program_id: str,
        value: str,
        *,
        entry_type: str = "in",
        kind: str = "domain",
        ports: list | None = None,
        protocols: list | None = None,
        added_by: str | None = None,
    ) -> ScopeEntry:
        if entry_type not in SCOPE_ENTRY_TYPES:
            raise ValueError(f"entry_type must be one of {SCOPE_ENTRY_TYPES}")
        if kind not in SCOPE_KINDS:
            raise ValueError(f"kind must be one of {SCOPE_KINDS}")
        if not (value or "").strip():
            raise ValueError("scope value is required")
        entry = ScopeEntry(
            program_id=program_id, value=value.strip(), entry_type=entry_type,
            kind=kind, ports=ports, protocols=protocols, added_by=added_by,
        )
        async with self._session() as session:
            session.add(entry)
            await session.commit()
            await session.refresh(entry)
        return entry

    async def scope_entries(self, program_id: str, *, active_only: bool = True) -> list[ScopeEntry]:
        stmt = select(ScopeEntry).where(ScopeEntry.program_id == program_id)
        if active_only:
            stmt = stmt.where(ScopeEntry.is_active.is_(True))
        async with self._session() as session:
            result = await session.execute(stmt.order_by(ScopeEntry.id))
            return list(result.scalars().all())

    async def deactivate_scope_entry(self, entry_id: int) -> bool:
        async with self._session() as session:
            entry = await session.get(ScopeEntry, entry_id)
            if entry is None:
                return False
            entry.is_active = False
            await session.commit()
        return True

    async def clear_scope(self, program_id: str) -> int:
        async with self._session() as session:
            result = await session.execute(
                delete(ScopeEntry).where(ScopeEntry.program_id == program_id)
            )
            await session.commit()
            return result.rowcount or 0


__all__ = ["ProgramGraph"]
