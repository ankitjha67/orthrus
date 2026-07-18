"""Async data-access layer for the operator graph (PRD §6, Phase 0).

A thin async repository over the unified-domain ORM entities, sharing the same
engine/schema as the v0.1 :class:`orthrus.db.store.Store`. Phase 0 covers Program
+ ScopeEntry CRUD; the ProgramAsset graph, scan_runs, evidence, audit and cost tables
land on the same class as they're built.

Deny-by-default is enforced at creation: a Program cannot be persisted without a
non-empty ``authorization_source`` (PRD §2.3) — the DB-level guarantee behind the
scope enforcer.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from orthrus.db.models import Base
from orthrus.model.entities import (
    ASSET_KINDS,
    PLATFORMS,
    SCAN_RUN_STATUSES,
    SCOPE_ENTRY_TYPES,
    SCOPE_KINDS,
    Program,
    ProgramAsset,
    ScanRun,
    ScopeEntry,
    _utcnow,
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

    # ------------------------------------------------------------------- assets
    async def record_asset(
        self,
        program_id: str,
        kind: str,
        canonical_value: str,
        display_value: str | None = None,
        *,
        discovered_by: str | None = None,
        fingerprint: dict | None = None,
        metadata: dict | None = None,
        scope_entry_id: int | None = None,
        alive: bool = True,
    ) -> tuple[ProgramAsset, bool]:
        """Upsert an asset by (program, kind, canonical_value); return (asset, is_new).

        The heart of continuous recon (PRD §7.2): re-seeing an asset bumps
        ``last_seen_at`` (and merges fresh fingerprint/metadata) rather than
        duplicating it, so a diff of ``first_seen_at`` surfaces only genuinely
        new surface. ``is_new`` lets the recon engine fire new-asset cascades.
        """
        if kind not in ASSET_KINDS:
            raise ValueError(f"asset kind must be one of {ASSET_KINDS}, got {kind!r}")
        if not (canonical_value or "").strip():
            raise ValueError("canonical_value is required")
        canonical_value = canonical_value.strip()
        now = _utcnow()
        async with self._session() as session:
            existing = await session.execute(
                select(ProgramAsset).where(
                    ProgramAsset.program_id == program_id,
                    ProgramAsset.kind == kind,
                    ProgramAsset.canonical_value == canonical_value,
                ).limit(1)
            )
            asset = existing.scalar_one_or_none()
            if asset is not None:
                asset.last_seen_at = now
                asset.is_alive = alive
                if alive:
                    asset.last_alive_at = now
                if fingerprint:
                    asset.fingerprint = {**(asset.fingerprint or {}), **fingerprint}
                if metadata:
                    asset.metadata_json = {**(asset.metadata_json or {}), **metadata}
                await session.commit()
                await session.refresh(asset)
                return asset, False

            asset = ProgramAsset(
                program_id=program_id, kind=kind, canonical_value=canonical_value,
                display_value=(display_value or canonical_value), discovered_by=discovered_by,
                fingerprint=fingerprint or {}, metadata_json=metadata or {},
                scope_entry_id=scope_entry_id, first_seen_at=now, last_seen_at=now,
                is_alive=alive, last_alive_at=now if alive else None,
            )
            session.add(asset)
            await session.commit()
            await session.refresh(asset)
            return asset, True

    async def get_asset(self, asset_id: str) -> ProgramAsset | None:
        async with self._session() as session:
            return await session.get(ProgramAsset, asset_id)

    async def list_assets(
        self, program_id: str, *, kind: str | None = None,
        alive_only: bool = False, include_noise: bool = False,
    ) -> list[ProgramAsset]:
        stmt = select(ProgramAsset).where(ProgramAsset.program_id == program_id)
        if kind:
            stmt = stmt.where(ProgramAsset.kind == kind)
        if alive_only:
            stmt = stmt.where(ProgramAsset.is_alive.is_(True))
        if not include_noise:
            stmt = stmt.where(ProgramAsset.is_wildcard_noise.is_(False))
        async with self._session() as session:
            result = await session.execute(stmt.order_by(ProgramAsset.canonical_value))
            return list(result.scalars().all())

    async def new_assets_since(self, program_id: str, since: datetime) -> list[ProgramAsset]:
        """Assets first seen at/after ``since`` — the continuous-recon diff (PRD §7.2)."""
        async with self._session() as session:
            result = await session.execute(
                select(ProgramAsset).where(
                    ProgramAsset.program_id == program_id,
                    ProgramAsset.first_seen_at >= since,
                    ProgramAsset.is_wildcard_noise.is_(False),
                ).order_by(ProgramAsset.first_seen_at)
            )
            return list(result.scalars().all())

    # --------------------------------------------------------------- scan runs
    async def start_scan_run(
        self, program_id: str, *, triggered_by: str = "manual",
        config: dict | None = None, workflow_id: str | None = None,
    ) -> ScanRun:
        run = ScanRun(
            program_id=program_id, triggered_by=triggered_by,
            config_snapshot=config or {}, workflow_id=workflow_id, status="running",
        )
        async with self._session() as session:
            session.add(run)
            await session.commit()
            await session.refresh(run)
        return run

    async def finish_scan_run(
        self, run_id: str, *, status: str = "completed",
        stats: dict | None = None, error: str | None = None,
    ) -> ScanRun | None:
        if status not in SCAN_RUN_STATUSES:
            raise ValueError(f"status must be one of {SCAN_RUN_STATUSES}")
        async with self._session() as session:
            run = await session.get(ScanRun, run_id)
            if run is None:
                return None
            run.status = status
            run.ended_at = _utcnow()
            if stats:
                run.stats = {**(run.stats or {}), **stats}
            if error:
                run.error_summary = error
            await session.commit()
            await session.refresh(run)
        return run


__all__ = ["ProgramGraph"]
