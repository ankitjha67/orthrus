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

import hashlib
import json
from datetime import UTC, datetime

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from orthrus.db.models import Base
from orthrus.model.entities import (
    ASSET_KINDS,
    FINDING_CONFIDENCES,
    FINDING_STATUSES,
    PLATFORMS,
    SCAN_RUN_STATUSES,
    SCOPE_ENTRY_TYPES,
    SCOPE_KINDS,
    AuditLogRow,
    CostLedgerRow,
    Evidence,
    Note,
    Program,
    ProgramAsset,
    ProgramFinding,
    ScanRun,
    ScopeEntry,
    _utcnow,
)


def _iso(dt: datetime) -> str:
    """UTC, second-resolution ISO — stable across DB round-trips for hashing."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).isoformat(timespec="seconds")


def _audit_row_hash(prev_hash: str | None, payload: dict) -> str:
    blob = json.dumps({"prev": prev_hash or "", **payload}, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


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
        wildcard_noise: bool = False,
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
                if wildcard_noise:
                    asset.is_wildcard_noise = True
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
                is_wildcard_noise=wildcard_noise,
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

    # -------------------------------------------------------------- findings
    async def record_finding(
        self,
        program_id: str,
        vuln_class: str,
        title: str,
        severity: str,
        signature: str,
        *,
        confidence: str = "tentative",
        found_by_tool: str = "unknown",
        scan_run_id: str | None = None,
        asset_id: str | None = None,
        endpoint_id: str | None = None,
        cwe_id: str | None = None,
        cvss_v3_vector: str | None = None,
        cvss_v3_score: float | None = None,
        priority_score: float | None = None,
    ) -> tuple[ProgramFinding, bool]:
        """Create or dedup a finding by (program, signature); return (finding, is_new).

        Cross-tool dedup (PRD §7.5): two tools reporting the same bug collapse to
        one finding by ``signature``; the first tool keeps the credit.
        """
        if confidence not in FINDING_CONFIDENCES:
            raise ValueError(f"confidence must be one of {FINDING_CONFIDENCES}")
        if not (signature or "").strip():
            raise ValueError("signature is required for dedup")
        async with self._session() as session:
            existing = (await session.execute(
                select(ProgramFinding).where(
                    ProgramFinding.program_id == program_id,
                    ProgramFinding.signature == signature,
                ).limit(1)
            )).scalar_one_or_none()
            if existing is not None:
                return existing, False
            finding = ProgramFinding(
                program_id=program_id, vuln_class=vuln_class, title=title,
                severity=severity, signature=signature, confidence=confidence,
                found_by_tool=found_by_tool, scan_run_id=scan_run_id, asset_id=asset_id,
                endpoint_id=endpoint_id, cwe_id=cwe_id, cvss_v3_vector=cvss_v3_vector,
                cvss_v3_score=cvss_v3_score, priority_score=priority_score, status="new",
            )
            session.add(finding)
            await session.commit()
            await session.refresh(finding)
            return finding, True

    async def list_findings(
        self, program_id: str, *, status: str | None = None,
    ) -> list[ProgramFinding]:
        stmt = select(ProgramFinding).where(ProgramFinding.program_id == program_id)
        if status:
            stmt = stmt.where(ProgramFinding.status == status)
        async with self._session() as session:
            result = await session.execute(
                stmt.order_by(ProgramFinding.priority_score.desc().nullslast())
            )
            return list(result.scalars().all())

    async def get_finding(self, finding_id: str) -> ProgramFinding | None:
        async with self._session() as session:
            return await session.get(ProgramFinding, finding_id)

    async def update_finding(self, finding_id: str, **fields) -> ProgramFinding | None:
        """Update triage/ownership fields (status uses set_finding_status for stamping)."""
        allowed = {"assigned_to", "hunter_notes_md", "bounty_amount", "currency",
                   "llm_fp_confidence", "duplicate_of", "priority_score"}
        async with self._session() as session:
            finding = await session.get(ProgramFinding, finding_id)
            if finding is None:
                return None
            for key, value in fields.items():
                if key in allowed:
                    setattr(finding, key, value)
            await session.commit()
            await session.refresh(finding)
        return finding

    async def set_finding_status(self, finding_id: str, status: str) -> ProgramFinding | None:
        if status not in FINDING_STATUSES:
            raise ValueError(f"status must be one of {FINDING_STATUSES}")
        stamp = {
            "confirmed": "confirmed_at", "filed": "filed_at", "rewarded": "rewarded_at",
        }.get(status)
        async with self._session() as session:
            finding = await session.get(ProgramFinding, finding_id)
            if finding is None:
                return None
            finding.status = status
            if stamp and getattr(finding, stamp) is None:
                setattr(finding, stamp, _utcnow())
            await session.commit()
            await session.refresh(finding)
        return finding

    # -------------------------------------------------------------- evidence
    async def add_evidence(
        self, finding_id: str, kind: str, content_ref: str, *,
        content: bytes | None = None, content_hash: str | None = None,
        is_redacted: bool = False, redaction_map: dict | None = None,
        mime_type: str | None = None,
    ) -> Evidence:
        """Attach content-addressable evidence; hash is computed from ``content`` if given."""
        if content is not None:
            content_hash = hashlib.sha256(content).hexdigest()
        if not content_hash:
            raise ValueError("provide content= (to hash) or an explicit content_hash=")
        ev = Evidence(
            finding_id=finding_id, kind=kind, content_ref=content_ref,
            content_hash=content_hash, is_redacted=is_redacted,
            redaction_map=redaction_map or {}, mime_type=mime_type,
            size_bytes=(len(content) if content is not None else None),
        )
        async with self._session() as session:
            session.add(ev)
            await session.commit()
            await session.refresh(ev)
        return ev

    # ------------------------------------------------------ audit (hash-chained)
    async def append_audit(
        self, event_type: str, action: str, *,
        subject_type: str | None = None, subject_id: str | None = None,
        actor: str = "system", details: dict | None = None,
    ) -> AuditLogRow:
        details = details or {}
        ts = _utcnow()
        async with self._session() as session:
            last = (await session.execute(
                select(AuditLogRow).order_by(AuditLogRow.id.desc()).limit(1)
            )).scalar_one_or_none()
            prev = last.row_hash if last else None
            payload = {
                "event_type": event_type, "subject_type": subject_type,
                "subject_id": subject_id, "actor": actor, "action": action,
                "details": details, "ts": _iso(ts),
            }
            row = AuditLogRow(
                event_type=event_type, subject_type=subject_type, subject_id=subject_id,
                actor=actor, action=action, details=details, ts=ts, prev_hash=prev,
                row_hash=_audit_row_hash(prev, payload),
            )
            session.add(row)
            await session.commit()
            await session.refresh(row)
        return row

    async def verify_audit(self) -> tuple[bool, int]:
        """Walk the hash chain; return (intact, first_bad_id) — first_bad_id -1 if OK."""
        async with self._session() as session:
            rows = list((await session.execute(
                select(AuditLogRow).order_by(AuditLogRow.id)
            )).scalars().all())
        prev = None
        for r in rows:
            payload = {
                "event_type": r.event_type, "subject_type": r.subject_type,
                "subject_id": r.subject_id, "actor": r.actor, "action": r.action,
                "details": r.details, "ts": _iso(r.ts),
            }
            if _audit_row_hash(prev, payload) != r.row_hash or (r.prev_hash or None) != prev:
                return False, r.id
            prev = r.row_hash
        return True, -1

    # ------------------------------------------------------------------ cost
    async def record_cost(
        self, category: str, provider: str, quantity: float, unit: str, cost_usd: float,
        *, program_id: str | None = None, scan_run_id: str | None = None,
    ) -> CostLedgerRow:
        row = CostLedgerRow(
            category=category, provider=provider, quantity=quantity, unit=unit,
            cost_usd=cost_usd, program_id=program_id, scan_run_id=scan_run_id,
        )
        async with self._session() as session:
            session.add(row)
            await session.commit()
            await session.refresh(row)
        return row

    async def cost_summary(self, program_id: str | None = None) -> dict:
        stmt = select(CostLedgerRow)
        if program_id:
            stmt = stmt.where(CostLedgerRow.program_id == program_id)
        async with self._session() as session:
            rows = list((await session.execute(stmt)).scalars().all())
        by_category: dict[str, float] = {}
        by_provider: dict[str, float] = {}
        total = 0.0
        for r in rows:
            total += r.cost_usd
            by_category[r.category] = round(by_category.get(r.category, 0.0) + r.cost_usd, 6)
            by_provider[r.provider] = round(by_provider.get(r.provider, 0.0) + r.cost_usd, 6)
        return {"entries": len(rows), "total_usd": round(total, 4),
                "by_category": by_category, "by_provider": by_provider}

    # ------------------------------------------------------------------- notes
    async def add_note(
        self, title: str, markdown: str = "", *, program_id: str | None = None,
        asset_id: str | None = None, finding_id: str | None = None,
        tags: list | None = None, created_by: str | None = None,
    ) -> Note:
        if not (title or "").strip():
            raise ValueError("note title is required")
        note = Note(title=title.strip(), markdown=markdown, program_id=program_id,
                    asset_id=asset_id, finding_id=finding_id, tags=tags or [],
                    created_by=created_by)
        async with self._session() as session:
            session.add(note)
            await session.commit()
            await session.refresh(note)
        return note

    async def get_note(self, note_id: str) -> Note | None:
        async with self._session() as session:
            return await session.get(Note, note_id)

    async def list_notes(self, *, program_id: str | None = None,
                         finding_id: str | None = None) -> list[Note]:
        stmt = select(Note)
        if program_id:
            stmt = stmt.where(Note.program_id == program_id)
        if finding_id:
            stmt = stmt.where(Note.finding_id == finding_id)
        async with self._session() as session:
            result = await session.execute(stmt.order_by(Note.updated_at.desc()))
            return list(result.scalars().all())

    async def search_notes(self, query: str, *, program_id: str | None = None) -> list[Note]:
        """Case-insensitive title/body/tag substring search (a real embedder can layer on)."""
        q = (query or "").strip().lower()
        if not q:
            return []
        notes = await self.list_notes(program_id=program_id)
        return [n for n in notes
                if q in (n.title or "").lower() or q in (n.markdown or "").lower()
                or any(q in str(t).lower() for t in (n.tags or []))]

    async def update_note(self, note_id: str, **fields) -> Note | None:
        allowed = {"title", "markdown", "tags", "asset_id", "finding_id"}
        async with self._session() as session:
            note = await session.get(Note, note_id)
            if note is None:
                return None
            for key, value in fields.items():
                if key in allowed:
                    setattr(note, key, value)
            await session.commit()
            await session.refresh(note)
        return note

    async def delete_note(self, note_id: str) -> bool:
        async with self._session() as session:
            result = await session.execute(delete(Note).where(Note.id == note_id))
            await session.commit()
        return (result.rowcount or 0) > 0


__all__ = ["ProgramGraph"]
