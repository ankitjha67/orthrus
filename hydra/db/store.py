"""Async persistence layer: findings CRUD and scan state management.

Converts the in-memory pydantic schemas (``hydra.core.schemas``) into ORM rows
and back. Modules depend on this ``Store`` rather than touching SQLAlchemy
sessions directly.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from hydra.core import schemas
from hydra.db.models import Asset as AssetRow
from hydra.db.models import Base
from hydra.db.models import Callback as CallbackRow
from hydra.db.models import Endpoint as EndpointRow
from hydra.db.models import Exploitation as ExploitationRow
from hydra.db.models import Finding as FindingRow
from hydra.db.models import Scan as ScanRow
from hydra.db.models import ScanLog as ScanLogRow


class Store:
    def __init__(self, db_url: str) -> None:
        self.engine = create_async_engine(db_url, future=True)
        self._session_factory = async_sessionmaker(
            self.engine, expire_on_commit=False, class_=AsyncSession
        )

    async def init(self) -> None:
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    def session(self) -> AsyncSession:
        return self._session_factory()

    async def close(self) -> None:
        await self.engine.dispose()

    # ------------------------------------------------------------------ scans
    async def create_scan(
        self,
        scan_id: str,
        target: str,
        scope_json: dict,
        config_json: dict,
    ) -> ScanRow:
        async with self.session() as session:
            row = ScanRow(
                id=scan_id,
                target=target,
                scope_json=scope_json,
                config_json=config_json,
                status="running",
            )
            session.add(row)
            await session.commit()
            return row

    async def set_scan_status(self, scan_id: str, status: str, *, completed: bool = False) -> None:
        async with self.session() as session:
            row = await session.get(ScanRow, scan_id)
            if row is None:
                return
            row.status = status
            if completed:
                row.completed_at = datetime.now(UTC)
            await session.commit()

    async def get_scan(self, scan_id: str) -> ScanRow | None:
        async with self.session() as session:
            return await session.get(ScanRow, scan_id)

    # ----------------------------------------------------------------- assets
    async def add_asset(self, scan_id: str, asset: schemas.Asset) -> int:
        async with self.session() as session:
            row = AssetRow(
                scan_id=scan_id,
                fqdn=asset.fqdn,
                ips_json=asset.ips,
                ports_json=asset.ports,
                technology_json=[t.model_dump(mode="json") for t in asset.technologies],
                discovery_method=asset.discovery_method,
                http_available=asset.http_available,
                https_available=asset.https_available,
                status_code=asset.status_code,
                title=asset.title,
            )
            session.add(row)
            await session.commit()
            return row.id

    # -------------------------------------------------------------- endpoints
    async def add_endpoint(
        self,
        scan_id: str,
        endpoint: schemas.Endpoint,
        asset_id: int | None = None,
    ) -> int:
        async with self.session() as session:
            row = EndpointRow(
                scan_id=scan_id,
                asset_id=asset_id,
                url=endpoint.url,
                method=endpoint.method.value,
                parameters_json=[p.model_dump(mode="json") for p in endpoint.params],
                response_status=endpoint.response_status,
                content_type=endpoint.content_type,
                content_hash=endpoint.content_hash,
                source=endpoint.source,
            )
            session.add(row)
            await session.commit()
            return row.id

    # --------------------------------------------------------------- findings
    async def add_finding(
        self,
        scan_id: str,
        finding: schemas.Finding,
        endpoint_id: int | None = None,
    ) -> int:
        async with self.session() as session:
            row = FindingRow(
                scan_id=scan_id,
                endpoint_id=endpoint_id,
                vuln_type=finding.vuln_type,
                title=finding.title,
                severity=finding.severity.value,
                confidence=finding.confidence.value,
                url=finding.url,
                parameter=finding.parameter,
                description=finding.description,
                remediation=finding.remediation,
                cwe=finding.cwe,
                cvss_score=finding.cvss_score,
                cvss_vector=finding.cvss_vector,
                scanner=finding.scanner,
                evidence_json=finding.evidence.model_dump(mode="json"),
            )
            session.add(row)
            await session.commit()
            return row.id

    async def get_findings(self, scan_id: str) -> list[FindingRow]:
        async with self.session() as session:
            result = await session.execute(
                select(FindingRow).where(FindingRow.scan_id == scan_id)
            )
            return list(result.scalars().all())

    async def set_finding_confidence(self, finding_id: int, confidence: str) -> None:
        async with self.session() as session:
            row = await session.get(FindingRow, finding_id)
            if row is not None:
                row.confidence = confidence
                await session.commit()

    async def severity_counts(self, scan_id: str) -> dict[str, int]:
        async with self.session() as session:
            result = await session.execute(
                select(FindingRow.severity, func.count())
                .where(FindingRow.scan_id == scan_id)
                .group_by(FindingRow.severity)
            )
            return {severity: count for severity, count in result.all()}

    # ---------------------------------------------------------- exploitations
    async def add_exploitation(self, finding_id: int, result: schemas.ExploitResult) -> int:
        async with self.session() as session:
            row = ExploitationRow(
                finding_id=finding_id,
                technique=result.technique,
                success=result.success,
                extracted_data=result.extracted_data,
                request_raw=result.evidence.request_raw,
                response_raw=result.evidence.response_raw,
                screenshot_path=result.evidence.screenshot_path,
                callback_id=result.callback_id,
            )
            session.add(row)
            await session.commit()
            return row.id

    # -------------------------------------------------------------- callbacks
    async def add_callback(
        self,
        unique_id: str,
        protocol: str,
        source_ip: str | None,
        request_data: dict,
    ) -> int:
        async with self.session() as session:
            row = CallbackRow(
                unique_id=unique_id,
                protocol=protocol,
                source_ip=source_ip,
                request_data=request_data,
            )
            session.add(row)
            await session.commit()
            return row.id

    # ------------------------------------------------------------------- logs
    async def log(self, scan_id: str, level: str, module: str, message: str) -> None:
        async with self.session() as session:
            session.add(
                ScanLogRow(scan_id=scan_id, level=level, module=module, message=message)
            )
            await session.commit()


__all__ = ["Store"]
