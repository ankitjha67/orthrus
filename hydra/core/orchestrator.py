"""Phase sequencing and task dispatch (PRD §4.1).

The orchestrator wires up the per-scan infrastructure, then drives the four
phases: recon -> scan -> exploit -> report. Recon is functional; scan and
exploit iterate their registries (empty until later roadmap phases) so the
pipeline runs end-to-end today and grows without structural change.
"""

from __future__ import annotations

from uuid import uuid4

from rich.table import Table

from hydra.core import schemas
from hydra.core.callback import LocalCallbackServer
from hydra.core.config import ScanConfig, Settings
from hydra.core.context import ScanContext
from hydra.core.event_bus import Event, EventBus, EventType
from hydra.core.http_client import HttpClient
from hydra.core.schemas import Aggressiveness, Confidence
from hydra.core.session import Session
from hydra.db.store import Store
from hydra.exploits.registry import exploits_for
from hydra.recon.base import BaseRecon
from hydra.recon.crawler import Crawler
from hydra.recon.tech_fingerprint import TechFingerprint
from hydra.reporting.generator import generate_report
from hydra.scanners.registry import get_scanners
from hydra.utils.logger import console, get_logger
from hydra.utils.scope import ScopeValidator

logger = get_logger("orchestrator")

_AGGRESSIVENESS_RANK = {
    Aggressiveness.PASSIVE: 0,
    Aggressiveness.NORMAL: 1,
    Aggressiveness.AGGRESSIVE: 2,
}


class Orchestrator:
    def __init__(self, config: ScanConfig, settings: Settings) -> None:
        self.config = config
        self.settings = settings
        self.scan_id = config.scan_id or f"scan-{uuid4().hex[:8]}"
        self.event_bus = EventBus()
        self.scope = ScopeValidator(config.scope)
        self.store = Store(settings.db_url)
        self.ctx: ScanContext | None = None

    async def setup(self) -> None:
        await self.store.init()

        session = Session.from_cookie_string(self.config.auth_cookie)
        session.headers.update(self.config.extra_headers)
        http = HttpClient.from_config(
            self.config, self.scope, event_bus=self.event_bus, session=session
        )
        self.ctx = ScanContext(
            scan_id=self.scan_id,
            config=self.config,
            scope=self.scope,
            http=http,
            store=self.store,
            event_bus=self.event_bus,
        )
        self._wire_events()

        if not self.config.no_exploit:
            if self.config.callback:
                logger.info(
                    "external callback (%s) not yet supported; using local listener",
                    self.config.callback,
                )
            callback = LocalCallbackServer()
            await callback.start()
            self.ctx.callback = callback

        await self.store.create_scan(
            self.scan_id,
            self.config.target,
            self.config.scope.model_dump(mode="json"),
            self.config.model_dump(mode="json"),
        )
        await self.event_bus.emit(
            EventType.SCAN_STARTED, scan_id=self.scan_id, target=self.config.target
        )
        logger.info("scan [bold]%s[/] started against %s", self.scan_id, self.config.target)

    def _wire_events(self) -> None:
        async def on_scope_violation(event: Event) -> None:
            await self.store.log(
                self.scan_id,
                "warning",
                "scope",
                f"blocked {event.data.get('url')}: {event.data.get('reason')}",
            )

        self.event_bus.subscribe(EventType.SCOPE_VIOLATION, on_scope_violation)

    # ----------------------------------------------------------- phase: recon
    async def run_recon(self, which: set[str] | None = None) -> tuple[int, int]:
        assert self.ctx is not None
        await self.event_bus.emit(EventType.PHASE_STARTED, phase="recon")

        modules: list[BaseRecon] = []
        if which is None or "fingerprint" in which:
            modules.append(TechFingerprint())
        if which is None or "crawl" in which:
            modules.append(Crawler())

        seen_endpoints: set[tuple[str, str]] = set()
        for module in modules:
            if not module.applicable(self.ctx):
                continue
            logger.info("recon: running %s", module.name)
            async for item in module.discover(self.ctx):
                if isinstance(item, schemas.Asset):
                    self.ctx.assets.append(item)
                    await self.store.add_asset(self.scan_id, item)
                    await self.event_bus.emit(EventType.ASSET_DISCOVERED, fqdn=item.fqdn)
                elif isinstance(item, schemas.Endpoint):
                    key = (item.method.value, item.url)
                    if key in seen_endpoints:
                        continue
                    seen_endpoints.add(key)
                    self.ctx.endpoints.append(item)
                    await self.store.add_endpoint(self.scan_id, item)
                    await self.event_bus.emit(EventType.ENDPOINT_DISCOVERED, url=item.url)

        await self.event_bus.emit(EventType.PHASE_COMPLETED, phase="recon")
        logger.info(
            "recon complete: %d asset(s), %d endpoint(s), %d request(s) sent",
            len(self.ctx.assets),
            len(self.ctx.endpoints),
            self.ctx.http.requests_sent,
        )
        return len(self.ctx.assets), len(self.ctx.endpoints)

    # ------------------------------------------------------------ phase: scan
    async def run_scan(self) -> int:
        assert self.ctx is not None
        await self.event_bus.emit(EventType.PHASE_STARTED, phase="scan")
        scanners = get_scanners(self.config.modules)
        if not scanners:
            logger.info("scan: no scanner modules registered yet (Roadmap Phase 2+)")
            await self.event_bus.emit(EventType.PHASE_COMPLETED, phase="scan")
            return 0

        configured_rank = _AGGRESSIVENESS_RANK[self.config.aggressiveness]
        total = 0
        for scanner in scanners:
            if not scanner.applicable(self.ctx):
                continue
            if _AGGRESSIVENESS_RANK[scanner.min_aggressiveness] > configured_rank:
                logger.info(
                    "scan: skipping %s (requires %s aggressiveness)",
                    scanner.name,
                    scanner.min_aggressiveness.value,
                )
                continue
            logger.info("scan: running %s", scanner.name)
            await scanner.setup(self.ctx)
            try:
                async for finding in scanner.scan(self.ctx):
                    db_id = await self.store.add_finding(self.scan_id, finding)
                    self.ctx.findings.append(finding)
                    self.ctx.finding_ids[finding.id] = db_id
                    await self.event_bus.emit(
                        EventType.FINDING_RAISED,
                        vuln_type=finding.vuln_type,
                        severity=finding.severity.value,
                        url=finding.url,
                    )
                    total += 1
            finally:
                await scanner.teardown(self.ctx)

        await self.event_bus.emit(EventType.PHASE_COMPLETED, phase="scan")
        logger.info("scan complete: %d finding(s)", total)
        return total

    # --------------------------------------------------------- phase: exploit
    async def run_exploit(self) -> int:
        assert self.ctx is not None
        if self.config.no_exploit:
            logger.info("exploitation skipped (--no-exploit)")
            return 0
        await self.event_bus.emit(EventType.PHASE_STARTED, phase="exploit")

        confirmed = 0
        for finding in self.ctx.findings:
            modules = exploits_for(finding)
            if not modules:
                continue
            for module in modules:
                try:
                    result = await module.confirm(self.ctx, finding)
                except Exception:
                    logger.exception("exploit module %s crashed on %s", module.name, finding.id)
                    continue
                finding_db_id = self.ctx.finding_ids.get(finding.id)
                if finding_db_id is not None:
                    await self.store.add_exploitation(finding_db_id, result)
                if result.success:
                    confirmed += 1
                    finding.confidence = Confidence.CONFIRMED
                    if finding_db_id is not None:
                        await self.store.set_finding_confidence(
                            finding_db_id, Confidence.CONFIRMED.value
                        )
                    await self.event_bus.emit(
                        EventType.EXPLOIT_CONFIRMED,
                        vuln_type=finding.vuln_type,
                        url=finding.url,
                        technique=result.technique,
                    )
                    logger.info(
                        "[bold green]CONFIRMED[/] %s at %s (%s)",
                        finding.vuln_type,
                        finding.url,
                        result.technique,
                    )
                    break  # one successful confirmation per finding is enough

        await self.event_bus.emit(EventType.PHASE_COMPLETED, phase="exploit")
        logger.info("exploitation complete: %d finding(s) confirmed", confirmed)
        return confirmed

    # ---------------------------------------------------------- phase: report
    async def run_report(self, fmt: str, output: str) -> str:
        path = await generate_report(self.store, self.scan_id, fmt, output)
        logger.info("report written to %s", path)
        return path

    async def run_full(self) -> None:
        await self.run_recon()
        await self.run_scan()
        await self.run_exploit()

    # ------------------------------------------------------------- lifecycle
    async def teardown(self, status: str = "completed") -> None:
        if self.ctx is not None:
            await self.ctx.http.aclose()
            if self.ctx.callback is not None:
                await self.ctx.callback.stop()
        await self.store.set_scan_status(self.scan_id, status, completed=True)
        await self.event_bus.emit(EventType.SCAN_COMPLETED, scan_id=self.scan_id, status=status)
        await self.store.close()

    async def print_summary(self) -> None:
        counts = await self.store.severity_counts(self.scan_id)
        table = Table(title=f"Scan {self.scan_id} - {self.config.target}")
        table.add_column("Severity", style="bold")
        table.add_column("Count", justify="right")
        for severity in ("critical", "high", "medium", "low", "info"):
            table.add_row(severity.title(), str(counts.get(severity, 0)))
        if self.ctx is not None:
            confirmed = sum(
                1 for f in self.ctx.findings if f.confidence == Confidence.CONFIRMED
            )
            table.add_section()
            table.add_row("Assets", str(len(self.ctx.assets)))
            table.add_row("Endpoints", str(len(self.ctx.endpoints)))
            table.add_row("Confirmed findings", str(confirmed))
            table.add_row("Requests sent", str(self.ctx.http.requests_sent))
            table.add_row("Scope violations blocked", str(self.ctx.http.scope_violations))
        console.print(table)


__all__ = ["Orchestrator"]
