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
from hydra.core.browser import BrowserManager
from hydra.core.callback import LocalCallbackServer
from hydra.core.config import ScanConfig, Settings
from hydra.core.context import ScanContext
from hydra.core.event_bus import Event, EventBus, EventType
from hydra.core.http_client import HttpClient
from hydra.core.schemas import Aggressiveness, Confidence
from hydra.core.session import Session
from hydra.db.store import Store
from hydra.exploits.registry import exploits_for
from hydra.plugins import load_plugins
from hydra.recon.api_discovery import ApiDiscovery
from hydra.recon.base import BaseRecon
from hydra.recon.content_discovery import ContentDiscovery
from hydra.recon.crawler import Crawler
from hydra.recon.dns_enum import DnsEnum
from hydra.recon.js_analyzer import JsAnalyzer
from hydra.recon.port_scan import PortScan
from hydra.recon.registry import get_recon_plugins
from hydra.recon.subdomain_enum import SubdomainEnum
from hydra.recon.tech_fingerprint import TechFingerprint
from hydra.recon.waf_detect import WafDetect
from hydra.recon.wayback import Wayback
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
        self.store = Store(settings.db_url, encryption_key=settings.encryption_key)
        self.ctx: ScanContext | None = None

    async def setup(self) -> None:
        load_plugins(self.settings.plugins_dir)
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

        if self.config.use_browser and BrowserManager.is_available():
            browser = BrowserManager(
                self.scope,
                user_agent=None if self.config.user_agent == "random" else self.config.user_agent,
                screenshot_dir=f"{self.settings.data_dir}/screenshots",
                har_path=self.config.har_path,
            )
            try:
                await browser.start()
                self.ctx.browser = browser
            except Exception:
                logger.exception("browser engine failed to start; continuing without it")
        elif self.config.use_browser:
            logger.info("Playwright not installed ([browser] extra); browser scanners disabled")

        await self.store.create_scan(
            self.scan_id,
            self.config.target,
            self.config.scope.model_dump(mode="json"),
            self.config.model_dump(mode="json"),
        )
        await self.event_bus.emit(
            EventType.SCAN_STARTED, scan_id=self.scan_id, target=self.config.target
        )
        await self.store.log(  # operator audit trail (PRD §12.2)
            self.scan_id,
            "audit",
            "audit",
            f"scan started target={self.config.target} scope={self.config.scope.domains or self.config.scope.ip_ranges} "
            f"modules={self.config.modules} aggressiveness={self.config.aggressiveness.value} "
            f"exploit={not self.config.no_exploit} encryption={'on' if self.settings.encryption_key else 'off'}",
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

        # Order matters: crawl populates script endpoints before js-analysis reads them.
        modules: list[BaseRecon] = []
        if which is None or "fingerprint" in which:
            modules.append(TechFingerprint())
        if which is None or "crawl" in which:
            modules.append(Crawler())
        if which is None or "js" in which:
            modules.append(JsAnalyzer())
        if which is None or "content" in which:
            modules.append(ContentDiscovery())
        if which is None or "waf" in which:
            modules.append(WafDetect())
        if which is None or "api" in which:
            modules.append(ApiDiscovery())
        if which is None or "dns" in which:
            modules.append(DnsEnum())  # applicable() skips IP targets
        if which is not None and "subdomains" in which:
            modules.append(SubdomainEnum())
        if which is not None and "wayback" in which:
            modules.append(Wayback())
        if which is not None and "ports" in which:
            modules.append(PortScan())
        modules.extend(get_recon_plugins())  # recon plugins run alongside built-ins

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
            if finding.confidence == Confidence.CONFIRMED:
                continue  # execution-based scanners (DOM/stored XSS) already proved it
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
        branding = {"logo": self.config.branding_logo} if self.config.branding_logo else None
        path = await generate_report(
            self.store,
            self.scan_id,
            fmt,
            output,
            template=self.config.report_template,
            branding=branding,
            min_severity=self.config.min_severity,
        )
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
