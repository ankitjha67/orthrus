"""Phase sequencing and task dispatch (PRD §4.1).

The orchestrator wires up the per-scan infrastructure, then drives the four
phases: recon -> scan -> exploit -> report. Recon is functional; scan and
exploit iterate their registries (empty until later roadmap phases) so the
pipeline runs end-to-end today and grows without structural change.
"""

from __future__ import annotations

import asyncio
import contextlib
from time import perf_counter
from urllib.parse import urlsplit
from uuid import uuid4

from rich.table import Table
from rich.text import Text

from orthrus.core import schemas
from orthrus.core.auth import LoginResult, acquire_oauth2_token, perform_login
from orthrus.core.baseline import build_baseline
from orthrus.core.browser import BrowserManager
from orthrus.core.callback import CallbackClient, InteractshCallbackClient, LocalCallbackServer
from orthrus.core.config import ScanConfig, Settings
from orthrus.core.context import ScanContext
from orthrus.core.event_bus import Event, EventBus, EventType
from orthrus.core.http_client import HttpClient
from orthrus.core.metrics import ScannerMetric, top_scanners, totals
from orthrus.core.schemas import Aggressiveness, Confidence
from orthrus.core.session import Session
from orthrus.db.store import Store
from orthrus.exploits.registry import exploits_for
from orthrus.plugins import load_plugins
from orthrus.recon.api_discovery import ApiDiscovery
from orthrus.recon.base import BaseRecon
from orthrus.recon.browser_crawl import BrowserCrawl
from orthrus.recon.content_discovery import ContentDiscovery
from orthrus.recon.crawler import Crawler
from orthrus.recon.dns_enum import DnsEnum
from orthrus.recon.host_gathering import HostGathering
from orthrus.recon.ip_intel import IpIntelRecon
from orthrus.recon.js_analyzer import JsAnalyzer
from orthrus.recon.param_mining import ParameterMiner
from orthrus.recon.port_scan import PortScan
from orthrus.recon.registry import get_recon_plugins
from orthrus.recon.robots_sitemap import RobotsSitemap
from orthrus.recon.sourcemap_recovery import SourceMapRecovery
from orthrus.recon.spa_crawl import SpaCrawl
from orthrus.recon.subdomain_enum import SubdomainEnum
from orthrus.recon.tech_fingerprint import TechFingerprint
from orthrus.recon.waf_detect import WafDetect
from orthrus.recon.wayback import Wayback
from orthrus.recon.well_known import WellKnown
from orthrus.reporting.generator import generate_report
from orthrus.scanners.registry import get_scanners
from orthrus.utils.logger import console, get_logger
from orthrus.utils.scope import ScopeValidator
from orthrus.utils.theme import findings_table, make_progress, section, severity_style

logger = get_logger("orchestrator")

_AGGRESSIVENESS_RANK = {
    Aggressiveness.PASSIVE: 0,
    Aggressiveness.NORMAL: 1,
    Aggressiveness.AGGRESSIVE: 2,
}

# Pipeline phases in execution order. On --resume, any phase at or below the
# last checkpointed phase is skipped (its persisted output is rehydrated).
_PHASE_ORDER = ("recon", "scan", "exploit")
_PHASE_RANK = {name: i for i, name in enumerate(_PHASE_ORDER)}


class Orchestrator:
    def __init__(self, config: ScanConfig, settings: Settings, *, resume: bool = False) -> None:
        self.config = config
        self.settings = settings
        self.scan_id = config.scan_id or f"scan-{uuid4().hex[:8]}"
        self.resume = resume
        self._resume_phase: str | None = None  # last completed phase of a resumed scan
        self.event_bus = EventBus()
        self.scope = ScopeValidator(config.scope)
        self.store = Store(settings.db_url, encryption_key=settings.encryption_key)
        self.ctx: ScanContext | None = None
        self.scanner_metrics: list[ScannerMetric] = []

    def _phase_complete(self, phase: str) -> bool:
        """True when a resumed scan already finished ``phase`` in a prior run."""
        if self._resume_phase is None:
            return False
        return _PHASE_RANK.get(self._resume_phase, -1) >= _PHASE_RANK[phase]

    async def setup(self) -> None:
        load_plugins(self.settings.plugins_dir)
        await self.store.init()

        resume_row = None
        if self.resume:
            resume_row = await self.store.get_scan(self.scan_id)
            if resume_row is None:
                raise ValueError(f"cannot resume: no scan '{self.scan_id}' in the database")
            self._resume_phase = resume_row.phase
        # Avoid a primary-key collision if the operator reuses an existing --scan-id
        # (previously this aborted the scan silently). Uniquify and warn instead.
        elif await self.store.get_scan(self.scan_id) is not None:
            new_id = f"{self.scan_id}-{uuid4().hex[:6]}"
            logger.warning("scan id '%s' already exists; using '%s'", self.scan_id, new_id)
            self.scan_id = new_id

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
            self.ctx.callback = await self._build_callback()
            from orthrus.core.second_order import SecondOrderRegistry

            self.ctx.second_order = SecondOrderRegistry(callback=self.ctx.callback)

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
                logger.info(
                    "browser engine ready - XSS/DOM confirmation will execute payloads in a "
                    "real headless browser"
                )
            except Exception:
                logger.exception("browser engine failed to start; continuing without it")
        elif self.config.use_browser:
            logger.info(
                "Playwright not installed ([browser] extra); XSS confirmation falls back to "
                "reflection heuristics - install with `pip install orthrus-framework[browser] "
                "&& playwright install chromium` for execution-proven XSS"
            )

        if resume_row is not None:
            # Resuming: keep the existing scan row, flip it back to running, and
            # reload the persisted inventory so skipped phases have their state.
            await self.store.set_scan_status(self.scan_id, "running")
            await self._rehydrate_state()
            await self.event_bus.emit(
                EventType.SCAN_STARTED, scan_id=self.scan_id, target=self.config.target
            )
            await self.store.log(
                self.scan_id,
                "audit",
                "audit",
                f"scan resumed from phase={self._resume_phase or 'start'} "
                f"target={self.config.target}",
            )
            logger.info(
                "scan [bold]%s[/] resumed (last completed phase: %s)",
                self.scan_id,
                self._resume_phase or "none",
            )
        else:
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

        # Authenticate before recon so the entire scan replays the session.
        if self.config.oauth2_token_url or (self.config.login_url and self.config.login_data):
            await self._authenticate(http, session)

    async def _rehydrate_state(self) -> None:
        """Reload a resumed scan's persisted assets/endpoints/findings into ctx."""
        assert self.ctx is not None
        self.ctx.assets = await self.store.get_assets(self.scan_id)
        self.ctx.endpoints = await self.store.get_endpoints(self.scan_id)
        for db_id, finding in await self.store.get_findings_with_ids(self.scan_id):
            self.ctx.findings.append(finding)
            self.ctx.finding_ids[finding.id] = db_id
        logger.info(
            "resumed state: %d asset(s), %d endpoint(s), %d finding(s)",
            len(self.ctx.assets),
            len(self.ctx.endpoints),
            len(self.ctx.findings),
        )

    async def _build_callback(self) -> CallbackClient:
        """Select and start the OOB collaborator (PRD §7.2).

        Prefers a real Interactsh collaborator when ``--interactsh`` is set so
        internet-reachable targets can call back; on registration failure (no
        egress, server down) it falls back to the same-host local listener. The
        ``--callback`` host, if given, is advertised by the local listener so a
        routable address is injected into payloads.
        """
        if self.config.interactsh or self.config.interactsh_server:
            client = InteractshCallbackClient(
                server=self.config.interactsh_server,
                token=self.config.interactsh_token,
            )
            try:
                await client.start()
                logger.info("OOB collaborator: Interactsh (%s)", client.base_url)
                return client
            except Exception as exc:  # network/egress/server failure -> fall back
                logger.warning(
                    "Interactsh unavailable (%s); using local callback listener", exc
                )
        advertise = None
        if self.config.callback:
            advertise = urlsplit(self.config.callback).hostname or self.config.callback
        server = LocalCallbackServer(advertise_host=advertise)
        await server.start()
        return server

    async def _run_login(self, http: HttpClient, session: Session) -> LoginResult:
        """Perform the configured login flow once (OAuth2, or form/JSON).

        Factored out so the same flow drives both the initial pre-recon login and
        the silent mid-scan re-authentication hook. Returns the outcome; never
        logs credentials or token values.
        """
        if self.config.oauth2_token_url:
            if not self.scope.is_allowed(self.config.oauth2_token_url):
                logger.warning("OAuth2 token URL is out of scope; continuing unauthenticated")
                return LoginResult(ok=False, reason="token-url-out-of-scope")
            return await acquire_oauth2_token(
                http,
                session,
                token_url=self.config.oauth2_token_url,
                grant_type=self.config.oauth2_grant,
                client_id=self.config.oauth2_client_id,
                client_secret=self.config.oauth2_client_secret,
                username=self.config.oauth2_username,
                password=self.config.oauth2_password,
                scope=self.config.oauth2_scope,
                refresh_token=self.config.oauth2_refresh_token,
                token_field=self.config.oauth2_token_field,
            )
        assert self.config.login_url is not None and self.config.login_data is not None
        if not self.scope.is_allowed(self.config.login_url):
            logger.warning("login URL is out of scope; continuing unauthenticated")
            return LoginResult(ok=False, reason="login-url-out-of-scope")
        return await perform_login(
            http,
            session,
            login_url=self.config.login_url,
            login_data=self.config.login_data,
            token_field=self.config.login_token_field,
            success_marker=self.config.login_check,
            csrf_url=self.config.csrf_url,
            csrf_field=self.config.csrf_field,
            csrf_header=self.config.csrf_header,
            totp_secret=self.config.totp_secret,
            totp_field=self.config.totp_field,
        )

    async def _authenticate(self, http: HttpClient, session: Session) -> None:
        """Establish the session before recon so the whole scan runs authenticated (§3.4).

        Dispatches to OAuth2 token acquisition or a form/JSON login (with optional
        rotating-CSRF capture and TOTP MFA). When ``--reauth`` is enabled, installs
        a hook the HTTP client calls to silently re-establish a session that drops
        mid-scan.
        """
        result = await self._run_login(http, session)
        # Never log the credentials or the token value - only the outcome.
        status_msg = f"status={result.status} token={'set' if result.token_set else 'none'}"
        if result.ok:
            logger.info("authentication succeeded (%s)", status_msg)
            await self.store.log(self.scan_id, "audit", "auth", f"login ok {status_msg}")
        else:
            logger.warning(
                "authentication failed (%s reason=%s); continuing unauthenticated",
                status_msg,
                result.reason or "no-success-signal",
            )
            await self.store.log(self.scan_id, "warning", "auth", f"login failed {status_msg}")

        # Silent session refresh: install a reauth hook the HTTP client invokes
        # when a later response looks unauthenticated (PRD §3.4).
        if self.config.reauth and result.ok:
            if self.config.reauth_markers:
                http.reauth_markers = tuple(self.config.reauth_markers)

            async def _reauth() -> bool:
                refreshed = await self._run_login(http, session)
                kind = "ok" if refreshed.ok else "failed"
                await self.store.log(
                    self.scan_id,
                    "audit" if refreshed.ok else "warning",
                    "auth",
                    f"session re-auth {kind} status={refreshed.status}",
                )
                if refreshed.ok:
                    logger.info("session re-authenticated mid-scan")
                else:
                    logger.warning("session re-authentication failed mid-scan")
                return refreshed.ok

            session.reauth = _reauth

    def _wire_events(self) -> None:
        async def on_scope_violation(event: Event) -> None:
            await self.store.log(
                self.scan_id,
                "warning",
                "scope",
                f"blocked {event.data.get('url')}: {event.data.get('reason')}",
            )

        self.event_bus.subscribe(EventType.SCOPE_VIOLATION, on_scope_violation)

    def _section(self, title: str) -> None:
        """Print a phase divider unless the run is --quiet (CI: results only)."""
        if not self.config.quiet:
            section(console, title)

    def _use_progress(self) -> bool:
        """Show a live progress bar only on an interactive TTY (never in --quiet
        or when output is piped/CI, where it would render as broken fragments)."""
        return console.is_terminal and not self.config.quiet

    # ----------------------------------------------------------- phase: recon
    async def run_recon(self, which: set[str] | None = None) -> tuple[int, int]:
        assert self.ctx is not None
        self._section("PHASE · RECON")
        if self._phase_complete("recon"):
            # Resuming past recon: assets/endpoints were rehydrated in setup().
            # Still rebuild the soft-404 baseline (scan-time calibration, not
            # persisted) so downstream scanners keep their FP suppression.
            if self.ctx.baseline is None:
                self.ctx.baseline = await build_baseline(self.ctx)
            logger.info(
                "recon already complete (resumed): reusing %d asset(s), %d endpoint(s)",
                len(self.ctx.assets),
                len(self.ctx.endpoints),
            )
            return len(self.ctx.assets), len(self.ctx.endpoints)
        await self.event_bus.emit(EventType.PHASE_STARTED, phase="recon")

        # Calibrate a soft-404/catch-all profile first so recon (content
        # discovery) and later template scans can suppress false positives that
        # merely echo the target's catch-all response.
        if self.ctx.baseline is None:
            self.ctx.baseline = await build_baseline(self.ctx)

        # Order matters: crawl populates script endpoints before js-analysis reads them.
        modules: list[BaseRecon] = []
        if which is None or "fingerprint" in which:
            modules.append(TechFingerprint())
        if which is None or "crawl" in which:
            modules.append(Crawler())
        if which is None or "js" in which:
            modules.append(JsAnalyzer())
        if which is None or "sourcemap" in which:
            modules.append(SourceMapRecovery())
        if which is None or "content" in which:
            modules.append(ContentDiscovery())
        if which is None or "waf" in which:
            modules.append(WafDetect())
        if which is None or "api" in which:
            modules.append(ApiDiscovery())
        # robots.txt / sitemap.xml + /.well-known/ - cheap, high-signal endpoint
        # discovery from the target's own advertised surface.
        if which is None or "robots" in which:
            modules.append(RobotsSitemap())
        if which is None or "well-known" in which:
            modules.append(WellKnown())
        # Dynamic (browser) crawl: navigates the SPA so its real XHR/fetch API
        # calls are captured as endpoints. applicable() gates on browser presence.
        if which is None or "browser" in which:
            modules.append(BrowserCrawl())
        # SPA route discovery: enumerate client-side routes and drive each so
        # route-specific lazy XHR/fetch fire. Runs after browser-crawl so it only
        # emits the deeper, route-gated surface. applicable() gates on browser.
        if which is None or "spa" in which:
            modules.append(SpaCrawl())
        if which is None or "dns" in which:
            modules.append(DnsEnum())  # applicable() skips IP targets
        if which is None or "ip-intel" in which:
            modules.append(IpIntelRecon())  # PTR/ASN/geo/cloud for resolved IP(s)
        if which is not None and "subdomains" in which:
            modules.append(SubdomainEnum())
        # Opt-in (third-party OSINT + a /24 reverse-DNS sweep): only on request.
        if which is not None and "host-gather" in which:
            modules.append(HostGathering())
        if which is not None and "wayback" in which:
            modules.append(Wayback())
        if which is not None and "ports" in which:
            modules.append(PortScan())
        # Parameter mining runs after the endpoint-discovering modules so it can
        # probe everything they found for undeclared parameters.
        if which is None or "params" in which:
            modules.append(ParameterMiner())
        modules.extend(get_recon_plugins())  # recon plugins run alongside built-ins

        seen_endpoints: set[tuple[str, str]] = set()
        progress = make_progress(console) if self._use_progress() else None
        with progress or contextlib.nullcontext():
            task = progress.add_task("recon", total=len(modules)) if progress else None
            for module in modules:
                if progress is not None:
                    progress.update(task, description=f"recon · {module.name}")
                if module.applicable(self.ctx):
                    if progress is None:
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
                if progress is not None:
                    progress.advance(task)

        await self.event_bus.emit(EventType.PHASE_COMPLETED, phase="recon")
        await self.store.set_scan_phase(self.scan_id, "recon")  # checkpoint for --resume
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
        self._section("PHASE · SCAN")
        if self._phase_complete("scan"):
            logger.info(
                "scan already complete (resumed): reusing %d finding(s)",
                len(self.ctx.findings),
            )
            return len(self.ctx.findings)
        await self.event_bus.emit(EventType.PHASE_STARTED, phase="scan")
        scanners = get_scanners(self.config.modules)
        if not scanners:
            logger.info("scan: no scanner modules registered yet (Roadmap Phase 2+)")
            await self.event_bus.emit(EventType.PHASE_COMPLETED, phase="scan")
            await self.store.set_scan_phase(self.scan_id, "scan")  # checkpoint for --resume
            return 0

        configured_rank = _AGGRESSIVENESS_RANK[self.config.aggressiveness]
        total = 0
        progress = make_progress(console) if self._use_progress() else None
        with progress or contextlib.nullcontext():
            task = progress.add_task("scan", total=len(scanners)) if progress else None
            for scanner in scanners:
                if progress is not None:
                    progress.update(task, description=f"scan · {scanner.name}")
                try:
                    if not scanner.applicable(self.ctx):
                        continue
                    if _AGGRESSIVENESS_RANK[scanner.min_aggressiveness] > configured_rank:
                        if progress is None:
                            logger.info(
                                "scan: skipping %s (requires %s aggressiveness)",
                                scanner.name,
                                scanner.min_aggressiveness.value,
                            )
                        continue
                    if progress is None:
                        logger.info("scan: running %s", scanner.name)
                    metric = ScannerMetric(name=scanner.name)
                    start = perf_counter()
                    start_requests = self.ctx.http.requests_sent
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
                            metric.findings += 1
                            total += 1
                    except Exception as exc:
                        # Isolate scanner failures: one crashing module must not abort
                        # the whole phase. Record it on the metric and keep going.
                        metric.error = type(exc).__name__
                        logger.exception(
                            "scanner %s crashed; continuing with the rest", scanner.name
                        )
                    finally:
                        await scanner.teardown(self.ctx)
                        metric.duration_s = perf_counter() - start
                        metric.requests = self.ctx.http.requests_sent - start_requests
                        self.scanner_metrics.append(metric)
                        await self.store.log(
                            self.scan_id, "info", "metrics", metric.summary_line()
                        )
                finally:
                    if progress is not None:
                        progress.advance(task)

        await self.event_bus.emit(EventType.PHASE_COMPLETED, phase="scan")
        await self.store.set_scan_phase(self.scan_id, "scan")  # checkpoint for --resume
        await self._report_block_reliability()
        logger.info("scan complete: %d finding(s)", total)
        return total

    async def _report_block_reliability(self) -> None:
        """Warn when a WAF blocked enough of the scan that findings are incomplete."""
        assert self.ctx is not None
        monitor = getattr(self.ctx.http, "block_monitor", None)
        if monitor is None:
            return
        summary = monitor.summary()
        if monitor.degraded():
            vendors = ", ".join(summary["vendors"]) or "a WAF/anti-automation layer"
            logger.warning(
                "scan reliability degraded: %.0f%% of requests (%d/%d) were blocked by %s "
                "- some vulnerabilities may have been masked",
                summary["block_rate"] * 100,
                summary["blocked"],
                summary["total"],
                vendors,
            )
            await self.event_bus.emit("waf.degraded", **summary)
        elif summary["blocked"]:
            logger.info(
                "WAF interference: %d/%d request(s) blocked%s",
                summary["blocked"],
                summary["total"],
                f" ({', '.join(summary['vendors'])})" if summary["vendors"] else "",
            )

    # --------------------------------------------------------- phase: exploit
    async def run_exploit(self) -> int:
        assert self.ctx is not None
        self._section("PHASE · EXPLOIT")
        if self.config.no_exploit:
            logger.info("exploitation skipped (--no-exploit)")
            return 0
        if self._phase_complete("exploit"):
            confirmed = sum(
                1 for f in self.ctx.findings if f.confidence == Confidence.CONFIRMED
            )
            logger.info(
                "exploitation already complete (resumed): %d finding(s) confirmed", confirmed
            )
            return confirmed
        await self.event_bus.emit(EventType.PHASE_STARTED, phase="exploit")

        # Second-order: plant canaries in writable forms and harvest any that detonated
        # out-of-band or reflected on another page - stored/blind bugs a request-oriented
        # confirmer can't see (e.g. a payload that fires in a staff console).
        so_confirmed = await self._run_second_order()

        # Confirmed findings (DOM/stored XSS proved by execution) and findings with
        # no matching confirmer are skipped; pre-filtering keeps the progress total honest.
        candidates = [
            (finding, modules)
            for finding in self.ctx.findings
            if finding.confidence != Confidence.CONFIRMED and (modules := exploits_for(finding))
        ]
        progress = make_progress(console) if (self._use_progress() and candidates) else None

        # Confirmation is network-bound: each module replays probes against the
        # target, so over WAN latency the serial sum of round-trips dominated the
        # phase. Run candidates concurrently under a bounded semaphore (sized to
        # the scan's concurrency knob) so the latencies overlap. Each finding's
        # own modules still run serially with break-on-first-success, and every
        # store write opens its own AsyncSession, so concurrent persistence is safe.
        limit = max(1, min(self.config.concurrency, len(candidates))) if candidates else 1
        sem = asyncio.Semaphore(limit)

        with progress or contextlib.nullcontext():
            task = progress.add_task("exploit", total=len(candidates)) if progress else None

            async def _confirm_finding(finding, modules) -> int:
                async with sem:
                    if progress is not None:
                        progress.update(task, description=f"exploit · {finding.vuln_type}")
                    try:
                        for module in modules:
                            try:
                                result = await module.confirm(self.ctx, finding)
                            except Exception:
                                logger.exception(
                                    "exploit module %s crashed on %s", module.name, finding.id
                                )
                                continue
                            finding_db_id = self.ctx.finding_ids.get(finding.id)
                            if finding_db_id is not None:
                                await self.store.add_exploitation(finding_db_id, result)
                            if result.success:
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
                                return 1  # one successful confirmation per finding is enough
                        return 0
                    finally:
                        if progress is not None:
                            progress.advance(task)

            results = await asyncio.gather(
                *(_confirm_finding(finding, modules) for finding, modules in candidates)
            )
        confirmed = sum(results) + so_confirmed

        await self.event_bus.emit(EventType.PHASE_COMPLETED, phase="exploit")
        await self.store.set_scan_phase(self.scan_id, "exploit")  # checkpoint for --resume
        logger.info("exploitation complete: %d finding(s) confirmed", confirmed)
        return confirmed

    async def _run_second_order(self) -> int:
        """Plant second-order canaries and harvest detonations. Best-effort, isolated."""
        registry = self.ctx.second_order if self.ctx is not None else None
        if registry is None:
            return 0
        try:
            if await registry.plant_writable_forms(self.ctx) == 0:
                return 0
            findings = await registry.harvest(self.ctx)
        except Exception:  # isolate: a second-order failure never aborts the phase
            logger.exception("second-order phase failed; continuing")
            return 0
        for finding in findings:
            db_id = await self.store.add_finding(self.scan_id, finding)
            self.ctx.findings.append(finding)
            self.ctx.finding_ids[finding.id] = db_id
        if findings:
            logger.info("second-order: %d stored/blind finding(s) confirmed", len(findings))
        return len(findings)

    # ---------------------------------------------------------- phase: report
    async def run_integrations(self) -> int:
        """Run opt-in external-tool adapters (--tools) and store their findings."""
        from orthrus.integrations import get_tools

        tools = get_tools(self.config.tools) if self.config.tools else []
        if not tools:
            return 0
        await self.event_bus.emit(EventType.PHASE_STARTED, phase="tools")
        total = 0
        for tool in tools:
            try:
                findings = await tool.run(self.ctx)
            except Exception:  # isolate adapter failures, like scanners
                logger.exception("tool %s crashed; continuing", tool.name)
                continue
            for finding in findings:
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
            logger.info("tool %s: %d finding(s)", tool.name, len(findings))
        await self.event_bus.emit(EventType.PHASE_COMPLETED, phase="tools")
        return total

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
        await self.run_integrations()

    # ------------------------------------------------------------- lifecycle
    async def teardown(self, status: str = "completed") -> None:
        if self.ctx is not None:
            if self.ctx.browser is not None:
                await self.ctx.browser.stop()
            await self.ctx.http.aclose()
            if self.ctx.callback is not None:
                await self.ctx.callback.stop()
        await self.store.set_scan_status(self.scan_id, status, completed=True)
        await self.event_bus.emit(EventType.SCAN_COMPLETED, scan_id=self.scan_id, status=status)
        await self.store.close()

    async def print_summary(self) -> None:
        counts = await self.store.severity_counts(self.scan_id)
        section(console, "RESULTS")
        table = Table(title=f"[orthrus.accent]Scan {self.scan_id}[/] · {self.config.target}")
        table.add_column("Severity", style="bold")
        table.add_column("Count", justify="right")
        for severity in ("critical", "high", "medium", "low", "info"):
            n = counts.get(severity, 0)
            style = severity_style(severity)
            # Colour the severity by risk; grey out empty buckets so the eye
            # lands on what actually fired.
            table.add_row(
                Text(severity.title(), style=style),
                Text(str(n), style=style if n else "dim"),
            )
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
        # The per-finding triage list: only worth showing when something fired.
        if self.ctx is not None and self.ctx.findings:
            console.print(findings_table(self.ctx.findings))
        self._print_analysis()
        self._print_scanner_metrics()

    def _print_analysis(self) -> None:
        """Surface the high-signal analysis (dedup count + attack paths) inline.

        Computes triage clustering and attack-path correlation over the in-memory
        findings, so every scan ends with "here are the paths an attacker would
        walk" - not just a flat list - without a separate command or the report.
        """
        if self.ctx is None or not self.ctx.findings:
            return
        from orthrus.chains import correlate_findings
        from orthrus.triage import triage_findings

        triage = triage_findings(self.ctx.findings)
        if triage.collapsed:
            console.print(
                f"\n[orthrus.muted]Triaged {triage.total} finding(s) → "
                f"{triage.unique} distinct issue(s) ({triage.collapsed} folded).[/]"
            )

        chains = correlate_findings(self.ctx.findings)
        if not chains:
            return
        crit = sum(1 for c in chains if c.severity == "critical")
        section(console, "ATTACK PATHS")
        console.print(
            f"[orthrus.muted]{len(chains)} attacker-walkable path(s) "
            f"({crit} critical) - prioritise breaking these:[/]\n"
        )
        for c in chains:
            style = severity_style(c.severity)
            console.print(
                f"[{style}]\\[{c.severity.upper()}][/] [orthrus.accent]{c.name}[/] "
                f"[orthrus.muted]@ {c.host}[/]"
            )
            console.print(
                "   [orthrus.muted]" + "  →  ".join(s.vuln_type for s in c.steps) + "[/]"
            )

    def _print_scanner_metrics(self) -> None:
        if not self.scanner_metrics:
            return
        table = Table(title="Per-scanner metrics")
        table.add_column("Scanner", style="bold")
        table.add_column("Findings", justify="right")
        table.add_column("Requests", justify="right")
        table.add_column("Time (s)", justify="right")
        table.add_column("Status")
        for m in top_scanners(self.scanner_metrics):
            table.add_row(
                m.name,
                str(m.findings),
                str(m.requests),
                f"{m.duration_s:.2f}",
                "[red]crashed[/]" if m.error else "ok",
            )
        agg = totals(self.scanner_metrics)
        table.add_section()
        table.add_row(
            f"total ({len(self.scanner_metrics)} ran)",
            str(agg.findings),
            str(agg.requests),
            f"{agg.duration_s:.2f}",
            f"[red]{agg.error}[/]" if agg.error else "ok",
        )
        console.print(table)


__all__ = ["Orchestrator"]
