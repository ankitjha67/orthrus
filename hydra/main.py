"""HYDRA command-line interface (PRD §10).

Authorized testing only. Scope is resolved and printed at the start of every
run so the operator can confirm the engagement boundary before any request goes
out. ``--scope auto`` derives a minimal scope from the target; real engagements
should pass an explicit scope.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import re
import sys
from urllib.parse import urlsplit

import click

from hydra import __version__
from hydra.core.config import ScanConfig, ScopeConfig, get_settings
from hydra.core.schemas import Aggressiveness
from hydra.db.store import Store
from hydra.reporting.generator import generate_report
from hydra.utils.logger import configure_logging, console, get_logger
from hydra.utils.theme import render_banner, scope_panel, section, status_style

logger = get_logger("cli")


def _as_ip_range(token: str) -> str | None:
    """Return a CIDR string if the token is a CIDR or a bare IP, else None."""
    if "/" in token:
        try:
            ipaddress.ip_network(token, strict=False)
            return token
        except ValueError:
            return None
    try:
        ip = ipaddress.ip_address(token)
        return f"{token}/{ip.max_prefixlen}"
    except ValueError:
        return None


def build_scope(
    scope_str: str | None,
    target: str,
    exclude_paths: str | None,
    *,
    block_third_party: bool = True,
) -> ScopeConfig:
    if not scope_str or scope_str == "auto":
        scope = ScopeConfig.auto_from_target(target)
    else:
        domains: list[str] = []
        ip_ranges: list[str] = []
        for raw in scope_str.split(","):
            token = raw.strip()
            if not token:
                continue
            ip_range = _as_ip_range(token)
            if ip_range:
                ip_ranges.append(ip_range)
            else:
                domains.append(token)
        scope = ScopeConfig(domains=domains, ip_ranges=ip_ranges)

    if exclude_paths:
        scope.exclude_paths = [p.strip() for p in exclude_paths.split(",") if p.strip()]
    scope.block_third_party = block_third_party

    # Always authorize the target's explicit port so custom-port targets work.
    target_port = urlsplit(target if "://" in target else f"//{target}").port
    if target_port and scope.ports and target_port not in scope.ports:
        scope.ports.append(target_port)
    return scope


# Internal PRD section refs (e.g. "(PRD §6.2)") must never leak into public
# output, so they are stripped from any description we surface.
_PRD_REF = re.compile(r"\s*\(PRD[^)]*\)")


def _first_doc_line(obj: object) -> str:
    """A one-line summary for ``obj``: its docstring, else its module's.

    Scanner/exploit classes document themselves at module level, so fall back to
    the module docstring when the class has none. Any PRD reference is stripped.
    """
    doc = (getattr(obj, "__doc__", None) or "").strip()
    if not doc and isinstance(obj, type):
        module = sys.modules.get(obj.__module__)
        doc = (getattr(module, "__doc__", None) or "").strip()
    line = next((s.strip() for s in doc.splitlines() if s.strip()), "")
    return _PRD_REF.sub("", line).strip()


# Aggressiveness tier -> theme style for the `modules` listing (read intrusiveness
# at a glance: passive=safe/dim, aggressive=loud/yellow).
_AGG_STYLE = {"passive": "hydra.muted", "normal": "default", "aggressive": "bold yellow"}


def _parse_headers(headers_json: str | None) -> dict[str, str]:
    if not headers_json:
        return {}
    try:
        data = json.loads(headers_json)
    except json.JSONDecodeError as exc:
        raise click.BadParameter(f"--headers must be valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise click.BadParameter("--headers JSON must be an object of header:value pairs")
    return {str(k): str(v) for k, v in data.items()}


def _log_scope(scope: ScopeConfig) -> None:
    # The engagement boundary is load-bearing, so render it as a prominent
    # bordered panel the operator can confirm before any request goes out.
    console.print(
        scope_panel(
            domains=scope.domains,
            ip_ranges=scope.ip_ranges,
            ports=scope.ports,
            exclude=scope.exclude_paths,
        )
    )


# --fail-on severity gating (CI pipelines). Mirrors the report-time severity
# ordering in hydra.reporting.generator so the threshold means the same thing
# everywhere. Process exits with this code when the gate trips, distinct from
# Click's usage-error code (2) so a pipeline can tell "vulns found" from
# "bad invocation".
_FAIL_ON_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
FAIL_ON_EXIT_CODE = 3


def _gate_breached(counts: dict[str, int], threshold: str) -> bool:
    """True if any severity bucket at or above ``threshold`` has a finding."""
    floor = _FAIL_ON_ORDER.get(threshold.lower(), 0)
    return any(
        n > 0 and _FAIL_ON_ORDER.get(sev, 0) >= floor for sev, n in counts.items()
    )


def _apply_fail_on(counts: dict[str, int], fail_on: str | None) -> None:
    """Exit non-zero when the severity gate is breached (no-op if disabled)."""
    if not fail_on:
        return
    if _gate_breached(counts, fail_on):
        logger.error(
            "fail-on gate: findings at or above '%s' severity present; exiting %d",
            fail_on.lower(),
            FAIL_ON_EXIT_CODE,
        )
        raise SystemExit(FAIL_ON_EXIT_CODE)


@click.group()
@click.version_option(__version__, prog_name="hydra")
@click.option(
    "--no-banner",
    is_flag=True,
    envvar="HYDRA_NO_BANNER",
    help="Suppress the startup banner (also via HYDRA_NO_BANNER=1).",
)
def cli(no_banner: bool) -> None:
    """HYDRA - automated vulnerability discovery & exploitation confirmation.

    For authorized security testing only.
    """
    if not no_banner:
        render_banner(console, __version__)


@cli.command()
@click.option("--target", "-t", default=None, help="Target URL (required unless --resume).")
@click.option("--scope", "scope_str", default="auto", help="Scope: wildcard domains / CIDR ranges.")
@click.option("--modules", default="all", help="Comma-separated scanner modules.")
@click.option("--aggressive", is_flag=True, help="Enable aggressive scanning.")
@click.option("--rate-limit", default=50.0, type=float, help="Max requests/sec per domain.")
@click.option("--crawl-depth", default=10, type=int, help="Maximum crawl depth.")
@click.option("--max-pages", default=5000, type=int, help="Maximum pages to crawl.")
@click.option("--timeout", default=30.0, type=float, help="HTTP request timeout (s).")
@click.option("--proxy", default=None, help="HTTP/SOCKS5 proxy URL.")
@click.option("--auth-cookie", default=None, help="Pre-authenticated session cookie string.")
@click.option("--auth-script", default=None, help="Playwright login script path (deferred).")
@click.option("--login-url", default=None, help="URL to POST credentials to before scanning.")
@click.option(
    "--login-data",
    default=None,
    help="Login body: 'user=admin&password=admin' or a JSON object.",
)
@click.option(
    "--login-token-field",
    default=None,
    help="Dotted path into a JSON login response to use as the bearer token.",
)
@click.option("--login-check", default=None, help="Substring proving the session is authenticated.")
@click.option(
    "--import",
    "import_spec",
    default=None,
    help="Import an OpenAPI/Swagger/GraphQL/HAR/Postman spec (file path or in-scope URL).",
)
@click.option(
    "--templates",
    default=None,
    help="Run declarative templates: 'builtin' for the bundled set, or a file/directory path.",
)
@click.option("--user-agent", default="random", help="User-Agent string or 'random'.")
@click.option("--callback", default=None, help="Callback server URL for OOB detection.")
@click.option("--no-exploit", is_flag=True, help="Skip exploitation confirmation phase.")
@click.option("--browser/--no-browser", default=True, help="Use headless browser (DOM/stored XSS).")
@click.option("--exclude-paths", default=None, help="Comma-separated regex paths to exclude.")
@click.option("--headers", default=None, help="Extra headers as JSON object.")
@click.option("--threads", default=10, type=int, help="Concurrent scanner threads.")
@click.option("--distributed", is_flag=True, help="Distribute targets across Celery workers.")
@click.option("--workers", default=4, type=int, help="Worker count (distributed partitioning).")
@click.option("--redis", "redis_url", default=None, help="Redis broker URL (distributed mode).")
@click.option("--scan-id", default=None, help="Custom scan identifier.")
@click.option(
    "--resume",
    is_flag=True,
    help="Resume an interrupted scan by --scan-id, reusing its stored config/scope "
    "and skipping phases already completed. Report options are taken from the CLI.",
)
@click.option("--output", "-o", default="hydra_report", help="Report output path.")
@click.option(
    "--format",
    "report_format",
    default="json",
    type=click.Choice(["json", "html", "pdf", "csv", "sarif"]),
    help="Report format.",
)
@click.option("--template", default="technical", help="Report template: executive/technical/compliance.")
@click.option("--min-severity", "min_severity", default=None, help="Only report findings >= this severity.")
@click.option("--logo", default=None, help="Logo image embedded in HTML/PDF reports.")
@click.option("--har", default=None, help="Record a browser HAR to this path (evidence).")
@click.option(
    "--fail-on",
    "fail_on",
    default=None,
    type=click.Choice(["critical", "high", "medium", "low", "info"]),
    help=f"Exit {FAIL_ON_EXIT_CODE} if any finding at or above this severity is found "
    "(CI gating). Applies to single-target scans.",
)
@click.option(
    "--quiet",
    "-q",
    is_flag=True,
    help="Suppress phase chrome and per-module chatter; show only the banner, scope "
    "and final results (pairs with --fail-on for CI).",
)
@click.option("--verbose", "-v", default="info", help="Log level: debug/info/warning/error.")
def scan(
    target: str | None,
    scope_str: str,
    modules: str,
    aggressive: bool,
    rate_limit: float,
    crawl_depth: int,
    max_pages: int,
    timeout: float,
    proxy: str | None,
    auth_cookie: str | None,
    auth_script: str | None,
    login_url: str | None,
    login_data: str | None,
    login_token_field: str | None,
    login_check: str | None,
    import_spec: str | None,
    templates: str | None,
    user_agent: str,
    callback: str | None,
    no_exploit: bool,
    browser: bool,
    exclude_paths: str | None,
    headers: str | None,
    threads: int,
    distributed: bool,
    workers: int,
    redis_url: str | None,
    scan_id: str | None,
    resume: bool,
    output: str,
    report_format: str,
    template: str,
    min_severity: str | None,
    logo: str | None,
    har: str | None,
    fail_on: str | None,
    quiet: bool,
    verbose: str,
) -> None:
    """Run the full pipeline: recon -> scan -> exploit -> report."""
    # --quiet silences per-module info chatter (warnings/errors still surface, so
    # scope blocks, auth failures and the --fail-on gate are never hidden).
    configure_logging("warning" if quiet else verbose)

    # Resume picks up an interrupted scan from its last checkpoint. The original
    # target/scope/config come from the DB, so only --scan-id is required here.
    if resume:
        if not scan_id:
            raise click.UsageError("--resume requires --scan-id")
        report_overrides = {
            "output": output,
            "report_format": report_format,
            "report_template": template,
            "min_severity": min_severity,
            "branding_logo": logo,
        }
        counts = asyncio.run(_resume_scan(scan_id, report_overrides))
        _apply_fail_on(counts, fail_on)
        return

    if not target:
        raise click.UsageError("--target is required (or use --resume with --scan-id)")

    module_list = [m.strip() for m in modules.split(",") if m.strip()]
    aggressiveness = Aggressiveness.AGGRESSIVE if aggressive else Aggressiveness.NORMAL

    if distributed:
        _run_distributed(
            target, scope_str, exclude_paths, module_list, aggressiveness,
            crawl_depth, max_pages, timeout, no_exploit, browser, report_format,
            workers, redis_url,
        )
        return

    scope = build_scope(scope_str, target, exclude_paths)
    config = ScanConfig(
        scan_id=scan_id,
        target=target,
        scope=scope,
        modules=module_list,
        aggressiveness=aggressiveness,
        crawl_depth=crawl_depth,
        max_pages=max_pages,
        timeout=timeout,
        concurrency=threads,
        proxy=proxy,
        user_agent=user_agent,
        extra_headers=_parse_headers(headers),
        auth_cookie=auth_cookie,
        auth_script=auth_script,
        login_url=login_url,
        login_data=login_data,
        login_token_field=login_token_field,
        login_check=login_check,
        import_spec=import_spec,
        templates=templates,
        callback=callback,
        no_exploit=no_exploit,
        use_browser=browser,
        har_path=har,
        output=output,
        report_format=report_format,
        report_template=template,
        min_severity=min_severity,
        branding_logo=logo,
        quiet=quiet,
    )
    config.rate_limit.requests_per_second = rate_limit
    _log_scope(scope)
    counts = asyncio.run(_run_scan(config))
    _apply_fail_on(counts, fail_on)


async def _run_scan(config: ScanConfig, *, resume: bool = False) -> dict[str, int]:
    """Run the pipeline and return the final severity-count tally (for --fail-on)."""
    from hydra.core.orchestrator import Orchestrator

    orch = Orchestrator(config, get_settings(), resume=resume)
    status = "completed"
    counts: dict[str, int] = {}
    try:
        await orch.setup()
        await orch.run_recon()
        await orch.run_scan()
        await orch.run_exploit()
        await orch.run_report(config.report_format, config.output)
        await orch.print_summary()
        # Capture before teardown closes the store; the gate is applied by the caller.
        counts = await orch.store.severity_counts(orch.scan_id)
    except Exception:
        status = "failed"
        logger.exception("scan aborted")
    finally:
        await orch.teardown(status)
    return counts


async def _resume_scan(
    scan_id: str, report_overrides: dict[str, str | None]
) -> dict[str, int]:
    """Reload a previous scan's config from the DB and re-run it from its checkpoint.

    Returns the final severity-count tally (empty if the scan id is unknown) so
    the caller can apply the --fail-on gate.
    """
    settings = get_settings()
    store = Store(settings.db_url, encryption_key=settings.encryption_key)
    try:
        scan = await store.get_scan(scan_id)
        if scan is None:
            logger.error("no such scan to resume: %s", scan_id)
            return {}
        config = ScanConfig.model_validate(scan.config_json)
        config.scan_id = scan_id
    finally:
        await store.close()

    # Report output is controlled by this invocation's CLI flags, not the
    # original run's; everything else (target, scope, modules) comes from the DB.
    for key, value in report_overrides.items():
        if value is not None:
            setattr(config, key, value)

    _log_scope(config.scope)
    logger.info("resuming scan %s against %s", scan_id, config.target)
    return await _run_scan(config, resume=True)


def _run_distributed(
    target_spec: str,
    scope_str: str,
    exclude_paths: str | None,
    module_list: list[str],
    aggressiveness: Aggressiveness,
    crawl_depth: int,
    max_pages: int,
    timeout: float,
    no_exploit: bool,
    browser: bool,
    report_format: str,
    workers: int,
    redis_url: str | None,
) -> None:
    import os

    if redis_url:
        os.environ["HYDRA_REDIS_URL"] = redis_url
    try:
        from hydra.distributed.dispatcher import dispatch, load_targets, partition_targets
    except ImportError:
        logger.error("distributed mode needs the [distributed] extra (celery + redis)")
        return

    targets = load_targets(target_spec)
    if not targets:
        logger.error("no targets found in %s", target_spec)
        return

    configs = [
        ScanConfig(
            target=t,
            scope=build_scope(scope_str, t, exclude_paths),
            modules=module_list,
            aggressiveness=aggressiveness,
            crawl_depth=crawl_depth,
            max_pages=max_pages,
            timeout=timeout,
            no_exploit=no_exploit,
            use_browser=browser,
            report_format=report_format,
        )
        for t in targets
    ]
    buckets = partition_targets(targets, workers)
    logger.info(
        "dispatching %d target(s) across %d worker bucket(s) via Redis",
        len(targets),
        len(buckets),
    )
    results = dispatch(configs)
    for r in results:
        logger.info("%s -> %s", r.get("target"), r.get("status"))


@cli.command()
@click.option("--target", "-t", required=True, help="Target URL.")
@click.option("--scope", "scope_str", default="auto", help="Scope: wildcard domains / CIDR ranges.")
@click.option("--fingerprint/--no-fingerprint", default=True, help="Run technology fingerprinting.")
@click.option("--crawl/--no-crawl", default=True, help="Run the web crawler.")
@click.option("--js/--no-js", "js_analysis", default=True, help="Run JS endpoint/secret analysis.")
@click.option("--content/--no-content", "content_discovery", default=True, help="Run content discovery.")
@click.option("--waf/--no-waf", "waf_detect", default=True, help="Run WAF detection.")
@click.option("--api/--no-api", "api_discovery", default=True, help="Run API discovery.")
@click.option("--dns/--no-dns", "dns_enum", default=True, help="Run DNS enumeration (domain targets).")
@click.option("--subdomains", is_flag=True, help="Run subdomain enumeration (needs *.domain scope).")
@click.option("--wayback", is_flag=True, help="Query the Wayback Machine for historical URLs.")
@click.option("--ports", is_flag=True, help="Run Nmap port scan (needs the nmap binary).")
@click.option("--crawl-depth", default=5, type=int, help="Maximum crawl depth.")
@click.option("--max-pages", default=2000, type=int, help="Maximum pages to crawl.")
@click.option("--rate-limit", default=50.0, type=float, help="Max requests/sec per domain.")
@click.option("--timeout", default=30.0, type=float, help="HTTP request timeout (s).")
@click.option("--proxy", default=None, help="HTTP/SOCKS5 proxy URL.")
@click.option("--auth-cookie", default=None, help="Pre-authenticated session cookie string.")
@click.option("--login-url", default=None, help="URL to POST credentials to before recon.")
@click.option(
    "--login-data",
    default=None,
    help="Login body: 'user=admin&password=admin' or a JSON object.",
)
@click.option(
    "--login-token-field",
    default=None,
    help="Dotted path into a JSON login response to use as the bearer token.",
)
@click.option("--login-check", default=None, help="Substring proving the session is authenticated.")
@click.option(
    "--import",
    "import_spec",
    default=None,
    help="Import an OpenAPI/Swagger/GraphQL/HAR/Postman spec (file path or in-scope URL).",
)
@click.option("--exclude-paths", default=None, help="Comma-separated regex paths to exclude.")
@click.option("--scan-id", default=None, help="Custom scan identifier.")
@click.option("--output", "-o", default=None, help="Optional JSON report output path.")
@click.option("--verbose", "-v", default="info", help="Log level.")
def recon(
    target: str,
    scope_str: str,
    fingerprint: bool,
    crawl: bool,
    js_analysis: bool,
    content_discovery: bool,
    waf_detect: bool,
    api_discovery: bool,
    dns_enum: bool,
    subdomains: bool,
    wayback: bool,
    ports: bool,
    crawl_depth: int,
    max_pages: int,
    rate_limit: float,
    timeout: float,
    proxy: str | None,
    auth_cookie: str | None,
    login_url: str | None,
    login_data: str | None,
    login_token_field: str | None,
    login_check: str | None,
    import_spec: str | None,
    exclude_paths: str | None,
    scan_id: str | None,
    output: str | None,
    verbose: str,
) -> None:
    """Run reconnaissance only."""
    configure_logging(verbose)
    scope = build_scope(scope_str, target, exclude_paths)
    config = ScanConfig(
        scan_id=scan_id,
        target=target,
        scope=scope,
        crawl_depth=crawl_depth,
        max_pages=max_pages,
        timeout=timeout,
        proxy=proxy,
        auth_cookie=auth_cookie,
        login_url=login_url,
        login_data=login_data,
        login_token_field=login_token_field,
        login_check=login_check,
        import_spec=import_spec,
    )
    config.rate_limit.requests_per_second = rate_limit
    flags = {
        "fingerprint": fingerprint, "crawl": crawl, "js": js_analysis,
        "content": content_discovery, "waf": waf_detect, "api": api_discovery,
        "dns": dns_enum, "subdomains": subdomains, "wayback": wayback, "ports": ports,
    }
    which = {name for name, on in flags.items() if on}
    _log_scope(scope)
    asyncio.run(_run_recon(config, which, output))


async def _run_recon(config: ScanConfig, which: set[str], output: str | None) -> None:
    from hydra.core.orchestrator import Orchestrator

    orch = Orchestrator(config, get_settings())
    status = "completed"
    try:
        await orch.setup()
        await orch.run_recon(which)
        if output:
            await orch.run_report("json", output)
        await orch.print_summary()
    except Exception:
        status = "failed"
        logger.exception("recon aborted")
    finally:
        await orch.teardown(status)


@cli.command()
@click.option("--scan-id", required=True, help="Scan identifier from a previous run.")
@click.option("--confirm-all", is_flag=True, help="Attempt confirmation of all findings.")
@click.option("--verbose", "-v", default="info", help="Log level.")
def exploit(scan_id: str, confirm_all: bool, verbose: str) -> None:
    """Run exploitation confirmation against a previous scan's findings."""
    configure_logging(verbose)
    asyncio.run(_run_exploit(scan_id))


async def _run_exploit(scan_id: str) -> None:
    store = Store(get_settings().db_url)
    try:
        scan = await store.get_scan(scan_id)
        if scan is None:
            logger.error("no such scan: %s", scan_id)
            return
        findings = await store.get_findings(scan_id)
        confirmed = sum(1 for f in findings if f.confidence == "confirmed")
        logger.info("scan %s has %d finding(s), %d already confirmed", scan_id, len(findings), confirmed)
        logger.info(
            "confirmation runs automatically during `hydra scan`; standalone replay-from-DB "
            "is not yet supported (re-run the scan to confirm)"
        )
    finally:
        await store.close()


@cli.command()
@click.option("--scan-id", required=True, help="Scan identifier to report on.")
@click.option(
    "--format",
    "fmt",
    default="json",
    type=click.Choice(["json", "html", "pdf", "csv", "sarif"]),
    help="Report format.",
)
@click.option("--template", default="technical", help="Template: executive/technical/compliance.")
@click.option("--logo", default=None, help="Logo image embedded in HTML/PDF reports.")
@click.option("--min-severity", "min_severity", default=None, help="Only report findings >= this severity.")
@click.option("--output", "-o", default="hydra_report", help="Output file path.")
@click.option("--verbose", "-v", default="info", help="Log level.")
def report(
    scan_id: str,
    fmt: str,
    template: str,
    logo: str | None,
    min_severity: str | None,
    output: str,
    verbose: str,
) -> None:
    """Generate a report from an existing scan."""
    configure_logging(verbose)
    asyncio.run(_run_report(scan_id, fmt, output, template, logo, min_severity))


async def _run_report(
    scan_id: str,
    fmt: str,
    output: str,
    template: str = "technical",
    logo: str | None = None,
    min_severity: str | None = None,
) -> None:
    settings = get_settings()
    store = Store(settings.db_url, encryption_key=settings.encryption_key)
    try:
        branding = {"logo": logo} if logo else None
        path = await generate_report(
            store, scan_id, fmt, output, template=template,
            branding=branding, min_severity=min_severity,
        )
        logger.info("report written to %s", path)
    finally:
        await store.close()


@cli.command(name="scans")
@click.option("--status", default=None, help="Filter by status: running / completed / failed.")
@click.option("--limit", default=50, type=int, help="Maximum number of scans to list.")
@click.option("--verbose", "-v", default="info", help="Log level.")
def scans(status: str | None, limit: int, verbose: str) -> None:
    """List previous scans (id, status, phase, findings) for resume/report."""
    configure_logging(verbose)
    asyncio.run(_list_scans(status, limit))


async def _list_scans(status: str | None, limit: int) -> None:
    from rich.table import Table

    settings = get_settings()
    store = Store(settings.db_url, encryption_key=settings.encryption_key)
    try:
        await store.init()
        rows = await store.list_scans(limit=limit, status=status)
    finally:
        await store.close()

    if not rows:
        logger.info("no scans found (filter: %s)", status or "none")
        return

    table = Table(title="[hydra.accent]HYDRA scans[/]")
    table.add_column("Scan ID", style="bold")
    table.add_column("Target")
    table.add_column("Status")
    table.add_column("Last phase")
    table.add_column("Findings", justify="right")
    table.add_column("Started")
    for row, count in rows:
        started = row.started_at.strftime("%Y-%m-%d %H:%M") if row.started_at else "-"
        table.add_row(
            row.id,
            row.target,
            f"[{status_style(row.status)}]{row.status}[/]",
            row.phase or "-",
            str(count),
            started,
        )
    console.print(table)
    # Nudge toward the resume workflow for any scan that didn't finish.
    if any(row.status in ("running", "failed") for row, _ in rows):
        logger.info("resume an interrupted scan with: hydra scan --resume --scan-id <id>")


@cli.command(name="modules")
@click.option("--json", "as_json", is_flag=True, help="Emit the inventory as JSON (stdout).")
@click.option("--verbose", "-v", default="warning", help="Log level.")
def modules(as_json: bool, verbose: str) -> None:
    """List available scanner and exploit-confirmation modules.

    These are the names accepted by ``hydra scan --modules``. Useful for
    discovering capabilities and building a targeted module selection.
    """
    configure_logging(verbose)
    # Importing the packages runs the @register side-effects that populate the
    # registries (no scanners are imported until something needs them).
    import hydra.exploits  # noqa: F401
    import hydra.scanners  # noqa: F401
    from hydra.exploits.registry import EXPLOIT_REGISTRY
    from hydra.scanners.registry import SCANNER_REGISTRY

    scanners = [
        {
            "name": cls.name,
            "vuln_type": cls.vuln_type,
            "min_aggressiveness": cls.min_aggressiveness.value,
            "description": _first_doc_line(cls),
        }
        for cls in sorted(SCANNER_REGISTRY.values(), key=lambda c: c.name)
    ]
    exploits = [
        {
            "name": cls.name,
            "handles": list(cls.handles),
            "description": _first_doc_line(cls),
        }
        for cls in sorted(EXPLOIT_REGISTRY.values(), key=lambda c: c.name)
    ]

    if as_json:
        # Machine-readable on stdout (stdout is reserved for data; chrome is stderr).
        click.echo(json.dumps({"scanners": scanners, "exploits": exploits}, indent=2))
        return

    _print_modules(scanners, exploits)


def _print_modules(scanners: list[dict], exploits: list[dict]) -> None:
    from rich.table import Table

    section(console, f"SCANNERS · {len(scanners)}")
    stable = Table(title="[hydra.accent]Vulnerability scanners[/]")
    stable.add_column("Module", style="bold")
    stable.add_column("Vuln type")
    stable.add_column("Aggr.")
    stable.add_column("Description", style="hydra.muted")
    for s in scanners:
        agg = s["min_aggressiveness"]
        stable.add_row(
            s["name"],
            s["vuln_type"],
            f"[{_AGG_STYLE.get(agg, 'default')}]{agg}[/]",
            s["description"],
        )
    console.print(stable)

    section(console, f"EXPLOIT CONFIRMATION · {len(exploits)}")
    etable = Table(title="[hydra.accent]Exploit-confirmation modules[/]")
    etable.add_column("Module", style="bold")
    etable.add_column("Confirms")
    etable.add_column("Description", style="hydra.muted")
    for e in exploits:
        etable.add_row(e["name"], ", ".join(e["handles"]), e["description"])
    console.print(etable)


@cli.command()
@click.option("--target", "-t", required=True, help="Target URL (a host you own / are authorized to test).")
@click.option(
    "--truth",
    required=True,
    help="Ground-truth file path, or a bundled name (e.g. 'reflecting-target').",
)
@click.option("--scope", "scope_str", default="auto", help="Scope: wildcard domains / CIDR ranges.")
@click.option("--modules", default="all", help="Comma-separated scanner modules.")
@click.option("--aggressive", is_flag=True, help="Enable aggressive scanning (some classes need it).")
@click.option("--confirm/--no-confirm", default=False, help="Run exploitation confirmation before scoring.")
@click.option("--browser/--no-browser", default=True, help="Use headless browser (DOM/stored XSS).")
@click.option("--rate-limit", default=50.0, type=float, help="Max requests/sec per domain.")
@click.option("--timeout", default=30.0, type=float, help="HTTP request timeout (s).")
@click.option("--exclude-paths", default=None, help="Comma-separated regex paths to exclude.")
@click.option("--output", "-o", default=None, help="Write the benchmark result as JSON to this path.")
@click.option("--verbose", "-v", default="info", help="Log level.")
def benchmark(
    target: str,
    truth: str,
    scope_str: str,
    modules: str,
    aggressive: bool,
    confirm: bool,
    browser: bool,
    rate_limit: float,
    timeout: float,
    exclude_paths: str | None,
    output: str | None,
    verbose: str,
) -> None:
    """Measure detection accuracy against a known-vulnerability ground truth.

    Scans a target you own, then scores the findings against an enumerated
    ground-truth file: detection rate (did we catch the known bugs?) and a
    false-positive proxy (did we report bugs that aren't in the truth?).
    """
    configure_logging(verbose)
    from hydra.benchmark.runner import load_truth

    truth_name, expected = load_truth(truth)
    scope = build_scope(scope_str, target, exclude_paths)
    config = ScanConfig(
        target=target,
        scope=scope,
        modules=[m.strip() for m in modules.split(",") if m.strip()],
        aggressiveness=Aggressiveness.AGGRESSIVE if aggressive else Aggressiveness.NORMAL,
        timeout=timeout,
        use_browser=browser,
        no_exploit=not confirm,
    )
    config.rate_limit.requests_per_second = rate_limit
    _log_scope(scope)
    asyncio.run(_run_benchmark(config, truth_name, expected, confirm, output))


async def _run_benchmark(
    config: ScanConfig,
    truth_name: str,
    expected: list,  # list[Expected]
    confirm: bool,
    output: str | None,
) -> None:
    from hydra.benchmark.runner import run_benchmark

    report = await run_benchmark(config, get_settings(), expected, confirm=confirm)
    _print_benchmark(report, truth_name, config.target)
    if output:
        _write_benchmark_json(report, truth_name, config.target, output)
        logger.info("benchmark result written to %s", output)


def _print_benchmark(report: object, truth_name: str, target: str) -> None:
    from rich.table import Table

    from hydra.utils.logger import console

    r = report  # BenchmarkReport
    table = Table(title=f"Benchmark: {truth_name} vs {target}")
    table.add_column("Metric", style="bold")
    table.add_column("Value", justify="right")
    table.add_row("Detection rate", f"{r.detection_rate:.0%} ({r.required_detected}/{r.required_total})")
    if r.optional_total:
        table.add_row(
            "Optional detected", f"{r.optional_detected}/{r.optional_total} (capability-gated)"
        )
    table.add_row("Unexpected findings", str(r.unexpected_count))
    table.add_row("False-positive rate", f"{r.false_positive_rate:.0%}")
    table.add_row("Total findings", str(r.total_findings))
    console.print(table)

    if r.missed:
        missed = Table(title="Missed (expected but not detected)", show_lines=False)
        missed.add_column("Vuln")
        missed.add_column("Where")
        missed.add_column("Kind")
        for e in r.missed:
            missed.add_row(e.vuln_type, e.url_contains or "*", "optional" if e.optional else "required")
        console.print(missed)
    if r.unexpected:
        unexpected = Table(title="Unexpected findings (possible false positives)")
        unexpected.add_column("Vuln")
        unexpected.add_column("URL")
        for f in r.unexpected:
            unexpected.add_row(f.vuln_type, f.url)
        console.print(unexpected)


def _write_benchmark_json(
    report: object, truth_name: str, target: str, output: str
) -> None:
    r = report  # BenchmarkReport
    payload = {
        "truth": truth_name,
        "target": target,
        "detection_rate": round(r.detection_rate, 4),
        "required_detected": r.required_detected,
        "required_total": r.required_total,
        "optional_detected": r.optional_detected,
        "optional_total": r.optional_total,
        "unexpected_count": r.unexpected_count,
        "false_positive_rate": round(r.false_positive_rate, 4),
        "total_findings": r.total_findings,
        "detected": [{"vuln_type": e.vuln_type, "where": e.url_contains, "param": e.param} for e in r.detected],
        "missed": [
            {"vuln_type": e.vuln_type, "where": e.url_contains, "param": e.param, "optional": e.optional}
            for e in r.missed
        ],
        "unexpected": [{"vuln_type": f.vuln_type, "url": f.url, "parameter": f.parameter} for f in r.unexpected],
    }
    with open(output, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)


if __name__ == "__main__":
    cli()
