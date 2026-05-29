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
from urllib.parse import urlsplit

import click

from hydra import __version__
from hydra.core.config import ScanConfig, ScopeConfig, get_settings
from hydra.core.schemas import Aggressiveness
from hydra.db.store import Store
from hydra.reporting.generator import generate_report
from hydra.utils.logger import configure_logging, get_logger

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
    logger.info(
        "[bold]Authorized scope[/] - domains=%s ip_ranges=%s ports=%s exclude=%s",
        scope.domains or "(none)",
        scope.ip_ranges or "(none)",
        scope.ports or "any",
        scope.exclude_paths or "(none)",
    )


@click.group()
@click.version_option(__version__, prog_name="hydra")
def cli() -> None:
    """HYDRA - automated vulnerability discovery & exploitation confirmation.

    For authorized security testing only.
    """


@cli.command()
@click.option("--target", "-t", required=True, help="Target URL.")
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
@click.option("--output", "-o", default="hydra_report", help="Report output path.")
@click.option(
    "--format",
    "report_format",
    default="json",
    type=click.Choice(["json", "html", "pdf", "csv"]),
    help="Report format.",
)
@click.option("--template", default="technical", help="Report template: executive/technical/compliance.")
@click.option("--min-severity", "min_severity", default=None, help="Only report findings >= this severity.")
@click.option("--logo", default=None, help="Logo image embedded in HTML/PDF reports.")
@click.option("--har", default=None, help="Record a browser HAR to this path (evidence).")
@click.option("--verbose", "-v", default="info", help="Log level: debug/info/warning/error.")
def scan(
    target: str,
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
    output: str,
    report_format: str,
    template: str,
    min_severity: str | None,
    logo: str | None,
    har: str | None,
    verbose: str,
) -> None:
    """Run the full pipeline: recon -> scan -> exploit -> report."""
    configure_logging(verbose)
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
        callback=callback,
        no_exploit=no_exploit,
        use_browser=browser,
        har_path=har,
        output=output,
        report_format=report_format,
        report_template=template,
        min_severity=min_severity,
        branding_logo=logo,
    )
    config.rate_limit.requests_per_second = rate_limit
    _log_scope(scope)
    asyncio.run(_run_scan(config))


async def _run_scan(config: ScanConfig) -> None:
    from hydra.core.orchestrator import Orchestrator

    orch = Orchestrator(config, get_settings())
    status = "completed"
    try:
        await orch.setup()
        await orch.run_recon()
        await orch.run_scan()
        await orch.run_exploit()
        await orch.run_report(config.report_format, config.output)
        await orch.print_summary()
    except Exception:
        status = "failed"
        logger.exception("scan aborted")
    finally:
        await orch.teardown(status)


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
    type=click.Choice(["json", "html", "pdf", "csv"]),
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


if __name__ == "__main__":
    cli()
