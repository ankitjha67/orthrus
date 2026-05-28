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
@click.option("--user-agent", default="random", help="User-Agent string or 'random'.")
@click.option("--callback", default=None, help="Callback server URL for OOB detection.")
@click.option("--no-exploit", is_flag=True, help="Skip exploitation confirmation phase.")
@click.option("--browser/--no-browser", default=True, help="Use headless browser (DOM/stored XSS).")
@click.option("--exclude-paths", default=None, help="Comma-separated regex paths to exclude.")
@click.option("--headers", default=None, help="Extra headers as JSON object.")
@click.option("--threads", default=10, type=int, help="Concurrent scanner threads.")
@click.option("--scan-id", default=None, help="Custom scan identifier.")
@click.option("--output", "-o", default="hydra_report", help="Report output path.")
@click.option(
    "--format",
    "report_format",
    default="json",
    type=click.Choice(["json", "html", "pdf", "csv"]),
    help="Report format (html/pdf land in Roadmap Phase 4).",
)
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
    user_agent: str,
    callback: str | None,
    no_exploit: bool,
    browser: bool,
    exclude_paths: str | None,
    headers: str | None,
    threads: int,
    scan_id: str | None,
    output: str,
    report_format: str,
    verbose: str,
) -> None:
    """Run the full pipeline: recon -> scan -> exploit -> report."""
    configure_logging(verbose)
    scope = build_scope(scope_str, target, exclude_paths)
    config = ScanConfig(
        scan_id=scan_id,
        target=target,
        scope=scope,
        modules=[m.strip() for m in modules.split(",") if m.strip()],
        aggressiveness=Aggressiveness.AGGRESSIVE if aggressive else Aggressiveness.NORMAL,
        crawl_depth=crawl_depth,
        max_pages=max_pages,
        timeout=timeout,
        concurrency=threads,
        proxy=proxy,
        user_agent=user_agent,
        extra_headers=_parse_headers(headers),
        auth_cookie=auth_cookie,
        auth_script=auth_script,
        callback=callback,
        no_exploit=no_exploit,
        use_browser=browser,
        output=output,
        report_format=report_format,
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
        fmt = config.report_format
        if fmt in ("html", "pdf", "csv"):
            logger.warning("%s reporting not implemented yet; emitting JSON instead", fmt)
            fmt = "json"
        await orch.run_report(fmt, config.output)
        await orch.print_summary()
    except Exception:
        status = "failed"
        logger.exception("scan aborted")
    finally:
        await orch.teardown(status)


@cli.command()
@click.option("--target", "-t", required=True, help="Target URL.")
@click.option("--scope", "scope_str", default="auto", help="Scope: wildcard domains / CIDR ranges.")
@click.option("--fingerprint/--no-fingerprint", default=True, help="Run technology fingerprinting.")
@click.option("--crawl/--no-crawl", default=True, help="Run the web crawler.")
@click.option("--subdomains", is_flag=True, help="Subdomain enumeration (deferred).")
@click.option("--crawl-depth", default=5, type=int, help="Maximum crawl depth.")
@click.option("--max-pages", default=2000, type=int, help="Maximum pages to crawl.")
@click.option("--rate-limit", default=50.0, type=float, help="Max requests/sec per domain.")
@click.option("--timeout", default=30.0, type=float, help="HTTP request timeout (s).")
@click.option("--proxy", default=None, help="HTTP/SOCKS5 proxy URL.")
@click.option("--auth-cookie", default=None, help="Pre-authenticated session cookie string.")
@click.option("--exclude-paths", default=None, help="Comma-separated regex paths to exclude.")
@click.option("--scan-id", default=None, help="Custom scan identifier.")
@click.option("--output", "-o", default=None, help="Optional JSON report output path.")
@click.option("--verbose", "-v", default="info", help="Log level.")
def recon(
    target: str,
    scope_str: str,
    fingerprint: bool,
    crawl: bool,
    subdomains: bool,
    crawl_depth: int,
    max_pages: int,
    rate_limit: float,
    timeout: float,
    proxy: str | None,
    auth_cookie: str | None,
    exclude_paths: str | None,
    scan_id: str | None,
    output: str | None,
    verbose: str,
) -> None:
    """Run reconnaissance only."""
    configure_logging(verbose)
    if subdomains:
        logger.warning("subdomain enumeration is deferred (Roadmap Phase 1 follow-up); skipping")
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
    )
    config.rate_limit.requests_per_second = rate_limit
    which = set()
    if fingerprint:
        which.add("fingerprint")
    if crawl:
        which.add("crawl")
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
        logger.info("scan %s has %d finding(s)", scan_id, len(findings))
        logger.info("exploit modules not registered yet (Roadmap Phase 4) — nothing to confirm")
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
@click.option("--branding", default=None, help="Logo/branding asset path (deferred).")
@click.option("--output", "-o", default="hydra_report", help="Output file path.")
@click.option("--verbose", "-v", default="info", help="Log level.")
def report(scan_id: str, fmt: str, template: str, branding: str | None, output: str) -> None:
    """Generate a report from an existing scan."""
    configure_logging(verbose="info")
    asyncio.run(_run_report(scan_id, fmt, output))


async def _run_report(scan_id: str, fmt: str, output: str) -> None:
    store = Store(get_settings().db_url)
    try:
        try:
            path = await generate_report(store, scan_id, fmt, output)
        except NotImplementedError as exc:
            logger.warning("%s", exc)
            path = await generate_report(store, scan_id, "json", output)
        logger.info("report written to %s", path)
    finally:
        await store.close()


if __name__ == "__main__":
    cli()
