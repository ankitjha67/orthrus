"""ORTHRUS command-line interface (PRD §10).

Authorized testing only. Scope is resolved and printed at the start of every
run so the operator can confirm the engagement boundary before any request goes
out. ``--scope auto`` derives a minimal scope from the target; real engagements
should pass an explicit scope.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import re
import sys
import tomllib
from collections.abc import Callable
from urllib.parse import urlsplit

import click

from orthrus import __version__
from orthrus.core.config import ScanConfig, ScopeConfig, get_settings
from orthrus.core.schemas import FINDING_STATUSES, Aggressiveness
from orthrus.db.store import Store
from orthrus.reporting.generator import generate_report
from orthrus.utils.logger import configure_logging, console, get_logger
from orthrus.utils.theme import findings_table, render_banner, scope_panel, section, status_style

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


def _normalize_scope_domain(token: str) -> str:
    """Reduce a scope token to a bare host(/wildcard), tolerating pasted URLs.

    Scope is host/domain-based, not URL-based, so 'https://site.com:8443/app' and
    '*.https://site.com:8443' are normalised to 'site.com' / '*.site.com'. The port
    is irrelevant here (the target port is authorised separately).
    """
    wildcard = token.startswith("*.")
    core = token[2:] if wildcard else token
    if "://" in core:
        core = core.split("://", 1)[1]
    core = core.split("/", 1)[0]  # drop any path
    if ":" in core:
        core = core.rsplit(":", 1)[0]  # drop :port (hostnames only; CIDR is handled earlier)
    core = core.strip().lower()
    return f"*.{core}" if wildcard else core


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
                domains.append(_normalize_scope_domain(token))
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
_AGG_STYLE = {"passive": "orthrus.muted", "normal": "default", "aggressive": "bold yellow"}


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


def _load_identities(path: str | None) -> list[dict]:
    """Load the --identities JSON file (a list of identity objects) for BOLA/BFLA."""
    if not path:
        return []
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise click.BadParameter(f"--identities must be a readable JSON file: {exc}") from exc
    if not isinstance(data, list):
        raise click.BadParameter("--identities JSON must be a list of identity objects")
    return [d for d in data if isinstance(d, dict)]


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


# Config-file keys are the long option names with hyphens (e.g. "rate-limit");
# they normalise to the Click parameter dest. A couple of options have a dest
# that differs from their flag, so alias those explicitly.
_CONFIG_KEY_ALIASES = {"scope": "scope_str", "redis": "redis_url"}
# Options whose CLI form is a single comma-separated string; a TOML array is a
# friendlier way to express them, so join lists back to the expected string.
_CONFIG_CSV_KEYS = {"modules", "exclude_paths"}


def _config_to_default_map(data: dict) -> dict:
    """Translate a parsed TOML config into a Click ``default_map``.

    Accepts either a top-level ``[scan]`` table or a flat document. Keys are
    normalised (hyphens -> underscores, plus the dest aliases) and TOML arrays
    for comma-separated options are joined back to a string.
    """
    section_data = data.get("scan", data)
    if not isinstance(section_data, dict):
        raise click.BadParameter("config '[scan]' section must be a table")
    out: dict = {}
    for key, value in section_data.items():
        name = _CONFIG_KEY_ALIASES.get(key.replace("-", "_"), key.replace("-", "_"))
        if name in _CONFIG_CSV_KEYS and isinstance(value, list):
            value = ",".join(str(v) for v in value)
        out[name] = value
    return out


def _load_config_file(ctx: click.Context, _param: object, value: str | None) -> str | None:
    """Eager --config callback: merge file defaults so CLI flags still win.

    Values flow into ``ctx.default_map``, which Click consults only for options
    the operator did *not* pass explicitly - so the command line overrides the
    file, and the file overrides built-in defaults.
    """
    if not value:
        return value
    try:
        with open(value, "rb") as fh:
            data = tomllib.load(fh)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise click.BadParameter(f"could not load config '{value}': {exc}") from exc
    ctx.default_map = {**(ctx.default_map or {}), **_config_to_default_map(data)}
    return value


def _resolve_plan(module_list: list[str], aggressiveness: Aggressiveness) -> dict[str, list[str]]:
    """Scanners that would run vs. be gated out at this aggressiveness.

    A pure planning view reflecting the --modules selection and the
    aggressiveness gate only. Per-target applicability (decided during recon)
    can narrow the 'will_run' set further at runtime; this never sends traffic.
    """
    import orthrus.scanners  # noqa: F401  (import populates SCANNER_REGISTRY)
    from orthrus.core.orchestrator import _AGGRESSIVENESS_RANK
    from orthrus.scanners.registry import get_scanners

    configured = _AGGRESSIVENESS_RANK[aggressiveness]
    will_run: list[str] = []
    gated: list[str] = []
    for scanner in get_scanners(module_list):
        bucket = will_run if _AGGRESSIVENESS_RANK[scanner.min_aggressiveness] <= configured else gated
        bucket.append(scanner.name)
    return {"will_run": sorted(will_run), "gated": sorted(gated)}


def _print_scan_plan(config: ScanConfig) -> None:
    """Render the dry-run plan: which modules run, and the key run settings."""
    from rich.markup import escape

    plan = _resolve_plan(config.modules, config.aggressiveness)
    section(console, "DRY RUN · SCAN PLAN")
    # Escape operator-supplied values: a target URL or output path can contain
    # bracketed text Rich would otherwise consume as markup.
    console.print(
        f"[orthrus.muted]Target:[/] {escape(config.target or '')}    "
        f"[orthrus.muted]Aggressiveness:[/] {config.aggressiveness.value}    "
        f"[orthrus.muted]Exploit:[/] {'off' if config.no_exploit else 'on'}    "
        f"[orthrus.muted]Browser:[/] {'on' if config.use_browser else 'off'}"
    )
    console.print(
        f"[orthrus.muted]Report:[/] {config.report_format} -> {escape(config.output)}    "
        f"[orthrus.muted]Rate limit:[/] {config.rate_limit.requests_per_second:g} req/s"
    )
    will_run = plan["will_run"]
    console.print(f"\n[status.completed]Will run[/] ({len(will_run)}): {', '.join(will_run) or '(none)'}")
    if plan["gated"]:
        console.print(
            f"[orthrus.muted]Gated (needs higher aggressiveness) "
            f"({len(plan['gated'])}): {', '.join(plan['gated'])}[/]"
        )
    console.print("\n[orthrus.muted]No requests were sent (--dry-run).[/]")


# --fail-on severity gating (CI pipelines). Mirrors the report-time severity
# ordering in orthrus.reporting.generator so the threshold means the same thing
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


def _install_uvloop() -> None:
    """Use uvloop's faster event loop when available (POSIX); a no-op otherwise."""
    try:
        import uvloop

        uvloop.install()
    except ImportError:
        pass


def _ensure_utf8_output() -> None:
    """Force UTF-8 on stdout/stderr so no command crashes on its own output.

    Windows consoles default to a legacy code page (e.g. cp1252); when CLI output
    contains non-Latin-1 glyphs - emoji in the runbook (🔓), the → in summaries -
    and stdout is a pipe or redirect, ``click.echo``/``print`` raise
    ``UnicodeEncodeError``. Reconfigure to UTF-8 with a replacing fallback.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):  # detached / already-closed stream
                pass


@click.group()
@click.version_option(__version__, prog_name="orthrus")
@click.option(
    "--no-banner",
    is_flag=True,
    envvar="ORTHRUS_NO_BANNER",
    help="Suppress the startup banner (also via ORTHRUS_NO_BANNER=1).",
)
def cli(no_banner: bool) -> None:
    """ORTHRUS - automated vulnerability discovery & exploitation confirmation.

    For authorized security testing only.
    """
    _ensure_utf8_output()
    _install_uvloop()
    if not no_banner:
        render_banner(console, __version__)


@cli.command()
@click.option(
    "--config",
    "config_path",
    default=None,
    type=click.Path(exists=True, dir_okay=False),
    callback=_load_config_file,
    is_eager=True,
    expose_value=False,
    help="Load scan options from a TOML file ([scan] table); CLI flags override it.",
)
@click.option("--target", "-t", default=None, help="Target URL (required unless --resume).")
@click.option(
    "--target-file",
    "target_file",
    default=None,
    type=click.Path(exists=True, dir_okay=False),
    help="File of targets (one per line; '#' comments allowed) for sequential batch scanning.",
)
@click.option("--scope", "scope_str", default="auto", help="Scope: wildcard domains / CIDR ranges.")
@click.option("--modules", default="all", help="Comma-separated scanner modules.")
@click.option("--tools", default="", help="External tool adapters to run (e.g. 'nuclei' or 'all'); needs the binary on PATH.")
@click.option("--aggressive", is_flag=True, help="Enable aggressive scanning.")
@click.option("--rate-limit", default=50.0, type=float, help="Max requests/sec per domain.")
@click.option("--crawl-depth", default=10, type=int, help="Maximum crawl depth.")
@click.option("--max-pages", default=5000, type=int, help="Maximum pages to crawl.")
@click.option("--timeout", default=30.0, type=float, help="HTTP request timeout (s).")
@click.option("--proxy", default=None, help="HTTP/SOCKS5 proxy URL.")
@click.option("--auth-cookie", default=None, help="Pre-authenticated session cookie string.")
@click.option("--auth-script", default=None, help="Playwright login script path (deferred).")
@click.option(
    "--identities",
    "identities_file",
    default=None,
    type=click.Path(exists=True, dir_okay=False),
    help="JSON file of identities for authorization testing (BOLA/BFLA). "
    'List of {"name","cookie"?,"token"?,"headers"?}; first = privileged baseline.',
)
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
    "--csrf-field",
    default=None,
    help="Anti-CSRF form field to harvest from the login page and replay in the login body.",
)
@click.option("--csrf-header", default=None, help="Request header to mirror the harvested CSRF token into.")
@click.option(
    "--csrf-url",
    default=None,
    help="Page to GET for the CSRF token (default: --login-url).",
)
@click.option("--totp-secret", default=None, help="Base32 MFA secret; a TOTP code is submitted with login.")
@click.option("--totp-field", default="otp", help="Login body field for the TOTP code (default: otp).")
@click.option("--oauth2-token-url", default=None, help="OAuth2 token endpoint to acquire a bearer token from.")
@click.option(
    "--oauth2-grant",
    default="password",
    type=click.Choice(["password", "client_credentials", "refresh_token"]),
    help="OAuth2 grant type (default: password).",
)
@click.option("--oauth2-client-id", default=None, help="OAuth2 client id.")
@click.option("--oauth2-client-secret", default=None, help="OAuth2 client secret.")
@click.option("--oauth2-username", default=None, help="OAuth2 password-grant username.")
@click.option("--oauth2-password", default=None, help="OAuth2 password-grant password.")
@click.option("--oauth2-scope", default=None, help="OAuth2 requested scope.")
@click.option("--oauth2-refresh-token", default=None, help="OAuth2 refresh token (refresh_token grant).")
@click.option(
    "--oauth2-token-field",
    default="access_token",
    help="Dotted path to the token in the OAuth2 JSON response (default: access_token).",
)
@click.option(
    "--reauth",
    is_flag=True,
    help="Silently re-run the login flow and retry when a response looks unauthenticated mid-scan.",
)
@click.option(
    "--reauth-marker",
    "reauth_markers",
    multiple=True,
    help="Body substring that signals a dropped session (repeatable; overrides defaults).",
)
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
@click.option("--callback", default=None, help="Advertise host for the local OOB listener.")
@click.option(
    "--interactsh",
    is_flag=True,
    help="Use a real Interactsh OOB collaborator (public pool) for blind/OOB detection.",
)
@click.option(
    "--interactsh-server",
    default=None,
    help="Specific Interactsh server host (default: public pool); implies --interactsh.",
)
@click.option("--interactsh-token", default=None, help="Auth token for a self-hosted Interactsh server.")
@click.option("--no-exploit", is_flag=True, help="Skip exploitation confirmation phase.")
@click.option("--browser/--no-browser", default=True, help="Use headless browser (DOM/stored XSS).")
@click.option(
    "--waf-adapt/--no-waf-adapt",
    default=True,
    help="On a WAF block/challenge, rotate request identity and retry once "
    "(and report scan-reliability).",
)
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
@click.option("--output", "-o", default="orthrus_report", help="Report output path.")
@click.option(
    "--format",
    "report_format",
    default="json",
    type=click.Choice(["json", "html", "pdf", "csv", "sarif", "md", "navigator"]),
    help="Report format ('navigator' = MITRE ATT&CK Navigator layer JSON).",
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
@click.option(
    "--dry-run",
    "dry_run",
    is_flag=True,
    help="Resolve the scope and scanner plan, print them, and exit without sending "
    "any requests (confirm the engagement boundary before scanning).",
)
@click.option("--verbose", "-v", default="info", help="Log level: debug/info/warning/error.")
def scan(
    target: str | None,
    target_file: str | None,
    scope_str: str,
    modules: str,
    tools: str,
    aggressive: bool,
    rate_limit: float,
    crawl_depth: int,
    max_pages: int,
    timeout: float,
    proxy: str | None,
    auth_cookie: str | None,
    auth_script: str | None,
    identities_file: str | None,
    login_url: str | None,
    login_data: str | None,
    login_token_field: str | None,
    login_check: str | None,
    csrf_field: str | None,
    csrf_header: str | None,
    csrf_url: str | None,
    totp_secret: str | None,
    totp_field: str,
    oauth2_token_url: str | None,
    oauth2_grant: str,
    oauth2_client_id: str | None,
    oauth2_client_secret: str | None,
    oauth2_username: str | None,
    oauth2_password: str | None,
    oauth2_scope: str | None,
    oauth2_refresh_token: str | None,
    oauth2_token_field: str,
    reauth: bool,
    reauth_markers: tuple[str, ...],
    import_spec: str | None,
    templates: str | None,
    user_agent: str,
    callback: str | None,
    interactsh: bool,
    interactsh_server: str | None,
    interactsh_token: str | None,
    no_exploit: bool,
    browser: bool,
    waf_adapt: bool,
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
    dry_run: bool,
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

    if not target and not target_file:
        raise click.UsageError(
            "provide --target or --target-file (or use --resume with --scan-id)"
        )
    if target and target_file:
        raise click.UsageError("use either --target or --target-file, not both")

    module_list = [m.strip() for m in modules.split(",") if m.strip()]
    tool_list = [t.strip() for t in tools.split(",") if t.strip()]
    aggressiveness = Aggressiveness.AGGRESSIVE if aggressive else Aggressiveness.NORMAL

    if distributed:
        if target_file:
            raise click.UsageError(
                "--target-file is for local sequential batch; in --distributed mode "
                "pass the target list to --target"
            )
        _run_distributed(
            target, scope_str, exclude_paths, module_list, aggressiveness,
            crawl_depth, max_pages, timeout, no_exploit, browser, report_format,
            workers, redis_url,
        )
        return

    def _config_for(t: str) -> ScanConfig:
        # Each target gets its own scope - auto-derived per target unless an
        # explicit --scope was given - so the engagement boundary is correct for
        # every host, single or batch. Mirrors the per-target build in
        # _run_distributed.
        cfg = ScanConfig(
            scan_id=scan_id,
            target=t,
            scope=build_scope(scope_str, t, exclude_paths),
            modules=module_list,
            tools=tool_list,
            aggressiveness=aggressiveness,
            crawl_depth=crawl_depth,
            max_pages=max_pages,
            timeout=timeout,
            concurrency=threads,
            proxy=proxy,
            user_agent=user_agent,
            extra_headers=_parse_headers(headers),
            waf_adapt=waf_adapt,
            auth_cookie=auth_cookie,
            auth_script=auth_script,
            identities=_load_identities(identities_file),
            login_url=login_url,
            login_data=login_data,
            login_token_field=login_token_field,
            login_check=login_check,
            csrf_field=csrf_field,
            csrf_header=csrf_header,
            csrf_url=csrf_url,
            totp_secret=totp_secret,
            totp_field=totp_field,
            oauth2_token_url=oauth2_token_url,
            oauth2_grant=oauth2_grant,
            oauth2_client_id=oauth2_client_id,
            oauth2_client_secret=oauth2_client_secret,
            oauth2_username=oauth2_username,
            oauth2_password=oauth2_password,
            oauth2_scope=oauth2_scope,
            oauth2_refresh_token=oauth2_refresh_token,
            oauth2_token_field=oauth2_token_field,
            reauth=reauth,
            reauth_markers=list(reauth_markers),
            import_spec=import_spec,
            templates=templates,
            callback=callback,
            interactsh=interactsh,
            interactsh_server=interactsh_server,
            interactsh_token=interactsh_token,
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
        cfg.rate_limit.requests_per_second = rate_limit
        return cfg

    if target_file:
        _run_target_file(target_file, _config_for, dry_run, fail_on)
        return

    config = _config_for(target)
    _log_scope(config.scope)
    if dry_run:
        # Preview only: show the resolved plan and stop before any packet leaves.
        _print_scan_plan(config)
        return
    counts = asyncio.run(_run_scan(config))
    _apply_fail_on(counts, fail_on)


def _read_targets(path: str) -> list[str]:
    """Targets from a file: one per line, '#' comments and blank lines ignored."""
    out: list[str] = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            token = line.strip()
            if token and not token.startswith("#"):
                out.append(token)
    return out


def _batch_output(output: str, target: str) -> str:
    """Per-target report path for batch scans, so reports don't overwrite.

    Stdout ('-') is preserved as-is; otherwise a filesystem-safe slug of the
    target host is appended before the generator adds the extension.
    """
    if output == "-":
        return "-"
    host = urlsplit(target if "://" in target else f"//{target}").hostname or target
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", host).strip("_") or "target"
    return f"{output}_{slug}"


def _run_target_file(
    target_file: str,
    config_for: Callable[[str], ScanConfig],
    dry_run: bool,
    fail_on: str | None,
) -> None:
    """Scan every target in a file sequentially, each with its own scope/report.

    Per-target reports go to distinct paths (the target host is appended to
    --output) so a batch never overwrites itself, and each target is its own
    scan (fresh id). The --fail-on gate is applied once over the combined
    severity tally, so any target breaching the threshold fails the whole run.
    """
    targets = _read_targets(target_file)
    if not targets:
        raise click.UsageError(f"no targets found in {target_file}")
    logger.info("batch: %d target(s) from %s", len(targets), target_file)
    aggregate: dict[str, int] = {}
    per_target: list[tuple[str, dict[str, int]]] = []
    for t in targets:
        cfg = config_for(t)
        cfg.scan_id = None  # each target is its own scan; never share an id
        cfg.output = _batch_output(cfg.output, t)
        _log_scope(cfg.scope)
        if dry_run:
            _print_scan_plan(cfg)
            continue
        counts = asyncio.run(_run_scan(cfg))
        per_target.append((t, counts))
        for sev, n in counts.items():
            aggregate[sev] = aggregate.get(sev, 0) + n
    if not dry_run:
        _print_batch_summary(per_target)
        _apply_fail_on(aggregate, fail_on)


def _print_batch_summary(results: list[tuple[str, dict[str, int]]]) -> None:
    """Roll-up table for a batch run: one row per target, severity counts + total.

    Each target already prints its own RESULTS panel; this final overview lets
    the operator compare targets at a glance and spot the worst offenders.
    """
    if not results:
        return
    from rich.table import Table
    from rich.text import Text

    from orthrus.utils.theme import severity_style

    section(console, f"BATCH SUMMARY · {len(results)} target(s)")
    table = Table(title="[orthrus.accent]Findings by target[/]", border_style="orthrus.muted")
    table.add_column("Target", style="bold", overflow="fold")
    for sev in ("critical", "high", "medium", "low"):
        table.add_column(sev.capitalize(), justify="right")
    table.add_column("Total", justify="right", style="bold")

    for target, counts in results:
        total = sum(counts.values())
        cells = []
        for sev in ("critical", "high", "medium", "low"):
            n = counts.get(sev, 0)
            cells.append(Text(str(n), style=severity_style(sev) if n else "orthrus.muted"))
        table.add_row(target, *cells, str(total))
    console.print(table)


def _print_bounty_scope(program, seeds: list[str], auth=None) -> None:
    section(console, "BUG BOUNTY · AUTHORIZED SCOPE ONLY")
    console.print(
        "[bold red]Only scan assets you are explicitly authorized to test[/] under the "
        "program's rules. Out-of-scope hosts are enforced and never touched."
    )
    if auth is not None:
        console.print(f"[bold]Authorization[/] - {auth.kind.value}: {auth.reference}")
    console.print(f"\n[bold]In scope[/] - {len(program.domains)} domain(s), "
                  f"{len(program.ip_ranges)} range(s):")
    for d in program.domains:
        console.print(f"  + {d}")
    for c in program.ip_ranges:
        console.print(f"  + {c}")
    if program.out_of_scope:
        console.print("[bold]Out of scope[/] - never touched:")
        for o in program.out_of_scope:
            console.print(f"  [red]![/] {o}")
    console.print(f"[bold]Seeds to scan[/] - {len(seeds)}:")
    for s in seeds:
        console.print(f"  -> {s}")
    console.print("")


def _print_bounty_summary(result, outdir: str, files: list[str]) -> None:
    section(console, "BUG BOUNTY · RESULTS")
    r = result.report
    failed = f", [red]{len(result.failed_seeds)} failed[/]" if result.failed_seeds else ""
    console.print(f"scanned [bold]{len(result.scan_ids)}[/] asset(s){failed}")
    console.print(
        f"[bold]{r.reportable}[/] reportable bug(s) - {r.considered} considered, "
        f"{r.out_of_scope} out-of-scope, {r.below_confidence} below the confidence floor"
    )
    console.print(f"submission-ready reports -> [bold]{outdir}/[/] ({len(files)} file(s))")


@cli.command()
@click.option("--program", "program_name", default=None, metavar="NAME",
              help="Save/load this engagement under a name: persists scope + authorization and "
                   "the campaign history, so you can re-run a program by name (see 'orthrus programs').")
@click.option("--scope-file", type=click.Path(exists=True, dir_okay=False),
              help="Program scope file: in-scope assets, one per line; a '!' prefix marks "
                   "an out-of-scope exclusion; '#' comments.")
@click.option("--in-scope", "in_scope", multiple=True, metavar="ASSET",
              help="Add an in-scope asset (domain / *.wildcard / URL / CIDR). Repeatable.")
@click.option("--out-scope", "out_scope", multiple=True, metavar="ASSET",
              help="Add an out-of-scope exclusion. Repeatable.")
@click.option("--authorization", "authorization", default=None, metavar="SOURCE",
              help="Proof you're authorized: a program URL (hackerone.com/…, bugcrowd.com/…), "
                   "'signed:<file>', 'direct:<note>', or 'self-owned-lab'. Required for public scopes.")
@click.option("--i-am-authorized", "i_am_authorized", multiple=True, metavar="HOST",
              help="Attest written authorization for a high-sensitivity host (gov/mil/edu/health) "
                   "so it isn't refused. Repeatable; name the exact host.")
@click.option("--enumerate/--no-enumerate", "enumerate_subs", default=True, show_default=True,
              help="Discover live in-scope subdomains (crt.sh + DNS) and scan them too, not just "
                   "the seeds you listed. In-scope, non-excluded, non-sensitive hosts only.")
@click.option("--min-confidence", type=click.Choice(["confirmed", "firm", "tentative"]),
              default="firm", show_default=True,
              help="Only report bugs at/above this confidence (keeps triager noise down).")
@click.option("--platform", type=click.Choice(
                  ["generic", "hackerone", "bugcrowd", "intigriti", "yeswehack", "immunefi"]),
              default="generic", show_default=True,
              help="Shape each per-bug report for this platform's submission form.")
@click.option("--notify-slack", "notify_slack", envvar="ORTHRUS_SLACK_WEBHOOK", default=None,
              metavar="WEBHOOK", help="Post a campaign summary to this Slack incoming webhook "
                                      "(or set ORTHRUS_SLACK_WEBHOOK).")
@click.option("--tools", default=None, metavar="NAMES",
              help="Also run external-tool adapters per asset (comma-separated, or 'all'): "
                   "nuclei, dalfox, testssl, ffuf. Needs the binaries on PATH.")
@click.option("--aggressive", is_flag=True, help="Enable aggressive scanning.")
@click.option("--browser/--no-browser", default=False, help="Use a headless browser (DOM/stored XSS).")
@click.option("--no-exploit", is_flag=True, help="Skip the exploitation-confirmation phase.")
@click.option("--callback", default=None,
              help="Advertise host for the local OOB listener (SSRF/XXE/deserialization confirmation).")
@click.option("--interactsh", is_flag=True,
              help="Use a real Interactsh OOB collaborator for blind/OOB confirmation.")
@click.option("--rate-limit", type=float, default=20.0, show_default=True, help="Max requests/sec per host.")
@click.option("--timeout", type=float, default=30.0, show_default=True, help="HTTP request timeout (s).")
@click.option("--crawl-depth", type=int, default=10, show_default=True)
@click.option("--max-pages", type=int, default=2000, show_default=True)
@click.option("--threads", type=int, default=10, show_default=True)
@click.option("-o", "--output", "outdir", default="bounty-report", show_default=True,
              help="Directory for the submission-ready reports.")
@click.option("--dry-run", is_flag=True,
              help="Resolve and print the scope + seeds, then stop (no requests sent).")
def bounty(program_name, scope_file, in_scope, out_scope, authorization, i_am_authorized,
           enumerate_subs, min_confidence, platform, notify_slack, tools, aggressive, browser,
           no_exploit, callback, interactsh, rate_limit, timeout, crawl_depth, max_pages, threads,
           outdir, dry_run):
    """Run an authorized bug-bounty campaign: scan every in-scope asset with all
    scanners, confirm the findings, and write submission-ready per-bug reports.

    Requires an explicit program scope (--scope-file or --in-scope) - ORTHRUS is
    deny-by-default and will not scan without one. Out-of-scope entries are
    enforced and never touched. Authorized programs only.
    """
    _ensure_utf8_output()
    from urllib.parse import urlsplit
    from uuid import uuid4

    from orthrus.bounty import killlist
    from orthrus.bounty.audit import AuditLog
    from orthrus.bounty.authorization import AuthorizationError, resolve_authorization
    from orthrus.bounty.campaign import run_campaign, write_reports
    from orthrus.bounty.scope_intake import parse_program_scope
    from orthrus.bounty.store import ProgramRecord, ProgramStore

    text_parts: list[str] = []
    if scope_file:
        with open(scope_file, encoding="utf-8") as fh:
            text_parts.append(fh.read())
    text_parts += list(in_scope)
    text_parts += [f"!{s}" for s in out_scope]

    # A saved program can supply the scope + authorization when none is given inline.
    pstore = ProgramStore()
    saved = pstore.get(program_name) if program_name else None
    has_new_scope = bool(scope_file or in_scope or out_scope)
    if saved and not has_new_scope:
        program = saved.to_scope()
        authorization = authorization or (saved.authorization or None)
        console.print(f"[bold]Loaded program[/] '{program_name}' - {len(program.domains)} "
                      f"domain(s), {len(program.ip_ranges)} range(s)")
    else:
        program = parse_program_scope("\n".join(text_parts))

    if not program.domains and not program.ip_ranges:
        raise click.UsageError(
            "bug bounty requires an authorized scope: pass --scope-file or --in-scope "
            "(or --program NAME for a saved one). ORTHRUS is deny-by-default and will not "
            "scan without an explicit in-scope target."
        )
    seeds = program.in_scope_seeds()

    # The hosts we're about to touch: in-scope domains + the host of every seed.
    in_scope_hosts = list(program.domains) + [
        h for s in seeds if (h := (urlsplit(s).hostname or ""))
    ]
    # 1) Every engagement needs a source of authorization (public scope) - or be a local lab.
    try:
        auth = resolve_authorization(authorization, in_scope_hosts)
    except AuthorizationError as exc:
        raise click.UsageError(str(exc)) from exc
    # 2) High-sensitivity hosts (gov/mil/edu/health/sanctioned) are refused unless attested.
    blocked = killlist.screen(in_scope_hosts, acknowledged=set(i_am_authorized))
    if blocked:
        AuditLog().append("bounty-refused", "kill-list-block",
                          {"program": program_name, "hosts": [d.host for d in blocked]})
        lines = "\n".join(f"  - {d.host}: {d.reason}" for d in blocked)
        raise click.UsageError(
            "refusing high-sensitivity target(s):\n" + lines + "\n\n"
            "If you hold WRITTEN authorization to test one, re-run with "
            "--i-am-authorized <host> for each (naming the exact host), or remove it from scope."
        )

    # Persist the program (scope + attested authorization) for re-runs by name.
    if program_name and has_new_scope:
        raw = [ln.strip() for part in text_parts for ln in part.splitlines()]
        raw = [ln for ln in raw if ln and not ln.startswith("#")]
        pstore.save(ProgramRecord(
            name=program_name,
            authorization=authorization or auth.reference,
            in_scope=[ln for ln in raw if not ln.startswith("!")],
            out_scope=[ln[1:].strip() for ln in raw if ln.startswith("!")],
        ))
        console.print(f"[bold]Saved program[/] '{program_name}' (re-run later with --program {program_name})")

    _print_bounty_scope(program, seeds, auth)
    if dry_run:
        note = " (--enumerate would discover more at scan time)" if enumerate_subs and program.domains else ""
        console.print(f"[orthrus.muted]dry-run - resolved scope shown above; no requests sent.{note}[/]")
        return

    # Turn a *.wildcard scope into the live in-scope hosts to actually scan.
    if enumerate_subs and program.domains:
        from orthrus.bounty.assets import expand_program
        console.print(f"[bold]Enumerating[/] live in-scope subdomains for "
                      f"{len(program.domains)} domain(s) (crt.sh + DNS)…")
        discovered = asyncio.run(expand_program(program))
        existing = set(program.seeds)
        added = [s for s in discovered if s not in existing]
        program.seeds.extend(added)
        seeds = program.in_scope_seeds()
        console.print(f"  discovered [bold]{len(added)}[/] new in-scope host(s); "
                      f"{len(seeds)} seed(s) to scan")
        # Cross-run: for a saved program, flag assets that are NEW since last time -
        # fresh, untested surface is the highest-signal bounty event.
        if program_name:
            from orthrus.bounty.asset_monitor import AssetMonitor
            hosts = sorted({urlsplit(s).hostname or "" for s in seeds} - {""})
            adiff = AssetMonitor().record(program_name, hosts)
            if adiff.is_first:
                console.print(f"[orthrus.muted]asset baseline recorded for '{program_name}' "
                              f"({adiff.total} host(s)).[/]")
            elif adiff.added:
                listing = ", ".join(adiff.added[:8]) + (" …" if len(adiff.added) > 8 else "")
                console.print(f"[bold]✚ {len(adiff.added)} NEW in-scope asset(s)[/] since last run: {listing}")
                console.print("[orthrus.muted]fresh attack surface - prioritize these.[/]")
                AuditLog().append("asset-drift", "new-assets",
                                  {"program": program_name, "added": adiff.added})
            else:
                console.print(f"[orthrus.muted]no new in-scope assets since last run "
                              f"({adiff.total} known).[/]")
            if adiff.removed:
                console.print(f"[orthrus.muted]−{len(adiff.removed)} asset(s) no longer resolving in scope.[/]")

    if not seeds:
        raise click.UsageError("no in-scope seeds to scan (every seed was excluded).")

    aggr = Aggressiveness.AGGRESSIVE if aggressive else Aggressiveness.NORMAL

    tool_list = [t.strip() for t in (tools or "").split(",") if t.strip()]

    # Honor a saved program's traffic policy (courtesy + ban-avoidance): the stated
    # rate is a ceiling (never exceeded, even if --rate-limit is higher), and the
    # identifying header is attached to every request so the program can see it's you.
    policy_rps = saved.max_rps if saved else None
    policy_header = saved.identify_header() if saved else {}
    effective_rps = min(rate_limit, policy_rps) if policy_rps else rate_limit
    if policy_header:
        console.print(f"[orthrus.muted]identifying traffic via '{next(iter(policy_header))}' header "
                      "(program policy).[/]")
    if policy_rps and effective_rps < rate_limit:
        console.print(f"[orthrus.muted]rate capped at {effective_rps:g} req/s by program policy "
                      f"(you asked for {rate_limit:g}).[/]")

    def make_config(seed: str, scope: ScopeConfig, scan_id: str) -> ScanConfig:
        cfg = ScanConfig(
            scan_id=scan_id, target=seed, scope=scope, modules=["all"], tools=tool_list,
            aggressiveness=aggr, crawl_depth=crawl_depth, max_pages=max_pages,
            timeout=timeout, concurrency=threads, callback=callback,
            interactsh=interactsh, no_exploit=no_exploit, use_browser=browser,
            extra_headers=dict(policy_header),
        )
        cfg.rate_limit.requests_per_second = effective_rps
        return cfg

    # Per-program mute rules: known-noise findings kept out of the queue (counted, not hidden).
    supps: list[dict] = []
    if program_name:
        from orthrus.bounty.suppress import SuppressionStore
        supps = SuppressionStore().rules(program_name)

    result = asyncio.run(run_campaign(
        program, make_config, campaign_id=f"bounty-{uuid4().hex[:8]}",
        min_confidence=min_confidence, suppressions=supps,
    ))
    if result.report.suppressed:
        console.print(f"[orthrus.muted]muted {result.report.suppressed} finding(s) via "
                      f"{len(supps)} program mute rule(s).[/]")
    # Flag likely cross-run duplicates in the reports (queried before we archive below,
    # so the counts reflect *earlier* runs only).
    from orthrus.bounty.history import HistoryStore
    hist = HistoryStore()
    seen_map = hist.seen_counts([g.lead for g in result.report.groups])
    files = write_reports(result.report, outdir, platform=platform,
                          program_name=program_name or "", prior_seen=seen_map)
    if program_name:
        pstore.record_run(program_name, result.scan_ids)
    AuditLog().append("bounty-campaign", "completed", {
        "program": program_name, "authorization": f"{auth.kind.value}:{auth.reference}"[:200],
        "seeds": len(seeds), "scan_ids": result.scan_ids,
        "reportable": result.report.reportable, "output": outdir,
    })
    # Archive this run's bugs (the reports above already flagged any that predate it).
    prior = hist.record([g.lead for g in result.report.groups], program_name or "")
    if prior:
        console.print(f"[bold]♻ {prior}[/] of {result.report.reportable} bug(s) match findings from "
                      "earlier runs (possible known/duplicate - check before filing).")
    if notify_slack and result.report.reportable:
        from orthrus.integrations.notify import send_slack, slack_message
        payload = slack_message(f"bounty · {program_name or 'campaign'}", program.seeds[0] if seeds else None,
                                [g.lead for g in result.report.groups], min_severity="high")
        ok = asyncio.run(send_slack(notify_slack, payload))
        console.print(f"[bold]Slack[/] campaign summary {'sent' if ok else 'failed'}.")
    _print_bounty_summary(result, outdir, files)


@cli.command(name="audit")
@click.option("--verify", is_flag=True, help="Check the hash-chain for tampering and exit.")
@click.option("-n", "--limit", type=int, default=20, show_default=True, help="How many recent entries to show.")
def audit(verify: bool, limit: int) -> None:
    """Show or verify the tamper-evident bug-bounty audit log."""
    _ensure_utf8_output()
    from orthrus.bounty.audit import AuditLog

    log = AuditLog()
    ok, bad = log.verify()
    if verify:
        if ok:
            console.print(f"[bold]audit chain intact[/] - {len(log.entries())} entr(y/ies), no tampering.")
        else:
            console.print(f"[bold red]audit chain BROKEN[/] at entry #{bad} - tampering or corruption.")
            raise SystemExit(3)
        return
    entries = log.entries()
    if not entries:
        console.print("[orthrus.muted]no audit entries yet.[/]")
        return
    status = "intact" if ok else f"[red]BROKEN at #{bad}[/]"
    section(console, f"BUG BOUNTY · AUDIT LOG ({len(entries)} entries · chain {status})")
    for e in entries[-limit:]:
        console.print(f"[bold]{e.get('ts', '?')}[/] {e.get('event', '?')}/{e.get('action', '?')} "
                      f"- {json.dumps(e.get('details', {}))[:160]}")


@cli.command(name="programs")
def programs() -> None:
    """List saved bug-bounty programs (scope, authorization, last run)."""
    _ensure_utf8_output()
    from orthrus.bounty.store import ProgramStore

    records = ProgramStore().list()
    if not records:
        console.print("[orthrus.muted]no saved programs. Save one with "
                      "`orthrus bounty --program NAME --authorization … --in-scope …`.[/]")
        return
    section(console, f"BUG BOUNTY · PROGRAMS ({len(records)})")
    for r in records:
        console.print(f"[bold]{r.name}[/]  ({len(r.in_scope)} in / {len(r.out_scope)} out"
                      f" · auth: {r.authorization or 'unset'})")
        console.print(f"  last run: {r.last_run_at or 'never'} · {len(r.scan_ids)} campaign(s)")
        if r.max_rps or r.identify:
            pol = []
            if r.max_rps:
                pol.append(f"≤{r.max_rps:g} req/s")
            if r.identify:
                pol.append(f"identify '{r.identify}'")
            console.print(f"  [orthrus.muted]policy: {' · '.join(pol)}[/]")


@cli.command(name="program-policy")
@click.option("--program", "program_name", required=True, help="Saved program to set policy on.")
@click.option("--max-rps", type=float, default=None, help="Rate ceiling (req/s) - honored as a cap on every run.")
@click.option("--identify", default=None, help="Identifying header to send, e.g. \"X-Bug-Bounty: yourname\".")
@click.option("--clear", is_flag=True, help="Clear both policy fields.")
def program_policy(program_name: str, max_rps: float | None, identify: str | None, clear: bool) -> None:
    """Set a program's traffic policy: a rate ceiling and an identifying header.

    Most programs state a max request rate and ask you to identify your traffic.
    Saved here, both are applied automatically on every `orthrus bounty --program
    NAME` run - the rate is a hard cap (never exceeded), the header is attached to
    every request.
    """
    _ensure_utf8_output()
    from orthrus.bounty.store import ProgramStore

    store = ProgramStore()
    rec = store.get(program_name)
    if rec is None:
        raise click.UsageError(
            f"no saved program '{program_name}'. Create it first with "
            f"`orthrus bounty --program {program_name} --authorization … --in-scope …`."
        )
    if clear:
        rec.max_rps = None
        rec.identify = ""
    if max_rps is not None:
        rec.max_rps = max_rps
    if identify is not None:
        rec.identify = identify.strip()
    if rec.identify and not rec.identify_header():
        raise click.UsageError('--identify must look like "Header-Name: value".')
    store.save(rec)
    console.print(f"[bold]Policy for '{program_name}'[/] - "
                  f"rate: {f'≤{rec.max_rps:g} req/s' if rec.max_rps else 'unset'} · "
                  f"identify: {rec.identify or 'unset'}")


@cli.command(name="bounty-assets")
@click.option("--program", "program_name", required=True, help="Program name (as saved).")
@click.option("--json", "as_json", is_flag=True, help="Emit the asset inventory as JSON.")
def bounty_assets(program_name: str, as_json: bool) -> None:
    """Show the live in-scope asset inventory recorded for a program.

    Populated by `orthrus bounty --program NAME --enumerate`, which snapshots the
    live in-scope hosts each run and reports which are NEW since the last one.
    """
    _ensure_utf8_output()
    from orthrus.bounty.asset_monitor import AssetMonitor

    assets = AssetMonitor().latest(program_name)
    if as_json:
        click.echo(json.dumps({"program": program_name, "assets": assets, "count": len(assets)},
                              indent=2))
        return
    if not assets:
        console.print(f"[orthrus.muted]no assets recorded for '{program_name}'. Run "
                      f"`orthrus bounty --program {program_name} --enumerate` to build the inventory.[/]")
        return
    section(console, f"BUG BOUNTY · ASSETS · {program_name} ({len(assets)})")
    for host in assets:
        console.print(f"  {host}")


@cli.command(name="suppress")
@click.option("--program", "program_name", required=True, help="Program the rule applies to.")
@click.option("--vuln-type", default="", help="Mute this vuln_type (e.g. security-headers).")
@click.option("--host", default="", help="Mute this host (matches the host and its subdomains).")
@click.option("--title-contains", default="", help="Mute findings whose title contains this text.")
@click.option("--reason", default="", help="Why it's muted (kept for the audit trail).")
def suppress(program_name: str, vuln_type: str, host: str, title_contains: str, reason: str) -> None:
    """Add a mute rule so known-noise findings stay out of a program's report queue.

    At least one of --vuln-type / --host / --title-contains is required (an empty
    rule would mute everything, so it's refused). Muted findings are still counted
    in the campaign summary - nothing silently disappears.
    """
    _ensure_utf8_output()
    from orthrus.bounty.suppress import SuppressionStore, make_rule

    try:
        rule = make_rule(vuln_type=vuln_type, host=host, title_contains=title_contains, reason=reason)
    except ValueError as exc:
        raise click.UsageError(str(exc)) from exc
    SuppressionStore().add(program_name, rule)
    crit = ", ".join(f"{k}={v}" for k, v in rule.items() if k in ("vuln_type", "host", "title_contains") and v)
    console.print(f"[bold]Muted[/] for '{program_name}': {crit}"
                  + (f"  ({reason})" if reason else ""))


@cli.command(name="suppressions")
@click.option("--program", "program_name", required=True, help="Program to list/edit rules for.")
@click.option("--remove", type=int, default=None, help="Remove the rule at this index (from the list).")
def suppressions(program_name: str, remove: int | None) -> None:
    """List (or --remove) a program's mute rules."""
    _ensure_utf8_output()
    from orthrus.bounty.suppress import SuppressionStore

    store = SuppressionStore()
    if remove is not None:
        ok = store.remove(program_name, remove)
        console.print(f"[bold]Removed[/] rule #{remove}." if ok
                      else f"[red]No rule #{remove}[/] for '{program_name}'.")
        return
    rules = store.rules(program_name)
    if not rules:
        console.print(f"[orthrus.muted]no mute rules for '{program_name}'. Add one with "
                      f"`orthrus suppress --program {program_name} --vuln-type … --reason …`.[/]")
        return
    section(console, f"BUG BOUNTY · MUTE RULES · {program_name} ({len(rules)})")
    for i, r in enumerate(rules):
        crit = " ".join(f"{k}={v}" for k, v in r.items()
                        if k in ("vuln_type", "host", "title_contains") and v)
        console.print(f"  [bold]#{i}[/] {crit}"
                      + (f"  - {r['reason']}" if r.get("reason") else "")
                      + f"  [orthrus.muted]({r.get('added', '?')})[/]")


@cli.command(name="bounty-report")
@click.option("--program", "program_name", required=True, help="Saved program to re-render.")
@click.option("--platform", type=click.Choice(
                  ["generic", "hackerone", "bugcrowd", "intigriti", "yeswehack", "immunefi"]),
              default="generic", help="Shape reports for this platform's submission form.")
@click.option("--min-confidence", type=click.Choice(["confirmed", "firm", "tentative"]),
              default="firm", help="Report floor.")
@click.option("-o", "--output", "outdir", default="bounty-report", help="Output directory.")
def bounty_report(program_name: str, platform: str, min_confidence: str, outdir: str) -> None:
    """Re-render a saved program's last campaign - no re-scanning.

    Regenerate the submission reports from the findings already stored for a
    program's past scans, e.g. in a different --platform format, applying the
    program's current mute rules and flagging cross-run duplicates.
    """
    _ensure_utf8_output()
    from orthrus.bounty.campaign import report_from_scans, write_reports
    from orthrus.bounty.history import HistoryStore
    from orthrus.bounty.store import ProgramStore
    from orthrus.bounty.suppress import SuppressionStore

    rec = ProgramStore().get(program_name)
    if rec is None:
        raise click.UsageError(f"no saved program '{program_name}' (see `orthrus programs`).")
    if not rec.scan_ids:
        raise click.UsageError(f"'{program_name}' has no recorded scans yet - run "
                               f"`orthrus bounty --program {program_name} …` first.")
    supps = SuppressionStore().rules(program_name)
    report = asyncio.run(report_from_scans(rec.scan_ids, rec.to_scope(),
                                           min_confidence=min_confidence, suppressions=supps))
    if not report.groups:
        console.print(f"[orthrus.muted]no reportable findings at '{min_confidence}'+ across "
                      f"{len(rec.scan_ids)} stored scan(s).[/]")
        return
    seen_map = HistoryStore().seen_counts([g.lead for g in report.groups])
    files = write_reports(report, outdir, program_name=program_name, platform=platform,
                          prior_seen=seen_map)
    section(console, f"BUG BOUNTY · RE-RENDER · {program_name}")
    console.print(f"[bold]{report.reportable}[/] bug(s) → [bold]{outdir}/[/] as [bold]{platform}[/] "
                  f"({len(files)} file(s), from {len(rec.scan_ids)} stored scan(s))"
                  + (f" · {report.suppressed} muted" if report.suppressed else ""))


@cli.command(name="submission")
@click.option("--id", "sub_id", default=None, help="Existing submission id to UPDATE (else a new one is added).")
@click.option("--program", default=None, help="Program name (required when adding).")
@click.option("--title", default=None, help="Bug title (required when adding).")
@click.option("--platform", default=None, help="hackerone/bugcrowd/intigriti/yeswehack/immunefi/generic.")
@click.option("--severity", default=None)
@click.option("--status", type=click.Choice(
                  ["draft", "filed", "triaged", "accepted", "duplicate",
                   "informative", "resolved", "rewarded", "closed", "n-a"]),
              default=None, help="Submission lifecycle state.")
@click.option("--bounty", "bounty_amount", type=float, default=None, help="Payout amount.")
@click.option("--currency", default=None)
@click.option("--url", default=None, help="Link to the report on the platform.")
@click.option("--notes", default=None)
def submission(sub_id, program, title, platform, severity, status, bounty_amount, currency, url, notes):
    """Record or update a bug-bounty submission (status, payout, link)."""
    _ensure_utf8_output()
    from orthrus.bounty.submissions import Submission, SubmissionStore

    store = SubmissionStore()
    if sub_id:
        updated = store.update(sub_id, program=program, title=title, platform=platform,
                               severity=severity, status=status, bounty_amount=bounty_amount,
                               currency=currency, url=url, notes=notes)
        if updated is None:
            raise click.UsageError(f"no submission with id '{sub_id}'.")
        console.print(f"[bold]updated[/] {updated.id} - {updated.status}"
                      + (f" · {updated.bounty_amount} {updated.currency}" if updated.bounty_amount else ""))
        return
    if not program or not title:
        raise click.UsageError("adding a submission needs --program and --title (or --id to update).")
    sub = store.add(Submission(program=program, title=title, platform=platform or "generic",
                               severity=severity or "", status=status or "draft",
                               bounty_amount=bounty_amount or 0.0, currency=currency or "USD",
                               url=url or "", notes=notes or ""))
    console.print(f"[bold]added[/] submission {sub.id} for '{program}' - {sub.status}")


@cli.command(name="submissions")
@click.option("--program", default=None, help="Filter to one program.")
def submissions(program) -> None:
    """List tracked submissions and roll up earnings."""
    _ensure_utf8_output()
    from orthrus.bounty.submissions import SubmissionStore

    store = SubmissionStore()
    subs = store.list(program)
    if not subs:
        console.print("[orthrus.muted]no submissions tracked. Add one with "
                      "`orthrus submission --program NAME --title '…'`.[/]")
        return
    summ = store.summary(program)
    earn = " · ".join(f"{amt} {cur}" for cur, amt in summ["earnings"].items()) or "none"
    section(console, f"BUG BOUNTY · SUBMISSIONS ({summ['total']})")
    console.print(f"rewarded: [bold]{summ['rewarded']}[/] · earnings: [bold]{earn}[/] · "
                  f"by status: {json.dumps(summ['by_status'])}")
    for s in subs:
        amt = f" · [bold]{s.bounty_amount} {s.currency}[/]" if s.bounty_amount else ""
        console.print(f"  {s.id}  [{s.status}] {s.title[:60]}  ({s.program}/{s.platform}){amt}")


@cli.command(name="note")
@click.option("--title", required=True, help="Note title.")
@click.option("--body", default=None, help="Note body (markdown). Or use --body-file.")
@click.option("--body-file", type=click.Path(exists=True, dir_okay=False), default=None,
              help="Read the note body from a markdown file.")
@click.option("--program", default=None, help="Attach the note to a program.")
@click.option("--tags", default=None, help="Comma-separated tags.")
def note(title, body, body_file, program, tags):
    """Save an operator note (methodology, per-program tips, recon summaries)."""
    _ensure_utf8_output()
    from orthrus.bounty.notes import Note, NotesStore

    text = body or ""
    if body_file:
        with open(body_file, encoding="utf-8") as fh:
            text = fh.read()
    tag_list = [t.strip() for t in (tags or "").split(",") if t.strip()]
    saved = NotesStore().add(Note(title=title, body=text, program=program or "", tags=tag_list))
    console.print(f"[bold]saved note[/] {saved.id} - '{title}'"
                  + (f" · #{'/#'.join(tag_list)}" if tag_list else ""))


@cli.command(name="notes")
@click.option("--program", default=None, help="Filter to one program.")
@click.option("--tag", default=None, help="Filter to one tag.")
@click.option("--search", "query", default=None, help="Full-text search over title/body/tags.")
def notes(program, tag, query):
    """List or search operator notes."""
    _ensure_utf8_output()
    from orthrus.bounty.notes import NotesStore

    store = NotesStore()
    results = store.search(query, program=program) if query else store.list(program=program, tag=tag)
    if not results:
        console.print("[orthrus.muted]no matching notes. Add one with `orthrus note --title '…' --body '…'`.[/]")
        return
    section(console, f"BUG BOUNTY · NOTES ({len(results)})")
    for n in results:
        meta = " · ".join(filter(None, [n.program, "#" + " #".join(n.tags) if n.tags else ""]))
        console.print(f"  {n.id}  [bold]{n.title}[/]" + (f"  ({meta})" if meta else ""))
        first = next((ln for ln in n.body.splitlines() if ln.strip()), "")
        if first:
            console.print(f"     {first[:100]}")


@cli.command(name="bounty-status")
@click.option("--json", "as_json", is_flag=True, help="Emit the full status as JSON (for scripting).")
def bounty_status(as_json: bool) -> None:
    """One-view operator dashboard: programs, submissions, earnings, audit integrity."""
    _ensure_utf8_output()
    from orthrus.bounty.status import gather_status

    st = gather_status()
    if as_json:
        click.echo(json.dumps(st, indent=2))
        return
    section(console, "BUG BOUNTY · STATUS")
    progs = st["programs"]
    console.print(f"[bold]Programs[/] - {len(progs)}")
    for p in progs:
        extra = []
        if p.get("assets"):
            extra.append(f"{p['assets']} asset(s)")
        if p.get("mute_rules"):
            extra.append(f"{p['mute_rules']} mute rule(s)")
        if p.get("max_rps"):
            extra.append(f"≤{p['max_rps']:g} rps")
        tail = ("  [orthrus.muted]" + " · ".join(extra) + "[/]") if extra else ""
        console.print(f"  {p['name']} ({p['in_scope']} in / {p['out_scope']} out) · "
                      f"{p['campaigns']} campaign(s) · last: {p['last_run'] or 'never'}" + tail)
    sub = st["submissions"]
    earn = " · ".join(f"{amt} {cur}" for cur, amt in sub["earnings"].items()) or "none"
    console.print(f"[bold]Submissions[/] - {sub['total']} tracked · {sub['rewarded']} rewarded · "
                  f"earnings: {earn}")
    console.print(f"[bold]History[/] - {st['history_signatures']} distinct bug signature(s) catalogued"
                  f" · {st['tracked_assets']} asset(s) · {st['mute_rules']} mute rule(s)")
    cost = st["cost"]
    if cost["entries"]:
        console.print(f"[bold]Spend[/] - ${cost['total_usd']:.4f} across {cost['entries']} ledger entr(y/ies)")
    a = st["audit"]
    chain = "intact" if a["intact"] else f"[red]BROKEN at #{a['first_bad']}[/]"
    console.print(f"[bold]Audit[/] - {a['entries']} entr(y/ies) · chain {chain}")


@cli.command(name="copilot")
@click.argument("query", nargs=-1, required=True)
@click.option("--llm", "llm_spec", default=None, metavar="PROVIDER:MODEL",
              help="Ground the answer with a model (e.g. ollama:llama3.1). Omit for raw snippets.")
@click.option("-k", "--top", "top_k", type=int, default=5, show_default=True, help="Snippets to retrieve.")
def copilot(query, llm_spec, top_k):
    """Ask a copilot grounded in YOUR notes + submissions (never invents findings)."""
    _ensure_utf8_output()
    from orthrus.bounty.copilot import SYSTEM_PROMPT, build_prompt, retrieve

    q = " ".join(query).strip()
    hits = retrieve(q, k=top_k)
    if not hits:
        console.print("[orthrus.muted]I don't see anything about that in your notes or submissions. "
                      "Add context with `orthrus note …`.[/]")
        return
    if llm_spec:
        from orthrus.ai.providers import LLMClient, LLMError, resolve_config
        from orthrus.bounty.cost import CostLedger
        try:
            cfg = resolve_config(llm_spec)
            prompt = build_prompt(q, hits)
            answer = asyncio.run(LLMClient(cfg).complete(SYSTEM_PROMPT, prompt))
            CostLedger().record_llm(cfg.model, SYSTEM_PROMPT + prompt, answer, provider=cfg.provider)
            console.print(answer.strip() or "[orthrus.muted](empty answer)[/]")
        except LLMError as exc:
            console.print(f"[red]LLM unavailable[/] ({exc}); showing retrieved snippets instead.")
            llm_spec = None
    if not llm_spec:
        section(console, "COPILOT · FROM YOUR DATA")
        for h in hits:
            console.print(f"[bold]{h.title}[/]  [orthrus.muted]([{h.source}] score {h.score})[/]")
            console.print(f"  {h.snippet.splitlines()[0][:120] if h.snippet else ''}")
    console.print(f"\n[orthrus.muted]sources: {', '.join(h.source for h in hits)}[/]")


@cli.command(name="cost")
@click.option("--program", default=None, help="Filter to one program.")
def cost(program) -> None:
    """Show the cost ledger (LLM spend auto-recorded by the copilot, plus anything you log)."""
    _ensure_utf8_output()
    from orthrus.bounty.cost import CostLedger

    summ = CostLedger().summary(program)
    if not summ["entries"]:
        console.print("[orthrus.muted]no cost recorded yet (use `orthrus copilot --llm …`, or log spend).[/]")
        return
    section(console, "BUG BOUNTY · COST LEDGER")
    console.print(f"[bold]${summ['total_usd']:.4f}[/] across {summ['entries']} entr(y/ies)"
                  + (f" for {program}" if program else ""))
    console.print(f"  by provider: {json.dumps(summ['by_provider'])}")
    console.print(f"  by category: {json.dumps(summ['by_category'])}")
    console.print("[orthrus.muted]LLM costs are blended estimates (~chars/4 tokens × per-model rate); "
                  "override with ORTHRUS_LLM_RATE.[/]")


async def _run_scan(config: ScanConfig, *, resume: bool = False) -> dict[str, int]:
    """Run the pipeline and return the final severity-count tally (for --fail-on)."""
    from orthrus.core.orchestrator import Orchestrator

    orch = Orchestrator(config, get_settings(), resume=resume)
    status = "completed"
    counts: dict[str, int] = {}
    try:
        await orch.setup()
        await orch.run_recon()
        await orch.run_scan()
        await orch.run_exploit()
        await orch.run_integrations()
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
        os.environ["ORTHRUS_REDIS_URL"] = redis_url
    try:
        from orthrus.distributed.dispatcher import dispatch, load_targets, partition_targets
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
@click.option("--ip-intel/--no-ip-intel", "ip_intel", default=True, help="Resolve the target's IP intelligence (PTR/ASN/geo/cloud).")
@click.option("--mine-params/--no-mine-params", "mine_params", default=True, help="Mine endpoints for hidden parameters.")
@click.option("--subdomains", is_flag=True, help="Run subdomain enumeration (needs *.domain scope).")
@click.option("--host-gather", "host_gather", is_flag=True, help="Gather the host footprint (CT logs, reverse-IP, /24 reverse-DNS, Wayback).")
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
    ip_intel: bool,
    mine_params: bool,
    subdomains: bool,
    host_gather: bool,
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
        "dns": dns_enum, "ip-intel": ip_intel, "params": mine_params,
        "subdomains": subdomains, "host-gather": host_gather,
        "wayback": wayback, "ports": ports,
    }
    which = {name for name, on in flags.items() if on}
    _log_scope(scope)
    asyncio.run(_run_recon(config, which, output))


async def _run_recon(config: ScanConfig, which: set[str], output: str | None) -> None:
    from orthrus.core.orchestrator import Orchestrator

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
            "confirmation runs automatically during `orthrus scan`; standalone replay-from-DB "
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
    type=click.Choice(["json", "html", "pdf", "csv", "sarif", "md", "navigator"]),
    help="Report format ('navigator' = MITRE ATT&CK Navigator layer JSON).",
)
@click.option("--template", default="technical", help="Template: executive/technical/compliance.")
@click.option("--logo", default=None, help="Logo image embedded in HTML/PDF reports.")
@click.option("--min-severity", "min_severity", default=None, help="Only report findings >= this severity.")
@click.option("--output", "-o", default="orthrus_report", help="Output file path.")
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

    table = Table(title="[orthrus.accent]ORTHRUS scans[/]")
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
        logger.info("resume an interrupted scan with: orthrus scan --resume --scan-id <id>")


def _finding_summary(row: object) -> dict:
    """A compact, JSON-serialisable triage view of a finding row.

    Deliberately omits raw evidence (request/response/extracted data): this is a
    triage listing, and that material can carry sensitive payloads - it stays in
    the encrypted store and the full report, never on stdout.
    """
    return {
        "id": getattr(row, "id", None),
        "vuln_type": row.vuln_type,
        "title": row.title,
        "severity": row.severity,
        "confidence": row.confidence,
        "url": row.url,
        "parameter": row.parameter,
        "cwe": row.cwe,
        "cvss_score": row.cvss_score,
        "scanner": row.scanner,
        "status": getattr(row, "status", None) or "open",
        "owner": getattr(row, "owner", None),
    }


@cli.command(name="findings")
@click.option("--scan-id", required=True, help="Scan identifier from a previous run.")
@click.option(
    "--severity",
    default=None,
    type=click.Choice(["critical", "high", "medium", "low", "info"]),
    help="Only show findings at or above this severity.",
)
@click.option("--json", "as_json", is_flag=True, help="Emit findings as JSON (stdout).")
@click.option("--verbose", "-v", default="warning", help="Log level.")
def findings(scan_id: str, severity: str | None, as_json: bool, verbose: str) -> None:
    """Show a stored scan's findings as a triage table (or JSON).

    A read-only, network-free view of what a previous scan found - the quick
    triage list (severity, type, where, how sure) without regenerating a full
    report. Use --severity to focus on the high-risk end and --json to pipe the
    findings into other tools (stdout is reserved for that JSON; chrome is stderr).
    """
    configure_logging(verbose)
    asyncio.run(_list_findings(scan_id, severity, as_json))


async def _list_findings(scan_id: str, severity: str | None, as_json: bool) -> None:
    settings = get_settings()
    store = Store(settings.db_url, encryption_key=settings.encryption_key)
    try:
        await store.init()
        scan = await store.get_scan(scan_id)
        rows = await store.get_findings(scan_id) if scan is not None else []
    finally:
        await store.close()

    if scan is None:
        logger.error("no such scan: %s (list scans with `orthrus scans`)", scan_id)
        return

    if severity:
        floor = _FAIL_ON_ORDER.get(severity.lower(), 0)
        rows = [r for r in rows if _FAIL_ON_ORDER.get(r.severity, 0) >= floor]
    # Highest severity first, then by type, so the riskiest findings lead - the
    # same ordering the human table uses, kept consistent for the JSON view too.
    rows.sort(key=lambda r: (-_FAIL_ON_ORDER.get(r.severity, 0), r.vuln_type))

    if as_json:
        click.echo(json.dumps([_finding_summary(r) for r in rows], indent=2, default=str))
        return

    if not rows:
        scope_note = f" at or above '{severity}'" if severity else ""
        logger.info("no findings for scan %s%s", scan_id, scope_note)
        return

    from orthrus.utils.theme import findings_table

    section(console, f"FINDINGS · {scan_id}")
    console.print(findings_table(rows))
    console.print(
        "[orthrus.muted]Triage: set status/owner with "
        "`orthrus finding status <id> <state>` / `orthrus finding assign <id> <owner>` "
        "(ids in `--json`).[/]"
    )


_UNSET = object()  # sentinel: "owner argument not provided" vs "clear owner to None"


@cli.group(name="finding")
def finding() -> None:
    """Manage a stored finding's triage lifecycle (status / ownership)."""


@finding.command(name="status")
@click.argument("finding_id", type=int)
@click.argument("state", type=click.Choice(FINDING_STATUSES))
@click.option("--verbose", "-v", default="warning", help="Log level.")
def finding_status(finding_id: int, state: str, verbose: str) -> None:
    """Set a finding's triage STATE (open/triaged/in-progress/resolved/…).

    FINDING_ID is the integer id shown by `orthrus findings --json`.
    """
    configure_logging(verbose)
    asyncio.run(_set_finding_field(finding_id, status=state))


@finding.command(name="assign")
@click.argument("finding_id", type=int)
@click.argument("owner")
@click.option("--verbose", "-v", default="warning", help="Log level.")
def finding_assign(finding_id: int, owner: str, verbose: str) -> None:
    """Assign a finding to an OWNER (use '-' to clear the assignment)."""
    configure_logging(verbose)
    asyncio.run(_set_finding_field(finding_id, owner=None if owner == "-" else owner))


async def _set_finding_field(
    finding_id: int, *, status: str | None = None, owner: str | None | object = _UNSET
) -> None:
    settings = get_settings()
    store = Store(settings.db_url, encryption_key=settings.encryption_key)
    try:
        await store.init()
        if status is not None:
            ok = await store.set_finding_status(finding_id, status)
            msg = f"status → {status}"
        else:
            ok = await store.set_finding_owner(finding_id, owner)  # type: ignore[arg-type]
            msg = f"owner → {owner or '(unassigned)'}"
    finally:
        await store.close()
    if ok:
        console.print(f"[status.completed]finding {finding_id}: {msg}[/]")
    else:
        logger.error("no such finding id: %s (see `orthrus findings --scan-id <id> --json`)", finding_id)


@cli.command(name="triage")
@click.option("--scan-id", required=True, help="Scan identifier from a previous run.")
@click.option("--llm", is_flag=True, help="Use an LLM judge to flag likely false positives (needs ORTHRUS_ANTHROPIC_API_KEY).")
@click.option("--model", default=None, help="LLM model id for --llm (default: a fast Claude Haiku).")
@click.option("--json", "as_json", is_flag=True, help="Emit the triaged report as JSON (stdout).")
@click.option("--verbose", "-v", default="warning", help="Log level.")
def triage(scan_id: str, llm: bool, model: str | None, as_json: bool, verbose: str) -> None:
    """Deduplicate + cluster a scan's findings into distinct issues.

    A real scan reports the same bug at many URLs (IDOR on /order/1..999, a
    missing header on every route). This folds id-like URLs together
    (/order/{id}) and clusters by type + location, so a 600-finding list becomes
    the handful of issues that actually need fixing - each with its severity, a
    count, and the affected URLs. With --llm, an LLM judge additionally flags
    clusters that look like false positives (opt-in; no-ops without an API key).
    """
    configure_logging(verbose)
    asyncio.run(_triage_cmd(scan_id, llm, model, as_json))


async def _triage_cmd(scan_id: str, use_llm: bool, model: str | None, as_json: bool) -> None:
    from orthrus.triage import DEFAULT_MODEL, llm_assess, triage_findings

    settings = get_settings()
    store = Store(settings.db_url, encryption_key=settings.encryption_key)
    try:
        await store.init()
        scan = await store.get_scan(scan_id)
        rows = await store.get_findings(scan_id) if scan is not None else []
    finally:
        await store.close()
    if scan is None:
        logger.error("no such scan: %s (list scans with `orthrus scans`)", scan_id)
        return

    report = triage_findings(rows)

    verdicts: dict[int, object] = {}
    if use_llm:
        api_key = os.environ.get("ORTHRUS_ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            logger.warning(
                "--llm requested but ORTHRUS_ANTHROPIC_API_KEY/ANTHROPIC_API_KEY is unset; "
                "showing dedup/cluster triage without the LLM judge"
            )
        else:
            for cluster in report.clusters:
                verdict = await llm_assess(cluster, api_key, model=model or DEFAULT_MODEL)
                if verdict is not None:
                    verdicts[id(cluster)] = verdict

    if as_json:
        out = report.to_dict()
        for cluster_dict, cluster in zip(out["clusters"], report.clusters, strict=False):
            v = verdicts.get(id(cluster))
            if v is not None:
                cluster_dict["false_positive"] = {
                    "is_fp": v.is_false_positive, "confidence": v.confidence,
                    "rationale": v.rationale,
                }
        click.echo(json.dumps(out, indent=2))
        return

    from rich.table import Table

    section(console, f"TRIAGE · {scan_id}")
    console.print(report.summary() + "\n")
    if not report.clusters:
        console.print("[orthrus.muted]No findings to triage.[/]")
        return
    table = Table(border_style="orthrus.muted")
    table.add_column("Severity")
    table.add_column("Type", style="orthrus.accent")
    table.add_column("Issue (templated)", style="orthrus.muted", overflow="fold")
    table.add_column("×", justify="right")
    if verdicts:
        table.add_column("Judge")
    for cluster in report.clusters:
        where = cluster.template + (f"  [{cluster.parameter}]" if cluster.parameter else "")
        row = [cluster.severity, cluster.vuln_type, where, str(cluster.count)]
        if verdicts:
            v = verdicts.get(id(cluster))
            if v is None:
                row.append("-")
            elif v.is_false_positive:
                row.append("[status.failed]likely FP[/]")
            else:
                row.append("[status.completed]real[/]")
        table.add_row(*row)
    console.print(table)


@cli.command(name="chains")
@click.option("--scan-id", required=True, help="Scan identifier from a previous run.")
@click.option("--json", "as_json", is_flag=True, help="Emit the attack paths as JSON (stdout).")
@click.option("--verbose", "-v", default="warning", help="Log level.")
def chains(scan_id: str, as_json: bool, verbose: str) -> None:
    """Correlate a scan's findings into attack paths (kill-chains).

    A flat finding list hides impact: one SSRF and one exposed Redis are two
    mediums - together they're RCE on the internal network. This matches the
    findings against a catalog of known attack chains and shows the paths an
    attacker would actually walk, each with an escalated severity and an impact
    narrative, prioritised above the raw list.
    """
    configure_logging(verbose)
    asyncio.run(_chains_cmd(scan_id, as_json))


async def _chains_cmd(scan_id: str, as_json: bool) -> None:
    from orthrus.chains import build_chain_report

    settings = get_settings()
    store = Store(settings.db_url, encryption_key=settings.encryption_key)
    try:
        await store.init()
        scan = await store.get_scan(scan_id)
        rows = await store.get_findings(scan_id) if scan is not None else []
    finally:
        await store.close()
    if scan is None:
        logger.error("no such scan: %s (list scans with `orthrus scans`)", scan_id)
        return

    report = build_chain_report(rows)

    if as_json:
        click.echo(json.dumps(report.to_dict(), indent=2))
        return

    section(console, f"ATTACK PATHS · {scan_id}")
    console.print(report.summary() + "\n")
    if not report.chains:
        console.print(
            "[orthrus.muted]No multi-step attack chains correlated from the current findings.[/]"
        )
        return
    for chain in report.chains:
        sev_style = {
            "critical": "status.failed", "high": "status.running",
        }.get(chain.severity, "orthrus.muted")
        console.print(
            f"[{sev_style}]\\[{chain.severity.upper()}][/] [orthrus.accent]{chain.name}[/] "
            f"[orthrus.muted]@ {chain.host}[/]"
        )
        for i, step in enumerate(chain.steps, 1):
            console.print(f"   [orthrus.muted]{i}.[/] {step.label} [orthrus.muted]({step.vuln_type})[/]")
        console.print(f"   [orthrus.muted]→ {chain.impact}[/]\n")


@cli.command(name="graph")
@click.option("--scan-id", required=True, help="Scan identifier from a previous run.")
@click.option("--json", "as_json", is_flag=True, help="Emit the attack graph as JSON (stdout).")
@click.option("--verbose", "-v", default="warning", help="Log level.")
def graph(scan_id: str, as_json: bool, verbose: str) -> None:
    """Collapse a scan's findings into the few reachable attack paths.

    Where `chains` matches each catalog rule independently, this builds a
    reachability graph and *merges* rules that share a finding into maximal
    kill-chains - e.g. LFI → exposed-secret → JWT-forgery becomes one three-step
    path. Reports how many raw findings collapse onto how few reachable paths.
    """
    configure_logging(verbose)
    asyncio.run(_graph_cmd(scan_id, as_json))


async def _graph_cmd(scan_id: str, as_json: bool) -> None:
    from orthrus.attack_graph import build_attack_graph

    settings = get_settings()
    store = Store(settings.db_url, encryption_key=settings.encryption_key)
    try:
        await store.init()
        scan = await store.get_scan(scan_id)
        rows = await store.get_findings(scan_id) if scan is not None else []
    finally:
        await store.close()
    if scan is None:
        logger.error("no such scan: %s (list scans with `orthrus scans`)", scan_id)
        return

    report = build_attack_graph(rows)

    if as_json:
        click.echo(json.dumps(report.to_dict(), indent=2))
        return

    section(console, f"ATTACK GRAPH · {scan_id}")
    console.print(report.summary() + "\n")
    if not report.paths:
        console.print(
            "[orthrus.muted]No reachable attack paths from the current findings.[/]"
        )
        return
    for p in report.paths:
        sev_style = {
            "critical": "status.failed", "high": "status.running",
        }.get(p.severity, "orthrus.muted")
        console.print(
            f"[{sev_style}]\\[{p.severity.upper()}][/] "
            f"[orthrus.accent]{p.length}-step path[/] [orthrus.muted]@ {p.host}[/]"
        )
        console.print(
            "   " + " [orthrus.muted]→[/] ".join(f"{s.vuln_type}" for s in p.steps)
        )
        console.print(f"   [orthrus.muted]⇒ {p.impact}[/]\n")


@cli.command(name="notify")
@click.option("--scan-id", required=True, help="Scan identifier from a previous run.")
@click.option(
    "--min-severity", default="high",
    type=click.Choice(["critical", "high", "medium", "low", "info"]),
    help="Only notify on findings at or above this severity.",
)
@click.option("--slack", "slack_webhook", default=None, envvar="ORTHRUS_SLACK_WEBHOOK",
              help="Slack incoming-webhook URL (or ORTHRUS_SLACK_WEBHOOK).")
@click.option("--jira-url", default=None, envvar="ORTHRUS_JIRA_URL", help="Jira base URL.")
@click.option("--jira-user", default=None, envvar="ORTHRUS_JIRA_USER", help="Jira account email.")
@click.option("--jira-token", default=None, envvar="ORTHRUS_JIRA_TOKEN", help="Jira API token.")
@click.option("--jira-project", default=None, envvar="ORTHRUS_JIRA_PROJECT", help="Jira project key.")
@click.option("--dry-run", is_flag=True, help="Print the payloads instead of sending them.")
@click.option("--verbose", "-v", default="warning", help="Log level.")
def notify(
    scan_id: str,
    min_severity: str,
    slack_webhook: str | None,
    jira_url: str | None,
    jira_user: str | None,
    jira_token: str | None,
    jira_project: str | None,
    dry_run: bool,
    verbose: str,
) -> None:
    """Push a scan's high-severity findings to Slack and/or Jira.

    Slack sends one summary message; Jira opens one issue per finding. Credentials
    come from flags or ORTHRUS_SLACK_WEBHOOK / ORTHRUS_JIRA_* env vars. Use
    --dry-run to preview the exact payloads without sending anything.
    """
    configure_logging(verbose)
    jira = (jira_url, jira_user, jira_token, jira_project)
    if not slack_webhook and not all(jira):
        raise click.UsageError(
            "specify --slack <webhook> and/or all of --jira-url/--jira-user/--jira-token/--jira-project"
        )
    asyncio.run(_notify_cmd(scan_id, min_severity, slack_webhook, jira, dry_run))


async def _notify_cmd(
    scan_id: str, min_severity: str, slack_webhook: str | None, jira: tuple, dry_run: bool
) -> None:
    from orthrus.integrations.notify import (
        at_or_above,
        create_jira_issues,
        jira_issue,
        send_slack,
        slack_message,
    )

    settings = get_settings()
    store = Store(settings.db_url, encryption_key=settings.encryption_key)
    try:
        await store.init()
        scan = await store.get_scan(scan_id)
        rows = await store.get_findings(scan_id) if scan is not None else []
    finally:
        await store.close()
    if scan is None:
        logger.error("no such scan: %s (list scans with `orthrus scans`)", scan_id)
        return

    selected = at_or_above(rows, min_severity)
    if not selected:
        console.print(f"[orthrus.muted]No findings at or above '{min_severity}' - nothing to notify.[/]")
        return

    if slack_webhook:
        payload = slack_message(scan_id, scan.target, rows, min_severity)
        if dry_run:
            section(console, "SLACK (dry-run)")
            click.echo(json.dumps(payload, indent=2, ensure_ascii=False))
        else:
            ok = await send_slack(slack_webhook, payload)
            console.print(
                f"[status.completed]Slack: sent summary of {len(selected)} finding(s)[/]"
                if ok else "[status.failed]Slack: send failed (see log)[/]"
            )

    if all(jira):
        jira_url, jira_user, jira_token, jira_project = jira
        if dry_run:
            section(console, "JIRA (dry-run)")
            for r in selected[:3]:
                click.echo(json.dumps(jira_issue(r, jira_project, scan_id), indent=2, ensure_ascii=False))
            if len(selected) > 3:
                console.print(f"[orthrus.muted]…and {len(selected) - 3} more issue(s).[/]")
        else:
            keys = await create_jira_issues(
                jira_url, jira_user, jira_token, jira_project, selected, scan_id
            )
            console.print(f"[status.completed]Jira: created {len(keys)} issue(s): {', '.join(keys)}[/]")


@cli.command(name="runbook")
@click.option("--scan-id", required=True, help="Scan identifier from a previous run.")
@click.option(
    "--min-severity", default="info",
    type=click.Choice(["critical", "high", "medium", "low", "info"]),
    help="Only include findings at or above this severity.",
)
@click.option("--output", "-o", type=click.Path(dir_okay=False, writable=True), default=None,
              help="Write the runbook to this file instead of stdout.")
@click.option("--json", "as_json", is_flag=True, help="Emit machine-readable JSON instead of Markdown.")
@click.option("--verbose", "-v", default="warning", help="Log level.")
def runbook(scan_id: str, min_severity: str, output: str | None, as_json: bool, verbose: str) -> None:
    """Consolidated remediation runbook - the few fixes that retire a scan's risk.

    Collapses findings that share a fix into one prioritised action, ordered so the
    highest-leverage change (one that breaks a correlated attack path) is first.
    Emits Markdown to stdout by default; use -o to write a file or --json for data.
    """
    configure_logging(verbose)
    # DB I/O runs in the async loop; rendering + file write stay in this sync layer.
    report = asyncio.run(_runbook_load(scan_id, min_severity))
    if report is None:
        return
    if as_json:
        click.echo(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))
        return
    markdown = report.to_markdown()
    if output:
        with open(output, "w", encoding="utf-8") as fh:
            fh.write(markdown)
        console.print(f"[status.completed]Runbook written to {output}[/] - {report.summary()}")
    else:
        click.echo(markdown)


async def _runbook_load(scan_id: str, min_severity: str):
    """Load a scan's findings, filter by severity, and build the runbook (or None)."""
    from orthrus.reporting.runbook import build_runbook

    settings = get_settings()
    store = Store(settings.db_url, encryption_key=settings.encryption_key)
    try:
        await store.init()
        scan = await store.get_scan(scan_id)
        rows = await store.get_findings(scan_id) if scan is not None else []
    finally:
        await store.close()
    if scan is None:
        logger.error("no such scan: %s (list scans with `orthrus scans`)", scan_id)
        return None

    order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    floor = order[min_severity]

    def _rank(row: object) -> int:
        sev = getattr(row, "severity", "info")
        return order.get(getattr(sev, "value", sev) or "info", 0)

    rows = [r for r in rows if _rank(r) >= floor]
    return build_runbook(rows, target=scan.target, scan_id=scan_id)


@cli.command(name="patch")
@click.option("--scan-id", required=True, help="Scan identifier from a previous run.")
@click.option(
    "--min-severity", default="info",
    type=click.Choice(["critical", "high", "medium", "low", "info"]),
    help="Only patch findings at or above this severity.",
)
@click.option("--vuln-type", default=None, help="Only generate patches for this vuln_type.")
@click.option("--llm", "use_llm", is_flag=True,
              help="Ask an Anthropic model for a patch where no template fits (needs API key).")
@click.option("--model", default=None, help="LLM model id (with --llm).")
@click.option("--output", "-o", type=click.Path(dir_okay=False, writable=True), default=None,
              help="Write the patch bundle to this file instead of stdout.")
@click.option("--json", "as_json", is_flag=True, help="Emit machine-readable JSON instead of Markdown.")
@click.option("--verbose", "-v", default="warning", help="Log level.")
def patch(
    scan_id: str, min_severity: str, vuln_type: str | None, use_llm: bool, model: str | None,
    output: str | None, as_json: bool, verbose: str,
) -> None:
    """Generate concrete remediation patches (config/code) for a scan's findings.

    Groups findings by fix and attaches paste-able templated patches per vuln type
    (security headers, parameterized queries, cookie flags, CSP, Terraform for cloud
    posture, …). With --llm, types without a template get a context-specific patch
    from an Anthropic model (opt-in, best-effort). Markdown to stdout by default.
    """
    configure_logging(verbose)
    report = asyncio.run(_patch_load(scan_id, min_severity, vuln_type, use_llm, model))
    if report is None:
        return
    if as_json:
        click.echo(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))
        return
    markdown = report.to_markdown()
    if output:
        with open(output, "w", encoding="utf-8") as fh:
            fh.write(markdown)
        console.print(f"[status.completed]Patches written to {output}[/] - {report.summary()}")
    else:
        click.echo(markdown)


async def _patch_load(
    scan_id: str, min_severity: str, vuln_type: str | None, use_llm: bool, model: str | None
):
    """Load findings, build the deterministic patch report, optionally LLM-enrich."""
    from orthrus.reporting.patches import build_patch_report, llm_patch, normalize_vuln_type
    from orthrus.triage import DEFAULT_MODEL

    settings = get_settings()
    store = Store(settings.db_url, encryption_key=settings.encryption_key)
    try:
        await store.init()
        scan = await store.get_scan(scan_id)
        rows = await store.get_findings(scan_id) if scan is not None else []
    finally:
        await store.close()
    if scan is None:
        logger.error("no such scan: %s (list scans with `orthrus scans`)", scan_id)
        return None

    order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    floor = order[min_severity]

    def _rank(row: object) -> int:
        sev = getattr(row, "severity", "info")
        return order.get(getattr(sev, "value", sev) or "info", 0)

    rows = [r for r in rows if _rank(r) >= floor]
    if vuln_type:
        rows = [r for r in rows if getattr(r, "vuln_type", "") == vuln_type]
    report = build_patch_report(rows, target=scan.target, scan_id=scan_id)

    if use_llm:
        api_key = os.environ.get("ORTHRUS_ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            logger.warning("--llm requested but ORTHRUS_ANTHROPIC_API_KEY/ANTHROPIC_API_KEY is unset; "
                           "emitting templated patches only")
        else:
            reps: dict[str, object] = {}
            for r in rows:
                reps.setdefault(normalize_vuln_type(getattr(r, "vuln_type", "") or "finding"), r)
            for g in report.groups:
                if not g.patches and g.vuln_type in reps:
                    ai = await llm_patch(reps[g.vuln_type], api_key, model=model or DEFAULT_MODEL)
                    if ai is not None:
                        g.patches.append(ai)
    return report


@cli.command(name="ai-report")
@click.option("--scan-id", required=True, help="Scan identifier to report on.")
@click.option("--llm", "llm_spec", default="anthropic",
              help="Model spec 'provider:model' - anthropic / openai / openai-compatible / ollama "
                   "(e.g. 'ollama:llama3.1', 'openai:gpt-4o'). Keys/base-url from env.")
@click.option("--model", default=None, help="Override the model id.")
@click.option("--output", "-o", default="orthrus_ai_report", help="Output file (extension set by --format).")
@click.option("--format", "output_format", type=click.Choice(["md", "html", "pdf"]), default="md",
              help="Deliverable format. html/pdf render a styled Big-Four document; "
                   "pdf reuses the Chromium pipeline (needs the [browser] extra).")
@click.option("--group/--no-group", default=True,
              help="Group like findings (same type + title) into one entry with an "
                   "affected-instances table. On by default.")
@click.option("--min-severity", default=None, help="Only include findings at/above this severity.")
@click.option("--max-detailed", default=60, type=int, help="Max findings given a full AI narrative.")
@click.option("--temperature", default=0.3, type=float, help="Model temperature.")
@click.option("--dry-run", is_flag=True,
              help="Assemble the full report scaffold + recorded evidence with NO model calls.")
@click.option("--verbose", "-v", default="info", help="Log level.")
def ai_report(
    scan_id: str, llm_spec: str, model: str | None, output: str, output_format: str,
    group: bool, min_severity: str | None, max_detailed: int, temperature: float,
    dry_run: bool, verbose: str,
) -> None:
    """Generate a Big-Four-grade consultant report - deterministic evidence + AI narrative.

    Every finding, CVSS score, and recorded request/response is rendered verbatim; a language
    model writes the consultant prose around those facts (executive summary, per-finding
    impact/likelihood/exploitation/remediation, attack-chain stories, remediation roadmap).
    The model can be local (ollama) or any market model. --dry-run shows the full structure and
    evidence without any model call.
    """
    configure_logging(verbose)
    markdown = asyncio.run(
        _ai_report_build(scan_id, llm_spec, model, min_severity, max_detailed, temperature,
                         dry_run, group)
    )
    if markdown is None:
        return
    stem = re.sub(r"\.(md|markdown|html?|pdf)$", "", output, flags=re.IGNORECASE)

    if output_format == "md":
        path = stem + ".md"
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(markdown)
        console.print(
            f"[status.completed]Consultant report written to {path}[/] - "
            f"{len(markdown):,} chars, {markdown.count(chr(10)) + 1} lines."
        )
        return

    from orthrus.ai.render import markdown_to_html
    html = markdown_to_html(markdown, title=f"Penetration Test Report - {scan_id}")
    html_path = stem + ".html"
    with open(html_path, "w", encoding="utf-8") as fh:
        fh.write(html)

    if output_format == "html":
        console.print(f"[status.completed]Consultant report written to {html_path}[/] "
                      f"- {len(html):,} chars.")
        return

    # pdf: render the HTML we just wrote through the headless-Chromium pipeline
    from orthrus.reporting.pdf import html_to_pdf
    pdf_path = stem + ".pdf"
    ok = asyncio.run(html_to_pdf(html_path, pdf_path))
    if ok:
        console.print(f"[status.completed]Consultant report written to {pdf_path}[/] "
                      f"(styled HTML kept at {html_path}).")
    else:
        console.print(
            f"[status.error]PDF rendering unavailable[/] - kept the HTML deliverable at "
            f"{html_path}. Install the browser extra (`pip install -e .[browser]` then "
            f"`playwright install chromium`) to emit PDF."
        )


async def _ai_report_build(scan_id, llm_spec, model, min_severity, max_detailed, temperature,
                           dry_run, group=True):
    from orthrus.ai.providers import LLMClient, resolve_config
    from orthrus.ai.report_writer import write_consultant_report
    from orthrus.reporting.generator import _build_context

    settings = get_settings()
    store = Store(settings.db_url, encryption_key=settings.encryption_key)
    try:
        await store.init()
        if await store.get_scan(scan_id) is None:
            logger.error("no such scan: %s (list scans with `orthrus scans`)", scan_id)
            return None
        context = await _build_context(store, scan_id, None, min_severity)
    finally:
        await store.close()

    client = None
    if not dry_run:
        cfg = resolve_config(llm_spec, model=model, temperature=temperature)
        if cfg.provider in ("anthropic", "openai", "openai-compatible") and not cfg.api_key:
            logger.error(
                "model '%s' needs an API key - set ORTHRUS_LLM_API_KEY (or ANTHROPIC_API_KEY / "
                "OPENAI_API_KEY), use a local model (--llm ollama:<model>), or --dry-run",
                cfg.provider,
            )
            return None
        client = LLMClient(cfg)
        console.print(
            f"[orthrus.muted]drafting with {cfg.provider}:{cfg.model}"
            f"{' (local, no data leaves host)' if cfg.is_local else ''} · "
            f"{context['summary']['total']} finding(s)…[/]"
        )
    return await write_consultant_report(
        context, client, group=group, max_detailed=max_detailed, dry_run=dry_run,
        log=lambda m: logger.info("ai-report: %s", m),
    )


@cli.command(name="surface")
@click.option("--scan-id", required=True, help="Scan whose recon to visualize.")
@click.option("--output", "-o", default="orthrus_surface", help="Output HTML file.")
@click.option("--verbose", "-v", default="info", help="Log level.")
def surface(scan_id: str, output: str, verbose: str) -> None:
    """Render a scan's recon (hosts / ports / technologies / endpoints) as an
    interactive attack-surface graph - a self-contained HTML page."""
    configure_logging(verbose)
    markup = asyncio.run(_surface_build(scan_id))
    if markup is None:
        return
    path = output if output.endswith((".html", ".htm")) else output + ".html"
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(markup)
    console.print(f"[status.completed]Attack-surface map written to {path}[/] - open it in a browser.")


async def _surface_build(scan_id: str) -> str | None:
    from orthrus.reporting.surface import render_surface_html

    settings = get_settings()
    store = Store(settings.db_url, encryption_key=settings.encryption_key)
    try:
        await store.init()
        scan = await store.get_scan(scan_id)
        if scan is None:
            logger.error("no such scan: %s (list scans with `orthrus scans`)", scan_id)
            return None
        assets = await store.get_assets(scan_id)
        endpoints = await store.get_endpoints(scan_id)
        return render_surface_html(scan.target, assets, endpoints)
    finally:
        await store.close()


@cli.command(name="replay")
@click.option("--request-file", "request_file", type=click.Path(exists=True, dir_okay=False),
              default=None, help="Raw HTTP request file (Burp-style paste).")
@click.option("--scan-id", default=None, help="Replay a finding's recorded request from this scan.")
@click.option("--finding-id", "finding_id", default=None,
              help="Finding id (with --scan-id) whose recorded request to replay.")
@click.option("--url", default=None, help="Ad-hoc URL to request, or override the source URL.")
@click.option("--method", default=None, help="Override the HTTP method.")
@click.option("--header", "headers", multiple=True,
              help="Add/override a header 'Name: value' (repeatable).")
@click.option("--body", default=None, help="Override the request body.")
@click.option("--scope", "scope_str", default=None, help="Scope token(s); defaults to the request host.")
@click.option("--scheme", default="https", help="Scheme for origin-form raw requests (default https).")
@click.option("--repeat", default=1, type=int, help="Send the request N times (timing/consistency).")
@click.option("--follow-redirects", is_flag=True, help="Follow redirects.")
@click.option("--show-body", is_flag=True, help="Print the full response body (default: a preview).")
@click.option("--verbose", "-v", default="info", help="Log level.")
def replay(
    request_file: str | None, scan_id: str | None, finding_id: str | None, url: str | None,
    method: str | None, headers: tuple[str, ...], body: str | None, scope_str: str | None,
    scheme: str, repeat: int, follow_redirects: bool, show_body: bool, verbose: str,
) -> None:
    """Resend a recorded request with optional tweaks - the mini-Repeater.

    Source the request from a finding (`--scan-id --finding-id`), a raw request
    file (`--request-file`), or an ad-hoc `--url`; tweak it with `--method`,
    `--header`, `--body`, `--url`; and observe the response. Scope-enforced.
    """
    configure_logging(verbose)
    raw_request = None
    if request_file:  # read here (sync) so the async worker never blocks on file I/O
        with open(request_file, encoding="utf-8") as fh:
            raw_request = fh.read()
    asyncio.run(_replay_run(
        raw_request, scan_id, finding_id, url, method, headers, body, scope_str,
        scheme, repeat, follow_redirects, show_body,
    ))


async def _replay_run(
    raw_request, scan_id, finding_id, url, method, headers, body, scope_str,
    scheme, repeat, follow_redirects, show_body,
) -> None:
    from urllib.parse import urlsplit

    from orthrus.proxy.replay import RequestSpec, parse_raw_http
    from orthrus.proxy.replay import replay as do_replay
    from orthrus.utils.scope import ScopeValidator

    spec: RequestSpec | None = None
    if raw_request is not None:
        spec = parse_raw_http(raw_request, default_scheme=scheme)
    elif scan_id and finding_id:
        settings = get_settings()
        store = Store(settings.db_url, encryption_key=settings.encryption_key)
        try:
            await store.init()
            pairs = await store.get_findings_with_ids(scan_id)
            match = next((f for fid, f in pairs if str(fid) == finding_id or f.id == finding_id), None)
        finally:
            await store.close()
        if match is None:
            logger.error("finding '%s' not found in scan '%s'", finding_id, scan_id)
            return
        raw = match.evidence.request_raw if match.evidence else None
        if not raw:
            logger.error("finding '%s' has no recorded request to replay", finding_id)
            return
        spec = parse_raw_http(raw, default_scheme=urlsplit(match.url).scheme or scheme)
        if not urlsplit(spec.url).netloc:
            spec = spec.tweaked(url=match.url)
    elif url:
        spec = RequestSpec(method=(method or "GET").upper(), url=url)
    else:
        logger.error("give a request source: --request-file, --scan-id/--finding-id, or --url")
        return

    hdr_overrides: dict[str, str] = {}
    for raw_hdr in headers:
        name, sep, value = raw_hdr.partition(":")
        if sep:
            hdr_overrides[name.strip()] = value.strip()
    spec = spec.tweaked(method=method, url=url, set_headers=hdr_overrides or None, body=body)

    host = urlsplit(spec.url).netloc.split("@")[-1].split(":")[0]
    scope = build_scope(scope_str or host, spec.url, None)
    validator = ScopeValidator(scope)

    console.print(f"[orthrus.muted]{spec.method} {spec.url}[/]")
    for i in range(max(1, repeat)):
        result = await do_replay(spec, validator, follow_redirects=follow_redirects)
        if not result.ok:
            console.print(f"[status.error]{result.error}[/]")
            continue
        tag = f" [{i + 1}/{repeat}]" if repeat > 1 else ""
        console.print(
            f"[status.completed]{result.status} {result.reason}[/]{tag} · "
            f"{result.elapsed_ms} ms · {len(result.body):,} bytes"
        )
        if show_body:
            console.print(result.body)
        elif i == 0 and result.body:
            preview = result.body[:400]
            console.print(f"[orthrus.muted]{preview}{'…' if len(result.body) > 400 else ''}[/]")


@cli.command(name="hosts")
@click.argument("target", required=False)
@click.option("--scope", "scope_str", default=None, help="Scope token(s); defaults to the target host (+subdomains).")
@click.option("--scan-id", default=None, help="List hosts from a stored scan instead of gathering live.")
@click.option("--no-reverse-ip", "no_reverse_ip", is_flag=True, help="Skip reverse-IP / co-hosting lookup.")
@click.option("--no-netblock", "no_netblock", is_flag=True, help="Skip the /24 reverse-DNS sweep.")
@click.option("--no-ct", "no_ct", is_flag=True, help="Skip Certificate Transparency (crt.sh).")
@click.option("--no-wayback", "no_wayback", is_flag=True, help="Skip Wayback Machine hostnames.")
@click.option("--in-scope-only", is_flag=True, help="Hide co-hosted / out-of-scope hosts.")
@click.option("--json", "as_json", is_flag=True, help="Emit the host inventory as JSON (stdout).")
@click.option("--csv", "csv_path", default=None, help="Write the host inventory to a CSV file.")
@click.option("--exclude-paths", default=None, help="Comma-separated regex paths to exclude (scope).")
@click.option("--verbose", "-v", default="warning", help="Log level.")
def hosts(
    target: str | None,
    scope_str: str | None,
    scan_id: str | None,
    no_reverse_ip: bool,
    no_netblock: bool,
    no_ct: bool,
    no_wayback: bool,
    in_scope_only: bool,
    as_json: bool,
    csv_path: str | None,
    exclude_paths: str | None,
    verbose: str,
) -> None:
    """Gather and list the host footprint for a TARGET (or a stored scan).

    Casts a passive net - Certificate Transparency, reverse-IP / co-hosting, a
    /24 reverse-DNS sweep, and Wayback - and folds the results into one
    deduplicated inventory. In-scope hosts are listed first; co-hosted hosts
    that fall outside scope are shown (flagged) for situational awareness but are
    never scanned. Use --scan-id to instead list the hosts a prior scan stored.
    """
    configure_logging(verbose)
    if not target and not scan_id:
        raise click.UsageError("provide a TARGET to gather, or --scan-id to list a stored scan.")
    asyncio.run(
        _gather_hosts_cmd(
            target, scope_str, scan_id, exclude_paths,
            reverse_ip=not no_reverse_ip, netblock=not no_netblock,
            ct_logs=not no_ct, wayback=not no_wayback,
            in_scope_only=in_scope_only, as_json=as_json, csv_path=csv_path,
        )
    )


async def _gather_hosts_cmd(
    target, scope_str, scan_id, exclude_paths, *,
    reverse_ip, netblock, ct_logs, wayback, in_scope_only, as_json, csv_path,
):
    from orthrus.recon.host_gathering import GatheredHost, _host_of, gather_hosts

    label = scan_id or _host_of(target)
    if scan_id:
        settings = get_settings()
        store = Store(settings.db_url, encryption_key=settings.encryption_key)
        try:
            await store.init()
            scan = await store.get_scan(scan_id)
            assets = await store.get_assets(scan_id) if scan is not None else []
        finally:
            await store.close()
        if scan is None:
            logger.error("no such scan: %s (list scans with `orthrus scans`)", scan_id)
            return
        rows = [
            GatheredHost(
                fqdn=a.fqdn, ips=list(a.ips),
                sources=[a.discovery_method], in_scope=True,
            )
            for a in assets
        ]
        rows.sort(key=lambda g: g.fqdn)
    else:
        from orthrus.utils.scope import ScopeValidator

        host = _host_of(target)
        scope_cfg = build_scope(scope_str, target, exclude_paths)
        _log_scope(scope_cfg)
        logger.warning("gathering hosts for %s - this queries CT/Wayback/reverse-IP and sweeps a /24…", host)
        rows = await gather_hosts(
            host, ScopeValidator(scope_cfg),
            reverse_ip=reverse_ip, netblock=netblock, ct_logs=ct_logs, wayback=wayback,
        )

    if in_scope_only:
        rows = [g for g in rows if g.in_scope]

    if as_json:
        click.echo(json.dumps(
            [{"fqdn": g.fqdn, "ips": g.ips, "sources": g.sources, "in_scope": g.in_scope}
             for g in rows],
            indent=2,
        ))
    if csv_path:
        await asyncio.to_thread(_write_hosts_csv, csv_path, rows)
        logger.info("wrote %d host(s) to %s", len(rows), csv_path)
    if as_json:
        return

    from rich.table import Table

    in_scope = sum(1 for g in rows if g.in_scope)
    section(console, f"HOSTS · {label}")
    if not rows:
        console.print("[orthrus.muted]No hosts gathered.[/]")
        return
    table = Table(border_style="orthrus.muted")
    table.add_column("Host", style="orthrus.accent", no_wrap=True)
    table.add_column("IP(s)")
    table.add_column("Sources", style="orthrus.muted")
    table.add_column("Scope")
    for g in rows:
        scope_cell = (
            "[status.completed]in-scope[/]" if g.in_scope else "[orthrus.muted]co-hosted[/]"
        )
        table.add_row(
            g.fqdn,
            ", ".join(g.ips) or "[orthrus.muted]-[/]",
            ", ".join(g.sources),
            scope_cell,
        )
    console.print(table)
    console.print(
        f"\n[orthrus.muted]{len(rows)} host(s) gathered · "
        f"{in_scope} in-scope · {len(rows) - in_scope} co-hosted/out-of-scope[/]"
    )


def _write_hosts_csv(csv_path: str, rows: list) -> None:
    """Write the gathered host inventory to a CSV file (sync; runs off-loop)."""
    import csv as _csv

    with open(csv_path, "w", newline="", encoding="utf-8") as fh:
        writer = _csv.writer(fh)
        writer.writerow(["fqdn", "ips", "sources", "in_scope"])
        for g in rows:
            writer.writerow([g.fqdn, ";".join(g.ips), ";".join(g.sources), g.in_scope])


@cli.command(name="monitor")
@click.argument("target", required=False)
@click.option("--target-file", "target_file", default=None, help="File of targets (one per line; '#' comments ok) to monitor as a portfolio.")
@click.option("--scope", "scope_str", default=None, help="Scope token(s); defaults to the target host (+subdomains).")
@click.option("--baseline", default=None, help="Scan id to diff against (default: this target's most recent prior scan).")
@click.option("--webhook", default=None, help="POST a JSON drift alert to this URL (Slack/Teams/custom).")
@click.option("--fail-on-change", is_flag=True, help="Exit non-zero when drift is detected (for cron/CI).")
@click.option("--deep", is_flag=True, help="Run a full vuln scan and also report NEW/RESOLVED findings (not just hosts).")
@click.option("--watch", default=None, type=int, metavar="SECONDS", help="Run continuously, re-snapshotting every N seconds (Ctrl-C to stop).")
@click.option("--max-runs", default=0, type=int, help="With --watch, stop after N iterations (0 = run until stopped).")
@click.option("--no-host-gather", "no_host_gather", is_flag=True, help="Skip the host-gather pass (faster, fewer sources).")
@click.option("--json", "as_json", is_flag=True, help="Emit the drift report as JSON (stdout).")
@click.option("--exclude-paths", default=None, help="Comma-separated regex paths to exclude (scope).")
@click.option("--scan-id", default=None, help="Custom scan identifier for this snapshot.")
@click.option("--rate-limit", default=50.0, type=float, help="Max requests/sec per domain.")
@click.option("--timeout", default=30.0, type=float, help="HTTP request timeout (s).")
@click.option("--verbose", "-v", default="info", help="Log level.")
def monitor(
    target: str | None,
    target_file: str | None,
    scope_str: str | None,
    baseline: str | None,
    webhook: str | None,
    fail_on_change: bool,
    deep: bool,
    watch: int | None,
    max_runs: int,
    no_host_gather: bool,
    as_json: bool,
    exclude_paths: str | None,
    scan_id: str | None,
    rate_limit: float,
    timeout: float,
    verbose: str,
) -> None:
    """Re-scan a TARGET and report drift vs the previous run.

    Continuous monitoring: each run takes a fresh snapshot, stores it, and diffs
    it against the target's previous snapshot. By default it monitors the
    *attack surface* (recon only) - hosts that appeared/vanished, new IPs, newly
    exposed ports. With --deep it runs a full vulnerability scan and also reports
    NEW and RESOLVED findings. Use --watch to run hands-off on an interval (each
    pass auto-diffs against the previous one), --webhook to get paged on change,
    and --fail-on-change for a CI gate.
    """
    configure_logging(verbose)
    if not target and not target_file:
        raise click.UsageError("provide a TARGET or --target-file.")
    if target and target_file:
        raise click.UsageError("use either a TARGET or --target-file, not both.")

    # Portfolio monitoring: one drift pass per target, consolidated summary.
    if target_file:
        targets = _read_targets(target_file)
        if not targets:
            raise click.UsageError(f"no targets found in {target_file}")
        any_change = asyncio.run(_monitor_batch(
            targets, scope_str, webhook, deep, no_host_gather, exclude_paths, rate_limit, timeout
        ))
        if fail_on_change and any_change:
            raise SystemExit(2)
        return

    scope = build_scope(scope_str, target, exclude_paths)
    config = ScanConfig(scan_id=scan_id, target=target, scope=scope, timeout=timeout)
    config.rate_limit.requests_per_second = rate_limit
    config.use_browser = deep  # browser only matters for the deep vuln scan
    _log_scope(scope)
    if watch:
        try:
            asyncio.run(_watch_monitor(
                config, baseline, webhook, deep, no_host_gather, as_json, watch, max_runs
            ))
        except KeyboardInterrupt:
            logger.info("monitor watch stopped")
        return  # a CI gate makes no sense for an endless watch loop
    changed = asyncio.run(_monitor(config, baseline, webhook, deep, no_host_gather, as_json))
    if fail_on_change and changed:
        raise SystemExit(2)


async def _monitor_batch(
    targets: list[str],
    scope_str: str | None,
    webhook: str | None,
    deep: bool,
    no_host_gather: bool,
    exclude_paths: str | None,
    rate_limit: float,
    http_timeout: float,
) -> bool:
    """Run one drift pass per target (portfolio ASM), then a consolidated summary.

    Each target gets its own auto-derived scope and chains against its own prior
    snapshot. Returns True if *any* target drifted (drives --fail-on-change).
    """
    results: list[tuple[str, bool]] = []
    for t in targets:
        scope = build_scope(scope_str, t, exclude_paths)
        config = ScanConfig(target=t, scope=scope, timeout=http_timeout)
        config.rate_limit.requests_per_second = rate_limit
        config.use_browser = deep
        logger.info("monitor portfolio: %s (%d/%d)", t, len(results) + 1, len(targets))
        changed = await _monitor(config, None, webhook, deep, no_host_gather, as_json=False)
        results.append((t, changed))

    drifted = [t for t, c in results if c]
    section(console, "MONITOR · PORTFOLIO")
    console.print(
        f"[orthrus.muted]{len(results)} target(s) monitored · "
        f"{len(drifted)} with drift[/]\n"
    )
    for t, c in results:
        mark = "[status.failed]drift[/]" if c else "[status.completed]no change[/]"
        console.print(f"  {mark}  {t}")
    return bool(drifted)


async def _watch_monitor(
    config: ScanConfig,
    baseline_id: str | None,
    webhook: str | None,
    deep: bool,
    no_host_gather: bool,
    as_json: bool,
    interval: int,
    max_runs: int,
) -> None:
    """Run :func:`_monitor` on a fixed interval (hands-off continuous ASM).

    Each pass stores a fresh snapshot; the next pass auto-diffs against it via
    the prior-scan lookup, so the loop chains baselines without bookkeeping. The
    explicit ``--baseline`` only applies to the first pass.
    """
    run = 0
    while True:
        run += 1
        suffix = f"/{max_runs}" if max_runs else ""
        logger.info("monitor watch · run %d%s (target %s)", run, suffix, config.target)
        config.scan_id = None  # fresh snapshot id each pass; prior lookup chains them
        await _monitor(config, baseline_id if run == 1 else None, webhook, deep,
                       no_host_gather, as_json)
        if max_runs and run >= max_runs:
            break
        await asyncio.sleep(interval)


async def _monitor(
    config: ScanConfig,
    baseline_id: str | None,
    webhook: str | None,
    deep: bool,
    no_host_gather: bool,
    as_json: bool,
) -> bool:
    from orthrus.core.drift import compute_asset_drift, compute_finding_drift
    from orthrus.core.orchestrator import Orchestrator

    which = {"dns", "ip-intel", "subdomains"}
    if not no_host_gather:
        which.add("host-gather")

    orch = Orchestrator(config, get_settings())
    status = "completed"
    drift = None
    finding_drift = None
    try:
        await orch.setup()
        prior = await orch.store.get_prior_scan(config.target, exclude_id=orch.scan_id)
        baseline_ref = baseline_id or (prior.id if prior else None)
        if deep:
            await orch.run_recon()       # full recon set
            await orch.run_scan()        # vulnerability scan
            await orch.run_exploit()     # confirmation
        else:
            await orch.run_recon(which)  # recon-only attack-surface snapshot
        current = list(orch.ctx.assets)
        baseline_assets = await orch.store.get_assets(baseline_ref) if baseline_ref else []
        drift = compute_asset_drift(
            baseline_assets, current, is_baseline=baseline_ref is None
        )
        if deep:
            current_findings = await orch.store.get_findings(orch.scan_id)
            baseline_findings = await orch.store.get_findings(baseline_ref) if baseline_ref else []
            finding_drift = compute_finding_drift(baseline_findings, current_findings)
        _render_drift(config.target, baseline_ref, orch.scan_id, drift, finding_drift, as_json)
        if webhook:
            await _post_drift_webhook(
                webhook, config.target, baseline_ref, orch.scan_id, drift, finding_drift
            )
    except Exception:
        status = "failed"
        logger.exception("monitor aborted")
    finally:
        await orch.teardown(status)
    asset_changed = bool(drift and drift.has_changes)
    finding_changed = bool(finding_drift and finding_drift.has_changes)
    return asset_changed or finding_changed


def _render_drift(target, baseline_id, current_id, drift, finding_drift, as_json) -> None:
    if as_json:
        payload = {"target": target, "baseline_scan": baseline_id, "current_scan": current_id,
                   "asset_drift": drift.to_dict()}
        if finding_drift is not None:
            payload["finding_drift"] = finding_drift.to_dict()
        click.echo(json.dumps(payload, indent=2, default=str))
        return

    from rich.table import Table

    section(console, f"DRIFT · {target}")
    console.print(f"[orthrus.muted]baseline {baseline_id or '(none)'} → current {current_id}[/]\n")
    console.print(drift.summary())
    if finding_drift is not None:
        console.print(finding_drift.summary())
    console.print()
    _render_finding_drift(finding_drift)
    if drift.is_baseline:
        console.print(
            f"[orthrus.muted]First snapshot - {drift.current_count} host(s) recorded "
            f"as the baseline for future runs.[/]"
        )
        return
    if not drift.has_changes:
        console.print("[status.completed]✓ No attack-surface drift.[/]")
        return
    if drift.new_hosts:
        t = Table(title="[status.failed]NEW hosts[/]", border_style="orthrus.muted")
        t.add_column("Host", style="orthrus.accent")
        t.add_column("IP(s)")
        t.add_column("Source", style="orthrus.muted")
        for a in drift.new_hosts:
            t.add_row(a.fqdn, ", ".join(a.ips) or "-", a.discovery_method)
        console.print(t)
    if drift.removed_hosts:
        console.print("[status.running]REMOVED hosts:[/] " + ", ".join(drift.removed_hosts))
    if drift.changed_hosts:
        t = Table(title="[status.running]CHANGED hosts[/]", border_style="orthrus.muted")
        t.add_column("Host", style="orthrus.accent")
        t.add_column("New IP(s)")
        t.add_column("New port(s)")
        t.add_column("Removed", style="orthrus.muted")
        for c in drift.changed_hosts:
            removed = ", ".join([*c.removed_ips, *(str(p) for p in c.removed_ports)])
            t.add_row(
                c.fqdn,
                ", ".join(c.new_ips) or "-",
                ", ".join(str(p) for p in c.new_ports) or "-",
                removed or "-",
            )
        console.print(t)


def _render_finding_drift(finding_drift) -> None:
    if finding_drift is None or not finding_drift.has_changes:
        return
    from rich.table import Table

    if finding_drift.new_findings:
        t = Table(title="[status.failed]NEW findings[/]", border_style="orthrus.muted")
        t.add_column("Severity")
        t.add_column("Type", style="orthrus.accent")
        t.add_column("URL", style="orthrus.muted", overflow="fold")
        for f in sorted(finding_drift.new_findings, key=_diff_sort_key):
            t.add_row(str(f.severity), f.vuln_type, f.url)
        console.print(t)
    if finding_drift.resolved_findings:
        console.print(
            "[status.completed]RESOLVED findings:[/] "
            + ", ".join(sorted({f.vuln_type for f in finding_drift.resolved_findings}))
        )


async def _post_drift_webhook(url, target, baseline_id, current_id, drift, finding_drift=None) -> None:
    import httpx

    payload = {
        "tool": "orthrus", "event": "asset_drift", "target": target,
        "baseline_scan": baseline_id, "current_scan": current_id,
        "asset_drift": drift.to_dict(),
    }
    if finding_drift is not None:
        payload["event"] = "drift"
        payload["finding_drift"] = finding_drift.to_dict()
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(url, json=payload)
        logger.info("drift alert POSTed to webhook (HTTP %s)", resp.status_code)
    except httpx.HTTPError as exc:
        logger.warning("drift webhook POST failed: %s", exc)


def _finding_key(row: object) -> tuple[str, str, str]:
    """Stable cross-scan identity for diffing: what + where + which parameter.

    Severity/confidence can change between runs without the underlying issue
    changing, so they are deliberately excluded from the key - a fixed bug that
    later reappears at a different severity still matches as 'still present'.
    """
    return (row.vuln_type, row.url, row.parameter or "")


def _diff_sort_key(row: object) -> tuple[int, str, str]:
    """Order diff rows highest-severity first, then stably by type/url."""
    return (-_FAIL_ON_ORDER.get(row.severity, 0), row.vuln_type, row.url)


def _partition_diff(base_rows: list, against_rows: list) -> dict[str, list]:
    """Split findings into NEW / FIXED / STILL-PRESENT across two scans.

    'new' is in the newer scan only, 'fixed' is in the baseline only, and
    'persisting' is in both (keyed by (vuln_type, url, parameter)). The newer row
    is kept for persisting items so its current severity is what's shown. Shares
    the drift engine with ``orthrus monitor --deep``.
    """
    from orthrus.core.drift import compute_finding_drift

    drift = compute_finding_drift(base_rows, against_rows)
    return {
        "new": sorted(drift.new_findings, key=_diff_sort_key),
        "fixed": sorted(drift.resolved_findings, key=_diff_sort_key),
        "persisting": sorted(drift.persisting, key=_diff_sort_key),
    }


@cli.command(name="diff")
@click.option("--base", "base_id", required=True, help="Baseline scan id (the 'before').")
@click.option("--against", "against_id", required=True, help="Newer scan id (the 'after').")
@click.option(
    "--severity",
    default=None,
    type=click.Choice(["critical", "high", "medium", "low", "info"]),
    help="Only consider findings at or above this severity.",
)
@click.option("--json", "as_json", is_flag=True, help="Emit the diff as JSON (stdout).")
@click.option(
    "--fail-on-new",
    is_flag=True,
    help=f"Exit {FAIL_ON_EXIT_CODE} if any NEW finding appears (retest/CI regression gate).",
)
@click.option("--verbose", "-v", default="warning", help="Log level.")
def diff(
    base_id: str,
    against_id: str,
    severity: str | None,
    as_json: bool,
    fail_on_new: bool,
    verbose: str,
) -> None:
    """Compare two scans: what's NEW, FIXED, or STILL PRESENT.

    A read-only, network-free retest view. Findings are matched across the two
    scans by type + URL + parameter, so you can confirm a fix landed (FIXED),
    catch regressions (NEW), and see what still needs work (STILL PRESENT).
    Pair --fail-on-new with a retest pipeline to fail the build on any new bug.
    """
    configure_logging(verbose)
    base_rows, against_rows = asyncio.run(_load_diff_rows(base_id, against_id, severity))
    parts = _partition_diff(base_rows, against_rows)

    if as_json:
        click.echo(
            json.dumps(
                {key: [_finding_summary(r) for r in rows] for key, rows in parts.items()},
                indent=2,
                default=str,
            )
        )
    else:
        _print_diff(base_id, against_id, parts)

    if fail_on_new and parts["new"]:
        logger.error(
            "fail-on-new: %d new finding(s) since %s; exiting %d",
            len(parts["new"]),
            base_id,
            FAIL_ON_EXIT_CODE,
        )
        raise SystemExit(FAIL_ON_EXIT_CODE)


async def _load_diff_rows(
    base_id: str, against_id: str, severity: str | None
) -> tuple[list, list]:
    """Load both scans' findings, applying the optional severity floor to each."""
    settings = get_settings()
    store = Store(settings.db_url, encryption_key=settings.encryption_key)
    try:
        await store.init()
        if await store.get_scan(base_id) is None:
            raise click.ClickException(f"no such scan: {base_id} (list scans with `orthrus scans`)")
        if await store.get_scan(against_id) is None:
            raise click.ClickException(
                f"no such scan: {against_id} (list scans with `orthrus scans`)"
            )
        base_rows = await store.get_findings(base_id)
        against_rows = await store.get_findings(against_id)
    finally:
        await store.close()

    if severity:
        floor = _FAIL_ON_ORDER.get(severity.lower(), 0)
        base_rows = [r for r in base_rows if _FAIL_ON_ORDER.get(r.severity, 0) >= floor]
        against_rows = [r for r in against_rows if _FAIL_ON_ORDER.get(r.severity, 0) >= floor]
    return base_rows, against_rows


def _print_diff(base_id: str, against_id: str, parts: dict[str, list]) -> None:
    from orthrus.utils.theme import findings_table

    section(console, f"SCAN DIFF · {base_id} -> {against_id}")
    console.print(
        f"[status.failed]New:[/] {len(parts['new'])}    "
        f"[status.completed]Fixed:[/] {len(parts['fixed'])}    "
        f"[orthrus.muted]Still present:[/] {len(parts['persisting'])}"
    )
    for label, key in (("NEW", "new"), ("FIXED", "fixed")):
        rows = parts[key]
        if rows:
            section(console, f"{label} · {len(rows)}")
            console.print(findings_table(rows))
    if not parts["new"] and not parts["fixed"]:
        console.print("\n[orthrus.muted]No change between the two scans.[/]")


@cli.command(name="modules")
@click.argument("name", required=False)
@click.option("--json", "as_json", is_flag=True, help="Emit the inventory as JSON (stdout).")
@click.option("--verbose", "-v", default="warning", help="Log level.")
def modules(name: str | None, as_json: bool, verbose: str) -> None:
    """List scanner and exploit-confirmation modules, or detail one by NAME.

    With no NAME, list every module (the names accepted by ``orthrus scan
    --modules``). Pass a NAME to filter to a single scanner (by module name or
    vuln type) or confirmer (by name or a vuln type it handles).
    """
    configure_logging(verbose)
    # Importing the packages runs the @register side-effects that populate the
    # registries (no scanners are imported until something needs them).
    import orthrus.exploits  # noqa: F401
    import orthrus.scanners  # noqa: F401
    from orthrus.exploits.registry import EXPLOIT_REGISTRY
    from orthrus.scanners.registry import SCANNER_REGISTRY

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

    if name:
        wanted = name.lower()
        scanners = [s for s in scanners if wanted in (s["name"].lower(), s["vuln_type"].lower())]
        exploits = [
            e
            for e in exploits
            if e["name"].lower() == wanted or wanted in [h.lower() for h in e["handles"]]
        ]
        if not scanners and not exploits:
            raise click.ClickException(f"no module matches '{name}' (try `orthrus modules`)")

    if as_json:
        # Machine-readable on stdout (stdout is reserved for data; chrome is stderr).
        click.echo(json.dumps({"scanners": scanners, "exploits": exploits}, indent=2))
        return

    _print_modules(scanners, exploits)


def _print_modules(scanners: list[dict], exploits: list[dict]) -> None:
    from rich.table import Table

    if scanners:
        section(console, f"SCANNERS · {len(scanners)}")
        stable = Table(title="[orthrus.accent]Vulnerability scanners[/]")
        stable.add_column("Module", style="bold")
        stable.add_column("Vuln type")
        stable.add_column("Aggr.")
        stable.add_column("Description", style="orthrus.muted")
        for s in scanners:
            agg = s["min_aggressiveness"]
            stable.add_row(
                s["name"],
                s["vuln_type"],
                f"[{_AGG_STYLE.get(agg, 'default')}]{agg}[/]",
                s["description"],
            )
        console.print(stable)

    if exploits:
        section(console, f"EXPLOIT CONFIRMATION · {len(exploits)}")
        etable = Table(title="[orthrus.accent]Exploit-confirmation modules[/]")
        etable.add_column("Module", style="bold")
        etable.add_column("Confirms")
        etable.add_column("Description", style="orthrus.muted")
        for e in exploits:
            etable.add_row(e["name"], ", ".join(e["handles"]), e["description"])
        console.print(etable)


# Hint lines (stdout, prepended as comments) so an operator who runs the command
# interactively learns how to install the script instead of just seeing a blob.
_COMPLETION_INSTALL = {
    "bash": "Add to ~/.bashrc:  eval \"$(orthrus completion bash)\"",
    "zsh": "Add to ~/.zshrc:  eval \"$(orthrus completion zsh)\"",
    "fish": "Save to file:  orthrus completion fish > ~/.config/fish/completions/orthrus.fish",
}


@cli.command(name="completion")
@click.argument("shell", type=click.Choice(["bash", "zsh", "fish"]))
def completion(shell: str) -> None:
    """Output a tab-completion script for SHELL (bash, zsh, or fish).

    The script is written to stdout so it can be sourced or saved, e.g.:

    \b
      eval "$(orthrus completion bash)"        # current shell
      orthrus completion bash >> ~/.bashrc     # persist (bash)
      orthrus completion zsh  >> ~/.zshrc      # persist (zsh)
      orthrus completion fish > ~/.config/fish/completions/orthrus.fish
    """
    from click.shell_completion import get_completion_class

    comp_cls = get_completion_class(shell)
    if comp_cls is None:  # defensive: Choice already constrains shell
        raise click.ClickException(f"unsupported shell: {shell}")
    # complete_var follows Click's PROG_COMPLETE convention so the generated
    # script and the runtime completion handshake agree on the trigger env var.
    comp = comp_cls(cli, {}, "orthrus", "_ORTHRUS_COMPLETE")
    click.echo(f"# {_COMPLETION_INSTALL[shell]}")
    click.echo(comp.source())


def _collect_diagnostics() -> dict:
    """Report optional-integration readiness without touching the network.

    Each capability is detected by an import or binary lookup only (never by
    connecting out), so ``orthrus doctor`` is safe to run anywhere and tells the
    operator which features are active vs. which extra would enable them.
    """
    import importlib.util
    import platform
    import shutil
    from pathlib import Path

    from orthrus.core.browser import BrowserManager

    def _has(module: str) -> bool:
        try:
            return importlib.util.find_spec(module) is not None
        except (ImportError, ValueError):
            return False

    # (label, available, purpose, how-to-enable)
    checks = [
        (
            "browser engine (Playwright)",
            BrowserManager.is_available(),
            "DOM/stored-XSS detection + JS-rendered crawling",
            "pip install 'orthrus-framework[browser]' && playwright install chromium",
        ),
        (
            "OOB collaborator (Interactsh)",
            _has("cryptography"),
            "blind/out-of-band detection (XXE, SSRF) via --interactsh; "
            "falls back to a local listener when absent",
            "pip install cryptography  (bundled with the default install)",
        ),
        (
            "nmap binary",
            shutil.which("nmap") is not None,
            "service/port discovery during recon",
            "install nmap via your OS package manager",
        ),
        (
            "nuclei binary",
            shutil.which("nuclei") is not None,
            "external-tool adapter: template-based scanning via --tools nuclei",
            "install nuclei (ProjectDiscovery), e.g. 'winget install ProjectDiscovery.Nuclei'",
        ),
        (
            "REST API server (FastAPI)",
            _has("fastapi"),
            "serve scans/findings over HTTP via 'orthrus serve'",
            "pip install 'orthrus-framework[api]'",
        ),
        (
            "MCP server (Model Context Protocol)",
            _has("mcp"),
            "expose scans/findings to AI agents via 'orthrus mcp'",
            "pip install 'orthrus-framework[mcp]'",
        ),
        (
            "python-nmap",
            _has("nmap"),
            "parse nmap output",
            "pip install 'orthrus-framework[recon]'",
        ),
        (
            "uvloop",
            _has("uvloop"),
            "faster asyncio event loop (POSIX)",
            "pip install uvloop  (not available on Windows)",
        ),
        (
            "Redis client",
            _has("redis"),
            "distributed task broker (--distributed)",
            "pip install 'orthrus-framework[distributed]'",
        ),
        (
            "Celery",
            _has("celery"),
            "distributed scan workers (--distributed)",
            "pip install 'orthrus-framework[distributed]'",
        ),
        (
            "asyncpg",
            _has("asyncpg"),
            "PostgreSQL result store (production scale)",
            "pip install 'orthrus-framework[postgres]'",
        ),
        (
            "WeasyPrint",
            _has("weasyprint"),
            "alternate PDF backend (default PDF uses Chromium)",
            "pip install 'orthrus-framework[reporting]'",
        ),
        (
            "cockpit (built)",
            (Path(__file__).resolve().parent.parent / "cockpit" / "dist" / "index.html").is_file(),
            "v2.0 operator cockpit at 'orthrus serve --cockpit'",
            "npm --prefix cockpit install && npm --prefix cockpit run build",
        ),
        (
            "cockpit desktop toolchain (Node + Rust)",
            shutil.which("node") is not None and shutil.which("cargo") is not None,
            "build the Tauri desktop cockpit ('npm --prefix cockpit run tauri build')",
            "install Node 18+ and the Rust toolchain (rustup)",
        ),
    ]
    from orthrus.core import panic
    return {
        "orthrus_version": __version__,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "panic_engaged": panic.is_engaged(),
        "capabilities": [
            {"name": name, "available": ok, "purpose": purpose, "enable": enable}
            for name, ok, purpose, enable in checks
        ],
    }


def _print_diagnostics(diag: dict) -> None:
    from rich.markup import escape
    from rich.table import Table

    section(console, "ENVIRONMENT")
    console.print(
        f"[orthrus.muted]ORTHRUS:[/] {diag['orthrus_version']}    "
        f"[orthrus.muted]Python:[/] {diag['python']}    "
        f"[orthrus.muted]Platform:[/] {escape(diag['platform'])}"
    )
    if diag.get("panic_engaged"):
        console.print("[red bold]■ PANIC engaged[/] - all outbound requests are halted. "
                      "Lift with `orthrus panic --clear`.")

    caps = diag["capabilities"]
    active = sum(1 for c in caps if c["available"])
    section(console, f"OPTIONAL INTEGRATIONS · {active}/{len(caps)} active")
    table = Table(title="[orthrus.accent]Capabilities[/]")
    table.add_column("Integration", style="bold")
    table.add_column("Status")
    table.add_column("Enables", style="orthrus.muted")
    for cap in caps:
        if cap["available"]:
            status = "[status.completed]available[/]"
        else:
            status = "[orthrus.muted]not installed[/]"
        # Escape dynamic text: enable-hints contain extras like "[recon]" that
        # Rich would otherwise parse (and silently drop) as markup tags.
        table.add_row(escape(cap["name"]), status, escape(cap["purpose"]))
    console.print(table)

    missing = [c for c in caps if not c["available"]]
    if missing:
        section(console, "ENABLE MORE")
        for cap in missing:
            console.print(f"[orthrus.muted]{escape(cap['name'])}:[/] {escape(cap['enable'])}")
    # The core scan engine never depends on these; absence only narrows coverage.
    console.print("\n[orthrus.muted]Core scanning works without any of the above.[/]")


@cli.command(name="doctor")
@click.option("--json", "as_json", is_flag=True, help="Emit diagnostics as JSON (stdout).")
def doctor(as_json: bool) -> None:
    """Check which optional integrations are available in this environment.

    A read-only, network-free environment probe: it reports the active vs.
    missing optional capabilities (browser engine, nmap, distributed broker,
    Postgres, ...) and how to enable each. Always exits 0.
    """
    diag = _collect_diagnostics()
    if as_json:
        click.echo(json.dumps(diag, indent=2))
        return
    _print_diagnostics(diag)


@cli.command(name="update")
def update() -> None:
    """Refresh threat-intel feeds (CISA KEV + EPSS) used to enrich CVE findings.

    Fetches the CISA Known Exploited Vulnerabilities catalog from cisa.gov and the
    full EPSS dataset from FIRST.org (both trusted data sources, not the target)
    and rewrites the bundled seeds so CVE findings are flagged when actively
    exploited (KEV) and prioritised by exploit probability (EPSS). Each feed
    refreshes independently - one failing does not abort the other.
    """
    import csv
    import gzip
    import io

    import httpx

    from orthrus.intel.cve_intel import CISA_KEV_FEED, EPSS_FEED, refresh_epss, refresh_kev

    failures: list[str] = []

    try:
        resp = httpx.get(CISA_KEV_FEED, timeout=30.0, follow_redirects=True)
        resp.raise_for_status()
        kev_count = refresh_kev(resp.json())
        click.echo(f"Updated CISA KEV catalog: {kev_count} known-exploited CVEs.")
    except (httpx.HTTPError, ValueError) as exc:
        failures.append(f"KEV: {type(exc).__name__}: {exc}")

    try:
        resp = httpx.get(EPSS_FEED, timeout=60.0, follow_redirects=True)
        resp.raise_for_status()
        text = gzip.decompress(resp.content).decode("utf-8", "replace")
        # The CSV begins with a '#model_version' comment line before the header.
        body = io.StringIO("\n".join(ln for ln in text.splitlines() if not ln.startswith("#")))
        mapping = {
            row["cve"]: row["epss"]
            for row in csv.DictReader(body)
            if row.get("cve") and row.get("epss")
        }
        epss_count = refresh_epss(mapping)
        click.echo(f"Updated EPSS scores: {epss_count} CVEs.")
    except (httpx.HTTPError, OSError, ValueError) as exc:
        failures.append(f"EPSS: {type(exc).__name__}: {exc}")

    if len(failures) == 2:  # both feeds failed
        raise click.ClickException("threat-intel update failed: " + "; ".join(failures))
    for msg in failures:
        click.echo(f"warning: {msg} (other feed updated)", err=True)


@cli.command(name="serve")
@click.option("--host", default="127.0.0.1", help="Bind address for the API server.")
@click.option("--port", default=8000, type=int, help="Port for the API server.")
@click.option("--cockpit", is_flag=True, help="Also serve the v2.0 operator cockpit at /cockpit.")
def serve(host: str, port: int, cockpit: bool) -> None:
    """Run the ORTHRUS REST API (scans/findings + operator-graph CRUD over HTTP).

    Needs the [api] extra (fastapi + uvicorn). Endpoints: /health, /api/scans*,
    /api/programs* (operator graph). With --cockpit, the built React/Tauri cockpit
    is served at /cockpit (build it first: `npm --prefix cockpit run build`).
    """
    try:
        import uvicorn
    except ImportError as exc:
        raise click.ClickException(
            "the API server needs the [api] extra: pip install 'orthrus-framework[api]'"
        ) from exc
    from orthrus.api import create_app
    from orthrus.api.app import cockpit_dist

    if cockpit:
        if cockpit_dist() is None:
            raise click.ClickException(
                "cockpit not built - run `npm --prefix cockpit install && "
                "npm --prefix cockpit run build`, then re-run `orthrus serve --cockpit`."
            )
        click.echo(f"ORTHRUS cockpit on http://{host}:{port}/cockpit/")
    click.echo(f"ORTHRUS API on http://{host}:{port}  (docs at /docs)")
    uvicorn.run(create_app(), host=host, port=port)


@cli.command(name="panic")
@click.option("--clear", "do_clear", is_flag=True, help="Lift a previously-engaged panic state.")
@click.option("--reason", default="", help="Why you're pulling the switch (recorded in the flag).")
def panic_cmd(do_clear: bool, reason: str) -> None:
    """Emergency kill switch: halt ALL outbound requests + abort in-flight scans (PRD §8.3).

    Engaging writes a flag the scope-enforced HTTP client checks before every
    request - deny-by-default becomes deny-everything until you `--clear` it.
    """
    _ensure_utf8_output()
    from orthrus.core import panic

    if do_clear:
        lifted = panic.clear()
        console.print("[bold]panic cleared[/] - scanning re-enabled."
                      if lifted else "[orthrus.muted]no panic state was engaged.[/]")
        return

    path = panic.engage(reason)
    aborted = asyncio.run(_abort_running_scans())
    console.print("[red bold]■ PANIC ENGAGED[/] - all outbound requests are now denied.")
    console.print(f"  flag: [orthrus.muted]{path}[/]")
    console.print(f"  aborted [bold]{aborted}[/] in-flight scan(s).")
    console.print("[orthrus.muted]lift with `orthrus panic --clear`.[/]")


async def _abort_running_scans() -> int:
    settings = get_settings()
    store = Store(settings.db_url, encryption_key=settings.encryption_key)
    try:
        await store.init()
        rows = await store.list_scans(limit=1000, status="running")
        for row, _count in rows:
            await store.set_scan_status(row.id, "aborted")
        return len(rows)
    finally:
        await store.close()


@cli.command(name="migrate")
@click.option("--dry-run", is_flag=True, help="Report what would migrate; write nothing.")
def migrate_cmd(dry_run: bool) -> None:
    """Promote existing v0.1 scans/findings into the v2.0 operator graph (PRD §4.2).

    Additive and idempotent - creates a 'Legacy v0.1 import' program and upserts
    every scan's assets/findings into the unified graph without touching the v0.1
    tables, so it's safe to re-run and trivially reversible.
    """
    _ensure_utf8_output()
    from orthrus.model.migrate import migrate_v01
    from orthrus.model.store import ProgramGraph

    settings = get_settings()

    async def _run() -> dict:
        store = Store(settings.db_url, encryption_key=settings.encryption_key)
        graph = ProgramGraph(settings.db_url)
        try:
            await store.init()
            return await migrate_v01(store, graph, dry_run=dry_run)
        finally:
            await store.close()
            await graph.close()

    result = asyncio.run(_run())
    section(console, "MIGRATE · v0.1 → v2.0 operator graph" + (" (dry-run)" if dry_run else ""))
    console.print(f"scanned [bold]{result['scans']}[/] v0.1 scan(s)")
    if dry_run:
        console.print(f"would promote [bold]{result['assets_seen']}[/] asset(s) and "
                      f"[bold]{result['findings_seen']}[/] finding(s) into a legacy program.")
        console.print("[orthrus.muted]re-run without --dry-run to apply.[/]")
    else:
        console.print(f"promoted [bold]{result['assets_new']}[/] new asset(s) "
                      f"(of {result['assets_seen']}) and [bold]{result['findings_new']}[/] "
                      f"new finding(s) (of {result['findings_seen']}).")
        console.print(f"[orthrus.muted]legacy program: {result['program_id']} · "
                      "re-runnable (dedups) · reversible (delete that program).[/]")


def _apex(value: str) -> str:
    return (value or "").strip().lstrip("*.").lower().rstrip(".")


@cli.command(name="recon-run")
@click.option("--program", "program_name", required=True, help="Operator-graph program to recon.")
@click.option("--in-scope", "in_scope", multiple=True,
              help="In-scope domain(s); creates the program if new, else adds to its scope.")
@click.option("--authorization", default=None,
              help="Authorization source (required to create a new program).")
@click.option("--sources", default="all", help="Comma-separated recon adapters, or 'all'.")
@click.option("--notify-slack", "notify_slack", default=None, metavar="WEBHOOK",
              help="POST a summary to this Slack webhook when NEW assets are found.")
@click.option("--notify-discord", "notify_discord", default=None, metavar="WEBHOOK",
              help="POST a summary to this Discord webhook when NEW assets are found.")
@click.option("--json", "as_json", is_flag=True, help="Emit the recon result as JSON.")
def recon_run(program_name, in_scope, authorization, sources,
              notify_slack, notify_discord, as_json) -> None:
    """Run continuous recon for a program: enumerate its scope into the operator graph.

    Every available source (crt.sh/certspotter/DNS/wayback + subfinder/amass if
    installed) discovers assets, which are deduped into the graph with first/last-seen
    so this reports what's NEW since the last run. Populates the cockpit's Assets tab.
    """
    _ensure_utf8_output()
    from orthrus.model.store import ProgramGraph
    from orthrus.recon_engine.run import recon_once

    settings = get_settings()

    async def _run():
        graph = ProgramGraph(settings.db_url)
        try:
            await graph.init()
            program = await graph.get_program_by_name(program_name)
            if program is None:
                if not authorization:
                    raise click.UsageError(
                        f"program '{program_name}' not found - pass --authorization "
                        "(and --in-scope) to create it.")
                if not [d for d in in_scope if d.strip()]:
                    raise click.UsageError("creating a program needs at least one --in-scope domain.")
                platform = "self" if (authorization or "").strip() == "self-owned-lab" else "direct"
                program = await graph.create_program(program_name, authorization, platform=platform)
                await graph.append_audit("program-created", "create", subject_type="program",
                                         subject_id=program.id,
                                         details={"name": program_name, "via": "recon-run"})
            existing = {se.value for se in await graph.scope_entries(program.id)}
            for d in in_scope:
                if d.strip() and d.strip() not in existing:
                    await graph.add_scope_entry(program.id, d.strip(), entry_type="in",
                                                kind="domain", added_by="recon-run")
            domains = sorted({_apex(se.value) for se in await graph.scope_entries(program.id)
                              if se.entry_type == "in" and se.kind == "domain" and _apex(se.value)})
            if not domains:
                raise click.UsageError("program has no in-scope domains - add with --in-scope.")
            result, notified = await recon_once(
                graph, program.id, program_name, domains, sources=sources,
                notify_slack=notify_slack, notify_discord=notify_discord)
            return program, domains, result, notified
        finally:
            await graph.close()

    program, domains, result, notified = asyncio.run(_run())
    if as_json:
        click.echo(json.dumps({
            "program_id": program.id, "domains": domains,
            "sources_run": result.sources_run, "discovered": result.discovered,
            "recorded": result.recorded, "new": result.new,
            "wildcard_noise": result.wildcard_noise, "failed_sources": result.failed_sources,
        }, indent=2))
        return
    section(console, f"RECON · {program_name}")
    console.print(f"scope: {', '.join(domains)} · sources: "
                  f"{', '.join(result.sources_run) or '(none available)'}")
    console.print(result.summary())
    if result.new:
        listing = ", ".join(result.new[:12]) + (" …" if len(result.new) > 12 else "")
        console.print(f"[bold]✚ {len(result.new)} NEW asset(s):[/] {listing}")
    else:
        console.print("[orthrus.muted]no new assets this run.[/]")
    for channel, ok in notified.items():
        console.print(f"[orthrus.muted]{channel} alert {'sent' if ok else 'failed'}.[/]")
    if result.failed_sources:
        console.print(f"[orthrus.muted]sources that errored: {', '.join(result.failed_sources)}[/]")


@cli.command(name="recon-watch")
@click.option("--program", "program_name", required=True, help="Saved operator-graph program.")
@click.option("--interval", default=3600, type=int, show_default=True,
              help="Seconds between recon passes.")
@click.option("--max-runs", default=0, type=int,
              help="Stop after N passes (0 = run until interrupted).")
@click.option("--sources", default="all", help="Comma-separated recon adapters, or 'all'.")
@click.option("--notify-slack", "notify_slack", default=None, metavar="WEBHOOK",
              help="Alert this Slack webhook on new assets.")
@click.option("--notify-discord", "notify_discord", default=None, metavar="WEBHOOK",
              help="Alert this Discord webhook on new assets.")
def recon_watch(program_name, interval, max_runs, sources, notify_slack, notify_discord) -> None:
    """Continuously re-run recon for a program, alerting on NEW assets (PRD §7.2).

    Runs when nobody's watching: each pass folds fresh discoveries into the graph
    and fires Slack/Discord alerts on new in-scope assets. Interrupt to stop.
    """
    _ensure_utf8_output()
    from orthrus.model.store import ProgramGraph
    from orthrus.recon_engine.run import recon_once

    settings = get_settings()

    async def _watch() -> int:
        graph = ProgramGraph(settings.db_url)
        try:
            await graph.init()
            program = await graph.get_program_by_name(program_name)
            if program is None:
                raise click.UsageError(
                    f"no program '{program_name}' - create it first with "
                    f"`orthrus recon-run --program {program_name} --in-scope … --authorization …`.")
            domains = sorted({_apex(se.value) for se in await graph.scope_entries(program.id)
                              if se.entry_type == "in" and se.kind == "domain" and _apex(se.value)})
            if not domains:
                raise click.UsageError("program has no in-scope domains.")
            runs = 0
            while True:
                result, _notified = await recon_once(
                    graph, program.id, program_name, domains, sources=sources,
                    notify_slack=notify_slack, notify_discord=notify_discord)
                runs += 1
                tail = f" · [bold]✚{len(result.new)} new[/]" if result.new else ""
                console.print(f"[orthrus.muted]pass {runs}:[/] {result.summary()}{tail}")
                if max_runs and runs >= max_runs:
                    return runs
                await asyncio.sleep(interval)
        finally:
            await graph.close()

    section(console, f"RECON-WATCH · {program_name}")
    cadence = f"{max_runs} pass(es)" if max_runs else "until interrupted"
    console.print(f"[orthrus.muted]every {interval}s · {cadence}[/]")
    try:
        runs = asyncio.run(_watch())
        console.print(f"[bold]done[/] - {runs} pass(es).")
    except KeyboardInterrupt:
        console.print("\n[orthrus.muted]stopped.[/]")


def _detect_traffic_format(text: str, path: str) -> str:
    """Sniff a proxy export's format from its extension, then its content."""
    low = path.lower()
    if low.endswith((".xml",)):
        return "burp"
    if low.endswith((".har",)):
        return "har"
    stripped = text.lstrip()
    if stripped.startswith("<"):
        return "burp"
    if '"log"' in stripped[:200] and "entries" in stripped[:400]:
        return "har"
    return "caido"  # any other JSON shape


@cli.command(name="import-traffic")
@click.argument("export_file", type=click.Path(exists=True, dir_okay=False))
@click.option("--program", "program_name", required=True, help="Operator-graph program to import into.")
@click.option("--format", "fmt", type=click.Choice(["auto", "burp", "caido", "har"]),
              default="auto", show_default=True, help="Proxy-export format.")
@click.option("--in-scope", "in_scope", multiple=True,
              help="In-scope domain(s); creates the program if new, else adds to its scope.")
@click.option("--authorization", default=None,
              help="Authorization source (required to create a new program).")
@click.option("--no-scope-filter", is_flag=True,
              help="Import every host in the file, even out-of-scope (default: refuse out-of-scope).")
@click.option("--json", "as_json", is_flag=True, help="Emit the import result as JSON.")
def import_traffic(export_file, program_name, fmt, in_scope, authorization,
                   no_scope_filter, as_json) -> None:
    """Import a Burp / Caido / HAR proxy history into a program's operator graph (PRD §7.12).

    Folds the real attack surface you browsed by hand - hosts and their routes,
    with query/body params and a juicy-score - into the program's assets and
    endpoints, so manual recon flows into the same scan/triage/report pipeline.
    Out-of-scope hosts (third-party CDNs, analytics) are refused by default.
    """
    _ensure_utf8_output()
    from pathlib import Path

    from orthrus.bounty.scope_intake import ProgramScope
    from orthrus.bridges import PARSERS, fold_traffic
    from orthrus.bridges.burp import UnsafeXmlError
    from orthrus.model.store import ProgramGraph

    text = Path(export_file).read_text(encoding="utf-8", errors="replace")
    fmt = _detect_traffic_format(text, export_file) if fmt == "auto" else fmt
    try:
        requests = PARSERS[fmt](text)
    except UnsafeXmlError as exc:
        raise click.ClickException(str(exc)) from exc
    if not requests:
        raise click.ClickException(
            f"no requests parsed from {export_file} as '{fmt}' - check --format.")

    settings = get_settings()

    async def _run():
        graph = ProgramGraph(settings.db_url)
        try:
            await graph.init()
            program = await graph.get_program_by_name(program_name)
            if program is None:
                if not authorization:
                    raise click.UsageError(
                        f"program '{program_name}' not found - pass --authorization "
                        "(and --in-scope) to create it.")
                platform = "self" if (authorization or "").strip() == "self-owned-lab" else "direct"
                program = await graph.create_program(program_name, authorization, platform=platform)
                await graph.append_audit("program-created", "create", subject_type="program",
                                         subject_id=program.id,
                                         details={"name": program_name, "via": "import-traffic"})
            existing = {se.value for se in await graph.scope_entries(program.id)}
            for d in in_scope:
                if d.strip() and d.strip() not in existing:
                    await graph.add_scope_entry(program.id, d.strip(), entry_type="in",
                                                kind="domain", added_by="import-traffic")

            entries = await graph.scope_entries(program.id)
            predicate = None
            if not no_scope_filter:
                scope = ProgramScope(
                    domains=[se.value for se in entries
                             if se.entry_type == "in" and se.kind in ("domain", "wildcard")],
                    ip_ranges=[se.value for se in entries
                               if se.entry_type == "in" and se.kind in ("cidr", "ip")],
                    out_of_scope=[se.value for se in entries if se.entry_type == "out"],
                )
                if not (scope.domains or scope.ip_ranges):
                    raise click.UsageError(
                        "program has no in-scope entries to filter against - add --in-scope, "
                        "or pass --no-scope-filter to import everything.")
                predicate = scope.is_in_scope

            result = await fold_traffic(graph, program.id, requests, source=f"import:{fmt}",
                                        in_scope=predicate)
            await graph.append_audit(
                "traffic-imported", "import", subject_type="program", subject_id=program.id,
                details={"format": fmt, "file": Path(export_file).name, "total": result.total,
                         "new_assets": result.new_assets, "new_endpoints": result.new_endpoints,
                         "skipped_out_of_scope": result.skipped_out_of_scope})
            return program, result
        finally:
            await graph.close()

    program, result = asyncio.run(_run())
    if as_json:
        click.echo(json.dumps({
            "program_id": program.id, "format": fmt, "total": result.total,
            "new_assets": result.new_assets, "seen_assets": result.seen_assets,
            "new_endpoints": result.new_endpoints, "seen_endpoints": result.seen_endpoints,
            "skipped_out_of_scope": result.skipped_out_of_scope,
            "skipped_no_host": result.skipped_no_host, "hosts": result.hosts,
        }, indent=2))
        return
    section(console, f"IMPORT · {program_name}")
    console.print(f"[orthrus.muted]{result.total} request(s) from {Path(export_file).name} "
                  f"as '{fmt}'[/]")
    console.print(f"assets: [bold]✚{result.new_assets}[/] new, {result.seen_assets} seen · "
                  f"endpoints: [bold]✚{result.new_endpoints}[/] new, {result.seen_endpoints} seen")
    if result.hosts:
        listing = ", ".join(result.hosts[:12]) + (" …" if len(result.hosts) > 12 else "")
        console.print(f"hosts: {listing}")
    if result.skipped_out_of_scope:
        console.print(f"[orthrus.muted]⊘ {result.skipped_out_of_scope} request(s) refused "
                      f"(out of scope) - use --no-scope-filter to include them.[/]")
    if result.skipped_no_host:
        console.print(f"[orthrus.muted]{result.skipped_no_host} request(s) had no host.[/]")


@cli.command(name="program-scan")
@click.option("--program", "program_name", required=True, help="Operator-graph program to scan.")
@click.option("--min-confidence", type=click.Choice(["confirmed", "firm", "tentative"]),
              default="firm", help="Confidence floor for promoted findings.")
@click.option("--max-assets", default=25, type=int, help="Cap live assets scanned this run.")
@click.option("--aggressive", is_flag=True, help="Aggressive scanning.")
def program_scan(program_name, min_confidence, max_assets, aggressive) -> None:
    """Scan a program's live in-scope assets → promote findings into the operator graph (PRD Phase 2).

    Bridges recon → scan → triage queue: takes the live assets the recon engine
    discovered, runs the full scan+confirm pipeline over them, and folds the bugs
    into the program's ProgramFinding queue (deduped, priority-scored, ScanRun-
    linked) - where the cockpit Findings tab and triage see them.
    """
    _ensure_utf8_output()
    from uuid import uuid4

    from orthrus.bounty.campaign import run_campaign
    from orthrus.bounty.scope_intake import ProgramScope
    from orthrus.model.promote import promote_findings
    from orthrus.model.store import ProgramGraph

    settings = get_settings()

    async def _run():
        graph = ProgramGraph(settings.db_url)
        try:
            await graph.init()
            program = await graph.get_program_by_name(program_name)
            if program is None:
                raise click.UsageError(
                    f"no program '{program_name}' - create it with "
                    f"`orthrus recon-run --program {program_name} …` first.")
            assets = await graph.list_assets(program.id, alive_only=True)
            seeds = []
            for a in assets:
                if a.kind in ("subdomain", "host"):
                    seeds.append(f"https://{a.canonical_value}")
                elif a.kind == "url":
                    seeds.append(a.canonical_value)
            seeds = seeds[:max_assets]
            if not seeds:
                return program, None, {"seen": 0, "new": 0, "duplicate": 0}, 0
            domains = sorted({_apex(se.value) for se in await graph.scope_entries(program.id)
                              if se.entry_type == "in" and se.kind == "domain" and _apex(se.value)})
            scope = ProgramScope(seeds=seeds, domains=domains or [
                h for s in seeds if (h := urlsplit(s).hostname)])
            run_row = await graph.start_scan_run(
                program.id, triggered_by="manual",
                config={"seeds": len(seeds), "min_confidence": min_confidence})

            aggr = Aggressiveness.AGGRESSIVE if aggressive else Aggressiveness.NORMAL

            def make_config(seed: str, scope_cfg: ScopeConfig, scan_id: str) -> ScanConfig:
                return ScanConfig(scan_id=scan_id, target=seed, scope=scope_cfg,
                                  modules=["all"], aggressiveness=aggr)

            result = await run_campaign(scope, make_config,
                                        campaign_id=f"pscan-{uuid4().hex[:8]}",
                                        min_confidence=min_confidence)
            counts = await promote_findings(
                graph, program.id, [g.lead for g in result.report.groups], scan_run_id=run_row.id)
            await graph.finish_scan_run(run_row.id, status="completed", stats={
                "assets": len(seeds), "findings_seen": counts["seen"], "findings_new": counts["new"]})
            return program, run_row, counts, len(seeds)
        finally:
            await graph.close()

    _program, run_row, counts, n_assets = asyncio.run(_run())
    section(console, f"PROGRAM-SCAN · {program_name}")
    if n_assets == 0:
        console.print("[orthrus.muted]no live in-scope assets - run "
                      f"`orthrus recon-run --program {program_name} --in-scope … --authorization …` first.[/]")
        return
    console.print(f"scanned [bold]{n_assets}[/] live asset(s) · promoted [bold]{counts['new']}[/] new "
                  f"finding(s) (of {counts['seen']}; {counts['duplicate']} dup) into the graph.")
    console.print(f"[orthrus.muted]scan run {run_row.id} · see the cockpit Findings tab / "
                  "`orthrus bounty-status`.[/]")


@cli.command(name="program-findings")
@click.option("--program", "program_name", required=True, help="Operator-graph program to list.")
@click.option("--status", "status", default=None,
              help="Filter by finding status (e.g. new, confirmed, filed).")
@click.option("--json", "as_json", is_flag=True, help="Emit findings as JSON.")
def program_findings(program_name, status, as_json) -> None:
    """List a program's operator-graph findings (the triage queue), priority-ranked.

    The read side of the operator loop: recon → scan promotes findings here, and
    this surfaces them by name/status so the planner's suggested commands land
    somewhere real. Sorted by priority score (juiciest first).
    """
    _ensure_utf8_output()
    from orthrus.model.store import ProgramGraph

    settings = get_settings()

    async def _run():
        graph = ProgramGraph(settings.db_url)
        try:
            await graph.init()
            program = await graph.get_program_by_name(program_name)
            if program is None:
                raise click.UsageError(f"no program '{program_name}'.")
            return program, await graph.list_findings(program.id, status=status)
        finally:
            await graph.close()

    program, findings = asyncio.run(_run())
    if as_json:
        click.echo(json.dumps([{
            "id": f.id, "vuln_class": f.vuln_class, "title": f.title,
            "severity": f.severity, "confidence": f.confidence, "status": f.status,
            "priority_score": f.priority_score, "assigned_to": f.assigned_to,
        } for f in findings], indent=2))
        return
    section(console, f"FINDINGS · {program_name}")
    if not findings:
        console.print("[orthrus.muted]no findings"
                      + (f" with status '{status}'" if status else "") + ".[/]")
        return
    for f in findings:
        score = f"{f.priority_score:.1f}" if f.priority_score is not None else "  -"
        console.print(f"  [bold]{score}[/]  {(f.severity or '?').upper():8} {f.status:14} "
                      f"{f.title}")
    console.print(f"[orthrus.muted]{len(findings)} finding(s)"
                  + (f" · status={status}" if status else "") + ".[/]")


@cli.command(name="plan")
@click.option("--program", "program_name", required=True, help="Operator-graph program to plan for.")
@click.option("--json", "as_json", is_flag=True, help="Emit the ranked action list as JSON.")
def plan_cmd(program_name, as_json) -> None:
    """Suggest the next steps for a program, grounded in its graph state (PRD §7.10).

    A deterministic, no-hallucination planner: it reads the program's assets,
    endpoints, findings, scan history and scope, then prints a priority-ranked
    list of the concrete `orthrus` commands to run next - each with the count it's
    based on. The honest core of the bounded operator agent.
    """
    _ensure_utf8_output()
    from orthrus.model.planner import next_actions
    from orthrus.model.store import ProgramGraph

    settings = get_settings()

    async def _run():
        graph = ProgramGraph(settings.db_url)
        try:
            await graph.init()
            program = await graph.get_program_by_name(program_name)
            if program is None:
                raise click.UsageError(
                    f"no program '{program_name}' - create it with "
                    f"`orthrus recon-run --program {program_name} …` first.")
            return await next_actions(graph, program.id, program_name=program_name)
        finally:
            await graph.close()

    actions = asyncio.run(_run())
    if as_json:
        click.echo(json.dumps([{
            "key": a.key, "priority": a.priority, "reason": a.reason, "command": a.command,
        } for a in actions], indent=2))
        return
    section(console, f"PLAN · {program_name}")
    if not actions:
        console.print("[orthrus.muted]nothing pending - program is in a steady state.[/]")
        return
    for i, a in enumerate(actions, 1):
        console.print(f"  [bold]{i}. {a.key}[/] [orthrus.muted]({a.priority:.2f})[/] - {a.reason}")
        console.print(f"     [orthrus.accent]{a.command}[/]")


@cli.group(name="team")
def team() -> None:
    """Manage team members + per-program roles on the operator graph (PRD §9).

    Team mode is opt-in: with no members a program behaves single-user as before.
    Add users, mint their API keys, and grant per-program roles (owner/member/viewer);
    the REST API then enforces those roles once a program has members.
    """


def _team_graph():
    from orthrus.model.store import ProgramGraph
    return ProgramGraph(get_settings().db_url)


@team.command(name="add-user")
@click.argument("email")
@click.option("--name", default=None, help="Display name.")
@click.option("--admin", is_flag=True, help="Cross-program superuser (implicit owner everywhere).")
@click.option("--with-key", is_flag=True, help="Also mint an API key and print it once.")
def team_add_user(email, name, admin, with_key) -> None:
    """Create a team USER (by email)."""
    _ensure_utf8_output()

    async def _run():
        graph = _team_graph()
        try:
            await graph.init()
            user = await graph.create_user(email, name=name, is_admin=admin)
            key = await graph.generate_api_key(user.id) if with_key else None
            return user, key
        finally:
            await graph.close()

    try:
        user, key = asyncio.run(_run())
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc
    section(console, "TEAM · add-user")
    console.print(f"created [bold]{user.email}[/] (id {user.id})"
                  + (" · [orthrus.accent]admin[/]" if user.is_admin else ""))
    if key:
        console.print(f"API key (shown once): [bold]{key}[/]")


@team.command(name="users")
def team_users() -> None:
    """List team members."""
    _ensure_utf8_output()

    async def _run():
        graph = _team_graph()
        try:
            await graph.init()
            return await graph.list_users()
        finally:
            await graph.close()

    users = asyncio.run(_run())
    section(console, "TEAM · users")
    if not users:
        console.print("[orthrus.muted]no users yet - add one with `orthrus team add-user`.[/]")
        return
    for u in users:
        flags = " ".join(filter(None, [
            "admin" if u.is_admin else "", "key" if u.api_key_hash else "",
            "" if u.is_active else "inactive"]))
        console.print(f"  {u.email:32} [orthrus.muted]{u.id}[/]  {flags}")


@team.command(name="key")
@click.argument("email")
def team_key(email) -> None:
    """Mint a fresh API key for EMAIL (invalidates the previous one)."""
    _ensure_utf8_output()

    async def _run():
        graph = _team_graph()
        try:
            await graph.init()
            user = await graph.get_user_by_email(email)
            if user is None:
                return None
            return await graph.generate_api_key(user.id)
        finally:
            await graph.close()

    key = asyncio.run(_run())
    if key is None:
        raise click.ClickException(f"no user '{email}' - add with `orthrus team add-user`.")
    section(console, "TEAM · key")
    console.print(f"API key for {email} (shown once): [bold]{key}[/]")


@team.command(name="grant")
@click.option("--program", "program_name", required=True, help="Program to grant access on.")
@click.option("--user", "email", required=True, help="Member email.")
@click.option("--role", type=click.Choice(["owner", "member", "viewer"]), default="viewer",
              show_default=True)
def team_grant(program_name, email, role) -> None:
    """Grant (or change) a USER's ROLE on a PROGRAM."""
    _ensure_utf8_output()

    async def _run():
        graph = _team_graph()
        try:
            await graph.init()
            program = await graph.get_program_by_name(program_name)
            if program is None:
                raise click.UsageError(f"no program '{program_name}'.")
            user = await graph.get_user_by_email(email)
            if user is None:
                raise click.UsageError(f"no user '{email}' - add with `orthrus team add-user`.")
            await graph.add_member(program.id, user.id, role)
            await graph.append_audit("member-added", "grant", subject_type="program",
                                     subject_id=program.id,
                                     details={"user": email, "role": role, "via": "cli"})
        finally:
            await graph.close()

    asyncio.run(_run())
    section(console, "TEAM · grant")
    console.print(f"[bold]{email}[/] is now [orthrus.accent]{role}[/] on {program_name}.")


@team.command(name="members")
@click.option("--program", "program_name", required=True, help="Program to list members of.")
def team_members(program_name) -> None:
    """List a PROGRAM's members and their roles."""
    _ensure_utf8_output()

    async def _run():
        graph = _team_graph()
        try:
            await graph.init()
            program = await graph.get_program_by_name(program_name)
            if program is None:
                raise click.UsageError(f"no program '{program_name}'.")
            members = await graph.list_members(program.id)
            return [(m.role, (await graph.get_user(m.user_id))) for m in members]
        finally:
            await graph.close()

    rows = asyncio.run(_run())
    section(console, f"TEAM · members · {program_name}")
    if not rows:
        console.print("[orthrus.muted]no members - grant with `orthrus team grant`.[/]")
        return
    for role, user in rows:
        console.print(f"  [bold]{role:7}[/] {user.email if user else '(deleted user)'}")


@team.command(name="revoke")
@click.option("--program", "program_name", required=True, help="Program to revoke access on.")
@click.option("--user", "email", required=True, help="Member email.")
def team_revoke(program_name, email) -> None:
    """Revoke a USER's access to a PROGRAM."""
    _ensure_utf8_output()

    async def _run():
        graph = _team_graph()
        try:
            await graph.init()
            program = await graph.get_program_by_name(program_name)
            if program is None:
                raise click.UsageError(f"no program '{program_name}'.")
            user = await graph.get_user_by_email(email)
            if user is None:
                raise click.UsageError(f"no user '{email}'.")
            return await graph.remove_member(program.id, user.id)
        finally:
            await graph.close()

    removed = asyncio.run(_run())
    section(console, "TEAM · revoke")
    console.print(f"{'revoked' if removed else 'no membership for'} {email} on {program_name}.")


@cli.command(name="mcp")
def mcp_cmd() -> None:
    """Run the ORTHRUS MCP server (stdio) - expose scans/findings as agent tools.

    Lets an MCP-capable AI agent query ORTHRUS results (list_scans, get_scan,
    get_findings, list_modules). Needs the [mcp] extra.
    """
    from orthrus.mcp_server import build_server

    try:
        server = build_server()
    except ImportError as exc:
        raise click.ClickException(
            "the MCP server needs the [mcp] extra: pip install 'orthrus-framework[mcp]'"
        ) from exc
    server.run()


@cli.command(name="proxy")
@click.option("--port", default=8080, type=int, help="Local port to listen on.")
@click.option("--host", default="127.0.0.1", help="Local bind address.")
@click.option("--scope", "scope_str", default=None,
              help="Authorized scope: comma-separated domains / CIDRs (required - deny by default).")
@click.option("--scan-id", default=None, help="Persist captured endpoints into this existing scan.")
@click.option("--allow-out-of-scope", is_flag=True,
              help="Pass through (don't block) out-of-scope requests; they are never captured.")
@click.option("--exclude-paths", default=None, help="Comma-separated regex paths to never forward.")
@click.option("--verbose", "-v", default="info", help="Log level.")
def proxy_cmd(
    port: int, host: str, scope_str: str | None, scan_id: str | None,
    allow_out_of_scope: bool, exclude_paths: str | None, verbose: str,
) -> None:
    """Run a scope-aware capturing proxy to feed the scanner from a manual browse.

    Point your browser / HTTP client at http://HOST:PORT and browse the authorized
    target; every in-scope request's endpoint + parameters are captured (into a
    scan with --scan-id). Deny-by-default: out-of-scope requests are blocked unless
    --allow-out-of-scope is set (pass-through traffic is never captured). HTTPS is
    tunneled opaquely (no TLS interception).
    """
    configure_logging(verbose)
    if not scope_str:
        raise click.UsageError(
            "--scope is required (deny by default): pass the authorized host(s)/CIDR(s)"
        )
    scope = build_scope(scope_str, "", exclude_paths, block_third_party=not allow_out_of_scope)
    asyncio.run(_proxy_cmd(host, port, scope, scan_id, allow_out_of_scope))


async def _proxy_cmd(host, port, scope, scan_id, allow_out_of_scope) -> None:
    from orthrus.proxy import ProxyServer

    settings = get_settings()
    store = None
    on_capture = None
    if scan_id:
        store = Store(settings.db_url, encryption_key=settings.encryption_key)
        await store.init()
        if await store.get_scan(scan_id) is None:
            logger.error("no such scan: %s (create one with `orthrus scan`)", scan_id)
            await store.close()
            return

        async def on_capture(endpoint) -> None:
            try:
                await store.add_endpoint(scan_id, endpoint)
            except Exception as exc:  # noqa: BLE001 - a capture failure must not kill the proxy
                logger.debug("capture persist failed: %s", exc)

    server = ProxyServer(scope, on_capture=on_capture, allow_out_of_scope=allow_out_of_scope)
    srv = await server.serve(host, port)
    section(console, f"PROXY · {host}:{port}")
    console.print(f"[orthrus.accent]Listening on http://{host}:{port}[/] - set your client's HTTP proxy to it.")
    scope_desc = ", ".join(scope.domains + scope.ip_ranges) or "auto"
    console.print(
        f"[orthrus.muted]scope: {scope_desc} · out-of-scope: "
        f"{'passthrough' if allow_out_of_scope else 'blocked'}"
        f"{' · capturing into ' + scan_id if scan_id else ' · not persisting (use --scan-id)'}[/]"
    )
    console.print("[orthrus.muted]Ctrl-C to stop.[/]")
    try:
        async with srv:
            await srv.serve_forever()
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        console.print(
            f"\n[status.completed]Captured {server.captured} in-scope request(s); "
            f"blocked {server.blocked} out-of-scope.[/]"
        )
        if store is not None:
            await store.close()


@cli.command(name="agent")
@click.option("--target", "-t", required=True, help="Target URL (a host you own / are authorized to test).")
@click.option("--scope", "scope_str", default="auto", help="Scope: wildcard domains / CIDR ranges.")
@click.option(
    "--aggressiveness", type=click.Choice(["passive", "normal", "aggressive"]), default="normal",
    help="Caps which scanners the agent may choose.",
)
@click.option("--max-steps", default=2, type=int, help="Max plan→execute→re-plan iterations.")
@click.option("--dry-run", is_flag=True, help="Show the plan; execute nothing.")
@click.option("--llm/--no-llm", "use_llm", default=True,
              help="Plan with an Anthropic model (needs API key); else a deterministic policy.")
@click.option("--model", default=None, help="LLM model id (with --llm).")
@click.option("--crawl-depth", default=2, type=int, help="Crawl depth per executed step.")
@click.option("--timeout", default=30.0, type=float, help="HTTP request timeout (s).")
@click.option("--exclude-paths", default=None, help="Comma-separated regex paths to exclude (scope).")
@click.option("--json", "as_json", is_flag=True, help="Emit the run report as JSON.")
@click.option("--verbose", "-v", default="info", help="Log level.")
def agent_cmd(
    target: str, scope_str: str, aggressiveness: str, max_steps: int, dry_run: bool, use_llm: bool,
    model: str | None, crawl_depth: int, timeout: float, exclude_paths: str | None, as_json: bool,
    verbose: str,
) -> None:
    """Autonomous orchestrator: an LLM plans which scope-enforced scanners to run, in a loop.

    The agent reasons over the target and findings-so-far and picks the next batch
    of ORTHRUS's own scanners to run, up to --max-steps. Its action space is a hard
    allow-list of registered modules - no shells, no arbitrary code - and every
    request still passes the deny-by-default scope check and non-destructive
    doctrine. Use --dry-run to see the plan without running anything.
    """
    configure_logging(verbose)
    scope = build_scope(scope_str, target, exclude_paths)
    api_key = None
    if use_llm:
        api_key = os.environ.get("ORTHRUS_ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_API_KEY")
        if not api_key and not dry_run:
            logger.warning("--llm set but no API key; using the deterministic planning policy")
    asyncio.run(_agent_cmd(
        target, scope, aggressiveness, max_steps, dry_run, api_key, model, crawl_depth, timeout, as_json,
    ))


async def _agent_cmd(
    target, scope, aggressiveness, max_steps, dry_run, api_key, model, crawl_depth, timeout_s, as_json,
) -> None:
    from orthrus.agent import AgentRunner, build_catalog
    from orthrus.core.orchestrator import Orchestrator

    catalog = build_catalog()
    execute_fn = None
    if not dry_run:
        async def execute_fn(modules: list[str], state) -> list[dict]:
            # Each step is one real, scope-enforced scan restricted to the chosen modules.
            config = ScanConfig(
                target=target, scope=scope, modules=modules,
                aggressiveness=Aggressiveness(aggressiveness), timeout=timeout_s, crawl_depth=crawl_depth,
            )
            orch = Orchestrator(config, get_settings())
            status, rows = "completed", []
            try:
                await orch.setup()
                await orch.run_recon()
                await orch.run_scan()
                rows = await orch.store.get_findings(orch.scan_id)
            except Exception as exc:  # noqa: BLE001 - one bad step shouldn't abort the whole run
                status = "failed"
                logger.error("agent step failed: %s", exc)
            finally:
                await orch.teardown(status)
            return [
                {"vuln_type": r.vuln_type, "severity": getattr(r.severity, "value", r.severity), "url": r.url}
                for r in rows
            ]

    runner = AgentRunner(
        target, catalog, aggressiveness=aggressiveness, max_steps=max_steps,
        execute_fn=execute_fn, api_key=api_key, model=model,
    )
    report = await runner.run(dry_run=dry_run)

    if as_json:
        click.echo(json.dumps(report.to_dict(), indent=2, default=str))
        return
    section(console, f"AGENT · {target}")
    planner_kind = "LLM" if api_key else "deterministic"
    console.print(
        f"[orthrus.muted]planner: {planner_kind} · aggressiveness: {aggressiveness} · "
        f"max-steps: {max_steps} · scope-enforced · non-destructive[/]\n"
    )
    if report.plan:
        console.print("[orthrus.accent]Plan:[/]")
        for a in report.plan:
            console.print(f"  • {a.tool}[orthrus.muted] - {a.rationale}[/]")
    for i, step in enumerate(report.steps, 1):
        console.print(
            f"\n[orthrus.accent]Step {i}:[/] ran {', '.join(step.modules)} "
            f"[orthrus.muted]→ {step.new_findings} finding(s)[/]"
        )
    console.print(f"\n[status.completed]{report.summary()}[/]")


@cli.command(name="iac")
@click.argument("path", type=click.Path(exists=True))
@click.option("--output", "-o", default=None, help="Write findings as JSON to this path.")
@click.option(
    "--fail-on",
    type=click.Choice(["critical", "high", "medium", "low", "info"]),
    default=None,
    help="Exit non-zero if a finding at/above this severity is found (for CI).",
)
@click.option("--verbose", "-v", default="warning", help="Log level.")
def iac_cmd(path: str, output: str | None, fail_on: str | None, verbose: str) -> None:
    """Audit Infrastructure-as-Code for misconfigurations (offline, no network).

    Scans Dockerfiles, docker-compose, and Terraform under PATH (a file or a
    directory) for root containers, unpinned/secret-bearing images, privileged
    or docker-socket-mounted services, world-open security groups, public
    buckets, unencrypted storage, and hardcoded secrets.
    """
    configure_logging(verbose)
    from orthrus.iac import analyze_path

    findings = analyze_path(path)
    section(console, "IAC AUDIT")
    if findings:
        console.print(findings_table(findings))
    else:
        console.print("[green]No IaC misconfigurations found.[/]")

    if output:
        payload = {"findings": [f.model_dump(mode="json") for f in findings]}
        with open(output, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, default=str)
        console.print(f"wrote {len(findings)} finding(s) to {output}")

    if fail_on:
        order = ["info", "low", "medium", "high", "critical"]
        threshold = order.index(fail_on)
        worst = max((order.index(f.severity.value) for f in findings), default=-1)
        if worst >= threshold:
            raise SystemExit(1)


@cli.command(name="cloud")
@click.argument("snapshot", type=click.Path(exists=True), required=False)
@click.option("--provider", type=click.Choice(["aws"]), default="aws", help="Cloud provider (for --live).")
@click.option("--live", is_flag=True,
              help="Collect a read-only inventory from the provider (needs credentials + [cloud] extra).")
@click.option("--regions", default="us-east-1", help="Comma-separated regions for --live collection.")
@click.option("--toxic-only", is_flag=True, help="Show only the correlated toxic-combination paths.")
@click.option("--output", "-o", default=None, help="Write findings as JSON to this path.")
@click.option(
    "--fail-on", type=click.Choice(["critical", "high", "medium", "low", "info"]), default=None,
    help="Exit non-zero if a finding at/above this severity is found (for CI).",
)
@click.option("--verbose", "-v", default="warning", help="Log level.")
def cloud_cmd(
    snapshot: str | None, provider: str, live: bool, regions: str, toxic_only: bool,
    output: str | None, fail_on: str | None, verbose: str,
) -> None:
    """Assess cloud security posture (CSPM/IAM) from a snapshot or read-only collection.

    Consumes a normalized inventory JSON (SNAPSHOT) - or, with --live, collects one
    read-only from the provider using your own credentials - and reports public /
    unencrypted / over-privileged resources plus the CRITICAL *toxic combinations*
    an attacker would chain (internet-reachable workload + privileged role, admin
    user without MFA, PassRole escalation). Read-only: it never modifies anything.
    """
    configure_logging(verbose)
    from orthrus.cloud.models import CloudInventory
    from orthrus.cloud.toxic import analyze_cloud, toxic_combinations

    if live:
        from orthrus.cloud.collect import collect_aws
        try:
            inv = collect_aws(regions=tuple(r.strip() for r in regions.split(",") if r.strip()))
        except RuntimeError as exc:
            raise click.ClickException(str(exc)) from exc
    elif snapshot:
        with open(snapshot, encoding="utf-8") as fh:
            inv = CloudInventory.from_dict(json.load(fh))
    else:
        raise click.UsageError("provide a SNAPSHOT inventory file, or use --live to collect one")

    findings = toxic_combinations(inv) if toxic_only else analyze_cloud(inv)
    section(console, f"CLOUD POSTURE · {inv.provider} {inv.account_id}".rstrip())
    if findings:
        console.print(findings_table(findings))
        combos = sum(1 for f in findings if f.vuln_type == "cloud-toxic-combo")
        console.print(
            f"\n[orthrus.muted]{len(inv.resources)} resource(s) · {len(findings)} finding(s) · "
            f"{combos} toxic combination(s)[/]"
        )
    else:
        console.print("[green]No cloud posture issues found.[/]")

    if output:
        payload = {"findings": [f.model_dump(mode="json") for f in findings]}
        with open(output, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, default=str)
        console.print(f"wrote {len(findings)} finding(s) to {output}")

    if fail_on:
        order = ["info", "low", "medium", "high", "critical"]
        threshold = order.index(fail_on)
        worst = max((order.index(f.severity.value) for f in findings), default=-1)
        if worst >= threshold:
            raise SystemExit(1)


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
    from orthrus.benchmark.runner import load_truth

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
    from orthrus.benchmark.runner import run_benchmark

    report = await run_benchmark(config, get_settings(), expected, confirm=confirm)
    _print_benchmark(report, truth_name, config.target)
    if output:
        _write_benchmark_json(report, truth_name, config.target, output)
        logger.info("benchmark result written to %s", output)


def _print_benchmark(report: object, truth_name: str, target: str) -> None:
    from rich.table import Table

    from orthrus.utils.logger import console

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
