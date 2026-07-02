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
from orthrus.core.schemas import Aggressiveness
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
    the operator did *not* pass explicitly — so the command line overrides the
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
    type=click.Choice(["json", "html", "pdf", "csv", "sarif", "md"]),
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
        # Each target gets its own scope — auto-derived per target unless an
        # explicit --scope was given — so the engagement boundary is correct for
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
    type=click.Choice(["json", "html", "pdf", "csv", "sarif", "md"]),
    help="Report format.",
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
    triage listing, and that material can carry sensitive payloads — it stays in
    the encrypted store and the full report, never on stdout.
    """
    return {
        "vuln_type": row.vuln_type,
        "title": row.title,
        "severity": row.severity,
        "confidence": row.confidence,
        "url": row.url,
        "parameter": row.parameter,
        "cwe": row.cwe,
        "cvss_score": row.cvss_score,
        "scanner": row.scanner,
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

    A read-only, network-free view of what a previous scan found — the quick
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
    # Highest severity first, then by type, so the riskiest findings lead — the
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
    the handful of issues that actually need fixing — each with its severity, a
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
                row.append("—")
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
    mediums — together they're RCE on the internal network. This matches the
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
    kill-chains — e.g. LFI → exposed-secret → JWT-forgery becomes one three-step
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

    Casts a passive net — Certificate Transparency, reverse-IP / co-hosting, a
    /24 reverse-DNS sweep, and Wayback — and folds the results into one
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
        logger.warning("gathering hosts for %s — this queries CT/Wayback/reverse-IP and sweeps a /24…", host)
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
            ", ".join(g.ips) or "[orthrus.muted]—[/]",
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
    *attack surface* (recon only) — hosts that appeared/vanished, new IPs, newly
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
            f"[orthrus.muted]First snapshot — {drift.current_count} host(s) recorded "
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
            t.add_row(a.fqdn, ", ".join(a.ips) or "—", a.discovery_method)
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
                ", ".join(c.new_ips) or "—",
                ", ".join(str(p) for p in c.new_ports) or "—",
                removed or "—",
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
    changing, so they are deliberately excluded from the key — a fixed bug that
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
    ]
    return {
        "orthrus_version": __version__,
        "python": platform.python_version(),
        "platform": platform.platform(),
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
    refreshes independently — one failing does not abort the other.
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
def serve(host: str, port: int) -> None:
    """Run the ORTHRUS REST API (read access to scans/findings over HTTP).

    Needs the [api] extra (fastapi + uvicorn). Endpoints: /health, /api/scans,
    /api/scans/{id}, /api/scans/{id}/findings, /api/scans/{id}/report.
    """
    try:
        import uvicorn
    except ImportError as exc:
        raise click.ClickException(
            "the API server needs the [api] extra: pip install 'orthrus-framework[api]'"
        ) from exc
    from orthrus.api import create_app

    click.echo(f"ORTHRUS API on http://{host}:{port}  (docs at /docs)")
    uvicorn.run(create_app(), host=host, port=port)


@cli.command(name="mcp")
def mcp_cmd() -> None:
    """Run the ORTHRUS MCP server (stdio) — expose scans/findings as agent tools.

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
