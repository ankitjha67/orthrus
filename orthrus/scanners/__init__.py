"""Scanner package.

Importing this package registers all built-in scanners with the registry via
their ``@register`` decorators (import side-effects below). New scanner modules
should be added here so the orchestrator can discover them.
"""

from orthrus.scanners import (  # noqa: F401  (registration side-effects)
    auth,
    business_logic,
    cache_poisoning,
    cmd_injection,
    cors,
    csrf,
    cve_matcher,
    default_creds,
    deserialization,
    dom_xss,
    exposed_files,
    graphql,
    headers,
    idor,
    jwt_analyzer,
    lfi,
    mass_assignment,
    open_redirect,
    prototype_pollution,
    race_condition,
    sqli,
    ssrf,
    ssti,
    stored_xss,
    tls_analyzer,
    websocket,
    xss,
    xxe,
)
from orthrus.templates import (
    scanner as _template_scanner,  # noqa: F401  (registers TemplateScanner)
)
