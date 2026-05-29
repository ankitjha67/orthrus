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
    crlf,
    csrf,
    cve_matcher,
    default_creds,
    deserialization,
    dom_xss,
    exposed_files,
    file_upload,
    framework_debug,
    graphql,
    headers,
    host_header,
    idor,
    jwt_analyzer,
    lfi,
    llm,
    mass_assignment,
    nosql,
    open_redirect,
    product_cve,
    prototype_pollution,
    race_condition,
    request_smuggling,
    sca,
    service_exposure,
    sqli,
    sspp,
    ssrf,
    ssti,
    stored_xss,
    subdomain_takeover,
    tls_analyzer,
    web_cache_deception,
    websocket,
    xss,
    xxe,
)
from orthrus.templates import (
    scanner as _template_scanner,  # noqa: F401  (registers TemplateScanner)
)
