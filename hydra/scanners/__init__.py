"""Scanner package.

Importing this package registers all built-in scanners with the registry via
their ``@register`` decorators (import side-effects below). New scanner modules
should be added here so the orchestrator can discover them.
"""

from hydra.scanners import (  # noqa: F401  (registration side-effects)
    auth,
    cache_poisoning,
    cmd_injection,
    cors,
    csrf,
    deserialization,
    dom_xss,
    graphql,
    headers,
    idor,
    jwt_analyzer,
    lfi,
    open_redirect,
    sqli,
    ssrf,
    ssti,
    stored_xss,
    tls_analyzer,
    xss,
    xxe,
)
