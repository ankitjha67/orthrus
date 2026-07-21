"""Traffic bridges — import proxy history from Burp Suite / Caido into the graph.

An operator's Burp or Caido session already holds the real, authenticated attack
surface (routes, params, methods) they browsed by hand. These bridges parse those
tools' export formats into a neutral :class:`CapturedRequest` and fold each host →
``ProgramAsset`` and route → ``ProgramEndpoint`` in the operator graph — so manual
recon flows into the same scan/triage/report pipeline (PRD §7.12, Phase 6).

Deny-by-default holds on import too: a scope predicate can refuse out-of-scope
hosts (third-party CDNs, analytics) that inevitably appear in a proxy history.
"""

from orthrus.bridges.base import (
    CapturedRequest,
    TrafficImportResult,
    endpoint_juicy_score,
    fold_traffic,
)
from orthrus.bridges.burp import UnsafeXmlError, parse_burp_xml
from orthrus.bridges.caido import parse_caido_json
from orthrus.bridges.har import parse_har

# format name -> parser, for the CLI/REST to dispatch on --format.
PARSERS = {
    "burp": parse_burp_xml,
    "caido": parse_caido_json,
    "har": parse_har,
}

__all__ = [
    "CapturedRequest",
    "TrafficImportResult",
    "UnsafeXmlError",
    "PARSERS",
    "endpoint_juicy_score",
    "fold_traffic",
    "parse_burp_xml",
    "parse_caido_json",
    "parse_har",
]
