"""Correlate operator-graph findings into persistent attack-chain edges (PRD §7.8).

Reuses the curated scan-level kill-chain catalog (``orthrus.chains.CHAIN_RULES``)
and materializes it as ``FindingChain`` edges between a program's ProgramFindings,
so the operator graph carries the same "SSRF enables metadata read" narratives the
scan-level report shows, but persistent and per-program. Rule-proposed edges are
tentative until an operator accepts them (``accept_finding_chain``).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from orthrus.chains import CHAIN_RULES

if TYPE_CHECKING:
    from orthrus.model.entities import FindingChain
    from orthrus.model.store import ProgramGraph

# every curated rule is an "upstream enables downstream" path.
_RELATIONSHIP = "enables"
_SEV_CONFIDENCE = {"critical": 0.9, "high": 0.75, "medium": 0.6, "low": 0.4, "info": 0.3}


async def correlate_program_chains(graph: ProgramGraph, program_id: str) -> list[FindingChain]:
    """Materialize attack-chain edges between a program's findings; return NEW edges.

    For each catalog rule, pairs every finding matching the upstream link with every
    finding matching the downstream link and records a deduped ``enables`` edge. Idempotent.
    """
    findings = await graph.list_findings(program_id)
    if len(findings) < 2:
        return []
    by_class: dict[str, list] = {}
    for f in findings:
        by_class.setdefault(f.vuln_class, []).append(f)

    created: list[FindingChain] = []
    for rule in CHAIN_RULES:
        upstream_link, downstream_link = rule.links[0], rule.links[1]
        ups = [f for vt in upstream_link.vuln_types for f in by_class.get(vt, [])]
        downs = [f for vt in downstream_link.vuln_types for f in by_class.get(vt, [])]
        if not ups or not downs:
            continue
        conf = _SEV_CONFIDENCE.get(rule.severity, 0.5)
        for up in ups:
            for down in downs:
                if up.id == down.id:
                    continue
                edge, is_new = await graph.add_finding_chain(
                    up.id, down.id, _RELATIONSHIP,
                    narrative_md=f"**{rule.name}** - {rule.impact}",
                    confidence=conf, proposed_by="rules",
                )
                if is_new:
                    created.append(edge)
    return created


__all__ = ["correlate_program_chains"]
