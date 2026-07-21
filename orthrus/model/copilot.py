"""Copilot retrieval over the operator graph (PRD §7.7).

Grounds the copilot in the program's *own* data - its findings and notes - using
the same dependency-free BM25-lite ranker the bounty copilot uses. Returns cited
snippets (never invents): the retrieval layer that a LanceDB + BGE embedding
backend can transparently replace, and that an LLM step can synthesize on top of
while staying held to the retrieved context.
"""

from __future__ import annotations

from orthrus.bounty.copilot import Doc, Hit, rank
from orthrus.model.store import ProgramGraph


async def gather_graph_corpus(graph: ProgramGraph, program_id: str) -> list[Doc]:
    """Build the retrieval corpus from a program's findings + notes."""
    docs: list[Doc] = []
    for f in await graph.list_findings(program_id):
        text = (f"{f.vuln_class} {f.title} {f.description_md or ''} "
                f"severity {f.severity} confidence {f.confidence} status {f.status} "
                f"tool {f.found_by_tool}")
        docs.append(Doc(f"finding:{f.id}", f.title, text))
    for n in await graph.list_notes(program_id=program_id):
        tags = " ".join(str(t) for t in (n.tags or []))
        docs.append(Doc(f"note:{n.id}", n.title, f"{n.title}\n{n.markdown}\n{tags}"))
    return docs


async def retrieve(graph: ProgramGraph, program_id: str, query: str, *, k: int = 5) -> list[Hit]:
    """Top-k cited snippets from the program's own findings + notes."""
    return rank(query, await gather_graph_corpus(graph, program_id), k=k)


__all__ = ["gather_graph_corpus", "retrieve"]
