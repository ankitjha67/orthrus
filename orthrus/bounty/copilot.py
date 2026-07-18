"""A copilot grounded in *your own* data (PRD §7.7).

Not a general chat: it retrieves over the operator's own notes and submissions and
answers only from what it finds. Retrieval is a dependency-free BM25-lite keyword
score (no embedding model to download); an optional LLM turns the retrieved
snippets into prose, but is held to the context — if nothing relevant is found it
says so rather than inventing a finding.

Corpus = your [[notes]] + tracked [[submissions]] + your cross-run finding
[[history]] (so "have I found SSRF on acme before?" is answerable from real data).
The LLM step reuses ``orthrus.ai.providers`` and only runs when you pass
``--llm``; otherwise you get the raw retrieved snippets, which never lie.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass

from orthrus.bounty.history import HistoryStore
from orthrus.bounty.notes import NotesStore
from orthrus.bounty.submissions import SubmissionStore

SYSTEM_PROMPT = (
    "You are a bug-bounty copilot answering strictly from the CONTEXT below, which is the "
    "operator's own notes and past submissions. Rules: answer ONLY from the context; cite the "
    "[source] tag for each claim; if the context does not contain the answer, say 'I don't see "
    "that in your data.' Never invent findings, payloads, or facts not present in the context."
)


@dataclass(frozen=True)
class Doc:
    source: str   # e.g. "note:ab12" / "submission:cd34"
    title: str
    text: str


@dataclass(frozen=True)
class Hit:
    source: str
    title: str
    snippet: str
    score: float


def _tokens(s: str) -> list[str]:
    return re.findall(r"[a-z0-9]{2,}", (s or "").lower())


def gather_corpus() -> list[Doc]:
    docs: list[Doc] = []
    for n in NotesStore().list():
        docs.append(Doc(f"note:{n.id}", n.title, f"{n.title}\n{n.body}\n{' '.join(n.tags)}"))
    for s in SubmissionStore().list():
        docs.append(Doc(f"submission:{s.id}", s.title,
                        f"{s.title} [{s.status}] {s.program} {s.notes}"))
    for r in HistoryStore().records():
        progs = " ".join(r["programs"])
        docs.append(Doc(f"finding:{r['vuln_type']}@{r['host']}",
                        f"{r['title']} on {r['host']}",
                        f"{r['vuln_type']} {r['title']} on {r['host']} {progs} "
                        f"(seen in {r['count']} run(s), last {r['last_seen']})"))
    return docs


def rank(query: str, docs: list[Doc], *, k: int = 5) -> list[Hit]:
    """BM25-lite ranking of ``docs`` against ``query`` (no external deps)."""
    q_terms = set(_tokens(query))
    if not q_terms or not docs:
        return []
    tokenized = [(d, _tokens(d.text)) for d in docs]
    n = len(tokenized)
    df = {t: sum(1 for _, toks in tokenized if t in toks) for t in q_terms}
    avgdl = sum(len(toks) for _, toks in tokenized) / n
    k1, b = 1.5, 0.75
    scored: list[Hit] = []
    for d, toks in tokenized:
        dl = len(toks) or 1
        score = 0.0
        for t in q_terms:
            if not df.get(t):
                continue
            tf = toks.count(t)
            idf = math.log(1 + (n - df[t] + 0.5) / (df[t] + 0.5))
            score += idf * (tf * (k1 + 1)) / (tf + k1 * (1 - b + b * dl / avgdl))
        if score > 0:
            scored.append(Hit(d.source, d.title, d.text[:500].strip(), round(score, 3)))
    scored.sort(key=lambda h: -h.score)
    return scored[:k]


def retrieve(query: str, *, k: int = 5) -> list[Hit]:
    return rank(query, gather_corpus(), k=k)


def build_prompt(query: str, hits: list[Hit]) -> str:
    context = "\n\n".join(f"[{h.source}] {h.title}\n{h.snippet}" for h in hits)
    return f"CONTEXT:\n{context}\n\nQUESTION: {query}"


__all__ = ["Doc", "Hit", "SYSTEM_PROMPT", "gather_corpus", "rank", "retrieve", "build_prompt"]
