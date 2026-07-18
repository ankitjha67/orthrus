"""Bug-bounty engagement runner (authorized programs only).

A thin orchestration layer over the core pipeline that models how a bug-bounty
hunter actually works: take a **program's authorized scope** (in-scope assets and,
critically, the out-of-scope exclusions), scan every in-scope asset with the full
scanner + confirmation pipeline, then emit **submission-ready per-bug reports**.

Scope is load-bearing here for the same reason it is everywhere in ORTHRUS: a
bug-bounty program authorizes testing of *specific* assets only, and touching an
out-of-scope host is both a rules violation (bans, disqualified bounties) and,
depending on jurisdiction, illegal. This module therefore refuses to run without
an explicit program scope and enforces it deny-by-default through the same
scope-checked HTTP client the rest of the tool uses.
"""

from orthrus.bounty.scope_intake import ProgramScope, parse_program_scope

__all__ = ["ProgramScope", "parse_program_scope"]
