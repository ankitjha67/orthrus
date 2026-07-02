# Security Policy

ORTHRUS is an **offensive security tool** for **authorized** testing. This policy
covers vulnerabilities **in ORTHRUS itself** — not findings you produced *with* it
against some third-party system (those belong to that system's disclosure
process, and only if you were authorized to test it).

## What's in scope

High-signal issues in the tool that could cause real harm:

- **Scope-enforcement bypass** — any way ORTHRUS sends a request to a host / port /
  path that the engagement `ScopeConfig` did not authorize (this is the load-bearing
  safety control; a bypass is the most serious class of bug here).
- **DNS-rebinding / redirect escapes** that reach an out-of-scope address.
- **Secret / credential leakage** — the tool writing API keys, tokens, or
  exploited data into reports/logs unredacted, or committing them.
- **Unsafe deserialization / RCE** in ORTHRUS's own parsing of responses, specs,
  configs, templates, or plugins.
- **Encryption-at-rest failures** when `ORTHRUS_ENCRYPTION_KEY` is set.
- Path traversal / arbitrary write via report output, plugin loading, or spec import.

Out of scope: vulnerabilities in third-party dependencies (report those upstream),
theoretical issues with no exploit path, and "the tool successfully attacked a lab
target" (that's the intended behavior).

## How to report

**Please do not open a public issue for a security bug.** Use either:

1. **GitHub private vulnerability reporting** — the repo's *Security → Report a
   vulnerability* tab (preferred; keeps the report private until a fix ships), or
2. **Email** the maintainer at **ankitjha67@gmail.com** with `[ORTHRUS SECURITY]`
   in the subject.

Include: affected version/commit, a minimal reproduction (ideally against the
bundled `tests/integration/reflecting_target.py` or `example.com`, **never** a live
third-party host), the impact, and any suggested fix.

## What to expect

This is a solo, best-effort open-source project — timelines are targets, not SLAs:

- **Acknowledgement** within ~72 hours.
- **Initial assessment** within ~1 week.
- A fix or mitigation for confirmed high-impact issues (especially scope bypasses)
  prioritized over feature work.

Please give a reasonable window (**90 days**, or sooner once a fix is released)
before public disclosure. Reporters who want credit will be acknowledged in the
release notes.

## Supported versions

Pre-1.0: only the latest `main` is supported. Security fixes land there; there are
no back-ported patch releases yet.

## Using ORTHRUS safely

- Only run it against systems you **own** or are **explicitly authorized** to test.
- Keep scope enforcement enabled; treat any need to disable it as a red flag.
- Reports may contain sensitive data — `reports/`, local DBs, and `.env` are
  git-ignored by default; keep them that way.
