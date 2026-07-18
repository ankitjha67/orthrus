# Bounty v2.0 — PRD → plan

The ORTHRUS **v2.0 "Unified Bug Bounty Operator Platform"** PRD describes a
44-week product: a Rust core, a Tauri cockpit, continuous cloud recon, a RAG
copilot, a managed SaaS tier, and team mode. This document maps that vision onto
what actually exists today and turns it into an **honest, incremental plan** the
current Python codebase can execute — without a rewrite and without pretending a
platform ships in a session.

**Guiding decision.** ORTHRUS stays a Python DAST + operator toolkit. We expand
the existing `orthrus/bounty/` module toward the PRD's *spirit* — authorization,
continuous recon, triage, platform-native reporting, a grounded copilot — one
tested, merged PR at a time. The Rust/Tauri/managed-SaaS layer is a separate
business bet, deliberately **not** started as part of "expand the bounty module".

Status legend: ✅ have · 🟡 partial · 🛠 build-now (Python, in-reach) · 🔑 needs
an account/credential/infra · 🏗 major rewrite / separate product bet.

## Subsystem map

| PRD subsystem | Status | Where it stands / next step |
|---|---|---|
| Scope enforcement (§5) | ✅ | Deny-by-default client + bounty scope intake. |
| **Authorization model + kill-list** (§2.3/§6/§11) | ✅ | Shipped: `bounty/authorization.py` (program URL / signed / direct / self-lab; public scope refused without it) + `bounty/killlist.py` (gov/mil/edu/health/sanctioned refused unless attested). |
| Program record + scope_entries (§6) | 🟡→🛠 | Authorization is captured; a persisted `programs` store (pause, jurisdiction, expiry, history) is next. |
| Recon engine — continuous / diff / CT-log (§7.2) | 🟡→🛠 | Have subdomain enum + recon modules. Next: **expand `*.wildcard` → live in-scope subdomains before scanning**; then diffing + a per-program scheduler; then external adapters (subfinder/amass/dnsx/httpx). CT-log + cloud workers are heavier. |
| Scan engine (§7.3) | ✅ + 🛠 | 59 scanners today; `--tools nuclei` exists. Adapters for sqlmap/dalfox/ffuf are build-now. |
| Confirm engine (§7.4) | ✅ + 🛠 | 19 confirmers, incl. XXE-OOB and deserialization-OOB (shipped). Next: SSRF→cloud-metadata chain, single-packet race. |
| Triage engine (§7.5) | 🟡→🛠 | Have dedup + lifecycle. Next: composite **priority scoring**, cross-program dedup, "similar finding in your history", optional LLM FP-judge. |
| Reporting engine (§7.6) | 🟡→🛠 | Submission-ready per-bug reports + AI report exist. Next: **platform-native templates** (H1/BC/Intigriti/YWH/Immunefi). Live submission APIs are 🔑 (your platform tokens). |
| AI copilot / RAG (§7.7) | 🟡→🛠 | AI report is grounded in evidence. A RAG copilot over your own findings/notes + vendored corpora (HackTricks/PayloadsAllTheThings) is build-now (LanceDB or sqlite-vec). |
| Attack graph (§7.8) | ✅ + 🛠 | `chains`/`graph` exist. Next: wire the SSRF→metadata and JWT→BOLA chains as first-class. |
| Monitoring & notifications (§7.9) | 🟡→🛠 | `notify` (Slack/Jira) exists. Next: per-program schedule + digest wired to bounty campaigns. |
| Vuln-class ontology (Appendix B) | 🟡→🛠 | Have attack-map + CVSS defaults. Formalize a versioned ontology module (severity/CVSS/CWE/OWASP/ATT&CK + `default_confidence_ceiling` + `is_destructive`). |
| Audit log (§6/§8.5) + cost ledger (§10) | 🛠 | Hash-chained append-only audit of scope decisions/requests; per-program cost tracking. |
| Payments/bounty tracking (§7.12), Notes (§7.13) | 🛠 | Both are self-contained Python additions. |
| Multi-domain: mobile/web3/LLM/cloud (Phase 5) | 🛠/🔑 | Adapter wrappers (MobSF/slither/garak/prowler) are build-now; several need the external binary installed. |
| Burp/Caido bridge (§7.10) | 🔑/🏗 | ORTHRUS side is buildable; the Burp/Caido extensions are separate Java/TS projects. |
| Team mode, OIDC/SCIM (§7.11) · Rust core + Tauri (§5) · Managed SaaS + Stripe + SOC2 (Phase 7) | 🏗 | Separate product bet. **Not** part of expanding the Python bounty module; revisit as a deliberate, resourced effort. |

## Build-now queue (Python, in-reach, one PR each)

1. ✅ **Authorization + kill-list** — *this PR.*
2. ✅ **Subdomain expansion recon** — `bounty/assets.py`: a `*.wildcard` scope is expanded into its live in-scope subdomains (crt.sh + DNS), filtered against exclusions + kill-list, via `--enumerate`.
3. ✅ **Platform-native report templates** — `bounty/platforms.py` + `--platform`: per-bug reports shaped for HackerOne / Bugcrowd (P1–P5) / Intigriti / YesWeHack / Immunefi (gist reminder).
4. ✅ **Program store** — `bounty/store.py` + `--program NAME` + `orthrus programs`: persist a program's authorization + scope + campaign history (JSON at `$ORTHRUS_HOME/programs.json`); re-run by name.
5. ✅ **Triage priority scoring** — `bounty/triage.py`: a 0–100 composite (severity × confidence + CVSS) ranks the bug queue so a confirmed medium outranks a tentative high; shown + sorted-on in the report index. (Cross-program dedup + history recall still to come.)
6. ✅ **Vuln-class ontology** — `bounty/ontology.py` (versioned): per-class `confidence_ceiling` + `is_destructive` governance metadata; destructive classes get a manual-verification caution in the report.
7. 🚧 **Audit log** — `bounty/audit.py` + `orthrus audit [--verify]`: hash-chained, append-only JSONL of authorization / kill-list refusals / campaigns; `verify()` pinpoints tampering. (Cost ledger still to come.)
8. **Attack chains**: SSRF→cloud-metadata, JWT→BOLA.
9. **Continuous monitoring** (per-program schedule + notifications + new-asset → auto-scan).
10. **RAG copilot** over your findings/notes + vendored knowledge.
11. **External-tool adapter layer** + multi-domain (mobile/web3/LLM/cloud) adapters.

## Needs you (the 🔑 items)

Platform submission tokens (H1/BC/Intigriti/YWH/Immunefi) for live filing · an
OAST domain/host for internet-facing OOB confirmation · a hosting target if you
want continuous cloud recon · LLM/API keys for the copilot. Everything else on
the build-now queue is code I can land.

## Explicitly out of session scope (separate product bet)

Rust core rewrite · Tauri desktop app · managed cloud tier · Stripe billing ·
OIDC/SCIM team mode · SOC 2. These are real and in the PRD, but they are a
company, not a module expansion — call them out as a funded effort, not a turn.
