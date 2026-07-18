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
| Scan engine (§7.3) | ✅ + 🛠 | 59 scanners today; `--tools nuclei` exists. **dalfox** (XSS) + **testssl** (TLS) adapters added; sqlmap/ffuf still to come. |
| Confirm engine (§7.4) | ✅ + 🛠 | 19 confirmers, incl. XXE-OOB and deserialization-OOB (shipped). Next: SSRF→cloud-metadata chain, single-packet race. |
| Triage engine (§7.5) | ✅ + 🛠 | Composite **priority scoring** (`bounty/triage.py`), cross-run history recall (`bounty/history.py`), LLM FP-judge (`orthrus triage --llm`), and per-program **mute rules** (`bounty/suppress.py` + `orthrus suppress`/`suppressions`): known-noise findings are kept out of the queue (counted, never silently hidden). Next: cross-program near-dup clustering. |
| Reporting engine (§7.6) | ✅ + 🛠 | Submission-ready per-bug reports, **platform-native templates** (H1/BC/Intigriti/YWH/Immunefi via `--platform`), cross-run duplicate flagging (♻), and a machine-readable **`findings.json`** (ranked queue + counts + `prior_seen`, for automation/diffing) written alongside the Markdown. Live submission APIs are 🔑 (your platform tokens). |
| AI copilot / RAG (§7.7) | 🟡→🛠 | AI report is grounded in evidence. A RAG copilot over your own findings/notes + vendored corpora (HackTricks/PayloadsAllTheThings) is build-now (LanceDB or sqlite-vec). |
| Attack graph (§7.8) | ✅ + 🛠 | `chains`/`graph` exist. Next: wire the SSRF→metadata and JWT→BOLA chains as first-class. |
| Monitoring & notifications (§7.9) | 🟡→🛠 | `notify` (Slack/Jira) exists. Next: per-program schedule + digest wired to bounty campaigns. |
| Vuln-class ontology (Appendix B) | 🟡→🛠 | Have attack-map + CVSS defaults. Formalize a versioned ontology module (severity/CVSS/CWE/OWASP/ATT&CK + `default_confidence_ceiling` + `is_destructive`). |
| Audit log (§6/§8.5) + cost ledger (§10) | ✅ | Hash-chained append-only audit of scope decisions/requests (`orthrus audit`); per-program cost ledger (`orthrus cost`) — LLM spend auto-recorded by the copilot, blended per-model estimate, `ORTHRUS_LLM_RATE` override. |
| Payments/bounty tracking (§7.12) | ✅ | `bounty/submissions.py` + `orthrus submission`/`submissions`: track status + payouts, roll up earnings. Notes (§7.13): ✅ `bounty/notes.py` + `orthrus note`/`notes` (tagged, searchable knowledge base). |
| Multi-domain: mobile/web3/LLM/cloud (Phase 5) | 🛠/🔑 | Adapter wrappers (MobSF/slither/garak/prowler) are build-now; several need the external binary installed. |
| Burp/Caido bridge (§7.10) | 🔑/🏗 | ORTHRUS side is buildable; the Burp/Caido extensions are separate Java/TS projects. |
| Team mode, OIDC/SCIM (§7.11) · Rust core + Tauri (§5) · Managed SaaS + Stripe + SOC2 (Phase 7) | 🏗 | Separate product bet. **Not** part of expanding the Python bounty module; revisit as a deliberate, resourced effort. |

## Build-now queue (Python, in-reach, one PR each)

1. ✅ **Authorization + kill-list** — *this PR.*
2. ✅ **Subdomain expansion recon** — `bounty/assets.py`: a `*.wildcard` scope is expanded into its live in-scope subdomains (crt.sh + DNS), filtered against exclusions + kill-list, via `--enumerate`.
3. ✅ **Platform-native report templates** — `bounty/platforms.py` + `--platform`: per-bug reports shaped for HackerOne / Bugcrowd (P1–P5) / Intigriti / YesWeHack / Immunefi (gist reminder).
4. ✅ **Program store + traffic policy** — `bounty/store.py` + `--program NAME` + `orthrus programs`: persist a program's authorization + scope + campaign history (JSON at `$ORTHRUS_HOME/programs.json`); re-run by name. `orthrus program-policy` records a **rate ceiling** (honored as a hard cap on every run) and an **identifying header** (attached to every request) — courtesy + ban-avoidance, applied automatically.
5. ✅ **Triage priority scoring** — `bounty/triage.py`: a 0–100 composite (severity × confidence + CVSS) ranks the bug queue so a confirmed medium outranks a tentative high; shown + sorted-on in the report index. History recall (`bounty/history.py`) flags bugs seen in earlier runs.
6. ✅ **Vuln-class ontology** — `bounty/ontology.py` (versioned): per-class `confidence_ceiling` + `is_destructive` governance metadata; destructive classes get a manual-verification caution in the report.
7. ✅ **Audit log + cost ledger** — `bounty/audit.py` + `orthrus audit [--verify]`: hash-chained, append-only JSONL of authorization / kill-list refusals / campaigns; `verify()` pinpoints tampering. `bounty/cost.py` + `orthrus cost [--program]`: append-only JSONL spend ledger — the copilot auto-records LLM token cost (blended per-model estimate, `ORTHRUS_LLM_RATE` override), rolled up by provider/category/program.
8. **Attack chains**: SSRF→cloud-metadata, JWT→BOLA.
9. 🚧 **Notifications & asset monitoring** — `orthrus bounty --notify-slack` (or `ORTHRUS_SLACK_WEBHOOK`) posts a campaign summary. Cross-run **new-asset detection**: `bounty/asset_monitor.py` snapshots a saved program's live in-scope hosts each `--enumerate` run and flags which are NEW since last time (fresh, untested surface — the highest-signal bounty event; audit-logged as `asset-drift`); `orthrus bounty-assets --program NAME` shows the inventory. (Time-based auto-scheduling still to come — pair with the existing `orthrus monitor --watch`.)
10. ✅ **Data-grounded copilot** — `bounty/copilot.py` + `orthrus copilot "…"`: BM25-lite retrieval over your notes + submissions (no embedding deps), optional `--llm` grounding held to the context (never invents). Embeddings + vendored corpora (HackTricks/PayloadsAllTheThings) are a follow-up.
11. 🚧 **External-tool adapters** — expanded the catalog beyond nuclei: `dalfox` (XSS), `testssl` (TLS), `ffuf` (content discovery), `nikto` (web-server misconfig, conservatively rated), `wpscan` (WordPress core/plugin/theme CVEs + exposed debug-log/listing). Each is a tested JSON parser + `@register_tool` class that normalizes to ORTHRUS Findings (run via `orthrus scan --tools` / `orthrus bounty --tools`); binaries absent on PATH are skipped cleanly. Multi-domain (mobile/web3/LLM/cloud) still to come.

## Needs you (the 🔑 items)

Platform submission tokens (H1/BC/Intigriti/YWH/Immunefi) for live filing · an
OAST domain/host for internet-facing OOB confirmation · a hosting target if you
want continuous cloud recon · LLM/API keys for the copilot. Everything else on
the build-now queue is code I can land.

## Explicitly out of session scope (separate product bet)

Rust core rewrite · Tauri desktop app · managed cloud tier · Stripe billing ·
OIDC/SCIM team mode · SOC 2. These are real and in the PRD, but they are a
company, not a module expansion — call them out as a funded effort, not a turn.
