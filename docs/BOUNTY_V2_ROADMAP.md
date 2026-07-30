# Bounty v2.0 - PRD → plan

The ORTHRUS **v2.0 "Unified Bug Bounty Operator Platform"** PRD describes a
44-week product: a Rust core, a Tauri cockpit, continuous cloud recon, a RAG
copilot, a managed SaaS tier, and team mode. This document maps that vision onto
what actually exists today and turns it into an **honest, incremental plan** the
current Python codebase can execute - without a rewrite and without pretending a
platform ships in a session.

**Guiding decision.** ORTHRUS stays a Python DAST + operator toolkit. We expand
the existing `orthrus/bounty/` module toward the PRD's *spirit* - authorization,
continuous recon, triage, platform-native reporting, a grounded copilot - one
tested, merged PR at a time. The Rust/Tauri/managed-SaaS layer is a separate
business bet, deliberately **not** started as part of "expand the bounty module".

Status legend: ✅ have · 🟡 partial · 🛠 build-now (Python, in-reach) · 🔑 needs
an account/credential/infra · 🏗 major rewrite / separate product bet.

## Delivered (v2.0 operator platform, shipped 2026-07)

The plan below has since been **executed**. The full v2.0 operator platform (PRD
Phases 0-7) shipped as the PR chain #28-#37, all merged to `main`, 1438 tests green.
The tables further down are kept as the historical plan; here is what actually landed:

| Phase | Delivered | Where it lives |
|---|---|---|
| 0 - Unified domain model | Program-anchored operator graph (assets/endpoints/scan-runs/findings/evidence/audit/cost) on the shared DB; REST API; Tauri/React cockpit (5 tabs); `orthrus panic`; v0.1->v2.0 migration | `orthrus/model/`, `orthrus/api/programs.py`, `cockpit/` |
| 1 - Continuous recon | Adapter framework + pure-Python sources (crt.sh/certspotter/DNS/wayback) + subfinder/amass; wildcard-DNS detection; new-asset diff; Slack/Discord alerts; `recon-run`/`recon-watch` | `orthrus/recon_engine/` |
| 2 - Scan -> graph | `promote_findings` bridge (cross-tool dedup signature, priority score, ScanRun-linked); `orthrus program-scan` | `orthrus/model/promote.py` |
| 3 - Triage + reports | Finding status/assign lifecycle; platform-native report renderer; cockpit Findings tab | `orthrus/model/report.py` |
| 3b - Attack chains (§7.8) | Persistent operator-graph `FindingChain` edges, rule-based correlation over the curated kill-chain catalog, auto-run after `program-scan`; `orthrus program-chains` + REST | `orthrus/model/chains.py`, `orthrus/model/store.py` |
| 4 - Copilot + notes | Operator-graph Notes (entity/DAL/REST) + grounded BM25 copilot over findings+notes (cites, never invents); cockpit Copilot tab | `orthrus/model/copilot.py`, `orthrus/model/entities.py` |
| 5 - Multi-domain adapters | slither (web3) / checkov (cloud-IaC) / semgrep (SAST) / mobsfscan (mobile) external-tool adapters, self-skip if binary absent; LLM covered natively by the `llm-prompt-injection` scanner | `orthrus/integrations/`, `orthrus/scanners/llm.py` |
| 6 - Traffic bridge + planner | Burp XML / Caido JSON / HAR import into the graph (XXE-guarded, deny-by-default on import); deterministic `orthrus plan` next-action engine | `orthrus/bridges/`, `orthrus/model/planner.py` |
| 7 - Team + deploy | User/Membership RBAC (owner/member/viewer), per-user API keys, `orthrus team` CLI + REST gating; `docker-compose.operator.yml` (API + cockpit over Postgres) | `orthrus/model/store.py`, `docker/` |

Optional/pluggable by design (not gaps): LanceDB/BGE embeddings (BM25-lite is the
default backend); external tools that self-skip when their binary is absent. Still a
deliberate out-of-repo bet: the **managed/SaaS tier** (org billing, hosted infra) and
the native Rust core (the cockpit ships as Tauri + FastAPI, per the hybrid decision).

## Subsystem map

| PRD subsystem | Status | Where it stands / next step |
|---|---|---|
| Scope enforcement (§5) | ✅ | Deny-by-default client + bounty scope intake. |
| **Authorization model + kill-list** (§2.3/§6/§11) | ✅ | Shipped: `bounty/authorization.py` (program URL / signed / direct / self-lab; public scope refused without it) + `bounty/killlist.py` (gov/mil/edu/health/sanctioned refused unless attested). |
| Program record + scope_entries (§6) | 🟡→🛠 | Authorization is captured; a persisted `programs` store (pause, jurisdiction, expiry, history) is next. |
| Recon engine - continuous / diff / CT-log (§7.2) | 🟡→🛠 | Have subdomain enum + recon modules. Next: **expand `*.wildcard` → live in-scope subdomains before scanning**; then diffing + a per-program scheduler; then external adapters (subfinder/amass/dnsx/httpx). CT-log + cloud workers are heavier. |
| Scan engine (§7.3) | ✅ + 🛠 | 67 scanners today; `--tools nuclei` exists. **dalfox** (XSS) + **testssl** (TLS) adapters added; sqlmap/ffuf still to come. |
| Confirm engine (§7.4) | ✅ + 🛠 | 28 confirmers, incl. XXE-OOB, deserialization-OOB, and the LDAP/XPath/CSRF/default-creds/OAuth/file-upload/cache-deception/prompt-injection/CSWSH batch (shipped). Honest gaps (not safely auto-confirmable): request-smuggling desync, single-packet race, SAML sig-strip, cross-identity privesc. |
| Triage engine (§7.5) | ✅ + 🛠 | Composite **priority scoring** (`bounty/triage.py`), a **submission gate** (`bounty/submission_gate.py` + `orthrus submission-gate`) that predicts submit / prove-impact-first / hold so reports lead with payable findings and drop header/CORS-no-cred/cookie-flag noise, cross-run history recall (`bounty/history.py`), LLM FP-judge (`orthrus triage --llm`), and per-program **mute rules** (`bounty/suppress.py` + `orthrus suppress`/`suppressions`). Next: cross-program near-dup clustering. |
| **Authenticated critical pipeline** | ✅ | `authz-matrix` escalates cross-identity access to **CRITICAL** with redacted PII/payment evidence (`utils/sensitivity.py`), an anonymous control kills public-page false positives, and unauthenticated sensitive exposure is flagged CWE-306. Run it via [docs/BOUNTY_AUTHENTICATED_RUNBOOK.md](BOUNTY_AUTHENTICATED_RUNBOOK.md) - two identities against the real authenticated API, where the criticals live. |
| **Auth capture from HAR** | ✅ | `orthrus capture-auth --har A.har --host <h> --name userA --out identities.json` (`core/auth_capture.py`) pulls the live session (cf_clearance + cookies + UA + bearer) out of the HAR you already export for `--import-spec`, so one browser export yields both the API surface and a two-identity file. No DevTools cURL-copy. |
| **Money-flow tampering severity** | ✅ | `business-logic` parameter tampering now escalates a **monetary** field to evidence-backed **HIGH/firm** when the tampered amount is reflected back as a money value in the response (reuses `utils/sensitivity.py`), plus a scientific-notation bypass vector - so a negative/zero amount that is actually carried downstream outranks a bare missing-validation MEDIUM. |
| **Recon depth (altdns + internal-IP)** | ✅ | Mined from m0chan's methodology: `recon/permutation.py` adds altdns-style subdomain mutations of CT-discovered labels (api -> api-dev/staging-api/api2), and the `internal-exposure` scanner (`utils/ip_classify.py`) flags any in-scope hostname resolving to RFC1918 / loopback / link-local / CGNAT / IPv6-ULA / cloud-metadata space - internal-topology disclosure and an SSRF-pivot lead (his `FindInternalIPSubdomains.sh`, as a first-class finding). |
| **Auth-flow abuse (OTP / rate-limit / enum)** | ✅ | `otp-2fa` (brute-force / rate-limit absence + client-trusted `success:false` tamper), `rate-limit` (missing throttling on login/reset/voucher/bonus via bounded, `AGGRESSIVE`-gated micro-bursts - not DoS), and `account-enumeration` (login/register/reset existence oracles, generic-error safe). Shared `_authflow.py` classifier. The OTP + throttling gap on 1win's login/withdrawal flows was the #1 program-relevant miss. Next tiers: payment-callback tampering, password-reset token analysis, session lifecycle, JS-chunk mining. |
| **Second-order / planted-payload registry** | ✅ | `core/second_order.py` + orchestrator exploit phase: plants a canary (OOB beacon + in-band marker) into writable forms, then correlates any detonation - an out-of-band callback fired in a staff/admin console the scanner never visits, or the marker reflected on another page - back to the plant site. Turns blind/stored bugs into evidenced `second-order-injection` findings (CWE-79), no browser required. The non-destructive answer to "plant in the profile, fire in the staff console". |
| **Chain synthesis (exploit algebra)** | ✅ | The deterministic `chains.py` composition engine gained 5 rules that wire this session's scanners into kill-chains: OTP-brute + account-targeting -> 2FA-bypass ATO (critical), account-enum + no-rate-limit -> credential stuffing, named internal host + SSRF -> confirmed pivot (cross-host, critical), monetary tampering + no-throttle/race -> automated financial abuse, second-order payload + weak session -> staff-console takeover. "Three $100 lows -> one five-figure critical" as analysis, not auto-exploitation. |
| **Origin-IP exposure (CDN bypass)** | ✅ | `origin-exposure` scanner + `utils/cdn.py` (Cloudflare/Fastly/CloudFront ranges): when the app is CDN-fronted but an in-scope host resolves to a public non-CDN IP, flags it as a candidate origin that bypasses the edge's WAF / rate-limit / geo controls (the leak that retroactively solves a Cloudflare-blocked engagement). Passive DNS-only analysis over already-resolved IPs, mail/DNS subdomains excluded, TENTATIVE (verify it serves the app). |
| **HackerOne weakness mapping** | ✅ | `bounty/weakness.py` maps every CWE ORTHRUS emits (54) to the exact HackerOne "Weakness" dropdown label, so `--platform hackerone` reports drop straight into the form (a regression test fails if a scanner ever emits an unmapped CWE). [docs/WEAKNESS_COVERAGE.md](WEAKNESS_COVERAGE.md) is the honest matrix: the H1 dropdown is the full CWE+CAPEC dictionary (~1,500), a labelling taxonomy not a checklist - ORTHRUS covers the web/API-observable subset and names what is out of scope (memory/hardware/network/wireless/mobile/physical) rather than shipping fake detectors for it. |
| Reporting engine (§7.6) | ✅ + 🛠 | Submission-ready per-bug reports, **platform-native templates** (H1/BC/Intigriti/YWH/Immunefi via `--platform`), cross-run duplicate flagging (♻), and a machine-readable **`findings.json`** (ranked queue + counts + `prior_seen`, for automation/diffing) written alongside the Markdown. Live submission APIs are 🔑 (your platform tokens). |
| AI copilot / RAG (§7.7) | 🟡→🛠 | AI report is grounded in evidence. A RAG copilot over your own findings/notes + vendored corpora (HackTricks/PayloadsAllTheThings) is build-now (LanceDB or sqlite-vec). |
| Attack graph (§7.8) | ✅ + 🛠 | `chains`/`graph` exist. Next: wire the SSRF→metadata and JWT→BOLA chains as first-class. |
| Monitoring & notifications (§7.9) | 🟡→🛠 | `notify` (Slack/Jira) exists. Next: per-program schedule + digest wired to bounty campaigns. |
| Vuln-class ontology (Appendix B) | 🟡→🛠 | Have attack-map + CVSS defaults. Formalize a versioned ontology module (severity/CVSS/CWE/OWASP/ATT&CK + `default_confidence_ceiling` + `is_destructive`). |
| Audit log (§6/§8.5) + cost ledger (§10) | ✅ | Hash-chained append-only audit of scope decisions/requests (`orthrus audit`); per-program cost ledger (`orthrus cost`) - LLM spend auto-recorded by the copilot, blended per-model estimate, `ORTHRUS_LLM_RATE` override. |
| Payments/bounty tracking (§7.12) | ✅ | `bounty/submissions.py` + `orthrus submission`/`submissions`: track status + payouts, roll up earnings. Notes (§7.13): ✅ `bounty/notes.py` + `orthrus note`/`notes` (tagged, searchable knowledge base). |
| Multi-domain: mobile/web3/LLM/cloud (Phase 5) | 🛠/🔑 | Adapter wrappers (MobSF/slither/garak/prowler) are build-now; several need the external binary installed. |
| Burp/Caido bridge (§7.10) | 🔑/🏗 | ORTHRUS side is buildable; the Burp/Caido extensions are separate Java/TS projects. |
| Team mode, OIDC/SCIM (§7.11) · Rust core + Tauri (§5) · Managed SaaS + Stripe + SOC2 (Phase 7) | 🏗 | Separate product bet. **Not** part of expanding the Python bounty module; revisit as a deliberate, resourced effort. |

## Build-now queue (Python, in-reach, one PR each)

1. ✅ **Authorization + kill-list** - *this PR.*
2. ✅ **Subdomain expansion recon** - `bounty/assets.py`: a `*.wildcard` scope is expanded into its live in-scope subdomains (crt.sh + DNS), filtered against exclusions + kill-list, via `--enumerate`.
3. ✅ **Platform-native report templates** - `bounty/platforms.py` + `--platform`: per-bug reports shaped for HackerOne / Bugcrowd (P1-P5) / Intigriti / YesWeHack / Immunefi (gist reminder).
4. ✅ **Program store + traffic policy** - `bounty/store.py` + `--program NAME` + `orthrus programs`: persist a program's authorization + scope + campaign history (JSON at `$ORTHRUS_HOME/programs.json`); re-run by name. `orthrus program-policy` records a **rate ceiling** (honored as a hard cap on every run) and an **identifying header** (attached to every request) - courtesy + ban-avoidance, applied automatically.
5. ✅ **Triage priority scoring** - `bounty/triage.py`: a 0-100 composite (severity × confidence + CVSS) ranks the bug queue so a confirmed medium outranks a tentative high; shown + sorted-on in the report index. History recall (`bounty/history.py`) flags bugs seen in earlier runs.
6. ✅ **Vuln-class ontology** - `bounty/ontology.py` (versioned): per-class `confidence_ceiling` + `is_destructive` governance metadata; destructive classes get a manual-verification caution in the report.
7. ✅ **Audit log + cost ledger** - `bounty/audit.py` + `orthrus audit [--verify]`: hash-chained, append-only JSONL of authorization / kill-list refusals / campaigns; `verify()` pinpoints tampering. `bounty/cost.py` + `orthrus cost [--program]`: append-only JSONL spend ledger - the copilot auto-records LLM token cost (blended per-model estimate, `ORTHRUS_LLM_RATE` override), rolled up by provider/category/program.
8. **Attack chains**: SSRF→cloud-metadata, JWT→BOLA.
9. 🚧 **Notifications & asset monitoring** - `orthrus bounty --notify-slack` (or `ORTHRUS_SLACK_WEBHOOK`) posts a campaign summary. Cross-run **new-asset detection**: `bounty/asset_monitor.py` snapshots a saved program's live in-scope hosts each `--enumerate` run and flags which are NEW since last time (fresh, untested surface - the highest-signal bounty event; audit-logged as `asset-drift`); `orthrus bounty-assets --program NAME` shows the inventory. (Time-based auto-scheduling still to come - pair with the existing `orthrus monitor --watch`.)
10. ✅ **Data-grounded copilot** - `bounty/copilot.py` + `orthrus copilot "…"`: BM25-lite retrieval over your notes + submissions (no embedding deps), optional `--llm` grounding held to the context (never invents). Embeddings + vendored corpora (HackTricks/PayloadsAllTheThings) are a follow-up.
11. 🚧 **External-tool adapters** - expanded the catalog beyond nuclei: `dalfox` (XSS), `testssl` (TLS), `ffuf` (content discovery), `nikto` (web-server misconfig, conservatively rated), `wpscan` (WordPress core/plugin/theme CVEs + exposed debug-log/listing). Each is a tested JSON parser + `@register_tool` class that normalizes to ORTHRUS Findings (run via `orthrus scan --tools` / `orthrus bounty --tools`); binaries absent on PATH are skipped cleanly. Multi-domain (mobile/web3/LLM/cloud) still to come.

## Needs you (the 🔑 items)

Platform submission tokens (H1/BC/Intigriti/YWH/Immunefi) for live filing · an
OAST domain/host for internet-facing OOB confirmation · a hosting target if you
want continuous cloud recon · LLM/API keys for the copilot. Everything else on
the build-now queue is code I can land.

## Explicitly out of session scope (separate product bet)

Rust core rewrite · Tauri desktop app · managed cloud tier · Stripe billing ·
OIDC/SCIM team mode · SOC 2. These are real and in the PRD, but they are a
company, not a module expansion - call them out as a funded effort, not a turn.
