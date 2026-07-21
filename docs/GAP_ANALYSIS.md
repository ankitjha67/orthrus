# ORTHRUS Gap Analysis (platform, engine, workflow)

Honest status of the platform/engine/operational suggestions raised from running ORTHRUS
end to end against a hardened production target. Written after an actual repo scan - many
of these are **already built** (ORTHRUS is a mature platform), several are **partial**, and
the genuine gaps are sized so they can be worked top-down as tested PRs.

Legend: ✅ built · ◑ partial · ⬜ gap · 🔒 safety-gated / careful · (S/M/L) = size.

## Engine & reliability

| # | Item | Status | Notes |
|---|---|---|---|
| 1 | Phase-granular checkpointing | ⬜ (L) | Resume is phase-boundary only; a mid-phase kill restarts the phase. Needs module- then request-level checkpoints. |
| 2 | Time budget (`--max-duration`) | ⬜ (M) | No graceful "stop and report what you have" deadline. Confirmed absent. |
| 3 | Preflight connectivity check | ✅ shipped | `orthrus doctor --target <url>` - layered DNS -> TCP -> TLS -> HTTP probe that fails in seconds with a diagnosis + remedy (`core/preflight.py`). |
| 4 | Yield-based payload scheduling | ⬜ (L) | Fires wordlist x endpoints uniformly; should prioritise by yield and deprioritise WAF-blocked paths. |
| 5 | Engine-level soft-404 calibration | ◑ | Per-scanner soft-404 exists (`shadow-api` `reachable_variant`, content-discovery baseline); no single shared engine primitive. |
| 6 | Capability-loss in the report | ⬜ (S) | `doctor` reports env capabilities, but the scan *report* doesn't state "XSS coverage: partial - browser absent". |

## Authentication & session

| # | Item | Status | Notes |
|---|---|---|---|
| 7 | Real login (`--auth-script` Playwright) | ⬜ (L) | Confirmed deferred stub. `--login-url` (form POST), `--identities`, `--auth-cookie`, TOTP, OAuth2, CSRF-token harvest all exist; browser-driven SPA login does not. |
| 8 | Cookie-session keep-alive | ◑ (M) | `--reauth` re-runs a login flow; a cookie-only session (cf_clearance) has no keep-alive/re-harvest hook. |
| 9 | Passive-only mode | ⬜ (S/M) | HAR/proxy import exists; no "analyse observed traffic, no active fuzz" profile. |

## Defaults & safety

| # | Item | Status | Notes |
|---|---|---|---|
| 10 | `--profile bounty-gentle` preset | ⬜ (S) | Defaults are 50 req/s + WAF-adapt UA rotation on. A gentle preset (low RPS, no rotation, logout excluded) is absent. High safety value. |
| 11 | Scope-file import (H1 CSV) | ◑ (S) | `parse_h1_scope_csv` already exists (`bounty/scope_report.py`); `--scope-file` currently uses the line-based parser. Gap = auto-detect + wire CSV into `--scope-file`. |

## Reporting & workflow

| # | Item | Status | Notes |
|---|---|---|---|
| 12 | Platform-native submission output | ✅ | `--platform` H1/Bugcrowd/Intigriti/YWH/Immunefi templates + severity mapping. |
| 13 | Evidence redaction in JSON/HTML | ◑ (S/M) | `redact_for_llm` scrubs before the LLM call; the standard JSON/HTML deliverables are not yet scrubbed of the operator's own session cookies. |
| 14 | Retest / remediation loop | ◑ (M) | `orthrus diff` compares scans; no automatic "retested/fixed" marking against a new scan. |
| 15 | Coverage accounting | ⬜ (M) | Report shows "N findings" but not "955 params discovered, X fuzzed, Y skipped and why". |
| 16 | WAF testability scoring | ⬜ (M/L) | `core/block_detect` measures per-host block rate; not surfaced as per-endpoint "testability" so "0 findings" is honest about what was actually reachable. |

## Stature (platform maturity)

| # | Item | Status | Notes |
|---|---|---|---|
| S1 | Human-in-the-loop escalation | ⬜ (L) | Pause on login/MFA/CAPTCHA/clearance-expiry, hand off to the operator's browser, harvest session, resume. The manual WebBridge maneuver as a built-in flow. |
| S2 | Multi-vantage geo-distributed | ◑ (L) | Celery distributed layer exists; no geo-labeled egress so a regional block is a scheduling detail. |
| S3 | Incremental / delta scanning | ⬜ (M/L) | Content-hash endpoint state; scan only what changed since last run. `diff` compares but doesn't drive delta scans. |
| S4 | Hypothesis-driven autonomy + budgets | ◑ (M/L) | `agent` planner exists; needs explicit request/cost budgets and a hypothesis -> minimal-experiment loop. |
| S5 | Finding economics (dollar-weighted) | ◑ (M) | `priority_score` + EPSS/KEV + `submission-gate` exist; no payout-table / dup-likelihood weighting. |
| S6 | Published detection accuracy | ◑ (M) | `benchmark` harness exists; not yet a per-release precision/recall scorecard vs OWASP Benchmark/DVWA/WebGoat. |
| S7 | Reproducibility bundles + submission pipeline | ◑ (M/L) | `reporting/reproduce` snippets + platform templates exist; no one-click curl+HAR+screenshot+PoC bundle with API push. |
| S8 | Signed attestation + hard RoE | ◑ (M) | Authorization capture + hash-chained audit log + engine kill-switch exist; no signed machine-readable attestation + blackout windows. |
| S9 | Secret validation + SBOM | ⬜ / 🔒 | Live credential validation is consent-gated dual-use (careful, opt-in only). SBOM (CycloneDX/SPDX) is a clean gap (S/M). |
| S10 | Trust signals | ◑ mixed | `notify` (Slack/Jira) is one-way; SLSA-signed reproducible builds, 2-way sync, GDPR PII scrub in evidence, and cross-scan trend reporting are gaps. |

## Recommended build order (top-down by leverage)

1. ✅ **Preflight** (`doctor --target`) - shipped.
2. `--profile bounty-gentle` (10) + wire H1 CSV into `--scope-file` (11) - small, safety-critical, both bit this engagement.
3. `--max-duration` time budget (2) + evidence redaction in JSON/HTML (13) - small, high value.
4. Coverage accounting (15) + capability-loss in report (6) + WAF testability score (16) - report honesty cluster.
5. Phase/request checkpointing (1) - larger engine work.
6. Real Playwright login (7) + cookie keep-alive (8) - the "90% behind login" blocker.
7. Stature items as dedicated efforts; S9 secret-validation stays opt-in/consent-gated.
