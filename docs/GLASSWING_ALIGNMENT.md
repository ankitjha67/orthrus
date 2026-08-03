# Glasswing / VVAH alignment

How ORTHRUS maps to Anthropic's **Project Glasswing** (Visa's *"Frontier AI: A New Era
of Cyber Resilience"* whitepaper, June 2026) and the open-source **Visa Vulnerability
Agentic Harness (VVAH)**. The goal is an honest ledger: what ORTHRUS already does, what
it is adding, and what it deliberately does not reimplement.

**One key difference up front.** VVAH is an **agentic SAST harness** - it reads *source
repositories* and reasons with frontier models across an 11-stage pipeline (S1-S11).
ORTHRUS is primarily a **black-box DAST** (plus SAST adapters and a bounded agent). So the
overlap is large but the *paradigm* differs: ORTHRUS proves exploitability against a
running target; VVAH reasons about it in code. We adopt Glasswing's **governance and
metrics** ideas (which are paradigm-neutral) and skip a wholesale re-clone of its SAST
pipeline.

## S1-S11 pipeline -> ORTHRUS

| VVAH stage | ORTHRUS status | Where |
|---|---|---|
| S1 Attack-surface map | ✅ | 18 recon modules (crawler, subdomain/DNS, wayback, API discovery, JS analysis) + attack-surface graph |
| S2 Threat model (STRIDE/OWASP) | ◑ partial | OWASP/CWE/PCI/NIST mappings on findings; no automated STRIDE pre-model |
| S3 Hunt strategy (taint, API boundaries, authz) | ✅ | shared injection taint layer, `shadow-api`, `authz-matrix` identity lattice |
| S4 Multi-lens research | ✅ | 67 DAST scanners + SAST adapters (slither/checkov/semgrep) |
| S4 n-vote convergence | ⬜ skip | LLM-provider-dependent + non-deterministic; see "not reimplementing" |
| S5 Policy gate (scope/severity floors/PCI) | ✅ **added** | `orthrus.risk.policy` - named, declarative policies; every keep/suppress/escalate decision is traceable to a specific policy + reason |
| S6 Adversarial verification | ✅ | 18-confirmer exploitation-confirmation (fresh-nonce re-proof) |
| S7 Dedup + business-context risk (P1-P4) | ✅ **added** | dedup/grouping + **`orthrus.risk.priority`** contextual P1-P4 bands |
| S8 Exploit chaining | ✅ | attack-graph chain synthesis + reachability |
| S9 SARIF + report bundles | ✅ | SARIF 2.1.0 + JSON/CSV/HTML/PDF/MD |
| S10 Remediation playbooks | ✅ | automated remediation patch generation |
| S11 Fix-validation gate ladder | ✅ **added** | `orthrus.risk.fix_validation` - deterministic gates (applies/syntax/scope/rescan/regression); build + full-tests + adversarial-LLM flagged as target-toolchain, not faked |
| run manifest / reproducibility | ✅ **added** | `orthrus.risk.manifest` - `run_manifest.json` beside every report; `manifest_hash` reproduces across identical re-runs (timestamps excluded) |
| Living SBOM (inventory freshness) | ✅ **added** | `orthrus.risk.sbom` - deterministic CycloneDX 1.5 from fingerprinted tech/SCA, detected CVEs linked to components |
| MTTA metric | ✅ **added** | `orthrus.risk.mtta` - inventory freshness, exploitable-paths-open, and time-to-confirm from the finding lifecycle (the production-fix leg needs a deploy timestamp - flagged, not faked) |

## Glasswing lessons -> ORTHRUS posture

- **"Prioritization matters more than volume"** (fewer than 1% of CVEs are actively
  exploited): ORTHRUS is confirmation-first and now ranks with contextual **P1-P4** bands
  (KEV/EPSS/exposure/asset-criticality/confirmed-exploitability).
- **"Chaining & exploitability is where models add most value"**: attack-graph chain
  synthesis + the confirmation phase already reason about reachable, chainable impact.
- **"Keep decisions deterministic and audit-traceable"** (*same evidence -> same
  decision*): the priority band is pure and emits a rationale; the coming **policy engine**
  and **run manifest** extend this to every promote/suppress/close decision.
- **"Validation is the bottleneck"**: the fix-validation gate ladder (S11) is the next
  build so generated patches are proven, not just proposed.

## The 12 Non-Negotiable Architectural Practices -> ORTHRUS evidence

Which ORTHRUS checks surface a violation of each appendix practice (a DAST sees symptoms,
not source, so some are partial):

| # | Practice | ORTHRUS evidence |
|---|---|---|
| 1 | Secrets never in code | `secret-scanner` (keys/PEM in responses/JS) |
| 2 | Authorization server-side & explicit | `authz-matrix`, `privilege-escalation`, `idor` |
| 3 | "Internal" is not a boundary | `internal-exposure`, `ssrf`, `origin-exposure` |
| 4 | Tenant isolation centrally enforced | `authz-matrix` (BOLA/BFLA cross-identity) |
| 5 | No raw HTML/script rendering | `xss` (reflected/DOM/stored), `csp-analyzer` |
| 6 | Cryptography correct or unused | `tls`, `jwt-analyzer`, weak-entropy in `auth-session` |
| 7 | Inputs hostile until proven | the whole injection scanner fleet |
| 8 | Sensitive data never logged | ◑ partial - `exposed-files`/`framework-debug` catch leaked logs/traces only |
| 9 | Security decisions fail closed | ◑ partial - `business-logic`, `default-creds` |
| 10 | Security patterns centralized | ⬜ architectural - not DAST-observable |
| 11 | AI agents are identities | governance concern; ORTHRUS's own agent runs bounded/audited |
| 12 | Design for absence | `shadow-api`, `exposed-files`, `subdomain-takeover` (dead surface) |

## Deliberately not reimplementing

- **VVAH's full S1-S11 agentic-SAST pipeline.** ORTHRUS already has the bounded agent
  orchestrator, SAST adapters, chaining, remediation, and SARIF. A parallel clone would be
  redundant, and VVAH is Apache-2.0 code we take *inspiration* from, not copy.
- **S4 multi-agent n-vote convergence** as a core feature. It depends on a specific LLM
  backend and is non-deterministic, so it cannot be honestly unit-tested. The deterministic
  layers here (priority, policy, manifest) are the auditable backbone such voting would feed.

## Build roadmap (this initiative)

1. ✅ **Contextual P1-P4 prioritisation** (`orthrus.risk.priority`) - done.
2. ✅ **run_manifest** (`orthrus.risk.manifest`) - per-scan reproducibility record; the
   deterministic per-scan artifact honest MTTA diffs.
3. ✅ **MTTA metric** (`orthrus.risk.mtta`) - inventory freshness, exploitable-paths-open,
   and validation cycle time (time-to-confirm). The production-fix leg needs a deploy
   timestamp ORTHRUS doesn't own; that gap is flagged, not faked.
4. ✅ **Deterministic finding-policy engine** (`orthrus.risk.policy`) - named,
   declarative keep/suppress/escalate policies, each decision traceable to a policy + reason.
5. ✅ **CycloneDX SBOM** (`orthrus.risk.sbom`) - deterministic CycloneDX 1.5 component
   inventory with detected CVEs linked to their components.
6. ✅ **Fix-validation gate ladder** (`orthrus.risk.fix_validation`) - deterministic gates
   (applies / syntax / minimal-scope / rescan / regression) with validated/rejected/
   inconclusive verdicts; build + full-tests + adversarial-LLM are flagged as needing the
   target's toolchain, not faked.

**The governance layer is complete** - all six deterministic pieces shipped (PRs #63-#68 +
this). Everything is pure and unit-tested; nothing that could not be measured honestly was
faked (MTTA's production-fix leg, S11's build/test gates, and LLM n-vote were all flagged,
not stubbed).

_This document is ORTHRUS's own analysis and summary; it quotes the Visa whitepaper only
minimally. Project Glasswing, VVAH, Mythos, and Visa are the property of their owners._
