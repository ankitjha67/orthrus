# ORTHRUS vs. other DAST tools

> **Read this first.** ORTHRUS is an early (v0.1.0), single-maintainer,
> open-source project. It has not been battle-tested at scale, it will have false
> positives and false negatives, and it is **not** a drop-in replacement for the
> mature tools below. This page exists so you can decide honestly when ORTHRUS is
> a good fit and when one of the established tools is the better choice. Verify
> ORTHRUS's findings, and treat it as a complement to — not a substitute for —
> Burp, ZAP, or Nuclei.

ORTHRUS's thesis is narrow and specific:

1. **Confirm, don't just flag.** Where most open scanners stop at *detection*,
   ORTHRUS treats a finding as a hypothesis and runs a separate
   exploitation-confirmation phase that re-proves the actively-exploitable
   classes with a fresh nonce, so a report can distinguish "this looks
   vulnerable" (`tentative`/`firm`) from "this was demonstrably re-proven"
   (`confirmed`). It never fabricates a confirmation — classes with no safe,
   generic automated exploit (e.g. insecure deserialization) stay detection-only
   and say so.
2. **Evidence-grounded reporting.** An optional AI consultant report writes the
   narrative *around* the fixed findings and their verbatim recorded evidence, so
   the model contextualizes only what the scanner already proved rather than
   inventing vulnerabilities. Credentials/cookies are redacted before anything is
   sent to a remote model, and a fully-local model is supported.
3. **Correlation, not just a finding list.** Findings are correlated into attack
   paths / kill-chains and a remediation runbook ordered so the highest-leverage
   fix comes first.

Everything runs behind a deny-by-default, scope-enforced HTTP client.

*ORTHRUS scale (v0.1.0, verified from the CLI): 18 recon modules, 59 vulnerability
scanners, 19 exploitation-confirmation modules, ~30 CLI sub-commands.*

---

## The tools at a glance

| Tool | One-line summary |
|---|---|
| **ORTHRUS** | Young, integrated open-source DAST pipeline: recon → scan → **exploitation-confirmation** → correlation → evidence-grounded reporting, in one command. |
| **OWASP ZAP** *(now "ZAP by Checkmarx")* | The mature, free, full-featured DAST workhorse — huge community, add-on marketplace, intercepting proxy, active/passive scanning, deep automation and scripting. |
| **Nuclei** *(ProjectDiscovery)* | Fast, template-driven scanner with a massive community template library — the go-to for known-CVE / misconfiguration / exposure sweeps across many hosts. |
| **Burp Suite Community** | Free entry point to the industry-standard manual toolkit: intercepting proxy + Repeater (Intruder is throttled; no automated scanner). |
| **Burp Suite Professional** | The professional web-pentester's daily driver: Burp Scanner, full-speed Intruder, Collaborator (OOB), DOM Invader, and a large BApp extension ecosystem. |
| **w3af** | Historically comprehensive Python framework; now largely **dormant** (Python-2 era, minimal maintenance for years). |
| **Wapiti** | Lightweight, actively-maintained, free Python black-box scanner; simple CLI, packaged in Kali. |
| **StackHawk** | Commercial, developer-first / CI-CD-native DAST (built on the ZAP engine), with config-driven API scanning and vendor support. |

---

## Feature matrix

Legend: **✓** built-in / strong · **◑** partial or limited · **✗** not available / not a focus.
Numbered notes below the table carry the honest nuance — read them; the symbols alone overstate the differences.

| Capability | ORTHRUS | ZAP | Nuclei | Burp CE | Burp Pro | w3af | Wapiti | StackHawk |
|---|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| Exploitation-confirmation / re-proof phase¹ | ✓ | ◑ | ◑ | ✗ | ◑ | ◑ | ✗ | ◑ |
| Scope enforcement — deny-by-default² | ✓ | ◑ | ◑ | ◑ | ◑ | ◑ | ◑ | ◑ |
| CVSS v4.0 scoring³ | ✓ | ✗ | ◑ | ✗ | ✗ | ✗ | ✗ | ✗ |
| CISA KEV / EPSS enrichment⁴ | ✓ | ✗ | ◑ | ✗ | ✗ | ✗ | ✗ | ✗ |
| MITRE ATT&CK mapping⁵ | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| Evidence-grounded AI report⁶ | ✓ | ✗ | ✗ | ✗ | ◑ | ✗ | ✗ | ◑ |
| Attack-graph / kill-chain correlation | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| Browser-verified DOM XSS⁷ | ✓ | ✓ | ◑ | ◑ | ✓ | ✗ | ✗ | ◑ |
| Template ecosystem⁸ | ◑ | ◑ | ✓ | ✗ | ◑ | ◑ | ✗ | ✗ |
| Manual proxy / repeater⁹ | ◑ | ✓ | ✗ | ✓ | ✓ | ◑ | ✗ | ✗ |
| Community / adoption | New (solo) | Very large | Very large | Very large | Very large | Dormant | Small, active | Commercial |
| Commercial support¹⁰ | ✗ | ◑ | ◑ | ✗ | ✓ | ✗ | ✗ | ✓ |
| License | MIT | Apache-2.0 | MIT | Proprietary (free) | Proprietary | GPLv2 | GPLv2 | Proprietary |
| Price | Free | Free | Free¹¹ | Free | ~$449 / user-yr¹² | Free | Free | Free tier + paid¹³ |

**Notes**

1. ORTHRUS runs confirmation as an explicit, separate phase that re-proves each
   actively-exploitable finding with a freshly-minted marker/origin/sentinel and
   captures the re-proof as evidence. This is **not unique in kind**: Burp Scanner
   performs active verification and rates issues Certain/Firm/Tentative, and ZAP
   attaches confidence levels (up to "Confirmed") to alerts. w3af historically
   shipped exploitation plugins; StackHawk inherits the ZAP engine's behavior;
   Nuclei's precision comes from matcher-based templates. ORTHRUS's distinction is
   that the confirmation is a first-class, transparent, tiered phase with recorded
   proof — not that competitors do no verification.
2. Every tool here supports *targeting* scope (include/exclude hosts or paths).
   ORTHRUS's difference is that scope is a **load-bearing safety control**: a
   deny-by-default check runs in the HTTP client before every request and
   re-validates every redirect hop, and the resolved scope is printed at the start
   of each run.
3. ORTHRUS emits CVSS v3.1 **and** v4.0 vectors per finding. Nuclei templates
   commonly carry CVSS metadata (typically v3.1). ZAP, Burp, w3af, and Wapiti use
   their own severity/risk ratings rather than per-finding CVSS.
4. ORTHRUS enriches version/product findings with CISA KEV and EPSS (`orthrus
   update`). Nuclei templates carry some KEV-related tags and ProjectDiscovery's
   cloud offering adds enrichment; the others generally leave KEV/EPSS to a
   separate vuln-management layer.
5. Most tools map to OWASP Top 10 / CWE. ORTHRUS additionally attaches MITRE
   ATT&CK technique IDs and D3FEND countermeasures (and can export an ATT&CK
   Navigator layer).
6. ORTHRUS generates a full consultant-style report whose narrative is grounded
   strictly in the recorded findings/evidence, with redaction before remote LLMs
   and a local-model option. Burp has added "Burp AI" issue-explanation features
   and StackHawk offers AI tooling; these are assistive features rather than a
   full grounded deliverable. Treat any AI-written narrative as draft to review.
7. ZAP (AJAX spider + browser), Burp Pro (Burp Scanner), and ORTHRUS (Playwright)
   drive a real browser for DOM/stored XSS. Burp's DOM Invader ships in Community
   and Pro as manual tooling; Nuclei has headless templates; StackHawk inherits
   ZAP's browser capabilities.
8. Nuclei is the clear leader — a community library of **12,000+** YAML templates.
   ORTHRUS ships a Nuclei-style template engine but only a small built-in set (and
   can orchestrate Nuclei itself via `--tools nuclei`). Burp Pro has BChecks and
   the BApp store; ZAP has an add-on marketplace and scripting; w3af has a legacy
   plugin set.
9. Burp (CE/Pro) and ZAP are full intercepting proxies with mature manual request
   editors — this is their home turf. ORTHRUS has a capturing proxy, a `replay`
   command, and a dashboard Repeater, but they are basic by comparison. Nuclei,
   Wapiti, and StackHawk are not interactive proxies.
10. ZAP is now stewarded by **Checkmarx** (the core team joined Checkmarx in
    Sept 2024 after leaving OWASP in 2023); it remains free and Apache-2.0, with a
    commercial enterprise DAST built on it. Nuclei is backed by ProjectDiscovery's
    commercial cloud. Burp Pro and StackHawk are vendor-supported commercial
    products. ORTHRUS has no commercial support.
11. Nuclei's engine and community templates are free/MIT; ProjectDiscovery sells a
    hosted cloud platform.
12. Burp Suite Professional's list price has historically been about
    **US$449 per user per year**; PortSwigger applied a pricing change effective
    early January 2026, so confirm the current figure on their site. Team/volume
    pricing differs.
13. StackHawk pricing is per code-contributor with a limited free tier and paid
    plans; exact tiers change — check their pricing page.

---

## Where ORTHRUS wins

These are genuine, concrete advantages — mostly about *integration* and *evidence*,
not about out-scanning mature engines.

1. **Confirmation is a first-class, transparent phase.** For the
   actively-exploitable classes, ORTHRUS re-issues a controlled payload with a
   fresh nonce (executes XSS in a real browser, awaits an out-of-band callback for
   SSRF, etc.), records the re-proof, and upgrades the finding to `confirmed`.
   Classes it can't safely prove stay detection-only and say why. The result is a
   lower-noise report where "confirmed" means something specific and auditable.
2. **An evidence-grounded written deliverable, in the box.** `orthrus ai-report`
   turns a scan into a consultant-style report (Markdown/HTML/PDF) whose narrative
   is pinned to the fixed findings and their verbatim evidence — it cannot
   hallucinate a vulnerability the scanner didn't find. Sensitive evidence is
   redacted before any remote model call, and a local Ollama model keeps
   everything on-host.
3. **Correlation and a leverage-ordered runbook.** ORTHRUS collapses findings into
   attack paths / kill-chains (`chains`, `graph`) and produces a remediation
   runbook ordered so the single fix that breaks an attack path comes first —
   uncommon in open-source DAST, which usually hands you a flat finding list.
4. **Rich standards mapping and threat intel, free and offline-capable.** CVSS
   v3.1 + v4.0, OWASP / CWE / PCI-DSS / NIST-CSF, MITRE ATT&CK + D3FEND, and CISA
   KEV + EPSS enrichment, out of one tool, in six report formats (JSON/CSV/HTML/
   PDF/SARIF/Markdown) plus an ATT&CK Navigator layer.
5. **Safety-first, integrated design.** Deny-by-default scope enforcement on every
   request and redirect, one command from URL to report, plus modern extras (MCP
   server for AI agents, IaC/cloud posture checks, a bounded non-destructive LLM
   planner, external-tool orchestration).

## Where ORTHRUS loses — and what to reach for instead

Be honest with yourself about the job in front of you. In many situations one of
these is the right tool:

- **Manual testing, and an extension ecosystem → Burp Suite (Pro).** For hands-on
  work — intercept, tweak, Repeater/Intruder, Collaborator, DOM Invader, hundreds
  of BApp extensions — Burp is the industry standard and ORTHRUS is not close. Its
  manual tooling (proxy/replay/dashboard Repeater) is deliberately basic. If your
  workflow is a human driving requests, use Burp.
- **A mature, battle-tested scanner with a huge community → OWASP ZAP.** A
  decade-plus of development, an enormous user base, an add-on marketplace,
  extensive docs, scripting, and proven behavior at scale. ORTHRUS is v0.1.0 and
  unproven; for a dependable free scanner you can trust today, ZAP is the safer
  pick.
- **Massive template-driven CVE / exposure sweeps at scale → Nuclei.** 12,000+
  community templates, extreme speed across large host lists, and a thriving
  ecosystem. ORTHRUS's template engine is nascent. (You can even let ORTHRUS drive
  Nuclei via `--tools nuclei` and normalize its output.)
- **Developer-first, CI/CD-native scanning with commercial support → StackHawk.**
  Purpose-built for pipelines and per-PR scanning, config-driven API coverage, and
  a vendor with SLAs. ORTHRUS is a young project with no support contract.
- **A lightweight, proven, packaged free CLI scanner → Wapiti.** Actively
  maintained, simple, and in Kali. If you want a small dependable black-box
  scanner without ORTHRUS's heavier footprint, Wapiti is a fine choice.
- **w3af**: largely dormant today — for new work prefer ZAP, Nuclei, Wapiti, or
  ORTHRUS over it.

Additional honest caveats about ORTHRUS specifically: it is single-maintainer and
early, so expect rough edges, some false positives/negatives, and API churn;
several capabilities need optional extras (headless browser via Playwright, Nmap,
PostgreSQL); and out-of-band confirmation against internet-facing targets needs a
reachable callback server (e.g. Interactsh), not just the bundled local listener.
**Always verify findings before acting on them or reporting them.**

## When to reach for ORTHRUS

Reach for ORTHRUS when you want a single command to take an **authorized** target
from URL to a set of **confirmed, prioritized, compliance-mapped findings with
evidence** — and you value low-noise "confirmed" results, an evidence-grounded
written deliverable, attack-path correlation, and scope-safe automation in one
open-source tool. It fits well as an integrated pipeline for a lab, a personal
engagement workflow, or as a second opinion that cross-checks and re-proves what a
mature tool flagged.

Use it *alongside* Burp, ZAP, and Nuclei, not instead of them: let the mature
tools give you breadth, manual depth, and template coverage, and let ORTHRUS add
confirmation, correlation, and a client-ready report. And whatever the tool, only
point it at systems you own or are explicitly authorized in writing to test.
