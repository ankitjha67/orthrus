# ORTHRUS roadmap

This roadmap turns an external technical + adoption review into a sequenced plan.
It is honest about three categories of work:

- **🛠 Code / docs** — buildable in-repo; tracked here and shipped in waves.
- **🔑 Needs an account/credential** — I can build everything up to the publish
  step, but the maintainer must hold the token / domain / account to finish it.
- **📣 Social / human** — reputation and outreach; assets can be drafted, but the
  work itself is human (talks, researcher relationships, community).

Status legend: ✅ done · 🚧 in progress · ⬜ planned.

---

## Part 1 — Technical

### Detection surface
| # | Item | Status | Notes |
|---|---|---|---|
| T1 | SSRF → cloud-metadata chain (IMDS 169.254.169.254, alt schemes, IMDSv2) correlated with CSPM | ⬜ | Wire as a first-class attack-graph chain, not a new scanner. |
| T2 | JWT/OAuth → IDOR/BOLA chain (forge token for another `sub`, replay through BOLA) | ⬜ | Emit in attack-graph output. |
| T3 | Client-side prototype-pollution → gadget-chain DOM XSS confirmation | ⬜ | Vendor the PortSwigger/s1r1us gadget corpus. |
| T4 | HTTP/2 & HTTP/3 attacks — Rapid Reset (CVE-2023-44487), h2c smuggling, QUIC timing | ⬜ | Genuine gap in most DAST. |
| T5 | Cache-poisoning DoS (oversized headers, host override, malformed encoding) | ⬜ | Kettle playbook. |
| T6 | CSRF token-quality auditor (double-submit not compared, no state binding, reuse) | ⬜ | Self-contained scanner. |
| T7 | SAML/OIDC forge-and-login confirmation (signature wrapping → authenticate as target) | ⬜ | Upgrade detection → confirmation. |
| T8 | Mobile API surface — ingest a Charles/Burp/Frida capture to extend the endpoint corpus | ⬜ | Differentiator vs Burp/ZAP. |
| T9 | WebSocket message-level fuzzing (subscribe, fuzz JSON, detect WS-driven DOM XSS) | ⬜ | Extends the connection-level WS scanner. |
| T10 | Request-smuggling desync expansion — 0.CL, TE.0, H2 downgrade, header/body mismatch | ⬜ | On top of existing CL.TE/TE.CL/CL.0. |

### Confirmation
| # | Item | Status | Notes |
|---|---|---|---|
| T11 | Deserialization OOB confirmation via safe-marker gadgets | 🚧 | **Python pickle** shipped (`deserialization_confirm.py`: `__reduce__`→`urlopen`, a single GET, no shell) — converts that class tentative→confirmed. Java URLDNS / PHP / .NET / Ruby gadgets are a follow-up (need external tooling / a DNS collaborator); unsupported formats fail honestly, never faked. |
| T12 | Race-condition confirmation via single-packet attack (last-byte sync) | ⬜ | Reliable race exploitation. |
| T13 | XXE OOB confirmation with parametric-entity DTD chaining | ✅ | `xxe_confirm.py` now re-proves blind XXE via a fresh parametric-entity callback (reuses `oob_xxe_payloads` + the SSRF OOB pattern). |

### Architecture / performance
| # | Item | Status | Notes |
|---|---|---|---|
| T14 | Incremental / delta scanning — fingerprint responses, only re-fuzz what changed | ⬜ | Makes CI use practical (4h → 5min per PR). |
| T15 | `orthrus login-record` — Playwright manual login, capture full session state (cookies, localStorage, tokens) | ⬜ | Critical for modern OIDC apps. |
| T16 | Endpoint "juicy score" prioritization — run heavy scanners against high-value endpoints first | ⬜ | Big wall-clock win, no coverage loss. |
| T17 | Confirmation retry with backoff + `flappy` state for ~40%-reproducible findings | ⬜ | Fewer false positives. |
| T18 | "Trace mode" — rrweb-style replayable session per confirmed finding | ⬜ | Turns "trust me" into "watch this." |

### Reporting / dev-experience
| # | Item | Status | Notes |
|---|---|---|---|
| T19 | Per-finding curl / Python / raw-request (Burp Repeater) reproduction snippets | ✅ | `orthrus/reporting/reproduce.py`; in both the deterministic and AI reports. |
| T20 | Report diffing baked into HTML/PDF ("since last engagement" section) | ⬜ | Build on `orthrus diff`. |
| T21 | Bidirectional triage sync to Jira/Linear/GitHub Issues (pull closes → `remediated`/`regressed`) | ⬜ | Extends push-only `notify`. |

---

## Part 2 — Adoption

### Discoverability
| # | Item | Status | Category | Notes |
|---|---|---|---|---|
| A1 | PyPI release (`pip install`) | ⬜ | 🔑 | Package + trusted-publish workflow buildable; **publish needs a PyPI token**. Name TBD (`orthrus` taken — `orthrus-dast`/`orthrus-sec`). |
| A2 | Docker Hub image (GHCR already published) | ⬜ | 🔑 | Push step **needs Docker Hub creds**; CI wiring buildable. |
| A3 | Pre-built binaries (Win/macOS/Linux) attached to releases | ✅ | 🛠 | PyInstaller onefile + release workflow shipped in v0.1.0. |
| A4 | Kali / BlackArch package repos | ⬜ | 📣 | Prep packaging; submitting the distro PR is a human step. |
| A5 | Hosted demo dashboard (`demo.orthrus.dev`) | ⬜ | 🔑 | Deploy config buildable; **needs hosting + domain**. |

### Trust & social proof
| # | Item | Status | Category |
|---|---|---|---|
| A6 | Blog series with real findings (ginandjuice, testfire, allowed H1 scope) | ⬜ | 📣 (draft posts buildable) |
| A7 | Talks — DEF CON Demo Labs / BSides / Black Hat Arsenal | ⬜ | 📣 (draft abstract buildable) |
| A8 | Bug-bounty writeups "found with ORTHRUS" | ⬜ | 📣 (outreach template buildable) |
| A9 | Comparison matrix vs ZAP/Nuclei/Burp/w3af/Wapiti/StackHawk | ✅ 🛠 | [`docs/COMPARISON.md`](COMPARISON.md) |
| A10 | Public benchmark (OWASP Benchmark, PortSwigger labs) | ⬜ | 🛠 (run `orthrus benchmark`, publish numbers) |

### Contributor experience
| # | Item | Status | Category |
|---|---|---|---|
| A11 | "Your first scanner in 15 minutes" tutorial | ✅ 🛠 | [`docs/WRITING_A_SCANNER.md`](WRITING_A_SCANNER.md) |
| A12 | `good-first-issue` / `help wanted` triaged issues | ⬜ | 🛠 (I can open them via `gh`) |
| A13 | Discord / Matrix + GitHub Discussions | ⬜ | 🔑 (needs maintainer to create) |
| A14 | `.devcontainer` for VS Code / Codespaces | ✅ 🛠 | `.devcontainer/devcontainer.json` |

### Business-model clarity
| # | Item | Status | Category |
|---|---|---|---|
| A15 | State the commercial layer now (hosted/managed/support/SLA) | 🚧 | 🔑 README "Commercial support" section added with a placeholder contact — **pick the model + link**. |
| A16 | `TRADEMARKS.md` — name reserved, code MIT | ✅ 🛠 | [`TRADEMARKS.md`](../TRADEMARKS.md) |

### Polish
| # | Item | Status | Category |
|---|---|---|---|
| A17 | 60–90s demo video at README top | ⬜ | 📣 (script + asciinema cast buildable; recording is human) |
| A18 | `evidence/` (or `samples/`) with raw reproducible reports | ✅ 🛠 | [`samples/`](../samples) shipped (HTML/PDF/JSON/SARIF). |
| A19 | Auto-generated CLI reference | ✅ 🛠 | [`docs/CLI.md`](CLI.md) generated from the Click tree. |
| A20 | Colab notebook that renders findings inline | ⬜ | 🛠 (upgrade the existing notebook). |

---

## Build sequence

- **Wave 1 (this PR):** T19 reproduction snippets · A9 comparison · A11 scanner tutorial · A14 devcontainer · A16 trademark · A19 CLI reference · A18 samples (done) · this roadmap.
- **Wave 2 — high-leverage confirmation & correlation:** T11 deser-OOB · T13 XXE-OOB · T1 SSRF→metadata chain · T2 JWT→BOLA chain · T16 juicy-score · T17 flappy retries.
- **Wave 3 — new detection surface:** T6 CSRF-quality · T9 WS message fuzzing · T4 HTTP/2 Rapid Reset · T10 smuggling expansion · T3 proto-pollution gadgets · T5 cache-DoS · T7 SAML forge-login.
- **Wave 4 — workflow depth:** T14 delta scan · T15 login-record · T18 trace mode · T20 report-diff · T21 bidirectional sync · T8 mobile capture · T12 single-packet race.
- **Adoption track (parallel):** A1/A2 packaging (I prep, you publish) · A10 benchmark numbers · A12 good-first-issues · A17 demo cast · A20 Colab · A15 commercial model (your call) · A5 hosted demo (your infra) · A4/A6/A7/A8/A13 human/social.

**Maintainer checklist (the 🔑 items only you can finish):** PyPI token + package name · Docker Hub creds · demo host + domain · commercial model + contact link · community server. Everything else is code/docs I can land.
