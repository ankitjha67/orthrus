# ORTHRUS — Credibility & Proof

This document records **real, reproducible scan evidence** produced by ORTHRUS
against an explicitly authorized test range, plus the automated quality gates the
project holds itself to. It exists to demonstrate that the tool's findings are
genuine — not synthetic fixtures — across multiple vulnerability classes.

> ⚠️ **Authorized testing only.** Every live result below was produced against
> **pentest-ground.com**, the public, intentionally-vulnerable playground operated
> by Pentest-Tools.com expressly for security testing. ORTHRUS enforces a
> deny-by-default scope on every request; nothing outside the sanctioned range was
> ever contacted. Do **not** point ORTHRUS at systems you do not own or are not
> authorized to test.

| | |
|---|---|
| Tool | ORTHRUS v0.1.0 |
| Date of run | 2026-05-30 |
| Environment | Windows 11, Python 3.14, scope-enforced `HttpClient` |
| Automated gates | **860 tests pass**, `ruff check orthrus tests` clean |
| Coverage | **55 vulnerability scanners · 17 confirmation modules · 16 recon modules** |
| Authorized range | `pentest-ground.com` (Pentest-Tools.com playground) + purpose-built localhost targets |

---

## 1. Automated quality gates

```
$ ruff check orthrus tests
All checks passed!

$ pytest -q
860 passed, 4 warnings
```

Every detector ships with pure unit tests; scanners additionally have
duck-typed end-to-end flow tests. Findings are held to a low false-positive bar —
during live testing the suite itself caught and fixed real FPs in new code
(subdomain-takeover generic-404, LLM canary reflection) before release.

---

## 2. Recent reliability/coverage fixes — each verified live

### Fix #1 — Deep GraphQL testing (DVGA-grade)

The GraphQL scanner previously only checked introspection. It now also detects
field-suggestion leakage, query batching, alias-overloading DoS, and debug /
stack-trace disclosure — the actual weaknesses in *Damn Vulnerable GraphQL
Application*.

**Live target:** `https://pentest-ground.com:5013` (DVGA) · `--modules graphql`

| Severity | Conf. | Type | Finding | Endpoint | CWE |
|---|---|---|---|---|---|
| MEDIUM | firm | graphql | GraphQL introspection enabled | `/graphql` | CWE-200 |
| MEDIUM | firm | graphql | GraphQL introspection enabled | `/graphiql` | CWE-200 |
| MEDIUM | firm | graphql-dos | GraphQL query batching enabled | `/graphql` | CWE-770 |
| MEDIUM | firm | graphql-dos | GraphQL alias overloading (no query-cost limit) — 100 aliases resolved | `/graphql` | CWE-770 |
| MEDIUM | firm | graphql | GraphQL debug / stack-trace disclosure | `/graphiql` | CWE-209 |

**5 findings across 2 distinct GraphQL endpoints.** The batching and alias-DoS
findings carry a dedicated `graphql-dos` vuln type so the report scores them on
*availability* impact rather than information disclosure.

### Fix #2 — Product fingerprint → known-CVE matching (version-less)

The NVD CVE matcher needs a precise version to correlate CPE ranges, so a
WebLogic admin console exposed without a version banner was previously skipped
entirely. A new `product-cve` scanner fingerprints KEV-heavy enterprise products
(WebLogic, Confluence, Jenkins, Solr), recovers a version when one is exposed,
and surfaces the product's known-exploited CVEs enriched with CISA-KEV / EPSS.

**Live target:** `https://pentest-ground.com:7001` (Oracle WebLogic console) · `--modules product-cve`

```
+----------------------------------------------------------------------+
| Sev      | Type | Finding                                            |
|----------+------+----------------------------------------------------|
| CRITICAL | cve  | Exposed Oracle WebLogic Server 12.2.1.3.0 —        |
|          |      | 7 known-exploited CVE(s) [7 CISA-KEV]              |
+----------------------------------------------------------------------+
 product-cve : 1 finding · 6 requests · 2.30s · ok
```

- **Severity** CRITICAL · **Confidence** firm · **CVSS** 9.8 · **CWE-502**
- **Version 12.2.1.3.0 recovered** directly from the console response.
- All **7** correlated CVEs are on the CISA Known Exploited Vulnerabilities
  catalog: CVE-2020-14882, CVE-2020-14883, CVE-2017-10271, CVE-2019-2725,
  CVE-2018-2628, CVE-2020-2551, CVE-2023-21839.

### Fix #3 — Confirmation phase parallelized over WAN latency

The exploit/confirm phase ran confirmers in a serial loop, so per-finding network
round-trips summed up. It now runs candidates concurrently under a bounded
semaphore (sized to the scan's `concurrency`), with per-finding store writes kept
safe via per-call DB sessions.

Proven by deterministic tests (8 confirmations of 100 ms each):

```
tests/unit/test_exploit_phase.py::test_exploit_runs_candidates_concurrently PASSED
    # 8 × 100ms confirmations complete in < 0.5s (serial would be ≥ 0.8s)
tests/unit/test_exploit_phase.py::test_exploit_concurrency_is_bounded_by_config PASSED
    # peak in-flight confirmers ≤ configured concurrency
```

### Fix #4 — Browser-driven XSS confirmation on by default

`--browser` defaults to **on**; when Playwright is present the orchestrator starts
a headless browser and the XSS confirmer executes payloads in it (window-flag /
dialog proof + screenshot) rather than relying on reflection heuristics. Startup
now logs which mode is active.

---

## 3. Breadth — findings across vulnerability classes

Beyond the four fixes above, ORTHRUS produces genuine findings across its scanner
fleet on the authorized range. Representative live results:

| Target (authorized) | Class | Headline finding | Severity |
|---|---|---|---|
| `:5013` DVGA | GraphQL | Introspection + batching + alias-DoS + stack-trace (×5) | MEDIUM |
| `:7001` WebLogic | Known-CVE product | WebLogic 12.2.1.3.0 — 7 CISA-KEV RCE CVEs | CRITICAL |
| `:6379` Redis | Service exposure | Unauthenticated Redis `INFO` (redis_version 5.0.7) via native protocol probe | CRITICAL |

Full machine-readable evidence for the GraphQL and WebLogic runs is in
`reports/proof_graphql.json` and `reports/proof_weblogic.json` (report artifacts
are git-ignored by policy). The Redis exposure was confirmed via the scanner's
native protocol probe (`redis_unauth() == True`, banner `redis_version:5.0.7`,
`redis_mode:standalone`) — a raw service port has no HTTP surface for the crawl
baseline, so the service-exposure scanner talks the Redis wire protocol directly.

---

## 4. Reproduce it yourself

```bash
# Deep GraphQL testing against DVGA
orthrus --no-banner scan -t "https://pentest-ground.com:5013/" \
  --scope pentest-ground.com --modules graphql --no-exploit \
  --format json -o reports/proof_graphql.json

# Version-less product → known-CVE matching against WebLogic
orthrus --no-banner scan -t "https://pentest-ground.com:7001/console/login/LoginForm.jsp" \
  --scope pentest-ground.com --modules product-cve --no-exploit \
  --crawl-depth 0 --format json -o reports/proof_weblogic.json

# Native unauthenticated service exposure against Redis
orthrus --no-banner scan -t "https://pentest-ground.com:6379/" \
  --scope pentest-ground.com --modules exposed-services --aggressive --no-exploit \
  --crawl-depth 0 --format json -o reports/proof_redis.json
```

Run the full pipeline (recon → scan → confirm → report) by dropping `--modules`.

---

## 5. Expanded fleet — new-capability verifications (controlled & reproducible)

The roadmap build-out grew ORTHRUS from 42 → **55 scanners**, 13 → **16 recon**,
and 667 → **860 tests**. (Recon's latest addition is passive IP-address
intelligence — PTR/ASN/geo/cloud — verified live below.) Every new capability
was verified against a **real**
target (a live JWKS endpoint, a real headless Chromium, a real gRPC server, raw
sockets, the real OOB collaborator) — never a mock of the thing under test. These
are deterministic and reproducible, which is why they make better evidence than a
WAN scan that depends on a third-party target exhibiting a specific bug.

| New capability | Live target | Verified result |
|---|---|---|
| **N-identity authz matrix (BOLA)** | localhost multi-tenant app, real sockets | `user` reached `admin`'s `/doc/1` → **HIGH / CWE-639**; enforced `/admin` (403) & anonymous → not flagged |
| **Privilege-escalation forced-browse (BFLA)** | localhost, real sockets | low-priv `user` reached the *unlinked* `/admin/users` → **HIGH / CWE-285**; enforced `/admin` → not flagged |
| **Blind OS command injection (OOB)** | real `LocalCallbackServer` + sim app | injected `curl <callback>` executed → callback hit → **CRITICAL / CWE-78** |
| **JWT RS→HS algorithm confusion** | localhost JWKS endpoint, real socket | fetched the published RSA public key, forged a valid HS256 token from it → **HIGH / CWE-347** |
| **CL.0 request-smuggling desync** | two purpose-built raw-socket servers | desynced backend → **HIGH / CWE-444** (marker returned as 2nd response); CL-honouring server → **0** (no FP) |
| **SAML response inspection** | crafted SAML XML (offline) | unsigned-assertion / multi-assertion XSW / NameID comment-truncation flagged; an XXE entity doc parses safely (no resolution) |
| **Browser taint engine (DOM source→sink)** | real headless **Chromium** + localhost page | URL canary reached `document.write` **and** `innerHTML` → 2 × **HIGH DOM-XSS / CWE-79** (sinks named); static page → **0** |
| **gRPC server-reflection** | real gRPC server (reflection on) | `ListServices` returned `billing.v1.Payments`, `orthrus.test.Greeter` → **MEDIUM / CWE-200** |
| **Source-map recovery (recon)** | localhost JS + `.map`, real socket | recovered 2 endpoints invisible in the minified bundle (`/api/internal/v3/users`, `/admin/secret-action`) |
| **IP-address intelligence (recon)** | `pentest-ground.com`, **real DNS + Team Cymru** | resolved `178.79.134.182` → PTR `…linodeusercontent.com`, **AS63949 (Akamai Connected Cloud)**, prefix `178.79.128.0/18`, RIPE/US, cloud=**Akamai**; survived a real SQLite round-trip; out-of-scope target → **0** |
| **Host gathering (recon)** | `pentest-ground.com`, **real crt.sh + reverse-IP + /24 PTR sweep** | folded CT-log + reverse-IP + a live 256-address reverse-DNS sweep into one inventory: `pentest-ground.com` flagged **in-scope**, **114** neighbouring `178.79.134.0/24` hosts gathered and flagged **co-hosted/out-of-scope (never scanned)** |
| **ASM drift monitor** | `pentest-ground.com` (real recon ×2) + real SQLite + real webhook socket | `orthrus monitor` run 1 **established a 4-host baseline**, run 2 diffed it → **"no drift"**; a seeded snapshot correctly surfaced **1 new / 1 removed / 1 changed (+IP +port)** host and **delivered the alert to a live webhook** (HTTP 200) |
| **Finding drift (`monitor --deep`)** | real SQLite + real webhook socket | across two stored scans the engine flagged **1 new (`ssrf`) / 1 resolved (`sqli`)** finding while `xss` correctly **persisted despite a severity change** (low→high); the `finding_drift` alert reached a live webhook (HTTP 200). Shares one engine with `orthrus diff` |
| **Race condition — last-byte sync** | two localhost servers, **real raw-socket synchronized bursts** | the upgraded scanner opened **20 last-byte-synchronized connections**; a non-atomic one-shot endpoint (leaked 3 grants) was flagged **HIGH/firm CWE-362** (`accepted=3 limit-rejected=17`), while an atomic (locked) endpoint returned 1×200 + 19×409 and was correctly **not flagged** (no FP) |
| **Finding triage (`orthrus triage`)** | real SQLite round-trip | 11 raw findings deduped to **7 distinct issues** — 5 IDOR across `/order/1..5` folded into one `/order/{id}` cluster (×5), `/product/42`→`/product/{id}`, sorted critical-first. Optional LLM false-positive judge (prompt/parse unit-tested; no-ops without an API key) |
| **SSRF → IMDS credential theft** | localhost SSRF app + mock metadata, **real HttpClient** | the full SSRF scanner coerced `/fetch?url=` to the metadata service and **escalated to CRITICAL/firm CWE-918** (`SSRF → cloud credential theft (AWS)`): the AccessKeyId/role was surfaced while the SecretAccessKey + session Token were **redacted** (never stored). AWS/GCP/Azure extraction unit-tested |
| **Attack-path chaining (`orthrus chains`)** | real SQLite round-trip | correlated 5 stored findings into **2 CRITICAL attack paths** — `SSRF → internal-service compromise` (matched the SSRF and the exposed Redis **across ports** `:443`↔`:6379` via hostname keying) and `Session foothold → privilege escalation` (jwt + BFLA); a lone header finding formed no chain, and cross-host findings don't fabricate paths |
| **Triage + chains in the report** | real SQLite → report render | the report context computes chains + triage and renders an **Attack Paths** section (technical + executive HTML), a `## Attack Paths` block and "duplicate(s) folded" note (Markdown), and `chains`/`triage` keys (JSON) — verified live across all four formats; the section is omitted when no chains exist |

### Low-false-positive discipline, demonstrated live

A fresh GraphQL run against **DVGA (`pentest-ground.com:5013`)** returned 3
genuine findings — introspection enabled, query batching, alias overloading — and
the new **circular-fragment** check *correctly stayed silent*: DVGA's spec-
compliant graphql-core rejects fragment cycles with a validation error, so the
scanner does **not** flag it. New detectors are built to fire on the vulnerable
case and stay quiet on the safe one.

```
$ orthrus --no-banner scan -t https://pentest-ground.com:5013/ \
    --scope pentest-ground.com --modules graphql --no-exploit
  [MEDIUM] graphql      GraphQL introspection enabled
  [MEDIUM] graphql-dos  GraphQL query batching enabled
  [MEDIUM] graphql-dos  GraphQL alias overloading (no query-cost limit)
  # circular-fragment: not flagged (DVGA correctly rejects fragment cycles)
```

> Note on optional runtimes: the browser taint engine needs
> `playwright install chromium` and the gRPC scanner needs the `grpc` extra
> (`pip install "orthrus-framework[grpc]"`); both no-op cleanly when absent.
