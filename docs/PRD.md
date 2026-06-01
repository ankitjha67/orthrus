# Project ORTHRUS — Product Requirements Document

**Authorized-only web application & API vulnerability framework**
*Implemented-system specification + forward roadmap*

---

## 0. Document control

| | |
|---|---|
| Document | ORTHRUS PRD — implemented system of record |
| Version | 1.0 |
| Date | 2026-05-30 |
| Status | Living document — describes what is **built and shipping** today, plus the roadmap for advanced capabilities |
| Source of truth | The public repository (`github.com/ankitjha67/orthrus`). Every requirement below is reflected in code + tests. |
| Relationship to code | This is the *engineering* PRD authored from the implemented codebase. It is **not** the original private design brief (which is excluded from the repo). Nothing proprietary is reproduced here. |
| Verified snapshot | 55 scanners · 17 confirmation modules · 15 recon modules · 802 passing tests · `ruff` clean |

**How to read this:** Sections 1–4 are product framing. Sections 5–18 are the granular requirements/spec of every shipping subsystem. Section 19 is the current metrics snapshot. Section 20 is the roadmap for *more advanced scanners and methods*. Appendices give master lookup tables and the file tree.

---

## 1. Product overview & vision

ORTHRUS is a **Kali-grade, fully-automated dynamic application security testing (DAST) framework** for **authorized** engagements. It crawls a target, fingerprints its stack, runs a broad fleet of vulnerability scanners, and — uniquely — runs a fourth **exploitation-confirmation** phase that actively re-proves the interesting findings so a report can distinguish *"this looks vulnerable"* (`tentative`/`firm`) from *"this was demonstrably exploited"* (`confirmed`).

**Positioning.** Where most open scanners stop at *detection* (and drown the user in unverified "potential" findings), ORTHRUS treats a finding as a hypothesis and tries to falsify or prove it. The result is a low-false-positive report with machine-readable evidence, CVSS v3.1/v4.0 scoring, and OWASP/CWE/PCI-DSS/NIST-CSF/MITRE-ATT&CK mappings, exportable as JSON/CSV/HTML/PDF/SARIF/Markdown.

**One-line vision.** *"A single command that safely takes an authorized target from URL → confirmed, prioritized, compliance-mapped findings — reproducibly, with evidence, and without scanning anything it wasn't told to."*

---

## 2. Goals, non-goals, and design principles

### 2.1 Goals
- **G1 — Breadth:** cover the OWASP Top 10 (Web + API + LLM), plus infrastructure, transport, supply-chain, and cloud/IaC posture.
- **G2 — Confirmation:** actively re-prove every *actively-exploitable* finding; upgrade confidence to `confirmed` with captured evidence.
- **G3 — Low false positives:** every detector ships with FP guards (baselines, differentials, fresh-nonce re-proof, content fingerprints).
- **G4 — Safety & legality:** deny-by-default scope enforced on **every** request, redirect, and browser subresource.
- **G5 — Operability:** one CLI, resumable scans, CI-friendly exit gates, SARIF for code scanning, REST API + dashboard + MCP for integration.
- **G6 — Self-contained working code:** native detectors, not thin wrappers that only work if an external binary is present (external tools are optional accelerators, never the only path).

### 2.2 Non-goals
- **N1:** Not a destructive exploitation framework. Confirmation is non-destructive proof, never damage (no `DROP TABLE`, no real RCE payloads — canaries, OOB callbacks, read-only file reads).
- **N2:** Not an unauthenticated mass-scanner / internet crawler. It scans exactly what scope allows.
- **N3:** Not a replacement for manual pentesting on bespoke business logic — it accelerates and de-risks the repeatable 80%.

### 2.3 Design principles (non-negotiable)
1. **Authorized testing only.** The operator attests authorization; the tool enforces scope deny-by-default.
2. **Confirm, don't just flag.** A confirmer exists for every class where a *safe, generic* active proof is possible.
3. **Detection-is-proof or detection-only — never fake a confirmation.** Observational classes (headers, TLS, banners, known-CVE product) ship `firm` from observation; classes with no safe generic exploit (e.g. insecure deserialization RCE) stay detection-only and say so.
4. **Evidence everywhere.** Every finding carries request/response/marker/screenshot evidence; secrets (JWT keys, credentials) are never emitted.
5. **Fresh-nonce re-proof.** Confirmers mint brand-new markers/origins/sentinels so a `confirmed` verdict can't be a cache hit, a static allow-list, or an echo coincidence.
6. **Crash isolation.** One scanner/recon/tool failure never aborts the run.

---

## 3. Personas & primary use cases

| Persona | Use case |
|---|---|
| **Pentester / red-teamer** | Point ORTHRUS at an in-scope target, get a confirmed-findings report with evidence to drop into the engagement deliverable. |
| **AppSec / DevSecOps engineer** | Wire the GitHub Action into CI; fail the build on `--fail-on high`; upload SARIF to the Security tab. |
| **Bug-bounty hunter** | Run authenticated scans against programs-in-scope; use confirmation to avoid filing false positives. |
| **Platform / automation** | Drive ORTHRUS via the REST API or the MCP server (LLM agent integration); query scans/findings programmatically. |
| **Blue-team / asset owner** | Continuous authorized scanning of owned properties; diff scans for regressions. |

**Canonical command:**
```bash
orthrus scan -t https://app.example.com --scope example.com \
  --aggressive --format sarif -o report.sarif --fail-on high
```

---

## 4. System architecture

### 4.1 The four-phase pipeline

```
        ┌──────────┐   ┌──────────┐   ┌────────────────────┐   ┌──────────┐
TARGET →│  RECON   │ → │   SCAN   │ → │ EXPLOIT / CONFIRM  │ → │  REPORT  │→ artifacts
        │ 14 mods  │   │ 55 scan  │   │ 17 confirmers      │   │ 6 fmts   │
        └──────────┘   └──────────┘   └────────────────────┘   └──────────┘
             │              │                   │                    │
        assets/        findings            confidence            JSON/CSV/HTML/
        endpoints/     (tentative/         upgraded to           PDF/SARIF/MD
        technologies   firm)               `confirmed`           + compliance maps
```

- **Orchestrator** sequences phases, isolates crashes, emits events, checkpoints for `--resume`, and parallelizes confirmation.
- **ScanContext** is the shared in-memory state (assets, endpoints, technologies, http client, scope, callback, browser).
- **Store** persists everything to SQLite/Postgres (encrypted evidence) so scans are resumable and reportable after the fact.
- **ScopeValidator** is consulted before every network egress (HTTP request, redirect hop, browser subresource).

### 4.2 Phase ordering
`_PHASE_ORDER = ("recon", "scan", "exploit")` with a numeric rank; `--resume` skips any phase whose rank ≤ the persisted checkpoint. `run_full()` runs recon → scan → exploit → integrations → report.

---

## 5. Core platform requirements

### 5.1 Data model (`orthrus/core/schemas.py`)

**Enums**

| Enum | Members |
|---|---|
| `Severity` | `INFO`(0) · `LOW`(1) · `MEDIUM`(2) · `HIGH`(3) · `CRITICAL`(4) |
| `Confidence` | `TENTATIVE` · `FIRM` · `CONFIRMED` (CONFIRMED set only by the exploit phase) |
| `HttpMethod` | `GET` · `POST` · `PUT` · `PATCH` · `DELETE` · `HEAD` · `OPTIONS` |
| `ParamLocation` | `QUERY` · `BODY` · `JSON` · `HEADER` · `COOKIE` · `PATH` · `XML` |
| `Aggressiveness` | `PASSIVE` · `NORMAL` · `AGGRESSIVE` |

**Core models** (Pydantic v2; all carry a 12-char hex `id` + `discovered_at`/`created_at` timestamps where relevant)

- **`Technology`** — `name`, `version?`, `category?` (server/framework/cms/js-library), `confidence`.
- **`Asset`** — `fqdn`, `ips[]`, `cname_chain[]`, `ports[]`, `discovery_method`, `http_available`, `https_available`, `status_code?`, `title?`, `technologies[]`.
- **`Param`** — `name`, `location` (ParamLocation), `value?`.
- **`Endpoint`** — `url`, `method`, `params[]`, `headers{}`, `cookies{}`, `response_status?`, `response_headers{}`, `set_cookies[]`, `content_type?`, `content_length?`, `content_hash?` (SHA-256, dedup), `source` (crawler/js-analyzer/spec/api-discovery/sensitive/…).
- **`Evidence`** — `request_raw?`, `response_raw?`, `matched_at?`, `screenshot_path?`, `notes?`, `extra{}`.
- **`Finding`** — `vuln_type`, `title`, `severity`, `confidence`, `url`, `parameter?`, `param_location?`, `description`, `remediation`, `cwe?`, `cvss_score?`, `cvss_vector?`, `scanner`, `evidence`.
- **`ExploitResult`** — `finding_id`, `technique`, `success`, `extracted_data?` (encrypted at rest), `callback_id?` (OOB token), `evidence`.

### 5.2 Configuration model (`orthrus/core/config.py`)

**`ScanConfig`** (53 fields) — full surface controlling a run. Highlights with defaults:

- Targeting: `target`, `scope: ScopeConfig`, `modules=["all"]`, `tools=[]`, `aggressiveness=NORMAL`.
- Crawl/transport: `crawl_depth=10`, `max_pages=5000`, `timeout=30.0`, `concurrency=10`, `rate_limit: RateLimitConfig`, `proxy?`, `user_agent="random"`, `extra_headers={}`, `verify_tls=False` (pentest default), `waf_adapt=True`.
- Auth: `auth_cookie?`, `login_url?`, `login_data?`, `login_token_field?`, `login_check?`, `csrf_url?`, `csrf_field?`, `csrf_header?`, `totp_secret?`, `totp_field="otp"`, full `oauth2_*` set (`grant="password"`, `token_field="access_token"`), `reauth=False`, `reauth_markers=[]`.
- Discovery import: `import_spec?` (OpenAPI/Swagger/GraphQL/HAR/Postman), `templates?`.
- OOB: `callback?`, `interactsh=False`, `interactsh_server?`, `interactsh_token?`.
- Exploit/browser: `no_exploit=False`, `use_browser=True`, `har_path?`.
- Reporting: `output="orthrus_report"`, `report_format="html"`, `report_template="technical"`, `min_severity?`, `branding_logo?`, `quiet=False`.

**`ScopeConfig`** — `domains[]` (exact or `*.wildcard`), `ip_ranges[]` (CIDR v4/v6), `ports=[80,443]` (empty = any), `exclude_paths[]` (regex), `block_third_party=True`. `auto_from_target()` derives scope from a URL.

**`RateLimitConfig`** — `requests_per_second=50.0`, `burst=10`, `jitter=0.0`, `adaptive=True` (back off on 429/503 + `Retry-After`).

**`Settings`** (env-driven) — `db_url` (default `sqlite+aiosqlite:///./orthrus.sqlite3`), `data_dir`, `log_level`, `redis_url`, `plugins_dir?`, `encryption_key?` (AES-256 at rest), plus optional API keys (`nvd_api_key`, `shodan`, `censys`, `virustotal`, `github_token`).

### 5.3 Scope enforcement (`orthrus/utils/scope.py`) — load-bearing

`ScopeValidator.check(url) -> ScopeDecision(allowed, reason, third_party)`:
1. Reject URLs with no host.
2. Deny any path matching an `exclude_paths` regex.
3. Host check: IP-literal must be in `ip_ranges`; hostname must match a `domains` entry (`*.x` matches `x` and `*.x`). Out-of-scope host → rejected when `block_third_party`, else allowed-but-flagged.
4. Port check: infer default from scheme; reject if not in `ports`.

`is_allowed()`, `assert_in_scope()` (raises `ScopeViolation`), `ip_in_scope()` (DNS-rebinding guard), `filter_in_scope()`. **Deny-by-default**: anything not explicitly matched is rejected. Enforced in the HTTP client before every request *and* every redirect hop, and in the browser route interceptor for every subresource.

### 5.4 HTTP transport (`HttpClient`)
- httpx-based, **HTTP/2 on**, `verify_tls=False` default, configurable proxy, `max_redirects=5` (each hop scope-checked + rate-limited).
- **Rate limiting**: per-host token bucket (`requests_per_second`, `burst`, `jitter`), adaptive backoff on 429/503 honoring `Retry-After`.
- **Identity**: realistic User-Agent pool + Chrome client-hints / Sec-Fetch headers; rotation on WAF block.
- **Counters**: `requests_sent`, `scope_violations`.
- **Silent re-auth**: if a response `looks_unauthenticated()` (401 or a re-auth marker) and a session reauth callback exists, re-run login once and replay (recursion-guarded).

### 5.5 WAF evasion + adaptive resilience
- **`_evasion.py` encoder library**: `url_encode`, `url_encode_special`, `double_url_encode`, `html_entity`, `unicode_escape` (encoders) + `mixed_case`, `comment_spacing` (transport-safe transforms). `variants(payload, max_variants, transport_safe)` and `transport_safe_variants()` produce labeled payload mutations. Wired into SQLi boolean detection under `--aggressive`.
- **Adaptive WAF (`waf_adapt`)**: `detect_block(status, headers, body)` classifies challenge/interstitial/block/rate_limit; on a true block, cool off (0.4–1.2 s) and retry once under a rotated identity. `BlockMonitor` reports a per-host block-rate as a scan-reliability signal.

### 5.6 Authentication engine (`orthrus/core/auth.py`)
- **Form/JSON login** (`perform_login`): parses `user=…&pass=…` or JSON creds; harvests anti-CSRF token from form fields / `<meta>` / double-submit cookie (`COMMON_CSRF_FIELDS`, `COMMON_CSRF_COOKIES`) and replays it in body and/or header; injects RFC-6238 **TOTP** (dependency-free HMAC-SHA1) under `totp_field`; POSTs creds; extracts a bearer token by dotted-path; success = token set OR success-marker present OR status < 400.
- **OAuth2/OIDC** (`acquire_oauth2_token`): `password` / `client_credentials` / `refresh_token` grants (RFC 6749), dotted-path token extraction.
- **Silent session refresh**: `looks_unauthenticated()` with default + custom markers.

### 5.7 OOB collaborator (`orthrus/core/callback.py`)
- **`LocalCallbackServer`** — threaded HTTP listener on `127.0.0.1:0`; `new_token()` → (16-hex token, URL); records method/path/headers/body; for same-host targets.
- **`InteractshCallbackClient`** — real Interactsh: RSA-2048 register against public pool (`oast.fun`/`oast.pro`/…) or self-hosted; AES-decrypts polled interactions; DNS/HTTP/SMTP protocols; for internet-reachable targets. Used by SSRF/XXE blind confirmation.

### 5.8 Headless browser engine (`orthrus/core/browser.py`)
- Playwright Chromium, headless, `ignore_https_errors`, optional HAR recording, context recycling every 20 pages (memory bound), `is_available()` gate.
- **`check_execution(url, marker)`** — proves XSS execution via `window['__hx_<marker>']` flag or dialog message; captures screenshot.
- **Route interception** — every browser subresource scope-checked; out-of-scope aborted. Captures in-scope XHR/fetch as `CapturedRequest` (dedup, cap 500) feeding the browser-crawl recon.

### 5.9 Persistence & store (`orthrus/db/`)
SQLAlchemy 2.0 async ORM (SQLite default, Postgres via `[postgres]`). Per-call `AsyncSession` (safe under concurrent confirmation). Tables: **Scan** (id/target/scope_json/config_json/status/**phase**/started_at/completed_at), **Asset**, **Endpoint** (content_hash dedup), **Finding** (vuln_type/severity/confidence/cwe/cvss/evidence_json), **Exploitation** (technique/success/encrypted extracted_data+request_raw+response_raw/screenshot/callback_id), **Callback**, **ScanLog**. Evidence fields encrypted via `crypto.protect()` when `encryption_key` set. `phase` column is the **resume checkpoint**.

### 5.10 Orchestrator, events, progress
- Phase methods: `setup` → `run_recon` → `run_scan` → `run_exploit` → `run_integrations` → `run_report` → `teardown`.
- **Event bus**: `SCAN_STARTED`, `PHASE_STARTED/COMPLETED`, `ASSET/ENDPOINT_DISCOVERED`, `FINDING_RAISED`, `EXPLOIT_CONFIRMED`, `SCOPE_VIOLATION` (logged to store).
- **Per-scanner metrics**: findings, requests, duration, status; one crash never aborts the run.
- **Confirmation parallelism**: candidates run under `asyncio.Semaphore(min(concurrency, len(candidates)))`; per-finding modules serial with break-on-first-success; aggregate confirmed count.
- **Progress**: Rich progress bars when `console.is_terminal and not quiet`.

---

## 6. Reconnaissance subsystem (14 modules)

Run in this order; each enriches `ScanContext`. Soft-404 baseline (`build_baseline`) computed first.

| Module | `name` | Discovers | Notable limits |
|---|---|---|---|
| `tech_fingerprint` | tech-fingerprint | Server/framework/CMS/JS-lib from headers, cookies, body sigs → `Asset.technologies` | passive |
| `crawler` | crawler | BFS static crawl; links + forms → endpoints; inline-script endpoints; content-hash dedup | `max_pages`, `crawl_depth` |
| `js_analyzer` | js-analyzer | API/WS URLs + hardcoded secrets from external `.js` (AWS/Google/Slack/JWT/private-key regexes) | `MAX_FILES=60` |
| `sourcemap_recovery` | sourcemap-recovery | Locates `.map` (inline `sourceMappingURL` or `<file>.map`), parses `sourcesContent`, mines endpoints from the **original un-minified source** | `MAX_JS=30`, `MAX_MAPS=30` |
| `content_discovery` | content-discovery | Dir/file brute (35-word list) with soft-404 calibration; tags `.env/.git/backup/config` as `source="sensitive"` | — |
| `waf_detect` | waf-detect | Passive WAF ID (Cloudflare/Akamai/AWS/Imperva/Sucuri/ModSec/F5/Barracuda/Fortinet) | passive |
| `api_discovery` | api-discovery | Probes spec paths (OpenAPI/Swagger/GraphQL) + imports operator specs + GraphQL introspection | scope-filtered |
| `browser_crawl` | browser-crawl | SPA bootstrap XHR/fetch captured via Playwright → typed endpoints | `MAX_NAV=20` |
| `spa_crawl` | spa-routes | Client-side route enumeration (Angular/React/Vue) + per-route API capture | `MAX_ROUTES=25` |
| `dns_enum` | dns-enum | A/AAAA/CNAME/MX/NS/TXT + AXFR zone-transfer attempts | domain-only |
| `subdomain_enum` | subdomain-enum | crt.sh CT logs + 60-word brute, wildcard-catch-all filtering | `MAX_BRUTE=60` |
| `wayback` | wayback | Historical URLs from Internet Archive CDX | `MAX_RESULTS=500` |
| `port_scan` | port-scan | Nmap `-sV` open ports (optional binary) | opt-in |
| `param_mining` | param-miner | Arjun-style hidden query-param discovery via reflection (40 candidates) | `MAX_ENDPOINTS=20`, `MAX_REQUESTS=900` |

**Spec parsing** (`spec_parsers.py`, offline): OpenAPI 3.x / Swagger 2.0, GraphQL introspection, HAR, Postman v2.x → typed `Endpoint`s with `$ref` deref + schema-sampled values.

---

## 7. Vulnerability scanning subsystem (55 scanners)

Each scanner subclasses `BaseScanner`, implements `async scan(ctx) -> AsyncIterator[Finding]`, declares `min_aggressiveness`, and self-registers. The shared injection layer (`_injection.py`) yields `InjectionPoint`s across `QUERY`, `BODY`, `JSON`, and `PATH` locations for `GET/POST/PUT/PATCH/DELETE`.

### 7.1 Injection & code execution
| Scanner | vuln_type | CWE | Aggr. | Method (granular) |
|---|---|---|---|---|
| `sqli` | sqli | CWE-89 | NORMAL | Error-based (5-DBMS signatures); boolean-blind across 5 closing contexts (+ transport-safe evasion under AGGRESSIVE); time-based `SLEEP/WAITFOR` (AGGRESSIVE, 60% threshold). `MAX_POINTS=120` |
| `nosql` | nosql-injection | CWE-943 | NORMAL | Operator/quote payloads (`{"$gt":""}`, `';return true`), Mongo/BSON/$where error signatures; baseline guard. `MAX_PROBES=80` |
| `cmd_injection` | cmd-injection | CWE-78 | NORMAL | Output-based `echo <canary>` (canary-alone guard); time-based sleep (AGGRESSIVE); **OOB callback** — inject `curl`/`wget` to the collaborator and poll, proving *blind* RCE. `MAX_POINTS=120` |
| `ssti` | ssti | CWE-1336 | NORMAL | Arithmetic polyglot `{a*b}` across 5 template syntaxes; evaluated-not-reflected guard |
| `ssrf` | ssrf | CWE-918 | PASSIVE | Cloud-metadata URLs (AWS/Azure/GCP/DO/Oracle) + signature match; OOB callback variant; URL-hinted param priority |
| `xxe` | xxe | CWE-611 | PASSIVE | In-band `file:///etc/passwd` + blind OOB entity; XML/SOAP/upload target priority |
| `lfi` | lfi | CWE-22 | NORMAL | `/etc/passwd` + `win.ini` signatures; baseline leak guard |
| `open_redirect` | open-redirect | CWE-601 | NORMAL | 4 payloads incl. `//`, backslash, `%2f` bypasses; 3xx + off-host Location |

### 7.2 Cross-site scripting (browser-backed)
| Scanner | vuln_type | CWE | Method |
|---|---|---|---|
| `xss` | xss | CWE-79 | Per-char reflection (`< > " '`), context classification, content-type aware (HTML only). `MAX_TESTS=300` |
| `stored_xss` | xss | CWE-79 | Submit `<img onerror>` via forms; re-render up to 10 pages in browser; window-flag proof → **CONFIRMED** |
| `dom_xss` | xss | CWE-79 | Fragment + query sources executed in browser, discriminated from server reflection → **CONFIRMED** |
| `dom_taint` | xss / open-redirect | CWE-79/601 | **Browser taint engine** — `BrowserManager.trace_taint` installs an init-script that hooks DOM injection/navigation sinks (eval/document.write/innerHTML/insertAdjacentHTML/setTimeout-str/location.assign/replace/window.open); a URL-seeded canary reaching a sink is reported as DOM XSS or client-side open redirect, naming the exact sink |

### 7.3 Access control & logic
| Scanner | vuln_type | CWE | Method |
|---|---|---|---|
| `authz_matrix` | broken-authorization | CWE-639/285 | **Multi-identity BOLA/BFLA** (`--identities`): replays each read endpoint as N principals (first = privileged baseline) via isolated per-identity clients; flags when a lower/anonymous identity gets the baseline's successful response. Object-ref → BOLA, else BFLA. FIRM for a named user, TENTATIVE for anonymous |
| `privilege_escalation` | privilege-escalation | CWE-285 | **Forced-browse** a curated admin/privileged-path corpus across the `--identities` lattice; flags an *unlinked* route the baseline reaches that a lower-priv/anon identity also reaches (BFLA on routes the crawler never found). Per-origin soft-404 guard |
| `idor` | idor | CWE-639 | Numeric ID ±1; 200 + structurally-similar + distinct → TENTATIVE enumeration |
| `mass_assignment` | mass-assignment | CWE-915 | Per-field nonce inject of 25 privileged fields; bound-only-after-inject differential; HIGH for role/admin/etc. |
| `business_logic` | business-logic / parameter-pollution | CWE-472 / CWE-235 | Monetary/qty tamper (negative/zero/fractional/overflow) + HPP duplicate-param winner detection |
| `race_condition` | race-condition | CWE-362 | AGGRESSIVE; 8 concurrent requests at transactional forms; partial-success window |

### 7.4 Authentication & session
| Scanner | vuln_type | CWE | Method |
|---|---|---|---|
| `auth` | auth-session | CWE-614/1004/1275/331 | Cookie flag analysis (Secure/HttpOnly/SameSite) + Shannon-entropy token strength (<64 bits) |
| `jwt_analyzer` | jwt | CWE-347/613/522 | alg:none, weak-HMAC brute (15-word list), missing `exp`, sensitive claims, `jku`/`x5u`/`kid` header attacks; **RS->HS algorithm confusion** — fetches JWKS, derives the RSA public PEM, and forges a valid HS256 token from it (raw-HMAC, bypassing PyJWT's guard) to prove the forgery primitive |
| `default_creds` | default-creds | CWE-1392 | 12 default credential pairs vs baseline-failure differential |

### 7.5 Transport, headers, cache
| Scanner | vuln_type | CWE | Method |
|---|---|---|---|
| `tls_analyzer` | tls | CWE-327/295/297/298 | sslyze protocol+cipher+cert audit (SSLv2/3, TLS1.0/1.1, weak ciphers, expiry, mismatch) |
| `headers` | security-headers | CWE-693/1021/319/200 | CSP, X-Frame-Options/frame-ancestors, HSTS (+max-age), nosniff, Referrer-Policy, version leak |
| `cors` | cors | CWE-942 | Origin reflection (arbitrary/null/subdomain) + credentialed escalation |
| `crlf` | crlf-injection | CWE-113 | `\r\n` sentinel header/cookie surviving into parsed response headers |
| `host_header` | host-header-injection | CWE-644 | Forged Host/X-Forwarded-Host reflected as **authority of an absolute URL** (regex-guarded) |
| `cache_poisoning` | cache-poisoning | CWE-444 | Unkeyed header reflection + cacheability indicators |
| `web_cache_deception` | web-cache-deception | CWE-525 | Static-suffix path returning verbatim dynamic page; soft-404 guard |

### 7.6 Infrastructure & configuration
| Scanner | vuln_type | CWE | Method |
|---|---|---|---|
| `exposed_files` | exposed-file | CWE-538 | Consumes `source="sensitive"` endpoints (.env/.git/backup/config) — no extra requests |
| `framework_debug` | framework-debug | CWE-200/489 | Debug-mode stack-trace probe + 9 content-fingerprinted mgmt endpoints (Actuator/phpinfo/server-status/metrics/Telescope/Rails) |
| `sca` | vulnerable-component | CWE-79/1321/1104 | JS lib version fingerprint vs vuln DB (jQuery/lodash/Handlebars/AngularJS) |
| `service_exposure` | exposed-service | CWE-306 | AGGRESSIVE; **raw-socket** native Redis `PING`/Memcached `stats` unauth probe (skips web ports) → CRITICAL/HIGH |
| `subdomain_takeover` | subdomain-takeover | CWE-350 | 15 provider-specific dangling-CNAME fingerprints (no generic-404) |

### 7.7 Protocol, advanced & API
| Scanner | vuln_type | CWE | Method |
|---|---|---|---|
| `graphql` | graphql / graphql-dos | CWE-200 / CWE-770 | Introspection, field-suggestion leakage, **query batching**, **alias overloading (100)**, debug/stack-trace (DVGA-grade) |
| `websocket` | websocket | CWE-1385 | Cross-origin WS handshake accepted (missing Origin validation) |
| `grpc_probe` | grpc-reflection | CWE-200 | Connects over gRPC and issues a reflection `ListServices`; if the server answers, the full RPC API surface (all services) is exposed in prod. Needs the `grpc` extra |
| `request_smuggling` | request-smuggling | CWE-444 | AGGRESSIVE; **raw-socket** CL.TE/TE.CL timing desync (TENTATIVE) **plus CL.0 differential desync** — a POST whose body is a request for a unique marker path; if the marker returns as a second HTTP response the connection desynced (FIRM) |
| `prototype_pollution` | prototype-pollution | CWE-1321 | Browser-evaluated `Object.prototype` pollution via 4 payload shapes → **CONFIRMED** |
| `sspp` | prototype-pollution | CWE-1321 | NORMAL; server-side JSON `__proto__` differential (clean-before / polluted-after) |
| `deserialization` | deserialization | CWE-502 | Passive serialized-blob signatures (Java/PHP/.NET/pickle/Ruby) — **detection-only** |

### 7.8 Intelligence, AI, services
| Scanner | vuln_type | CWE | Method |
|---|---|---|---|
| `cve_matcher` | cve | (per-CVE) | NVD 2.0 CPE version-range match for fingerprinted product+version; KEV/EPSS enrichment; on-disk cache |
| `product_cve` | cve | (per-product) | **Version-less** KEV-heavy product fingerprint (WebLogic/Confluence/Jenkins/Solr) → known-exploited CVEs |
| `llm` | prompt-injection / llm-info-disclosure | CWE-1427 / CWE-200 | LLM01 canary-obey injection (reflection-guarded → CONFIRMED) + LLM06 system-prompt leak (≥2 markers) |

### 7.9 Roadmap Wave-1 additions (shipped)
| Scanner | vuln_type | CWE | Aggr. | Method |
|---|---|---|---|---|
| `csp_analyzer` | csp | CWE-693 | PASSIVE | Parses a *present* CSP; flags `unsafe-inline`/`unsafe-eval`/wildcard/`data:` script sources, missing `object-src 'none'`/`frame-ancestors`, insecure `http:` sources (no duplicate of "missing CSP") |
| `secret_scanner` | exposed-secret | CWE-798 | PASSIVE | AWS/Google/Slack/Stripe/GitHub/OAuth keys + PEM private-key blocks in responses/JS; **redacted** to a 4-char preview |
| `csv_injection` | formula-injection | CWE-1236 | NORMAL | Benign nonce formula surviving into a CSV/spreadsheet export (content-type-guarded) |
| `api_misconfig` | api-misconfig | CWE-16/693 | NORMAL | TRACE/XST (echoed nonce) + dangerous advertised methods via OPTIONS `Allow` |
| `shadow_api` | shadow-api | CWE-668 | NORMAL | Version/inventory mutation (`/v1↔/v2↔/internal↔/beta…`) with soft-404 calibration (OWASP API9) |
| `directory_listing` | directory-listing | CWE-548 | NORMAL | Autoindex/"Index of /" pages over endpoint parent-dirs + common dirs |

*(Plus the declarative `templates` scanner — see §11.)*

---

## 8. Exploitation-confirmation subsystem (17 modules)

Each confirmer subclasses `BaseExploit`, declares a `handles` tuple of `vuln_type`s, and re-proves impact with a **fresh** probe — upgrading `tentative/firm → confirmed`. Helpers in `_replay.py`: `reissue` (replay original GET/body/JSON), `send_value` (fresh value into the param), `replay_get/post/json`, `payload_from_evidence`, `find_endpoint`, `format_request/response`.

| Confirmer | handles | Re-proof technique |
|---|---|---|
| `xss-confirm` | xss | Browser execution (window-flag/dialog + screenshot) for query XSS; HTML-context reflection for body XSS |
| `sqli-confirm` | sqli | Replay → re-prove DBMS error (blind stays firm) |
| `ssrf-confirm` | ssrf | Fresh OOB callback URL → poll collaborator |
| `lfi-confirm` | lfi | Replay → re-match file signature |
| `ssti-confirm` | ssti | Replay → evaluated expression reappears |
| `cmd-confirm` | cmd-injection | Replay → canary output present |
| `xxe-confirm` | xxe | Re-POST external-entity payloads → file signature |
| `open-redirect-confirm` | open-redirect | Replay (no-follow) → 3xx off-host Location |
| `nosql-confirm` | nosql-injection | Replay → re-prove driver/query error |
| `crlf-confirm` | crlf-injection | **Fresh nonce** header survives into response headers |
| `cors-confirm` | cors | **Fresh unique attacker Origin** reflected (or `*`+creds) |
| `host-header-confirm` | host-header-injection | **Fresh sentinel host** re-reflected into link/redirect |
| `mass-assignment-confirm` | mass-assignment | **Fresh per-field nonce** re-bound into response object |
| `idor-confirm` | idor | Neighbour + adjacent resolve; **implausible far ID does not** → enumeration reproduced |
| `jwt-confirm` | jwt | Weak-secret only: recover key, forge tampered token, round-trip verify (secret never emitted) |
| `prototype-pollution-confirm` | prototype-pollution | Server-side differential with **fresh sentinel** |
| `graphql-dos-confirm` | graphql-dos | Re-issue batching array / 100-alias probe and re-observe amplification |

### 8.1 The confirmation doctrine (why exactly these)
- **Actively-confirmable (17 above):** a safe, generic active proof exists.
- **Confirmed-by-detection:** observation *is* the proof and ships `firm`/`confirmed` — security-headers, TLS, banner, known-CVE product, SCA, subdomain-takeover, web-cache-deception, framework-debug, GraphQL introspection; plus classes already actively proven at detection time (default-creds login, request-smuggling desync timing, native service-exposure protocol probe, stored/DOM-XSS browser execution).
- **Detection-only by design:** **insecure deserialization** — a passive serialized-blob signature; proving RCE needs a target-specific gadget chain, so ORTHRUS reports it rather than inventing a misleading confirmation.

---

## 9. Injection & evasion framework
- **`_injection.py`**: `injection_points(ctx)` (unique method/path/location/param), `send(ctx, point, value)`, `used_url(point, value)`. `INJECTABLE_LOCATIONS = QUERY/BODY/JSON/PATH`; body methods `POST/PUT/PATCH/DELETE`.
- **`_evasion.py`**: 5 encoders + 2 transport-safe transforms; `variants()` / `transport_safe_variants()`.

---

## 10. Intelligence & enrichment (`orthrus/intel/`)
- `enrich(cve_id) -> CveIntel(kev, epss)`; `escalate_severity(base, intel)` (KEV raises sub-HIGH→HIGH); `summary(intel)` (human tag); `refresh_kev(feed)` (wired to `orthrus update`).
- Offline seeds: **CISA KEV (46 CVEs)** + **EPSS (21 CVEs)** — snapshot so enrichment works without network; refreshable from the live CISA feed.
- Consumed by `cve_matcher` and `product_cve` (KEV escalation + EPSS prioritization tags in findings).

---

## 11. Declarative template engine (`orthrus/templates/`)
Nuclei-style YAML/JSON engine. **Matchers**: `word`/`regex`/`status`/`size` over `body`/`header`/`status`/`all`, `and`/`or` condition, negative + case-insensitive flags. **Extractors**: `regex`/`kval`. **RequestTemplate**: `{{BaseURL}}`/`{{RootURL}}`/`{{Hostname}}`/`{{Host}}` placeholders, headers/body, matcher condition, stop-at-first-match. **Loader**: `builtin` directory / file / recursive directory. `TemplateScanner` (`templates` module), `MAX_REQUESTS=1000`, status-only matchers calibrated against 404 baseline. Run via `--templates builtin|<path>`.

---

## 12. Cloud / IaC analyzer (`orthrus/iac/`)
`orthrus iac PATH` — static analysis (no network). All `vuln_type="iac-misconfig"`.
- **Dockerfile (5)**: unpinned base (CWE-1104), curl|sh (CWE-494), remote `ADD` (CWE-494), hardcoded ENV/ARG secrets (CWE-798), runs-as-root (CWE-250).
- **docker-compose (6)**: privileged (CWE-250), host network/PID (CWE-668), docker.sock mount (CWE-668), dangerous capabilities (CWE-250), unpinned image (CWE-1104), env secrets (CWE-798).
- **Terraform (4)**: `0.0.0.0/0` ingress (CWE-284), public ACL (CWE-284), encryption disabled (CWE-311), hardcoded secrets (CWE-798).
- Secret regex skips `$`/var-references/path/`{{` templating to avoid FPs. `--fail-on` severity gate.

---

## 13. Reporting & compliance (`orthrus/reporting/`)
- **Formats (6)**: JSON, CSV, HTML (Jinja2: executive/technical/compliance), PDF (Chromium or WeasyPrint), **SARIF 2.1.0** (rules+results, `security-severity`, stable partial-fingerprints), Markdown.
- **CVSS**: full v3.1 base-score formula + v4.0 approximation (vector remap); ~40 default vectors keyed by `vuln_type` (scanner-supplied vectors win).
- **Compliance maps**: OWASP Top-10 2021 (40+ types), PCI-DSS v4.0 (32), NIST CSF (7 + default), MITRE ATT&CK (10 + default). All use `.get(key, default)` so a new `vuln_type` never crashes a report.
- **Evidence**: screenshots base64-embedded; `_safe_output_path()` sanitizes pasted scheme + NTFS-illegal chars; `min_severity` floor; branding logo.

---

## 14. Platform & integrations
- **REST API** (`orthrus serve`, `[api]`): `GET /health`, `/api/scans`, `/api/scans/{id}`, `/api/scans/{id}/findings`, `/api/scans/{id}/report`, plus dark-theme **dashboard** at `/` and `/dashboard/scans/{id}`. All HTML-escaped.
- **MCP server** (`orthrus mcp`, `[mcp]`): FastMCP tools `list_scans`, `get_scan`, `get_findings`, `list_modules` (+ SDK-free data fns).
- **External tools** (`--tools`): `ExternalToolAdapter` ABC + `NucleiAdapter` (`nuclei -jsonl` → `tool-nuclei` findings); scope-checked subprocess; `available_tools()` PATH probe. Native scanners never depend on these.

---

## 15. CLI surface (`orthrus …`)
`scan` (full pipeline, 60+ flags), `recon` (selective), `report` (regenerate from stored scan), `scans` (list), `findings` (triage), `diff` (NEW/FIXED/PERSISTING + `--fail-on-new`), `modules` (inventory + per-module detail), `completion` (bash/zsh/fish), `doctor` (env readiness), `update` (refresh KEV), `serve` (API), `mcp` (MCP), `iac` (IaC scan). Exit codes: `0` success, `2` usage, `3` `--fail-on` breached. `--config file.toml`, `--resume --scan-id`, `--dry-run`, `--target-file` (batch), `--distributed` (Celery/Redis).

---

## 16. Distribution & packaging
- **Extras**: `browser`, `api`, `mcp`, `perf` (uvloop, non-Windows), `scanners` (pyjwt/cryptography/sslyze/paramiko/websockets), `recon` (python-nmap), `reporting` (weasyprint), `distributed` (celery/redis), `postgres` (asyncpg/alembic), `dev`.
- **Entry point**: `orthrus = orthrus.main:cli`.
- **Docker**: python:3.12-slim + nmap + all major extras + Playwright Chromium, `EXPOSE 8000`.
- **GitHub Action** (`action.yml`): composite — install, `orthrus scan … --format sarif`, upload to code-scanning; inputs `target`/`scope`/`fail_on`/`args`/`ref`.
- **CI**: lint + test matrix on Python 3.11/3.12/3.13.

---

## 17. Quality engineering
- **802 tests**, `ruff` clean (E,F,I,UP,B,ASYNC). Pure detector unit tests + duck-typed fakes + real-socket / real-process / real-browser integration checks (raw-socket desync, live JWKS forge, Chromium DOM taint, real gRPC reflection, OOB collaborator).
- **Detection-accuracy benchmark harness** for precision/recall tracking.
- **Low-FP doctrine** enforced by living verification: live testing has caught and fixed real FPs in the project's own new code (subdomain-takeover generic-404, LLM canary reflection) before release.
- **Definition of done** per increment: full pytest + ruff green, a live verification against real sockets/processes/targets, and a local commit.

---

## 18. Security, privacy, legal & ethics
- **Authorized-only**; deny-by-default scope on every egress; DNS-rebinding guard.
- **No secret emission**: confirmers report *whether* auth/forge succeeded, never the credential/key.
- **Evidence-at-rest encryption** (AES-256) when keyed.
- **Non-destructive confirmation** (canaries, OOB, read-only file reads).
- **Private artifacts**: `reports/`, local DBs, and `.claude/` are git-ignored; scan results of third-party/private targets are never published.

---

## 19. Current metrics snapshot (verified)

| Metric | Value |
|---|---|
| Vulnerability scanners | **55** |
| Exploitation-confirmation modules | **17** |
| Reconnaissance modules | **14** |
| Spec formats imported | 5 (OpenAPI/Swagger/GraphQL/HAR/Postman) |
| Report formats | 6 (JSON/CSV/HTML/PDF/SARIF/MD) |
| Compliance frameworks mapped | 4 (OWASP/PCI-DSS/NIST-CSF/MITRE) + CVSS v3.1/v4.0 |
| CISA KEV / EPSS seed | 46 / 21 |
| CLI commands | 13 |
| Automated tests | **802** (ruff clean) |
| Confirmation phase | parallelized (bounded by `concurrency`) |

---

## 20. Roadmap — advanced scanners & methods (to make ORTHRUS more robust)

Prioritized into waves. Each item is a self-contained increment (detector + tests + live-verify + commit), following the existing doctrine (confirm where safely possible; never fake a confirmation).

> **✅ Build-out Wave 1 shipped** (no new core infra — pure detectors, 42→48 scanners, +49 tests): CSP weakness analysis, exposed-secret scanning (redacted), CSV/formula injection, HTTP misconfig (TRACE/XST + dangerous methods), shadow/inventory API (API9), directory-listing/autoindex. See §7.9.
>
> **✅ Build-out Wave 2 shipped** — item #1, the highest-leverage gap: the **N-identity authorization matrix** (`orthrus/core/identity.py` + `scanners/authz_matrix.py`, `--identities` JSON manifest). Autorize-style multi-principal replay over isolated per-identity clients flags **BOLA** (CWE-639) and **BFLA** (CWE-285); live-verified over real sockets. 48→49 scanners, +9 tests. See §7.3.
>
> **✅ Build-out Waves 3+ shipped** (49→55 scanners, 13→15 recon, all live-verified against real targets — see PROOF.md §5):
> - **Privilege-escalation forced-browse** (BFLA on *unlinked* admin routes via the identity lattice) — `privilege_escalation`, CWE-285.
> - **Blind OS command injection via OOB** — `cmd_injection` now mints a callback per point and polls (Interactsh/local collaborator), proving blind RCE (CWE-78).
> - **JWT RS→HS algorithm confusion** — fetches JWKS, derives the RSA public PEM, forges a valid HS256 token from it (raw HMAC) — `jwt_analyzer`, CWE-347.
> - **SAML response inspection** — unsigned assertion / signature-wrapping (XSW) / NameID comment-truncation — `saml`, CWE-347/290 (XXE-safe parsing).
> - **CL.0 request-smuggling desync** — differential raw-socket probe (marker returns as a 2nd response) — `request_smuggling`, CWE-444.
> - **Browser taint engine** — instrumented Chromium source→sink tracing (DOM XSS / client-side redirect, sink named) — `dom_taint`, CWE-79/601.
> - **gRPC server-reflection** exposure — `grpc_probe`, CWE-200 (needs the `grpc` extra).
> - **Source-map recovery** recon — endpoints mined from leaked `.map` originals — `sourcemap_recovery`.
> - **OAuth/OIDC flow misconfig** (missing state/PKCE, implicit flow, redirect_uri takeover) — `oauth_flow`.
> - **GraphQL circular-fragment** recursion DoS, **mixed-content**, and the Wave-1 detector batch (CSP, secrets, CSV-injection, API-misconfig, shadow-API, directory-listing).
>
> **What genuinely remains** (and why it isn't shipped): **tenant-isolation** is effectively covered by the authz-matrix (which replays a tenant's object URL under another identity); **step-up-auth bypass** is intentionally deferred as too false-positive-prone to do at low FP without app-specific knowledge; **gRPC field-level fuzzing** (beyond reflection) and **HTTP/2 binary smuggling** are larger transport builds; and the **method** items below (ML-assisted anomaly/param discovery, grammar/mutation fuzzing, a reusable differential engine) are research-grade rather than discrete scanners. The list below is retained as the forward backlog.

### Wave A — Authenticated & multi-identity testing (highest impact)
1. **Two-identity BOLA/IDOR** — drive the scan with *two* authenticated sessions; confirm true cross-tenant object access (not just enumeration). Requires a session-pool abstraction in `ScanContext`.
2. **Authenticated crawl depth** — persist the auth session into browser-crawl/spa-crawl so the post-login app surface is fully discovered.
3. **Function-level authz (BFLA)** — replay privileged endpoints with a low-priv session; confirm missing function-level checks.
4. **Workflow/state-machine probes** — sequence-aware business logic (cart→checkout→pay skips, coupon re-use, negative quantity end-to-end).

### Wave B — Deeper injection & OOB everywhere
5. **Blind SQLi/cmd via OOB** — DNS/HTTP exfil through the Interactsh collaborator (today's blind cases stay firm).
6. **Deserialization OOB confirmation** — language-specific *safe* gadget probes (ysoserial-style URLDNS / DNS-only) to upgrade deserialization from detection-only to confirmed where a callback fires.
7. **SSRF advanced** — DNS-rebinding, gopher/dict/file scheme probes, cloud-metadata IMDSv2 header variants, 169.254.169.254 alternates, redirect-based SSRF.
8. **Header/SMTP/template injection breadth** — host-header cache-poisoning end-to-end, email-header injection, ESI injection, expression-language (Spring SpEL / OGNL) detection.
9. **Prototype-pollution gadget scanning** — client-side gadget chains (DOM clobbering, script-src sink) and server-side pollution-to-RCE gadget probing.

### Wave C — Modern protocols & transport
10. **HTTP/2 & H2C smuggling, CL.0 / TE.0** — extend the raw-socket desync engine to H2 downgrade and CL.0 variants; front/back-end differential where a proxy is present.
11. **gRPC / Protobuf** — reflection-based service discovery + field fuzzing.
12. **WebSocket message fuzzing** — beyond handshake: message-level injection (CSWSH end-to-end, message tampering).
13. **GraphQL deep auth** — mutation abuse, field-level authz, persisted-query bypass, cost-analysis confirmation.

### Wave D — Identity, tokens & crypto
14. **JWT alg-confusion (RS→HS)** — fetch the server's public key (or JWKS), sign an HS256 token with it, confirm acceptance on a protected endpoint.
15. **OAuth/OIDC/SAML flow attacks** — redirect_uri manipulation, state/PKCE absence, token leakage, SAML signature-wrapping detection.
16. **Session fixation / rotation** — confirm session ID survives privilege change.

### Wave E — Race, cache & client-side
17. **Single-packet race attack** — HTTP/2 single-packet technique for sub-millisecond race windows (limit-overrun confirmation).
18. **Advanced cache poisoning** — parameter cloaking, fat-GET, cache-key normalization, header-reflection chains with cache-buster confirmation.
19. **postMessage / web-messaging** — origin-check bypass, DOM-clobbering, client-side path traversal via browser instrumentation.
20. **CSP analysis & bypass** — parse CSP, flag `unsafe-inline`/wildcard/JSONP-endpoint bypasses, nonce reuse.

### Wave F — Supply chain, secrets & cloud
21. **Secret scanning** across responses/JS/source maps (entropy + provider regexes) with verification (live key validation where safe).
22. **SBOM & dependency confusion** — parse lockfiles, flag internal-package namesquatting risk; OSV API enrichment.
23. **Source-map recovery** — reconstruct original source from `.map` to mine endpoints/secrets/logic.
24. **Live cloud posture** — optional read-only cloud API checks (S3 ACLs, IAM exposure) given operator-supplied credentials.
25. **Container image scanning** — analyze a pulled image's layers for known-vuln packages + secrets.

### Wave G — Intelligence & method upgrades (cross-cutting)
26. **ML-assisted anomaly/parameter discovery** — learn per-endpoint response baselines; flag statistically anomalous responses; rank likely-injectable params.
27. **Grammar/mutation fuzzing** — payload grammars per context (SQL/JS/template) with feedback-guided mutation instead of fixed lists.
28. **Differential & baseline learning everywhere** — generalize the SSPP/IDOR differential pattern into a reusable "clean-vs-perturbed" engine for all reflection-prone classes.
29. **Smarter dedup & severity calibration** — cluster near-duplicate findings; calibrate severity from confirmed exploitability + KEV/EPSS.
30. **Distributed scale-out** — mature the Celery/Redis path for fleet-scale authorized scanning with shared scope + result aggregation.
31. **Crawl intelligence** — form-filling heuristics, auth-aware state graph, sitemap/robots ingestion, GraphQL/OpenAPI-driven targeted fuzzing.

**Sequencing rationale:** Wave A unlocks the *majority* of high-impact real-world bugs (they live behind auth), so it is the top priority; Waves B–E deepen active confirmation; Waves F–G broaden coverage and raise signal quality.

---

## 21. Appendix A — `vuln_type` → primary CWE / OWASP (master lookup)

| vuln_type | CWE | OWASP 2021 |
|---|---|---|
| sqli | CWE-89 | A03 Injection |
| xss | CWE-79 | A03 Injection |
| cmd-injection | CWE-78 | A03 Injection |
| ssti | CWE-1336 | A03 Injection |
| nosql-injection | CWE-943 | A03 Injection |
| crlf-injection | CWE-113 | A03 Injection |
| lfi | CWE-22 | A03 Injection |
| host-header-injection | CWE-644 | A03 Injection |
| xxe | CWE-611 | A05 Misconfiguration |
| ssrf | CWE-918 | A10 SSRF |
| idor | CWE-639 | A01 Broken Access Control |
| csrf | CWE-352 | A01 Broken Access Control |
| open-redirect | CWE-601 | A01 Broken Access Control |
| mass-assignment | CWE-915 | A08 Integrity Failures |
| auth-session | CWE-614/1004/1275 | A07 Auth Failures |
| jwt | CWE-347 | A07 Auth Failures |
| default-creds | CWE-1392 | A07 Auth Failures |
| deserialization | CWE-502 | A08 Integrity Failures |
| prototype-pollution | CWE-1321 | A08 Integrity Failures |
| tls | CWE-327 | A02 Cryptographic Failures |
| security-headers | CWE-693 | A05 Misconfiguration |
| cors | CWE-942 | A05 Misconfiguration |
| cache-poisoning | CWE-444 | A05 Misconfiguration |
| web-cache-deception | CWE-525 | A05 Misconfiguration |
| framework-debug | CWE-200/489 | A05 Misconfiguration |
| exposed-file | CWE-538 | A05 Misconfiguration |
| subdomain-takeover | CWE-350 | A05 Misconfiguration |
| graphql | CWE-200 | A05 Misconfiguration |
| graphql-dos | CWE-770 | A05 Misconfiguration |
| websocket | CWE-1385 | A05 Misconfiguration |
| request-smuggling | CWE-444 | A03 Injection |
| vulnerable-component | CWE-1104/79/1321 | A06 Vulnerable Components |
| cve | (per-CVE) | A06 Vulnerable Components |
| exposed-service | CWE-306 | A07 Auth Failures |
| business-logic | CWE-472 | A04 Insecure Design |
| parameter-pollution | CWE-235 | A03 Injection |
| race-condition | CWE-362 | A04 Insecure Design |
| prompt-injection | CWE-1427 | A03 Injection |
| llm-info-disclosure | CWE-200 | A04 Insecure Design |
| iac-misconfig | CWE-250/284/798/… | A05 Misconfiguration |

## 22. Appendix B — repository layout (abridged)

```
orthrus/
  core/        orchestrator, config, schemas, context, auth, callback,
               browser, baseline, events, http client
  utils/       scope (deny-by-default), encoding, logger, crypto
  recon/       14 modules + spec_parsers + registry
  scanners/    55 scanners + base + registry + _injection + _evasion
  exploits/    17 confirmation modules + base + registry + _replay
  intel/       cve_intel + CISA-KEV/EPSS seeds
  templates/   declarative engine (schema/matchers/loader/scanner) + builtin
  iac/         Dockerfile/compose/Terraform analyzer
  reporting/   generator (6 formats) + cvss (v3.1/v4.0) + compliance maps + templates
  integrations/ ExternalToolAdapter + nuclei
  api/         FastAPI REST + dashboard
  db/          SQLAlchemy async store + models (encrypted evidence)
  mcp_server.py  FastMCP tools
  main.py      Click CLI (13 commands)
docs/          README, PROOF.md, this PRD, screenshot
tests/         unit + integration (802 tests)
.github/       CI matrix + reusable scan action
docker/        Dockerfile (all extras + Chromium)
```

---

*End of PRD. This document tracks the implemented system; update §19 metrics and §20 roadmap as increments land.*
