# Project ORTHRUS

**Automated vulnerability discovery & exploitation-confirmation framework for authorized security testing.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![Use](https://img.shields.io/badge/use-authorized%20testing%20only-red.svg)](#-legal--ethical-use)
[![Open in Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/ankitjha67/orthrus/blob/main/examples/orthrus_colab.ipynb)

ORTHRUS crawls a target, fingerprints its stack, runs 56 vulnerability scanners,
and then **re-proves** the interesting findings with a dedicated
exploitation-confirmation phase — so a report distinguishes "this looks
vulnerable" (tentative) from "this was demonstrably exploited" (confirmed). It
produces JSON / CSV / HTML / PDF / SARIF / Markdown reports with CVSS v3.1 + v4.0
scoring and OWASP / CWE / PCI-DSS / NIST-CSF / MITRE ATT&CK mappings.

![Orthrus terminal output: the banner, the AUTHORIZED SCOPE panel, the scan summary, OWASP Top-10 coverage, and the colour-coded findings table](docs/screenshot.png)

<sub>A real scan of the bundled, 127.0.0.1-only practice target. Regenerate this view from any JSON report with [`examples/render_report_ui.py`](examples/render_report_ui.py).</sub>

📊 **Proof it works on real targets:** [`docs/PROOF.md`](docs/PROOF.md) records
reproducible live findings against an authorized range (DVGA GraphQL, an Oracle
WebLogic console matched to 7 CISA-KEV CVEs, unauthenticated Redis) plus the
870-test / lint-clean quality gates.

📐 **Full system spec:** [`docs/PRD.md`](docs/PRD.md) — the granular,
implemented-system PRD: every subsystem (56 scanners, 17 confirmers, 16 recon
modules), the data/config/scope/store models, the confirmation doctrine, and the
roadmap for advanced scanners & methods.

---

> ## ⚠️ Legal & Ethical Use — read before running anything
>
> **ORTHRUS is an offensive security tool. It sends real attack payloads and, in
> its confirmation phase, actively attempts to exploit findings.**
>
> - ✅ Use it **only** against systems you **own**, or for which you hold
>   **explicit, written authorization** to test (a signed engagement / scope
>   document, bug-bounty program rules, or your own lab).
> - ❌ Scanning, exploiting, or accessing systems without permission is
>   **illegal** in most jurisdictions (e.g. the U.S. CFAA, the UK Computer
>   Misuse Act, the EU directive on attacks against information systems) and can
>   result in criminal prosecution and civil liability.
> - 🧭 **You** are solely responsible for how you use this software and for
>   staying within the bounds of your authorization and local law.
> - 🚫 The authors and contributors provide this tool **as-is, with no warranty**,
>   and accept **no liability** for misuse or for any damage it causes.
>
> If you do not have written permission to test a target, **do not point ORTHRUS
> at it.** Use the bundled deliberately-vulnerable practice target or a
> self-hosted lab instead (see [Try it safely](#-try-it-safely)).
>
> As a guardrail, ORTHRUS is **deny-by-default**: every outbound request is
> validated against your declared engagement scope before it is sent, and the
> resolved scope is printed at the start of every run. This is a safety aid, **not**
> a substitute for authorization. See [Scope enforcement](#-scope-enforcement-the-safety-boundary).

---

## Table of contents

- [Features](#-features)
- [How it works](#-how-it-works)
- [Scope enforcement](#-scope-enforcement-the-safety-boundary)
- [Requirements](#-requirements)
- [Installation](#-installation)
- [Run in VS Code or Google Colab](#-run-in-vs-code-or-google-colab)
- [Quickstart](#-quickstart)
- [Try it safely](#-try-it-safely)
- [Usage guide](#-usage-guide)
- [Configuration](#-configuration)
- [Reporting](#-reporting)
- [Production: PostgreSQL & distributed scanning](#-production-postgresql--distributed-scanning)
- [Architecture & project layout](#-architecture--project-layout)
- [Extending ORTHRUS (plugins)](#-extending-orthrus-plugins)
- [Development](#-development)
- [Legal & Ethical Use](#-legal--ethical-use)
- [Contributing](#-contributing)
- [License](#-license)

---

## ✨ Features

**Reconnaissance (14 modules)**
- Scope-aware web crawler, passive technology fingerprinting
- Headless-browser (dynamic) crawl + SPA client-side route discovery — captures JS-rendered XHR/fetch endpoints
- Parameter mining (Arjun-style hidden-parameter discovery)
- JavaScript analysis (endpoint + secret extraction), **source-map recovery** (recover endpoints from leaked `.map` files), content discovery
- Subdomain enumeration, DNS enumeration (+ AXFR attempt), WAF detection
- REST/GraphQL API discovery, Wayback Machine historical URLs
- Nmap port scan (optional; needs the `nmap` binary)

**Vulnerability scanners (55)**

| Category | Scanners |
|---|---|
| Injection | SQLi (error / boolean / time-based, WAF-evasion), command injection, SSTI, LFI, XXE, NoSQL, CRLF / response splitting, HTTP request smuggling (CL.TE/TE.CL + **CL.0 desync**), CSV / formula injection |
| XSS | Reflected (content-type aware), DOM-based, stored (browser-verified), **browser taint engine** (instrumented source→sink: URL data reaching eval/innerHTML/document.write = DOM XSS, location.assign/window.open = client-side redirect) |
| Access / logic | IDOR, **multi-identity authorization matrix (BOLA/BFLA, Autorize-style `--identities`)**, **privilege-escalation forced-browse (unlinked admin routes via the identity lattice)**, CSRF, open redirect, race conditions, business-logic (parameter tampering / HPP), host-header injection (password-reset poisoning) |
| API (OWASP API Top 10) | Mass assignment / object-property injection |
| Auth / session | Auth-session analysis, default credentials, JWT (alg:none, weak secret, jku/x5u/kid header attacks, **RS->HS algorithm confusion** via published JWKS), **OAuth/OIDC flow misconfig (missing state/PKCE, implicit flow, redirect_uri takeover)**, **SAML response inspection (unsigned assertion, signature-wrapping, NameID comment-truncation)** |
| Server-side | SSRF (out-of-band + metadata), **OS command injection (output / time / OOB-callback blind RCE)**, deserialization, prototype pollution (client- & server-side) |
| Config / transport | Security headers, **CSP weakness analysis**, **mixed-content / insecure-transport refs**, CORS, TLS analysis, exposed files, **directory-listing / autoindex**, cache poisoning, web cache deception, framework debug-exposure, unrestricted file upload, subdomain takeover, **HTTP misconfig (TRACE/XST, dangerous methods)** |
| Protocol / API | GraphQL (introspection, field-suggestion leakage, query batching + alias-overloading + circular-fragment DoS, debug/stack-trace disclosure — DVGA-grade), WebSocket, **gRPC server-reflection exposure**, **shadow / improper-inventory API (API9)** |
| Secrets | **Exposed-secret scanner** — AWS/Google/Slack/Stripe/GitHub keys + private-key blocks in responses/JS (redacted) |
| Supply chain | SCA — known-vulnerable JS libraries (retire.js-style) |
| Templates | Declarative Nuclei-style YAML/JSON template engine (`--templates`) |
| Intelligence | CVE matcher (version → known-CVE) **plus** version-less product fingerprinting (WebLogic, Confluence, Jenkins, Solr → known-exploited CVEs), all enriched with CISA KEV + EPSS (`orthrus update`) |
| AI / LLM | Prompt injection + system-prompt / sensitive-info disclosure (OWASP LLM Top 10) |
| Services / infra | Unauthenticated service exposure (Redis, Memcached) via native protocol probes |

Active injection scanners share a **WAF-evasion encoder library** (URL / double-URL /
mixed-case / comment-spacing / HTML-entity / unicode); transport-surviving
variants are tried automatically under `--aggressive`.

**Exploitation confirmation (17 modules)** — re-proves findings to upgrade their
confidence to `confirmed`:

- **Injection** — SQLi, command injection, SSTI, LFI, XXE, **NoSQL** (driver-error replay)
- **XSS** — browser-executed by default when Playwright is present (window-flag/dialog + screenshot)
- **Redirect / headers** — open redirect, **CRLF / response splitting** (fresh-nonce header survives), **host-header injection** (a freshly-forged attacker host re-reflected into links/redirects)
- **Access / objects** — **IDOR** (sequential object enumeration reproduced: adjacent IDs resolve, an implausible ID does not), **mass assignment** (a fresh per-field nonce re-bound into the response object)
- **Cross-origin / tokens** — **CORS** (arbitrary-origin reflection re-proven with a freshly-minted attacker origin), **JWT** (a weak HMAC secret is recovered and used to forge a validly-signed token — the secret is never emitted)
- **JS-runtime / DoS** — **server-side prototype pollution** (a fresh `__proto__` sentinel re-persists onto a new object via a clean-before/polluted-after differential), **GraphQL DoS** (query-batching and alias-overloading amplification re-issued and re-observed)
- **Out-of-band** — SSRF (collaborator callback)

Confirmation works on query-string **and** POST/JSON body parameters and runs
**concurrently** (bounded by `concurrency`) so WAN round-trips overlap instead of
summing.

It deliberately covers the *actively-exploitable* classes. Findings already
definitively proven by observation (missing security headers, deprecated TLS,
known-CVE product exposure, banner disclosure, exposed services, request
smuggling, GraphQL introspection) ship as `firm`/`confirmed` from detection
itself. A few classes are intentionally **detection-only** because no *safe*,
generic automated exploit exists — most notably **insecure deserialization**
(a passive serialized-blob signature; proving RCE needs a target-specific gadget
chain) — so ORTHRUS reports them rather than inventing a misleading confirmation.

**Reporting**
- Formats: **JSON, CSV, HTML, PDF, SARIF, Markdown**
- Templates: **executive**, **technical**, **compliance**
- **CVSS v3.1 + v4.0** scoring; **OWASP Top 10 / CWE / PCI-DSS / NIST-CSF / MITRE ATT&CK** mappings
- Severity filtering, logo branding, embedded screenshots & raw request/response evidence

**Platform**
- Async core (`httpx`, HTTP/2), per-host token-bucket rate limiting, User-Agent rotation
- Headless-browser engine (Playwright/Chromium) for DOM/stored XSS & JS-rendered crawling
- Out-of-band callback server (local listener) for blind SSRF/RCE detection
- Pluggable scanner/exploit/recon/reporter modules auto-discovered at startup
- SQLite (dev) or **PostgreSQL** (+ Alembic migrations); optional **distributed** scanning via Celery/Redis
- OpSec: AES-256-GCM evidence-at-rest encryption, operator audit log, HAR export

**Platform & integrations**
- **REST API** (`orthrus serve`, FastAPI) with auto Swagger docs at `/docs`, plus a served **web dashboard**
- **MCP server** (`orthrus mcp`) exposing scans/findings as tools for AI agents
- **External-tool orchestration** (`--tools nuclei`) — runs best-of-breed CLIs and normalizes their output into ORTHRUS findings
- **IaC misconfiguration audit** (`orthrus iac`) — Dockerfile / docker-compose / Terraform, fully offline

## 🔁 How it works

ORTHRUS runs a four-phase pipeline. Every network request — in every phase — goes
through the scope-enforced HTTP client.

```mermaid
flowchart LR
    A[Target + Scope] --> B[Recon]
    B --> C[Scan]
    C --> D[Exploit / Confirm]
    D --> E[Report]
    B -. assets & endpoints .-> DB[(Findings DB)]
    C -. findings .-> DB
    D -. confirmations .-> DB
    DB --> E
    subgraph guard [Scope-enforced HTTP client deny-by-default]
        B
        C
        D
    end
```

1. **Recon** — discover hosts, endpoints, parameters, and technology.
2. **Scan** — run the selected scanners against discovered injection points;
   emit findings with a confidence of `tentative`/`firm`.
3. **Exploit / Confirm** — re-issue a controlled payload (and, for XSS, execute
   it in a real browser; for SSRF, await an out-of-band callback) to upgrade
   proven findings to `confirmed`.
4. **Report** — render the findings (with CVSS, compliance mappings, and
   evidence) to your chosen format.

## 🛡️ Scope enforcement (the safety boundary)

`orthrus.utils.scope.ScopeValidator` is the load-bearing safety control. It is
**deny-by-default**: a host / port / path is only contacted if your
`ScopeConfig` explicitly authorizes it. `orthrus.core.http_client.HttpClient`
consults it **before every request** and **re-validates every redirect hop**, and
the headless browser is bound by the same check. Scanner modules must use
`HttpClient` rather than raw `httpx`, so the boundary cannot be bypassed.

The resolved scope is printed at the start of every run so you can confirm the
engagement boundary before any traffic leaves your machine:

```text
Authorized scope - domains=['*.target.com'] ip_ranges=['10.0.0.0/24'] ports=[80, 443] exclude=['/admin/delete/.*']
```

`--scope auto` derives a minimal scope from the target host; **real engagements
should always pass an explicit `--scope`.**

## 📋 Requirements

- **Python 3.11+** (developed on 3.14, Windows 11)
- The "lean core" dependencies are pure-Python / wheels and install on Windows
  with no external binaries. Heavier integrations are opt-in extras.

## 📦 Installation

```bash
git clone https://github.com/ankitjha67/orthrus.git
cd orthrus

python -m venv .venv
# Windows:  .\.venv\Scripts\Activate.ps1
# Linux/macOS:  source .venv/bin/activate

pip install -e .
```

Optional dependency groups:

```bash
pip install -e ".[browser]"      # Playwright headless browser (DOM/stored XSS, PDF)
pip install -e ".[scanners]"     # pyjwt, cryptography, sslyze, paramiko, websockets
pip install -e ".[recon]"        # python-nmap (needs the nmap binary too)
pip install -e ".[reporting]"    # weasyprint (alt PDF backend; default PDF uses [browser])
pip install -e ".[postgres]"     # asyncpg + alembic
pip install -e ".[distributed]"  # celery + redis
pip install -e ".[dev]"          # pytest, ruff, mypy

# After installing [browser], download the Chromium runtime once:
playwright install chromium
```

> The **jwt** and **tls** scanners need `[scanners]`; **dom-xss** / **stored-xss**
> and XSS confirmation need `[browser]` + `playwright install chromium`. Each
> module self-disables cleanly if its extra is missing — the lean core still runs
> everything else.

## 💻 Run in VS Code or Google Colab

Prefer a guided, copy-paste setup? Two detailed step-by-step walkthroughs live in
**[docs/USAGE_VSCODE_COLAB.md](docs/USAGE_VSCODE_COLAB.md)**:

- **VS Code** — virtual-environment setup, recommended extensions, running the
  bundled practice target, breakpoint debugging (`launch.json`), and the
  test/lint workflow.
- **Google Colab** — zero local install, all in the browser. Open the
  ready-to-run notebook and choose **Runtime → Run all**:
  [![Open in Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/ankitjha67/orthrus/blob/main/examples/orthrus_colab.ipynb)

## 🚀 Quickstart

```bash
# Recon only, scope auto-derived from the target
orthrus recon -t https://example.com --crawl-depth 3

# Full pipeline (recon → scan → confirm → report) → JSON
orthrus scan -t https://example.com -o report.json

# See every option
orthrus --help
orthrus scan --help
```

## 🧪 Try it safely

Do not learn the tool on someone else's systems. Use one of these **authorized**
targets:

- **Bundled practice target.** This repo ships a deliberately-vulnerable app at
  `tests/integration/reflecting_target.py` that exercises every scanner locally:

  ```bash
  python tests/integration/reflecting_target.py 8731     # terminal 1
  orthrus scan -t http://127.0.0.1:8731 --aggressive -o report.json   # terminal 2
  ```

- **Self-hosted labs** (you own the instance): OWASP Juice Shop, DVWA, OWASP
  WebGoat, bWAPP, OWASP Mutillidae II.
- **Vendor-sanctioned public test sites** that explicitly permit scanning:
  `testphp.vulnweb.com`, `testasp.vulnweb.com`, `rest.vulnweb.com` (Acunetix),
  `demo.testfire.net` (IBM), `ginandjuice.shop` (PortSwigger).

> ⚠️ Public exploit/CVE databases (e.g. Exploit-DB) catalog *vulnerabilities*,
> **not authorized targets**. Never point ORTHRUS at a live system you found
> listed somewhere; that is unauthorized access.

## 📖 Usage guide

ORTHRUS's core sub-commands are `recon`, `scan`, `exploit`, and `report`, plus
utility commands: `doctor` (environment readiness), `modules` (module inventory),
`findings` (terminal triage view), `diff` (compare two scans), `scans` (list past
scans), `benchmark` (detection-accuracy harness), `update` (refresh CISA-KEV
intel), `serve` (REST API + dashboard), `mcp` (MCP server for AI agents), `iac`
(Infrastructure-as-Code audit), and `completion` (shell completion). Run
`orthrus --help` for the full list.

### `orthrus scan` — the full pipeline

```bash
# Explicit engagement scope (wildcard domains + CIDR), exclude sensitive paths
orthrus scan -t https://app.target.com \
  --scope "*.target.com,api.target.com,10.0.0.0/24" \
  --exclude-paths "/admin/delete/.*,/api/v1/payments" \
  -o report.html --format html --template technical

# Run only specific scanner modules
orthrus scan -t https://app.target.com --modules sqli,xss,ssti,ssrf -o report.json

# Aggressive mode also enables time-based blind tests (SQLi/cmd) and race conditions
orthrus scan -t https://app.target.com --aggressive -o report.json

# Authenticated scan (re-use a captured session cookie + extra headers)
orthrus scan -t https://app.target.com \
  --auth-cookie "session=abc123; csrf=def456" \
  --headers '{"Authorization": "Bearer eyJ..."}' \
  -o report.json

# Route through a proxy (e.g. Burp), cap the request rate, raise the timeout
orthrus scan -t https://app.target.com --proxy http://127.0.0.1:8080 --rate-limit 10 --timeout 45

# Skip the confirmation phase (also disables the OOB callback server)
orthrus scan -t https://example.com --no-exploit -o report.json

# Disable the headless browser (skips DOM/stored XSS + browser confirmation)
orthrus scan -t https://example.com --no-browser -o report.json
```

Common `scan` options: `--modules`, `--aggressive`, `--rate-limit`,
`--crawl-depth`, `--max-pages`, `--timeout`, `--proxy`, `--auth-cookie`,
`--user-agent`, `--callback`, `--no-exploit`, `--browser/--no-browser`,
`--exclude-paths`, `--headers`, `--threads`, `--scan-id`, `-o/--output`,
`--format`, `--template`, `--min-severity`, `--logo`, `--har`, `-v/--verbose`.

### Full end-to-end scan of a site you own (recommended workflow)

`orthrus scan` runs all four phases — recon → scan → exploit-confirm → report — in
a single command, and writes the report when you pass `-o` + `--format`. With the
`[browser]` extra installed, DOM/stored-XSS and JS-rendered crawling are included
automatically. A safe, live-site-friendly flow for **a site you own or are
explicitly authorized to test**:

```bash
# 1) Preview the engagement scope + plan — sends NO traffic
orthrus scan -t https://yoursite.com --scope "yoursite.com,*.yoursite.com" --dry-run

# 2) Run the full pipeline with gentle settings → technical HTML report
orthrus scan -t https://yoursite.com \
  --scope "yoursite.com,*.yoursite.com" \
  --rate-limit 10 \
  --crawl-depth 3 --max-pages 200 \
  --exclude-paths "/logout,/admin/delete/.*" \
  -o reports/yoursite.html --format html --template technical

# 3) Export more formats from the SAME stored scan (no re-scan needed)
orthrus scans                                                          # list scans, copy the id
orthrus report --scan-id <id> --format pdf   --template executive -o reports/yoursite_exec
orthrus report --scan-id <id> --format sarif -o reports/yoursite     # CI / code-scanning
orthrus report --scan-id <id> --format json  -o reports/yoursite     # machine-readable
```

Tune it for your target:
- **Deeper testing** (more load — use deliberately, ideally on staging): add
  `--aggressive` for time-based blind SQLi/command tests and race-condition probes.
- **Authenticated areas**: add `--auth-cookie "session=…; csrf=…"` (copy a logged-in
  cookie from your browser's dev tools), or drive a login with `--login-url` and the
  related flags (`orthrus scan --help`).
- **Watch every request**: route through Burp/ZAP with `--proxy http://127.0.0.1:8080`.
- **Gate CI**: add `--fail-on high` to exit non-zero when a high-or-worse finding appears.

> Only scan hosts you **own** or hold **written authorization** for, and keep
> `--scope` tight (deny-by-default — only listed hosts are contacted). On shared
> hosting, check your provider's policy before active scanning.

### `orthrus recon` — reconnaissance only

```bash
# All recon modules (fingerprint, crawl, JS, content, WAF, API, DNS)
orthrus recon -t https://example.com -o recon.json

# Turn modules on/off; add subdomain enum (needs a *.domain scope) and Wayback
orthrus recon -t https://target.com --scope "*.target.com" \
  --subdomains --wayback --no-content --crawl-depth 5
```

### `orthrus report` — render an existing scan

```bash
# Reports are generated from the stored scan; pick format + template
orthrus report --scan-id scan-abcd1234 --format pdf --template executive -o exec_report
orthrus report --scan-id scan-abcd1234 --format csv -o findings
orthrus report --scan-id scan-abcd1234 --format html --template compliance --min-severity high -o audit
```

### `orthrus exploit`

```bash
orthrus exploit --scan-id scan-abcd1234
```

> Note: confirmation runs automatically during `orthrus scan`. Standalone
> replay-from-DB is not yet implemented — re-run the scan to (re-)confirm.

## ⚙️ Configuration

Runtime settings are read from environment variables (prefix `ORTHRUS_`) or a
`.env` file. None are required for a basic SQLite run.

| Variable | Purpose | Default |
|---|---|---|
| `ORTHRUS_DB_URL` | Database URL (SQLite or PostgreSQL) | `sqlite+aiosqlite:///./orthrus.sqlite3` |
| `ORTHRUS_DATA_DIR` | Screenshots / scan artifacts directory | `./scan_data` |
| `ORTHRUS_LOG_LEVEL` | Default log level | `info` |
| `ORTHRUS_ENCRYPTION_KEY` | base64 AES-256 key; encrypts sensitive evidence at rest | _(off)_ |
| `ORTHRUS_REDIS_URL` | Celery broker/backend (distributed mode) | `redis://localhost:6379/0` |
| `ORTHRUS_PLUGINS_DIR` | External plugin directory auto-loaded at startup | _(none)_ |
| `ORTHRUS_SHODAN_API_KEY`, `ORTHRUS_CENSYS_API_ID`/`_SECRET`, `ORTHRUS_VIRUSTOTAL_API_KEY`, `ORTHRUS_NVD_API_KEY`, `ORTHRUS_GITHUB_TOKEN` | Optional passive-recon / CVE-intel credentials | _(none)_ |

```bash
# Example: PostgreSQL + at-rest encryption
export ORTHRUS_DB_URL="postgresql+asyncpg://orthrus:orthrus@localhost:5432/orthrus"
export ORTHRUS_ENCRYPTION_KEY="$(python -c 'import base64,os;print(base64.b64encode(os.urandom(32)).decode())')"
```

## 📑 Reporting

- **JSON** — full structured output (every field, evidence, exploitation results).
- **CSV** — one row per finding (severity, confidence, CVSS, type, URL, parameter,
  param location, CWE, OWASP) for spreadsheets/triage.
- **HTML** — styled report; `technical` includes raw request/response evidence and
  screenshots, `executive` is a summary, `compliance` emphasises framework mappings.
- **PDF** — the HTML report rendered to PDF via headless Chromium (needs `[browser]`).
- **SARIF** — Static Analysis Results Interchange Format for CI / code-scanning
  dashboards (e.g. GitHub code scanning); pair with `--fail-on` to gate a pipeline.
- **Markdown** — portable plain-text report for tickets, pull requests, and wikis.

Every finding carries CVSS v3.1 + v4.0 vectors/scores and is mapped to OWASP Top
10, CWE, PCI-DSS, NIST-CSF, and MITRE ATT&CK.

**Share the terminal view.** `examples/render_report_ui.py` renders any JSON
report into the themed terminal UI (banner, scope panel, summary, OWASP coverage,
findings table) and exports an **SVG + HTML** frame (and a **PNG** when the
`[browser]` extra is installed) — useful for docs, slides, and tickets:

```bash
orthrus scan -t http://127.0.0.1:8731 -o report.json
python examples/render_report_ui.py report.json -o out/scan
# → out/scan.svg, out/scan.html, out/scan.png
```

## 🏭 Production: PostgreSQL & distributed scanning

```bash
# PostgreSQL backend (needs [postgres]: asyncpg + alembic)
export ORTHRUS_DB_URL="postgresql+asyncpg://orthrus:orthrus@localhost:5432/orthrus"
alembic upgrade head

# Distributed scanning across Celery workers (needs [distributed] + Redis)
celery -A orthrus.distributed.celery_app worker --loglevel=info
orthrus scan --distributed --workers 4 --redis redis://localhost:6379/0 -t targets.txt

# Or bring up the whole stack (app + workers + redis + postgres) with Docker
docker compose -f docker/docker-compose.yml up -d --build
docker compose -f docker/docker-compose.yml run --rm app scan -t https://example.com
```

> Distributed out-of-band detection needs a shared, externally-reachable callback
> server (e.g. Interactsh); the built-in local listener only serves same-host targets.

## 🧱 Architecture & project layout

```
orthrus/
  core/        config, scope-enforced HTTP client, browser engine, callback server, orchestrator, schemas
  recon/       crawler, dynamic/SPA crawl, param-mining, fingerprint, JS analyzer, source-map recovery, content discovery, subdomain/DNS enum, WAF, API, wayback, ports
  scanners/    56 scanners + base interface + registry
  exploits/    17 confirmation modules + base interface + registry
  integrations/ external-tool adapters (nuclei, ...) normalized into findings
  intel/       CVE threat-intel enrichment (CISA KEV + EPSS)
  iac/         Infrastructure-as-Code misconfig analyzer (Dockerfile/compose/Terraform)
  api/         FastAPI REST API + web dashboard;  mcp_server.py = MCP server
  reporting/   JSON/CSV/HTML/PDF/SARIF/Markdown generator, CVSS engine, Jinja2 templates
  db/          SQLAlchemy 2.0 models, async store, Alembic migrations
  distributed/ Celery app, tasks, target dispatcher
  utils/       logger, scope validator, rate limiter, encoding
  main.py      Click CLI entry point
docker/        Dockerfile + docker-compose (app, workers, redis, postgres)
examples/      render_report_ui.py (report → themed SVG/HTML/PNG) + a sample report
docs/          screenshots and supporting images
tests/         unit tests + a bundled deliberately-vulnerable integration target
```

## 🔌 Extending ORTHRUS (plugins)

Scanners, exploits, recon modules, and reporters are auto-discovered via
decorators. Drop a module that subclasses the relevant base class and registers
itself into `ORTHRUS_PLUGINS_DIR` (or the in-tree package) and it joins the
pipeline — no core changes needed. A new scanner is roughly:

```python
from orthrus.scanners.base_scanner import BaseScanner
from orthrus.scanners.registry import register

@register
class MyScanner(BaseScanner):
    name = "my-scanner"
    vuln_type = "my-vuln"

    async def scan(self, ctx):
        # use ctx.http (scope-enforced) only; yield Finding(...) objects
        ...
```

## 🧰 Development

```bash
pip install -e ".[dev]"
ruff check orthrus tests
mypy orthrus
pytest -q
```

The suite is offline and deterministic (unit tests + a bundled vulnerable target);
it does not touch the network or any external host.

## ⚖️ Legal & Ethical Use

This software is provided for **authorized security testing, education, and
research only.**

- Only use ORTHRUS against systems you **own** or are **explicitly authorized in
  writing** to test. Keep a copy of that authorization.
- Define an accurate `--scope` and respect it. Scope enforcement is a safety aid,
  not legal cover.
- Running active scanners/exploits against systems without permission may violate
  computer-misuse laws (CFAA, UK CMA, EU 2013/40, and equivalents) and can lead to
  **criminal and civil liability**.
- The software is provided **"AS IS", without warranty of any kind**. The authors
  and contributors are **not liable** for any misuse, damage, data loss, or legal
  consequence arising from its use.
- By using ORTHRUS you accept full responsibility for your actions and confirm you
  have the authorization required for every target you test.

**If in doubt, don't.** Practice on the bundled target or a self-hosted lab.

## 🤝 Contributing

Issues and pull requests are welcome. Please keep changes scope-safe (all network
access must go through `HttpClient`), add tests for new scanners/exploits, and run
`ruff` + `pytest` before submitting.

## 📄 License

[MIT](LICENSE) © 2026 Ankit Jha. See the additional **authorized-use notice** in
the LICENSE file and the [Legal & Ethical Use](#-legal--ethical-use) section above.
