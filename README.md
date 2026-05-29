# Project HYDRA

**Automated vulnerability discovery & exploitation-confirmation framework for authorized security testing.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![Use](https://img.shields.io/badge/use-authorized%20testing%20only-red.svg)](#-legal--ethical-use)

HYDRA crawls a target, fingerprints its stack, runs 26 vulnerability scanners,
and then **re-proves** the interesting findings with a dedicated
exploitation-confirmation phase — so a report distinguishes "this looks
vulnerable" (tentative) from "this was demonstrably exploited" (confirmed). It
produces JSON / CSV / HTML / PDF reports with CVSS v3.1 + v4.0 scoring and
OWASP / CWE / PCI-DSS / NIST-CSF / MITRE ATT&CK mappings.

---

> ## ⚠️ Legal & Ethical Use — read before running anything
>
> **HYDRA is an offensive security tool. It sends real attack payloads and, in
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
> If you do not have written permission to test a target, **do not point HYDRA
> at it.** Use the bundled deliberately-vulnerable practice target or a
> self-hosted lab instead (see [Try it safely](#-try-it-safely)).
>
> As a guardrail, HYDRA is **deny-by-default**: every outbound request is
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
- [Quickstart](#-quickstart)
- [Try it safely](#-try-it-safely)
- [Usage guide](#-usage-guide)
- [Configuration](#-configuration)
- [Reporting](#-reporting)
- [Production: PostgreSQL & distributed scanning](#-production-postgresql--distributed-scanning)
- [Architecture & project layout](#-architecture--project-layout)
- [Extending HYDRA (plugins)](#-extending-hydra-plugins)
- [Development](#-development)
- [Legal & Ethical Use](#-legal--ethical-use)
- [Contributing](#-contributing)
- [License](#-license)

---

## ✨ Features

**Reconnaissance (10 modules)**
- Scope-aware web crawler, passive technology fingerprinting
- JavaScript analysis (endpoint + secret extraction), content discovery
- Subdomain enumeration, DNS enumeration (+ AXFR attempt), WAF detection
- REST/GraphQL API discovery, Wayback Machine historical URLs
- Nmap port scan (optional; needs the `nmap` binary)

**Vulnerability scanners (28)**

| Category | Scanners |
|---|---|
| Injection | SQLi (error / boolean / time-based, WAF-evasion), command injection, SSTI, LFI, XXE |
| XSS | Reflected (content-type aware), DOM-based, stored (browser-verified) |
| Access / logic | IDOR, CSRF, open redirect, race conditions |
| API (OWASP API Top 10) | Mass assignment / object-property injection |
| Auth / session | Auth-session analysis, default credentials, JWT analysis |
| Server-side | SSRF (out-of-band + metadata), deserialization, prototype pollution |
| Config / transport | Security headers, CORS, TLS analysis, exposed files, cache poisoning |
| Protocol / API | GraphQL, WebSocket |
| Templates | Declarative Nuclei-style YAML/JSON template engine (`--templates`) |
| Intelligence | CVE matcher (version → known-CVE correlation) |

Active injection scanners share a **WAF-evasion encoder library** (URL / double-URL /
mixed-case / comment-spacing / HTML-entity / unicode); transport-surviving
variants are tried automatically under `--aggressive`.

**Exploitation confirmation (8 modules)** — re-proves findings to upgrade their
confidence to `confirmed`: SSRF, SQLi, LFI, command injection, SSTI, open
redirect, XXE, and XSS (browser-executed). Confirmation works on both
query-string **and** POST form-body parameters.

**Reporting**
- Formats: **JSON, CSV, HTML, PDF**
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

## 🔁 How it works

HYDRA runs a four-phase pipeline. Every network request — in every phase — goes
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

`hydra.utils.scope.ScopeValidator` is the load-bearing safety control. It is
**deny-by-default**: a host / port / path is only contacted if your
`ScopeConfig` explicitly authorizes it. `hydra.core.http_client.HttpClient`
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
git clone https://github.com/ankitjha67/project_hydra.git
cd project_hydra

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

## 🚀 Quickstart

```bash
# Recon only, scope auto-derived from the target
hydra recon -t https://example.com --crawl-depth 3

# Full pipeline (recon → scan → confirm → report) → JSON
hydra scan -t https://example.com -o report.json

# See every option
hydra --help
hydra scan --help
```

## 🧪 Try it safely

Do not learn the tool on someone else's systems. Use one of these **authorized**
targets:

- **Bundled practice target.** This repo ships a deliberately-vulnerable app at
  `tests/integration/reflecting_target.py` that exercises every scanner locally:

  ```bash
  python tests/integration/reflecting_target.py 8731     # terminal 1
  hydra scan -t http://127.0.0.1:8731 --aggressive -o report.json   # terminal 2
  ```

- **Self-hosted labs** (you own the instance): OWASP Juice Shop, DVWA, OWASP
  WebGoat, bWAPP, OWASP Mutillidae II.
- **Vendor-sanctioned public test sites** that explicitly permit scanning:
  `testphp.vulnweb.com`, `testasp.vulnweb.com`, `rest.vulnweb.com` (Acunetix),
  `demo.testfire.net` (IBM), `ginandjuice.shop` (PortSwigger).

> ⚠️ Public exploit/CVE databases (e.g. Exploit-DB) catalog *vulnerabilities*,
> **not authorized targets**. Never point HYDRA at a live system you found
> listed somewhere; that is unauthorized access.

## 📖 Usage guide

HYDRA exposes four sub-commands: `recon`, `scan`, `exploit`, `report`.

### `hydra scan` — the full pipeline

```bash
# Explicit engagement scope (wildcard domains + CIDR), exclude sensitive paths
hydra scan -t https://app.target.com \
  --scope "*.target.com,api.target.com,10.0.0.0/24" \
  --exclude-paths "/admin/delete/.*,/api/v1/payments" \
  -o report.html --format html --template technical

# Run only specific scanner modules
hydra scan -t https://app.target.com --modules sqli,xss,ssti,ssrf -o report.json

# Aggressive mode also enables time-based blind tests (SQLi/cmd) and race conditions
hydra scan -t https://app.target.com --aggressive -o report.json

# Authenticated scan (re-use a captured session cookie + extra headers)
hydra scan -t https://app.target.com \
  --auth-cookie "session=abc123; csrf=def456" \
  --headers '{"Authorization": "Bearer eyJ..."}' \
  -o report.json

# Route through a proxy (e.g. Burp), cap the request rate, raise the timeout
hydra scan -t https://app.target.com --proxy http://127.0.0.1:8080 --rate-limit 10 --timeout 45

# Skip the confirmation phase (also disables the OOB callback server)
hydra scan -t https://example.com --no-exploit -o report.json

# Disable the headless browser (skips DOM/stored XSS + browser confirmation)
hydra scan -t https://example.com --no-browser -o report.json
```

Common `scan` options: `--modules`, `--aggressive`, `--rate-limit`,
`--crawl-depth`, `--max-pages`, `--timeout`, `--proxy`, `--auth-cookie`,
`--user-agent`, `--callback`, `--no-exploit`, `--browser/--no-browser`,
`--exclude-paths`, `--headers`, `--threads`, `--scan-id`, `-o/--output`,
`--format`, `--template`, `--min-severity`, `--logo`, `--har`, `-v/--verbose`.

### `hydra recon` — reconnaissance only

```bash
# All recon modules (fingerprint, crawl, JS, content, WAF, API, DNS)
hydra recon -t https://example.com -o recon.json

# Turn modules on/off; add subdomain enum (needs a *.domain scope) and Wayback
hydra recon -t https://target.com --scope "*.target.com" \
  --subdomains --wayback --no-content --crawl-depth 5
```

### `hydra report` — render an existing scan

```bash
# Reports are generated from the stored scan; pick format + template
hydra report --scan-id scan-abcd1234 --format pdf --template executive -o exec_report
hydra report --scan-id scan-abcd1234 --format csv -o findings
hydra report --scan-id scan-abcd1234 --format html --template compliance --min-severity high -o audit
```

### `hydra exploit`

```bash
hydra exploit --scan-id scan-abcd1234
```

> Note: confirmation runs automatically during `hydra scan`. Standalone
> replay-from-DB is not yet implemented — re-run the scan to (re-)confirm.

## ⚙️ Configuration

Runtime settings are read from environment variables (prefix `HYDRA_`) or a
`.env` file. None are required for a basic SQLite run.

| Variable | Purpose | Default |
|---|---|---|
| `HYDRA_DB_URL` | Database URL (SQLite or PostgreSQL) | `sqlite+aiosqlite:///./hydra.sqlite3` |
| `HYDRA_DATA_DIR` | Screenshots / scan artifacts directory | `./scan_data` |
| `HYDRA_LOG_LEVEL` | Default log level | `info` |
| `HYDRA_ENCRYPTION_KEY` | base64 AES-256 key; encrypts sensitive evidence at rest | _(off)_ |
| `HYDRA_REDIS_URL` | Celery broker/backend (distributed mode) | `redis://localhost:6379/0` |
| `HYDRA_PLUGINS_DIR` | External plugin directory auto-loaded at startup | _(none)_ |
| `HYDRA_SHODAN_API_KEY`, `HYDRA_CENSYS_API_ID`/`_SECRET`, `HYDRA_VIRUSTOTAL_API_KEY`, `HYDRA_NVD_API_KEY`, `HYDRA_GITHUB_TOKEN` | Optional passive-recon / CVE-intel credentials | _(none)_ |

```bash
# Example: PostgreSQL + at-rest encryption
export HYDRA_DB_URL="postgresql+asyncpg://hydra:hydra@localhost:5432/hydra"
export HYDRA_ENCRYPTION_KEY="$(python -c 'import base64,os;print(base64.b64encode(os.urandom(32)).decode())')"
```

## 📑 Reporting

- **JSON** — full structured output (every field, evidence, exploitation results).
- **CSV** — one row per finding (severity, confidence, CVSS, type, URL, parameter,
  param location, CWE, OWASP) for spreadsheets/triage.
- **HTML** — styled report; `technical` includes raw request/response evidence and
  screenshots, `executive` is a summary, `compliance` emphasises framework mappings.
- **PDF** — the HTML report rendered to PDF via headless Chromium (needs `[browser]`).

Every finding carries CVSS v3.1 + v4.0 vectors/scores and is mapped to OWASP Top
10, CWE, PCI-DSS, NIST-CSF, and MITRE ATT&CK.

## 🏭 Production: PostgreSQL & distributed scanning

```bash
# PostgreSQL backend (needs [postgres]: asyncpg + alembic)
export HYDRA_DB_URL="postgresql+asyncpg://hydra:hydra@localhost:5432/hydra"
alembic upgrade head

# Distributed scanning across Celery workers (needs [distributed] + Redis)
celery -A hydra.distributed.celery_app worker --loglevel=info
hydra scan --distributed --workers 4 --redis redis://localhost:6379/0 -t targets.txt

# Or bring up the whole stack (app + workers + redis + postgres) with Docker
docker compose -f docker/docker-compose.yml up -d --build
docker compose -f docker/docker-compose.yml run --rm app scan -t https://example.com
```

> Distributed out-of-band detection needs a shared, externally-reachable callback
> server (e.g. Interactsh); the built-in local listener only serves same-host targets.

## 🧱 Architecture & project layout

```
hydra/
  core/        config, scope-enforced HTTP client, browser engine, callback server, orchestrator, schemas
  recon/       crawler, fingerprint, JS analyzer, content discovery, subdomain/DNS enum, WAF, API, wayback, ports
  scanners/    26 scanners + base interface + registry
  exploits/    8 confirmation modules + base interface + registry
  reporting/   JSON/CSV/HTML/PDF generator, CVSS engine, Jinja2 templates
  db/          SQLAlchemy 2.0 models, async store, Alembic migrations
  distributed/ Celery app, tasks, target dispatcher
  utils/       logger, scope validator, rate limiter, encoding
  main.py      Click CLI entry point
docker/        Dockerfile + docker-compose (app, workers, redis, postgres)
tests/         unit tests + a bundled deliberately-vulnerable integration target
```

## 🔌 Extending HYDRA (plugins)

Scanners, exploits, recon modules, and reporters are auto-discovered via
decorators. Drop a module that subclasses the relevant base class and registers
itself into `HYDRA_PLUGINS_DIR` (or the in-tree package) and it joins the
pipeline — no core changes needed. A new scanner is roughly:

```python
from hydra.scanners.base_scanner import BaseScanner
from hydra.scanners.registry import register

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
ruff check hydra tests
mypy hydra
pytest -q
```

The suite is offline and deterministic (unit tests + a bundled vulnerable target);
it does not touch the network or any external host.

## ⚖️ Legal & Ethical Use

This software is provided for **authorized security testing, education, and
research only.**

- Only use HYDRA against systems you **own** or are **explicitly authorized in
  writing** to test. Keep a copy of that authorization.
- Define an accurate `--scope` and respect it. Scope enforcement is a safety aid,
  not legal cover.
- Running active scanners/exploits against systems without permission may violate
  computer-misuse laws (CFAA, UK CMA, EU 2013/40, and equivalents) and can lead to
  **criminal and civil liability**.
- The software is provided **"AS IS", without warranty of any kind**. The authors
  and contributors are **not liable** for any misuse, damage, data loss, or legal
  consequence arising from its use.
- By using HYDRA you accept full responsibility for your actions and confirm you
  have the authorization required for every target you test.

**If in doubt, don't.** Practice on the bundled target or a self-hosted lab.

## 🤝 Contributing

Issues and pull requests are welcome. Please keep changes scope-safe (all network
access must go through `HttpClient`), add tests for new scanners/exploits, and run
`ruff` + `pytest` before submitting.

## 📄 License

[MIT](LICENSE) © 2026 Ankit Jha. See the additional **authorized-use notice** in
the LICENSE file and the [Legal & Ethical Use](#-legal--ethical-use) section above.
