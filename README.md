# Project HYDRA

Automated vulnerability discovery & exploitation-confirmation framework.

> **Authorized security testing only.** HYDRA is for penetration testers, red
> teamers, and security researchers operating **within an explicitly authorized
> scope**. Every outgoing request is validated against the engagement scope
> before transmission (deny-by-default). Do not point it at systems you do not
> have written permission to test.

This repository is being built incrementally from `HYDRA_PRD_v1.0.docx`. The
sections below describe **what works today** (the Phase-1 foundation), not the
full PRD vision.

## Status

| Area | State |
|------|-------|
| Core: config, scope engine, HTTP client, rate limiter, event bus | Implemented |
| Database (SQLAlchemy 2.0, SQLite dev) | Implemented |
| Recon: crawler, fingerprint, JS analysis (endpoints/secrets/ws), content discovery, subdomain enum (DNS + crt.sh) | Implemented |
| Scanners (24): security-headers, cors, reflected/dom/stored xss, sqli, ssti, lfi, cmd-injection, open-redirect, csrf, auth-session, deserialization, idor, cache-poisoning, graphql, xxe, jwt, tls, ssrf, prototype-pollution, cve, exposed-file, websocket | Implemented |
| Headless browser engine (Playwright/Chromium, scope-enforced) | Implemented |
| OOB callback server (local fallback listener) | Implemented |
| CVE matching via NVD (cached) | Implemented |
| Exploitation confirmation (ssrf, sqli, lfi, cmd, ssti, open-redirect, xxe, xss) | Implemented |
| Reporting: JSON, CSV, HTML + PDF (executive/technical/compliance), CVSS v3.1, OWASP/CWE mapping | Implemented |
| Production: PostgreSQL (+ Alembic migrations), distributed scanning (Celery/Redis), Docker Compose stack | Implemented |
| Scanners: race condition | Deferred (app-aware, high false-positive) |
| Recon: port scan (Nmap), Shodan/Censys passive recon | Planned next |

## Requirements

- Python **3.11+** (developed on 3.14, Windows 11)
- The "lean core" dependencies install on Windows without external binaries.

## Install

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .
```

Optional dependency groups (added per roadmap phase):

```powershell
pip install -e ".[browser]"      # Playwright headless browser
pip install -e ".[scanners]"     # pyjwt, cryptography, sslyze, paramiko
pip install -e ".[reporting]"    # weasyprint (optional alt PDF backend; default uses [browser])
pip install -e ".[dev]"          # pytest, ruff, mypy
```

> The **jwt** and **tls** scanners require the `[scanners]` extra (pyjwt /
> cryptography / sslyze). The **dom-xss** and **stored-xss** scanners and **xss**
> confirmation require the `[browser]` extra plus `playwright install chromium`.
> All self-disable cleanly if their extra is absent; the lean core still runs the
> rest.

## Usage

```powershell
# Reconnaissance only (fingerprint + crawl), scope auto-derived from target
hydra recon -t https://example.com --crawl-depth 3

# Explicit engagement scope (wildcards + CIDR), exclude sensitive paths
hydra recon -t https://app.target.com `
  --scope "*.target.com,api.target.com,10.0.0.0/24" `
  --exclude-paths "/admin/delete/.*,/api/v1/payments"

# Full pipeline (recon -> scan -> exploit -> report). 18 scanners run; detected
# findings are then re-proven by the confirmation phase (confidence -> confirmed).
# A local OOB callback server starts automatically for SSRF/blind detection.
# Time-based SQLi/cmd-injection blind tests run only with --aggressive.
hydra scan -t https://example.com -o report.json

# Skip the confirmation phase (also disables the callback server)
hydra scan -t https://example.com --no-exploit -o report.json

# Disable the headless browser (skips DOM/stored XSS + browser confirmation)
hydra scan -t https://example.com --no-browser -o report.json

# Run only specific scanner modules
hydra scan -t https://app.target.com --modules sqli,xss,ssti -o report.json

# Generate reports from a stored scan (json/csv/html/pdf; templates: executive/technical/compliance)
hydra report --scan-id scan-abcd1234 --format pdf --template executive -o exec_report
hydra report --scan-id scan-abcd1234 --format html --template technical -o tech_report
```

Run `hydra --help` or `hydra <command> --help` for all options.

## Production: PostgreSQL & distributed scanning

```powershell
# Use PostgreSQL instead of SQLite (needs the [postgres] extra: asyncpg + alembic)
$env:HYDRA_DB_URL = "postgresql+asyncpg://hydra:hydra@localhost:5432/hydra"
alembic upgrade head            # create/upgrade schema (or rely on auto-create for dev)

# Distributed scanning across Celery workers (needs the [distributed] extra + Redis)
celery -A hydra.distributed.celery_app worker --loglevel=info   # start worker(s)
hydra scan --distributed --workers 4 --redis redis://localhost:6379/0 -t targets.txt

# Or run the whole stack (app + workers + redis + postgres) with Docker
docker compose -f docker/docker-compose.yml up -d --build
docker compose -f docker/docker-compose.yml run --rm app scan -t https://example.com
```

> Distributed OOB detection needs a shared, externally-reachable callback server
> (Interactsh); the built-in LocalCallbackServer only serves same-host targets.

## Scope enforcement (read this)

`hydra.utils.scope.ScopeValidator` is the safety boundary. It is **deny by
default**: a host/port/path is only allowed if the `ScopeConfig` authorizes it.
`hydra.core.http_client.HttpClient` calls it before every request and validates
each redirect hop. Modules must use `HttpClient` rather than raw `httpx` so the
boundary cannot be bypassed.

## Project layout

```
hydra/
  core/        config, scope-enforced HTTP client, browser engine, callback server, orchestrator, schemas
  recon/       crawler, fingerprint, JS analyzer, content discovery, subdomain enum
  scanners/    24 scanners + base interface + registry
  exploits/    confirmation modules + base interface + registry
  reporting/   JSON/CSV/HTML/PDF generator, CVSS engine, Jinja2 templates
  db/          SQLAlchemy models, async store, Alembic migrations
  distributed/ Celery app, tasks, target dispatcher
  utils/       logger, scope validator, rate limiter, encoding
  main.py      Click CLI entry point
docker/        Dockerfile + docker-compose (app, workers, redis, postgres)
```

## Development

```powershell
pip install -e ".[dev]"
ruff check hydra
mypy hydra
pytest
```
