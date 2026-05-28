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
| Recon: static crawler, passive tech fingerprinting | Implemented |
| Recon: subdomain enum, port scan, JS analysis, content discovery | Planned |
| Scanners (16): security-headers, cors, xss, sqli, ssti, lfi, cmd-injection, open-redirect, csrf, auth-session, deserialization, idor, cache-poisoning, graphql, xxe, jwt, tls | Implemented |
| Scanners: SSRF, stored/DOM XSS, prototype pollution, websocket, race condition, CVE matcher | Deferred (need callback server / Playwright / NVD) |
| Exploitation confirmation | Interface + registry only |
| Reporting | JSON only (HTML/PDF templates planned) |
| Playwright browser engine, Nmap, Interactsh, Celery, Postgres | Deferred behind interfaces |

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
pip install -e ".[reporting]"    # jinja2, weasyprint (HTML/PDF reports)
pip install -e ".[dev]"          # pytest, ruff, mypy
```

> The **jwt** and **tls** scanners require the `[scanners]` extra (pyjwt /
> cryptography / sslyze). Without it they self-disable; the other 14 scanners run
> on the lean core.

## Usage

```powershell
# Reconnaissance only (fingerprint + crawl), scope auto-derived from target
hydra recon -t https://example.com --crawl-depth 3

# Explicit engagement scope (wildcards + CIDR), exclude sensitive paths
hydra recon -t https://app.target.com `
  --scope "*.target.com,api.target.com,10.0.0.0/24" `
  --exclude-paths "/admin/delete/.*,/api/v1/payments"

# Full pipeline (recon -> scan -> exploit -> report). Active scanners today:
# security-headers, cors, xss, sqli, ssti, lfi, cmd-injection, open-redirect.
# Time-based SQLi/cmd-injection blind tests run only with --aggressive.
hydra scan -t https://example.com -o report.json

# Run only specific scanner modules
hydra scan -t https://app.target.com --modules sqli,xss,ssti -o report.json

# Generate a report from a stored scan
hydra report --scan-id scan-abcd1234 --format json -o report.json
```

Run `hydra --help` or `hydra <command> --help` for all options.

## Scope enforcement (read this)

`hydra.utils.scope.ScopeValidator` is the safety boundary. It is **deny by
default**: a host/port/path is only allowed if the `ScopeConfig` authorizes it.
`hydra.core.http_client.HttpClient` calls it before every request and validates
each redirect hop. Modules must use `HttpClient` rather than raw `httpx` so the
boundary cannot be bypassed.

## Project layout

```
hydra/
  core/        config, scope-enforced HTTP client, session, event bus, orchestrator, schemas, context
  recon/       crawler, tech fingerprint (+ base interface)
  scanners/    base interface + registry (modules land here)
  exploits/    base interface + registry (modules land here)
  reporting/   report generator (JSON now)
  db/          SQLAlchemy models + async store
  utils/       logger, scope validator, rate limiter
  plugins/     plugin loader (planned)
  main.py      Click CLI entry point
```

## Development

```powershell
pip install -e ".[dev]"
ruff check hydra
mypy hydra
pytest
```
