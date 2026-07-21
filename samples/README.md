# ORTHRUS - sample reports

Real, unedited output from a single ORTHRUS run, published so you can see what
the tool produces before installing it. Every file here was generated from the
**same scan** against the project's **bundled local test target** (an
intentionally-vulnerable app on `127.0.0.1`, see
[`tests/integration/reflecting_target.py`](../tests/integration/reflecting_target.py)).

> **No real credentials are in these files.** The API keys, JWTs, and passwords
> visible in the evidence are the test target's *deliberately planted* fakes -
> the AWS key is Amazon's public documentation example `AKIAIOSFODNN7EXAMPLE`,
> the JWTs decode to `{"user":"admin","role":"user"}`, the login is `admin/admin`.
> They are the vulnerabilities ORTHRUS is demonstrating it can find, not secrets.

## The scan

| | |
|---|---|
| Target | `http://127.0.0.1:8791` (bundled test app) |
| Mode | full pipeline, aggressive, **headless browser on** |
| Total findings | **82** |
| **Confirmed by active exploitation** | **30** |
| Firm (proven by direct observation) | 35 |
| Tentative (flagged for human review) | 17 |
| Severity | 2 critical · 34 high · 25 medium · 19 low · 2 info |

The flagship confirmed finding is an **OS command injection in the GraphQL
argument `systemDiagnostics.cmd`** - re-proven non-destructively by injecting a
canary that the OS shell echoed back.

### Why the three confidence tiers matter

ORTHRUS never fakes a confirmation. A finding is only **confirmed** when a safe,
active proof succeeded (a canary echoed, a JWT forged, a payload executed in a
real browser with a screenshot captured). Findings that are certain by *direct
observation* - a missing security header, an exposed `.git`, an outdated library
- are **firm**: real, but there is nothing to "exploit," so labelling them
confirmed would be dishonest. Heuristic signals that genuinely need a human eye
are **tentative**. The split is the point: the report tells you exactly how sure
it is, and why.

## The files

| File | What it is |
|---|---|
| [`orthrus-ai-remediation-report.pdf`](orthrus-ai-remediation-report.pdf) | The **AI consultant report** - renders inline on GitHub. Per-finding technical description, business impact, likelihood, exploitation walkthrough, and **tactical + strategic remediation**, plus a prioritised remediation plan and phased roadmap. |
| [`orthrus-ai-remediation-report.html`](orthrus-ai-remediation-report.html) | Same report as self-contained HTML (download & open in a browser). |
| [`orthrus-scan-report.html`](orthrus-scan-report.html) | The standard deterministic scan report - findings, CVSS v3.1/v4.0, and verbatim recorded evidence. |
| [`orthrus-findings.json`](orthrus-findings.json) | Machine-readable findings (for pipelines / triage). |
| [`orthrus-findings.sarif`](orthrus-findings.sarif) | SARIF 2.1.0 - drop into GitHub code scanning or any SARIF viewer. |

> GitHub shows committed `.html` as source, not a rendered page. Download the HTML
> and open it locally, or just view the **PDF**, which renders in the browser.

## Regenerate these yourself

```bash
# scan the bundled target (browser on) → deterministic report
orthrus scan -t http://127.0.0.1:8791 --aggressive --browser \
  --scan-id demo --format html -o orthrus-scan-report.html

# AI consultant report from the same scan (any provider; local Ollama keeps data on-host)
orthrus ai-report --scan-id demo --llm ollama:llama3.1 --format pdf \
  -o orthrus-ai-remediation-report.pdf

# machine-readable formats
orthrus report --scan-id demo --format json  -o orthrus-findings.json
orthrus report --scan-id demo --format sarif -o orthrus-findings.sarif
```

The AI narrative in this sample was written by a hosted model over an
OpenAI-compatible endpoint; credentials and cookies in the evidence are
[redacted before anything is sent to a remote model](../orthrus/ai/providers.py).
Everything is grounded in the recorded evidence - **review before client delivery.**
