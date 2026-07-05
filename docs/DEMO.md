# ORTHRUS — 6-step demo

A safe, reproducible walkthrough that runs **only** against the bundled,
`127.0.0.1`-only, intentionally-vulnerable practice target — nothing external is
contacted. Everything below is **real output** from [`demo.sh`](../demo.sh).

## Run it

```bash
# from a clone with ORTHRUS installed (pip install -e ".[dev,scanners]")
./demo.sh
# or, without installing the console script:
ORTHRUS="python -m orthrus.main" ./demo.sh
```

It takes ~3–4 minutes (the scan runs in `--aggressive` mode so the injection
scanners actually confirm). To capture a GIF/cast for sharing:

```bash
asciinema rec orthrus-demo.cast -c ./demo.sh     # then upload, or render to GIF with agg
termtosvg orthrus-demo.svg      -c ./demo.sh     # animated SVG, no extra services
```

## What it shows

### 1 · Full pipeline — recon → scan → exploitation-confirmation → report

A curated 12-scanner run against the practice target finds **25 issues**, and the
confirmation phase actively re-proves the interesting ones:

```
                    Per-scanner metrics
┌────────────────┬──────────┬──────────┬──────────┬────────┐
│ Scanner        │ Findings │ Requests │ Time (s) │ Status │
├────────────────┼──────────┼──────────┼──────────┼────────┤
│ reflected-xss  │        7 │       22 │     0.39 │ ok     │
│ csrf           │        6 │        0 │     0.03 │ ok     │
│ jwt            │        4 │        5 │     0.08 │ ok     │
│ cors           │        2 │       75 │     7.22 │ ok     │
│ ssrf           │        2 │       71 │    51.49 │ ok     │
│ cmd-injection  │        1 │      767 │    20.22 │ ok     │
│ sqli           │        1 │      758 │    43.29 │ ok     │
│ ssti           │        1 │      240 │     4.61 │ ok     │
│ idor           │        1 │        9 │     0.17 │ ok     │
│ total (12 ran) │       25 │     1947 │   127.52 │ ok     │
└────────────────┴──────────┴──────────┴──────────┴────────┘
```

(A full 58-scanner `--aggressive` run of the same target finds **76 issues — 1
critical, 32 high, 22 medium** (plus 19 low / 2 info) — **with 24
exploitation-confirmed**, including command injection, SQLi, SSTI, weak-secret JWT
forgery, NoSQL injection, and prompt injection. See [PROOF.md](PROOF.md).)

### 2 · Collapse findings into reachable attack paths

`orthrus graph` treats the chain-rule catalog as a directed graph and extracts the
few kill-chains an attacker can actually walk:

```
25 findings collapsed into 2 attack path(s) (1 critical); 4 finding(s) on a reachable path

[CRITICAL] 2-step path @ 127.0.0.1
   jwt → idor
   ⇒ An attacker obtains a session via the authentication weakness, then escalates
     authorization to reach other users'/admin data — full account/admin takeover.

[HIGH] 2-step path @ 127.0.0.1
   xss → cors
   ⇒ Script injection with weak session/anti-CSRF protection lets an attacker ride a
     victim's session and take over the account.
```

### 3 · Consolidated remediation runbook

`orthrus runbook` collapses the 25 findings into the few fixes that retire them,
ordered so the highest-leverage change (one that breaks an attack path) is first:

```
25 finding(s) collapse into 9 fix action(s); 4 break at least one attack path.

## 1. Reflected XSS via parameter 'q' — HIGH
Fixes 7 finding(s) across 7 endpoint(s). · CWE-79
> 🔓 Breaks attack path: xss → csrf
Remediation: Contextually output-encode reflected user input and apply a strict CSP.
```

### 4 · Concrete remediation patches

`orthrus patch` turns each fix into paste-able config/code (parameterized queries,
security-header snippets, cookie flags, CSP, Terraform for cloud findings, …).

### 5 · Read-only cloud posture (CSPM/IAM) + toxic combinations

`orthrus cloud examples/cloud_inventory.json` analyzes a normalized snapshot (or a
read-only `--live` boto3 collection) and correlates single misconfigs into the
critical *combinations* an attacker would chain:

```
6 resource(s) · 10 finding(s) · 3 toxic combination(s)

CRITICAL  cloud-toxic-combo  Internet-reachable workload with a privileged role 'web-1'
CRITICAL  cloud-toxic-combo  Privileged IAM user without MFA 'ci-deploy'
HIGH      cloud-toxic-combo  IAM privilege-escalation path on 'ci-deploy'  (PassRole + RunInstances)
```

### 6 · Autonomous agent — plan only (dry-run)

`orthrus agent --dry-run` shows the LLM (or deterministic) planner choosing the next
batch of scanners to run. Its action space is a **hard allow-list of registered,
scope-enforced, non-destructive modules** — no shell, no arbitrary code:

```
AGENT · http://127.0.0.1:8791
planner: deterministic · aggressiveness: passive · max-steps: 2 · scope-enforced · non-destructive

Plan:
  • auth-session — baseline coverage (deterministic policy)
  • cors — baseline coverage (deterministic policy)
  • csrf — baseline coverage (deterministic policy)
  …
planned 16 action(s) (dry-run — nothing executed)
```

---

> ⚠️ Run ORTHRUS only against systems you own or are explicitly authorized to test.
> The demo target is safe because it's local and intentionally vulnerable.
