# Bug-bounty mode (`orthrus bounty`)

`orthrus bounty` runs a whole bug-bounty engagement in one command: it takes a
program's **authorized scope**, scans every in-scope asset with all 59 scanners,
**confirms** what it can with the exploitation-confirmation phase, and writes
**submission-ready per-bug reports** you can paste into HackerOne / Bugcrowd /
Intigriti.

> ## ⚠️ Authorized programs only
> A bug-bounty program authorizes testing of **specific assets under specific
> rules**. Touching an out-of-scope host is a rules violation (bans, forfeited
> bounties) and, depending on where you and the target are, a crime. `orthrus
> bounty` is **deny-by-default**: it refuses to run without an explicit in-scope
> target, enforces your out-of-scope exclusions on every request, and prints the
> resolved scope before it sends a single packet. Read the program's scope and
> rules first, and keep to them.

## Authorization (required for public scopes)

Every engagement must declare **where your authorization comes from** - ORTHRUS
will not scan public hosts without it:

```bash
orthrus bounty --in-scope '*.example.com' \
  --authorization https://hackerone.com/example
```

`--authorization` accepts a **program URL** (HackerOne / Bugcrowd / Intigriti /
YesWeHack / Immunefi), `signed:<file-or-hash>` (a private engagement letter),
`direct:<note>` (direct written permission / a link to the program's policy), or
`self-owned-lab`. A scope made up **entirely of loopback / RFC1918 hosts** is
treated as a self-owned lab automatically, so local practice needs no flag.

**High-sensitivity hosts are refused.** Anything that looks like government,
military, education, healthcare, or a sanctioned-jurisdiction TLD is blocked by
default. If you genuinely hold written authorization for one, attest it per host:

```bash
orthrus bounty --in-scope security.university.edu \
  --authorization 'signed:letter.pdf' --i-am-authorized security.university.edu
```

This is a conservative safety brake (TLD/keyword based, not a legal ruling) - it
errs toward refusing. Read the program's rules; you are responsible for staying in
scope and in the law.

## Quick start

```bash
# from a program scope file (authorization can live in the file's context; pass it explicitly)
orthrus bounty --scope-file program.txt --authorization https://hackerone.com/acme -o bounty-report/

# inline
orthrus bounty --in-scope '*.example.com' --out-scope 'admin.example.com' \
  --authorization https://bugcrowd.com/acme -o bounty-report/

# local practice target - no authorization flag needed (implied self-owned lab)
orthrus bounty --in-scope http://127.0.0.1:8791 -o bounty-report/

# see exactly what would be scanned, send nothing:
orthrus bounty --scope-file program.txt --authorization … --dry-run
```

## The scope file

Plain text, one entry per line - the format most programs already publish:

```
# Acme Corp - public program scope
*.acme.com               # wildcard: the apex and any subdomain are in scope
api.acme.com             # a specific host
https://app.acme.com     # a URL to seed the crawl from
198.51.100.0/24          # a CIDR range
!admin.acme.com          # a leading '!' marks an OUT-OF-SCOPE exclusion
!*.internal.acme.com     # out-of-scope wildcard
!203.0.113.0/24          # out-of-scope range
```

Everything without `!` is in scope; `!` lines carve exclusions back out. A host
that matches both is treated as **out of scope**. Comments start with `#`. You
can mix a `--scope-file` with extra `--in-scope` / `--out-scope` flags.

## What it does

1. **Intake, authorize & enforce scope** - builds the deny-by-default engagement
   boundary and the seed list; refuses a public scope with no authorization and
   any high-sensitivity host without attestation. With `--enumerate` (default), a
   `*.wildcard` scope is expanded into its **live in-scope subdomains** (crt.sh +
   DNS), so you scan discovered hosts, not just the ones you typed.
2. **Scan every in-scope seed** - the full `recon → scan → confirm` pipeline per
   asset (all scanners; `--aggressive`, `--browser`, `--callback`/`--interactsh`
   for out-of-band confirmation of SSRF / XXE / deserialization all apply).
3. **Aggregate, filter, dedupe** - keeps only in-scope findings at/above the
   `--min-confidence` floor (default `firm`, so unproven `tentative` heuristics
   don't reach a triager), and collapses the same bug across parameters/URLs into
   one report with an *affected-locations* list.
4. **Write submission-ready reports** - one Markdown file per bug (title,
   severity + CVSS, weakness/CWE, affected asset, **copy-paste steps to
   reproduce** - curl / Python / raw request for Burp - impact, and remediation),
   shaped for your `--platform`; a priority-ranked `README.md` index; and a
   machine-readable `findings.json` (the ranked queue + counts) for automation.
   Bugs you've reported in earlier runs are flagged **♻ Seen before** so you don't
   re-file a duplicate, and any per-program **mute rules** drop known noise
   (counted, never silently hidden).

## Useful flags

| Flag | Purpose |
|---|---|
| `--authorization SOURCE` | Program URL / `signed:<file>` / `direct:<note>` / `self-owned-lab`. Required for public scopes. |
| `--i-am-authorized HOST` | Attest written authorization for a refused high-sensitivity host (gov/mil/edu/health). Repeatable. |
| `--enumerate / --no-enumerate` | Discover live in-scope subdomains (crt.sh + DNS) and scan them too, not just the seeds you listed. On by default; in-scope, non-excluded, non-sensitive hosts only. |
| `--min-confidence confirmed\|firm\|tentative` | Report floor. `confirmed` = only re-proven bugs (lowest noise); `firm` (default) adds strong observational findings; `tentative` includes everything. |
| `--platform generic\|hackerone\|bugcrowd\|intigriti\|yeswehack\|immunefi` | Shape each per-bug report for that platform's submission form (fields, severity language, Bugcrowd P1-P5, Immunefi gist reminder). |
| `--program NAME` | Save (or re-run) a **named program**: its scope, authorization, campaign history, mute rules, traffic policy, and asset inventory are persisted so you re-run by name and get cross-run intelligence (new assets, duplicate flags). |
| `--tools nuclei,dalfox,…` | Also run external tools, normalized into the same findings pipeline - web (nuclei / dalfox / testssl / ffuf / nikto / wpscan), code SAST (semgrep), cloud & IaC (checkov), web3 (slither), mobile (mobsfscan). Tools whose binary isn't on `PATH` are skipped. |
| `--notify-slack URL` | Post a campaign summary to Slack (or set `ORTHRUS_SLACK_WEBHOOK`). |
| `--aggressive` | Enable aggressive scanning. |
| `--browser` | Drive a headless browser (DOM / stored XSS). |
| `--callback HOST` / `--interactsh` | Out-of-band collaborator for blind SSRF / XXE / deserialization confirmation. |
| `--rate-limit`, `--timeout`, `--threads`, `--crawl-depth`, `--max-pages` | Politeness / performance - respect the program's rate rules. A saved program's `program-policy` rate ceiling is honored as a hard cap regardless. |
| `--dry-run` | Resolve and print scope + seeds, then stop. |

## A program-anchored workflow

Save a program once, then let ORTHRUS carry the cross-run intelligence:

```bash
# 1. Save the program (scope + authorization persist under the name)
orthrus bounty --program acme --in-scope '*.acme.com' \
  --authorization https://hackerone.com/acme --dry-run

# 2. Record the program's rules so every run honors them automatically
orthrus program-policy --program acme --max-rps 5 --identify 'X-Bug-Bounty: yourname'

# 3. Mute a class the program won't pay for (kept out of the queue, still counted)
orthrus suppress --program acme --vuln-type security-headers --reason 'out of policy'

# 4. Run it - enumerates subdomains, flags NEW assets since last time, dedupes vs history
orthrus bounty --program acme --platform hackerone --enumerate -o acme-report/

# 5. Track what you filed and what paid out
orthrus submission --program acme --title 'SQLi in /search' --status filed --severity high
orthrus submissions --program acme          # earnings roll-up
```

### Companion commands

| Command | What it's for |
|---|---|
| `orthrus programs` / `program-policy` | List saved programs; set a rate ceiling + identifying header. |
| `orthrus bounty-assets --program NAME` | The live in-scope asset inventory (new hosts are flagged during `--enumerate`). |
| `orthrus suppress` / `suppressions` | Add / list per-program mute rules for known-noise findings. |
| `orthrus submission` / `submissions` | Record a submission (status, payout, link); roll up earnings. |
| `orthrus note` / `notes` | A tagged, searchable knowledge base of your own tradecraft. |
| `orthrus copilot "…"` | Ask a copilot grounded in your notes + submissions (never invents findings). |
| `orthrus cost` | The spend ledger - LLM tokens the copilot used, rolled up by provider/program. |
| `orthrus audit --verify` | The tamper-evident, hash-chained log of scope/authorization decisions. |
| `orthrus bounty-report --program NAME --platform …` | Re-render a program's last campaign in a different platform format - **no re-scanning** (reuses stored findings). |
| `orthrus bounty-status` | One-view cockpit: programs, earnings, assets, mute rules, spend, audit integrity. |

## Operator graph (v2.0)

The v2.0 operator platform anchors everything to a persistent, DB-backed **program
graph** (assets → endpoints → findings), driven by these commands and the cockpit
(`orthrus serve --cockpit`). Deny-by-default holds at every entry point.

```bash
# 1. Continuous recon → dedup into the graph, alert on NEW assets
orthrus recon-run --program acme --in-scope acme.com --authorization https://hackerone.com/acme

# 2. Import the surface you browsed by hand - Burp / Caido / HAR (out-of-scope hosts refused)
orthrus import-traffic history.har --program acme            # --format auto-detects
orthrus import-traffic burp-items.xml --program acme --format burp

# 3. Ask what to do next - deterministic, grounded in real graph state (no LLM, no invented steps)
orthrus plan --program acme

# 4. Scan the live assets → promote findings into the triage queue
orthrus program-scan --program acme

# 5. Work the queue
orthrus program-findings --program acme --status new
```

| Command | What it's for |
|---|---|
| `orthrus recon-run` / `recon-watch` | Enumerate scope into the graph (once / continuously), alerting on new assets. |
| `orthrus import-traffic FILE --program NAME` | Fold a Burp XML / Caido JSON / HAR proxy history into the graph as assets + endpoints (query/body params + a juicy-score). Out-of-scope hosts refused unless `--no-scope-filter`. |
| `orthrus program-scan --program NAME` | Scan the graph's live assets and promote deduped findings into the queue. |
| `orthrus plan --program NAME` | A priority-ranked, grounded to-do list of the exact next commands to run. |
| `orthrus program-findings --program NAME` | The operator-graph triage queue (filter `--status`), priority-first. |

### Team mode

For a shared, multi-operator deployment, run the platform behind Postgres with the
API + cockpit image and grant per-program roles (owner/member/viewer):

```bash
ORTHRUS_API_TOKEN=$(openssl rand -hex 24) \
  docker compose -f docker/docker-compose.operator.yml up -d --build

# seed the first admin (implicit owner everywhere), then grant teammates
orthrus team add-user you@org.test --admin --with-key
orthrus team grant --program acme --user teammate@org.test --role member
```

RBAC engages once `ORTHRUS_API_TOKEN` is set: mutations need the shared token **or**
a sufficient per-user API key (managing members needs `owner`, reading needs `viewer`).
With no token and no members, a program stays single-user, exactly as before.

## Notes

- **Reduce triager noise:** submit `--min-confidence confirmed` first - those come
  with a re-proof and a reproduction snippet, which is what gets bounties paid.
- **Respect the rules:** save a `program-policy` rate ceiling; never point it at
  anything you haven't been authorized to test.
- **Automation:** consume `findings.json` (the ranked queue, with `prior_seen`
  duplicate flags) from a script or dashboard rather than parsing the Markdown.

The full plan - mapping the ORTHRUS v2.0 operator-platform PRD onto what's built,
buildable, or a separate product bet - is in
[BOUNTY_V2_ROADMAP.md](BOUNTY_V2_ROADMAP.md).
