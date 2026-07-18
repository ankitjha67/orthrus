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

Every engagement must declare **where your authorization comes from** — ORTHRUS
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

This is a conservative safety brake (TLD/keyword based, not a legal ruling) — it
errs toward refusing. Read the program's rules; you are responsible for staying in
scope and in the law.

## Quick start

```bash
# from a program scope file (authorization can live in the file's context; pass it explicitly)
orthrus bounty --scope-file program.txt --authorization https://hackerone.com/acme -o bounty-report/

# inline
orthrus bounty --in-scope '*.example.com' --out-scope 'admin.example.com' \
  --authorization https://bugcrowd.com/acme -o bounty-report/

# local practice target — no authorization flag needed (implied self-owned lab)
orthrus bounty --in-scope http://127.0.0.1:8791 -o bounty-report/

# see exactly what would be scanned, send nothing:
orthrus bounty --scope-file program.txt --authorization … --dry-run
```

## The scope file

Plain text, one entry per line — the format most programs already publish:

```
# Acme Corp — public program scope
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

1. **Intake & enforce scope** — builds the deny-by-default engagement boundary
   and the seed list; an excluded host can never be a seed or get scanned.
2. **Scan every in-scope seed** — the full `recon → scan → confirm` pipeline per
   asset (all scanners; `--aggressive`, `--browser`, `--callback`/`--interactsh`
   for out-of-band confirmation of SSRF / XXE / deserialization all apply).
3. **Aggregate, filter, dedupe** — keeps only in-scope findings at/above the
   `--min-confidence` floor (default `firm`, so unproven `tentative` heuristics
   don't reach a triager), and collapses the same bug across parameters/URLs into
   one report with an *affected-locations* list.
4. **Write submission-ready reports** — one Markdown file per bug (title,
   severity + CVSS, weakness/CWE, affected asset, **copy-paste steps to
   reproduce** — curl / Python / raw request for Burp — impact, and remediation),
   plus a severity-sorted `README.md` index.

## Useful flags

| Flag | Purpose |
|---|---|
| `--authorization SOURCE` | Program URL / `signed:<file>` / `direct:<note>` / `self-owned-lab`. Required for public scopes. |
| `--i-am-authorized HOST` | Attest written authorization for a refused high-sensitivity host (gov/mil/edu/health). Repeatable. |
| `--min-confidence confirmed\|firm\|tentative` | Report floor. `confirmed` = only re-proven bugs (lowest noise); `firm` (default) adds strong observational findings; `tentative` includes everything. |
| `--aggressive` | Enable aggressive scanning. |
| `--browser` | Drive a headless browser (DOM / stored XSS). |
| `--callback HOST` / `--interactsh` | Out-of-band collaborator for blind SSRF / XXE / deserialization confirmation. |
| `--rate-limit`, `--timeout`, `--threads`, `--crawl-depth`, `--max-pages` | Politeness / performance — respect the program's rate rules. |
| `--dry-run` | Resolve and print scope + seeds, then stop. |

## Notes & roadmap

- **Reduce triager noise:** submit `--min-confidence confirmed` first — those come
  with a re-proof and a reproduction snippet, which is what gets bounties paid.
- **Respect the rules:** set `--rate-limit` to the program's ceiling; never point
  it at anything you haven't been authorized to test.
- **Coming next:** active subdomain enumeration to expand a `*.wildcard` into all
  live in-scope hosts before scanning, platform-native report templates
  (HackerOne / Bugcrowd / Intigriti / YesWeHack / Immunefi), per-program dedupe,
  and continuous monitoring. The full plan — mapping the ORTHRUS v2.0 operator-platform
  PRD onto what's built, buildable, or a separate product bet — is in
  [BOUNTY_V2_ROADMAP.md](BOUNTY_V2_ROADMAP.md). Today, list the specific in-scope
  hosts (or the apex) you want scanned.
