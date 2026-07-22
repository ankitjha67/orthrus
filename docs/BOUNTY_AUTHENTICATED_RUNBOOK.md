# Authenticated Bug-Bounty Runbook (1win-class targets)

This runbook exists because of one measurable fact: an **unauthenticated** scan of a
mature target's marketing surface yields security headers, non-credentialed CORS, and
cookie flags - none of which a serious program pays for. The critical bugs live
**behind login**, in the wallet / bet / deposit / withdraw / KYC APIs and in business
logic. ORTHRUS already ships the scanners that find them (`authz-matrix`,
`privilege-escalation`, `idor`, `race-condition`, `business-logic`); they only produce
findings when you give them an authenticated session and a second identity.

> Authorized testing only. Stay inside the program scope, use your own accounts, keep
> everything non-destructive, and never inflate severity. One real BOLA beats 18 header
> findings.

---

## 0. Prerequisites

- You are enrolled in the program and testing from an account/IP the program allows.
- The scope export is on disk (e.g. `scopes_for_1win_com_...csv`); ORTHRUS enforces it.
- Two accounts you control, **A** (baseline) and **B** (attacker), both fully registered.

---

## 1. Register two accounts and export one HAR each

Authorization testing is a differential: does **B** reach **A**'s object? You need two
real, separate accounts. Log into each in a normal browser, exercise the wallet, bet
history, profile, deposit and withdraw screens (so the API calls are recorded), then
**DevTools -> Network -> Save all as HAR** for each account (`A.har`, `B.har`).

That single HAR per account carries **both** things you need: the real authenticated API
surface *and* the live session (`cf_clearance` + cookies + the exact User-Agent).

## 2. Build `identities.json` with `capture-auth` (no manual copying)

`orthrus capture-auth` extracts the session straight out of each HAR - no DevTools
cURL-copy, no hand-editing:

```bash
orthrus capture-auth --har A.har --host 1win.com --name userA-baseline --out identities.json
orthrus capture-auth --har B.har --host 1win.com --name userB-attacker  --out identities.json
```

It writes a two-identity file (first = privileged baseline; the rest are tested against
it), capturing the full `Cookie` (including `cf_clearance`), the bound `User-Agent`, and a
bearer token if the app uses one. ORTHRUS injects its own anonymous control automatically,
so you do not need to add an anonymous entry.

The resulting file looks like:

```json
[
  { "name": "userA-baseline", "cookie": "cf_clearance=...; session=AAA...",
    "headers": { "User-Agent": "Mozilla/5.0 (... exact UA A ...)" } },
  { "name": "userB-attacker", "cookie": "cf_clearance=...; session=BBB...",
    "headers": { "User-Agent": "Mozilla/5.0 (... exact UA B ...)" } }
]
```

## 3. Feed the SAME HAR as the API surface

Do not point the scanner at `https://1win.com/` and hope. Pass A's HAR to the scan so it
tests the real endpoints the app calls, not static pages:

- `--import-spec A.har` reads endpoints, methods, and JSON bodies from the HAR, so
  `authz-matrix` and `idor` test the real object-referencing endpoints
  (`/api/.../wallet`, `/api/.../bets/{id}`, `/kyc/...`).
- `--import-spec` also accepts an OpenAPI/Swagger, GraphQL introspection, or Postman file
  if the program publishes one.

## 4. Run ORTHRUS authenticated, two identities

```bash
orthrus scan https://1win.com \
  --scope "1win.com,*.1win.com" \
  --identities identities.json \
  --import-spec A.har \
  --login-url "https://1win.com/api/.../login" \
  --login-data '{"email":"A@example.com","password":"..."}' \
  --login-check '"balance"' \
  --auth-cookie "cf_clearance=...; session=AAA..." \
  --user-agent "Mozilla/5.0 (... exact UA A ...)" \
  --no-waf-adapt \
  --rate-limit 3 \
  --modules authz-matrix,privilege-escalation,idor,business-logic,race-condition,sqli,ssrf,jwt,graphql-injection \
  --scan-id onewin-authz
```

Notes:
- `--no-waf-adapt` stops ORTHRUS rotating the User-Agent the `cf_clearance` is pinned to.
- `--login-url/--login-data/--login-check` re-establish the session if it drops mid-scan.
  Add `--csrf-url/--csrf-field/--csrf-header` if the login form carries a rotating token,
  and `--totp-secret` if the account uses TOTP MFA.
- Keep `--rate-limit` low (the target challenges/drops 25-50% of automated traffic).
- Drop `--modules` to run everything, or keep the authz-focused list above for a fast pass.

## 5. What the new capabilities give you

- **`authz-matrix` now escalates to CRITICAL with evidence.** When identity B reaches A's
  object, ORTHRUS scans the accessible body for PII / payment / token data, attaches a
  **redacted** sample as proof, and marks the finding CRITICAL (CWE-639). It also runs an
  **anonymous control** on every endpoint, so genuinely public pages are no longer flagged
  as BOLA, and sensitive data reachable with no auth at all is reported as missing
  authentication (CWE-306). This is the single highest-value class on a betting platform.
- **Submission gate.** Before you write a word, get the triage prediction:

  ```bash
  orthrus submission-gate --scan-id onewin-authz
  ```

  It sorts findings into **submit / prove-impact-first / hold** so you lead with what pays
  and never submit the header/CORS-no-cred/cookie-flag noise that gets closed N/A.

## 6. The manual money-flow checklist (where the prizes are)

No scanner finds these alone. Test them by hand, logged in, with A and B:

- **BOLA / IDOR on money and identity objects.** As B, request A's `wallet`, `transaction`,
  `bet/{id}`, `kyc/document`, `payout`. Reading A's balance or documents is a critical.
- **Broken authentication.** Password-reset token reuse/leak/predictability, OTP brute or
  bypass, JWT alg/secret issues, session fixation, "remember me" that never expires.
- **Deposit/withdraw race conditions (double-spend).** Fire N parallel withdraw or
  bonus-claim requests for a balance that should only allow one. This is the classic
  gambling-platform critical - and the most dangerous to test (see safety below).
- **Amount / currency / sign tampering.** Negative deposits, fractional/rounding abuse,
  currency confusion (deposit weak currency, withdraw strong), quantity overflow on bets.
- **Bonus / promo abuse.** Re-trigger one-time bonuses, stack referral credits, replay a
  claim.
- **SSRF** via avatar-by-URL, payment/withdrawal callback URLs, or any "fetch this link".
- **Stored / second-order XSS** in profile name, support chat, bet notes - anything an
  operator or another user later renders.

### 6.1 Financial-flow sequence attacks (deposit -> KYC -> withdraw)

Payload tampering never models *order*. These are state-machine bugs - tested by hand
because they need the real multi-step flow, two accounts, and a ledger you can read.
ORTHRUS's `business-logic`/`race-condition` scanners find the mechanical precursors; the
sequence itself you drive:

1. **Map the states.** From your logged-in HAR, list the ordered steps and the token/flag
   each produces (e.g. `deposit_id`, `kyc_status`, `withdraw_authz`). Note which step is
   supposed to gate the next.
2. **Step-skip.** Send the *later* step's request from a session that never completed the
   earlier one - e.g. POST `/withdraw` before KYC, or before a deposit clears. If it is
   accepted, the server trusts client-side ordering.
3. **Step-replay.** Replay a one-time step (a deposit-confirm, a bonus-credit, a
   withdrawal-authz) twice with the same token. A second success is a double-credit
   precursor.
4. **Cross-session ordering.** Start the flow as account A, then complete a step as A
   using an identifier minted in account B's session (or vice versa). Mixed ownership that
   the server accepts is a tenancy break in the money flow.
5. **Deferred ledger assertion (the key discipline).** The bug often does not show at
   request time. Note the balance/ledger before, run the sequence, then re-read the
   balance **minutes to hours later** (pending windows settle asynchronously). The
   invariant "money out == money debited, exactly once" is what you assert.

Safety: your own funded accounts only, the minimum amount that proves the invariant, and
stop at proof - never repeat for effect. Get the program's explicit nod before any
state-changing cashier test.

### 6.2 Account pre-hijacking & identity collision (zero-interaction ATO)

High-value on a Telegram/Google-login-heavy platform, and entirely manual (it needs the
real OAuth/social-link flow). Use email addresses and social accounts **you control** as
both "attacker" and "victim".

1. **Classic pre-hijack.** Register `victim@yourdomain` on the site *without* verifying it,
   set your own password, and stop. Now perform the victim's first-time **social login**
   (Google/Telegram) for that same email. If the provider-login *links into* your
   pre-created account instead of creating a fresh one, you retain access after they take
   over - full ATO with zero victim interaction.
2. **Unverified-email linking.** In your account settings, link a social identity whose
   email you do **not** own. If the app binds it without proving ownership, the inverse
   hijack is possible.
3. **Email-identity collision.** Register variants the app may fold to one identity:
   case (`Victim@` vs `victim@`), plus-tagging (`victim+x@`), a trailing dot, or a unicode
   homoglyph/normalization (`vïctim@`). If two "different" registrations collide onto one
   account, that is an authn boundary break.
4. **Change-without-reconfirmation.** Change your account's email (or phone) to a new
   address and check whether the app re-verifies before the change takes effect. A silent
   change is an account-takeover primitive when chained with the collisions above.

Safety: only addresses/social accounts you own on both sides; never target a real user's
identity. Prove the linking/collision on your own pair and report the mechanism.

## 7. Rules of engagement (non-negotiable)

- **Scope:** `1win.com`, `/betting`, `/casino`, `1w.cash`, `1w.run` only. External payment
  providers are out of scope. ORTHRUS enforces this; do not disable it.
- **Non-destructive by default.** Race/double-spend and payment tampering change real money
  and real state. Only test them with the program's explicit allowance, on **your own
  accounts**, with **minimal amounts**, and stop at the minimum proof. Never touch another
  real user's funds or data beyond a single read-proof with your own second account.
- **No PII exfiltration.** The tool redacts sensitive samples on purpose; keep it that way
  in anything you submit.
- **No severity inflation.** Report impact you can demonstrate. Padding a report with
  informational findings lowers your signal and your payout odds.

---

## Appendix: how the prior 1win report maps to the submission gate

| Finding class from the old report | Gate disposition | Why |
| --- | --- | --- |
| CORS reflection, `Allow-Credentials: false` | hold | no read impact without credentials |
| Missing CSP / nosniff / Referrer-Policy | hold | routinely closed informational |
| Cookie flags on `cdn_cache_id`, `click_id_2`, `device-id` | hold | tracking cookies, not sessions |
| `shadow-api` /resources/... (no body captured) | borderline | verify real API vs SPA catch-all |
| (new) BOLA on `/wallet` leaking balance/email | **submit** | reproduced cross-user access to PII/money |

The old report had zero in the "submit" column. The whole point of the authenticated run
is to put something real there.
