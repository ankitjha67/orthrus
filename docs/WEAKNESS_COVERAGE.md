# Weakness coverage (HackerOne CWE/CAPEC taxonomy)

The HackerOne **"Weakness"** dropdown is the full **CWE + CAPEC dictionary** (~1,500
entries). It is a *taxonomy for labelling a report*, not a checklist a scanner detects -
and it deliberately spans hardware, firmware, network, wireless, mobile-internal, and
physical/social weaknesses that **no black-box web/API DAST can observe over HTTP**.

So the honest answer to "does ORTHRUS cover every weakness?" is **no, and it shouldn't**:
it covers the **web/API-relevant subset** it can actually produce evidence for, maps each
to the exact dropdown label (`orthrus/bounty/weakness.py`, used by the `--platform
hackerone` report), and names below what is out of scope so "0 findings" stays honest.

Source of truth: `orthrus/bounty/weakness.py` (`WEAKNESS_LABELS`). A regression test fails
if any scanner emits a CWE not in that map.

## Covered - the CWEs ORTHRUS detects (mapped to HackerOne labels)

**Injection** - SQL (CWE-89), NoSQL (CWE-943), OS command (CWE-78), code (CWE-94),
generic injection (CWE-74), LDAP (CWE-90), XPath (CWE-643), SSTI (CWE-1336), XXE
(CWE-611), CSV/formula (CWE-1236), LLM prompt (CWE-1427).

**Cross-site & request-level** - XSS reflected/DOM/stored (CWE-79), CSRF (CWE-352), open
redirect (CWE-601), HTTP response splitting (CWE-113), request smuggling (CWE-444), header
injection (CWE-644), HTTP parameter pollution (CWE-235).

**Access control / authorization** - IDOR/BOLA (CWE-639), improper authorization / BFLA
(CWE-285), path traversal (CWE-22), mass assignment (CWE-915), assumed-immutable parameter
tampering (CWE-472).

**Authentication / session** - JWT signature (CWE-347), client-side auth / OTP-result trust
(CWE-603), no brute-force protection (CWE-307), user enumeration (CWE-204), default creds
(CWE-1392), hard-coded creds (CWE-798), weak entropy (CWE-331).

**Business logic / abuse** - race condition (CWE-362), no rate limiting (CWE-799),
resource exhaustion / GraphQL DoS (CWE-770, CWE-674).

**Server-side & SSRF** - SSRF (CWE-918), deserialization (CWE-502), prototype pollution
(CWE-1321), unrestricted file upload (CWE-434).

**Information exposure** - sensitive info exposure (CWE-200), verbose errors (CWE-209),
externally-accessible sensitive file (CWE-538), directory listing (CWE-548), cacheable
sensitive response / web-cache deception (CWE-525), resource-to-wrong-sphere incl.
internal-IP & origin exposure (CWE-668), reverse-DNS trust (CWE-350), untrusted script
inclusion / SRI (CWE-829).

**Configuration / transport** - CORS misconfig (CWE-942), WebSocket origin (CWE-1385),
missing security headers / protection-mechanism failure (CWE-693), active debug code
(CWE-489), cleartext transmission (CWE-319), weak crypto strength (CWE-326), generic
misconfiguration (CWE-16).

**Supply chain** - known-vulnerable components / SCA (CWE-1035).

Every finding already carries its `cwe`; `--platform hackerone` now renders the readable
label (e.g. `Cross-site Scripting (XSS) (cwe-79)`) so it maps one-to-one onto the dropdown.

## Out of scope by design (structurally undetectable by a web/API DAST)

| Family | Why, and what to use instead |
|---|---|
| **Memory safety** (buffer over/underflow, use-after-free, uninitialised pointers) | Needs source/binary analysis or native fuzzing - not visible over HTTP. |
| **Hardware / firmware** (BIOS, ASIC, firmware, sentinels) | A different domain entirely. |
| **Network / protocol** (BGP disabling, Blue Boxing, link-layer amplification) | Not HTTP-observable. |
| **Wireless** (Bluetooth impersonation/BIAS, RF) | Out of a web scanner's reach. |
| **Mobile-internal** (Android activity/intent hijack, thick-client internals) | Needs the APK + a device (see the mobile methodology). |
| **Physical / social / process** (malicious shared webroot, altered software update, phishing) | Human/process, not automatable here. |

These are not gaps to "build" - shipping a detector that can't observe the weakness would
be fake coverage. For anything in this table, test it by hand or with the right tool
(disassembler/fuzzer, mobile rig, network lab) and label the report from the dropdown; the
`weakness.py` map still gives you the CWE for the web-adjacent ones.
