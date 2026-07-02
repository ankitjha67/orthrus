# Contributing to ORTHRUS

Thanks for your interest. ORTHRUS is an integrated, incrementally-built DAST
framework, and contributions — bug reports, false-positive fixes, new detectors,
docs — are welcome.

## Ground rule: authorized-use only

ORTHRUS sends real attack payloads and actively confirms exploitation. Every
contribution must respect that:

- **Scope enforcement is load-bearing.** Do not weaken, bypass, or route around
  the deny-by-default scope check (`orthrus/utils/scope.py`). Every outgoing
  request must validate against scope before it is sent.
- **Non-destructive by default.** Exploitation-confirmation proves a finding
  (canary values, OOB callbacks, reading `/etc/passwd`) — it does not damage,
  persist, or exfiltrate.
- **No secret emission.** Confirmers report *whether* auth/forgery succeeded,
  never the credential or key. Redact secrets in findings and reports.
- We will not accept features whose primary purpose is malicious — detection
  evasion for its own sake, autonomous offense without bounds, mass/untargeted
  scanning, or anything designed to hide an attacker from a defender.

Test only against systems you own or are authorized to test. The bundled
`tests/integration/reflecting_target.py` (127.0.0.1) is the sanctioned target for
exercising scanners; `example.com` (RFC 2606) is fine for a single benign smoke.

## Dev setup

```bash
git clone https://github.com/ankitjha67/orthrus.git
cd orthrus
python -m venv .venv
# Windows: .venv\Scripts\activate   |   POSIX: source .venv/bin/activate
pip install -e ".[dev]"
# Optional feature groups, add as needed:
#   .[scanners]  pyjwt/cryptography/sslyze/paramiko/websockets
#   .[browser]   Playwright (DOM/stored XSS) — then: playwright install chromium
#   .[cloud]     boto3 (read-only AWS collection for `orthrus cloud --live`)
#   .[api] .[mcp] .[recon] .[distributed] .[postgres]
```

Requires Python 3.11+.

## Quality gates (must be green before you open a PR)

CI runs exactly these two — match them locally:

```bash
ruff check orthrus tests      # E,F,I,UP,B,ASYNC · line-length 100
pytest -q                     # all tests must pass
```

There is **no mypy gate** in CI. Keep the working tree `ruff`-clean and the suite
green; a PR that breaks either won't merge.

## Adding a scanner (the common case)

1. Create `orthrus/scanners/<name>.py` with a `BaseScanner` subclass: set `name`,
   `vuln_type`, `min_aggressiveness`, and implement the detector. Keep the core
   detection logic **pure** (a function over request/response) so it unit-tests
   without a network.
2. Register it: `@register` from `orthrus.scanners.registry`, and make sure it's
   imported so the registry populates (`orthrus/scanners/__init__.py`).
3. Add a pure unit test in `tests/unit/` for the detector, plus — if it's an active
   scanner — a matching vulnerable route in `tests/integration/reflecting_target.py`
   so the end-to-end flow is exercised.
4. Run the gates. If you added a new `vuln_type`, consider a remediation entry in
   `orthrus/reporting/patches.py`.

The same pattern applies to recon modules (`orthrus/recon/`), exploit confirmers
(`orthrus/exploits/`), and reporters — each has a registry and a base class.

## Pull requests

- Branch off `main`; keep PRs focused.
- Write a clear description of *what* and *why*. Commit messages follow
  Conventional Commits (`feat:`, `fix:`, `docs:`, `chore:`…), as in the history.
- Include tests for behavior changes and update the docs/counts if you add a
  scanner, command, or module (`README.md`, `docs/PRD.md`, `docs/PROOF.md`).
- Be responsive to review. Harsh-but-fair feedback on detection quality and
  false-positive rates is the whole point.

## Reporting bugs & security issues

- Functional bugs / false positives → open a GitHub issue with a reproduction
  (ideally against the reflecting target).
- **Security vulnerabilities in ORTHRUS itself** → follow [SECURITY.md](SECURITY.md);
  do not file them as public issues.

By contributing, you agree your contributions are licensed under the repository's
[MIT License](LICENSE).
