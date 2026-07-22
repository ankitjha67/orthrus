"""Attack-path chaining - correlate individual findings into kill-chains.

A flat finding list hides *impact*. One SSRF and one exposed Redis look like two
medium issues - together they are remote code execution on the internal network.
This engine matches a scan's findings against a catalog of well-known attack
chains and emits the ones whose every link is present, each with an escalated
severity and a plain-English impact narrative. The result is the handful of
*paths an attacker would actually walk*, prioritised above the raw list.

Pure and deterministic: ``correlate_findings`` takes findings and returns chains.
Each link of a chain must be satisfied by a *distinct* finding (so a chain is
always ≥2 real findings, never one finding counted twice), and - for host-scoped
chains - all links must sit on the same host, so unrelated findings on different
hosts don't fabricate a path.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from urllib.parse import urlsplit

_SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


@dataclass(frozen=True)
class ChainLink:
    label: str
    vuln_types: frozenset[str]


@dataclass(frozen=True)
class ChainRule:
    name: str
    severity: str
    impact: str
    links: tuple[ChainLink, ...]
    same_host: bool = True


def _link(label: str, *vuln_types: str) -> ChainLink:
    return ChainLink(label, frozenset(vuln_types))


# Curated catalog of recognised attack paths. Each rule needs ≥2 distinct
# findings; severities reflect the *combined* impact, not the individual links.
CHAIN_RULES: tuple[ChainRule, ...] = (
    ChainRule(
        "SSRF → internal-service compromise", "critical",
        "The SSRF can reach the exposed internal service, turning request forgery into "
        "data theft or code execution on the internal network.",
        (_link("Server-side request forgery", "ssrf"),
         _link("Exposed internal service", "exposed-service")),
    ),
    ChainRule(
        "Leaked secret → authentication forgery", "critical",
        "A leaked signing key/secret lets an attacker mint their own valid tokens and "
        "authenticate as any user - full authentication bypass.",
        (_link("Exposed secret / signing key", "exposed-secret"),
         _link("Token-based authentication", "jwt", "saml-misconfig", "auth-session")),
    ),
    ChainRule(
        "Session foothold → privilege escalation", "critical",
        "An attacker obtains a session via the authentication weakness, then escalates "
        "authorization to reach other users' or admin data - full account/admin takeover.",
        (_link("Authentication weakness", "jwt", "auth-session", "default-creds", "oauth-misconfig"),
         _link("Authorization bypass", "idor", "broken-authorization",
               "privilege-escalation", "mass-assignment")),
    ),
    ChainRule(
        "Debug surface → remote code execution", "critical",
        "An exposed debug/framework surface combined with an injection primitive yields "
        "server-side code execution.",
        (_link("Debug / framework exposure", "framework-debug", "directory-listing", "exposed-file"),
         _link("Code-execution primitive", "deserialization", "cmd-injection", "ssti", "file-upload")),
    ),
    ChainRule(
        "Source/config disclosure → secret exposure", "high",
        "Exposed source, listings, or debug output reveal secrets/credentials that unlock "
        "deeper access.",
        (_link("Content / source disclosure", "exposed-file", "directory-listing", "framework-debug"),
         _link("Secret exposed", "exposed-secret")),
    ),
    ChainRule(
        "XSS → account takeover", "high",
        "Script injection with weak session/anti-CSRF protections lets an attacker ride a "
        "victim's session and take over the account.",
        (_link("Cross-site scripting", "xss"),
         _link("Weak session protection", "csrf", "cors", "security-headers", "csp")),
    ),
    ChainRule(
        "Open redirect → OAuth token theft", "high",
        "An open redirect on the OAuth flow lets an attacker steal authorization codes/tokens "
        "via redirect_uri abuse - account takeover.",
        (_link("Open redirect", "open-redirect"),
         _link("OAuth misconfiguration", "oauth-misconfig")),
    ),
    ChainRule(
        "Cache poisoning → fleet-wide XSS", "high",
        "A poisoned or deceptive cache serves an injected payload to every visitor, turning a "
        "single injection into a stored, fleet-wide attack.",
        (_link("Cache poisoning", "cache-poisoning", "web-cache-deception", "host-header-injection"),
         _link("Injectable content", "xss", "open-redirect")),
    ),
    ChainRule(
        "Subdomain takeover → session hijack", "high",
        "A hijacked subdomain under a permissive cookie/CORS scope lets an attacker capture "
        "parent-domain sessions.",
        (_link("Subdomain takeover", "subdomain-takeover"),
         _link("Permissive cookie/CORS scope", "cors", "security-headers", "csp")),
    ),
    ChainRule(
        "File read → secret → lateral movement", "high",
        "Path traversal / XXE reads config or key files; the leaked secrets enable lateral "
        "movement or authentication bypass.",
        (_link("File read / traversal", "lfi", "xxe"),
         _link("Secret / credential exposed", "exposed-secret")),
    ),
    ChainRule(
        "OTP brute-force → 2FA bypass (account takeover)", "critical",
        "An OTP verification step with no brute-force protection, plus a way to target valid "
        "accounts, lets an attacker walk the code space and defeat the second factor - full "
        "account and, on a cashier, funds takeover.",
        (_link("OTP without brute-force protection", "otp-security"),
         _link("Account targeting", "account-enumeration", "default-creds", "missing-rate-limit")),
    ),
    ChainRule(
        "Account enumeration → credential stuffing", "high",
        "An enumeration oracle yields a list of valid accounts; missing rate limiting on login "
        "then lets that list be credential-stuffed at scale.",
        (_link("Account enumeration oracle", "account-enumeration"),
         _link("No login throttling", "missing-rate-limit")),
    ),
    ChainRule(
        "Named internal host → SSRF pivot", "critical",
        "A public DNS record exposes an internal host by name/address; an SSRF primitive can "
        "then reach that named internal service directly - request forgery becomes a confirmed "
        "internal pivot.",
        (_link("Internal host disclosed", "internal-ip-disclosure"),
         _link("Server-side request forgery", "ssrf")),
        same_host=False,  # the internal host and the SSRF sink are different assets
    ),
    ChainRule(
        "Monetary tampering → automated financial abuse", "high",
        "A monetary field that accepts out-of-band values, combined with missing throttling or "
        "a non-atomic money operation, lets an attacker automate or amplify financial "
        "manipulation (discounted/negative charges, balance overruns).",
        (_link("Monetary parameter tampering", "parameter-tampering", "business-logic"),
         _link("No throttle / non-atomic op", "missing-rate-limit", "race-condition")),
    ),
    ChainRule(
        "Second-order payload → staff-console takeover", "critical",
        "A stored payload that detonates in a staff/admin console, with weak session or "
        "anti-CSRF protection there, escalates to takeover of a privileged operator account.",
        (_link("Second-order / stored injection", "second-order-injection"),
         _link("Weak session protection", "csrf", "cors", "security-headers", "csp")),
    ),
)


@dataclass
class ChainStep:
    label: str
    vuln_type: str
    url: str


@dataclass
class AttackChain:
    name: str
    severity: str
    host: str
    impact: str
    steps: list[ChainStep] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "severity": self.severity,
            "host": self.host,
            "impact": self.impact,
            "steps": [
                {"label": s.label, "vuln_type": s.vuln_type, "url": s.url} for s in self.steps
            ],
        }


def _vt(finding) -> str:
    return getattr(finding, "vuln_type", "")


def _host_of(url: str) -> str:
    # Key on hostname (not netloc) so the same host correlates across ports -
    # an SSRF on app:443 and an exposed Redis on app:6379 are one host.
    return (urlsplit(url or "").hostname or "").lower()


def _match(rule: ChainRule, findings: list) -> list[ChainStep] | None:
    """Satisfy each link with a distinct finding, in order, or return None."""
    used: set[int] = set()
    steps: list[ChainStep] = []
    for link in rule.links:
        candidate = next(
            (f for f in findings if _vt(f) in link.vuln_types and id(f) not in used), None
        )
        if candidate is None:
            return None
        used.add(id(candidate))
        steps.append(ChainStep(link.label, _vt(candidate), getattr(candidate, "url", "")))
    return steps


def correlate_findings(findings: list) -> list[AttackChain]:
    """Return the attack chains present in ``findings``, highest-severity first."""
    by_host: dict[str, list] = defaultdict(list)
    for f in findings:
        by_host[_host_of(getattr(f, "url", ""))].append(f)

    chains: list[AttackChain] = []
    for rule in CHAIN_RULES:
        if rule.same_host:
            for host, host_findings in by_host.items():
                steps = _match(rule, host_findings)
                if steps:
                    chains.append(AttackChain(rule.name, rule.severity, host, rule.impact, steps))
        else:
            steps = _match(rule, findings)
            if steps:
                chains.append(AttackChain(rule.name, rule.severity, "(cross-host)", rule.impact, steps))

    chains.sort(key=lambda c: (-_SEV_ORDER.get(c.severity, 0), c.name, c.host))
    return chains


@dataclass
class ChainReport:
    chains: list[AttackChain]

    def summary(self) -> str:
        if not self.chains:
            return "no attack chains correlated"
        crit = sum(1 for c in self.chains if c.severity == "critical")
        return f"{len(self.chains)} attack path(s) correlated ({crit} critical)"

    def to_dict(self) -> dict:
        return {"summary": self.summary(), "chains": [c.to_dict() for c in self.chains]}


def build_chain_report(findings: list) -> ChainReport:
    return ChainReport(correlate_findings(findings))


__all__ = [
    "ChainLink",
    "ChainRule",
    "ChainStep",
    "AttackChain",
    "ChainReport",
    "CHAIN_RULES",
    "correlate_findings",
    "build_chain_report",
]
