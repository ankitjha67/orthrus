"""Live secret validators - turn a *detected* secret into a *verified* one.

secret_scanner flags candidate keys/tokens; a huge fraction are already-rotated,
example, or test values. This upgrades detection to verification: hit the
credential's **own provider** with a minimal read-only call and classify the
response as ``live`` / ``invalid`` / ``unknown``. A live key is a critical,
CONFIRMED finding; an invalid one can be de-prioritised.

Design + safety:
  - The HTTP call is performed by an **injected** async ``request`` callable, not
    a hard-wired client. Tests inject a mock; a real engagement injects a client
    that is allow-listed to the provider hosts. Nothing here calls out on its own,
    and validation is strictly opt-in (it contacts a third party, unlike the rest
    of ORTHRUS which stays in the target's scope).
  - Pure ``classify_validation`` is fully deterministic and unit-tested.
  - The secret is never echoed back in results - only the provider + verdict.
  - AWS-style credentials need SigV4 request signing and are reported
    ``unsupported`` here rather than mis-validated.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

# request(method, url, headers) -> (status_code, body_text)
Request = Callable[[str, str, dict[str, str]], Awaitable[tuple[int, str]]]


@dataclass(frozen=True)
class ValidatorSpec:
    provider: str
    method: str
    url: str
    header_name: str
    header_template: str  # "{secret}" is replaced with the raw secret
    live_status: tuple[int, ...] = (200,)
    invalid_status: tuple[int, ...] = (401, 403)
    live_body_signal: str | None = None
    invalid_body_signal: str | None = None
    requires_signing: bool = False
    extra_headers: dict[str, str] = field(default_factory=dict)


# Keyed by a substring matched against the secret type/label the scanner emits.
VALIDATORS: dict[str, ValidatorSpec] = {
    "github": ValidatorSpec(
        "GitHub", "GET", "https://api.github.com/user", "Authorization", "token {secret}",
        live_body_signal='"login"',
        extra_headers={"User-Agent": "orthrus", "Accept": "application/vnd.github+json"},
    ),
    "gitlab": ValidatorSpec(
        "GitLab", "GET", "https://gitlab.com/api/v4/user", "PRIVATE-TOKEN", "{secret}",
        live_body_signal='"username"',
    ),
    "slack": ValidatorSpec(
        "Slack", "POST", "https://slack.com/api/auth.test", "Authorization", "Bearer {secret}",
        live_status=(200,), invalid_status=(),
        live_body_signal='"ok":true', invalid_body_signal='"ok":false',
    ),
    "stripe": ValidatorSpec(
        "Stripe", "GET", "https://api.stripe.com/v1/balance", "Authorization", "Bearer {secret}",
    ),
    "openai": ValidatorSpec(
        "OpenAI", "GET", "https://api.openai.com/v1/models", "Authorization", "Bearer {secret}",
    ),
    "anthropic": ValidatorSpec(
        "Anthropic", "GET", "https://api.anthropic.com/v1/models", "x-api-key", "{secret}",
        extra_headers={"anthropic-version": "2023-06-01"},
    ),
    "sendgrid": ValidatorSpec(
        "SendGrid", "GET", "https://api.sendgrid.com/v3/scopes", "Authorization", "Bearer {secret}",
    ),
    "npm": ValidatorSpec(
        "npm", "GET", "https://registry.npmjs.org/-/whoami", "Authorization", "Bearer {secret}",
        live_body_signal='"username"',
    ),
    "aws": ValidatorSpec(
        "AWS", "POST", "https://sts.amazonaws.com/", "Authorization", "{secret}",
        requires_signing=True,
    ),
}


@dataclass(frozen=True)
class SecretValidation:
    secret_type: str
    verdict: str  # "live" | "invalid" | "unknown" | "unsupported"
    provider: str | None
    status: int | None
    note: str


def validator_for(secret_type_or_label: str) -> ValidatorSpec | None:
    low = (secret_type_or_label or "").lower()
    for key, spec in VALIDATORS.items():
        if key in low:
            return spec
    return None


def classify_validation(spec: ValidatorSpec, status: int, body: str) -> str:
    """Deterministically map a provider response to live / invalid / unknown."""
    low = (body or "").lower()
    if spec.invalid_body_signal and spec.invalid_body_signal.lower() in low:
        return "invalid"
    if status in spec.invalid_status:
        return "invalid"
    if status in spec.live_status:
        if spec.live_body_signal and spec.live_body_signal.lower() not in low:
            return "unknown"
        return "live"
    return "unknown"


async def validate_secret(secret_type: str, secret: str, request: Request) -> SecretValidation:
    """Validate one secret via its provider, using the injected ``request`` callable."""
    spec = validator_for(secret_type)
    if spec is None:
        return SecretValidation(secret_type, "unsupported", None, None, "no validator for this type")
    if spec.requires_signing:
        return SecretValidation(
            secret_type, "unsupported", spec.provider, None, "requires request signing (SigV4)"
        )
    headers = {spec.header_name: spec.header_template.replace("{secret}", secret), **spec.extra_headers}
    status, body = await request(spec.method, spec.url, headers)
    verdict = classify_validation(spec, status, body)
    return SecretValidation(
        secret_type, verdict, spec.provider, status, f"{spec.method} {spec.provider} -> HTTP {status}"
    )


__all__ = [
    "Request",
    "ValidatorSpec",
    "SecretValidation",
    "VALIDATORS",
    "validator_for",
    "classify_validation",
    "validate_secret",
]
