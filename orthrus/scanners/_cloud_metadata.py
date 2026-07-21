"""Cloud-metadata credential extraction (SSRF → IMDS escalation).

When SSRF reaches a cloud instance's metadata service, the prize is not the
metadata itself but the **temporary credentials** it hands out: an attacker who
reads them can act as the instance's role across the cloud account. This module
turns a metadata *response body* into the concrete credential material it leaked
- redacting the secret portions so ORTHRUS proves the exposure without ever
storing a usable key.

Pure and offline: ``extract_credentials`` takes a body string and returns the
provider + the (redacted) credential fields, or ``None``. Used by the SSRF
scanner to escalate a "reached metadata" finding (HIGH) to a confirmed
"credential theft" finding (CRITICAL).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# AWS IMDS IAM credentials JSON.
_AWS_AKID = re.compile(r'"AccessKeyId"\s*:\s*"([^"]+)"')
_AWS_SAK = re.compile(r'"SecretAccessKey"\s*:\s*"([^"]+)"')
_AWS_TOKEN = re.compile(r'"Token"\s*:\s*"([^"]+)"')
_AWS_EXP = re.compile(r'"Expiration"\s*:\s*"([^"]+)"')

# Azure IMDS managed-identity token (has a client_id alongside the token).
_AZ_CLIENT = re.compile(r'"client_id"\s*:\s*"([0-9a-fA-F-]{36})"')
_ACCESS_TOKEN = re.compile(r'"access_token"\s*:\s*"([^"]+)"')

# GCP service-account OAuth token.
_GCP_YA29 = re.compile(r'ya29\.[A-Za-z0-9._\-]+')
_BEARER = re.compile(r'"token_type"\s*:\s*"Bearer"', re.IGNORECASE)


@dataclass
class CloudCreds:
    provider: str          # aws / gcp / azure
    summary: str
    fields: dict[str, str]  # secret values already redacted


def redact_secret(value: str, keep: int = 4) -> str:
    """Render a secret as a non-recoverable preview (prefix + length only)."""
    if not value:
        return ""
    return f"{value[:keep]}…({len(value)} chars)"


def extract_credentials(body: str) -> CloudCreds | None:
    """Extract leaked cloud credentials from a metadata response, redacted.

    Returns the first provider matched (AWS, then Azure, then GCP - Azure is
    checked before GCP because both carry an ``access_token`` but only Azure
    carries a ``client_id``). Secret material (SecretAccessKey, session/OAuth
    tokens) is redacted; the AccessKeyId is kept in full as it is an identifier,
    not a secret, and naming the role is useful triage.
    """
    if not body:
        return None

    akid = _AWS_AKID.search(body)
    sak = _AWS_SAK.search(body)
    if akid and sak:
        fields = {
            "AccessKeyId": akid.group(1),  # identifier, not a secret
            "SecretAccessKey": redact_secret(sak.group(1)),
        }
        if (tok := _AWS_TOKEN.search(body)):
            fields["Token"] = redact_secret(tok.group(1))
        if (exp := _AWS_EXP.search(body)):
            fields["Expiration"] = exp.group(1)
        return CloudCreds("aws", f"AWS IAM credentials ({akid.group(1)})", fields)

    client = _AZ_CLIENT.search(body)
    atok = _ACCESS_TOKEN.search(body)
    if client and atok:
        return CloudCreds(
            "azure", "Azure managed-identity access token",
            {"client_id": client.group(1), "access_token": redact_secret(atok.group(1))},
        )

    if atok and (_GCP_YA29.search(body) or _BEARER.search(body)):
        return CloudCreds(
            "gcp", "GCP service-account OAuth token",
            {"access_token": redact_secret(atok.group(1))},
        )

    return None


__all__ = ["CloudCreds", "extract_credentials", "redact_secret"]
