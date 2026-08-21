"""Live secret validators (spec classifier + injected-request validation)."""

from __future__ import annotations

from orthrus.intel.secret_validators import (
    VALIDATORS,
    classify_validation,
    validate_secret,
    validator_for,
)


def _request(status: int, body: str):
    async def req(method: str, url: str, headers: dict[str, str]):
        return (status, body)

    return req


# ----------------------------------------------------------------- pure logic
def test_validator_for_matches_scanner_labels() -> None:
    assert validator_for("GitHub personal access token").provider == "GitHub"
    assert validator_for("Slack token").provider == "Slack"
    assert validator_for("AWS access key").provider == "AWS"
    assert validator_for("some unknown secret") is None


def test_classify_github() -> None:
    gh = VALIDATORS["github"]
    assert classify_validation(gh, 200, '{"login":"octocat"}') == "live"
    assert classify_validation(gh, 401, '{"message":"Bad credentials"}') == "invalid"
    assert classify_validation(gh, 200, "{}") == "unknown"  # 200 but no login signal


def test_classify_slack_uses_body_ok_flag() -> None:
    slack = VALIDATORS["slack"]
    assert classify_validation(slack, 200, '{"ok":true,"user_id":"U1"}') == "live"
    assert classify_validation(slack, 200, '{"ok":false,"error":"invalid_auth"}') == "invalid"


# ------------------------------------------------------------- validate_secret
async def test_validate_live_github() -> None:
    r = await validate_secret("GitHub token", "ghp_x", _request(200, '{"login":"octocat"}'))
    assert r.verdict == "live" and r.provider == "GitHub" and r.status == 200


async def test_validate_invalid_github() -> None:
    r = await validate_secret("GitHub token", "ghp_x", _request(401, '{"message":"Bad credentials"}'))
    assert r.verdict == "invalid"


async def test_aws_is_unsupported_without_signing() -> None:
    r = await validate_secret("AWS access key", "AKIAxxx", _request(200, ""))
    assert r.verdict == "unsupported" and "signing" in r.note.lower()


async def test_unknown_type_is_unsupported() -> None:
    r = await validate_secret("mystery blob", "x", _request(200, ""))
    assert r.verdict == "unsupported"


async def test_secret_is_never_echoed_in_result() -> None:
    secret = "ghp_supersecretvalue_1234567890"
    r = await validate_secret("GitHub token", secret, _request(200, '{"login":"x"}'))
    assert secret not in r.note and secret not in str(r)
