"""Capture an authenticated session from a HAR export -> identities.json.

One HAR from the logged-in browser yields both the API surface (--import-spec) and
the session. These tests cover the extraction (richest cookie wins, host-scoped,
bearer + UA), the identity serialisation, and the `orthrus capture-auth` CLI writing
a two-identity file.
"""

from __future__ import annotations

import json

from click.testing import CliRunner

from orthrus.core.auth_capture import auth_from_har, merge_identity, to_identity
from orthrus.main import cli


def _har(*entries: dict) -> dict:
    return {"log": {"entries": [{"request": e} for e in entries]}}


def _req(url: str, cookie: str = "", ua: str = "", bearer: str = "",
         cookies: list | None = None) -> dict:
    headers = []
    if cookie:
        headers.append({"name": "Cookie", "value": cookie})
    if ua:
        headers.append({"name": "User-Agent", "value": ua})
    if bearer:
        headers.append({"name": "Authorization", "value": f"Bearer {bearer}"})
    req: dict = {"url": url, "headers": headers}
    if cookies is not None:
        req["cookies"] = cookies
    return req


def test_picks_richest_cookie_and_captures_ua_and_bearer():
    har = _har(
        _req("https://1win.com/api/wallet", cookie="cf_clearance=abc; session=S1", ua="EdgeUA"),
        _req("https://1win.com/api/bets",
             cookie="cf_clearance=abc; session=S1; x=1; y=2", ua="EdgeUA", bearer="eyJtok"),
        _req("https://other.example/x", cookie="third=party"),   # different host -> ignored
    )
    mat = auth_from_har(har, "1win.com")
    assert mat is not None and mat.ok
    assert mat.cookie == "cf_clearance=abc; session=S1; x=1; y=2"   # the richest, and it had the token
    assert mat.user_agent == "EdgeUA" and mat.token == "eyJtok"
    assert "third=party" not in mat.cookie


def test_subdomain_of_target_host_matches():
    har = _har(_req("https://www.1win.com/", cookie="session=SUB"))
    mat = auth_from_har(har, "1win.com")
    assert mat is not None and mat.cookie == "session=SUB"


def test_cookie_falls_back_to_request_cookie_list():
    har = _har(_req("https://1win.com/", cookies=[{"name": "a", "value": "1"},
                                                  {"name": "b", "value": "2"}]))
    mat = auth_from_har(har, "1win.com")
    assert mat is not None and mat.cookie == "a=1; b=2"


def test_returns_none_without_a_matching_session():
    assert auth_from_har(_har(_req("https://elsewhere.com/", cookie="x=1")), "1win.com") is None
    assert auth_from_har("not json", "1win.com") is None
    assert auth_from_har(_har(_req("https://1win.com/")), "1win.com") is None  # no creds


def test_to_identity_and_merge():
    har = _har(_req("https://1win.com/", cookie="session=S", ua="UA", bearer="tok"))
    entry = to_identity("userA", auth_from_har(har, "1win.com"))
    assert entry == {"name": "userA", "cookie": "session=S", "token": "tok",
                     "headers": {"User-Agent": "UA"}}
    merged = merge_identity([{"name": "userA", "cookie": "old"}], entry)
    assert len(merged) == 1 and merged[0]["cookie"] == "session=S"   # replaced by name
    merged2 = merge_identity(merged, {"name": "userB", "cookie": "session=T"})
    assert [i["name"] for i in merged2] == ["userA", "userB"]


def test_cli_capture_auth_builds_two_identity_file(tmp_path):
    har_a = tmp_path / "a.har"
    har_a.write_text(json.dumps(_har(_req("https://1win.com/api", cookie="session=AAA", ua="UA"))))
    har_b = tmp_path / "b.har"
    har_b.write_text(json.dumps(_har(_req("https://1win.com/api", cookie="session=BBB", ua="UA"))))
    out = tmp_path / "identities.json"
    runner = CliRunner()

    r1 = runner.invoke(cli, ["capture-auth", "--har", str(har_a), "--host", "1win.com",
                             "--name", "userA-baseline", "--out", str(out)])
    r2 = runner.invoke(cli, ["capture-auth", "--har", str(har_b), "--host", "1win.com",
                             "--name", "userB-attacker", "--out", str(out)])
    assert r1.exit_code == 0 and r2.exit_code == 0, (r1.output, r2.output)
    identities = json.loads(out.read_text(encoding="utf-8"))
    assert [i["name"] for i in identities] == ["userA-baseline", "userB-attacker"]
    assert identities[0]["cookie"] == "session=AAA" and identities[1]["cookie"] == "session=BBB"


def test_cli_capture_auth_errors_when_no_session(tmp_path):
    har = tmp_path / "empty.har"
    har.write_text(json.dumps(_har(_req("https://elsewhere.com/", cookie="x=1"))))
    r = CliRunner().invoke(cli, ["capture-auth", "--har", str(har), "--host", "1win.com"])
    assert r.exit_code == 1
