"""Bug-bounty authorization + kill-list guardrails."""

from __future__ import annotations

import pytest

from orthrus.bounty import killlist
from orthrus.bounty.authorization import (
    AuthKind,
    AuthorizationError,
    classify_authorization,
    resolve_authorization,
    scope_is_private_lab,
)

# ----------------------------------------------------------------- authorization

def test_classify_platform_and_forms():
    assert classify_authorization("https://hackerone.com/acme").kind is AuthKind.HACKERONE
    assert classify_authorization("bugcrowd.com/acme").kind is AuthKind.BUGCROWD
    assert classify_authorization("https://app.intigriti.com/x").kind is AuthKind.INTIGRITI
    assert classify_authorization("signed:engagement-letter.pdf").kind is AuthKind.SIGNED
    assert classify_authorization("direct:emailed permission from CISO").kind is AuthKind.DIRECT
    assert classify_authorization("self-owned-lab").kind is AuthKind.SELF_LAB
    assert classify_authorization("https://acme.com/security.txt").kind is AuthKind.DIRECT  # policy URL


def test_classify_rejects_garbage():
    for bad in ("", "   ", "just some words"):
        with pytest.raises(AuthorizationError):
            classify_authorization(bad)


def test_scope_is_private_lab():
    assert scope_is_private_lab(["127.0.0.1", "localhost", "10.1.2.3", "192.168.0.5"]) is True
    assert scope_is_private_lab(["example.com"]) is False
    assert scope_is_private_lab(["127.0.0.1", "example.com"]) is False  # one public host is enough
    assert scope_is_private_lab([]) is False


def test_resolve_requires_auth_for_public_scope():
    # explicit source always wins
    assert resolve_authorization("self-owned-lab", ["example.com"]).kind is AuthKind.SELF_LAB
    # private scope needs no source
    assert resolve_authorization(None, ["127.0.0.1"]).kind is AuthKind.SELF_LAB
    # public scope with no source is refused
    with pytest.raises(AuthorizationError):
        resolve_authorization(None, ["example.com"])


# ----------------------------------------------------------------- kill-list

def test_killlist_classifies_sensitive():
    assert killlist.classify("nasa.gov").category == "government-military"
    assert killlist.classify("army.mil").category == "government-military"
    assert killlist.classify("service.gov.uk").category == "government-military"
    assert killlist.classify("mit.edu").category == "education-health"
    assert killlist.classify("central-hospital.com").category == "education-health"
    assert killlist.classify("bank.ru").category == "sanctioned"
    assert killlist.classify("shop.example.com") is None  # ordinary host is fine


def test_killlist_screen_respects_acknowledgment():
    hosts = ["shop.example.com", "portal.example.gov", "army.mil"]
    blocked = killlist.screen(hosts)
    assert {d.host for d in blocked} == {"portal.example.gov", "army.mil"}
    # attesting authorization for one clears just that one
    blocked2 = killlist.screen(hosts, acknowledged={"army.mil"})
    assert {d.host for d in blocked2} == {"portal.example.gov"}
