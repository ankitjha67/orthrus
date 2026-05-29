"""Tests for the CSRF token-presence heuristic."""

from __future__ import annotations

from orthrus.scanners.csrf import form_has_csrf_token


def test_form_with_csrf_token():
    assert form_has_csrf_token(["username", "password", "csrf_token"]) is True


def test_form_with_django_token():
    assert form_has_csrf_token(["comment", "csrfmiddlewaretoken"]) is True


def test_form_case_insensitive():
    assert form_has_csrf_token(["user", "__RequestVerificationToken"]) is True


def test_form_without_token():
    assert form_has_csrf_token(["q"]) is False
    assert form_has_csrf_token(["username", "password"]) is False
