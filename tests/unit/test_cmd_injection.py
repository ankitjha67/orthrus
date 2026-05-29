"""Tests for the command-injection output detector."""

from __future__ import annotations

from orthrus.scanners.cmd_injection import cmd_executed

CANARY = "ORTHRUSDEADBEEF"


def test_canary_as_output_is_execution():
    assert cmd_executed(CANARY, f"<pre>{CANARY}\n</pre>") is True


def test_reflected_echo_command_is_not_execution():
    assert cmd_executed(CANARY, f"you sent: ; echo {CANARY}") is False


def test_absent_canary():
    assert cmd_executed(CANARY, "<html>nothing</html>") is False
