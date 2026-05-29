"""Tests for the LFI signature detector."""

from __future__ import annotations

from orthrus.scanners.lfi import detect_lfi


def test_detect_etc_passwd():
    body = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"
    assert detect_lfi(body) == "/etc/passwd"


def test_detect_win_ini():
    body = "; for 16-bit app support\n[fonts]\n[extensions]\n"
    assert detect_lfi(body) == "C:\\windows\\win.ini"


def test_clean_body_is_none():
    assert detect_lfi("<html><body>Welcome</body></html>") is None
