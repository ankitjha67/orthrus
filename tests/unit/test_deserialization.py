"""Tests for serialized-object signature detection."""

from __future__ import annotations

from orthrus.scanners.deserialization import detect_serialized


def test_java_base64():
    assert detect_serialized("rO0ABXNyABFqYXZhLnV0aWwu") == "Java serialized object"


def test_php_serialized():
    assert detect_serialized('a:1:{i:0;s:3:"foo";}') == "PHP serialized object"
    assert detect_serialized('O:8:"stdClass":0:{}') == "PHP serialized object"


def test_dotnet_binaryformatter():
    assert detect_serialized("AAEAAAD/////AQAAAAAAAAAM") == ".NET BinaryFormatter"


def test_python_pickle():
    assert detect_serialized("gASVAAAAAAAAAACMBHRlc3Q") == "Python pickle"


def test_plain_value_is_none():
    assert detect_serialized("just-a-normal-value") is None


def test_too_short_is_none():
    assert detect_serialized("rO0AB") is None
