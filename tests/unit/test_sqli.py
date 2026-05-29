"""Tests for SQLi pure detectors."""

from __future__ import annotations

from orthrus.scanners.sqli import boolean_injectable, detect_sql_error


def test_detect_mysql_error():
    body = "You have an error in your SQL syntax; check the manual that corresponds to your MySQL"
    assert detect_sql_error(body) == "MySQL"


def test_detect_postgres_error():
    assert detect_sql_error("ERROR: unterminated quoted string at or near \"'\"") == "PostgreSQL"


def test_detect_oracle_error():
    assert detect_sql_error("ORA-01756: quoted string not properly terminated") == "Oracle"


def test_detect_mssql_error():
    assert (
        detect_sql_error("Unclosed quotation mark after the character string")
        == "Microsoft SQL Server"
    )


def test_no_error_is_none():
    assert detect_sql_error("<html>welcome user</html>") is None


def test_boolean_injectable_true():
    base = "rows: " + "x" * 1000
    true_resp = "rows: " + "x" * 1000
    false_resp = "no rows"
    assert boolean_injectable(base, true_resp, false_resp) is True


def test_boolean_injectable_false_when_all_same():
    body = "static page " * 100
    assert boolean_injectable(body, body, body) is False
