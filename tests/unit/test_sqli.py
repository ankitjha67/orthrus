"""Tests for SQLi pure detectors."""

from __future__ import annotations

from orthrus.scanners.sqli import boolean_injectable, detect_sql_error, error_status_signal


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


def test_boolean_injectable_when_comment_truncates_other_param():
    # ginandjuice regression: a `-- -` comment truncates a second parameter so the
    # TRUE response diverges from the baseline, but FALSE still matches it.
    base = "no results " * 50           # baseline had a second filter applied -> empty
    true_resp = "product card " * 300   # comment dropped the filter -> full list
    false_resp = "no results " * 50     # AND 1=2 -> empty, matches baseline
    assert boolean_injectable(base, true_resp, false_resp) is True


def test_boolean_injectable_false_when_neither_side_matches_baseline():
    # Guard against random triple-divergence being mistaken for injection.
    base = "A" * 300
    assert boolean_injectable(base, "B" * 600, "C" * 90) is False


def test_error_status_signal_broken_fixed_quote():
    assert error_status_signal(200, 500, 200) is True     # ' -> 500, '' -> 200
    assert error_status_signal(200, 500, 500) is False    # '' also errors -> not SQL
    assert error_status_signal(500, 500, 200) is False    # baseline already 5xx
    assert error_status_signal(200, 200, 200) is False    # single quote didn't error
