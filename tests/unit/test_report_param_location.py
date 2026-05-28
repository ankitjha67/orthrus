"""Reports must distinguish query-param from form-body (POST) vulnerabilities.

Exercises the full persist -> load -> report-context chain so a regression in
either the ORM column or the generator dict is caught.
"""

from __future__ import annotations

from hydra.core.schemas import Finding, ParamLocation, Severity
from hydra.db.store import Store
from hydra.reporting.generator import _build_context, _write_csv


async def test_report_surfaces_body_param_location(tmp_path):
    store = Store(f"sqlite+aiosqlite:///{(tmp_path / 'hydra.db').as_posix()}")
    await store.init()
    try:
        scan_id = "scan-1"
        await store.create_scan(scan_id, "http://target", {}, {})
        await store.add_finding(
            scan_id,
            Finding(
                vuln_type="xss",
                title="Reflected XSS in comment form",
                severity=Severity.HIGH,
                url="http://target/comment",
                parameter="comment",
                param_location=ParamLocation.BODY,
            ),
        )

        context = await _build_context(store, scan_id, None, None)
    finally:
        await store.close()

    assert len(context["findings"]) == 1
    fdict = context["findings"][0]
    assert fdict["param_location"] == "body"

    csv_text = _write_csv(context["findings"])
    header, row = csv_text.splitlines()[:2]
    assert "param_location" in header.split(",")
    assert "body" in row.split(",")
