"""Celery tasks: run a full ORTHRUS scan for a single target on a worker."""

from __future__ import annotations

import asyncio
from typing import Any

from orthrus.distributed.celery_app import app


@app.task(name="orthrus.scan_target")
def scan_target(config_json: dict[str, Any]) -> dict[str, Any]:
    """Run recon -> scan -> exploit -> report for one target. Returns a summary."""
    from orthrus.core.config import ScanConfig, get_settings
    from orthrus.core.orchestrator import Orchestrator

    config = ScanConfig(**config_json)

    async def _run() -> dict[str, Any]:
        orch = Orchestrator(config, get_settings())
        status = "completed"
        try:
            await orch.setup()
            await orch.run_recon()
            await orch.run_scan()
            await orch.run_exploit()
            output = config.output or f"report-{orch.scan_id}"
            await orch.run_report(config.report_format, output)
        except Exception:
            status = "failed"
        finally:
            await orch.teardown(status)
        counts = await orch.store.severity_counts(orch.scan_id) if orch.ctx else {}
        return {
            "scan_id": orch.scan_id,
            "target": config.target,
            "status": status,
            "severity_counts": counts,
        }

    return asyncio.run(_run())


__all__ = ["scan_target"]
