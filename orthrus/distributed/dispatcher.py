"""Target loading, partitioning, and Celery dispatch for distributed scans."""

from __future__ import annotations

import os
from typing import Any

from orthrus.core.config import ScanConfig


def partition_targets(targets: list[str], workers: int) -> list[list[str]]:
    """Round-robin targets into up to ``workers`` buckets (for tracking/logging)."""
    workers = max(1, workers)
    n = min(workers, len(targets)) or 1
    buckets: list[list[str]] = [[] for _ in range(n)]
    for i, target in enumerate(targets):
        buckets[i % n].append(target)
    return buckets


def load_targets(spec: str) -> list[str]:
    """Load targets from a file (one per line, # comments) or a comma-separated list."""
    if os.path.isfile(spec):
        with open(spec, encoding="utf-8") as fh:
            return [
                line.strip()
                for line in fh
                if line.strip() and not line.lstrip().startswith("#")
            ]
    return [t.strip() for t in spec.split(",") if t.strip()]


def dispatch(
    configs: list[ScanConfig],
    *,
    wait: bool = True,
    timeout: float = 3600.0,
) -> list[dict[str, Any]]:
    """Dispatch one scan task per per-target config; optionally collect results."""
    from orthrus.distributed.tasks import scan_target

    handles = [scan_target.delay(c.model_dump(mode="json")) for c in configs]

    if not wait:
        return [
            {"task_id": h.id, "target": c.target}
            for h, c in zip(handles, configs, strict=True)
        ]

    results: list[dict[str, Any]] = []
    for handle, config in zip(handles, configs, strict=True):
        try:
            results.append(handle.get(timeout=timeout))
        except Exception as exc:  # noqa: BLE001 - report per-target failure
            results.append({"target": config.target, "status": "error", "error": str(exc)})
    return results


__all__ = ["partition_targets", "load_targets", "dispatch"]
