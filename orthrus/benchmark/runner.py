"""Benchmark runner: scan a target, then score it against ground truth.

This is the bridge between the live scanner and the pure :mod:`scorer`. It drives
the standard orchestrator (recon -> scan, and optionally exploit confirmation),
collects the in-memory findings, and hands them to :func:`scorer.score`.

Ground-truth files are small JSON documents enumerating the known
vulnerabilities of a *target you own* (see ``orthrus/benchmark/data``). Running a
benchmark against an arbitrary third-party host is meaningless and out of scope.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

from orthrus.benchmark.scorer import BenchmarkReport, Expected, score
from orthrus.utils.logger import get_logger

if TYPE_CHECKING:
    from orthrus.core.config import ScanConfig, Settings

logger = get_logger("benchmark")

# Bundled ground-truth files shipped with ORTHRUS, addressable by bare name.
DATA_DIR = Path(__file__).parent / "data"


def load_truth(location: str) -> tuple[str, list[Expected]]:
    """Load a ground-truth document, returning ``(name, expected_entries)``.

    ``location`` may be a filesystem path or the bare name of a bundled truth
    file (e.g. ``reflecting-target``).
    """
    path = Path(location)
    if not path.exists():
        candidate = DATA_DIR / f"{location}.json"
        if candidate.exists():
            path = candidate
        else:
            raise FileNotFoundError(f"ground-truth file not found: {location}")

    raw = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(raw, list):
        entries, name = raw, path.stem
    elif isinstance(raw, dict):
        entries = raw.get("expected", [])
        name = str(raw.get("name", path.stem))
    else:
        raise ValueError("ground-truth file must be a JSON object or list")

    expected = [Expected.from_dict(e) for e in entries]
    if not expected:
        raise ValueError(f"ground-truth file '{path}' declares no expected vulnerabilities")
    return name, expected


async def run_benchmark(
    config: ScanConfig,
    settings: Settings,
    expected: list[Expected],
    *,
    confirm: bool = False,
) -> BenchmarkReport:
    """Run recon + scan (+ optional confirmation) and score the findings.

    The orchestrator is always torn down, even on error, so the HTTP client and
    any callback/browser resources are released.
    """
    from orthrus.core.orchestrator import Orchestrator

    orch = Orchestrator(config, settings)
    status = "completed"
    try:
        await orch.setup()
        await orch.run_recon()
        await orch.run_scan()
        if confirm and not config.no_exploit:
            await orch.run_exploit()
        findings = list(orch.ctx.findings) if orch.ctx is not None else []
        report = score(findings, expected)
    except Exception:
        status = "failed"
        logger.exception("benchmark run aborted")
        raise
    finally:
        await orch.teardown(status)
    return report


__all__ = ["load_truth", "run_benchmark", "DATA_DIR"]
