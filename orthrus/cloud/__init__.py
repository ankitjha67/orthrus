"""Cloud security posture (CSPM/IAM) — read-only misconfiguration + toxic-combination analysis.

`orthrus cloud` consumes a normalized inventory snapshot (or collects one
read-only via boto3) and emits ORTHRUS Findings for public/unencrypted/over-
privileged resources plus the CRITICAL *combinations* an attacker would chain.
Findings flow into the existing report / attack-graph / runbook / notify layers.
"""

from __future__ import annotations

from orthrus.cloud.analyze import analyze_inventory
from orthrus.cloud.models import CloudInventory, CloudResource
from orthrus.cloud.toxic import analyze_cloud, toxic_combinations

__all__ = [
    "CloudInventory",
    "CloudResource",
    "analyze_inventory",
    "toxic_combinations",
    "analyze_cloud",
]
