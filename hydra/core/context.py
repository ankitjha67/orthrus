"""Shared per-scan context handed to every module.

Bundles the wired-up infrastructure (HTTP client, scope, store, event bus) and
the growing asset/endpoint inventory so recon, scanners, and exploits all
operate against the same state without global singletons.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from hydra.core import schemas
from hydra.core.config import ScanConfig
from hydra.core.event_bus import EventBus
from hydra.core.http_client import HttpClient
from hydra.db.store import Store
from hydra.utils.scope import ScopeValidator


@dataclass
class ScanContext:
    scan_id: str
    config: ScanConfig
    scope: ScopeValidator
    http: HttpClient
    store: Store
    event_bus: EventBus
    assets: list[schemas.Asset] = field(default_factory=list)
    endpoints: list[schemas.Endpoint] = field(default_factory=list)


__all__ = ["ScanContext"]
