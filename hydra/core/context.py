"""Shared per-scan context handed to every module.

Bundles the wired-up infrastructure (HTTP client, scope, store, event bus) and
the growing asset/endpoint inventory so recon, scanners, and exploits all
operate against the same state without global singletons.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from hydra.core import schemas
from hydra.core.baseline import BaselineProfile
from hydra.core.browser import BrowserManager
from hydra.core.callback import CallbackClient
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
    callback: CallbackClient | None = None
    browser: BrowserManager | None = None
    baseline: BaselineProfile | None = None
    assets: list[schemas.Asset] = field(default_factory=list)
    endpoints: list[schemas.Endpoint] = field(default_factory=list)
    websockets: list[str] = field(default_factory=list)
    findings: list[schemas.Finding] = field(default_factory=list)
    finding_ids: dict[str, int] = field(default_factory=dict)


__all__ = ["ScanContext"]
