"""Shared per-scan context handed to every module.

Bundles the wired-up infrastructure (HTTP client, scope, store, event bus) and
the growing asset/endpoint inventory so recon, scanners, and exploits all
operate against the same state without global singletons.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from orthrus.core import schemas
from orthrus.core.baseline import BaselineProfile
from orthrus.core.browser import BrowserManager
from orthrus.core.callback import CallbackClient
from orthrus.core.config import ScanConfig
from orthrus.core.event_bus import EventBus
from orthrus.core.http_client import HttpClient
from orthrus.db.store import Store
from orthrus.utils.scope import ScopeValidator

if TYPE_CHECKING:
    from orthrus.core.second_order import SecondOrderRegistry


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
    second_order: SecondOrderRegistry | None = None
    baseline: BaselineProfile | None = None
    assets: list[schemas.Asset] = field(default_factory=list)
    endpoints: list[schemas.Endpoint] = field(default_factory=list)
    websockets: list[str] = field(default_factory=list)
    findings: list[schemas.Finding] = field(default_factory=list)
    finding_ids: dict[str, int] = field(default_factory=dict)


__all__ = ["ScanContext"]
