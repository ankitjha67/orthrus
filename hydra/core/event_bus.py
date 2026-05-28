"""Lightweight async pub/sub for inter-module communication.

Phases and modules emit events (asset discovered, finding raised, scope
violation, etc.) without needing direct references to each other. The
orchestrator, logger, and persistence layer subscribe to what they care about.
"""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from hydra.utils.logger import get_logger

logger = get_logger("event_bus")

Handler = Callable[["Event"], Awaitable[None] | None]


class EventType:
    """Well-known event names. Modules may publish custom names too."""

    SCAN_STARTED = "scan.started"
    SCAN_COMPLETED = "scan.completed"
    PHASE_STARTED = "phase.started"
    PHASE_COMPLETED = "phase.completed"
    ASSET_DISCOVERED = "asset.discovered"
    ENDPOINT_DISCOVERED = "endpoint.discovered"
    FINDING_RAISED = "finding.raised"
    EXPLOIT_CONFIRMED = "exploit.confirmed"
    CALLBACK_RECEIVED = "callback.received"
    SCOPE_VIOLATION = "scope.violation"


@dataclass
class Event:
    type: str
    data: dict[str, Any] = field(default_factory=dict)


class EventBus:
    def __init__(self) -> None:
        self._subscribers: dict[str, list[Handler]] = {}

    def subscribe(self, event_type: str, handler: Handler) -> None:
        self._subscribers.setdefault(event_type, []).append(handler)

    def unsubscribe(self, event_type: str, handler: Handler) -> None:
        handlers = self._subscribers.get(event_type)
        if handlers and handler in handlers:
            handlers.remove(handler)

    async def publish(self, event: Event) -> None:
        handlers = [*self._subscribers.get(event.type, []), *self._subscribers.get("*", [])]
        pending: list[Awaitable[None]] = []
        for handler in handlers:
            try:
                result = handler(event)
                if inspect.isawaitable(result):
                    pending.append(result)
            except Exception:  # a faulty subscriber must not break the publisher
                logger.exception("event handler failed for %s", event.type)
        for coro in pending:
            try:
                await coro
            except Exception:
                logger.exception("async event handler failed for %s", event.type)

    async def emit(self, event_type: str, **data: Any) -> None:
        await self.publish(Event(type=event_type, data=data))


__all__ = ["EventBus", "Event", "EventType"]
