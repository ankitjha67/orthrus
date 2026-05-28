"""Celery application for distributed scanning.

Broker + result backend come from ``HYDRA_REDIS_URL`` (settings.redis_url).
Start a worker with::

    celery -A hydra.distributed.celery_app worker --loglevel=info

Requires a running Redis broker (PRD §15.2 hydra-redis).
"""

from __future__ import annotations

from celery import Celery

from hydra.core.config import get_settings

_settings = get_settings()

app = Celery(
    "hydra",
    broker=_settings.redis_url,
    backend=_settings.redis_url,
    include=["hydra.distributed.tasks"],
)
app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    task_acks_late=True,
    worker_prefetch_multiplier=1,  # stateless workers, fair per-target distribution
)

__all__ = ["app"]
