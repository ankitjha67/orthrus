"""Reporter plugin interface + registry (PRD §13.1 Reporter Plugin).

Built-in formats (json/csv/html/pdf) are handled by ``reporting.generator``.
A reporter plugin registers a custom output format keyed by name; the report
command can then select it by ``--format <name>``.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class BaseReporter(ABC):
    name: str = "base-reporter"

    @abstractmethod
    async def generate(self, context: dict[str, Any], output: str) -> str:
        """Render the report context to a file; return the output path."""
        raise NotImplementedError


REPORTER_REGISTRY: dict[str, type[BaseReporter]] = {}


def register(cls: type[BaseReporter]) -> type[BaseReporter]:
    REPORTER_REGISTRY[cls.name] = cls
    return cls


def get_reporter(name: str) -> BaseReporter | None:
    cls = REPORTER_REGISTRY.get(name)
    return cls() if cls else None


__all__ = ["BaseReporter", "REPORTER_REGISTRY", "register", "get_reporter"]
