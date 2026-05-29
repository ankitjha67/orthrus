"""Declarative (Nuclei-style) template engine.

Templates are data files (YAML/JSON) describing HTTP requests + matchers. They
let detections be added without writing Python, and ship a curated ``builtin``
set. See :mod:`hydra.templates.schema` for the supported subset.
"""

from __future__ import annotations

from hydra.templates.loader import load_templates
from hydra.templates.schema import Template

__all__ = ["load_templates", "Template"]
