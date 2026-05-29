"""Load declarative templates from YAML/JSON files or directories.

``--templates builtin`` resolves to the set shipped under
``orthrus/templates/builtin``; any other value is treated as a filesystem path to
a single template or a directory scanned recursively for ``*.yaml/*.yml/*.json``.

YAML support is optional: if PyYAML is not installed, ``.yaml/.yml`` files are
skipped with a warning and JSON templates still load. This keeps the dependency
soft, matching how the browser engine is treated.
"""

from __future__ import annotations

import json
from pathlib import Path

from orthrus.templates.schema import Template
from orthrus.utils.logger import get_logger

logger = get_logger("templates")

BUILTIN_DIR = Path(__file__).parent / "builtin"
_SUFFIXES = (".yaml", ".yml", ".json")

try:
    import yaml  # type: ignore

    _HAS_YAML = True
except ImportError:  # pragma: no cover - exercised only when PyYAML is absent
    yaml = None  # type: ignore
    _HAS_YAML = False


def _parse_text(text: str, *, is_yaml: bool) -> dict | None:
    if is_yaml:
        if not _HAS_YAML:
            return None
        data = yaml.safe_load(text)
    else:
        data = json.loads(text)
    return data if isinstance(data, dict) else None


def load_template_file(path: Path) -> Template | None:
    """Parse a single template file, returning ``None`` if it can't be loaded."""
    is_yaml = path.suffix.lower() in (".yaml", ".yml")
    if is_yaml and not _HAS_YAML:
        logger.warning("skipping %s: PyYAML not installed (pip install pyyaml)", path.name)
        return None
    try:
        data = _parse_text(path.read_text(encoding="utf-8"), is_yaml=is_yaml)
    except (OSError, ValueError) as exc:
        logger.warning("skipping %s: %s", path.name, exc)
        return None
    if not data or "id" not in data:
        logger.warning("skipping %s: not a valid template (missing 'id')", path.name)
        return None
    try:
        return Template.from_dict(data)
    except Exception as exc:  # noqa: BLE001 - one bad template shouldn't abort the load
        logger.warning("skipping %s: %s", path.name, exc)
        return None


def load_templates(location: str) -> list[Template]:
    """Load all templates addressed by ``location`` (the bundled name, a file, or a dir)."""
    if location == "builtin":
        root = BUILTIN_DIR
    else:
        root = Path(location)
        if not root.exists():
            raise FileNotFoundError(f"templates path not found: {location}")

    if root.is_file():
        tpl = load_template_file(root)
        return [tpl] if tpl else []

    files = sorted(p for p in root.rglob("*") if p.suffix.lower() in _SUFFIXES)
    templates = [tpl for p in files if (tpl := load_template_file(p)) is not None]
    logger.info("loaded %d template(s) from %s", len(templates), location)
    return templates


__all__ = ["load_templates", "load_template_file", "BUILTIN_DIR"]
