"""Plugin loader (PRD §13.2).

Auto-discovers plugin modules at startup and imports them so their
``@register`` decorators populate the scanner / exploit / recon / reporter
registries. Discovers both the built-in ``hydra/plugins`` package and an
optional external directory (``HYDRA_PLUGINS_DIR``).
"""

from __future__ import annotations

import importlib
import importlib.util
import os
import pkgutil

from hydra.utils.logger import get_logger

logger = get_logger("plugins")

_loaded = False


def load_plugins(extra_dir: str | None = None) -> list[str]:
    """Import all plugin modules once; return the list of loaded plugin names."""
    global _loaded
    loaded: list[str] = []

    import hydra.plugins as pkg

    for module in pkgutil.iter_modules(pkg.__path__):
        if module.name.startswith("_"):
            continue
        try:
            importlib.import_module(f"hydra.plugins.{module.name}")
            loaded.append(module.name)
        except Exception:
            logger.exception("failed to load built-in plugin %s", module.name)

    if extra_dir and os.path.isdir(extra_dir):
        for filename in sorted(os.listdir(extra_dir)):
            if not filename.endswith(".py") or filename.startswith("_"):
                continue
            name = filename[:-3]
            path = os.path.join(extra_dir, filename)
            try:
                spec = importlib.util.spec_from_file_location(f"hydra_plugin_{name}", path)
                if spec and spec.loader:
                    mod = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(mod)
                    loaded.append(name)
            except Exception:
                logger.exception("failed to load external plugin %s", path)

    _loaded = True
    if loaded:
        logger.info("loaded %d plugin(s): %s", len(loaded), ", ".join(loaded))
    return loaded


__all__ = ["load_plugins"]
