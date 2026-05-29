"""External-tool orchestration: run best-of-breed CLI tools and normalize their
output into ORTHRUS Findings so they flow through the same DB / report / CVSS
pipeline. Importing this package registers the built-in adapters.
"""

from orthrus.integrations import nuclei as _nuclei  # noqa: F401  (registration side-effect)
from orthrus.integrations.base import (
    TOOL_REGISTRY,
    ExternalToolAdapter,
    available_tools,
    get_tools,
    register_tool,
)

__all__ = [
    "ExternalToolAdapter",
    "TOOL_REGISTRY",
    "get_tools",
    "register_tool",
    "available_tools",
]
