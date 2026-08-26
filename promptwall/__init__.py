"""PromptWall -- a layered prompt-injection firewall for LLM applications.

PromptWall sits between an application and its model provider and applies
seven defence layers (L0-L6) to every request, response and tool call.
Its primary signal is *provenance*, not maliciousness: see
``docs/adr/002-taint-over-classification.md``.
"""

from .constants import (
    API_VERSION,
    AttackFamily,
    Decision,
    LayerName,
    Mode,
    Phase,
    Severity,
    TrustLevel,
)
from .exceptions import BlockedError, ConfigError, PolicyError, PromptWallError

__version__ = "0.1.0"

__all__ = [
    "API_VERSION",
    "AttackFamily",
    "BlockedError",
    "ConfigError",
    "Decision",
    "LayerName",
    "Mode",
    "Phase",
    "PolicyError",
    "PromptWallError",
    "Severity",
    "TrustLevel",
    "__version__",
]
