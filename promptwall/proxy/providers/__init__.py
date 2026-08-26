"""Upstream provider adapters."""

from .anthropic import AnthropicProvider
from .base import Provider
from .openai_compat import OpenAICompatProvider

#: Registry keyed by the PW_UPSTREAM_PROVIDER value.
PROVIDERS: dict[str, type[Provider]] = {
    "openai_compat": OpenAICompatProvider,
    "anthropic": AnthropicProvider,
}


def get_provider(name: str) -> Provider:
    try:
        return PROVIDERS[name]()
    except KeyError as exc:
        raise ValueError(
            f"unknown provider {name!r}; expected one of {sorted(PROVIDERS)}"
        ) from exc


__all__ = ["PROVIDERS", "AnthropicProvider", "OpenAICompatProvider", "Provider", "get_provider"]
