"""Upstream provider adapters."""

from .anthropic import AnthropicProvider
from .base import Provider
from .openai_compat import OpenAICompatProvider

#: Registry keyed by the PW_UPSTREAM_PROVIDER value.
PROVIDERS: dict[str, type[Provider]] = {
    "openai_compat": OpenAICompatProvider,
    "anthropic": AnthropicProvider,
    # Speaks the OpenAI shape but is short-circuited in UpstreamClient,
    # so PromptWall can be run and demonstrated with no provider account.
    "echo": OpenAICompatProvider,
}


def get_provider(name: str) -> Provider:
    try:
        return PROVIDERS[name]()
    except KeyError as exc:
        raise ValueError(
            f"unknown provider {name!r}; expected one of {sorted(PROVIDERS)}"
        ) from exc


__all__ = ["PROVIDERS", "AnthropicProvider", "OpenAICompatProvider", "Provider", "get_provider"]
