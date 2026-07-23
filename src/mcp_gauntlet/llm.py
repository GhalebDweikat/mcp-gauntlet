"""Provider-agnostic LLM backend (OpenAI-compatible).

The agent-under-test and the judge talk to any OpenAI-compatible endpoint through
the ``openai`` SDK: pick a provider (or a custom ``base_url``), a model, and an
API key. The first supported backend is Groq's free tier; the same code path
covers OpenRouter, Together, and local Ollama / vLLM / LM Studio.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from openai import AsyncOpenAI, OpenAI

# provider -> (base_url, api-key env var, default model)
PROVIDERS: dict[str, tuple[str, str, str]] = {
    "groq": ("https://api.groq.com/openai/v1", "GROQ_API_KEY", "llama-3.3-70b-versatile"),
    "openai": ("https://api.openai.com/v1", "OPENAI_API_KEY", "gpt-4o-mini"),
    "openrouter": (
        "https://openrouter.ai/api/v1",
        "OPENROUTER_API_KEY",
        "meta-llama/llama-3.3-70b-instruct",
    ),
    "gemini": (
        "https://generativelanguage.googleapis.com/v1beta/openai/",
        "GEMINI_API_KEY",
        "gemini-2.0-flash",
    ),
    "ollama": ("http://localhost:11434/v1", "OLLAMA_API_KEY", "llama3.1"),
}

DEFAULT_PROVIDER = "groq"


class LLMConfigError(RuntimeError):
    """Raised when a usable provider/model/key combination can't be resolved."""


@dataclass
class LLMConfig:
    provider: str
    base_url: str
    model: str
    api_key: str

    def redacted(self) -> str:
        """A log-safe one-line description that never exposes the key."""
        return f"{self.provider}:{self.model} @ {self.base_url}"

    @classmethod
    def from_env(
        cls,
        provider: str = DEFAULT_PROVIDER,
        *,
        model: str | None = None,
        base_url: str | None = None,
        api_key: str | None = None,
    ) -> LLMConfig:
        preset = PROVIDERS.get(provider)
        if preset is None and base_url is None:
            known = ", ".join(sorted(PROVIDERS))
            raise LLMConfigError(
                f"unknown provider {provider!r}; choose one of [{known}] or pass base_url"
            )
        default_base, key_env, default_model = preset or ("", "", "")

        resolved_base = base_url or default_base
        resolved_model = model or default_model
        resolved_key = api_key or (os.environ.get(key_env) if key_env else None)
        # Local servers (Ollama) ignore the key but the OpenAI client requires a non-empty string.
        if not resolved_key and provider == "ollama":
            resolved_key = "ollama"

        if not resolved_base:
            raise LLMConfigError(f"no base_url for provider {provider!r}")
        if not resolved_model:
            raise LLMConfigError(f"no model resolved for provider {provider!r}; pass model=...")
        if not resolved_key:
            hint = f"set {key_env}" if key_env else "pass api_key=..."
            raise LLMConfigError(
                f"no API key for provider {provider!r}; {hint} "
                "(get a free Groq key at https://console.groq.com/keys)"
            )
        return cls(
            provider=provider,
            base_url=resolved_base,
            model=resolved_model,
            api_key=resolved_key,
        )


def make_client(config: LLMConfig) -> OpenAI:
    """Construct an OpenAI-compatible client for the given backend."""
    return OpenAI(base_url=config.base_url, api_key=config.api_key)


def make_async_client(config: LLMConfig) -> AsyncOpenAI:
    """Construct an async OpenAI-compatible client (used by the agent loop)."""
    return AsyncOpenAI(base_url=config.base_url, api_key=config.api_key)


def list_models(config: LLMConfig) -> list[str]:
    """Return the model ids the backend advertises (cheap auth/connectivity check)."""
    client = make_client(config)
    return [model.id for model in client.models.list().data]
