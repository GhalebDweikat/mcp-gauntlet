"""Provider-agnostic LLM backend (OpenAI-compatible).

The agent-under-test and the judge talk to any OpenAI-compatible endpoint through
the ``openai`` SDK: pick a provider (or a custom ``base_url``), a model, and an
API key. The first supported backend is Groq's free tier; the same code path
covers OpenRouter, Together, and local Ollama / vLLM / LM Studio.
"""

from __future__ import annotations

import math
import os
import random
from dataclasses import dataclass
from typing import Any

import anyio
from openai import APIConnectionError, APIStatusError, AsyncOpenAI, OpenAI

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
        "gemini-flash-latest",
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
        provider: str | None = None,
        *,
        model: str | None = None,
        base_url: str | None = None,
        api_key: str | None = None,
    ) -> LLMConfig:
        # Resolution order: explicit arg → environment → provider preset default.
        provider = provider or os.environ.get("MCP_GAUNTLET_PROVIDER") or DEFAULT_PROVIDER
        model = model or os.environ.get("MCP_GAUNTLET_MODEL")
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
        if not resolved_key and base_url is not None:
            # An explicitly overridden endpoint (vLLM / LM Studio / a gateway) often has
            # no auth at all; don't demand the provider's key for a URL that isn't the
            # provider's. Endpoints that DO need one take api_key / --api-key.
            resolved_key = "unused"

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


# HTTP statuses worth a retry: rate limits and transient server/gateway failures.
RETRYABLE_STATUS = frozenset({408, 429, 500, 502, 503, 504})
_MAX_RETRY_WAIT_S = 65.0  # a longer Retry-After means an exhausted daily quota, not a blip


def _retry_after_s(exc: APIStatusError) -> float | None:
    """Seconds the server asked us to wait, if it said so (Groq and OpenAI both do).

    The endpoint is user-chosen but still remote input: reject non-finite and
    negative values ("nan" passes a ``> cap`` check and would reach anyio.sleep).
    """
    headers = getattr(getattr(exc, "response", None), "headers", None)
    if headers is None:
        return None
    for header, scale in (("retry-after-ms", 1000.0), ("retry-after", 1.0)):
        raw = headers.get(header)
        if not raw:
            continue
        try:
            value = float(raw) / scale
        except ValueError:  # an HTTP-date; LLM providers send plain seconds
            continue
        if math.isfinite(value) and value >= 0:
            return value
    return None


async def chat_completion(client: AsyncOpenAI, *, max_attempts: int = 4, **kwargs: Any) -> Any:
    """``client.chat.completions.create`` with bounded backoff on transient failures.

    Groq's free tier — the default backend — rate-limits bursty runs, and without a
    retry every 429 voids a repeat (inconclusive) or a whole task set. Honors
    Retry-After when the server sends one, EXCEPT when it exceeds
    ``_MAX_RETRY_WAIT_S``: that long a wait is a spent daily quota, and sleeping on
    it would burn the run's --timeout budget to accomplish nothing. Anything
    non-transient (auth, bad request) raises immediately.
    """
    delay = 1.0
    for attempt in range(1, max_attempts + 1):
        try:
            return await client.chat.completions.create(**kwargs)
        except APIStatusError as exc:
            if attempt >= max_attempts or exc.status_code not in RETRYABLE_STATUS:
                raise
            wait = _retry_after_s(exc)
            if wait is None:
                wait = delay + random.uniform(0, delay / 4)
                delay = min(delay * 2, 16.0)
            elif wait > _MAX_RETRY_WAIT_S:
                raise
            await anyio.sleep(wait)
        except APIConnectionError:  # includes APITimeoutError
            if attempt >= max_attempts:
                raise
            await anyio.sleep(delay + random.uniform(0, delay / 4))
            delay = min(delay * 2, 16.0)
    raise AssertionError("unreachable")  # the loop always returns or raises


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
