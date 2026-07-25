from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from openai import APIConnectionError, APIStatusError, RateLimitError

from mcp_gauntlet.llm import LLMConfig, LLMConfigError, chat_completion

_VARS = (
    "MCP_GAUNTLET_PROVIDER",
    "MCP_GAUNTLET_MODEL",
    "GROQ_API_KEY",
    "GEMINI_API_KEY",
    "OPENAI_API_KEY",
    "OPENROUTER_API_KEY",
)


def _clear(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in _VARS:
        monkeypatch.delenv(var, raising=False)


def test_explicit_args_win(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear(monkeypatch)
    monkeypatch.setenv("GROQ_API_KEY", "k")
    monkeypatch.setenv("MCP_GAUNTLET_PROVIDER", "gemini")  # arg should override env
    config = LLMConfig.from_env("groq", model="custom-model")
    assert config.provider == "groq"
    assert config.model == "custom-model"


def test_provider_and_model_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear(monkeypatch)
    monkeypatch.setenv("GEMINI_API_KEY", "k")
    monkeypatch.setenv("MCP_GAUNTLET_PROVIDER", "gemini")
    monkeypatch.setenv("MCP_GAUNTLET_MODEL", "gemini-flash-latest")
    config = LLMConfig.from_env()
    assert config.provider == "gemini"
    assert config.model == "gemini-flash-latest"


def test_defaults_to_groq(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear(monkeypatch)
    monkeypatch.setenv("GROQ_API_KEY", "k")
    config = LLMConfig.from_env()
    assert config.provider == "groq"
    assert config.model == "llama-3.3-70b-versatile"


def test_missing_key_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear(monkeypatch)
    with pytest.raises(LLMConfigError):
        LLMConfig.from_env("groq")


def test_base_url_override(monkeypatch: pytest.MonkeyPatch) -> None:
    # --base-url (README's "any OpenAI-compatible endpoint") overrides the provider default.
    _clear(monkeypatch)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-x")
    config = LLMConfig.from_env("openai", base_url="https://vllm.internal/v1")
    assert config.base_url == "https://vllm.internal/v1"


# --- R13: a keyless custom endpoint (vLLM / LM Studio) must be usable -------------


def test_keyless_base_url_gets_placeholder(monkeypatch: pytest.MonkeyPatch) -> None:
    # The README promises "any OpenAI-compatible endpoint"; a local vLLM has no key,
    # but the OpenAI client demands a non-empty string.
    _clear(monkeypatch)
    config = LLMConfig.from_env(base_url="http://localhost:8000/v1")
    assert config.api_key == "unused"
    assert config.base_url == "http://localhost:8000/v1"
    assert config.model  # still resolves the provider-default model


def test_api_key_arg_beats_placeholder_and_env(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear(monkeypatch)
    monkeypatch.setenv("GROQ_API_KEY", "env-key")
    config = LLMConfig.from_env(base_url="https://gw.internal/v1", api_key="cli-key")
    assert config.api_key == "cli-key"


def test_env_key_still_flows_to_a_custom_base_url(monkeypatch: pytest.MonkeyPatch) -> None:
    # Documented behavior: --provider picks the API *shape and credentials*; --base-url
    # only moves the endpoint (the gateway/proxy case). Keyless endpoints skip the env var.
    _clear(monkeypatch)
    monkeypatch.setenv("GROQ_API_KEY", "env-key")
    config = LLMConfig.from_env(base_url="https://gw.internal/v1")
    assert config.api_key == "env-key"


def test_unknown_provider_with_base_url_works_keyless(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear(monkeypatch)
    config = LLMConfig.from_env("lmstudio", base_url="http://localhost:1234/v1", model="local")
    assert config.api_key == "unused"


def test_no_base_url_still_requires_a_key(monkeypatch: pytest.MonkeyPatch) -> None:
    # The placeholder is only for explicitly overridden endpoints — never for a real
    # provider default, where "unused" would turn an auth error into a confusing 401.
    _clear(monkeypatch)
    with pytest.raises(LLMConfigError):
        LLMConfig.from_env("groq")


# --- 429/transient backoff in chat_completion --------------------------------------


class _FlakyClient:
    """Raises the scripted failures in order, then returns the sentinel result."""

    def __init__(self, failures: list[BaseException], result: Any = "ok") -> None:
        self._failures = list(failures)
        self._result = result
        self.calls = 0
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    async def _create(self, **kwargs: Any) -> Any:
        self.calls += 1
        if self._failures:
            raise self._failures.pop(0)
        return self._result


def _rate_limit(headers: dict[str, str] | None = None) -> RateLimitError:
    request = httpx.Request("POST", "https://api.groq.com/openai/v1/chat/completions")
    response = httpx.Response(429, headers=headers or {}, request=request)
    return RateLimitError("rate limited", response=response, body=None)


def _status_error(code: int) -> APIStatusError:
    request = httpx.Request("POST", "https://api.example/v1/chat/completions")
    return APIStatusError("boom", response=httpx.Response(code, request=request), body=None)


@pytest.fixture
def sleeps(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    recorded: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        recorded.append(seconds)

    monkeypatch.setattr("mcp_gauntlet.llm.anyio.sleep", fake_sleep)
    return recorded


async def test_429_with_retry_after_is_honored(sleeps: list[float]) -> None:
    client = _FlakyClient([_rate_limit({"retry-after": "2"})], result="fine")
    assert await chat_completion(client, model="m", messages=[]) == "fine"  # type: ignore[arg-type]
    assert client.calls == 2
    assert sleeps == [2.0]


async def test_retry_after_ms_takes_precedence(sleeps: list[float]) -> None:
    client = _FlakyClient([_rate_limit({"retry-after-ms": "1500", "retry-after": "9"})])
    await chat_completion(client, model="m", messages=[])  # type: ignore[arg-type]
    assert sleeps == [1.5]


async def test_daily_quota_retry_after_gives_up_immediately(sleeps: list[float]) -> None:
    # A Retry-After longer than any sane in-run wait means the daily quota is spent;
    # sleeping an hour inside a 900s --timeout would void the run to accomplish nothing.
    client = _FlakyClient([_rate_limit({"retry-after": "3600"})])
    with pytest.raises(RateLimitError):
        await chat_completion(client, model="m", messages=[])  # type: ignore[arg-type]
    assert client.calls == 1
    assert sleeps == []


async def test_garbage_retry_after_falls_back_to_backoff(sleeps: list[float]) -> None:
    # "nan" passes a `> cap` comparison (NaN compares false) and would reach
    # anyio.sleep; negative values must not become time travel either.
    for bad in ("nan", "-5", "inf", "Tue, 29 Jul 2026 09:00:00 GMT"):
        sleeps.clear()
        client = _FlakyClient([_rate_limit({"retry-after": bad})], result="fine")
        assert await chat_completion(client, model="m", messages=[]) == "fine"  # type: ignore[arg-type]
        assert len(sleeps) == 1 and 1.0 <= sleeps[0] <= 1.25, (bad, sleeps)


async def test_non_retryable_status_raises_immediately(sleeps: list[float]) -> None:
    client = _FlakyClient([_status_error(400)])
    with pytest.raises(APIStatusError):
        await chat_completion(client, model="m", messages=[])  # type: ignore[arg-type]
    assert client.calls == 1
    assert sleeps == []


async def test_repeated_429_exhausts_attempts(sleeps: list[float]) -> None:
    client = _FlakyClient([_rate_limit() for _ in range(4)])
    with pytest.raises(RateLimitError):
        await chat_completion(client, model="m", messages=[])  # type: ignore[arg-type]
    assert client.calls == 4  # max_attempts
    assert len(sleeps) == 3
    assert all(0 < s <= 65 for s in sleeps)


async def test_connection_errors_retry_then_raise(sleeps: list[float]) -> None:
    request = httpx.Request("POST", "https://api.example/v1/chat/completions")
    failures: list[BaseException] = [APIConnectionError(request=request) for _ in range(4)]
    with pytest.raises(APIConnectionError):
        await chat_completion(_FlakyClient(failures), model="m", messages=[])  # type: ignore[arg-type]
    assert len(sleeps) == 3


async def test_unrelated_exceptions_propagate_without_retry(sleeps: list[float]) -> None:
    # The mocked-agent suite scripts plain exceptions; they must never trigger backoff.
    client = _FlakyClient([RuntimeError("scripted")])
    with pytest.raises(RuntimeError):
        await chat_completion(client, model="m", messages=[])  # type: ignore[arg-type]
    assert client.calls == 1
    assert sleeps == []


async def test_transient_5xx_recovers(sleeps: list[float]) -> None:
    client = _FlakyClient([_status_error(503)], result="fine")
    assert await chat_completion(client, model="m", messages=[]) == "fine"  # type: ignore[arg-type]
    assert client.calls == 2
