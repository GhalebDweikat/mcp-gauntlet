import pytest

from mcp_gauntlet.llm import LLMConfig, LLMConfigError

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
