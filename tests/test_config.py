import pytest
from pydantic import ValidationError

from redteaming_ai.config import Provider, Settings, get_settings


def test_default_is_mock():
    settings = Settings()
    assert settings.provider == Provider.MOCK
    assert settings.openai_api_key is None
    assert settings.anthropic_api_key is None


def test_openai_provider_requires_api_key(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "openai")
    with pytest.raises(ValidationError) as exc_info:
        Settings()
    assert "OPENAI_API_KEY" in str(exc_info.value)


def test_anthropic_provider_requires_api_key(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    with pytest.raises(ValidationError) as exc_info:
        Settings()
    assert "ANTHROPIC_API_KEY" in str(exc_info.value)


def test_openai_with_key_succeeds(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "openai")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-key")
    monkeypatch.setenv("MODEL_NAME", "gpt-4")
    settings = Settings()
    assert settings.provider == Provider.OPENAI
    assert settings.openai_api_key == "sk-test-key"
    assert settings.model_name == "gpt-4"


def test_anthropic_with_key_succeeds(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    settings = Settings()
    assert settings.provider == Provider.ANTHROPIC
    assert settings.anthropic_api_key == "sk-ant-test"


def test_provider_case_insensitive(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "OPENAI")
    monkeypatch.setenv("OPENAI_API_KEY", "test")
    settings = Settings()
    assert settings.provider == Provider.OPENAI


def test_mock_mode_no_credentials_required(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "mock")
    settings = Settings()
    assert settings.provider == Provider.MOCK


def test_get_settings_returns_settings():
    settings = get_settings()
    assert isinstance(settings, Settings)
