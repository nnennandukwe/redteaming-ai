import pytest

from redteaming_ai.config import Provider, Settings, get_settings


@pytest.fixture(autouse=True)
def isolate_working_directory_and_env(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    for variable in (
        "LLM_PROVIDER",
        "MODEL_NAME",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
    ):
        monkeypatch.delenv(variable, raising=False)


def test_provider_required(monkeypatch):
    with pytest.raises(ValueError) as exc_info:
        Settings()
    assert "LLM_PROVIDER is not set" in str(exc_info.value)


def test_openai_provider_requires_api_key(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "openai")
    with pytest.raises(ValueError) as exc_info:
        Settings()
    assert "OPENAI_API_KEY" in str(exc_info.value)


def test_anthropic_provider_requires_api_key(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    with pytest.raises(ValueError) as exc_info:
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


def test_get_settings_returns_settings(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "mock")
    settings = get_settings()
    assert isinstance(settings, Settings)


def test_get_settings_reads_dotenv_file(tmp_path, monkeypatch):
    (tmp_path / ".env").write_text("LLM_PROVIDER=mock\nMODEL_NAME=dotenv-model\n")

    settings = get_settings()

    assert settings.provider == Provider.MOCK
    assert settings.model_name == "dotenv-model"
