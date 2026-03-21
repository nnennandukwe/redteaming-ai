import sys
from types import SimpleNamespace

import pytest

from redteaming_ai.adapters import normalize_target_spec, resolve_target_spec


def test_normalize_hosted_chat_spec_defaults_metadata():
    spec = normalize_target_spec(
        target_type="hosted_chat_model",
        target_provider="openai",
        target_model="gpt-4.1",
        target_config={"system_prompt": "audit me"},
    )

    assert spec.target_type == "hosted_chat_model"
    assert spec.target_provider == "openai"
    assert spec.target_model == "gpt-4.1"
    assert spec.target_config["system_prompt"] == "audit me"
    assert spec.target_config["capabilities"] == {
        "tool_use": False,
        "memory": False,
        "retrieval": False,
        "policy_layer": False,
    }
    assert spec.target_config["constraints"] == []


def test_normalize_hosted_chat_spec_accepts_anthropic():
    spec = normalize_target_spec(
        target_type="hosted_chat_model",
        target_provider="anthropic",
        target_model="claude-3-5-haiku-latest",
        target_config={
            "capabilities": {"memory": True},
            "constraints": ["no-pii"],
        },
    )

    assert spec.target_provider == "anthropic"
    assert spec.target_config["capabilities"]["memory"] is True
    assert spec.target_config["constraints"] == ["no-pii"]


def test_normalize_hosted_chat_rejects_unsupported_provider():
    with pytest.raises(ValueError, match="must be one of"):
        normalize_target_spec(
            target_type="hosted_chat_model",
            target_provider="mock",
            target_model="demo-model",
        )


def test_resolve_hosted_chat_openai_runtime(monkeypatch):
    class FakeOpenAIClient:
        def __init__(self, api_key):
            self.api_key = api_key
            self.chat = SimpleNamespace(
                completions=SimpleNamespace(
                    create=lambda **_kwargs: SimpleNamespace(
                        choices=[SimpleNamespace(message=SimpleNamespace(content="hello from openai"))]
                    )
                )
            )

    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setitem(sys.modules, "openai", SimpleNamespace(OpenAI=FakeOpenAIClient))

    spec = normalize_target_spec(
        target_type="hosted_chat_model",
        target_provider="openai",
        target_model="gpt-4.1",
    )
    resolved, runtime = resolve_target_spec(spec)
    response = runtime.process_message("hi")

    assert resolved.target_type == "hosted_chat_model"
    assert response["message"] == "hello from openai"
    assert response["provider_used"] == "openai"


def test_resolve_hosted_chat_runtime_reads_api_key_from_dotenv(tmp_path, monkeypatch):
    class FakeOpenAIClient:
        def __init__(self, api_key):
            self.api_key = api_key
            self.chat = SimpleNamespace(
                completions=SimpleNamespace(
                    create=lambda **_kwargs: SimpleNamespace(
                        choices=[SimpleNamespace(message=SimpleNamespace(content="hello from dotenv"))]
                    )
                )
            )

    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    (tmp_path / ".env").write_text("OPENAI_API_KEY=dotenv-openai-key\n")
    monkeypatch.setitem(sys.modules, "openai", SimpleNamespace(OpenAI=FakeOpenAIClient))

    spec = normalize_target_spec(
        target_type="hosted_chat_model",
        target_provider="openai",
        target_model="gpt-4.1",
    )
    resolved, runtime = resolve_target_spec(spec)
    response = runtime.process_message("hi")

    assert resolved.target_provider == "openai"
    assert response["message"] == "hello from dotenv"
    assert response["provider_used"] == "openai"
