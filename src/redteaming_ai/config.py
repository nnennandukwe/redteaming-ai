"""
Typed configuration and settings for redteaming-ai.

Validates environment variables at startup and fails fast on misconfiguration.
Mock mode must be explicitly selected via LLM_PROVIDER=mock.
"""

from enum import Enum
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator


class Provider(str, Enum):
    """Available LLM providers."""

    MOCK = "mock"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"


class Settings(BaseModel):
    """Validated application settings.

    Loaded from environment variables. Raises ValueError at startup if
    a non-mock provider is specified without the corresponding API key.
    """

    provider: Provider = Field(
        default=Provider.MOCK,
        description="LLM provider to use (mock, openai, anthropic).",
    )
    openai_api_key: Optional[str] = Field(
        default=None, description="OpenAI API key. Required when provider=openai."
    )
    anthropic_api_key: Optional[str] = Field(
        default=None, description="Anthropic API key. Required when provider=anthropic."
    )
    model_name: Optional[str] = Field(
        default=None,
        description="Model name. Defaults to provider-specific default if not set.",
    )

    @model_validator(mode="before")
    @classmethod
    def _load_from_env(cls, data):
        import os

        if isinstance(data, dict):
            env_provider = os.getenv("LLM_PROVIDER", "").strip().lower()
            if not env_provider:
                raise ValueError(
                    "LLM_PROVIDER is not set. Must be one of: mock, openai, anthropic. "
                    "Use 'mock' for testing without API calls."
                )
            data["provider"] = Provider(env_provider)
            if data.get("openai_api_key") is None:
                data["openai_api_key"] = os.getenv("OPENAI_API_KEY") or None
            if data.get("anthropic_api_key") is None:
                data["anthropic_api_key"] = os.getenv("ANTHROPIC_API_KEY") or None
            if data.get("model_name") is None:
                data["model_name"] = os.getenv("MODEL_NAME") or None
        return data

    @model_validator(mode="after")
    def _validate_credentials(self) -> "Settings":
        if self.provider == Provider.OPENAI and not self.openai_api_key:
            raise ValueError(
                "LLM_PROVIDER=openai is set but OPENAI_API_KEY is not configured."
            )
        if self.provider == Provider.ANTHROPIC and not self.anthropic_api_key:
            raise ValueError(
                "LLM_PROVIDER=anthropic is set but ANTHROPIC_API_KEY is not configured."
            )
        return self

    model_config = ConfigDict(extra="ignore")


def get_settings() -> Settings:
    """Load and validate settings from environment.

    Raises:
        ValueError: If LLM_PROVIDER is not set, or if provider is non-mock and required credentials are missing.
    """
    return Settings()
