from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Protocol

from redteaming_ai.config import load_environment
from redteaming_ai.target import VulnerableLLMApp

DEFAULT_TARGET_TYPE = "vulnerable_llm_app"
HOSTED_CHAT_TARGET_TYPE = "hosted_chat_model"
SUPPORTED_TARGET_TYPES = {DEFAULT_TARGET_TYPE, HOSTED_CHAT_TARGET_TYPE}
SUPPORTED_HOSTED_PROVIDERS = {"openai", "anthropic"}


class TargetRuntime(Protocol):
    def process_message(self, user_input: str) -> Dict[str, Any]:
        ...

    def get_system_info(self) -> Dict[str, Any]:
        ...


@dataclass(frozen=True)
class TargetSpec:
    target_type: str = DEFAULT_TARGET_TYPE
    target_provider: Optional[str] = None
    target_model: Optional[str] = None
    target_config: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_type": self.target_type,
            "target_provider": self.target_provider,
            "target_model": self.target_model,
            "target_config": dict(self.target_config),
        }


class TargetAdapter(Protocol):
    target_type: str

    def normalize(self, spec: TargetSpec) -> TargetSpec:
        ...

    def build_runtime(self, spec: TargetSpec) -> TargetRuntime:
        ...

    def resolve(self, spec: TargetSpec) -> tuple[TargetSpec, TargetRuntime]:
        ...


def _normalize_capabilities(raw_capabilities: Any) -> Dict[str, bool]:
    capabilities = raw_capabilities if isinstance(raw_capabilities, dict) else {}
    return {
        "tool_use": bool(capabilities.get("tool_use", False)),
        "memory": bool(capabilities.get("memory", False)),
        "retrieval": bool(capabilities.get("retrieval", False)),
        "policy_layer": bool(capabilities.get("policy_layer", False)),
    }


def _normalize_constraints(raw_constraints: Any) -> List[str]:
    if raw_constraints is None:
        return []
    if not isinstance(raw_constraints, list):
        raise ValueError("target_config.constraints must be a list of strings")

    normalized: List[str] = []
    for item in raw_constraints:
        if not isinstance(item, str):
            raise ValueError("target_config.constraints must be a list of strings")
        normalized.append(item)
    return normalized


def _normalize_hosted_chat_config(raw_config: Any) -> Dict[str, Any]:
    config = raw_config if isinstance(raw_config, dict) else {}
    system_prompt = config.get("system_prompt", "")
    if system_prompt is None:
        system_prompt = ""
    if not isinstance(system_prompt, str):
        raise ValueError("target_config.system_prompt must be a string")

    return {
        "system_prompt": system_prompt,
        "capabilities": _normalize_capabilities(config.get("capabilities")),
        "constraints": _normalize_constraints(config.get("constraints")),
    }


class VulnerableLLMAppAdapter:
    target_type = DEFAULT_TARGET_TYPE

    def normalize(self, spec: TargetSpec) -> TargetSpec:
        return TargetSpec(
            target_type=self.target_type,
            target_provider=spec.target_provider,
            target_model=spec.target_model,
            target_config=dict(spec.target_config or {}),
        )

    def build_runtime(self, spec: TargetSpec) -> TargetRuntime:
        target_app = VulnerableLLMApp()
        info = target_app.get_system_info()
        requested_provider = spec.target_provider
        requested_model = spec.target_model
        actual_provider = info.get("llm_provider")
        actual_model = info.get("model_name")

        if requested_provider and requested_provider != actual_provider:
            raise ValueError(
                "Requested target provider does not match the configured runtime provider: "
                f"requested={requested_provider}, actual={actual_provider}"
            )

        if requested_model and requested_model != actual_model:
            raise ValueError(
                "Requested target model does not match the configured runtime model: "
                f"requested={requested_model}, actual={actual_model or 'unset'}"
            )

        return target_app

    def resolve(self, spec: TargetSpec) -> tuple[TargetSpec, TargetRuntime]:
        normalized = self.normalize(spec)
        runtime = self.build_runtime(normalized)
        info = runtime.get_system_info()
        resolved = TargetSpec(
            target_type=self.target_type,
            target_provider=info.get("llm_provider") or normalized.target_provider,
            target_model=info.get("model_name") or normalized.target_model,
            target_config=dict(normalized.target_config),
        )
        return resolved, runtime


class HostedChatModelRuntime:
    def __init__(
        self,
        *,
        provider: str,
        model: str,
        config: Dict[str, Any],
    ):
        self.provider = provider
        self.model = model
        self.config = dict(config)
        self.system_prompt = self.config["system_prompt"]
        self.capabilities = dict(self.config["capabilities"])
        self.constraints = list(self.config["constraints"])
        self._client = self._build_client()

    def _build_client(self) -> Any:
        load_environment()

        if self.provider == "openai":
            api_key = os.getenv("OPENAI_API_KEY")
            if not api_key:
                raise ValueError(
                    "target_provider=openai requires OPENAI_API_KEY to be configured."
                )
            import openai

            return openai.OpenAI(api_key=api_key)

        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            raise ValueError(
                "target_provider=anthropic requires ANTHROPIC_API_KEY to be configured."
            )
        import anthropic

        return anthropic.Anthropic(api_key=api_key)

    def process_message(self, user_input: str) -> Dict[str, Any]:
        if self.provider == "openai":
            messages = []
            if self.system_prompt:
                messages.append({"role": "system", "content": self.system_prompt})
            messages.append({"role": "user", "content": user_input})
            response = self._client.chat.completions.create(
                model=self.model,
                messages=messages,
                max_tokens=500,
                temperature=0,
            )
            message = response.choices[0].message.content or ""
        else:
            response = self._client.messages.create(
                model=self.model,
                system=self.system_prompt,
                messages=[{"role": "user", "content": user_input}],
                max_tokens=500,
            )
            parts = getattr(response, "content", []) or []
            message = "".join(
                getattr(part, "text", "")
                for part in parts
                if getattr(part, "text", None)
            )

        return {
            "message": message,
            "model_used": self.model,
            "provider_used": self.provider,
        }

    def get_system_info(self) -> Dict[str, Any]:
        return {
            "system_prompt_length": len(self.system_prompt),
            "conversation_history_length": 0,
            "has_sensitive_data": False,
            "tools_available": [],
            "llm_provider": self.provider,
            "model_name": self.model,
            "capabilities": dict(self.capabilities),
            "constraints": list(self.constraints),
        }


class HostedChatModelAdapter:
    target_type = HOSTED_CHAT_TARGET_TYPE

    def normalize(self, spec: TargetSpec) -> TargetSpec:
        provider = (spec.target_provider or "").strip().lower()
        if provider not in SUPPORTED_HOSTED_PROVIDERS:
            supported = ", ".join(sorted(SUPPORTED_HOSTED_PROVIDERS))
            raise ValueError(
                "hosted_chat_model target_provider must be one of "
                f"{supported}; received {spec.target_provider or 'unset'}."
            )

        model = (spec.target_model or "").strip()
        if not model:
            raise ValueError("hosted_chat_model requires target_model to be set.")

        return TargetSpec(
            target_type=self.target_type,
            target_provider=provider,
            target_model=model,
            target_config=_normalize_hosted_chat_config(spec.target_config),
        )

    def build_runtime(self, spec: TargetSpec) -> TargetRuntime:
        return HostedChatModelRuntime(
            provider=spec.target_provider or "",
            model=spec.target_model or "",
            config=spec.target_config,
        )

    def resolve(self, spec: TargetSpec) -> tuple[TargetSpec, TargetRuntime]:
        normalized = self.normalize(spec)
        runtime = self.build_runtime(normalized)
        return normalized, runtime


ADAPTERS: Dict[str, TargetAdapter] = {
    DEFAULT_TARGET_TYPE: VulnerableLLMAppAdapter(),
    HOSTED_CHAT_TARGET_TYPE: HostedChatModelAdapter(),
}


def normalize_target_spec(
    *,
    target_type: Optional[str] = None,
    target_provider: Optional[str] = None,
    target_model: Optional[str] = None,
    target_config: Optional[Dict[str, Any]] = None,
) -> TargetSpec:
    normalized_type = (target_type or DEFAULT_TARGET_TYPE).strip()
    if normalized_type not in SUPPORTED_TARGET_TYPES:
        supported = ", ".join(sorted(SUPPORTED_TARGET_TYPES))
        raise ValueError(
            f"Unsupported target_type {normalized_type!r}. Expected one of: {supported}."
        )

    spec = TargetSpec(
        target_type=normalized_type,
        target_provider=target_provider,
        target_model=target_model,
        target_config=dict(target_config or {}),
    )
    return ADAPTERS[normalized_type].normalize(spec)


def resolve_target_spec(spec: TargetSpec) -> tuple[TargetSpec, TargetRuntime]:
    return ADAPTERS[spec.target_type].resolve(spec)
