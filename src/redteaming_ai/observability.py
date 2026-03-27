from __future__ import annotations

import contextvars
import json
import logging
import re
import uuid
from contextlib import contextmanager
from typing import Any, Dict, Iterable, Iterator, Mapping, Optional

REQUEST_ID_HEADER = "X-Request-ID"
SERVICE_NAME = "redteaming-ai-api"

_REQUEST_ID = contextvars.ContextVar("redteaming_ai_request_id", default=None)
_REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
_EMAIL_PATTERN = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
_PHONE_PATTERN = re.compile(r"(?<!\w)(?:\+?\d[\d(). -]{7,}\d)")
_BEARER_PATTERN = re.compile(r"(?i)\bbearer\s+[A-Z0-9._~+/-]+=*")
_HEADER_SECRET_PATTERN = re.compile(
    r"(?i)\b(authorization|cookie)\s*:\s*([^\s,;]+(?:\s+[^\s,;]+)*)"
)
_QUOTED_SECRET_PATTERN = re.compile(
    r"""(?ix)
    (["']?(?:authorization|cookie|token|secret|password|api[_-]?key)["']?\s*[:=]\s*)
    (["'])
    (?:\\.|(?!\2).)*
    \2
    """
)
_ASSIGNMENT_SECRET_PATTERN = re.compile(
    r"(?i)\b(token|secret|password|api[_-]?key)\b\s*[:=]\s*([^\s,;]+)"
)
_SAFE_LOC_PARTS = {"body", "query", "path", "header", "cookie"}
_SAFE_LOC_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")

_SENSITIVE_KEY_PARTS = (
    "authorization",
    "cookie",
    "token",
    "secret",
    "password",
    "api_key",
    "apikey",
    "email",
    "phone",
    "payload",
    "response",
    "prompt",
    "body",
    "text",
)
_SAFE_KEYS = {
    "error_message",
    "error_type",
    "hint",
    "method",
    "path",
    "request_id",
    "run_id",
    "status",
    "status_code",
    "target_type",
    "validation_errors",
}
_RAW_STRING_SAFE_KEYS = {"request_id", "run_id"}


def normalize_request_id(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    request_id = value.strip()
    if not request_id or len(request_id) > 128:
        return None
    if _REQUEST_ID_PATTERN.fullmatch(request_id) is None:
        return None
    return request_id


def resolve_request_id(value: Optional[str]) -> str:
    return normalize_request_id(value) or str(uuid.uuid4())


def get_request_id() -> Optional[str]:
    return _REQUEST_ID.get()


@contextmanager
def request_id_context(request_id: Optional[str]) -> Iterator[Optional[str]]:
    token = _REQUEST_ID.set(request_id)
    try:
        yield request_id
    finally:
        _REQUEST_ID.reset(token)


def sanitize_text(value: Any) -> str:
    text = str(value)
    text = _HEADER_SECRET_PATTERN.sub(lambda match: f"{match.group(1)}: [redacted]", text)
    text = _QUOTED_SECRET_PATTERN.sub(
        lambda match: f"{match.group(1)}{match.group(2)}[redacted]{match.group(2)}",
        text,
    )
    text = _ASSIGNMENT_SECRET_PATTERN.sub(lambda match: f"{match.group(1)}=[redacted]", text)
    text = _BEARER_PATTERN.sub("Bearer [redacted]", text)
    text = _EMAIL_PATTERN.sub("[redacted-email]", text)
    text = _PHONE_PATTERN.sub("[redacted-phone]", text)
    return text


def safe_validation_errors(errors: Iterable[Mapping[str, Any]]) -> list[Dict[str, Any]]:
    sanitized = []
    for error in errors:
        sanitized.append(
            {
                "loc": [_sanitize_loc_part(part) for part in error.get("loc", ())],
                "type": sanitize_text(error.get("type", "validation_error")),
            }
        )
    return sanitized


def log_event(
    logger: logging.Logger,
    level: int,
    operation: str,
    outcome: str,
    **fields: Any,
) -> Dict[str, Any]:
    event: Dict[str, Any] = {
        "service": SERVICE_NAME,
        "operation": operation,
        "outcome": outcome,
    }
    request_id = fields.pop("request_id", None) or get_request_id()
    if request_id:
        event["request_id"] = request_id

    for key, value in fields.items():
        if value is None:
            continue
        event[key] = _sanitize_field(key, value)

    logger.log(level, json.dumps(event, sort_keys=True))
    return event


def log_info(logger: logging.Logger, operation: str, outcome: str, **fields: Any) -> Dict[str, Any]:
    return log_event(logger, logging.INFO, operation, outcome, **fields)


def log_warning(
    logger: logging.Logger, operation: str, outcome: str, **fields: Any
) -> Dict[str, Any]:
    return log_event(logger, logging.WARNING, operation, outcome, **fields)


def log_error(logger: logging.Logger, operation: str, outcome: str, **fields: Any) -> Dict[str, Any]:
    return log_event(logger, logging.ERROR, operation, outcome, **fields)


def _sanitize_field(key: str, value: Any) -> Any:
    if key == "validation_errors":
        return safe_validation_errors(value)
    if _is_sensitive_key(key) or key not in _SAFE_KEYS:
        return "[redacted]"
    if key in _RAW_STRING_SAFE_KEYS:
        return str(value)
    if isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, Mapping):
        return "[redacted]"
    if isinstance(value, (list, tuple, set)):
        return [sanitize_text(item) for item in value]
    return sanitize_text(value)


def _is_sensitive_key(key: str) -> bool:
    normalized = key.lower()
    return any(part in normalized for part in _SENSITIVE_KEY_PARTS)


def _sanitize_loc_part(part: Any) -> Any:
    if isinstance(part, int):
        return part

    text = sanitize_text(part)
    if text in _SAFE_LOC_PARTS:
        return text
    if _is_sensitive_key(text):
        return "[redacted]"
    if _SAFE_LOC_IDENTIFIER_PATTERN.fullmatch(text):
        return text
    return "[redacted]"
