from __future__ import annotations

import json
import logging
import re
import uuid
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Any, Dict, Iterator, Optional

REQUEST_ID_HEADER = "X-Request-ID"
SERVICE_NAME = "redteaming_ai.api"

_REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_REQUEST_ID_CONTEXT: ContextVar[Optional[str]] = ContextVar(
    "redteaming_ai_request_id",
    default=None,
)
_SAFE_FIELD_NAMES = {
    "duration_ms",
    "error_type",
    "method",
    "operation",
    "outcome",
    "path",
    "reason",
    "remediation",
    "request_id",
    "run_id",
    "run_status",
    "status_code",
    "target_model",
    "target_provider",
    "target_type",
}
_LOGGER = logging.getLogger(SERVICE_NAME)


def normalize_request_id(value: Optional[str]) -> str:
    candidate = (value or "").strip()
    if candidate and _REQUEST_ID_PATTERN.fullmatch(candidate):
        return candidate
    return str(uuid.uuid4())


def get_request_id() -> Optional[str]:
    return _REQUEST_ID_CONTEXT.get()


@contextmanager
def request_logging_context(request_id: Optional[str]) -> Iterator[None]:
    token = _REQUEST_ID_CONTEXT.set(request_id)
    try:
        yield
    finally:
        _REQUEST_ID_CONTEXT.reset(token)


def log_event(
    event: str,
    *,
    level: int = logging.INFO,
    request_id: Optional[str] = None,
    **fields: Any,
) -> None:
    payload: Dict[str, Any] = {
        "event": event,
        "service": SERVICE_NAME,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    active_request_id = request_id or get_request_id()
    if active_request_id:
        payload["request_id"] = active_request_id

    for key, value in fields.items():
        if key not in _SAFE_FIELD_NAMES:
            continue
        if isinstance(value, (str, int, float, bool)) or value is None:
            payload[key] = value

    _LOGGER.log(
        level,
        json.dumps(payload, sort_keys=True),
        extra={"structured_event": payload},
    )
