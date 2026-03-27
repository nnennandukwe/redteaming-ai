from __future__ import annotations

import json
import logging
from contextvars import ContextVar, Token
from typing import Any, Dict, Optional

REQUEST_ID_HEADER = "X-Request-ID"

_request_id_var: ContextVar[Optional[str]] = ContextVar("request_id", default=None)

SAFE_LOG_FIELDS = frozenset(
    {
        "duration_ms",
        "duration_seconds",
        "error_type",
        "method",
        "path",
        "request_id",
        "run_id",
        "status",
        "status_code",
        "target_model",
        "target_provider",
        "target_type",
    }
)


def get_request_id() -> Optional[str]:
    return _request_id_var.get()


def set_request_id(request_id: Optional[str]) -> Token[Optional[str]]:
    return _request_id_var.set(request_id)


def reset_request_id(token: Token[Optional[str]]) -> None:
    _request_id_var.reset(token)


def clear_request_id() -> None:
    _request_id_var.set(None)


def log_event(
    logger: logging.Logger,
    level: int,
    event: str,
    **fields: Any,
) -> Dict[str, Any]:
    payload: Dict[str, Any] = {"event": event}
    request_id = fields.pop("request_id", None) or get_request_id()
    if request_id:
        payload["request_id"] = request_id

    for key, value in fields.items():
        if key not in SAFE_LOG_FIELDS or value is None:
            continue
        if isinstance(value, (str, int, float, bool)):
            payload[key] = value
        else:
            payload[key] = str(value)

    logger.log(
        level,
        json.dumps(payload, sort_keys=True),
        extra={"event_name": event, "structured_data": payload, **payload},
    )
    return payload
