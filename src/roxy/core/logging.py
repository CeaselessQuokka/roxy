"""Structured logging: one JSON object per line on stderr, with secrets scrubbed from every record.

What this is
    `configure_logging(level)` installs Roxy's log handler on the root logger, `get_logger(name)` returns a logger,
    and `RedactionFilter` is the filter that cleans every record before it is written. Log with an event name and
    structured fields: `log.info("cache_purged", extra={"fields": {"keys": 12}})`.

Why it exists
    v1 printed free text through a handler nobody configured, so most of it was lost, and what was printed could
    contain query strings with secrets (the journal dump in alert emails leaked them). Plan 9.15: JSON lines to
    journald, redaction on the ROOT handler so third-party loggers (httpx, uvicorn) are scrubbed too, and the noisy
    HTTP libraries pinned to WARNING so DEBUG never prints request headers (C2 item 8).

How it works
    The handler writes to stderr (systemd sends it to journald). The filter runs before formatting: it renders the
    message, runs `redact_text` over it, over every string inside `fields`, over exception tracebacks and stack
    traces, and replaces values whose field NAME is secret. The formatter then builds one JSON object with the
    time, level, logger, event, the current request id (from a context variable the request id middleware sets,
    so every line logged while serving a request carries its id without passing it around) and the fields.
    Client IP fields can be replaced by their keyed hash when `log_hash_client_ips` is on (`set_ip_hasher`).

What to read next
    `roxy/core/redact.py` (what "scrubbed" means), then `roxy/core/middleware.py` (where the request id is set).
"""

from __future__ import annotations

import json
import logging
import sys
from collections.abc import Callable, Mapping
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import IO, Any

from roxy.core.redact import MASK, is_secret_field, redact_text

request_id_var: ContextVar[str | None] = ContextVar("roxy_request_id", default=None)
"""The id of the request being served by the current task (None outside requests)."""

THIRD_PARTY_PINNED = ("httpx", "httpcore", "h2", "hpack", "aiosmtplib")
"""Loggers held at WARNING or above whatever ROXY_LOG_LEVEL says: at DEBUG they print headers and bodies (C2)."""

SERVER_LOGGERS = ("uvicorn", "uvicorn.error", "uvicorn.access", "uvicorn.asgi", "gunicorn.error", "gunicorn.access")
"""Loggers the server configures with its own handlers (not propagating to root); they get the filter too."""

IP_FIELD_NAMES = frozenset({"client_ip", "ip", "peer_ip", "caller_ip", "remote_ip"})
"""Field names that hold a caller IP, hashed in logs when `log_hash_client_ips` is on (plan 9.15)."""

_MAX_FIELD_DEPTH = 5
_RESERVED_KEYS = frozenset({"ts", "level", "logger", "event", "request_id", "exc", "stack"})

_ip_hasher: Callable[[str], str] | None = None


def set_ip_hasher(hasher: Callable[[str], str] | None) -> None:
    """Turn client IP hashing in log fields on (pass `lambda ip: ip_hash(ip, key)`) or off (None)."""
    global _ip_hasher
    _ip_hasher = hasher


def _clean_value(name: str | None, value: Any, depth: int) -> Any:
    if name is not None and is_secret_field(name, value):
        return MASK
    if isinstance(value, str):
        if name in IP_FIELD_NAMES and _ip_hasher is not None and value:
            return _ip_hasher(value)
        return redact_text(value)
    if isinstance(value, bytes | bytearray):
        return redact_text(bytes(value).decode("utf-8", "replace"))
    if depth >= _MAX_FIELD_DEPTH:
        return redact_text(str(value))
    if isinstance(value, Mapping):
        return {str(k): _clean_value(str(k), v, depth + 1) for k, v in value.items()}
    if isinstance(value, list | tuple | set | frozenset):
        return [_clean_value(None, item, depth + 1) for item in value]
    if value is None or isinstance(value, bool | int | float):
        return value
    # Anything else (exceptions, enums, paths, objects) is logged by its text, which is scrubbed like any text.
    return redact_text(str(value))


def redact_fields(fields: Mapping[str, Any]) -> dict[str, Any]:
    """Return a scrubbed copy of a structured `fields` mapping (secret names masked, strings redacted)."""
    return {str(k): _clean_value(str(k), v, 0) for k, v in fields.items()}


class RedactionFilter(logging.Filter):
    """Scrubs a log record in place. Attached to handlers, so it sees records from every logger.

    It never drops a record (always returns True) and never raises: a filter that raised would lose the very log
    line that explains a failure.
    """

    _formatter = logging.Formatter()

    def filter(self, record: logging.LogRecord) -> bool:
        if getattr(record, "_roxy_redacted", False):
            return True  # already cleaned by another handler's filter; redaction is not free
        try:
            try:
                message = record.getMessage()
            except Exception:  # a bad %-format must not lose the line
                message = f"{record.msg!s} {record.args!r}"
            cleaned = redact_text(message)
            if not self._keep_positional_args(record, message, cleaned):
                record.msg = cleaned
                record.args = None
            fields = getattr(record, "fields", None)
            if isinstance(fields, Mapping):
                # setattr: `fields` arrives through `extra=`, so LogRecord does not declare it for the type checker.
                setattr(record, "fields", redact_fields(fields))  # noqa: B010
            if record.exc_info:
                if not record.exc_text:
                    record.exc_text = self._formatter.formatException(record.exc_info)
                record.exc_text = redact_text(record.exc_text)
            elif record.exc_text:
                record.exc_text = redact_text(record.exc_text)
            if record.stack_info:
                record.stack_info = redact_text(record.stack_info)
        except Exception:  # pragma: no cover - defensive: keep a minimal, safe line rather than nothing
            record.msg = "log_record_redaction_failed"
            record.args = None
            record.exc_info = None
            record.exc_text = None
        setattr(record, "_roxy_redacted", True)  # noqa: B010
        return True

    @staticmethod
    def _keep_positional_args(record: logging.LogRecord, message: str, cleaned: str) -> bool:
        """Keep a positional `args` tuple when the rendered line is provably clean; True when kept.

        Some server formatters read `record.args` directly instead of the rendered message: uvicorn's access
        formatter unpacks the five values (client, method, path, HTTP version, status), so replacing them with None
        breaks every access line. The tuple is kept when nothing in the line needed redacting, or when redacting
        each argument (and the format string) on its own yields a line that is clean. Otherwise the caller falls
        back to the rendered, redacted text with no args: a secret never survives to save a formatter.
        """
        args = record.args
        if not isinstance(args, tuple) or not args or not isinstance(record.msg, str):
            return False
        if cleaned == message:
            return True  # nothing secret in this line: leave it exactly as it was logged
        redacted_args = tuple(redact_text(arg) if isinstance(arg, str) else arg for arg in args)
        redacted_msg = redact_text(record.msg)
        try:
            candidate = redacted_msg % redacted_args
        except Exception:
            return False
        if redact_text(candidate) != candidate:
            return False
        record.msg, record.args = redacted_msg, redacted_args
        return True


class JsonFormatter(logging.Formatter):
    """Formats a record as one JSON object on one line (journald keeps it as a single entry)."""

    def __init__(self, static_fields: Mapping[str, Any] | None = None) -> None:
        super().__init__()
        self._static = dict(static_fields or {})

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname.lower(),
            "logger": record.name,
            "event": record.getMessage(),
        }
        request_id = getattr(record, "request_id", None) or request_id_var.get()
        if request_id:
            payload["request_id"] = request_id
        payload.update(self._static)
        fields = getattr(record, "fields", None)
        if isinstance(fields, Mapping):
            for key, value in fields.items():
                # A field never overwrites the envelope (so a field called "level" cannot fake a severity).
                payload[f"field_{key}" if key in _RESERVED_KEYS else str(key)] = value
        if record.exc_info and not record.exc_text:
            record.exc_text = self.formatException(record.exc_info)
        if record.exc_text:
            payload["exc"] = record.exc_text
        if record.stack_info:
            payload["stack"] = record.stack_info
        # ensure_ascii keeps control characters and odd bytes escaped, so a caller cannot forge log lines.
        return json.dumps(payload, default=str, ensure_ascii=True, separators=(",", ":"))


def _level_number(level: str | int) -> int:
    if isinstance(level, int):
        return level
    number = logging.getLevelName(level.strip().upper())
    if not isinstance(number, int):
        raise ValueError(f"unknown log level: {level!r}")
    return number


def configure_logging(
    level: str | int = "info",
    *,
    static_fields: Mapping[str, Any] | None = None,
    stream: IO[str] | None = None,
) -> logging.Handler:
    """Install Roxy's JSON handler with the redaction filter on the root logger. Safe to call more than once.

    Returns the handler (tests pass a `stream` and read it back).
    """
    number = _level_number(level)
    root = logging.getLogger()
    for existing in list(root.handlers):
        if getattr(existing, "_roxy_handler", False):
            root.removeHandler(existing)
    handler = logging.StreamHandler(stream or sys.stderr)
    handler.setFormatter(JsonFormatter(static_fields))
    handler.addFilter(RedactionFilter())
    handler._roxy_handler = True  # type: ignore[attr-defined]
    root.addHandler(handler)
    root.setLevel(number)
    # Pinned, never more verbose than WARNING (and never more verbose than the root level either).
    for name in THIRD_PARTY_PINNED:
        logging.getLogger(name).setLevel(max(logging.WARNING, number))
    # Server loggers keep their own handlers (gunicorn's error log); scrub those too.
    for name in SERVER_LOGGERS:
        for server_handler in logging.getLogger(name).handlers:
            if not any(isinstance(f, RedactionFilter) for f in server_handler.filters):
                server_handler.addFilter(RedactionFilter())
    logging.captureWarnings(True)
    return handler


def get_logger(name: str) -> logging.Logger:
    """Return the logger for a module. Use `get_logger(__name__)`."""
    return logging.getLogger(name)
