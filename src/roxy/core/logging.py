"""Structured logging: one JSON object per line on stderr, with secrets scrubbed from every record.

What this is
    `configure_logging(level)` installs Roxy's log handler on the root logger, `get_logger(name)` returns a logger,
    and `RedactionFilter` is the filter that cleans every record before it is written. Log with an event name and
    structured fields: `log.info("cache_purged", extra={"fields": {"keys": 12}})`. The server passes
    `background=True`: lines are then written by `BackgroundLogWriter`'s thread, never on the event loop, and
    `flush_logging(timeout_s)` waits (bounded) until they are out.

Why it exists
    v1 printed free text through a handler nobody configured, so most of it was lost, and what was printed could
    contain query strings with secrets (the journal dump in alert emails leaked them). Plan 9.15: JSON lines to
    journald, redaction on the ROOT handler so third-party loggers (httpx, uvicorn) are scrubbed too, and the noisy
    HTTP libraries pinned to WARNING so DEBUG never prints request headers (C2 item 8).
    systemd connects stderr to journald through a pipe. A plain `StreamHandler` writes to it on the thread that
    logs, which for the server is the event loop: when journald pauses (busy, restarting) and the pipe's 64 KiB
    fill up, the next log line freezes every request of the worker until journald reads again, and a 30 s pause
    gets the worker killed by gunicorn's watchdog (finding mp-11). Incidents are when the most lines are logged.

How it works
    The filter runs before formatting, on the thread that logs: it renders the message, runs `redact_text` over
    it, over every string inside `fields` (each cut to `MAX_FIELD_CHARS` first, so one huge caller text cannot make
    a log line expensive), over exception tracebacks and stack traces, and replaces values whose field NAME is
    secret. The formatter then builds one JSON object with the time, level, logger, event, the current request id
    (from a context variable the request id middleware sets, so every line logged while serving a request carries
    its id without passing it around) and the fields. Client IP fields can be replaced by their keyed hash when
    `log_hash_client_ips` is on (`set_ip_hasher`).
    Writing differs by mode. Scripts and tests (the default) write each line at once, so they can read the stream
    back. The server (`background=True`, `roxy/lifespan.py`) formats on the logging thread as above (redaction and
    the request id need that thread), then hands the finished line to `BackgroundLogWriter`: a bounded queue
    (`LOG_QUEUE_MAX_LINES` lines and `LOG_QUEUE_MAX_BYTES` of text, plan P9) drained by one daemon thread that
    owns the stream. A full queue drops the line and counts it, never waits; the writer reports the count in a
    `log_lines_dropped` line as soon as the stream takes lines again. The lifespan flushes it at shutdown within
    its budget, and `logging.shutdown` (at process exit) flushes and closes it with a bounded wait.

What to read next
    `roxy/core/redact.py` (what "scrubbed" means), then `roxy/core/middleware.py` (where the request id is set).
"""

from __future__ import annotations

import json
import logging
import os
import sys
import threading
import time
from collections import deque
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

MAX_FIELD_CHARS = 8192
"""Longest text one log field keeps; the rest is cut BEFORE redaction, so a caller's 8 KiB path or 1 MiB body
never makes a log line cost more than this much scrubbing (defense in depth for findings INGRESS-1 and public-4).
Cutting first is safe: a credential piece shorter than the 24 character leak window is not a leak, and a longer
one before the cut is still found."""

LOG_QUEUE_MAX_LINES = 10_000
"""Lines the background writer holds at most while the stream is slow (plan P9); more are dropped and counted."""

LOG_QUEUE_MAX_BYTES = 4 * 1024 * 1024
"""Characters of text the background writer holds at most (one batch being written can add as much again)."""

LOG_CLOSE_TIMEOUT_S = 2.0
"""How long closing the background writer (process exit, a new `configure_logging`) waits for queued lines."""

_ip_hasher: Callable[[str], str] | None = None


def set_ip_hasher(hasher: Callable[[str], str] | None) -> None:
    """Turn client IP hashing in log fields on (pass `lambda ip: ip_hash(ip, key)`) or off (None)."""
    global _ip_hasher
    _ip_hasher = hasher


def _bounded(text: str) -> str:
    """`text` cut to `MAX_FIELD_CHARS`, saying how much was cut."""
    if len(text) <= MAX_FIELD_CHARS:
        return text
    return f"{text[:MAX_FIELD_CHARS]}...[cut {len(text) - MAX_FIELD_CHARS} chars]"


def _clean_value(name: str | None, value: Any, depth: int) -> Any:
    if name is not None and is_secret_field(name, value):
        return MASK
    if isinstance(value, str):
        if name in IP_FIELD_NAMES and _ip_hasher is not None and value:
            return _ip_hasher(value)
        return redact_text(_bounded(value))
    if isinstance(value, bytes | bytearray):
        return redact_text(_bounded(bytes(value[: MAX_FIELD_CHARS * 4]).decode("utf-8", "replace")))
    if depth >= _MAX_FIELD_DEPTH:
        return redact_text(_bounded(str(value)))
    if isinstance(value, Mapping):
        return {str(k): _clean_value(str(k), v, depth + 1) for k, v in value.items()}
    if isinstance(value, list | tuple | set | frozenset):
        return [_clean_value(None, item, depth + 1) for item in value]
    if value is None or isinstance(value, bool | int | float):
        return value
    # Anything else (exceptions, enums, paths, objects) is logged by its text, which is scrubbed like any text.
    return redact_text(_bounded(str(value)))


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


class BackgroundLogWriter:
    """Writes finished log lines to a stream on its own daemon thread, so a slow reader never stalls the logger.

    `put(line)` never blocks: it queues the line, or drops and counts it when `max_lines` lines or `max_bytes`
    characters are already waiting (plan P9). The thread takes everything queued at once, writes it with one
    `write` and one `flush`, and before the next batch reports what was dropped meanwhile in a
    `log_lines_dropped` line. `flush(timeout_s)` waits until the queue is written, `close(timeout_s)` does the same
    and stops the thread; both wait at most `timeout_s`. A write error (a closed stream) is counted, never raised.
    The thread starts on the first line and again in a forked child (it does not survive a fork).
    """

    def __init__(
        self,
        stream: IO[str],
        *,
        max_lines: int = LOG_QUEUE_MAX_LINES,
        max_bytes: int = LOG_QUEUE_MAX_BYTES,
        name: str = "roxy-log-writer",
    ) -> None:
        self.stream = stream
        self.max_lines = max(1, int(max_lines))
        self.max_bytes = max(1, int(max_bytes))
        self._name = name
        self._cond = threading.Condition()
        self._lines: deque[str] = deque()
        self._bytes = 0
        self._writing = False  # a batch is being written right now
        self._unreported = 0  # dropped since the last `log_lines_dropped` line
        self._closed = False
        self._thread: threading.Thread | None = None
        self._pid = os.getpid()
        self.written = 0
        self.dropped = 0
        self.write_errors = 0

    def put(self, line: str) -> bool:
        """Queue one line (without its newline). Never blocks; False when it was dropped."""
        size = len(line)
        with self._cond:
            if self._closed or len(self._lines) >= self.max_lines or self._bytes + size > self.max_bytes:
                self.dropped += 1
                self._unreported += 1
                return False
            self._lines.append(line)
            self._bytes += size
            self._start_locked()
            self._cond.notify_all()
        return True

    def _start_locked(self) -> None:
        if self._thread is not None and self._pid == os.getpid():
            return
        # First line, or a forked child: threads do not survive fork(), so this process needs its own.
        self._pid = os.getpid()
        self._thread = threading.Thread(target=self._run, name=self._name, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        while True:
            with self._cond:
                while not self._lines and not self._closed:
                    self._cond.wait()
                if not self._lines:
                    return  # closed and everything written
                batch = list(self._lines)
                self._lines.clear()
                self._bytes = 0
                dropped, self._unreported = self._unreported, 0
                self._writing = True
            try:
                text = "".join(f"{line}\n" for line in batch)
                if dropped:
                    text = _dropped_line(dropped) + "\n" + text
                self.stream.write(text)
                self.stream.flush()
                self.written += len(batch)
            except Exception:  # a closed or broken stream: nothing to report it to, so count it
                self.write_errors += 1
            finally:
                with self._cond:
                    self._writing = False
                    self._cond.notify_all()

    def flush(self, timeout_s: float) -> bool:
        """Wait (at most `timeout_s`) until every queued line is written; True when it is."""
        deadline = time.monotonic() + max(0.0, timeout_s)
        with self._cond:
            if self._thread is None or self._pid != os.getpid():
                return not self._lines
            while self._lines or self._writing:
                left = deadline - time.monotonic()
                if left <= 0:
                    return False
                self._cond.wait(left)
            return True

    def close(self, timeout_s: float = LOG_CLOSE_TIMEOUT_S) -> bool:
        """Write what is queued (at most `timeout_s`), then stop the thread. Later lines are dropped."""
        written = self.flush(timeout_s)
        with self._cond:
            self._closed = True
            self._cond.notify_all()
            thread = self._thread
        if thread is not None and written and thread is not threading.current_thread():
            thread.join(timeout=max(0.0, timeout_s))
        return written

    def pending(self) -> int:
        """Lines queued and not written yet."""
        with self._cond:
            return len(self._lines)


def _dropped_line(count: int) -> str:
    """The line that reports lines the background writer had to drop (same JSON shape as every other line)."""
    payload = {
        "ts": datetime.now(UTC).isoformat(timespec="milliseconds"),
        "level": "warning",
        "logger": __name__,
        "event": "log_lines_dropped",
        "count": count,
        "pid": os.getpid(),
    }
    return json.dumps(payload, separators=(",", ":"))


class BackgroundStreamHandler(logging.Handler):
    """A handler that formats on the logging thread and writes through a `BackgroundLogWriter`.

    Filters (`RedactionFilter`) and the formatter run in `handle()` on the thread that logged, so every line is
    scrubbed and carries its request id before it is queued; only the write happens on the writer's thread.
    """

    def __init__(self, stream: IO[str], **writer_options: Any) -> None:
        super().__init__()
        self.writer = BackgroundLogWriter(stream, **writer_options)
        self.format_errors = 0

    def emit(self, record: logging.LogRecord) -> None:
        try:
            line = self.format(record)
        except Exception:
            self.format_errors += 1  # handleError would print to stderr on this thread: the very wait we avoid
            return
        self.writer.put(line)

    def flush(self) -> None:
        self.writer.flush(LOG_CLOSE_TIMEOUT_S)

    def close(self) -> None:
        self.writer.close(LOG_CLOSE_TIMEOUT_S)
        super().close()


def flush_logging(timeout_s: float) -> bool:
    """Wait (at most `timeout_s`) until Roxy's background log handler has written every queued line.

    True when nothing is left (also when logging is not in background mode). The lifespan calls it last at
    shutdown, on a thread, with what is left of its budget.
    """
    for handler in logging.getLogger().handlers:
        if getattr(handler, "_roxy_handler", False) and isinstance(handler, BackgroundStreamHandler):
            return handler.writer.flush(timeout_s)
    return True


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
    background: bool = False,
) -> logging.Handler:
    """Install Roxy's JSON handler with the redaction filter on the root logger. Safe to call more than once.

    Returns the handler (tests pass a `stream` and read it back). With `background=True` (the server) lines are
    written by a `BackgroundLogWriter` thread, so logging never blocks the caller (module docstring); the handler
    it replaces is closed (its queued lines written, at most `LOG_CLOSE_TIMEOUT_S`).
    """
    number = _level_number(level)
    root = logging.getLogger()
    for existing in list(root.handlers):
        if getattr(existing, "_roxy_handler", False):
            root.removeHandler(existing)
            if isinstance(existing, BackgroundStreamHandler):
                existing.close()  # stop its writer thread; a plain StreamHandler's stream belongs to the caller
    target = stream or sys.stderr
    handler: logging.Handler = BackgroundStreamHandler(target) if background else logging.StreamHandler(target)
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
