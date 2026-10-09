"""Structured logging tests (plan 9.15): JSON lines, redaction on the root handler, pinned third-party loggers."""

from __future__ import annotations

import io
import json
import logging
import secrets
import threading
import time

import pytest

from roxy.core.logging import (
    MAX_FIELD_CHARS,
    THIRD_PARTY_PINNED,
    BackgroundLogWriter,
    BackgroundStreamHandler,
    configure_logging,
    flush_logging,
    get_logger,
    redact_fields,
    request_id_var,
    set_ip_hasher,
)
from roxy.core.redact import MASK, TOKEN_PREFIX, SecretRegistry

pytestmark = pytest.mark.usefixtures("restore_logging")


def lines(stream: io.StringIO) -> list[dict[str, object]]:
    return [json.loads(line) for line in stream.getvalue().splitlines() if line.strip()]


def test_json_line_with_event_and_fields() -> None:
    stream = io.StringIO()
    configure_logging("info", static_fields={"color": "dev"}, stream=stream)
    get_logger("roxy.test").info("cache_purged", extra={"fields": {"keys": 12, "level": "fake"}})
    [record] = lines(stream)
    assert record["event"] == "cache_purged"
    assert record["level"] == "info"
    assert record["logger"] == "roxy.test"
    assert record["keys"] == 12
    assert record["color"] == "dev"
    assert record["field_level"] == "fake"  # a field can never overwrite the envelope


def test_request_id_from_context() -> None:
    stream = io.StringIO()
    configure_logging("info", stream=stream)
    token = request_id_var.set("01TESTREQUESTID0000000000")
    try:
        logging.getLogger("roxy.test").info("inside_request")
    finally:
        request_id_var.reset(token)
    logging.getLogger("roxy.test").info("outside_request")
    first, second = lines(stream)
    assert first["request_id"] == "01TESTREQUESTID0000000000"
    assert "request_id" not in second


def test_debug_logging_redacts_secrets_from_every_logger() -> None:
    """P0 part of `test_debug_logging_never_leaks` (9.15): DEBUG on, secrets logged every way, none printed."""
    stream = io.StringIO()
    configure_logging("debug", stream=stream)
    credential = TOKEN_PREFIX + "FAKE" + secrets.token_hex(100).upper()
    smtp = "smtp-" + secrets.token_hex(8)
    SecretRegistry.register("roblox_credential", credential)
    SecretRegistry.register("smtp_password", smtp)
    half = credential[len(TOKEN_PREFIX) + 10 : len(TOKEN_PREFIX) + 60]
    log = logging.getLogger("some.third.party")
    log.debug("sending cookie %s", credential)
    log.debug("partial %s and smtp %s", half, smtp)
    log.debug("proxy", extra={"fields": {"url": "http://u:p4ssw0rd@gw.example.test:1", "password": "x" * 20}})
    try:
        raise RuntimeError(f"upstream said no for {credential}")
    except RuntimeError:
        log.exception("failure")
    output = stream.getvalue()
    for leaked in (credential, half, smtp, "p4ssw0rd", "x" * 20, "WARNING:-DO-NOT-SHARE"):
        assert leaked not in output
    assert MASK in output


def test_uvicorn_access_lines_keep_their_args_and_stay_redacted() -> None:
    """Integration pass: uvicorn's AccessFormatter unpacks `record.args`, so the filter must keep the 5-tuple.

    Before the fix every access line raised "cannot unpack non-iterable NoneType" inside the handler (a logging
    traceback per request under plain uvicorn) and the line itself was lost.
    """
    from uvicorn.logging import AccessFormatter

    stream = io.StringIO()
    access = logging.getLogger("uvicorn.access")
    saved = (list(access.handlers), access.propagate, access.level)
    handler = logging.StreamHandler(stream)
    handler.setFormatter(AccessFormatter('%(client_addr)s - "%(request_line)s" %(status_code)s', use_colors=False))
    access.handlers[:] = [handler]
    access.propagate = False
    access.setLevel(logging.INFO)
    secret = "smtp-" + secrets.token_hex(12)
    SecretRegistry.register("smtp_password", secret)
    try:
        configure_logging("info", stream=io.StringIO())  # adds the redaction filter to the server handler
        line = '%s - "%s %s HTTP/%s" %d'
        access.info(line, "127.0.0.1:50000", "GET", "/games.roblox.com/v1/games?universeIds=1", "1.1", 200)
        access.info(line, "127.0.0.1:50000", "GET", f"/x?note={secret}", "1.1", 404)
    finally:
        access.handlers[:], access.propagate = saved[0], saved[1]
        access.setLevel(saved[2])
    output = stream.getvalue().splitlines()
    # The formatter adds the status phrase itself ("200 OK"), which only works when it got the real args back.
    assert output[0] == '127.0.0.1:50000 - "GET /games.roblox.com/v1/games?universeIds=1 HTTP/1.1" 200 OK'
    assert output[1].startswith('127.0.0.1:50000 - "GET /x?note=')
    assert output[1].endswith(' HTTP/1.1" 404 Not Found')
    assert secret not in "\n".join(output)


def test_third_party_loggers_pinned_to_warning() -> None:
    configure_logging("debug", stream=io.StringIO())
    for name in THIRD_PARTY_PINNED:
        assert logging.getLogger(name).level == logging.WARNING
    configure_logging("error", stream=io.StringIO())
    for name in THIRD_PARTY_PINNED:
        assert logging.getLogger(name).level == logging.ERROR  # never more verbose than the root


def test_httpx_debug_lines_not_printed() -> None:
    stream = io.StringIO()
    configure_logging("debug", stream=stream)
    logging.getLogger("httpx").debug("HTTP Request: GET https://games.roblox.com/ with headers")
    logging.getLogger("httpcore.http11").debug("send_request_headers.started")
    assert stream.getvalue() == ""


def test_configure_logging_is_idempotent() -> None:
    stream = io.StringIO()
    configure_logging("info", stream=io.StringIO())
    configure_logging("info", stream=stream)
    logging.getLogger("roxy.test").info("once")
    assert len(lines(stream)) == 1
    roxy_handlers = [h for h in logging.getLogger().handlers if getattr(h, "_roxy_handler", False)]
    assert len(roxy_handlers) == 1


def test_client_ip_fields_hashed_when_enabled() -> None:
    stream = io.StringIO()
    configure_logging("info", stream=stream)
    set_ip_hasher(lambda ip: "hashed-" + ip.replace(".", ""))
    logging.getLogger("roxy.test").info("seen", extra={"fields": {"client_ip": "203.0.113.9", "path": "/x"}})
    set_ip_hasher(None)
    logging.getLogger("roxy.test").info("seen", extra={"fields": {"client_ip": "203.0.113.9"}})
    first, second = lines(stream)
    assert first["client_ip"] == "hashed-2030113" + "9"
    assert second["client_ip"] == "203.0.113.9"


def test_redact_fields_nested() -> None:
    cleaned = redact_fields({"outer": {"token": "abc", "list": ["password=hunter2", 3]}, "ok": True})
    assert cleaned == {"outer": {"token": MASK, "list": [f"password={MASK}", 3]}, "ok": True}


def test_unknown_level_rejected() -> None:
    with pytest.raises(ValueError):
        configure_logging("loud", stream=io.StringIO())


# --- background writing (finding mp-11) --------------------------------------------------------------------------


class StalledStream(io.StringIO):
    """A stream whose `write` waits until `release` is set, like a pipe whose reader (journald) paused."""

    def __init__(self) -> None:
        super().__init__()
        self.release = threading.Event()
        self.entered = threading.Event()

    def write(self, text: str) -> int:
        self.entered.set()
        self.release.wait(10)
        return super().write(text)


def test_background_logging_never_waits_for_a_stalled_stream() -> None:
    stream = StalledStream()
    configure_logging("info", stream=stream, background=True)
    log = logging.getLogger("roxy.test")
    secret = TOKEN_PREFIX + "BG" + secrets.token_hex(40).upper()
    started = time.perf_counter()
    for n in range(200):
        log.warning("slow", extra={"fields": {"n": n, "cookie": secret, "note": f"value {secret}"}})
    elapsed = time.perf_counter() - started
    assert stream.entered.wait(2)  # the writer thread is stuck in write(), not the logging thread
    assert elapsed < 1.0, f"200 log calls took {elapsed:.2f} s while the stream was stalled"
    assert stream.getvalue() == ""
    stream.release.set()
    assert flush_logging(5.0)
    out = lines(stream)
    assert [line["n"] for line in out] == list(range(200))  # every line, in order
    assert secret not in stream.getvalue()  # scrubbed before it was queued
    assert all(line["cookie"] == MASK for line in out)


def test_background_queue_is_bounded_and_reports_what_it_dropped() -> None:
    stream = StalledStream()
    writer = BackgroundLogWriter(stream, max_lines=5, max_bytes=10_000)
    assert writer.put("first")
    assert stream.entered.wait(2)  # the thread holds "first" and waits in write()
    accepted = [writer.put(f"line {n}") for n in range(12)]
    assert accepted == [True] * 5 + [False] * 7  # never waits: a full queue drops the line
    assert writer.dropped == 7
    stream.release.set()
    assert writer.flush(5.0)
    assert writer.put("after")
    assert writer.flush(5.0)
    text = stream.getvalue().splitlines()
    assert text[0] == "first"
    report = json.loads(text[1])  # reported before the next batch, as soon as the stream takes lines again
    assert (report["event"], report["count"], report["level"]) == ("log_lines_dropped", 7, "warning")
    assert text[2:] == ["line 0", "line 1", "line 2", "line 3", "line 4", "after"]
    assert writer.close(1.0)
    assert not writer.put("closed")


def test_background_queue_is_bounded_by_bytes_too() -> None:
    stream = StalledStream()
    writer = BackgroundLogWriter(stream, max_lines=100, max_bytes=100)
    assert writer.put("a" * 60)
    assert stream.entered.wait(2)  # taken by the thread, which waits in write()
    assert writer.put("b" * 60)
    assert not writer.put("c" * 60)  # 120 characters would be waiting
    assert (writer.pending(), writer.dropped) == (1, 1)
    stream.release.set()
    assert writer.close(5.0)


def test_flush_and_close_wait_at_most_their_timeout() -> None:
    stream = StalledStream()
    writer = BackgroundLogWriter(stream)
    writer.put("stuck")
    assert stream.entered.wait(2)
    started = time.perf_counter()
    assert not writer.flush(0.2)
    assert not writer.close(0.2)
    assert time.perf_counter() - started < 1.0
    stream.release.set()  # let the thread finish its write and end


def test_a_broken_stream_is_counted_never_raised() -> None:
    stream = io.StringIO()
    stream.close()
    writer = BackgroundLogWriter(stream)
    assert writer.put("lost")
    assert writer.flush(2.0)
    assert writer.write_errors == 1
    writer.close(1.0)


def test_background_lines_carry_the_request_id_of_the_logging_task() -> None:
    stream = io.StringIO()
    configure_logging("info", stream=stream, background=True)
    token = request_id_var.set("01REQUESTIDFORBACKGROUND00")
    try:
        logging.getLogger("roxy.test").info("inside")
    finally:
        request_id_var.reset(token)
    assert flush_logging(2.0)
    assert lines(stream)[0]["request_id"] == "01REQUESTIDFORBACKGROUND00"


def test_replacing_a_background_handler_stops_its_writer() -> None:
    first = io.StringIO()
    old = configure_logging("info", stream=first, background=True)
    logging.getLogger("roxy.test").info("one")
    configure_logging("info", stream=io.StringIO(), background=True)
    assert isinstance(old, BackgroundStreamHandler)
    assert [line["event"] for line in lines(first)] == ["one"]  # written before the old handler stopped
    thread = old.writer._thread
    assert thread is not None
    thread.join(2)
    assert not thread.is_alive()


def test_long_fields_are_cut_before_redaction() -> None:
    stream = io.StringIO()
    configure_logging("info", stream=stream)
    secret = TOKEN_PREFIX + "LONG" + secrets.token_hex(40).upper()
    logging.getLogger("roxy.test").info("big", extra={"fields": {"path": f"/x {secret} " + "a" * 100_000}})
    path = str(lines(stream)[0]["path"])
    assert len(path) < MAX_FIELD_CHARS + 40
    assert path.endswith("chars]")
    assert secret not in path
