"""Structured logging tests (plan 9.15): JSON lines, redaction on the root handler, pinned third-party loggers."""

from __future__ import annotations

import io
import json
import logging
import secrets

import pytest

from roxy.core.logging import (
    THIRD_PARTY_PINNED,
    configure_logging,
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
