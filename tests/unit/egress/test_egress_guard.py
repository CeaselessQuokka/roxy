"""The leak guard and its matcher: every 24+ character piece of the credential is found, public text is not.

What this is
    Unit tests for `LeakMatcher` (in `roxy.egress.credential`) and `GuardTransport`, `inspect_request` and
    `NoStoreCookieJar` (in `roxy.egress.guard`).

Why it exists
    Plan C2 item 4: the guard must catch the credential value or any substring of 24 or more characters in any
    header, the URL or the body, and must not treat the public `TOKEN_PREFIX` or cookie name as a leak (item 5).
    The matcher samples positions to stay fast, so its correctness argument is tested exhaustively and with
    random inputs.

How it works
    A fake credential built like a real one (the public prefix plus a long hex value). Hypothesis draws offsets,
    lengths and surrounding text.

What to read next
    `src/roxy/egress/guard.py` and `LeakMatcher` in `src/roxy/egress/credential.py`.
"""

from __future__ import annotations

import pickle
import secrets
from typing import Any

import httpx
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from roxy.core.reasons import Egress
from roxy.core.redact import TOKEN_PREFIX
from roxy.egress.credential import LeakMatcher
from roxy.egress.errors import AuthSmugglingBlocked, CredentialLeakBlocked
from roxy.egress.guard import (
    GuardTransport,
    LeakTrip,
    NoStoreCookieJar,
    Verdict,
    guard_context,
    inspect_request,
)

SECRET_PART = "FAKETESTCREDENTIAL" + secrets.token_hex(160).upper()
VALUE = TOKEN_PREFIX + SECRET_PART
MATCHER = LeakMatcher([VALUE])


class Recorder(httpx.AsyncBaseTransport):
    def __init__(self) -> None:
        self.sent: list[httpx.Request] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.sent.append(request)
        return httpx.Response(200, content=b"ok")


def test_matcher_finds_every_24_char_window() -> None:
    for start in range(len(SECRET_PART) - 24 + 1):
        piece = SECRET_PART[start : start + 24]
        assert MATCHER.matches(b"xx" + piece.encode() + b"yy"), start


def test_matcher_ignores_23_char_pieces_and_public_prefix() -> None:
    for start in range(0, len(SECRET_PART) - 23, 7):
        assert not MATCHER.matches(SECRET_PART[start : start + 23].encode())
    assert not MATCHER.matches(TOKEN_PREFIX.encode())
    assert not MATCHER.matches((TOKEN_PREFIX + "0" * 40).encode())


@settings(max_examples=200, deadline=None)
@given(
    start=st.integers(min_value=0, max_value=len(SECRET_PART) - 24),
    length=st.integers(min_value=24, max_value=120),
    prefix=st.binary(max_size=80),
    suffix=st.binary(max_size=80),
    lower=st.booleans(),
)
def test_matcher_property(start: int, length: int, prefix: bytes, suffix: bytes, lower: bool) -> None:
    piece = SECRET_PART[start : start + length]
    if len(piece) < 24:
        return
    text = piece.lower() if lower else piece
    assert MATCHER.matches(prefix + text.encode() + suffix)


@settings(max_examples=200, deadline=None)
@given(data=st.binary(max_size=400))
def test_matcher_no_false_positive_on_random_bytes(data: bytes) -> None:
    assert not MATCHER.matches(data)


def test_matcher_hides_the_secret() -> None:
    assert SECRET_PART not in repr(MATCHER)
    assert "values=1" in repr(MATCHER)
    with pytest.raises(TypeError):
        pickle.dumps(MATCHER)
    assert not LeakMatcher([]).active
    assert not LeakMatcher([]).matches(VALUE.encode())


def _request(**kwargs: Any) -> httpx.Request:
    return httpx.Request(kwargs.pop("method", "GET"), kwargs.pop("url", "https://games.roblox.com/v1/x"), **kwargs)


@pytest.mark.parametrize(
    ("request_kwargs", "location"),
    [
        ({"headers": {"Cookie": f".ROBLOSECURITY={VALUE}"}}, "header:cookie"),
        ({"headers": {"X-Anything": SECRET_PART[100:130]}}, "header:x-anything"),
        ({"headers": {"Authorization": "Bearer " + SECRET_PART[5:40].lower()}}, "header:authorization"),
        ({"url": f"https://games.roblox.com/v1/x?q={SECRET_PART[50:80]}"}, "url"),
        ({"url": "https://games.roblox.com/v1/" + SECRET_PART[10:40]}, "url"),
        ({"method": "POST", "content": b'{"a":"' + SECRET_PART[200:260].encode() + b'"}'}, "body"),
        ({"method": "POST", "content": b"x=%46%41%4B%45" + SECRET_PART[4:40].encode()}, "body"),
    ],
)
def test_inspection_finds_the_leak_everywhere(request_kwargs: dict[str, Any], location: str) -> None:
    request = _request(**request_kwargs)
    body = request.content
    result = inspect_request(request, body, MATCHER, 2_000_000)
    assert result.verdict is Verdict.LEAK
    assert result.location == location


@pytest.mark.parametrize(
    ("request_kwargs", "marker"),
    [
        ({"method": "POST", "content": b"note=" + TOKEN_PREFIX.encode()}, "token_prefix"),
        ({"headers": {"X-Note": ".roblosecurity"}}, "cookie_name"),
        ({"url": "https://games.roblox.com/v1/x?c=%2EROBLOSECURITY%3D1"}, "cookie_name"),
        ({"headers": {"Cookie": ".ROBLOSECURITY=not-the-real-one"}}, "cookie_name"),
    ],
)
def test_inspection_reports_public_markers(request_kwargs: dict[str, Any], marker: str) -> None:
    request = _request(**request_kwargs)
    result = inspect_request(request, request.content, MATCHER, 2_000_000)
    assert result.verdict is Verdict.MARKER
    assert result.marker == marker


def test_inspection_clean_and_oversize() -> None:
    clean = _request(headers={"Accept": "application/json"})
    assert inspect_request(clean, b"", MATCHER, 10).verdict is Verdict.CLEAN
    big = _request(method="POST", content=b"a" * 11)
    assert inspect_request(big, big.content, MATCHER, 10).verdict is Verdict.OVERSIZE


async def test_guard_transport_refuses_and_never_reaches_the_network() -> None:
    inner = Recorder()
    trips: list[LeakTrip] = []
    markers: list[Any] = []

    async def on_leak(trip: LeakTrip) -> None:
        trips.append(trip)

    guard = GuardTransport(
        inner,
        egress=Egress.ROTATOR,
        matcher=lambda: MATCHER,
        max_body_bytes=lambda: 1000,
        on_leak=on_leak,
        on_marker=lambda egress, inspection: markers.append((egress, inspection.marker)),
    )
    with guard_context("caller"), pytest.raises(CredentialLeakBlocked) as raised:
        await guard.handle_async_request(_request(headers={"X-Y": SECRET_PART[:30]}))
    assert SECRET_PART[:30] not in str(raised.value)
    assert trips
    assert trips[0].purpose == "caller"
    assert trips[0].egress is Egress.ROTATOR
    with pytest.raises(AuthSmugglingBlocked):
        await guard.handle_async_request(_request(headers={"X-Y": TOKEN_PREFIX}))
    with pytest.raises(AuthSmugglingBlocked):
        await guard.handle_async_request(_request(method="POST", content=b"z" * 1001))
    assert markers == [(Egress.ROTATOR, "token_prefix"), (Egress.ROTATOR, "oversize_body")]
    assert inner.sent == []
    response = await guard.handle_async_request(_request())
    assert response.status_code == 200
    assert len(inner.sent) == 1
    assert guard.stats.leak_trips == 1
    assert guard.stats.smuggling_refusals == 1
    assert guard.stats.oversize_refusals == 1


async def test_guard_reads_streamed_bodies() -> None:
    inner = Recorder()
    guard = GuardTransport(inner, egress=Egress.DIRECT, matcher=lambda: MATCHER, max_body_bytes=lambda: 10_000)

    async def stream() -> Any:
        yield b"part1-"
        yield SECRET_PART[:40].encode()

    with pytest.raises(CredentialLeakBlocked):
        await guard.handle_async_request(httpx.Request("POST", "https://games.roblox.com/x", content=stream()))
    assert inner.sent == []


def test_guard_refuses_to_wrap_the_credential_client() -> None:
    with pytest.raises(ValueError):
        GuardTransport(Recorder(), egress=Egress.CREDENTIAL, matcher=lambda: MATCHER, max_body_bytes=lambda: 1)


def test_no_store_cookie_jar_never_stores_or_sends() -> None:
    jar = NoStoreCookieJar()
    cookies = httpx.Cookies(jar)
    cookies.set(".ROBLOSECURITY", "x", domain=".roblox.com")
    response = httpx.Response(
        200,
        headers={"Set-Cookie": "a=b; Domain=.roblox.com; Path=/"},
        request=httpx.Request("GET", "https://games.roblox.com/"),
    )
    cookies.extract_cookies(response)
    assert list(jar) == []
    assert dict(cookies) == {}
    request = httpx.Request("GET", "https://games.roblox.com/")
    cookies.set_cookie_header(request)
    assert "cookie" not in request.headers
