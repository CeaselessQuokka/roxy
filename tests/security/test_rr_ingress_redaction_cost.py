"""Ingress re-review (rr), redaction cost lens: scrubbing caller text must stay linear, before any limit applies.

What this is
    Probes that time `roxy.core.redact` (stdlib `re`, no timeout, run on the event loop) on caller-controlled text,
    and the request path that runs it on the FULL decoded path before any rate limit: the 414 answer of
    `core/middleware.py SizeLimitMiddleware`, whose client error event redacts `scope["path"]` whole
    (`core/errors.py event_from_scope`), then logs it (the log filter redacts it again) and hands it to the probe
    hook.

Why it exists
    `_HEADER_LINE_RE` is `(?im)^(\\s*(?:cookie|...)\\s*:\\s*)(\\S.*)$`. With MULTILINE, `^` matches after every
    newline and `\\s*` also eats newlines, so text made of n newlines costs O(n^2) steps. A caller controls that
    text: `%0A` in the path is decoded by the server into `scope["path"]`, and `redact_text` also percent-decodes
    (twice) before judging. One 8 KiB request line (what nginx admits, `large_client_header_buffers 4 8k`) of
    `%0A` costs about 80 ms of event loop time in `event_from_scope` alone on the review machine (a plain 8 KiB
    path: 7 ms), about 160 ms once the log filter (`core/logging.py RedactionFilter`) scrubs the logged
    `http_client_error` line again, and the 414 is answered before the flood limit, the per-IP limit or the tarpit
    see the request. nginx lets one address send 20 such requests a second (burst 100), so one
    client can keep both workers' event loops busy (finding INGRESS-1).

How it works
    Each probe compares newline-shaped input with plain input of the same size, best of three runs, so the bounds
    hold on a fast or slow machine: a linear scrub costs about the same for both, the quadratic one an order of
    magnitude more. The end-to-end probe uses the real middleware stack and proxy route
    (`ingress_support.make_proxy_app`). Fixed: the spaces around the header name and colon in `_HEADER_LINE_RE` can
    no longer cross a line break, so every redaction rule is linear; `tests/unit/core/test_core_redact_cost.py`
    times every rule on hostile shapes.

What to read next
    `roxy/core/redact.py` (`_HEADER_LINE_RE`, `redact_text`), `roxy/core/errors.py` (`event_from_scope`), then
    `tests/security/test_ingress_redos.py` (the admin-pattern half of the regex cost question).
"""

from __future__ import annotations

import time
from collections.abc import Awaitable, Callable
from types import SimpleNamespace
from typing import Any

import pytest
from ingress_support import CatalogSettings, make_proxy_app, raw_asgi_request

from roxy.core.clock import FakeClock
from roxy.core.redact import redact_label, redact_query, redact_text

REQUEST_LINE = 8190
"""Bytes of path nginx passes on (`large_client_header_buffers 4 8k` in deploy/nginx/roxy.conf.template)."""


def _best_of(runs: int, work: Callable[[], Any]) -> float:
    best = float("inf")
    for _ in range(runs):
        started = time.perf_counter()
        work()
        best = min(best, time.perf_counter() - started)
    return best


async def _best_of_async(runs: int, work: Callable[[], Awaitable[Any]]) -> float:
    best = float("inf")
    for _ in range(runs):
        started = time.perf_counter()
        await work()
        best = min(best, time.perf_counter() - started)
    return best


@pytest.mark.parametrize("scrub", [redact_text, redact_label, redact_query], ids=lambda f: f.__name__)
def test_scrubbing_newline_text_costs_about_what_plain_text_costs(scrub: Callable[[str], str]) -> None:
    """`%0A` decodes to a newline: the encoded form is what a path, query or header value carries."""
    plain = "a" * (REQUEST_LINE // 3 * 3)
    encoded_newlines = "%0A" * (REQUEST_LINE // 3)
    plain_s = _best_of(3, lambda: scrub(plain))
    newline_s = _best_of(3, lambda: scrub(encoded_newlines))
    assert newline_s < 3 * plain_s + 0.010, (
        f"{scrub.__name__}: {newline_s * 1000:.1f} ms for {REQUEST_LINE // 3} encoded newlines against "
        f"{plain_s * 1000:.1f} ms for {len(plain)} plain characters"
    )


async def test_a_414_with_a_newline_path_costs_about_what_a_plain_414_costs() -> None:
    """The 414 is answered by the middleware before any limit, so its cost per request is what one client can make
    every worker pay at nginx's per-address rate."""
    ctx = SimpleNamespace(
        settings=CatalogSettings(), clock=FakeClock(), abuse=None, cache=None, upstream=None, recorder=None
    )
    app = make_proxy_app(ctx)
    plain_path = b"/" + b"a" * (REQUEST_LINE - 1)
    newline_path = b"/" + b"%0A" * ((REQUEST_LINE - 1) // 3)

    async def send(path: bytes) -> None:
        status, _headers, _body, _ = await raw_asgi_request(app, path)
        assert status == 414

    plain_s = await _best_of_async(3, lambda: send(plain_path))
    newline_s = await _best_of_async(3, lambda: send(newline_path))
    assert newline_s < 3 * plain_s + 0.015, (
        f"a 414 for {len(newline_path)} bytes of %0A took {newline_s * 1000:.1f} ms against "
        f"{plain_s * 1000:.1f} ms for {len(plain_path)} plain bytes"
    )


def test_control_secret_header_lines_are_still_redacted() -> None:
    """Control for any fix of `_HEADER_LINE_RE`: a logged raw request keeps losing its secret header values."""
    text = "GET /x HTTP/1.1\nHost: a\n  Cookie: session=abc123\nAuthorization:\tBearer zzz\n"
    cleaned = redact_text(text)
    assert "abc123" not in cleaned
    assert "zzz" not in cleaned
    assert "Host: a" in cleaned
