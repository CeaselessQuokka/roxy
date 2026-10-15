"""Adversarial review (public site lens): anonymous text whose redaction costs quadratic time on the event loop.

What this is
    Two scaling tests on the fully wired app. Each sends the same hostile shape at two sizes, n and 4n, and compares
    the best of five answer times. Linear work grows about 4 times; quadratic work grows about 16 times. The shape
    is a run of percent-encoded line breaks (`%0A`): in a CSP report's `document-uri`, and in a proxy path that
    Roxy refuses before it calls anyone.

Why it exists
    `core.redact.redact_text` runs `_HEADER_LINE_RE`, `(?im)^(\\s*(?:cookie|...)\\s*:\\s*)(\\S.*)$`. With `MULTILINE`,
    `^` matches after every line break, and `\\s*` then runs over all the following line breaks before it fails and
    backs off one character at a time, so text with k line breaks costs about k * k / 2 steps. Line breaks reach it
    from anonymous callers: `redact_text` percent-decodes `%0A` itself (so `urlsplit` stripping raw line breaks in
    `csp_report.page_path` does not help), and Starlette hands the proxy and the error hooks an already decoded
    path. Measured here: one 8 KiB `POST /csp-report` costs about 80 ms of event loop time (a normal one about
    1 ms), and one refused 4 KiB proxy URL about 60 ms (each redacted several times: the log line, the client error
    hook, labels). A handful of clients inside every rate limit can keep a worker's loop busy, and every request
    of that worker waits (plan 5.2, C6 with 2 workers on the 1 GB box).
    - Finding public-4: quadratic redaction of line-break-heavy text (core/redact.py `_HEADER_LINE_RE`).

How it works
    The `client` fixture runs the real app and lifespan; `respx_mock` makes sure nothing leaves the process (the
    hostile proxy URL is refused before routing anyway). Every request comes from its own address, so the per-IP
    limits never change the code path being timed. Fixed (the same root cause as finding INGRESS-1): the spaces
    around the header name and colon in `_HEADER_LINE_RE` can no longer cross a line break, so the growth is linear.

What to read next
    `roxy/core/redact.py` (`_HEADER_LINE_RE`, `redact_text`), `roxy/public/csp_report.py` (`page_path`),
    `roxy/core/logging.py` (which redacts every log field).
"""

from __future__ import annotations

import json
import time
from typing import Any

import httpx

LINEAR_RATIO_CEILING = 5.0
"""4x the input. With the fixed cost of a request in both timings, linear redaction grows the total well under 2x
and quadratic redaction about 12x to 14x here; 5 sits between them with room for noise."""
RUNS = 5


async def _best_time(send: Any, count: int) -> float:
    best = float("inf")
    for run in range(RUNS):
        start = time.perf_counter()
        await send(count, run)
        best = min(best, time.perf_counter() - start)
    return best


async def test_rr_public_csp_report_cost_grows_linearly_with_line_breaks(client: httpx.AsyncClient) -> None:
    sent = 0

    async def send(count: int, run: int) -> None:
        nonlocal sent
        sent += 1
        body = json.dumps({"csp-report": {"document-uri": "https://roxytheproxy.com/" + "%0A" * count}})
        assert len(body) <= 8 * 1024  # inside the endpoint's own size cap
        response = await client.post(
            "/csp-report",
            content=body.encode(),
            headers={"content-type": "application/csp-report", "X-Forwarded-For": f"198.51.100.{sent}"},
        )
        assert response.status_code == 204

    await send(10, 0)  # warm up
    small = await _best_time(send, 675)
    large = await _best_time(send, 2700)
    print(f"\n/csp-report: n=675 {small * 1000:.1f} ms, n=2700 {large * 1000:.1f} ms, ratio {large / small:.1f}")
    assert large / small < LINEAR_RATIO_CEILING


async def test_rr_public_refused_proxy_path_cost_grows_linearly_with_line_breaks(
    client: httpx.AsyncClient, respx_mock: Any
) -> None:
    sent = 0

    async def send(count: int, run: int) -> None:
        nonlocal sent
        sent += 1
        path = "/games.roblox.com/v1/" + "%0A" * count
        assert len(path) <= 4096  # inside the default max_url_length
        response = await client.get(path, headers={"User-Agent": "Mozilla/5.0", "X-Forwarded-For": f"203.0.113.{sent}"})
        assert 400 <= response.status_code < 500  # refused before any upstream call

    await send(10, 0)  # warm up
    small = await _best_time(send, 337)
    large = await _best_time(send, 1348)
    print(f"\nproxy path: n=337 {small * 1000:.1f} ms, n=1348 {large * 1000:.1f} ms, ratio {large / small:.1f}")
    assert len(respx_mock.calls) == 0
    assert large / small < LINEAR_RATIO_CEILING
