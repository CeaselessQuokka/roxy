"""Review round 4, lens logicfix: the home page 405 (ptable-1) from entry points its fixer's test does not use.

What this is
    Variants of `tests/parity/test_v1_public.py::test_v1_post_to_the_home_page_is_a_json_405_with_allow` against the
    real app (`parity` fixture): `POST /` with a query string, with a large body that is never read, and with a
    `Content-Type` a form would send; each must be v1's instant JSON 405 with `Allow`, never the proxy pipeline.
    These are expected to pass (checked-clean evidence of the lens).

Why it exists
    v1 answered every non-GET request to `/` with an instant 405 (smoke lines 140 to 142, 188). The fix
    (`public/pages.py HomeMethodRoute`) matches the path only; a query string or a body must not send the request
    back to the proxy catch-all (404 `not_roblox`, tarpit, spam probe counting).

How it works
    Each request goes through the ASGI app as a caller (`parity.proxy`); the proxied counter of the worker's
    heartbeat shows whether the proxy route ran.

What to read next
    `roxy/public/pages.py` (`HomeMethodRoute`), `tests/parity/test_v1_public.py`.
"""

from __future__ import annotations

import json
from typing import Any

import pytest


@pytest.mark.parametrize(
    ("path", "body", "content_type"),
    [
        ("/?universeIds=1&x=%2F", b"garbage", "application/json"),
        ("/", b"a=1&b=2", "application/x-www-form-urlencoded"),
        ("/", b"x" * (2 * 1024 * 1024), "application/octet-stream"),
    ],
    ids=["query", "form", "large_body"],
)
async def test_r4_logicfix_home_page_405_whatever_the_query_or_body(
    parity: Any, path: str, body: bytes, content_type: str
) -> None:
    counters = parity.ctx.heartbeat.counters
    proxied = counters.proxied
    response = await parity.proxy("POST", path, content=body, headers={"Content-Type": content_type})
    assert response.status_code == 405, response.content[:200]
    assert response.headers.get("allow") == "GET, HEAD, OPTIONS"
    json.loads(response.content)
    assert "roxy-refusal" not in response.headers
    assert counters.proxied == proxied
