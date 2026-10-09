"""Review round 3, parity lens: the Endpoints table against v1 "Top Endpoints" (plan 14.1 row 11; parity row 74).

What this is
    A strict xfail test for the columns of v1's Top Endpoints table that the v2 endpoint table dropped: `Methods`
    (the verb mix of a template, `GET:3 POST:1`) and `Last Request` (when the template was last asked for), plus the
    `Last Status` of that request.

Why it exists
    `.remake/v1notes/dashboard.md` 4.8: every template row showed Count, Methods, Last Caller, Last Status and Last
    Request, and v1's endpoints CSV exported `Level,Endpoint,Count,Methods,LastRequestTime`. Plan 14.1 maps the section
    to Endpoints > Table and Overview > Top endpoints. v2's table is traffic, cache, 429 and latency numbers only; the
    verb mix and the recency are in the rollups (method dimension, bucket times) but no route answers them per
    template, and the drill-down's recent requests cover 15 minutes at most.

How it works
    Requests are seeded through the real recorder with two verbs at two times, then `GET /endpoints` is read as a
    signed-in admin. Field names are matched loosely. The test is `xfail(strict=True)` with its finding id.

What to read next
    `roxy/admin/api/endpoints.py` (`ENDPOINTS_SPEC`, `endpoint_table`), `roxy/metrics/queries.py`
    (`endpoint_table_sync`).
"""

from __future__ import annotations

from typing import Any

import pytest

pytestmark = pytest.mark.asyncio

TEMPLATE = "games.roblox.com/v1/games"


@pytest.mark.xfail(
    strict=True, reason="finding parity-13: the Endpoints table lacks v1's Methods and Last Request columns"
)
async def test_parity_13_endpoint_rows_keep_methods_and_last_request(
    api: Any, api_app: Any, api_json: Any, metrics_seed: Any
) -> None:
    metrics_seed.record(3, method="GET")
    api_app.clock.advance(120)
    metrics_seed.record(1, method="POST", status=404)
    last_s = int(api_app.clock.now())
    api_app.clock.advance(61)
    await metrics_seed.flush()
    body = api_json(await api.get("endpoints", params={"range": "1h"}))
    row = next(item for item in body["items"] if item["key"] == TEMPLATE)
    assert row["requests"] == 4
    methods = row.get("methods")
    wanted_methods = ({"GET": 3, "POST": 1}, [{"method": "GET", "requests": 3}, {"method": "POST", "requests": 1}])
    assert methods in wanted_methods, row
    names = ("last_request", "last_seen", "last_at", "last_ms", "last_request_at")
    last = next((row[name] for name in names if name in row), None)
    assert last is not None, row
    last_seconds = int(last) // 1000 if int(last) > 10**11 else int(last)  # epoch seconds or milliseconds
    assert abs(last_seconds - last_s) <= 60, row
