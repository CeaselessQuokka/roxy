"""Review round 3, parity lens: the Endpoints table against v1 "Top Endpoints" (plan 14.1 row 11; parity row 74).

What this is
    Tests for the columns of v1's Top Endpoints table that the v2 endpoint table had dropped (finding parity-13,
    fixed; it was a strict xfail): `Methods` (the verb mix of a template, `GET:3 POST:1`) and `Last Request` (when
    the template was last asked for), plus the `Last Status` and `Last Caller` of that request.

Why it exists
    `.remake/v1notes/dashboard.md` 4.8: every template row showed Count, Methods, Last Caller, Last Status and Last
    Request, and v1's endpoints CSV exported `Level,Endpoint,Count,Methods,LastRequestTime`. Plan 14.1 maps the section
    to Endpoints > Table and Overview > Top endpoints. v2's table is traffic, cache, 429 and latency numbers only; the
    verb mix and the recency are in the rollups (method dimension, bucket times) but no route answers them per
    template, and the drill-down's recent requests cover 15 minutes at most.

How it works
    Requests are seeded through the real recorder with two verbs at two times, then `GET /endpoints` is read as a
    signed-in admin. Field names are matched loosely first, then the fields the fix chose are pinned.

What to read next
    `roxy/admin/api/endpoints.py` (`ENDPOINTS_SPEC`, `endpoint_table`), `roxy/metrics/queries.py`
    (`endpoint_table_sync`).
"""

from __future__ import annotations

from typing import Any

import pytest

pytestmark = pytest.mark.asyncio

TEMPLATE = "games.roblox.com/v1/games"


async def test_parity_13_endpoint_rows_keep_methods_and_last_request(
    api: Any, api_app: Any, api_json: Any, metrics_seed: Any
) -> None:
    """Finding parity-13 (fixed): rows carry `methods` and the newest request (exact while its Live row is kept)."""
    metrics_seed.record(3, method="GET")
    api_app.clock.advance(120)
    last_ms = api_app.clock.now_ms()
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
    names = ("last_request", "last_seen", "last_at", "last_ms", "last_request_at", "last_request_ms")
    last = next((row[name] for name in names if name in row), None)
    assert last is not None, row
    last_seconds = int(last) // 1000 if int(last) > 10**11 else int(last)  # epoch seconds or milliseconds
    assert abs(last_seconds - last_s) <= 60, row
    assert list(row["methods"]) == ["GET", "POST"]  # busiest first, v1's `GET:3 POST:1`
    exact = (row["last_request_ms"], row["last_request_precision"], row["last_status"], row["last_caller"])
    assert exact == (last_ms, "exact", 404, "203.0.113.5"), row
    assert "last_place" in body["caller_text"]


async def test_parity_13_last_request_falls_back_to_the_rollup_minute(
    api: Any, api_app: Any, api_json: Any, metrics_seed: Any
) -> None:
    """Without a kept Live row the newest request is dated by its rollup bucket (minute precision), and the Live-only
    columns are unknown (None), never guessed; a CSV export carries the new columns with the caller hashed."""
    metrics_seed.record(2, method="GET")
    minute_ms = api_app.clock.now_ms() // 60_000 * 60_000
    await metrics_seed.flush()

    def drop_live(conn: Any) -> None:
        conn.execute("DELETE FROM events WHERE type = 'live'")

    await api_app.ctx.dbs.metrics.write(drop_live)
    body = api_json(await api.get("endpoints", params={"range": "1h"}))
    row = next(item for item in body["items"] if item["key"] == TEMPLATE)
    assert (row["methods"], row["last_request_ms"], row["last_request_precision"]) == ({"GET": 2}, minute_ms, "minute")
    assert (row["last_status"], row["last_caller"], row["last_place"]) == (None, None, None)
    export = await api.get("endpoints", params={"range": "1h", "format": "csv"})
    assert export.status_code == 200, export.text
    assert "Methods" in export.text.splitlines()[0]
