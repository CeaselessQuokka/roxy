"""Review round 3, parity lens: the Protection page tables against v1's sections (plan 14.1 rows 4, 10; rows 72, 135).

What this is
    Tests for the Protection page data the v1 dashboard showed and the v2 API had lost (findings parity-3 and
    parity-4, both fixed in review round 3; they were strict xfails): the columns of v1's "Refusal Reasons" section
    and of the throttle-all watch "Who is being throttled right now".

Why it exists
    Plan 14.1 maps v1 "Refusal Reasons" (Reason, Count, Status, Last Path, Last IP, Unique IPs, Last Seen) to
    Protection > Refusals, and parity row 135 keeps the throttle-all watch "the same live table" (IP, Requests,
    Refused, Rate, Top Endpoint, Last Seen; `.remake/v1notes/dashboard.md` 4.1 and 4.7). The data each column needs is
    recorded in v2 (refusal events carry status and path, client activity carries refusals and the busiest endpoint),
    but the routes do not answer it, so the P11 pages cannot show it.

How it works
    The admin API fixtures (`tests/integration/admin_api/conftest.py`) seed refusals through the real recorder and
    read the routes over HTTP as a signed-in admin. Field names are matched loosely (`pick`), so a fix may choose its
    own names; the values must carry the v1 meaning. Each test is named after its finding (`test_parity_N_...`).

What to read next
    `roxy/admin/api/protection.py` (`refusals`, `throttle_all_watch_table`), `roxy/metrics/queries.py`
    (`refusal_reasons`), `roxy/abuse/throttle_all.py` (`throttle_all_watch`), `roxy/metrics/read_clients.py`.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import pytest

from roxy.core.reasons import CacheState, Egress, Outcome, ReasonCode, Source

pytestmark = pytest.mark.asyncio

_MISSING: Any = object()


def pick(item: Mapping[str, Any], *names: str) -> Any:
    """The first of `names` present in `item`, or a sentinel that compares unequal to everything."""
    for name in names:
        if name in item:
            return item[name]
    return _MISSING


def refused(seed: Any, count: int, reason: ReasonCode, status: int, **fields: Any) -> None:
    seed.record(
        count,
        outcome=Outcome.REFUSED,
        reason=reason,
        status=status,
        source=Source.ROXY,
        cache_state=CacheState.NA,
        egress=Egress.NONE,
        upstream_calls=0,
        upstream_bytes_in=0,
        upstream_bytes_out=0,
        check=str(fields.pop("check", reason.value)),
        **fields,
    )


async def test_parity_3_refusal_reasons_keep_the_v1_columns(
    api: Any, api_app: Any, api_json: Any, metrics_seed: Any
) -> None:
    first_ms = api_app.clock.now_ms()
    refused(metrics_seed, 2, ReasonCode.THROTTLE, 429, client_ip="203.0.113.71", path="games.roblox.com/v1/games/1")
    api_app.clock.advance(2)
    refused(metrics_seed, 1, ReasonCode.THROTTLE, 429, client_ip="203.0.113.72", path="games.roblox.com/v1/games/2")
    last_ms = api_app.clock.now_ms()
    api_app.clock.advance(1)
    refused(metrics_seed, 1, ReasonCode.NOT_ROBLOX, 404, client_ip="203.0.113.73", path="example.invalid/<b>x</b>")
    await metrics_seed.flush()
    body = api_json(await api.get("protection/refusals", params={"range": "1h"}))
    item = next(row for row in body["items"] if row["reason"] == "throttle")
    assert pick(item, "requests", "count") == 3
    found = {
        "status": pick(item, "status", "last_status"),
        "last_path": pick(item, "last_path", "path"),
        "unique_ips": pick(item, "unique_ips", "clients", "unique_clients"),
        "last_seen_ms": pick(item, "last_ms", "last_seen_ms"),
    }
    assert found == {
        "status": 429,
        "last_path": "games.roblox.com/v1/games/2",
        "unique_ips": 2,
        "last_seen_ms": last_ms,
    }, item
    assert (item["first_ms"], item["unattributed"]) == (first_ms, 0)
    # A section 13 table: sorted and paged on the server, caller text named, exported like every table.
    assert body["sort"] == "requests"
    assert [row["reason"] for row in body["items"]] == ["throttle", "not_roblox"]
    assert body["caller_text"] == ["last_path"]
    probe = next(row for row in body["items"] if row["reason"] == "not_roblox")
    assert probe["last_path"] == "example.invalid/<b>x</b>"  # raw text: the page escapes it, the API never renders
    by_last = api_json(await api.get("protection/refusals", params={"range": "1h", "sort": "last_ms", "order": "asc"}))
    assert [row["reason"] for row in by_last["items"]] == ["throttle", "not_roblox"]
    export = await api.get("protection/refusals", params={"range": "1h", "format": "csv"})
    assert export.status_code == 200, export.text
    assert export.text.splitlines()[0].startswith('"Reason","Count","Status","Last path"'), export.text[:200]


async def test_parity_4_throttle_all_watch_keeps_the_v1_columns(
    api: Any, api_app: Any, api_json: Any, metrics_seed: Any
) -> None:
    """v1's watch answered "the callers actually being turned away, what they are asking for and how fast".
    Finding parity-4 (fixed): the rows carry requests and refusals since the state began, rates, the busiest
    endpoint and the last seen time from client activity."""
    ip = "203.0.113.9"
    await api.post("protection/throttle-all", json={"enabled": True, "limit": 1, "period": 60, "reason": "attack"})
    now_ms = api_app.clock.now_ms()

    def seed(conn: Any) -> None:
        conn.execute(
            "INSERT INTO limiter (bucket_key, tat_ms, window_start, count, updated_at) VALUES (?, ?, ?, ?, ?)",
            (f"tall:{ip}", now_ms + 20_000, now_ms - 10_000, 5, now_ms // 1000),
        )

    await api_app.ctx.dbs.hot.write(seed)
    metrics_seed.record(1, client_ip=ip, endpoint_template="economy.roblox.com/v1/assets/{id}")
    refused(metrics_seed, 4, ReasonCode.THROTTLE_ALL, 429, client_ip=ip, endpoint_template="economy.roblox.com/v1/x")
    await metrics_seed.flush()
    table = api_json(await api.get("protection/throttle-all/watch"))
    assert table["total"] == 1
    row = table["items"][0]
    assert row["ip"] == ip
    found = {
        "refused": pick(row, "refused", "refused_count"),
        "top_endpoint": pick(row, "top_endpoint", "endpoint"),
        "has_rate": pick(row, "rate1", "rate", "rate_per_min") is not _MISSING,
        "has_last_seen": pick(row, "last_seen", "last_ms", "last_seen_ms") is not _MISSING,
    }
    assert found == {
        "refused": 4,
        "top_endpoint": "economy.roblox.com/v1/x",
        "has_rate": True,
        "has_last_seen": True,
    }, row
    assert (row["requests"], row["last_seen_ms"]) == (5, now_ms), row  # the Live row gives the exact time
    assert isinstance(row["rate1"], float), row
    assert isinstance(row["rate60"], float), row
    assert table["caller_text"] == ["top_endpoint"]
    export = await api.get("protection/throttle-all/watch", params={"format": "csv"})
    assert export.status_code == 200, export.text
    assert "economy.roblox.com/v1/x" in export.text
    assert ip not in export.text  # the client column is hashed in files that leave the server (plan 9.15)
