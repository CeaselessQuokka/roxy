"""Review round 3, parity lens: Clients against v1 "Callers and Top Talkers" (plan 14.1 row 9; parity row 73).

What this is
    The test of finding parity-7 (a strict xfail until review round 3 fixed it): the columns of v1's Callers (per
    Roblox-Id) and Top Talkers (per IP) tables that the v2 client tables had dropped: `Last Seen`, and the peer count
    (`IPs`, distinct source IPs of a place; `Places`, distinct places seen from an IP) that v1 showed on every row and
    listed in the row drill-down.

Why it exists
    The peer count is how the owner told one game's many servers (one place, many IPs) from one scraper cycling place
    ids (one IP, many places), and Last Seen told an old talker from an active one (`.remake/v1notes/dashboard.md`
    4.6). Plan 14.1 maps the section to Clients > Places, IPs.

How it works
    Requests are seeded through the real recorder for two IPs and two places, two minutes apart, then
    `GET /clients/ips`, `GET /clients/places` and both drill-down pages are read as a signed-in admin. Names are
    matched loosely where the review left the choice open; the values must mean what v1's columns meant.

What to read next
    `roxy/admin/api/clients.py`, `roxy/metrics/queries.py` (`client_table_sync`), `roxy/metrics/read_client_extras.py`
    (peers and last seen), `roxy/metrics/recorder.py` (`_count_clients`: the `pair` rows that keep which IP called as
    which place).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import pytest

pytestmark = pytest.mark.asyncio

_MISSING: Any = object()


def pick(item: Mapping[str, Any], *names: str) -> Any:
    for name in names:
        if name in item:
            return item[name]
    return _MISSING


async def test_parity_7_client_tables_keep_last_seen_and_peers(
    api: Any, api_app: Any, api_json: Any, metrics_seed: Any
) -> None:
    old_minute = int(api_app.clock.now()) // 60 * 60
    metrics_seed.record(1, client_ip="203.0.113.82", place_id="111")
    api_app.clock.advance(120)
    newest_minute = int(api_app.clock.now()) // 60 * 60
    metrics_seed.record(2, client_ip="203.0.113.81", place_id="111")
    metrics_seed.record(1, client_ip="203.0.113.81", place_id="222")
    await metrics_seed.flush()
    ips = api_json(await api.get("clients/ips", params={"range": "1h"}))
    talker = next(row for row in ips["items"] if row["key"] == "203.0.113.81")
    places = api_json(await api.get("clients/places", params={"range": "1h"}))
    caller = next(row for row in places["items"] if row["key"] == "111")
    found = {
        "talker_places": pick(talker, "places", "place_count", "peers", "peer_count"),
        "caller_ips": pick(caller, "ips", "ip_count", "clients", "peers", "peer_count"),
        "talker_last_seen": pick(talker, "last_seen", "last_ms", "last_seen_ms") is not _MISSING,
        "caller_last_seen": pick(caller, "last_seen", "last_ms", "last_seen_ms") is not _MISSING,
    }
    assert found == {
        "talker_places": 2,
        "caller_ips": 2,
        "talker_last_seen": True,
        "caller_last_seen": True,
    }, (talker, caller)
    quiet = next(row for row in ips["items"] if row["key"] == "203.0.113.82")
    assert (talker["last_seen"], quiet["last_seen"], quiet["peers"]) == (newest_minute, old_minute, 1)
    by_seen = api_json(await api.get("clients/ips", params={"range": "1h", "sort": "last_seen", "order": "asc"}))
    assert [row["key"] for row in by_seen["items"]] == ["203.0.113.82", "203.0.113.81"]
    # The drill-downs list the peers themselves (v1's "Places" and "Source IPs" lists), busiest first.
    talker_page = api_json(await api.get("clients/ips/203.0.113.81", params={"range": "1h"}))
    assert [(p["key"], p["requests"]) for p in talker_page["peers"]["items"]] == [("111", 2), ("222", 1)]
    caller_page = api_json(await api.get("clients/places/111", params={"range": "1h"}))
    assert [(p["key"], p["requests"]) for p in caller_page["peers"]["items"]] == [
        ("203.0.113.81", 2),
        ("203.0.113.82", 1),
    ]
    assert caller_page["peers"]["total"] == 2
