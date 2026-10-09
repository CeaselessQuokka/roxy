"""Review round 3, parity lens: Clients against v1 "Callers and Top Talkers" (plan 14.1 row 9; parity row 73).

What this is
    A strict xfail test for the columns of v1's Callers (per Roblox-Id) and Top Talkers (per IP) tables that the v2
    client tables dropped: `Last Seen`, and the peer count (`IPs`, distinct source IPs of a place; `Places`, distinct
    places seen from an IP) that v1 showed on every row and listed in the row drill-down.

Why it exists
    The peer count is how the owner told one game's many servers (one place, many IPs) from one scraper cycling place
    ids (one IP, many places), and Last Seen told an old talker from an active one (`.remake/v1notes/dashboard.md`
    4.6). Plan 14.1 maps the section to Clients > Places, IPs; the v2 tables carry requests, refusals, rates and the
    busiest endpoint only.

How it works
    Requests are seeded through the real recorder for two IPs and two places, then `GET /clients/ips` and
    `GET /clients/places` are read as a signed-in admin. Names are matched loosely; the values must mean what v1's
    columns meant. The test is `xfail(strict=True)` with its finding id.

What to read next
    `roxy/admin/api/clients.py`, `roxy/metrics/queries.py` (`client_table_sync`), `roxy/metrics/recorder.py`
    (`_count_clients`: the IP and the place of one request are counted apart, so their relation is not kept).
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


@pytest.mark.xfail(
    strict=True,
    reason="finding parity-7: client tables lack v1's Last Seen and peer counts (IPs per place, places per IP)",
)
async def test_parity_7_client_tables_keep_last_seen_and_peers(
    api: Any, api_app: Any, api_json: Any, metrics_seed: Any
) -> None:
    metrics_seed.record(2, client_ip="203.0.113.81", place_id="111")
    metrics_seed.record(1, client_ip="203.0.113.81", place_id="222")
    metrics_seed.record(1, client_ip="203.0.113.82", place_id="111")
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
