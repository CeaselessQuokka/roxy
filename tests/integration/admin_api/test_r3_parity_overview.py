"""Review round 3, parity lens: the Overview tiles and the "Who returned it?" split against v1 (plan 14.1 rows 1 to 3).

What this is
    Tests, one per finding of the parity review of the admin API (wave 3b; findings parity-1 and parity-2, fixed in
    review round 3, were strict xfails), for the numbers the Overview and the Traffic > Status codes card show.
    Each test drives the real app (a real proxied request where the attribution matters, the real recorder and read
    models otherwise) and states the v1 meaning it checks.

Why it exists
    v1's dashboard is the ground truth for what each tile means (`.remake/v1notes/dashboard.md` sections 3 and 4.16,
    with the corrections in its section 1.1). A tile that exists under the same name but counts something else, or a
    tile that went missing, is a parity defect (plan C3) that no other test catches.

How it works
    The `api`, `api_app`, `api_json` and `metrics_seed` fixtures of `tests/integration/admin_api/conftest.py` give a
    signed-in admin on the real app with respx playing Roblox. Each test is named after its finding
    (`test_parity_N_...`) and pins the fixed behavior.

What to read next
    `roxy/metrics/queries.py` (the `roblox_5xx` measure), `roxy/admin/api/traffic.py` (`traffic_status_sources`),
    `roxy/admin/api/overview.py` (the KPI tiles), `roxy/proxy/respond.py` (`FAILURE_ROWS`, `upstream_5xx`).
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from roxy.core.reasons import Egress, Outcome, ReasonCode, Source

pytestmark = pytest.mark.asyncio

GAMES = "games.roblox.com"


async def _proxy_get(api_app: Any, path: str) -> httpx.Response:
    """One caller request through the real proxy route, from a fresh client address."""
    headers = {"User-Agent": "Roblox/Linux", "X-Forwarded-For": "198.51.100.77"}
    response: httpx.Response = await api_app.harness.http.get(path, headers=headers)
    await api_app.ctx.cache.settle()
    return response


async def test_parity_1_a_roblox_5xx_counts_as_5xx_from_roblox(api: Any, api_app: Any, api_json: Any) -> None:
    """v1 "5xx from Roblox" counted Roblox's 5xx answers; v2's tile help says "Server errors that came from Roblox and
    were passed to the caller". The proxy passes Roblox's real 5xx status (plan 7.13 `upstream_5xx`, owner D4), so the
    tile must count it, and "5xx from Roxy" ("Our own failures") must not. The "Who returned it?" table and the
    source series read the same definition: the 503 is Roblox's, relayed with Roxy's retry text."""
    await api_app.settings(upstream_max_attempts=1)
    api_app.roblox.route(host=GAMES, path="/v1/games").mock(return_value=httpx.Response(503, text="Service down"))
    response = await _proxy_get(api_app, f"/{GAMES}/v1/games?universeIds=4242")
    assert response.status_code == 503, response.text  # Roblox's own status reached the caller (D4)
    assert response.headers.get("Roxy-Upstream-Status") == "503"
    await api_app.ctx.recorder.flush()
    sources = api_json(await api.get("traffic/status/sources", params={"range": "1h"}))
    tiles = sources["tiles"]
    kpis = api_json(await api.get("overview/kpis", params={"range": "1h"}))
    overview = {tile["key"]: tile["value"] for tile in kpis["tiles"]}
    assert (tiles["roblox_5xx"], tiles["roxy_5xx"], overview["roblox_5xx"]) == (1, 0, 1), (tiles, overview)
    pairs = {(row["source"], row["status"]): row["requests"] for row in sources["items"]}
    assert pairs == {("relay", 503): 1}, pairs  # never listed under "Roxy (its own answers)"
    series = api_json(await api.get("traffic/status", params={"range": "1h", "view": "source"}))
    by_source = {entry["key"]: sum(point[1] or 0 for point in entry["points"]) for entry in series["series"]}
    assert by_source == {"requests:relay": 1}, by_source


async def test_parity_2_overview_has_the_v1_failures_last_hour_tile(
    api: Any, api_app: Any, api_json: Any, metrics_seed: Any
) -> None:
    """v1's Overview had 11 tiles (dashboard.md 1.1 correction to plan 14.1 row 1), among them `Failures (Last Hour)`
    ("Requests we could not answer in the last 60 minutes") next to `Requests (Last Hour)`. Finding parity-2 (fixed):
    v2 dropped it; `failures_last_hour` now counts failed requests in the trailing hour, with the hour before as its
    delta. A refusal by Roxy's protection is not a failure (v1 never counted refusals in `Failed`)."""
    failed = {"outcome": Outcome.FAILED, "status": 504, "source": Source.ROXY, "egress": Egress.DIRECT}
    hour_before_ms = api_app.clock.now_ms() - 3720 * 1000  # inside the hour before, two minutes from its end
    metrics_seed.record(1, reason=ReasonCode.UPSTREAM_TIMEOUT, at_ms=hour_before_ms, **failed)
    metrics_seed.record(3)
    metrics_seed.record(2, reason=ReasonCode.UPSTREAM_TIMEOUT, **failed)
    metrics_seed.record(
        1, outcome=Outcome.REFUSED, reason=ReasonCode.THROTTLE, status=429, source=Source.ROXY, egress=Egress.NONE
    )
    await metrics_seed.flush()
    kpis = api_json(await api.get("overview/kpis", params={"range": "7d"}))
    tiles = {tile["key"]: tile for tile in kpis["tiles"]}
    assert tiles["requests_last_hour"]["value"] == 6
    keys = [tile["key"] for tile in kpis["tiles"]]
    assert keys.index("failures_last_hour") == keys.index("requests_last_hour") + 1  # v1's order: side by side
    tile = tiles["failures_last_hour"]
    assert (tile["value"], tile["delta"], tile["good_direction"], tile["unit"]) == (2, 1, "down", "requests")
    assert sum(value for _t, value in tile["sparkline"]) == 2  # the sparkline sums to its tile
    assert "not answer" in tile["help"]
