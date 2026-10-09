"""v1 parity: upstream timeouts never alert, and Roxy's own probes are never touched by caller-facing rules.

What this is
    Ports of v1 smoke line 691 (S016: "Timeouts never email the admin"), lines 2562 to 2569 (S080: "Internal
    probes are exempt from every caller-facing rule") and the method health fields of S069 and S045 (lines 2096,
    2097, 2103 and 1353 to 1355), which v2 does not show yet (a strict xfail, finding parity-5).

Why it exists
    v1 learned the hard way that a slow Roblox must not flood the owner's inbox: a timeout is an ordinary upstream
    outcome, not an error. And Roxy's own probes (credential liveness, lookups, health checks) must keep working
    while the owner has paused the proxy, switched on the emergency limit or blocked the very endpoint a probe uses;
    otherwise the dashboard would report a healthy credential as dead exactly when the owner is busy with an
    incident.

How it works
    The `parity` fixture runs the real app with Roblox played by respx and the notifier's mail recorded. The first
    test makes Roblox time out; the second sets every caller-facing rule against `accountinformation.roblox.com`,
    then calls `UpstreamService.internal_fetch` (the path every v2 probe takes) and reads the recorded internal call.

What to read next
    `roxy/upstream/internal.py` (the probe list and its note), `roxy/upstream/service.py` (`internal_fetch`) and
    `roxy/notify/notifier.py` (what raises an alert).
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from roxy.abuse.pause import set_pause
from roxy.abuse.throttle_all import set_throttle_all
from roxy.config.audit import Actor

ADMIN = Actor("admin", "parity")
PROBE_URL = "https://accountinformation.roblox.com/v1/birthdate"


async def test_v1_upstream_timeouts_never_send_an_alert(parity: Any) -> None:
    """v1 smoke line 691: an upstream timeout is answered and logged, but no mail goes to the owner."""
    parity.roblox.route(host="games.roblox.com").mock(side_effect=httpx.ReadTimeout("slow"))
    response = await parity.get("/games.roblox.com/v1/games?universeIds=1")
    assert response.status_code in (502, 503, 504)
    assert response.headers["roxy-refusal"] in ("upstream_timeout", "deadline")
    await parity.harness.drain()
    assert parity.mail.subjects() == []
    # v1 lines 690 and 1916 to 1918: the timeout is counted against the egress that carried it.
    parity.clock.advance(61)
    await parity.ctx.recorder.flush()
    admin = await parity.admin()
    cards = await admin.get("upstream/egress", params={"range": "1h"})
    assert cards.status_code == 200, cards.text
    direct = {card["egress"]: card for card in cards.json()["items"]}["direct"]
    assert direct["requests"] >= 1
    assert direct["timeouts"] >= 1


async def test_v1_internal_probes_are_exempt_from_every_caller_facing_rule(parity: Any) -> None:
    """v1 smoke lines 2562 to 2569: paused, throttle-all on, the probe endpoint blocked and rate-limited and a
    filter on `Accept`; Roxy's own probe still reaches Roblox, succeeds and is recorded as an internal call."""
    route = parity.roblox.route(host="accountinformation.roblox.com").mock(
        return_value=httpx.Response(200, json={"birthMonth": 1})
    )
    await set_pause(parity.ctx.dbs.control, parity.clock, ADMIN, paused=True)
    await set_throttle_all(parity.ctx.dbs.control, parity.clock, ADMIN, enabled=True)
    await parity.ctx.abuse.switches.reload()
    await parity.rule("rules_endpoint_block", {"pattern": "accountinformation.roblox.com"})
    await parity.rule("rules_endpoint_limit", {"pattern": "accountinformation.roblox.com", "limit": 1, "period": 60})
    await parity.rule("rules_header", {"needle": "json", "header": "Accept"})
    caller = await parity.get("/accountinformation.roblox.com/v1/birthdate")
    assert caller.status_code == 503  # a caller is refused (paused) ...
    result = await parity.ctx.upstream.internal_fetch("health_check", "GET", PROBE_URL)
    assert result.status == 200  # ... while the probe passes untouched
    assert route.call_count == 1
    parity.clock.advance(61)
    await parity.ctx.recorder.flush()
    rows = await parity.ctx.dbs.metrics.read(
        lambda conn: conn.execute("SELECT reason_code, ip_hash FROM events WHERE type = 'internal_call'").fetchall()
    )
    assert [row[0] for row in rows] == ["health_check"]  # recorded as Roxy's own call
    assert rows[0][1] is None  # never attributed to a client address (not caller traffic)


@pytest.mark.xfail(
    strict=True,
    reason=(
        "finding parity-5: the per-egress health cards (GET /upstream/egress) give counts and rates only; v1's "
        "LastSuccessAt, LastErrorAt and LastError (parity row 71) and the last failed status and endpoint of its "
        "request failure log (row 72) have no v2 counterpart beyond the 15 minute Live rows"
    ),
)
async def test_v1_egress_health_says_when_it_last_worked_and_what_failed_last(parity: Any) -> None:
    """v1 smoke lines 2096, 2097 and 2103 (S069) and 1353 to 1355 (S045): after a success and a Roblox 500, the
    egress that carried them reports when it last succeeded, when it last failed, and what that failure was."""
    good = parity.roblox.route(host="games.roblox.com", path="/v1/games").mock(
        return_value=httpx.Response(200, json={"ok": True})
    )
    parity.roblox.route(host="games.roblox.com", path="/v1/boom").mock(return_value=httpx.Response(500, text="boom"))
    assert (await parity.get("/games.roblox.com/v1/games?universeIds=1")).status_code == 200
    assert (await parity.get("/games.roblox.com/v1/boom")).status_code >= 500
    assert good.call_count == 1
    parity.clock.advance(61)
    await parity.ctx.recorder.flush()
    admin = await parity.admin()
    cards = await admin.get("upstream/egress", params={"range": "1h"})
    assert cards.status_code == 200, cards.text
    direct = {card["egress"]: card for card in cards.json()["items"]}["direct"]
    assert direct["requests"] >= 2  # the counts are there (Requests, Failed, Timeouts are kept) ...
    last_success = [key for key in direct if "last_success" in key]
    last_error = [key for key in direct if "last_error" in key or "last_failure" in key]
    assert last_success, sorted(direct)  # ... the "when did it last work, what failed last" fields are not
    assert last_error, sorted(direct)
    assert "500" in str({key: direct[key] for key in last_error})
    assert "boom" in str({key: direct[key] for key in last_error})
