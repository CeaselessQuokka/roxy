"""v1 parity: bot probes at the public surface get clean answers, are logged as probes and never send an alert.

What this is
    Ports of the v1 smoke checks of section S002 ("Bot probes return clean errors and never email"), the probe log
    checks of S003 (line 188) and S040 (line 1255), and the concurrency hammer of S055 (lines 1606, 1646 and 1648)
    that no other v2 test covered. Each test names the v1 lines it ports; `tests/V1_PARITY.md` points back at them.

Why it exists
    v1 answered `POST /` (the request that once flooded the owner with error emails) with a JSON 405 that keeps the
    `Allow` header, logged every probe (a non-Roblox URL, unsafe characters, a smuggled cookie) in the exploit log
    and sent no email. Those properties are easy to lose in a router rewrite: the v2 catch-all proxy route now sees
    `/` too, and the probe log is fed by other code than the refusal itself.

How it works
    The `parity` fixture runs the real app (tests/parity/conftest.py) with the mail transport recorded. Probes are
    sent, the recorder flushed, and the Security page read model (`GET /admin/api/v1/security/probes`) and the
    recorded mail are read back. The tests of findings parity-1 and parity-2 were strict xfails until review round
    3 fixed both; they now pin the fixed behavior.

What to read next
    `roxy/public/pages.py` (which methods `/` answers), `roxy/proxy/router.py` (the catch-all),
    `roxy/abuse/pipeline.py` (what a probe refusal reports) and `roxy/admin/api/security.py` (the probe log).
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest

from roxy.core.redact import TOKEN_PREFIX


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE", "TRACE"])
async def test_v1_post_to_the_home_page_is_a_json_405_with_allow(parity: Any, method: str) -> None:
    """v1 smoke lines 140 to 142 and 188 (finding parity-1, fixed): `POST /` (body `garbage`) gets 405, keeps the
    `Allow` header, the body is JSON, the probe log reads `HTTP 405 via POST /`, and the request never reaches the
    proxy route (so neither the abuse pipeline nor the tarpit sees it). Every other method but GET, HEAD and OPTIONS
    gets the same answer."""
    counters = parity.ctx.heartbeat.counters
    proxied = counters.proxied
    probe_ip = parity.ip()
    response = await parity.proxy(method, "/", ip=probe_ip, content=b"garbage")
    assert response.status_code == 405
    assert response.headers.get("allow") == "GET, HEAD, OPTIONS"
    assert response.headers["content-type"].startswith("application/json")
    json.loads(response.content)  # a JSON document, as v1's jsonify sent
    assert "roxy-refusal" not in response.headers  # an answer of the site, not a proxy refusal
    assert counters.proxied == proxied  # the proxy route never ran
    await parity.ctx.recorder.flush()
    admin = await parity.admin()
    probes = await admin.get("security/probes", params={"ip": probe_ip})
    assert probes.status_code == 200, probes.text
    # v1's reason `HTTP 405 via POST /` is kept as a signature plus a target (the B19 fix splits the two).
    logged = [(item.get("reason"), item.get("target")) for item in probes.json()["items"]]
    assert (f"HTTP 405 via {method}", "/") in logged, logged


async def test_the_home_page_still_answers_get_head_and_options(parity: Any) -> None:
    """Control for the 405 route: GET and HEAD are the home page, OPTIONS keeps the proxy's local 204."""
    assert (await parity.http.get("/")).status_code == 200
    assert (await parity.http.head("/")).status_code == 200
    assert (await parity.proxy("OPTIONS", "/")).status_code == 204


async def test_v1_bot_probes_get_clean_answers_and_never_send_an_alert(parity: Any) -> None:
    """v1 smoke lines 144, 146, 147 and 152: probes get clean 4xx answers (never a 500) and send no mail."""
    probe_ip = parity.ip()
    answers = [
        await parity.proxy("POST", "/", ip=probe_ip, content=b"garbage"),
        await parity.proxy("POST", "/health", ip=probe_ip),
        await parity.get("/this-is-not-roblox", ip=probe_ip),
        await parity.http.post("/admin/api/v1/auth/login", content=b"not json", headers=parity.harness.headers()),
        await parity.http.post("/admin/api/v1/auth/login", json=["a", "list"], headers=parity.harness.headers()),
    ]
    assert [response.status_code for response in answers] == [405, 404, 404, 400, 400]
    assert answers[1].content == b'"Not a Roblox URL"\n'  # POST /health falls to the proxy's 404 (row 129)
    assert answers[2].content == b'"Not a Roblox URL"\n'
    assert answers[2].headers["roxy-throttled"] in ("True", "False")  # v1 line 147: a clean bool string
    await parity.harness.drain()
    assert parity.mail.subjects() == []  # HTTP errors below 500 are never emailed


async def test_v1_proxy_probes_reach_the_probe_log(parity: Any) -> None:
    """v1 smoke lines 188 and 1255: a probe through the proxy route (here a non-Roblox URL and a smuggled cookie)
    is an entry of the exploit log, which v2 shows on the Security page (finding parity-2, fixed)."""
    probe_ip = parity.ip()
    assert (await parity.get("/this-is-not-roblox", ip=probe_ip)).status_code == 404
    smuggled = await parity.get(
        "/games.roblox.com/v1/games?universeIds=1", ip=probe_ip, headers={"X-Custom-Auth": TOKEN_PREFIX + "SECRET"}
    )
    assert smuggled.status_code == 400
    await parity.ctx.recorder.flush()
    admin = await parity.admin()
    probes = await admin.get("security/probes", params={"ip": probe_ip})
    assert probes.status_code == 200, probes.text
    reasons = [str(item.get("reason", "")) for item in probes.json()["items"]]
    assert len(reasons) >= 2, reasons
    assert any("Roblox" in reason for reason in reasons), reasons
    # v1's texts, with the probed URL in the target column and Roxy's own words as the signature (v1 bug B19).
    assert set(reasons) == {
        "Non-Roblox URL",
        "Sent a ROBLOSECURITY token (a header carried a ROBLOSECURITY-shaped value)",
    }, reasons
    targets = {str(item.get("reason")): item.get("target") for item in probes.json()["items"]}
    assert targets["Non-Roblox URL"] == "this-is-not-roblox"
    assert "SECRET" not in probes.text


async def test_v1_probe_storms_never_break_shared_state_or_the_admin(parity: Any) -> None:
    """v1 smoke lines 1606, 1646 and 1648: 8 concurrent clients x 25 rounds of (probe GET, POST /) raise nothing,
    every answer is a clean 4xx, and the admin can still sign in and read the dashboard data afterwards."""

    async def storm(worker: int) -> list[int]:
        statuses = []
        for _round in range(25):
            ip = f"198.51.100.{worker + 1}"
            statuses.append((await parity.get("/wp-login.php", ip=ip)).status_code)
            statuses.append((await parity.proxy("POST", "/", ip=ip, content=b"x")).status_code)
        return statuses

    results = await asyncio.gather(*(storm(worker) for worker in range(8)))
    statuses = [status for batch in results for status in batch]
    assert len(statuses) == 400
    assert all(400 <= status < 500 for status in statuses), sorted(set(statuses))
    admin = await parity.admin()  # a full login (password and TOTP) still works after the storm
    overview = await admin.get("overview/kpis")
    assert overview.status_code == 200, overview.text
