"""Review round 4 (lens secfix): a download whose client goes away gives its export slot back.

What this is
    Variants of the apisec-6 fix: a table download holds one of the worker's `MAX_CONCURRENT_EXPORTS` (2) slots
    from its first read to its last byte (`common.export_format`, a yield dependency). The round 3 tests cover a
    download that completes and one refused with 503. These drive the ASGI app directly and lose the client in the
    middle of the file: the server's `send` raises (a reset connection, as uvicorn reports it), or the client
    disconnects before reading. If either path kept its slot, two dropped downloads (a phone losing signal, a closed
    tab) would leave every later download in that worker answering 429 until the worker restarts.

Why it exists
    Plan P9 and C6: the bound must hold without turning into a permanent refusal for the owner.

How it works
    1,000 audit rows (four export pages of 250) are seeded; each download is driven with a scope carrying the signed
    in session's cookie, then the slot counter (`common.export_slots(app).busy`) must be back at 0 and a normal
    download must still be answered 200.

What to read next
    `roxy/admin/api/common.py` (`export_format`, `ExportSlots`, `_drain`, `_deliver`).
"""

from __future__ import annotations

import asyncio
import contextlib
import json
from typing import Any

from roxy.admin.api import common

ROWS = 1000


async def _seed(api_app: Any) -> None:
    now = int(api_app.clock.now())

    def rows(conn: Any) -> None:
        conn.executemany(
            "INSERT INTO audit_log (at, actor, actor_ip, action, target, before_json, after_json, reason, request_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (now - i, "admin:owner", None, "rule.update", f"rules_cache:{i}", json.dumps({"n": i}),
                 json.dumps({"n": i + 1}), "seed", None)
                for i in range(ROWS)
            ],
        )  # fmt: skip

    await api_app.ctx.dbs.control.write(rows)


def _scope(api: Any) -> dict[str, Any]:
    headers = dict(api.headers())
    token = api.http.cookies.get("__Host-roxy_session")
    headers.update({"Host": "testserver", "Cookie": f"__Host-roxy_session={token}"})
    return {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "https",
        "path": "/admin/api/v1/audit",
        "raw_path": b"/admin/api/v1/audit",
        "query_string": b"format=csv",
        "root_path": "",
        "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
        "client": ("127.0.0.1", 50000),
        "server": ("testserver", 443),
    }


async def _broken_send_download(api: Any, api_app: Any) -> list[str]:
    """The client's connection resets after the first part of the file: `send` raises."""
    seen: list[str] = []
    asked = False

    async def receive() -> dict[str, Any]:
        nonlocal asked
        if not asked:
            asked = True
            return {"type": "http.request", "body": b"", "more_body": False}
        await asyncio.sleep(3600)
        return {"type": "http.disconnect"}

    async def send(message: dict[str, Any]) -> None:
        seen.append(message["type"])
        if message["type"] == "http.response.body" and seen.count("http.response.body") >= 2:
            raise OSError("connection reset by peer")

    with contextlib.suppress(Exception):
        await asyncio.wait_for(api_app.app(_scope(api), receive, send), timeout=30)
    return seen


async def _gone_before_reading(api: Any, api_app: Any) -> list[str]:
    """The client disconnects right after sending its request (the server learns it from `receive`)."""
    seen: list[str] = []
    asked = False

    async def receive() -> dict[str, Any]:
        nonlocal asked
        if not asked:
            asked = True
            return {"type": "http.request", "body": b"", "more_body": False}
        return {"type": "http.disconnect"}

    async def send(message: dict[str, Any]) -> None:
        seen.append(message["type"])

    with contextlib.suppress(Exception):
        await asyncio.wait_for(api_app.app(_scope(api), receive, send), timeout=30)
    return seen


async def test_a_dropped_download_gives_its_slot_back(api: Any, api_app: Any) -> None:
    await _seed(api_app)
    slots = common.export_slots(api_app.app)
    for _ in range(common.MAX_CONCURRENT_EXPORTS + 1):
        seen = await _broken_send_download(api, api_app)
        assert seen.count("http.response.body") == 2, seen  # the head went out, the first page hit the reset
        assert slots.busy == 0, f"{slots.busy} slot(s) still held after a dropped download"
    for _ in range(common.MAX_CONCURRENT_EXPORTS + 1):
        await _gone_before_reading(api, api_app)
        assert slots.busy == 0, f"{slots.busy} slot(s) still held after a client left before reading"
    again = await api.get("audit", params={"format": "csv"})
    assert again.status_code == 200, again.text[:200]
    assert int(again.headers["roxy-export-rows"]) >= ROWS  # the seeded rows, plus the sign-in's own audit rows
