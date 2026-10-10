"""Review round 3, parity lens: the Upstream page against v1's Request Failures and method health (plan 14.1 row 24).

What this is
    Tests for two v1 views of upstream trouble that had no v2 API home (findings parity-5, parity-6 and the parity
    table's parity-5, fixed; they were strict xfails): the "Request Failures" log (v1 section 24, mapped to
    Upstream > Failures; parity row 72) and the per-method health fields of v1's Service Health tiles (Requests,
    Failed, Timeouts, Last success, Last error; parity row 71, "per egress, per host").

Why it exists
    v1 kept one row per `Method: reason` signature with Count, Last Status, Last Endpoint, First Seen, Last Seen and
    the last detail (`app/diagnostics.py log_request_failure`), and its Token and Rotate tiles named the last
    success and the last error. v2 records every failed request as a `failure` event (status, path, upstream status,
    upstream error, egress), but no route reads them back as a log, and the egress health cards carry rates and
    percentiles only. An admin chasing "why does the rotator keep failing" has nothing to look at.

How it works
    Failures are seeded through the real recorder (`metrics_seed`), then the Upstream routes are read over HTTP as a
    signed-in admin. The failure log is looked for at the plan's anchor (`/upstream/failures`) and one alias; field
    names are matched loosely first, then the exact fields the fix chose are pinned.

What to read next
    `roxy/admin/api/upstream.py` (`egress_cards`), `roxy/metrics/recorder.py` (`_record_refusal_event`, the
    `failure` events), `roxy/metrics/queries.py` (`refusal_reasons` reads them only for the message split).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import pytest

from roxy.core.reasons import Egress, Outcome, ReasonCode, Source

pytestmark = pytest.mark.asyncio

FAILURE_ROUTES = ("upstream/failures", "upstream/request-failures")


def failed(seed: Any, count: int, reason: ReasonCode, status: int, **fields: Any) -> None:
    seed.record(count, outcome=Outcome.FAILED, reason=reason, status=status, source=Source.ROXY, **fields)


def keys_like(item: Mapping[str, Any], prefix: str) -> list[str]:
    return [key for key in item if key.startswith(prefix) and item[key] not in (None, "", 0)]


async def test_parity_5_upstream_failures_log_exists(api: Any, api_app: Any, api_json: Any, metrics_seed: Any) -> None:
    """Finding parity-5 (fixed): `GET /upstream/failures` is v1's Request Failures log."""
    first_ms = api_app.clock.now_ms()
    failed(
        metrics_seed, 2, ReasonCode.UPSTREAM_5XX, 503, egress=Egress.DIRECT, upstream_status=503,
        upstream_error="HTTP 503", path="games.roblox.com/v1/games/7",
    )  # fmt: skip
    api_app.clock.advance(1)
    failed(
        metrics_seed, 1, ReasonCode.UPSTREAM_TIMEOUT, 504, egress=Egress.ROTATOR, upstream_error="ReadTimeout",
        path="thumbnails.roblox.com/v1/assets",
    )  # fmt: skip
    await metrics_seed.flush()
    answers = {route: await api.get(route, params={"range": "1h"}) for route in FAILURE_ROUTES}
    found = [(route, r) for route, r in answers.items() if r.status_code == 200]
    assert found, {route: r.status_code for route, r in answers.items()}
    body = api_json(found[0][1])
    rows = body.get("items", [])
    direct = [row for row in rows if "direct" in str(row) and "upstream_5xx" in str(row)]
    assert direct, rows
    row = direct[0]
    assert row.get("count", row.get("failures")) == 2, row
    assert "games.roblox.com/v1/games/7" in str(row), row  # last endpoint
    assert "HTTP 503" in str(row), row  # last detail
    assert keys_like(row, "first"), row  # first seen
    assert keys_like(row, "last_seen") or keys_like(row, "last_ms") or keys_like(row, "last_at"), row
    assert (row["egress"], row["upstream_status"], row["last_status"], row["first_ms"]) == (
        "direct",
        503,
        503,
        first_ms,
    )
    assert {"last_path", "last_error"} <= set(body["caller_text"])  # caller text is marked for the page
    rotator = api_json(await api.get("upstream/failures", params={"range": "1h", "egress": "rotator"}))
    assert [(item["reason"], item["count"]) for item in rotator["items"]] == [("upstream_timeout", 1)]
    export = await api.get("upstream/failures", params={"range": "1h", "format": "csv"})
    assert export.status_code == 200, export.text
    assert "games.roblox.com/v1/games/7" in export.text


async def test_parity_6_egress_cards_carry_v1_method_health(
    api: Any, api_app: Any, api_json: Any, metrics_seed: Any
) -> None:
    """Finding parity-6 and lane parity-5 (fixed): the cards carry Failed, Last success and Last error."""
    metrics_seed.record(3, egress=Egress.DIRECT)
    failed(metrics_seed, 2, ReasonCode.UPSTREAM_5XX, 503, egress=Egress.DIRECT, upstream_status=503,
           upstream_error="HTTP 503")  # fmt: skip
    api_app.clock.advance(1)
    error_ms = api_app.clock.now_ms()
    failed(metrics_seed, 1, ReasonCode.UPSTREAM_TIMEOUT, 504, egress=Egress.DIRECT, upstream_error="ReadTimeout")
    await metrics_seed.flush()
    body = api_json(await api.get("upstream/egress", params={"range": "1h"}))
    card = next(item for item in body["items"] if item["egress"] == "direct")
    assert card["timeouts"] == 1  # v1 "Timeouts" survives
    found = {
        "failed": card.get("failed", card.get("failures")),
        "last_success": bool(keys_like(card, "last_success")),
        "last_error": bool(keys_like(card, "last_error")),
    }
    assert found == {"failed": 3, "last_success": True, "last_error": True}, card
    minute = error_ms // 1000 // 60 * 60
    assert (card["last_success_at"], card["last_error_at"], card["last_success_precision"]) == (
        minute,
        minute,
        "minute",
    )
    error = card["last_error"]
    assert (error["at_ms"], error["reason"], error["status"], error["error"]) == (
        error_ms, "upstream_timeout", 504, "ReadTimeout"
    )  # fmt: skip
    rotator = next(item for item in body["items"] if item["egress"] == "rotator")
    assert (rotator["failed"], rotator["last_success_at"], rotator["last_error"]) == (0, None, None)  # unknown: None
    hosts = api_json(await api.get("upstream/hosts", params={"range": "1h"}))
    host = next(item for item in hosts["items"] if item["host"] == "games.roblox.com")
    assert (host["failed"], host["last_error"]["reason"]) == (3, "upstream_timeout")
