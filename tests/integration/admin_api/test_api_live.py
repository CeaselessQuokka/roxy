"""The Live API (`/admin/api/v1/live`) in the real app: the live tail query with every filter and its cursor, the
capture detail with v1's exact expired text, and the capture state (plan 14.1 Live row, parity rows 81, 82, 126 to
128)."""

from __future__ import annotations

from typing import Any

from roxy.core.reasons import CacheState, Egress, Outcome, ReasonCode, Source
from roxy.metrics.capture import CAPTURE_EXPIRED_MESSAGE, CAPTURE_OFF_MESSAGE, CaptureInput

REFUSED = {
    "outcome": Outcome.REFUSED,
    "reason": ReasonCode.THROTTLE,
    "status": 429,
    "source": Source.ROXY,
    "cache_state": CacheState.NA,
    "upstream_calls": 0,
    "egress": Egress.NONE,
}


def request_id(n: int) -> str:
    return f"LIVE{n:022d}"


def record(seed: Any, n: int, **fields: Any) -> str:
    rid = request_id(n)
    seed.owner.ctx.recorder.record_outcome(
        seed.outcome(request_id=rid, path=f"games.roblox.com/v1/games/{n}", **fields)
    )
    return rid


async def test_live_needs_a_session(anon_api: Any) -> None:
    assert (await anon_api.get("live")).status_code == 401
    assert (await anon_api.get(f"live/{request_id(1)}")).status_code == 401
    assert (await anon_api.get("live/state")).status_code == 401


async def test_rows_newest_first_with_filters(api: Any, metrics_seed: Any, api_json: Any) -> None:
    record(metrics_seed, 1)
    record(metrics_seed, 2, client_ip="198.51.100.20", place_id="4242")
    record(metrics_seed, 3, **REFUSED)
    record(metrics_seed, 4, egress=Egress.ROTATOR, status=503, outcome=Outcome.FAILED,
           reason=ReasonCode.UPSTREAM_5XX, source=Source.ROXY)  # fmt: skip
    await metrics_seed.flush()
    body = api_json(await api.get("live"))
    assert [row["request_id"] for row in body["items"]] == [request_id(n) for n in (4, 3, 2, 1)]
    assert all(row["event_id"] for row in body["items"])
    assert body["next_before"] is None
    for field_name in ("outcome", "reason", "status", "egress", "cache", "ip", "place", "duration_ms", "attempts"):
        assert field_name in body["items"][0], field_name

    async def fetch(params: dict[str, Any]) -> dict[str, Any]:
        return api_json(await api.get("live", params=params))  # type: ignore[no-any-return]

    async def ids_of(params: dict[str, Any]) -> list[str]:
        return [row["request_id"] for row in (await fetch(params))["items"]]

    assert await ids_of({"outcome": "refused"}) == [request_id(3)]
    assert await ids_of({"outcome": "refused,failed"}) == [request_id(4), request_id(3)]
    assert await ids_of({"status": "4xx"}) == [request_id(3)]
    assert await ids_of({"status": "503"}) == [request_id(4)]
    assert await ids_of({"egress": "rotator"}) == [request_id(4)]
    assert await ids_of({"client": "198.51.100"}) == [request_id(2)]  # a substring, like the page's own filter
    assert await ids_of({"client": "4242"}) == [request_id(2)]  # the place id counts as the client too
    assert await ids_of({"endpoint": "GAMES/1"}) == [request_id(1)]  # case-insensitive
    assert await ids_of({"reason": "throttle"}) == [request_id(3)]
    assert await ids_of({"cache": "n/a"}) == [request_id(3)]
    described = (await fetch({"outcome": "refused", "status": "4xx"}))["filters"]
    assert described["outcome"] == ["refused"]
    assert described["status"] == ["4xx"]


async def test_bad_filters_are_422_with_fields(api: Any, section13: Any) -> None:
    fields = section13(await api.get("live", params={"outcome": "partying"}), 422, "validation_failed")
    assert "outcome" in fields
    fields = section13(await api.get("live", params={"status": "6xx"}), 422, "validation_failed")
    assert "status" in fields
    fields = section13(await api.get("live", params={"limit": 501}), 422, "validation_failed")
    assert "limit" in fields


async def test_cursor_pages_back_without_gaps(api: Any, metrics_seed: Any, api_json: Any) -> None:
    for n in range(1, 31):
        record(metrics_seed, n)
    await metrics_seed.flush()
    first = api_json(await api.get("live", params={"limit": 10}))
    assert [row["request_id"] for row in first["items"]] == [request_id(n) for n in range(30, 20, -1)]
    assert first["next_before"] is not None
    second = api_json(await api.get("live", params={"limit": 10, "before": first["next_before"]}))
    assert [row["request_id"] for row in second["items"]] == [request_id(n) for n in range(20, 10, -1)]
    third = api_json(await api.get("live", params={"limit": 10, "before": second["next_before"]}))
    assert [row["request_id"] for row in third["items"]] == [request_id(n) for n in range(10, 0, -1)]


async def test_rows_this_worker_did_not_write_are_added(
    api: Any, api_app: Any, metrics_seed: Any, api_json: Any
) -> None:
    record(metrics_seed, 1)  # in the ring only: not flushed to the shared table yet
    body = api_json(await api.get("live"))
    assert [row["request_id"] for row in body["items"]] == [request_id(1)]
    assert body["items"][0]["event_id"] is None
    assert body["from_this_worker"] == 1


async def test_capture_detail_expired_and_not_captured(
    api: Any, api_app: Any, metrics_seed: Any, api_json: Any, section13: Any
) -> None:
    # A short capture window: waiting out the default 15 minutes would also idle out the admin session.
    await api_app.settings(capture_sample_served_pct=100, capture_ttl_seconds=60)
    recorder = api_app.ctx.recorder
    rid = request_id(7)
    capture = CaptureInput(
        request_id=rid,
        at_ms=api_app.clock.now_ms(),
        request_headers={"Cookie": "session=abc", "Accept": "application/json"},
        request_body=b'{"ask": 1}',
        response_headers={"Content-Type": "application/json"},
        response_body=b'{"data": [1, 2]}',
    )
    recorder.record_outcome(metrics_seed.outcome(request_id=rid, path="games.roblox.com/v1/games/7"), capture)
    await metrics_seed.flush()
    body = api_json(await api.get(f"live/{rid}"))
    captured = body["capture"]
    assert captured["request_id"] == rid
    assert captured["response_body"] == '{"data": [1, 2]}'
    assert captured["request_headers"]["Cookie"] == "[redacted]"  # redacted when captured (row 82)
    assert body["live"]["request_id"] == rid
    assert body["live"]["capture_id"] == rid
    assert body["capture_window_s"] == 60
    state = api_json(await api.get("live/state"))
    assert state["capture"]["count"] == 1
    assert state["live"]["keep_s"] == 900

    await api_app.settings(capture_sample_served_pct=0)
    other = request_id(8)
    recorder.record_outcome(metrics_seed.outcome(request_id=other), CaptureInput(request_id=other, at_ms=0))
    await metrics_seed.flush()
    response = await api.get(f"live/{other}")
    section13(response, 404, "not_captured")
    assert response.json()["error"]["message"] == CAPTURE_OFF_MESSAGE

    api_app.clock.advance(int(api_app.ctx.settings.int("capture_ttl_seconds")) + 1)
    expired = await api.get(f"live/{rid}")
    section13(expired, 404, "capture_expired")
    assert expired.json()["error"]["message"] == CAPTURE_EXPIRED_MESSAGE  # v1's exact text (row 128)
    unknown = await api.get(f"live/{request_id(99)}")
    section13(unknown, 404, "capture_expired")
    fields = section13(await api.get("live/not an id!"), 422, "validation_failed")
    assert "request_id" in fields
