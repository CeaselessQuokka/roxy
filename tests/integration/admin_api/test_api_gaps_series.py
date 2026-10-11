"""Series and fleet answers added for the metrics-side gaps of the P11 pages (gaps G2 and G3), in the real app.

What this is
    `GET /admin/api/v1/protection/spam/series` (the plan 10.9 detector timelines, gap G2): decision events recorded
    through the real recorder, read back as a section 13 series answer with one series per detector, totals that
    equal the decisions table, the filters of `GET /spam/events` and a comparison window. And the fleet's per worker
    CPU (gap G3, `worker_cpu_pct`): the System API's workers rows carry the last complete minute's mean CPU from
    `worker_minute`.

Why it exists
    One number, one definition (P6): the chart, the table and the System page read the same rows.

What to read next
    `roxy/admin/api/protection.py` (`spam_series_answer`), `roxy/metrics/read_protection.py` (`spam_points`),
    `roxy/scheduler/read_fleet.py`, `roxy/admin/api/system.py`.
"""

from __future__ import annotations

from typing import Any

import pytest

pytestmark = pytest.mark.asyncio


def ok(response: Any, api_json: Any, status: int = 200) -> Any:
    assert response.status_code == status, response.text
    return api_json(response)


def _decision(metrics_seed: Any, kind: str, detector: str) -> None:
    metrics_seed.event(
        kind,
        "warning",
        "",
        {"detector": detector, "subject": "ip:198.51.100.7", "value": 9.0, "threshold": 5.0, "window_s": 600,
         "action": "ban", "configured_action": "ban", "game_server": False, "evidence": "9 a second"},
    )  # fmt: skip


async def test_the_detector_timelines_are_a_series_answer_that_equals_the_table(
    api: Any, api_json: Any, metrics_seed: Any, section13: Any
) -> None:
    _decision(metrics_seed, "spam_would_ban", "SPAM-RATE")
    _decision(metrics_seed, "spam_would_ban", "SPAM-RATE")
    _decision(metrics_seed, "spam_strike", "SPAM-PROBE")
    await metrics_seed.flush()
    answer = ok(await api.get("protection/spam/series", params={"range": "1h"}), api_json)
    assert set(answer) >= {"range", "series", "compare", "annotations", "notices", "totals", "total"}
    assert [entry["key"] for entry in answer["series"]] == ["SPAM-PROBE", "SPAM-RATE"]
    assert all(entry["unit"] == "count" for entry in answer["series"])
    rate = next(entry for entry in answer["series"] if entry["key"] == "SPAM-RATE")
    assert sum(value for _t, value in rate["points"]) == 2
    assert answer["totals"] == {"SPAM-PROBE": 1, "SPAM-RATE": 2}
    assert answer["total"] == 3
    table = ok(await api.get("protection/spam/events", params={"range": "1h"}), api_json)
    assert table["total"] == answer["total"]  # one definition: the chart and the decisions table
    state = ok(await api.get("protection/spam", params={"range": "1h"}), api_json)
    decisions = {item["label"]: sum(item["decisions"].values()) for item in state["detectors"] if item["decisions"]}
    assert decisions == answer["totals"]
    only = ok(await api.get("protection/spam/series", params={"range": "1h", "kind": "strike"}), api_json)
    assert only["totals"] == {"SPAM-PROBE": 1}
    one = ok(await api.get("protection/spam/series", params={"range": "1h", "detector": "SPAM-RATE"}), api_json)
    assert [entry["key"] for entry in one["series"]] == ["SPAM-RATE"]
    compared = ok(await api.get("protection/spam/series", params={"range": "1h", "compare": "previous"}), api_json)
    assert compared["compare"]["mode"] == "previous"
    assert compared["compare"]["series"] == []  # nothing decided in the hour before
    bad = await api.get("protection/spam/series", params={"detector": "<script>"})
    assert bad.status_code == 422
    section13(await api.get("protection/spam/series", params={"kind": "nope"}), 422, "validation_failed")


async def test_an_empty_range_has_no_series(api: Any, api_json: Any) -> None:
    answer = ok(await api.get("protection/spam/series", params={"range": "24h"}), api_json)
    assert answer["series"] == []
    assert answer["total"] == 0


async def test_the_workers_rows_carry_each_workers_last_minute_of_cpu(api: Any, api_app: Any, api_json: Any) -> None:
    """Gap G3 (`worker_cpu_pct`): the last complete minute of `worker_minute` joined to the heartbeat rows."""
    ctx = api_app.ctx
    await ctx.recorder.flush()
    minute = int(ctx.clock.now()) // 60 * 60 - 60

    def write(conn: Any) -> None:
        conn.execute(
            "INSERT OR REPLACE INTO worker_minute (bucket_start, worker_id, samples, cpu_pct_sum, cpu_pct_max) "
            "VALUES (?, ?, 4, 50.0, 20.25)",
            (minute, ctx.worker_id),
        )

    await ctx.dbs.metrics.write(write)
    table = ok(await api.get("system/workers"), api_json)
    assert "cpu_pct" in {column["key"] for column in table["columns"]}
    mine = next(item for item in table["items"] if item["worker_id"] == ctx.worker_id)
    assert (mine["cpu_pct"], mine["cpu_pct_max"], mine["cpu_minute"]) == (12.5, 20.2, minute)
    fleet = ok(await api.get("system/fleet"), api_json)
    assert next(w for w in fleet["workers"] if w["worker_id"] == ctx.worker_id)["cpu_pct"] == 12.5
