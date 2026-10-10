"""Review round 3, lens mpjobs: data resets that fail part way under live load.

What this is
    An adversarial test against the running app (it was a strict xfail; finding mpjobs-4 is fixed: the reset writes
    its marker before the first delete and keeps it, labeled incomplete, when it fails after deleting): a metric
    family reset whose second table cannot be written (metrics.db busy past its timeout, the way a VACUUM, a
    checkpoint or another worker's long transaction holds it) after the first table's rows were already deleted.

Why it exists
    Plan 6.8: every reset, wherever it is triggered, writes an `annotations` row, so every chart covering that time
    shows a "data reset" marker and every KPI whose window overlaps it shows the partial data notice; "comparison
    baselines are never synthesized to hide the gap". A reset that deleted rows and then failed is still a reset of
    those rows: without the marker the Overview shows a confident drop to zero with no notice. The lens asks that
    no partial reset is ever visible as if it were real data.

How it works
    `data._run_part` is wrapped so the first part (`rollup_minute`) really runs and the next one raises
    `SharedStateUnavailable`, which is exactly what `Database.write` raises after `busy_timeout` under contention.
    The test then reads the `annotations` table and the reset markers the KPI read models use.

What to read next
    `roxy/admin/api/data.py` (`execute_reset`), `roxy/metrics/annotate.py`, `roxy/metrics/queries.py`
    (`reset_annotations`), `roxy/admin/api/common.py` (`reset_notices`).
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from roxy.admin.api import data
from roxy.metrics import queries
from roxy.storage.db import SharedStateUnavailable


async def _count(db: Any, table: str) -> int:
    rows = await db.read(lambda conn: conn.execute(f"SELECT count(*) FROM {table}").fetchone())
    return int(rows[0])


async def test_r3_mpjobs_a_reset_that_fails_midway_still_marks_what_it_deleted(
    api: Any, api_app: Any, api_json: Any, metrics_seed: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    metrics_seed.record(5)
    await metrics_seed.flush()
    metrics = api_app.ctx.dbs.metrics
    assert await _count(metrics, "rollup_minute") > 0

    scope = {"scope": "family", "families": ["traffic"]}
    preview = api_json(await api.post("data/resets/preview", json=scope))
    original = data._run_part

    async def busy_after_the_first_table(ctx: Any, op: Any, lease: Any, part: Any, window: Any) -> int:
        if part.table != "rollup_minute":
            raise SharedStateUnavailable("metrics", "database is locked")  # busy_timeout ran out under load
        return await original(ctx, op, lease, part, window)

    monkeypatch.setattr(data, "_run_part", busy_after_the_first_table)
    answer = await api.post(
        "data/resets", json={**scope, "preview": preview["preview"], "confirm": "reset traffic", "reason": "clean"}
    )
    assert answer.status_code in (200, 202, 500), answer.text
    for _ in range(100):
        if await _count(metrics, "rollup_minute") == 0:
            break
        await asyncio.sleep(0.02)
    await asyncio.sleep(0.2)
    assert await _count(metrics, "rollup_minute") == 0  # the first table's rows are gone for good

    now = int(api_app.clock.now())
    markers = await metrics.read(lambda conn: queries.reset_annotations(conn, now - 3600, now + 60))
    # Plan 6.8: the rows that were deleted are marked, so a KPI over this hour says "Partial data".
    assert markers, "no data reset marker for rows a failed reset deleted"
    # The marker says the reset did not finish and links to the audit row that records what it deleted.
    failed = await api_app.ctx.dbs.control.read(
        lambda conn: conn.execute("SELECT id FROM audit_log WHERE action = 'data.reset.failed'").fetchall()
    )
    assert [m["label"] for m in markers] == ["Data reset (incomplete): Traffic"]
    assert [m["audit_id"] for m in markers] == [failed[0][0]]
