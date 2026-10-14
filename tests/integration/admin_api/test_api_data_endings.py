"""A reset, a backup or a VACUUM that ends early says how it ended (finding data-7), through the running app.

What this is
    The reach of the data-7 fix beyond its reproduction (`tests/review_final/test_data.py`: a reset canceled by a
    worker shutdown): a reset that fails part way through its first table keeps the rows it already deleted on
    record and its chart marker reads "incomplete" (before, the batches of the table in progress were not counted,
    so the marker was removed although rows were gone); Back up now and VACUUM write a `.failed` audit row when
    their work fails, and give the reset lease back.

Why it exists
    Plan 6.8 and 9.7: every reset records its exact row counts, a marker never reads as a finished reset when the
    reset stopped part way, and `GET /data/operations/{id}` answers from the audit log on another worker, where an
    operation without a `.done` or `.failed` row reads "started" for ever.

How it works
    The `api` fixtures of `conftest.py` (the real app over temporary databases, a fake clock). Failures are
    injected by monkeypatching the Data module's own functions (`_delete_batch`, `take_snapshot`,
    `_vacuum_estimates`, `retention.database_sizes`).

What to read next
    `roxy/admin/api/data.py` (`execute_reset`, `back_up_now`, `run_vacuum`, `settle_ending`),
    `tests/unit/admin_api/test_data_operation_endings.py`.
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any

import pytest

from roxy.admin.api import data
from roxy.config.audit import Actor
from roxy.storage import retention
from roxy.storage.db import SharedStateUnavailable

ADMIN = Actor("admin", "endings", "127.0.0.1")


async def _q(db: Any, sql: str, params: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
    rows: list[tuple[Any, ...]] = await db.read(lambda conn: [tuple(r) for r in conn.execute(sql, params).fetchall()])
    return rows


async def _lease_held(api_app: Any) -> bool:
    rows = await _q(
        api_app.ctx.dbs.hot,
        "SELECT count(*) FROM lease WHERE name = ? AND expires_ms > ?",
        (data.RESET_LEASE, api_app.clock.now_ms()),
    )
    return bool(rows[0][0])


async def test_a_reset_that_fails_in_its_first_table_keeps_its_marker_and_its_counts(
    api_app: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    ctx = api_app.ctx
    now_ms = int(ctx.clock.now_ms())
    rows = [(now_ms - 1000 - i,) for i in range(2 * data.BATCH_ROWS)]
    await ctx.dbs.metrics.write(
        lambda conn: conn.executemany(
            "INSERT INTO events (at_ms, type, severity, reason_code, detail_json) "
            "VALUES (?, 'probe', 'info', 'not_roblox', '{}')",
            rows,
        )
    )
    real = data._delete_batch
    batches: dict[str, int] = {}

    def second_batch_fails(conn: sqlite3.Connection, part: Any, where: str, params: Any, limit: int) -> int:
        batches[part.table] = batches.get(part.table, 0) + 1
        if part.table == "events" and batches["events"] > 1:
            raise RuntimeError("disk I/O error")
        return real(conn, part, where, params, limit)

    monkeypatch.setattr(data, "_delete_batch", second_batch_fails)
    body = data.ResetBody.model_validate({"scope": "family", "families": ["probes"]})
    plan = data.build_plan(body, ctx, ctx.clock.now())
    op = data.Operation(data._new_id("reset"), "reset", plan.label, ctx.clock.now())
    target = f"operation:{op.id}"
    op.audit_id = await data._audit(ctx, ADMIN, data.AUDIT_RESET, target, {"plan": plan.label}, "endings", None)
    lease = data.ResetLease(ctx, "endings")
    assert await lease.acquire()
    with pytest.raises((RuntimeError, SharedStateUnavailable)):
        await data.execute_reset(ctx, op, plan, ADMIN, "endings", None, lease)

    failed = await _q(
        ctx.dbs.control,
        "SELECT after_json FROM audit_log WHERE action = ? AND target = ?",
        (data.AUDIT_RESET_FAILED, target),
    )
    assert len(failed) == 1
    assert json.loads(failed[0][0])["deleted"]["metrics.events"] == data.BATCH_ROWS
    left = await _q(ctx.dbs.metrics, "SELECT count(*) FROM events WHERE type = 'probe'")
    assert left == [(data.BATCH_ROWS,)]
    labels = [str(r[0]) for r in await _q(ctx.dbs.metrics, "SELECT label FROM annotations")]
    assert labels == [f"Data reset (incomplete): {plan.label}"]
    assert not await _lease_held(api_app)


async def test_back_up_now_that_fails_writes_its_failed_row(
    api: Any, api_app: Any, section13: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def no_space(ctx: Any, name: str, kind: str, now: float) -> dict[str, Any]:
        raise OSError("No space left on device")

    monkeypatch.setattr(data, "take_snapshot", no_space)
    section13(await api.post("data/backups", json={"reason": "before an upgrade"}), 500, "operation_failed")
    rows = await _q(
        api_app.ctx.dbs.control,
        "SELECT action, after_json FROM audit_log WHERE action LIKE 'data.backup%' ORDER BY id",
    )
    assert [r[0] for r in rows] == ["data.backup", "data.backup.failed"]
    failed = json.loads(rows[1][1])
    assert failed["error"] == "OSError: No space left on device"
    assert failed["request"]["written"] is True  # the root backup was still asked
    assert not await _lease_held(api_app)


async def test_a_vacuum_that_fails_writes_its_failed_row(
    api: Any, api_app: Any, section13: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def estimates(ctx: Any) -> list[dict[str, Any]]:
        return [{"db": "metrics", "bytes": 4096, "enough_disk": True, "allowed": True}]

    def unreadable(conn: sqlite3.Connection) -> dict[str, int]:
        raise sqlite3.DatabaseError("database disk image is malformed")

    monkeypatch.setattr(data, "_vacuum_estimates", estimates)
    monkeypatch.setattr(retention, "database_sizes", unreadable)
    response = await api.post("data/vacuum", json={"database": "metrics", "confirm": "vacuum metrics"})
    section13(response, 500, "operation_failed")
    rows = await _q(
        api_app.ctx.dbs.control,
        "SELECT action, after_json FROM audit_log WHERE action LIKE 'data.vacuum%' ORDER BY id",
    )
    assert [r[0] for r in rows] == ["data.vacuum", "data.vacuum.failed"]
    assert json.loads(rows[1][1])["database"] == "metrics"
