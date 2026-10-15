"""How a data operation that ends early is written down, and how a snapshot file is named (no app).

What this is
    Unit tests of the Data API helpers that the final review's fixes added: `settle_ending` and `failure_text`
    (finding data-7: a reset, backup or VACUUM canceled by its worker's shutdown records how it ended, within a time
    bound, then lets the cancellation go on), `deleted_so_far` (the rows of the table a reset was working on count
    as deleted) and `snapshot_kind` (finding docs_b-9: the deploy's `pre-migrate-` copies read as taken before a
    migration).

Why it exists
    `asyncio.CancelledError` is not an `Exception`, so a cleanup written as `except Exception` never runs when a
    gunicorn recycle or a deploy stops a worker; and a cleanup that waited on a database for ever would hold the
    shutdown past gunicorn's `graceful_timeout`. Both halves are pinned here with plain tasks.

How it works
    Plain asyncio tasks canceled the way `TaskSupervisor.stop` cancels them (one `cancel()`), with the time bound
    made short through monkeypatch; `deploy/prestart.py` is read with `ast` (it is a script, not a package module).

What to read next
    `roxy/admin/api/data.py`, `roxy/core/tasks.py` (`TaskSupervisor.stop`),
    `tests/integration/admin_api/test_api_data_endings.py` (the same through the running app).
"""

from __future__ import annotations

import ast
import asyncio
import time
from pathlib import Path

import pytest

from roxy.admin.api import data

REPO = Path(__file__).resolve().parents[3]


async def test_a_canceled_operation_records_its_end_within_the_bound(monkeypatch: pytest.MonkeyPatch) -> None:
    """One cancel (as `TaskSupervisor.stop` sends), then the record runs (an await still works after it), is cut at
    `STOPPED_RECORD_S` when the database never answers, and the cancellation goes on."""
    monkeypatch.setattr(data, "STOPPED_RECORD_S", 0.05)
    recorded: list[str] = []
    started = asyncio.Event()

    async def operation() -> None:
        try:
            started.set()
            await asyncio.sleep(3600)
        except asyncio.CancelledError as exc:
            text = data.failure_text(exc)

            async def record() -> None:
                await asyncio.sleep(0)
                recorded.append(text)
                await asyncio.sleep(3600)  # a database that never answers

            await data.settle_ending(record, exc)
            raise

    task = asyncio.create_task(operation())
    await started.wait()
    began = time.monotonic()
    task.cancel()
    (outcome,) = await asyncio.gather(task, return_exceptions=True)
    assert isinstance(outcome, asyncio.CancelledError)
    assert recorded == [data.STOPPED_MESSAGE]
    assert time.monotonic() - began < 2.0


async def test_a_failed_record_never_hides_the_failure() -> None:
    """A record that raises (the database may be why the operation failed) is swallowed; the caller re-raises."""

    async def record() -> None:
        raise RuntimeError("database is locked")

    await data.settle_ending(record, RuntimeError("the operation's own failure"))


def test_failure_text_names_a_shutdown_in_words() -> None:
    assert data.failure_text(asyncio.CancelledError()) == data.STOPPED_MESSAGE
    assert data.failure_text(OSError("No space left on device")) == "OSError: No space left on device"


def test_the_rows_of_the_table_in_progress_count_as_deleted() -> None:
    """`op.progress` holds the batches committed so far; `deleted` only the tables that finished."""
    finished = {"metrics.rollup_minute": 12, "control.bans": 2}
    progress = {"metrics.rollup_minute": 12, "metrics.events": 5000}
    assert data.deleted_so_far(finished, progress) == {
        "metrics.rollup_minute": 12,
        "control.bans": 2,
        "metrics.events": 5000,
    }
    assert data.deleted_so_far({}, {}) == {}


@pytest.mark.parametrize(
    ("name", "kind"),
    [
        ("pre-migrate-20261013T120000Z-65d4bd5abcde.db", "premigrate"),
        ("pre-migrate-20261013T120000Z-65d4bd5abcde-2.db", "premigrate"),
        ("reset-20261013T120000Z-metrics.db", "reset"),
        ("manual-20261013T120000Z-control.db", "manual"),
        ("other-20261013T120000Z-control.db", "other"),
    ],
)
def test_a_snapshot_kind_is_its_whole_prefix(name: str, kind: str) -> None:
    assert data.snapshot_kind(name) == kind


def test_the_premigrate_prefix_is_the_one_the_deploy_writes() -> None:
    """`deploy/prestart.py` names its copies; the Data page reads the kind from the same prefix."""
    tree = ast.parse((REPO / "deploy" / "prestart.py").read_text(encoding="utf-8"))
    values = [
        node.value.value
        for node in tree.body
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "SNAPSHOT_PREFIX" for target in node.targets)
        and isinstance(node.value, ast.Constant)
    ]
    assert values == [data.PREMIGRATE_SNAPSHOT_PREFIX]
