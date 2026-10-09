"""Review round 3 (lens apisec): bounds on expensive admin API work, and path ids out of SQLite's range.

What this is
    Strict-xfail tests for three findings about what one signed-in session can make a 1 GB server do:
      * apisec-5: `POST /data/backups` ("Back up now") copies control.db and metrics.db with `VACUUM INTO` every
        time it is called. Its feasibility check compares one database with `snapshots_max_bytes` and the free disk
        with one more copy, but never counts the snapshots already in the folder, and nothing stops a second call
        while the first copies. The cap ("Total disk space all safety snapshots may use together") holds only when
        the `file_retention` job next runs (every 600 s); until then repeated calls fill the state volume down to
        `SNAPSHOT_MIN_FREE_BYTES` (64 MiB).
      * apisec-6: every table route's `format=csv|json` download (`common.export_table`) reads up to 50,000 rows
        into memory and renders the whole file on a worker thread, with no limit on how many run at once. The LLM
        export caps its builds at 2 per worker (429 above); table exports have no such bound.
      * apisec-7: an integer path id larger than SQLite's 64-bit range (`/routing-rules/{rule_id}`,
        `/credential-allowlist/{row_id}`, `/cache/rules/{rule_id}`, `/health/runs/{run_id}`) reaches the database
        unbounded; sqlite3 raises `OverflowError`, the answer is the unhandled 500 and every such request fires the
        owner's "Roxy Error" alert (`notify.notifier.error_alert`). Other areas bound the same ids with
        `Path(ge=1, le=2**62)`.

Why it exists
    Plan P9 (every queue, table and file bounded), 6.6 and 6.10 (snapshots capped), the 1 GB memory budget of
    DESIGN.md section 0, and DESIGN.md 13 ("nothing a service refuses turns into a 500").

How it works
    Backups: `snapshots_max_bytes` is set to the whole MiB just above one backup's size, then backups are made
    one after another; the folder must never hold more than the cap. Exports: `common.render_export` is wrapped so
    each render waits on an event, six downloads are started at once and the number rendering together is
    counted. Ids: each route is called with a 26-digit id and must answer a section 13 error below 500.

What to read next
    `roxy/admin/api/data.py` (`back_up_now`, `snapshot_feasibility`, `take_snapshot`), `roxy/storage/retention.py`
    (`prune_directory`), `roxy/admin/api/common.py` (`export_table`, `collect_pages`), `roxy/admin/api/export_llm.py`
    (the 2-build bound), `roxy/admin/api/routing_rules.py`, `credential_allowlist.py`, `cache.py`, `health.py`.
"""

from __future__ import annotations

import asyncio
import os
import threading
from pathlib import Path
from typing import Any

import pytest

from roxy.admin.api import common

MIB = 1024 * 1024
HUGE_ID = "99999999999999999999999999"


def _folder_bytes(folder: Path) -> int:
    if not folder.is_dir():
        return 0
    return sum(entry.stat().st_size for entry in os.scandir(folder) if entry.is_file())


def _db_bytes(api_app: Any, name: str) -> int:
    path = Path(api_app.ctx.dbs.get(name).path)
    wal = path.with_name(path.name + "-wal")
    return path.stat().st_size + (wal.stat().st_size if wal.exists() else 0)


# =============================================================================================== apisec-5


@pytest.mark.xfail(
    strict=True,
    reason="finding apisec-5: Back up now ignores the snapshots already on disk, so the folder outgrows the cap",
)
async def test_back_up_now_keeps_the_snapshot_folder_within_its_cap(api: Any, api_app: Any) -> None:
    folder = Path(api_app.ctx.env.state_dir) / "snapshots"
    one_backup = _db_bytes(api_app, "control") + _db_bytes(api_app, "metrics")
    cap = -(-one_backup // MIB) * MIB  # the whole MiB just above one backup
    await api_app.settings(snapshots_max_bytes=cap)
    calls = cap // one_backup + 2  # enough backups to pass the cap at least once
    over: list[str] = []
    for number in range(1, calls + 1):
        response = await api.post("data/backups", json={"reason": f"backup {number}"})
        if response.status_code == 200:
            assert response.json()["status"] == "done", response.text[:200]
        else:
            assert response.status_code in (409, 429), response.text[:200]  # a refusal keeps the cap
        held = _folder_bytes(folder)
        if held > cap:
            over.append(f"after call {number}: {held} bytes in snapshots/ (cap {cap})")
    assert over == [], "; ".join(over)


# =============================================================================================== apisec-6


@pytest.mark.xfail(
    strict=True,
    reason="finding apisec-6: table exports have no concurrency bound; six 50,000-row renders may run at once",
)
async def test_table_exports_are_bounded_per_worker(api: Any, api_app: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    release = threading.Event()
    lock = threading.Lock()
    state = {"now": 0, "peak": 0}
    real = common.render_export

    def held_render(*args: Any, **kwargs: Any) -> Any:
        with lock:
            state["now"] += 1
            state["peak"] = max(state["peak"], state["now"])
        try:
            release.wait(timeout=10)
            return real(*args, **kwargs)
        finally:
            with lock:
                state["now"] -= 1

    monkeypatch.setattr(common, "render_export", held_render)
    tasks = [asyncio.create_task(api.get("audit", params={"format": "csv"})) for _ in range(6)]
    try:
        for _ in range(60):  # 3 s at most: until every download is either rendering (held) or answered
            if state["now"] + sum(task.done() for task in tasks) >= len(tasks):
                break
            await asyncio.sleep(0.05)
        await asyncio.sleep(0.2)
        peak = state["peak"]
    finally:
        release.set()
        answers = await asyncio.gather(*tasks)
    refused = [r for r in answers if r.status_code == 429]
    assert all(r.status_code in (200, 429) for r in answers), [r.status_code for r in answers]
    assert peak <= 2, f"{peak} exports rendered at once; {len(refused)} of 6 refused"
    assert len(refused) >= 4, f"{len(refused)} of 6 refused while {peak} rendered at once"


# =============================================================================================== apisec-7

HUGE_ID_ROUTES: tuple[tuple[str, str], ...] = (
    ("GET", f"routing-rules/{HUGE_ID}"),
    ("DELETE", f"routing-rules/{HUGE_ID}"),
    ("GET", f"credential-allowlist/{HUGE_ID}"),
    ("DELETE", f"credential-allowlist/{HUGE_ID}"),
    ("DELETE", f"cache/rules/{HUGE_ID}"),
    ("GET", f"health/runs/{HUGE_ID}"),
    ("GET", f"health/runs/{HUGE_ID}/compare"),
    ("GET", f"health/runs/{HUGE_ID}/export"),
)


async def test_bounded_ids_answer_a_section13_error(api: Any) -> None:
    """Control (passes today): an area that bounds its id (`Path(ge=1, le=2**62)`) answers 422, not 500."""
    response = await api.get(f"audit/{HUGE_ID}")
    assert response.status_code == 422, response.text[:200]
    assert response.json()["error"]["code"] == "validation_failed"


@pytest.mark.xfail(
    strict=True,
    reason="finding apisec-7: integer path ids above 2**63 reach sqlite3 and answer the unhandled 500 (and an alert)",
)
async def test_huge_path_ids_are_refused_without_a_server_error(api: Any) -> None:
    failures: list[str] = []
    for method, path in HUGE_ID_ROUTES:
        response = await api.request(method, path, json={} if method == "DELETE" else None)
        if response.status_code >= 500:
            failures.append(f"{method} {path.split('/')[0]}: {response.status_code}")
    assert failures == [], "; ".join(failures)
