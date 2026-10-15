"""Review round 3 (lens apisec): bounds on expensive admin API work, and path ids out of SQLite's range.

What this is
    Tests for three findings about what one signed-in session can make a 1 GB server do (strict xfails until
    review round 3 fixed all three; they now pin the fixed behavior):
      * apisec-5 (fixed): `POST /data/backups` ("Back up now") copied control.db and metrics.db with `VACUUM INTO`
        every time it was called, never counting the snapshots already in the folder, and nothing stopped a second
        call while the first copied, so repeated calls filled the state volume until the `file_retention` job ran.
        Now the copies count against `snapshots_max_bytes` with the folder, Back up now replaces its own oldest
        copies to make room (a copy that still does not fit is skipped, and since review round 4, finding
        secfix-4, the root backup is asked anyway) and takes the data operation lease.
      * apisec-6 (fixed): every table route's `format=csv|json` download read up to 50,000 rows into memory and
        rendered the whole file on a worker thread, with no limit on how many ran at once. Now a worker builds at
        most `common.MAX_CONCURRENT_EXPORTS` (2) downloads at once, from the first read to the last byte sent
        (the `format` dependency holds a slot), and answers 429 `rate_limited` beyond, as the LLM export does.
      * apisec-7 (fixed): an integer path id larger than SQLite's 64-bit range (`/routing-rules/{rule_id}`,
        `/credential-allowlist/{row_id}`, `/cache/rules/{rule_id}`, `/health/runs/{run_id}`) reached the database
        unbounded; sqlite3 raised `OverflowError`, the answer was the unhandled 500 and every such request fired the
        owner's "Roxy Error" alert. They are `common.RowId` now (`Path(ge=1, le=2**62)`, 422), and an
        `OverflowError` anywhere in an area route is a 422 (`common.service_error`).

Why it exists
    Plan P9 (every queue, table and file bounded), 6.6 and 6.10 (snapshots capped), the 1 GB memory budget of
    DESIGN.md section 0, and DESIGN.md 13 ("nothing a service refuses turns into a 500").

How it works
    Backups: `snapshots_max_bytes` is set to the whole MiB just above one backup's size, then backups are made
    one after another; the folder must never hold more than the cap. Exports: `common.ExportBuilder.add` (every
    download renders its rows through it, page by page) is wrapped so each render waits on an event, six downloads
    are started at once and the number rendering together is counted. Ids: each route is called with a 26-digit id
    and must answer a section 13 error below 500.

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
from roxy.config import audit
from roxy.storage.db import SharedStateUnavailable

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


async def test_back_up_now_keeps_the_snapshot_folder_within_its_cap(api: Any, api_app: Any) -> None:
    """apisec-5 (fixed): Back up now counts the folder against `snapshots_max_bytes` and replaces its own oldest
    copies (`data.backup_plan`), else skips the copy that does not fit; one backup or reset runs at a time."""
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


async def test_table_exports_are_bounded_per_worker(api: Any, api_app: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    release = threading.Event()
    lock = threading.Lock()
    state = {"now": 0, "peak": 0}
    real = common.ExportBuilder.add

    def held_add(self: Any, items: Any) -> Any:
        with lock:
            state["now"] += 1
            state["peak"] = max(state["peak"], state["now"])
        try:
            release.wait(timeout=10)
            return real(self, items)
        finally:
            with lock:
                state["now"] -= 1

    monkeypatch.setattr(common.ExportBuilder, "add", held_add)
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
    assert peak <= common.MAX_CONCURRENT_EXPORTS, f"{peak} exports rendered at once; {len(refused)} of 6 refused"
    assert peak == 2, peak  # the bound is a bound, not a queue of one: two downloads do build side by side
    assert len(refused) == 4, f"{len(refused)} of 6 refused while {peak} rendered at once"
    for response in refused:
        assert response.json()["error"]["code"] == "rate_limited"
        assert response.headers["retry-after"] == str(common.EXPORT_BUSY_RETRY_S)
    assert common.export_slots(api_app.app).busy == 0  # every slot is given back once its file is sent
    again = await api.get("audit", params={"format": "json"})
    assert again.status_code == 200, again.text[:200]


async def test_a_refused_download_gives_its_slot_back(api: Any, api_app: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """A download that ends in an error (here the audit row cannot be written: 503, no file) frees its slot too."""

    def busy(*_args: Any, **_kwargs: Any) -> int:
        raise SharedStateUnavailable("control", "simulated lock")

    monkeypatch.setattr(audit, "record", busy)
    for _ in range(common.MAX_CONCURRENT_EXPORTS + 2):
        response = await api.get("audit", params={"format": "csv"})
        assert response.status_code == 503, response.text[:200]
        assert response.headers.get("content-disposition") is None
    assert common.export_slots(api_app.app).busy == 0


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


async def test_huge_path_ids_are_refused_without_a_server_error(api: Any) -> None:
    failures: list[str] = []
    for method, path in HUGE_ID_ROUTES:
        response = await api.request(method, path, json={} if method == "DELETE" else None)
        if response.status_code >= 500:
            failures.append(f"{method} {path.split('/')[0]}: {response.status_code}")
        elif (response.status_code, response.json()["error"]["code"]) != (422, "validation_failed"):
            failures.append(f"{method} {path}: {response.status_code} {response.text[:120]}")
    assert failures == [], "; ".join(failures)
    compare = await api.get("health/runs/1/compare", params={"with": HUGE_ID})  # the query id is bounded too
    assert compare.status_code == 422, compare.text[:200]


async def test_an_overflow_in_an_area_route_is_a_422_not_a_500(api: Any, api_app: Any) -> None:
    """The safety net behind `common.RowId`: an `OverflowError` (sqlite3 binding a too-large number) that reaches
    an area route's handler is the caller's mistake, never a 500 with an alert."""
    router = common.area_router("zzoverflow")

    @router.get("/x")
    async def overflow(_admin: common.AdminSession) -> dict[str, Any]:
        raise OverflowError("Python int too large to convert to SQLite INTEGER")

    api_app.include(build_api_router_for(router))
    response = await api.get("zzoverflow/x")
    assert response.status_code == 422, response.text[:200]
    assert response.json()["error"] == {"code": "validation_failed", "message": common.TOO_LARGE_MESSAGE, "fields": {}}


def build_api_router_for(area: Any) -> Any:
    """`area` under `/admin/api/v1`, as `roxy.admin.api` mounts a module's router."""
    from fastapi import APIRouter

    outer = APIRouter(prefix=common.API_PREFIX)
    outer.include_router(area)
    return outer
