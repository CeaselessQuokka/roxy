"""Review round, lens mp: how long Roblox's answer waits for hot.db after the call (the effects write).

What this is
    A reproduction of finding mp-7 (fixed) with the real `UpstreamService` over migrated temporary databases
    and a real "lock holder" process. The fake egress plays Roblox: when the call arrives it asks the lock holder to
    take hot.db's write lock (`BEGIN IMMEDIATE`), waits until it holds it, then answers 429 with `Retry-After: 60`
    (or a 503). So the bucket reservation before the call succeeded, and hot.db is locked while the answer comes
    back: what a long prune batch, a backup or a stalled worker in another process does to a request in flight.

Why it exists
    The fix pass made every budgeted hot-path write a deadline from enqueue time (finding HOT-HOL) and moved the
    cache's stores and publishes behind the answer (CACHE-WAIT, SF-ORPHAN), recording the rule "answers no longer
    wait for cache.db or hot.db" (fix1_integrate.md, CHANGES items). UP-COOLDOWN-LOST made a 429 whose cooldown
    hot.db cannot record still answer 429 and keep the cooldown in memory; its test made hot.db READ-ONLY, which
    fails at once. With a LOCKED hot.db the same path waits: `UpstreamService._after_call` writes the call's effects
    (`apply_call_outcome`: cooldowns, breaker counts, the AIMD release) with `self.hot.write(...)` and no busy
    budget, so SQLite's full 5 s `busy_timeout` passes before `_local_effects` keeps the cooldown and the caller is
    answered. Every 429, 5xx, timeout and connect error that comes back while another process holds hot.db makes
    its caller (and, on a cache miss, every follower of that flight) wait 5 s more, and the first one opens the
    busy circuit for every write of the worker. The same unbudgeted write pattern is in the CSRF token store, the
    unused-slot refund and `CredentialManager.set_cooldown`.

How it works
    `_armed_lock` waits for `go`, takes the lock, sets `ready`, and keeps it until `release`. The test measures the
    time from Roblox's answer to the `fetch` result, and checks the result is still the right 429 (the
    UP-COOLDOWN-LOST fix itself holds). Fixed in the review round (findings mp-7, mp-8, mp-9): the writes after the
    call wait at most `HOT_SIDE_WRITE_BUDGET_MS`, a retry hot.db cannot pace is not made and Roblox's answer goes
    back, and a reservation canceled while its write runs gives back what it granted.

What to read next
    `roxy/upstream/service.py` (`_after_call`, `HOT_BUSY_TIMEOUT_MS`), `roxy/storage/db.py` (budgets and the busy
    circuit), tests/integration/test_review_c7_failure_modes.py (the read-only variant).
"""

from __future__ import annotations

import asyncio
import multiprocessing as mp
import sqlite3
import sys
import time
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest

from roxy.core.clock import SystemClock
from roxy.core.reasons import Egress, ReasonCode
from roxy.storage.db import DB_NAMES
from roxy.storage.migrate import migrate_paths

pytestmark = [
    pytest.mark.multiprocess,
    pytest.mark.skipif(sys.platform == "win32", reason="needs POSIX processes"),
]

CTX = mp.get_context("spawn")
ANSWER_BUDGET_S = 2.5
"""Generous: the reservation's own hot.db budget is 2 s (`HOT_BUSY_TIMEOUT_MS`) and the abuse write's 0.5 s."""


def _armed_lock(path: str, go: Any, ready: Any, release: Any) -> None:
    """Child process: once `go` is set, hold hot.db's write lock until `release` is set."""
    conn = sqlite3.connect(path, isolation_level=None, timeout=30)
    go.wait(60)
    conn.execute("BEGIN IMMEDIATE")
    ready.set()
    release.wait(60)
    conn.execute("ROLLBACK")
    conn.close()


@pytest.fixture
def paths(tmp_path: Path) -> dict[str, str]:
    files = {name: tmp_path / f"{name}.db" for name in DB_NAMES}
    migrate_paths(files)
    return {name: str(path) for name, path in files.items()}


@pytest.fixture
def procs() -> Iterator[list[Any]]:
    started: list[Any] = []
    yield started
    for proc in started:
        if proc.is_alive():
            proc.kill()
        proc.join(5)


@dataclass
class _Reply:
    status: int
    headers: httpx.Headers
    body: bytes
    elapsed_ms: float = 5.0
    bytes_out: int = 100
    bytes_in: int = 100
    egress: Egress = Egress.DIRECT
    session_id: str | None = None
    http_version: str = "HTTP/2"


class _LockingRoblox:
    """`ctx.egress`: direct only. The first call makes another process lock hot.db, then answers `status`."""

    def __init__(self, go: Any, ready: Any, status: int) -> None:
        self.go, self.ready, self.status = go, ready, status
        self.credential = None
        self.rotator = None
        self.headers = None
        self.calls = 0
        self.answered_at = 0.0

    def is_enabled(self, egress: Egress, purpose: str | None = None) -> tuple[bool, str]:
        return egress is Egress.DIRECT, ""

    async def send(self, egress: Egress, out: Any) -> _Reply:
        self.calls += 1
        self.go.set()
        assert await asyncio.to_thread(self.ready.wait, 20), "the lock holder never took hot.db's write lock"
        self.answered_at = time.monotonic()
        headers = {"content-type": "application/json"}
        if self.status == 429:
            headers["retry-after"] = "60"
        return _Reply(self.status, httpx.Headers(headers), b'{"errors":[{"code":0}]}')


class _NullRecorder:
    def record_upstream_429(self, **row: Any) -> None:
        pass

    def record_event(self, *args: Any, **kwargs: Any) -> None:
        pass

    def record_internal_call(self, purpose: str, **row: Any) -> None:
        pass

    def record_retry(self, **row: Any) -> None:
        pass


@dataclass
class _UpReq:
    deadline_at: float
    request_id: str = "rr-mp"
    host: str = "games.roblox.com"
    path: str = "/v1/games"
    method: str = "GET"
    query: Sequence[tuple[str, str]] = field(default_factory=lambda: [("universeIds", "77")])
    body: bytes = b""
    content_type: str | None = None
    headers: Mapping[str, str] = field(default_factory=dict)
    template: str = "games.roblox.com/v1/games"


@pytest.mark.parametrize("status", [429, 503])
async def test_rr_mp_roblox_answer_never_waits_out_a_locked_hot_db(
    status: int, paths: dict[str, str], procs: list[Any]
) -> None:
    from roxy.config.runtime import load_runtime_settings
    from roxy.rules.store import load_rules_store
    from roxy.storage.db import open_databases
    from roxy.upstream.queue import Priority
    from roxy.upstream.service import UpstreamService

    go, ready, release = CTX.Event(), CTX.Event(), CTX.Event()
    holder = CTX.Process(target=_armed_lock, args=(paths["hot"], go, ready, release), daemon=True)
    holder.start()
    procs.append(holder)
    env = {f"ROXY_{name.upper()}_DB": path for name, path in paths.items()}
    env["ROXY_STATE_DIR"] = str(Path(paths["hot"]).parent)
    dbs = open_databases(env)
    clock = SystemClock()
    roblox = _LockingRoblox(go, ready, status)
    ctx = SimpleNamespace(
        clock=clock,
        dbs=dbs,
        settings=await load_runtime_settings(dbs, clock),
        rules=await load_rules_store(dbs, clock),
        egress=roblox,
        recorder=_NullRecorder(),
        worker_id="rr-mp",
        tasks=None,
    )
    service = UpstreamService(ctx)
    try:
        result = await service.fetch(
            _UpReq(deadline_at=time.monotonic() + 60), priority=Priority.INTERACTIVE, stale_available=False
        )
        waited = time.monotonic() - roblox.answered_at
    finally:
        release.set()
        await dbs.close_all()
    print(f"\nRoblox answered {status}; the caller got {result.status} {result.reason.value} {waited:.2f} s later")
    assert roblox.calls >= 1
    if status == 429:
        # The UP-COOLDOWN-LOST fix holds: Roblox's own 429 and Retry-After, never `degraded`.
        assert (result.status, result.reason, result.retry_after_s) == (429, ReasonCode.UPSTREAM_COOLDOWN, 60)
    assert waited < ANSWER_BUDGET_S, f"the answer waited {waited:.2f} s for hot.db after Roblox answered"


# ==================================== mp-8: a retry that cannot reserve replaces Roblox's answer with `degraded`


class _ReadOnlyRoblox:
    """`ctx.egress`: direct only. Every call answers 503; the first one also makes hot.db refuse writes (the
    writer connection turns `query_only`, SQLITE_READONLY: a disk remounted read-only, a full disk)."""

    def __init__(self, hot: Any) -> None:
        self.hot = hot
        self.credential = None
        self.rotator = None
        self.headers = None
        self.calls = 0

    def is_enabled(self, egress: Egress, purpose: str | None = None) -> tuple[bool, str]:
        return egress is Egress.DIRECT, ""

    async def send(self, egress: Egress, out: Any) -> _Reply:
        self.calls += 1
        writer = next(thread for thread in self.hot._threads if thread.role == "writer")
        assert writer._conn is not None, "the reservation opened the writer connection"
        writer._conn.execute("PRAGMA query_only=1")
        return _Reply(503, httpx.Headers({"content-type": "application/json"}), b'{"errors":[{"code":0}]}')


async def test_rr_mp_a_failed_retry_reservation_keeps_robloxs_answer(paths: dict[str, str]) -> None:
    """Plan 7.9 and 7.13, D4 ("callers see Roblox's real status"), and the rule UP-COOLDOWN-LOST set for a 429:
    when Roblox answered, the caller gets Roblox's answer, never `degraded`. Roblox answers 503 while hot.db stops
    taking writes. The 5xx is retryable, so `_run` routes a retry; its reservation raises
    `SharedStateUnavailable`, which escapes `_run`, and `_guarded` answers the `degraded` row (503, Retry-After
    10, Roxy's busy text) instead of `state.last_failure`, the `upstream_5xx` answer Roblox actually gave."""
    from roxy.config.runtime import load_runtime_settings
    from roxy.rules.store import load_rules_store
    from roxy.storage.db import open_databases
    from roxy.upstream.queue import Priority
    from roxy.upstream.service import UpstreamService

    env = {f"ROXY_{name.upper()}_DB": path for name, path in paths.items()}
    env["ROXY_STATE_DIR"] = str(Path(paths["hot"]).parent)
    dbs = open_databases(env)
    clock = SystemClock()
    roblox = _ReadOnlyRoblox(dbs.hot)
    ctx = SimpleNamespace(
        clock=clock,
        dbs=dbs,
        settings=await load_runtime_settings(dbs, clock),
        rules=await load_rules_store(dbs, clock),
        egress=roblox,
        recorder=_NullRecorder(),
        worker_id="rr-mp",
        tasks=None,
    )
    service = UpstreamService(ctx)
    try:
        result = await service.fetch(
            _UpReq(deadline_at=time.monotonic() + 60), priority=Priority.INTERACTIVE, stale_available=False
        )
    finally:
        await dbs.close_all()
    print(f"\nRoblox answered 503 ({roblox.calls} call); the caller got {result.status} {result.reason.value}")
    assert roblox.calls == 1, "the retry never reached Roblox (hot.db could not pace it)"
    assert result.reason is not ReasonCode.DEGRADED, "Roblox answered, yet the caller was told shared state is down"
    assert (result.reason, result.upstream_status) == (ReasonCode.UPSTREAM_5XX, 503)


# =============================== mp-9: a request canceled during its reservation write keeps the slot forever


class _NeverCalledRoblox:
    """`ctx.egress`: direct only; records calls (the test cancels the request before any call)."""

    def __init__(self) -> None:
        self.credential = None
        self.rotator = None
        self.headers = None
        self.calls = 0

    def is_enabled(self, egress: Egress, purpose: str | None = None) -> tuple[bool, str]:
        return egress is Egress.DIRECT, ""

    async def send(self, egress: Egress, out: Any) -> _Reply:
        self.calls += 1
        return _Reply(200, httpx.Headers({"content-type": "application/json"}), b"{}")


@pytest.mark.parametrize("lock_ends", ["after_the_request_ended", "while_the_request_is_canceled"])
async def test_rr_mp_a_reservation_canceled_mid_write_is_refunded(
    lock_ends: str, paths: dict[str, str], procs: list[Any]
) -> None:
    """Plan 7.3: "If it is canceled before t (caller disconnected, deadline hit), it refunds by subtracting
    interval_b from each TAT it advanced" (the lens rule "reservations never leak"). The refund existed for a
    request canceled while it WAITS for its slot (`_attempt`), not for one canceled while the reservation write
    itself runs: `Database.write` lets a started job finish (commit), the coroutine gets `CancelledError`, and the
    `Grant` it would have refunded is never seen. The deadline middleware (`asyncio.timeout`) and uvicorn's
    shutdown cancel exactly like this, and the reservation write takes up to its 2 s budget while another process
    holds hot.db. The same transaction also takes a half-open breaker's fleet-wide probe lease (held until its TTL,
    `request_timeout + 5` s, so no worker probes) and, for a cache miss, the single-flight lease (followers in
    other workers wait for the owner deadline). Here the endpoint bucket runs 6 per minute with burst 1, so a
    leaked slot is a 10 s gap in which no worker may call that endpoint, for a request that never called it.

    Fixed in the review round (`UpstreamService._reserve_shielded`): the canceled request waits for its write and
    gives back what it granted before the cancellation goes on. `while_the_request_is_canceled` ends the lock right
    after the cancel, so the started write commits a grant that must be refunded; `after_the_request_ended` keeps
    the lock until the request is gone, so the write runs out of its budget and grants nothing."""
    from roxy.config.runtime import bump_config_version, load_runtime_settings
    from roxy.rules.store import load_rules_store
    from roxy.storage.db import open_databases
    from roxy.upstream.queue import Priority
    from roxy.upstream.service import UpstreamService

    control = sqlite3.connect(paths["control"], isolation_level=None)
    for key, value in {"endpoint_bucket_default_per_min": 6, "endpoint_bucket_default_burst": 1}.items():
        control.execute(
            "INSERT INTO settings (key, value_json, updated_at, updated_by) VALUES (?, ?, ?, 'rr-mp')",
            (key, str(value), int(time.time())),
        )
    control.execute("BEGIN IMMEDIATE")
    bump_config_version(control, int(time.time()))
    control.execute("COMMIT")
    control.close()

    go, ready, release = CTX.Event(), CTX.Event(), CTX.Event()
    holder = CTX.Process(target=_armed_lock, args=(paths["hot"], go, ready, release), daemon=True)
    holder.start()
    procs.append(holder)
    env = {f"ROXY_{name.upper()}_DB": path for name, path in paths.items()}
    env["ROXY_STATE_DIR"] = str(Path(paths["hot"]).parent)
    dbs = open_databases(env)
    clock = SystemClock()
    roblox = _NeverCalledRoblox()
    ctx = SimpleNamespace(
        clock=clock,
        dbs=dbs,
        settings=await load_runtime_settings(dbs, clock),
        rules=await load_rules_store(dbs, clock),
        egress=roblox,
        recorder=_NullRecorder(),
        worker_id="rr-mp",
        tasks=None,
    )
    service = UpstreamService(ctx)
    try:
        go.set()
        assert await asyncio.to_thread(ready.wait, 20), "the lock holder never took hot.db's write lock"
        request = asyncio.ensure_future(
            service.fetch(
                _UpReq(deadline_at=time.monotonic() + 60), priority=Priority.INTERACTIVE, stale_available=False
            )
        )
        await asyncio.sleep(0.5)  # the reservation write is running: waiting for the lock inside its 2 s budget
        request.cancel()  # the deadline (asyncio.timeout) or a shutdown cancels the request here
        if lock_ends == "while_the_request_is_canceled":
            release.set()  # the lock ends now; the reservation job that already started gets it and commits
        with pytest.raises(asyncio.CancelledError):
            await request
        release.set()
        await dbs.hot.write(lambda conn: None)  # queued behind every earlier job: they have finished
        now_ms = clock.now_ms()
        rows = await dbs.hot.read(
            lambda conn: conn.execute("SELECT bucket_key, tat_ms FROM upstream_bucket").fetchall()
        )
    finally:
        release.set()
        await dbs.close_all()
    held = {str(key): round((float(tat) - now_ms) / 1000, 1) for key, tat in rows if float(tat) > now_ms + 1000}
    print(f"\ncalls {roblox.calls}; bucket slots still held by the canceled request (seconds ahead): {held}")
    assert roblox.calls == 0
    assert held == {}, f"a canceled request that never called Roblox still holds bucket slots: {held}"
    if lock_ends == "while_the_request_is_canceled":
        assert rows, "the reservation never committed, so this variant did not exercise the refund"
