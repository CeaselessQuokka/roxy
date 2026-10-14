"""Final review, lens memory: what grows without a bound on the 909 MB server (two workers within MemoryHigh 420M).

What this is
    The reproductions of the memory lens findings (`.remake/final_review/find_memory.md`), regression tests since
    the final review fixed them. Each test builds the smallest real state that shows a per-process structure (a
    queue, a read, a held request) holding memory in proportion to something a caller controls, measured with
    `tracemalloc` on one process, and asserts the bound the fix must give it. The numbers in each docstring scale the
    measurement to the production defaults. memory-4 (both workers of a color recycling at once) runs real gunicorn
    masters, so its test lives beside the other gunicorn tests: `tests/multiprocess/test_worker_recycle_mp.py`.

Why it exists
    The units hold each color at MemoryHigh 420M and MemoryMax 500M (DESIGN.md section 0 and 15.7), sized from soaks
    of ordinary traffic with worker recycling. A structure whose size a caller drives (an attacker's bodies, a header
    value chosen per request) is outside that sizing, and on a box with no swap the kernel then kills a worker.

How it works
    Temporary databases from `tests/conftest.py` (`dbs`, `fake_clock`), the real recorder, read models and proxy
    router, and fakes shaped like `tests/unit/proxy/conftest.py` for the parts the measured path does not need.
    Memory is `tracemalloc` (Python allocations; SQLite's own page cache is not traced and is bounded by its
    `cache_size`), taken after `gc.collect()`.

What to read next
    `src/roxy/storage/batch.py`, `src/roxy/metrics/queries.py` (`_client_totals`), `src/roxy/proxy/router.py`
    (`build_request`, `refuse`), `src/roxy/cache/spread.py`, docs/PERFORMANCE.md "Memory per color".
"""

from __future__ import annotations

import asyncio
import gc
import json
import random
import string
import tracemalloc
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from starlette.applications import Starlette

from roxy.abuse.verdict import Refuse
from roxy.config import catalog
from roxy.core.client_ip import parse_cidrs
from roxy.core.clock import FakeClock
from roxy.core.middleware import build_middleware
from roxy.core.reasons import AuthClass, CacheState, Egress, Outcome, ReasonCode, Source
from roxy.metrics import queries
from roxy.metrics.capture import CaptureInput
from roxy.metrics.recorder import KIND_CAPTURES, MetricsRecorder, OutcomeEvent
from roxy.proxy.router import router
from roxy.storage.db import SharedStateUnavailable

MIB = 1024 * 1024
REPO = Path(__file__).resolve().parents[2]


class _Settings:
    """`get(key)` over the catalog defaults plus overrides, with a `version` (like `tests/unit/metrics/conftest.py`)."""

    def __init__(self, **overrides: Any) -> None:
        self.values: dict[str, Any] = catalog.defaults()
        self.values.update(overrides)
        self.version = 1

    def get(self, key: str) -> Any:
        return self.values[key]


def _traced_now() -> int:
    gc.collect()
    return tracemalloc.get_traced_memory()[0]


@pytest.fixture
def traced() -> Iterator[None]:
    tracemalloc.start()
    try:
        yield
    finally:
        tracemalloc.stop()


# ------------------------------------------------------------------------------------------------- memory-1


def _refused_event(clock: FakeClock, n: int) -> OutcomeEvent:
    return OutcomeEvent(
        at_ms=clock.now_ms(),
        request_id=f"01REVIEWMEMORY{n:012d}",
        endpoint_template="auth.roblox.com/v2/login",
        host="auth.roblox.com",
        method="POST",
        egress=Egress.NONE,
        outcome=Outcome.REFUSED,
        reason=ReasonCode.THROTTLE,
        status=429,
        source=Source.ROXY,
        cache_state=CacheState.NA,
        auth_class=AuthClass.ANON,
        caller_bytes_in=16 * 1024,
        caller_bytes_out=60,
        upstream_calls=0,
        upstream_bytes_in=0,
        upstream_bytes_out=0,
        latency_ms=1.0,
        queue_wait_ms=0.0,
        upstream_ms=0.0,
        client_ip=f"203.0.113.{n % 250 + 1}",
        place_id=None,
        user_agent="Roblox/WinInet",
        bypass=False,
        error=False,
    )


# Fixed (fixer data): the capture kind of the batch writer keeps at most the capture caps queued
# (`BatchWriter.register(keep_items=, keep_bytes=, weigh=)`).
async def test_memory_1_queued_captures_stay_within_the_capture_caps_while_metrics_db_is_unwritable(
    dbs: Any, fake_clock: FakeClock, monkeypatch: pytest.MonkeyPatch, traced: None
) -> None:
    """A refusal flood of POSTs with 16 KiB bodies while metrics.db cannot be written.

    Disk full is SQLITE_FULL, which `storage/db.py` reports as `SharedStateUnavailable`, so every flush puts its
    items back (`BatchWriter._requeue_kinds`) and the queue keeps them until `metrics_queue_max` (50,000 items)
    counts them full. Refusals are always captured (`CapturePolicy.wants`), and a capture row of a 16 KiB alphanumeric
    body is 12,676 compressed bytes (17.5 KiB traced per row): 50,000 of them are about 605 MiB of blobs, 835 MiB
    traced, per worker, against MemoryMax 500M for the whole color. Yet `write_captures` keeps at most
    `capture_max_records` captures and `capture_max_bytes` bytes on disk, pruning the rest the moment they are
    inserted, so every queued capture beyond those caps is memory spent on rows that can never be kept.

    Measured today (caps lowered to 50 captures and 256 KiB): all 600 captures stay queued after the failed flushes,
    10.8 MiB traced. The bound: at most `capture_max_records` captures queued and their memory near
    `capture_max_bytes`. SYS-METRICS-DROP makes it worse: on any drop it proposes doubling `metrics_queue_max` (risk
    "low", auto-apply bounds up to 100,000, high risk only past 200,000), a count whose bytes nothing estimates.
    """
    settings = _Settings(capture_max_records=50, capture_max_bytes=256 * 1024, capture_max_body=16 * 1024)
    recorder = MetricsRecorder(dbs, settings, fake_clock, rng=random.Random(7).random)

    async def disk_full(*_args: Any, **_kwargs: Any) -> Any:
        raise SharedStateUnavailable("metrics", "database or disk is full")

    monkeypatch.setattr(dbs.metrics, "write", disk_full)
    rng = random.Random(11)
    alphabet = (string.ascii_letters + string.digits).encode()
    before = _traced_now()
    sent = 600
    for n in range(sent):
        body = bytes(rng.choice(alphabet) for _ in range(16 * 1024))
        event = _refused_event(fake_clock, n)
        capture = CaptureInput(
            request_id=event.request_id,
            at_ms=event.at_ms,
            method="POST",
            url="auth.roblox.com/v2/login",
            request_headers={"content-type": "application/json"},
            request_body=body,
            response_headers=[("content-type", "application/json")],
            response_body=b'"Too many requests; please slow down."\n',
        )
        recorder.record_outcome(event, capture=capture)
        if n % 100 == 99:
            assert await recorder.captures.drain(30.0)
            await recorder.flush()  # metrics.db is full: everything goes back into the queue
    queued = recorder.batch.stats()["kinds"][KIND_CAPTURES]["queued"]
    held = _traced_now() - before
    print(f"\nqueued captures: {queued} of {sent}; traced memory held: {held / MIB:.1f} MiB")
    assert queued <= 50, f"{queued} captures queued in memory; the disk keeps at most 50 (capture_max_records)"
    assert held <= 4 * MIB, f"{held / MIB:.1f} MiB held by the recorder; the capture caps allow about 0.25 MiB"


# ------------------------------------------------------------------------------------------------- memory-2


def _fill_rotating_places(dbs: Any, now: int, per_minute: int) -> int:
    """One day of `client_minute` rows where every minute has `per_minute` places never seen before.

    What a caller sending a fresh `Roblox-Id` value with each request leaves behind: the recorder keeps up to 5,000
    new places a minute per worker (`MAX_CLIENTS_PER_MINUTE`) and the compaction caps each closed minute at 500 plus
    `other` (`max_caller_records`), so a day holds up to 720,000 distinct places, all kept.
    """
    start = now - 86_400
    rows = []
    for minute in range(1440):
        bucket = start - start % 60 + minute * 60
        for k in range(per_minute):
            rows.append((bucket, "place", f"{minute:04d}{k:03d}000000", 1, 1, 0, 0, "auth.roblox.com/v2/login"))
    dbs.metrics.write_sync(
        lambda conn: conn.executemany(
            "INSERT INTO client_minute (bucket_start, client_type, client_key, requests, refused, served, bytes, "
            "top_endpoint) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            rows,
        )
    )
    return len(rows)


# Fixed (fixer data): `queries._client_totals` streams the clients in key order and ranks them through a bounded
# heap, so a read holds the page it answers, never the window's clients.
def test_memory_2_a_top_ten_places_read_is_bounded_whatever_the_number_of_places(
    dbs: Any, fake_clock: FakeClock, traced: None
) -> None:
    """The Overview's "Top places" card asks for 10 rows of the selected range (`overview.build_breakdown`:
    `client_table_sync(conn, window, "place", page=Page(size=10))`), and so do the Clients page, its export, the
    health check, the LLM export and the insights rules (`client_rows_sync`, at most 10,000 rows). Every one of them
    goes through `queries._client_totals`, which `fetchall()`s one row per distinct client of the window and builds a
    dict per client before it sorts and cuts. A 24 hour range is minute aligned, so it reads only `client_minute`.

    `Roblox-Id` is free caller text (`activity.place_key`), counted for refused requests too (`_count_clients`). At
    70 new places a minute (about 1.2 requests a second) one day holds 100,800 distinct places and the read peaks at
    58.9 MiB traced; measured the same way at 360,000 places it peaks at 212 MiB and at 720,000 (the compaction's own
    cap, 500 kept a minute: one address at 10 requests a second, refused or not) at 424.5 MiB, for a page of 10
    rows: past MemoryMax 500M for the color once the worker's own 150 to 200 MiB is added, on every Overview load
    and on every insights evaluation on the leader. The bound asserted: a top-10 read peaks under 16 MiB.
    """
    now = int(fake_clock.now())
    count = _fill_rotating_places(dbs, now, per_minute=70)
    window = queries.resolve_window("24h", now=now)

    def read(conn: Any) -> tuple[int, int]:
        tracemalloc.reset_peak()
        start = tracemalloc.get_traced_memory()[0]
        result = queries.client_table_sync(conn, window, "place", now=now, page=queries.Page(size=10, sort="requests"))
        peak = tracemalloc.get_traced_memory()[1] - start
        return int(result["total"]), peak

    total, peak = dbs.metrics.read_sync(read)
    print(f"\n{count} place rows, {total} distinct places; top 10 read peak {peak / MIB:.1f} MiB")
    assert total == count
    assert peak < 16 * MIB, f"a top-10 places read peaked at {peak / MIB:.1f} MiB for {total:,} places"


# ------------------------------------------------------------------------------------------------- memory-3


class _Holds:
    """The test's side of the holds: `gate` ends them, `all_in` is set once `target` requests are being held."""

    def __init__(self) -> None:
        self.gate = asyncio.Event()
        self.all_in = asyncio.Event()
        self.target = 0
        self.held = 0

    def arrive(self) -> None:
        self.held += 1
        if self.target and self.held >= self.target:
            self.all_in.set()


class _HoldPlan:
    """A tarpit hold that lasts until the test releases it (the real one sleeps 8 to 20 s)."""

    def __init__(self, holds: _Holds) -> None:
        self.kind = "hold"
        self._holds = holds

    async def wait(self) -> None:
        self._holds.arrive()
        await self._holds.gate.wait()

    def release(self) -> None:
        return None


class _Tarpit:
    def __init__(self, holds: _Holds) -> None:
        self._holds = holds

    async def plan(self, category: str, req: Any, *, reason: str = "") -> _HoldPlan:
        del category, req, reason
        return _HoldPlan(self._holds)


class _Abuse:
    """Refuses every request as an auth attempt (`tarpit_on_auth_attempt` is on by default)."""

    def __init__(self, tarpit: _Tarpit) -> None:
        self.tarpit = tarpit

    async def evaluate(self, req: Any) -> Refuse:
        del req
        return Refuse(
            status=403,
            body="Requests that look like sign in attempts are not allowed.",
            reason=ReasonCode.SPAM,
            check="spam",
            tarpit_category="auth_attempt",
        )


class _Recorder:
    def __init__(self) -> None:
        self.events: list[Any] = []

    def record_outcome(self, event: Any) -> None:
        self.events.append(event.request_id)


class _NoSettings:
    def get(self, key: str) -> Any:
        raise KeyError(key)


async def test_memory_3_a_held_refusal_does_not_keep_the_callers_body(traced: None) -> None:
    """`ProxyFlow.build_request` reads the whole body of every POST, PUT, PATCH and DELETE before the abuse check
    (`await self.request.body()`, up to `max_body_bytes`, 2 MiB by default; nginx allows 2m). A refusal in a tarpit
    category (auth attempts, request filters, probes, bans and spam are on by default) is then held 8 to 20 s
    (`tarpit_min_seconds`, `tarpit_max_seconds`) by `ProxyFlow.refuse`, and the request, its Starlette `Request`
    (`_body`) and the `ProxyRequest` keep the body until the answer is sent. The tarpit cap is fleet wide
    (`tarpit_max_concurrent` 50, up to 500): 50 held 2 MiB bodies are 100 MiB, about all the headroom between the
    405 MiB a busy color settles at and MemoryMax 500M (docs/PERFORMANCE.md), and an abuser needs only one address
    (nginx allows 50 connections and 20 requests a second per address) to keep every slot full. Nothing in the hold
    needs the body: the capture keeps at most `capture_max_body` (16 KiB) of it.

    Measured: 8 held POSTs of 1 MiB (streamed in 64 KiB chunks, as uvicorn hands them over) hold 8.24 MiB traced,
    1,055 KiB each. The bound asserted: under 256 KiB per held request.
    """
    holds = _Holds()
    ctx = SimpleNamespace(
        settings=_NoSettings(),
        clock=FakeClock(),
        abuse=_Abuse(_Tarpit(holds)),
        cache=None,
        upstream=None,
        recorder=_Recorder(),
    )
    app = Starlette(
        routes=list(router.routes),
        middleware=build_middleware(trusted_cidrs=parse_cidrs("127.0.0.1/32,::1/128"), hops=1),
    )
    app.state.ctx = ctx
    size, chunk = 1024 * 1024, 64 * 1024

    async def body() -> AsyncIterator[bytes]:
        for _ in range(size // chunk):
            yield random.randbytes(chunk)

    transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 50000))
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver", timeout=60) as client:
        # Warm every lazy import and cache on the path once, then measure.
        holds.gate.set()
        warm = await client.post("/auth.roblox.com/v2/login", content=b"{}", headers={"content-type": "text/plain"})
        assert warm.status_code == 403
        holds.gate.clear()
        held = 8
        holds.held, holds.target = 0, held
        before = _traced_now()
        tasks = [
            asyncio.create_task(
                client.post("/auth.roblox.com/v2/login", content=body(), headers={"content-type": "text/plain"})
            )
            for _ in range(held)
        ]
        await asyncio.wait_for(holds.all_in.wait(), timeout=30)  # every request is in its tarpit hold
        during = _traced_now() - before
        holds.gate.set()
        answers = await asyncio.gather(*tasks)
    assert [answer.status_code for answer in answers] == [403] * held
    per_hold = during / held
    print(
        f"\n{held} held requests of {size // 1024} KiB: {during / MIB:.2f} MiB traced, {per_hold / 1024:.0f} KiB a hold"
    )
    assert per_hold < 256 * 1024, f"each held refusal keeps {per_hold / 1024:.0f} KiB (the body is {size // 1024} KiB)"


# ------------------------------------------------------------------------------------------------- memory-5


def test_memory_5_the_key_spread_read_is_bounded_in_bytes(dbs: Any, traced: None) -> None:
    """`providers_rules_cache_egress.spread` (CACHE-KEYSPLIT and CACHE-LOW-HIT, every 30 s on the leader) and
    `CacheService.key_spread` (the Cache page) read the newest `DEFAULT_MAX_ROWS` (100,000) content entries of
    cache.db with their whole `params_json` (`read_spread.spread_rows`, `SharedTier.spread_rows`) and decode every
    one into a tuple of parameter strings (`spread.rows_from_db`) while the raw rows are still alive. The grouping
    (`compute_spread`) only needs to tell at most `MAX_SPREAD_VALUES + 1` value signatures apart per parameter.

    A batch endpoint keyed by its id list is ordinary Roblox traffic (`thumbnails.roblox.com/v1/users/avatar-headshot
    ?userIds=<100 ids>`: about 1 KiB of query) and it is exactly the key split this diagnostic exists to find: every
    combination of ids is its own entry (`cache_max_entries` 200,000). Measured here: 20,000 such entries peak at
    61.0 MiB traced (3.2 KB a row); the 100,000 rows the read allows are about 305 MiB on the leader every 30 s (far
    past the 95 MiB between a busy color's 405 MiB and MemoryMax 500M), and a caller can make each query up to
    `max_url_length` (4,096 characters) long, about 4 times that. The bound asserted: under 16 MiB.
    """
    from roxy.cache.read_spread import spread_rows
    from roxy.cache.spread import rows_from_db

    rng = random.Random(5)
    now = 1_760_000_000
    rows = []
    for n in range(20_000):
        ids = ",".join(str(rng.randrange(10**8, 10**10)) for _ in range(100))
        params = json.dumps({"params": [["userIds", ids], ["size", "48x48"], ["format", "Png"]], "stripped": []})
        path = "/v1/users/avatar-headshot"
        rows.append(
            (f"e{n:08d}", f"GET thumbnails.roblox.com{path}?{n}", "GET", "thumbnails.roblox.com", path, params, 200,
             now, now + 3600, now + 7200, 3600, 2048)
        )  # fmt: skip
    dbs.cache.write_sync(
        lambda conn: conn.executemany(
            "INSERT INTO entries (id, key, method, host, path, params_json, status, stored_at, expires_at, "
            "stale_until, ttl, bytes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            rows,
        )
    )
    rows.clear()

    def read(conn: Any) -> tuple[int, int]:
        gc.collect()
        tracemalloc.reset_peak()
        start = tracemalloc.get_traced_memory()[0]
        decoded = rows_from_db(spread_rows(conn))
        peak = tracemalloc.get_traced_memory()[1] - start
        return len(decoded), peak

    count, peak = dbs.cache.read_sync(read)
    print(f"\nkey spread read of {count} entries peaked at {peak / MIB:.1f} MiB ({peak / max(1, count):.0f} B a row)")
    # A byte budget may cut the slice (16 MiB of parameter text is about 14,000 of these rows), but the read must
    # still see a useful part of it: a row cap alone low enough to pass the bound below (about 5,000 rows here) is
    # not a byte bound (queries up to max_url_length are 4 times longer) and fails this check (skeptic edit).
    assert 6_000 <= count <= 20_000, f"the key spread read decoded {count:,} of 20,000 entries"
    assert peak < 16 * MIB, f"the key spread read peaked at {peak / MIB:.1f} MiB for {count:,} cache entries"
