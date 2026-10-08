"""Ingress review, resource exhaustion lens: what one caller can make Roxy hold, store or loop over (plan 9.12, P9).

What this is
    Probes for the size limits (`core/middleware.py SizeLimitMiddleware`, plan 9.12), for every in-memory map a
    caller can add keys to on the request path (abuse, spam, bot, tarpit, ban hits, single-flight, metrics
    vocabulary), for the shared tables a caller can add rows to (`hot.db spam_windows`), and for tarpit slot leaks
    (a hold canceled by the deadline, a drip whose client went away).

Why it exists
    Plan P9: every map, queue, table and file is bounded, and the bound must hold whatever a caller sends. A map
    keyed by a caller-chosen value (a header, a path, a place id) with no cap is a memory or disk leak an attacker
    can drive at line rate. A tarpit slot that is not released shrinks the fleet-wide hold cap until the lease
    expires.

How it works
    Size limits run through the real middleware stack and proxy route (`ingress_support.make_proxy_app`) with
    hand-built ASGI messages, counting how many body chunks the app pulled. Map bounds feed each structure far more
    distinct keys than its cap. Table growth counts rows after one flush. Tarpit probes use the real abuse
    pipeline and hot.db leases, with a sleep that never returns (to cancel a hold) or a client that disconnects.

What to read next
    `roxy/core/middleware.py`, `roxy/abuse/spam.py`, `roxy/abuse/tarpit.py`, then `test_ingress_refusal_order.py`.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any

import pytest
from ingress_support import CLIENT_IP, CatalogSettings, make_proxy_app, raw_asgi_request

from roxy.abuse.bans import BanHits
from roxy.abuse.bot import ClientTracker
from roxy.abuse.limiter import MemoryRowStore
from roxy.abuse.pipeline import AbusePipeline
from roxy.abuse.spam import MAX_SUBJECTS, SpamDetectors
from roxy.abuse.tarpit import MAX_IP_RECORDS, MAX_REASON_RECORDS, TarpitStats
from roxy.core.clock import FakeClock
from roxy.core.reasons import ReasonCode
from roxy.metrics.templating import OTHER, VocabularyGate
from roxy.proxy import respond
from roxy.rules.store import RulesSnapshot
from roxy.upstream.queue import Priority, WaitQueue
from roxy.upstream.singleflight import FlightOutcome, FlightStart, OutcomeKind, SingleFlight

# --- size limits through the real stack ------------------------------------------------------------------------------


class RecordingCache:
    """A cache stand-in that records what reached it (the proxy would fetch from here)."""

    def __init__(self) -> None:
        self.served: list[Any] = []

    async def peek(self, req: Any) -> Any:
        return None

    async def serve(self, req: Any, peek: Any) -> Any:
        self.served.append(req)
        return respond.ProxyResult(reason=ReasonCode.UPSTREAM_OK, status=200, body=b"SERVED")


class AllowAll:
    tarpit = None

    async def evaluate(self, req: Any) -> Any:
        return SimpleNamespace(headers={}, serve_throttled_from_cache=False)


@pytest.fixture
def allow_app() -> tuple[Any, RecordingCache]:
    cache = RecordingCache()
    ctx = SimpleNamespace(
        settings=CatalogSettings(), clock=FakeClock(), abuse=AllowAll(), cache=cache, upstream=None, recorder=None
    )
    return make_proxy_app(ctx), cache


async def test_header_count_over_the_limit_is_431(allow_app: tuple[Any, RecordingCache]) -> None:
    app, cache = allow_app
    headers = [(b"host", b"testserver")] + [(f"x-h{i}".encode(), b"1") for i in range(100)]
    status, _, _, stats = await raw_asgi_request(app, b"/games.roblox.com/v1/games", headers=headers)
    assert status == 431
    assert stats["chunks_read"] == 0
    assert cache.served == []


async def test_one_oversized_header_is_431(allow_app: tuple[Any, RecordingCache]) -> None:
    app, cache = allow_app
    headers = [(b"host", b"testserver"), (b"user-agent", b"a" * (8 * 1024))]
    status, _, _, _ = await raw_asgi_request(app, b"/games.roblox.com/v1/games", headers=headers)
    assert status == 431
    assert cache.served == []


async def test_long_url_is_414_before_parsing(allow_app: tuple[Any, RecordingCache]) -> None:
    app, cache = allow_app
    status, _, _, _ = await raw_asgi_request(
        app, b"/games.roblox.com/v1/games", query=b"a=" + b"1" * 4096, headers=[(b"host", b"testserver")]
    )
    assert status == 414
    assert cache.served == []


async def test_declared_oversized_body_is_refused_unread(allow_app: tuple[Any, RecordingCache]) -> None:
    app, cache = allow_app
    headers = [(b"host", b"testserver"), (b"content-length", str(2 * 1024 * 1024 + 1).encode())]
    status, _, _, stats = await raw_asgi_request(
        app, b"/users.roblox.com/v1/users", method="POST", headers=headers, body_chunks=[b"x" * 1024]
    )
    assert status == 413
    assert stats["chunks_read"] == 0
    assert cache.served == []


async def test_streamed_oversized_body_stops_being_read_at_the_limit(allow_app: tuple[Any, RecordingCache]) -> None:
    """No Content-Length (chunked): reading stops one chunk past `max_body_bytes`, never at the end of the stream."""
    app, cache = allow_app
    chunk = b"x" * (64 * 1024)
    status, _, _, stats = await raw_asgi_request(
        app,
        b"/users.roblox.com/v1/users",
        method="POST",
        headers=[(b"host", b"testserver")],
        body_chunks=[chunk] * 200,  # 12.5 MiB offered
    )
    assert status == 413
    assert stats["chunks_read"] == 2 * 1024 * 1024 // len(chunk) + 1
    assert cache.served == []


async def test_get_body_is_never_read(allow_app: tuple[Any, RecordingCache]) -> None:
    """The router reads a body only for methods that forward one; a GET body is neither buffered nor sent."""
    app, cache = allow_app
    status, _, _, stats = await raw_asgi_request(
        app, b"/games.roblox.com/v1/games", headers=[(b"host", b"testserver")], body_chunks=[b"x" * 1024] * 50
    )
    assert status == 200
    assert stats["chunks_read"] == 0
    assert cache.served[0].body == b""


async def test_a_slow_body_is_cut_off_by_the_request_deadline() -> None:
    """A client that never finishes its body holds a worker slot only until `request_deadline_s` (504)."""
    cache = RecordingCache()
    ctx = SimpleNamespace(
        settings=CatalogSettings({"request_deadline_s": 1}),
        clock=FakeClock(),
        abuse=AllowAll(),
        cache=cache,
        upstream=None,
        recorder=None,
    )
    app = make_proxy_app(ctx)
    status, _, _, stats = await asyncio.wait_for(
        raw_asgi_request(
            app,
            b"/users.roblox.com/v1/users",
            method="POST",
            headers=[(b"host", b"testserver")],
            body_chunks=[b"{"],
            stall_after_chunks=True,
        ),
        timeout=10,
    )
    assert status == 504
    assert stats["chunks_read"] == 1
    assert cache.served == []


def test_upstream_wait_queue_is_bounded() -> None:
    queue = WaitQueue(3)
    tickets = [queue.enter(Priority.INTERACTIVE) for _ in range(10)]
    assert sum(ticket is not None for ticket in tickets) == 3
    assert len(queue) == 3
    assert queue.refused == 7


async def test_thousand_query_fields_is_unsafe_not_a_crash(allow_app: tuple[Any, RecordingCache]) -> None:
    app, cache = allow_app
    query = b"&".join(b"a" for _ in range(1001))  # 2001 bytes, under max_url_length
    status, _, body, _ = await raw_asgi_request(
        app, b"/games.roblox.com/v1/games", query=query, headers=[(b"host", b"testserver")]
    )
    assert status == 404
    assert body == b'"Invalid URL"\n'
    assert cache.served == []


# --- maps a caller can add keys to ------------------------------------------------------------------------------------


def test_tarpit_stats_tables_are_bounded() -> None:
    stats = TarpitStats()
    for n in range(10_000):
        stats.record(
            category="probe", reason=f"r{n}", ip=f"198.51.100.{n % 250}:{n}", held_s=1.0, skipped=False, gap_s=0, at=n
        )
    assert len(stats.ips) <= MAX_IP_RECORDS
    assert len(stats.reasons) <= MAX_REASON_RECORDS


def test_ban_hit_buffer_is_bounded() -> None:
    hits = BanHits(max_pending=100)
    for ban_id in range(10_000):
        hits.record(ban_id, 0)
    assert len(hits) == 100
    assert hits.dropped == 9_900


def test_bot_client_tracker_is_bounded() -> None:
    tracker = ClientTracker(max_clients=50)
    for n in range(5_000):
        tracker.observe(f"key{n}", now=float(n), monotonic=float(n), refused=False, probe=False, query_fp=n)
    assert len(tracker._clients) <= 50


def test_degraded_memory_limiter_is_bounded() -> None:
    store: MemoryRowStore[int] = MemoryRowStore(max_rows=100)
    for n in range(10_000):
        store.put(f"k{n}", n)
    assert len(store) == 100


def test_spam_pending_subjects_are_bounded_per_flush(fake_clock: FakeClock) -> None:
    spam = SpamDetectors(CatalogSettings(), None, fake_clock)
    for n in range(MAX_SUBJECTS + 5_000):
        spam.observe(
            limit_key=CLIENT_IP,
            place_id=f"p{n}",
            template="games.roblox.com/v1/games",
            path="/v1/games",
            query=[],
            user_agent=f"ua{n}",
            refused=False,
            probe=False,
            auth=False,
            game_server=False,
            bypass=False,
        )
    assert spam.pending_subjects() <= MAX_SUBJECTS


def test_endpoint_template_vocabulary_is_bounded() -> None:
    gate = VocabularyGate(limit=10)
    names = {gate.admit(f"games.roblox.com/v1/x{n}") for n in range(1_000)}
    assert len(gate) == 10
    assert OTHER in names


async def test_single_flight_table_is_bounded(dbs: Any) -> None:
    """Distinct keys in flight at once never exceed `max_flights`; beyond it a caller fetches solo."""
    flights = SingleFlight(dbs.hot, FakeClock(), "w1", max_flights=2)
    gate = asyncio.Event()
    peak = 0

    async def fetch(start: FlightStart) -> tuple[None, FlightOutcome]:
        nonlocal peak
        peak = max(peak, len(flights._flights))
        await gate.wait()
        return None, FlightOutcome(OutcomeKind.NOSTORE)

    tasks = [asyncio.create_task(flights.run(f"key{n}", fetch, owner_deadline_s=5.0, wait_s=1.0)) for n in range(12)]
    for _ in range(100):
        await asyncio.sleep(0.01)
    assert len(flights._flights) <= 2
    gate.set()
    await asyncio.gather(*tasks)
    assert peak <= 2
    assert len(flights._flights) == 0


# --- shared tables a caller can add rows to ---------------------------------------------------------------------------


@pytest.mark.xfail(
    strict=True,
    reason=(
        "ingress finding: abuse/spam.py keys spam_windows rows by caller-chosen values (Roblox-Id place ids, the "
        "User-Agent hash per template, path-derived templates) for every request, refused ones included; rows are "
        "pruned only after 24 h idle and nothing caps the count, so one client adds rows at request rate"
    ),
)
async def test_one_client_cannot_grow_spam_windows_without_bound(dbs: Any, fake_clock: FakeClock) -> None:
    spam = SpamDetectors(CatalogSettings(), dbs.hot, fake_clock)
    for n in range(1_000):
        spam.observe(
            limit_key=CLIENT_IP,
            place_id=f"{1_000_000 + n}",
            template="games.roblox.com/v1/games",
            path="/v1/games",
            query=[],
            user_agent=f"Roblox/WinInet {n}",
            refused=True,  # already refused (flood): still observed
            probe=False,
            auth=False,
            game_server=False,
            bypass=False,
        )
    await spam.flush()
    rows = dbs.hot.read_sync(lambda conn: conn.execute("SELECT count(*) FROM spam_windows").fetchone()[0])
    assert rows <= 64, f"one client created {rows} spam_windows rows in one flush"


# --- tarpit slots -----------------------------------------------------------------------------------------------------


class NeverEnding:
    """A tarpit sleep that never returns by itself (the hold only ends by cancellation)."""

    def __init__(self) -> None:
        self.entered = asyncio.Event()

    async def __call__(self, seconds: float) -> None:
        self.entered.set()
        await asyncio.Event().wait()


class AdvancingSleep:
    """A tarpit sleep that returns at once and moves the fake clock (drip ticks)."""

    def __init__(self, clock: FakeClock) -> None:
        self.clock = clock

    async def __call__(self, seconds: float) -> None:
        self.clock.advance(seconds)
        await asyncio.sleep(0)


def tarpit_app(dbs: Any, clock: FakeClock, sleep: Any, **overrides: Any) -> tuple[Any, AbusePipeline]:
    settings = CatalogSettings({"tarpit_enabled": 1, "tarpit_on_probe": 1, **overrides})
    pipeline = AbusePipeline(
        settings=settings,
        rules=RulesSnapshot.empty(),
        hot_db=dbs.hot,
        control_db=dbs.control,
        clock=clock,
        tarpit_sleep=sleep,
        monotonic=clock.monotonic,
    )
    ctx = SimpleNamespace(settings=settings, clock=clock, abuse=pipeline, cache=None, upstream=None, recorder=None)
    return make_proxy_app(ctx), pipeline


PROBE = b"/evil.example/wp-login.php"
HEADERS = [(b"host", b"testserver"), (b"x-forwarded-for", CLIENT_IP.encode())]


async def test_a_hold_canceled_by_the_deadline_releases_its_slot(dbs: Any, fake_clock: FakeClock) -> None:
    sleep = NeverEnding()
    app, pipeline = tarpit_app(dbs, fake_clock, sleep)
    task = asyncio.create_task(raw_asgi_request(app, PROBE, headers=HEADERS))
    await asyncio.wait_for(sleep.entered.wait(), timeout=5)
    assert await pipeline.tarpit.active_holds() == 1
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert await pipeline.tarpit.active_holds() == 0


async def test_a_drip_whose_client_went_away_releases_its_slot(dbs: Any, fake_clock: FakeClock) -> None:
    app, pipeline = tarpit_app(
        dbs, fake_clock, AdvancingSleep(fake_clock), tarpit_default_type="drip", tarpit_drip_interval_ms=100
    )
    status, headers, _body, _ = await raw_asgi_request(app, PROBE, headers=HEADERS, disconnect_after_first_body=True)
    assert status == 404
    assert headers.get(b"x-accel-buffering") == b"no"
    assert await pipeline.tarpit.active_holds() == 0


async def test_holds_never_exceed_the_fleet_cap_and_all_slots_come_back(dbs: Any, fake_clock: FakeClock) -> None:
    sleep = NeverEnding()
    app, pipeline = tarpit_app(dbs, fake_clock, sleep, tarpit_max_concurrent=3)
    tasks = [asyncio.create_task(raw_asgi_request(app, PROBE, headers=HEADERS)) for _ in range(10)]
    for _ in range(200):
        await asyncio.sleep(0.01)
        if sum(task.done() for task in tasks) == 7:
            break
    assert await pipeline.tarpit.active_holds() == 3
    assert pipeline.tarpit.stats.total.skipped == 7
    for task in tasks:
        task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
    assert await pipeline.tarpit.active_holds() == 0
