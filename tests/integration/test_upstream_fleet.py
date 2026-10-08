"""Upstream integration (plan 19.2, upstream bullet): two service instances sharing one set of databases, the way
two workers share them, with `respx` playing Roblox where a real HTTP client is involved.

Covers: a 429 with Retry-After opens the cooldown fleet-wide; no cascade onto the credential; rotator 429s count
under the distinct-exit rule; the CSRF handshake with a token cached for every worker; 2xx other than 200 is
success; 5xx retried with backoff within the deadline; the half-open probe is one call in the whole fleet.
"""

from __future__ import annotations

import importlib.util
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from roxy.core.reasons import Egress, ReasonCode
from roxy.storage.db import open_databases
from roxy.upstream.queue import Priority
from roxy.upstream.service import UpstreamService


def load_fakes() -> Any:
    """The upstream test doubles live with the unit tests; load them by path (tests are not a package)."""
    if "upstream_fakes" in sys.modules:
        return sys.modules["upstream_fakes"]
    path = Path(__file__).resolve().parents[1] / "unit" / "upstream" / "upstream_fakes.py"
    spec = importlib.util.spec_from_file_location("upstream_fakes", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["upstream_fakes"] = module
    spec.loader.exec_module(module)
    return module


fakes = load_fakes()
TEMPLATE = "games.roblox.com/v1/games"


@pytest.fixture
def second_dbs(env: Any, dbs: Any) -> Iterator[Any]:
    """A second worker's view of the same files: its own connections and writer thread."""
    other = open_databases(env)
    try:
        yield other
    finally:
        other.close_all_sync()


@pytest.fixture
def clock() -> Any:
    return fakes.SteppingClock()


def pair(dbs: Any, second_dbs: Any, clock: Any, egress_a: Any, egress_b: Any, **knobs: Any) -> tuple[Any, Any]:
    rules = fakes.FakeRules()
    settings = fakes.FakeSettings(**knobs)
    a = fakes.make_service(fakes.make_ctx(dbs, clock, egress_a, settings=settings, rules=rules, worker_id="wa"), seed=1)
    b = fakes.make_service(
        fakes.make_ctx(second_dbs, clock, egress_b, settings=settings, rules=rules, worker_id="wb"), seed=2
    )
    return a, b


async def get(service: UpstreamService, **fields: Any) -> Any:
    return await service.fetch(fakes.request(service, **fields), priority=Priority.INTERACTIVE, stale_available=False)


async def test_429_retry_after_cools_down_every_worker(dbs: Any, second_dbs: Any, clock: Any, respx_mock: Any) -> None:
    state = {"limited": True}

    def roblox(request: httpx.Request) -> httpx.Response:
        if state["limited"]:
            return httpx.Response(429, headers={"Retry-After": "30"}, json={"errors": [{"message": "Too many"}]})
        return httpx.Response(200, json={"data": []})

    route = respx_mock.route(host="games.roblox.com", path="/v1/games").mock(side_effect=roblox)
    egress_a = fakes.RespxEgress(disabled={Egress.ROTATOR})
    egress_b = fakes.RespxEgress(disabled={Egress.ROTATOR})
    a, b = pair(dbs, second_dbs, clock, egress_a, egress_b)

    first = await get(a)
    assert (first.status, first.reason, first.retry_after_s) == (429, ReasonCode.UPSTREAM_COOLDOWN, 30)
    assert route.call_count == 1
    # Worker B never saw the 429, yet makes no call while the cooldown lasts, and tells its callers to wait.
    start = clock.now()
    for at in (1, 10, 29):
        clock.advance(start + at - clock.now())
        result = await get(b)
        assert result.reason is ReasonCode.UPSTREAM_COOLDOWN
        assert result.retry_after_s == 30 - at
        assert result.cooldown_s == 30 - at
        assert route.call_count == 1
    clock.advance(start + 30.5 - clock.now())
    state["limited"] = False
    recovered = await get(b)
    assert recovered.status == 200
    assert route.call_count == 2  # one half-open probe, then normal traffic
    assert (await get(a)).status == 200
    await egress_a.http.aclose()
    await egress_b.http.aclose()


async def test_half_open_probe_is_one_call_fleet_wide(dbs: Any, second_dbs: Any, clock: Any) -> None:
    from roxy.upstream import breaker

    egress_a = fakes.FakeEgress(disabled={Egress.ROTATOR})
    egress_b = fakes.FakeEgress(disabled={Egress.ROTATOR})
    a, b = pair(dbs, second_dbs, clock, egress_a, egress_b)
    key = f"endpoint:{TEMPLATE}:direct"
    row, _ = breaker.trip(None, key, clock.now() - 60, 30)  # open, and half-open since 30 s ago
    dbs.hot.write_sync(lambda c: breaker.save(c, row))
    dbs.hot.write_sync(lambda c: breaker.try_acquire_probe(c, key, "wa:probe", clock.now_ms(), 20))  # A is probing
    blocked = await get(b)
    assert blocked.reason is ReasonCode.UPSTREAM_COOLDOWN
    assert egress_b.calls == []
    dbs.hot.write_sync(lambda c: breaker.release_probe(c, key, "wa:probe"))
    assert (await get(b)).status == 200  # B's probe closes the breaker
    assert len(egress_b.calls) == 1
    assert (await get(a)).status == 200


async def test_no_cascade_to_credential(dbs: Any, second_dbs: Any, clock: Any) -> None:
    egress = fakes.FakeEgress(lambda e, out: fakes.answer(429, b"", {"retry-after": "5"}))
    a, _b = pair(dbs, second_dbs, clock, egress, fakes.FakeEgress(), fallback_on_429=1)
    for _ in range(5):
        await get(a)
        clock.advance(6)
    assert Egress.CREDENTIAL not in egress.egresses()
    assert set(egress.egresses()) <= {Egress.DIRECT, Egress.ROTATOR}


async def test_rotator_429s_count_by_distinct_exits(dbs: Any, second_dbs: Any, clock: Any) -> None:
    from upstream_fakes import read_rows

    egress_a = fakes.FakeEgress(lambda e, out: fakes.answer(429, b""), disabled={Egress.DIRECT})
    egress_b = fakes.FakeEgress(lambda e, out: fakes.answer(429, b""), disabled={Egress.DIRECT})
    egress_a.rotator = fakes.FakeRotator("a")
    egress_b.rotator = fakes.FakeRotator("b")
    a, b = pair(dbs, second_dbs, clock, egress_a, egress_b)
    await get(a)  # exit a1
    await get(b)  # exit b1, seen by another worker
    cooling = {row[0] for row in read_rows(dbs.hot, "SELECT key FROM cooldown")}
    assert f"endpoint:{TEMPLATE}:rotator" not in cooling  # one or two burned exits never park the endpoint
    await get(a)  # A rotated after its 429: exit a2, the third distinct exit within 60 s
    cooling = {row[0] for row in read_rows(dbs.hot, "SELECT key FROM cooldown")}
    assert f"endpoint:{TEMPLATE}:rotator" in cooling
    assert egress_a.rotator.rotations[0][1] == "429"
    calls = len(egress_a.calls) + len(egress_b.calls)
    await get(b)
    assert len(egress_a.calls) + len(egress_b.calls) == calls  # now worker B stays away too


async def test_csrf_token_cached_for_every_worker(dbs: Any, second_dbs: Any, clock: Any) -> None:
    def roblox(e: Egress, out: Any) -> Any:
        if out.headers.get("x-csrf-token") == "fleet-token":
            return fakes.answer(200, b"{}")
        return fakes.answer(403, b"", {"x-csrf-token": "fleet-token"})

    egress_a, egress_b = fakes.FakeEgress(roblox), fakes.FakeEgress(roblox)
    a, b = pair(dbs, second_dbs, clock, egress_a, egress_b)
    assert (await get(a, method="POST", body=b"{}")).status == 200
    assert len(egress_a.calls) == 2  # the handshake: 403, then the retry with the token
    assert (await get(b, method="POST", body=b"{}")).status == 200
    assert len(egress_b.calls) == 1  # worker B used the token worker A cached


@pytest.mark.parametrize("status", [201, 202, 204])
async def test_2xx_other_than_200_is_success(
    dbs: Any, second_dbs: Any, clock: Any, respx_mock: Any, status: int
) -> None:
    respx_mock.route(host="games.roblox.com").mock(return_value=httpx.Response(status, content=b""))
    egress = fakes.RespxEgress()
    a, _b = pair(dbs, second_dbs, clock, egress, fakes.FakeEgress())
    result = await get(a, method="POST", body=b"{}")
    assert (result.status, result.reason, result.attempts, result.calls) == (status, ReasonCode.UPSTREAM_OK, 1, 1)
    await egress.http.aclose()


async def test_5xx_retried_with_backoff_within_deadline(dbs: Any, second_dbs: Any, clock: Any, respx_mock: Any) -> None:
    route = respx_mock.route(host="games.roblox.com").mock(
        side_effect=[httpx.Response(503), httpx.Response(200, json={"ok": True})]
    )
    egress = fakes.RespxEgress()
    a, _b = pair(dbs, second_dbs, clock, egress, fakes.FakeEgress())
    result = await get(a)
    assert result.status == 200
    assert route.call_count == 2
    assert len(clock.slept) == 1
    assert 0.2 <= clock.slept[0] <= 2.0
    # With too little deadline left, the 5xx is answered at once with the real status and no retry.
    route.side_effect = [httpx.Response(503)]
    route.reset()
    short = fakes.request(a)
    short.deadline_at = clock.monotonic() + 1.1
    failed = await a.fetch(short, priority=Priority.INTERACTIVE, stale_available=False)
    assert (failed.status, failed.reason, failed.retry_after_s) == (503, ReasonCode.UPSTREAM_5XX, 5)
    assert route.call_count == 1
    await egress.http.aclose()


async def test_429_during_a_hot_outage_reaches_every_worker_once_hot_recovers(
    dbs: Any, second_dbs: Any, clock: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Finding UP-COOLDOWN-LOST with two workers (C6, C7): worker A sees a 429 while hot.db takes no writes and
    keeps the cooldown in memory; once hot.db takes writes again A shares it, and worker B (its own connections,
    the same files) refuses the endpoint too, without calling Roblox."""
    from roxy.storage.db import SharedStateUnavailable

    egress_a = fakes.FakeEgress(lambda e, out: fakes.answer(429, b"{}", {"retry-after": "60"}))
    egress_b = fakes.FakeEgress()
    a, b = pair(dbs, second_dbs, clock, egress_a, egress_b, rotator_enabled=0)
    real_write = dbs.hot.write
    broken = {"on": False}

    async def write(fn: Any, **kwargs: Any) -> Any:
        if broken["on"]:
            raise SharedStateUnavailable("hot", "attempt to write a readonly database")
        return await real_write(fn, **kwargs)

    monkeypatch.setattr(dbs.hot, "write", write)

    def limited(e: Egress, out: Any) -> Any:
        broken["on"] = True  # hot.db stops taking writes while Roblox answers
        return fakes.answer(429, b"{}", {"retry-after": "60"})

    egress_a.handler = limited
    first = await get(a)
    assert (first.reason, first.retry_after_s) == (ReasonCode.UPSTREAM_COOLDOWN, 60)
    assert len(a.local_cooldowns) == 1
    before_b = await get(b)  # nothing shared yet: B may still call (C7 allows the per-worker fallback meanwhile)
    assert before_b.status == 200
    broken["on"] = False
    clock.advance(5)
    assert await a.flush_local_cooldowns() == 1  # what A's mirror loop (or its next request) does
    calls_b = len(egress_b.calls)
    after = await get(b)
    assert (after.status, after.reason, after.retry_after_s) == (429, ReasonCode.UPSTREAM_COOLDOWN, 55)
    assert len(egress_b.calls) == calls_b
