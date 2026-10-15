"""End to end: the `upstream_cooldown_retry` tarpit category through the fully wired app (plan 10.6, 15.3 F).

What this is
    Spec review finding F4 (repro R3, moved here from `.remake/scripts/review_repro`): with
    `tarpit_on_upstream_cooldown_retry` on, a caller that retries the same key inside the `Retry-After` it was
    given is held with the `jitter` type before it gets the same pacing answer again. Plus the cases that must NOT
    be held: the first answer, another client, another key, and the switch off (the default).

Why it exists
    The switch existed with no producer (the same class of bug as v1 B34): turning it on did nothing. Only the full
    app shows the producer is wired: the router sees the 7.13 cooldown answer, the tarpit remembers the Retry-After
    in hot.db and holds the retry.

How it works
    The e2e harness of `tests/integration/test_pipeline_e2e.py` (loaded by path under its own module name, so its
    tests are not collected twice) runs the real app with respx playing Roblox. Roblox answers 429 with
    `Retry-After: 30`; the tarpit's sleep is replaced by a recorder, so holds are observed instead of waited.

What to read next
    `roxy/abuse/tarpit.py` (`plan_cooldown_retry`), `roxy/proxy/router.py` (`cooldown_retry_plan`).
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

import httpx
import pytest

from roxy.abuse.tarpit import RETRY_CATEGORY, RETRY_PREFIX


def _load(name: str, path: Path) -> Any:
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


E2E = _load("abuse_cooldown_retry_e2e_harness", Path(__file__).with_name("test_pipeline_e2e.py"))


class RecordingSleep:
    def __init__(self) -> None:
        self.calls: list[float] = []

    async def __call__(self, seconds: float) -> None:
        self.calls.append(seconds)


def roblox_429() -> httpx.Response:
    payload = {"errors": [{"code": 0, "message": "Too many requests"}]}
    return httpx.Response(429, json=payload, headers={"Retry-After": "30"})


@pytest.fixture
async def app(env: Any, credentials_dir: Path, fake_secrets: dict[str, str], respx_mock: Any) -> Any:
    async with E2E.running_app(env, credentials_dir, fake_secrets, respx_mock) as harness:
        yield harness


async def test_r3_retry_inside_retry_after_is_jitter_tarpitted(app: Any) -> None:
    await app.settings(tarpit_enabled=1, tarpit_on_upstream_cooldown_retry=1)
    app.route(E2E.GAMES, E2E.GAMES_PATH).mock(return_value=roblox_429())
    sleep = RecordingSleep()
    app.ctx.abuse.tarpit.sleep = sleep
    ip = app.ip()
    first = await app.get(E2E.games(), ip=ip)
    assert first.status_code == 429
    assert int(first.headers["Retry-After"]) > 0
    assert sleep.calls == []  # the answer that hands out the Retry-After is never held
    second = await app.get(E2E.games(), ip=ip)  # the same key, well inside the 30 s it was told to wait
    assert second.status_code == 429
    assert second.content == first.content
    [held] = sleep.calls
    assert 0.5 <= held <= 3.0  # the jitter type (tarpit_jitter_min_ms..tarpit_jitter_max_ms), never a long hold
    stats = app.ctx.abuse.tarpit.stats.snapshot()
    assert stats["categories"][RETRY_CATEGORY]["held"] == 1
    assert await app.ctx.abuse.tarpit.active_holds() == 0  # the slot came back


async def test_cooldown_retry_is_per_client_and_per_key_and_bounded(app: Any) -> None:
    await app.settings(tarpit_enabled=1, tarpit_on_upstream_cooldown_retry=1)
    app.route(E2E.GAMES, E2E.GAMES_PATH).mock(return_value=roblox_429())
    sleep = RecordingSleep()
    app.ctx.abuse.tarpit.sleep = sleep
    ip = app.ip()
    assert (await app.get(E2E.games(1), ip=ip)).status_code == 429
    assert (await app.get(E2E.games(1))).status_code == 429  # another client: its own first answer
    assert (await app.get(E2E.games(2), ip=ip)).status_code == 429  # the same client, another key
    assert sleep.calls == []
    for universe in range(3, 40):  # many keys from one client: the remembered answers stay bounded
        await app.get(E2E.games(universe), ip=ip)

    def rows(conn: Any) -> int:
        return int(
            conn.execute(
                "SELECT count(*) FROM limiter WHERE bucket_key >= ? AND bucket_key < ?",
                (f"{RETRY_PREFIX}{ip}|", f"{RETRY_PREFIX}{ip}|\U0010ffff"),
            ).fetchone()[0]
        )

    assert await app.ctx.dbs.hot.read(rows) <= 8


async def test_cooldown_retry_switch_off_holds_nothing(app: Any) -> None:
    await app.settings(tarpit_enabled=1)  # tarpit_on_upstream_cooldown_retry stays at its default, 0
    app.route(E2E.GAMES, E2E.GAMES_PATH).mock(return_value=roblox_429())
    sleep = RecordingSleep()
    app.ctx.abuse.tarpit.sleep = sleep
    ip = app.ip()
    for _ in range(3):
        assert (await app.get(E2E.games(), ip=ip)).status_code == 429
    assert sleep.calls == []

    def rows(conn: Any) -> int:
        return int(conn.execute("SELECT count(*) FROM limiter WHERE bucket_key LIKE 'ucr:%'").fetchone()[0])

    assert await app.ctx.dbs.hot.read(rows) == 0  # with the category off nothing is read or written
