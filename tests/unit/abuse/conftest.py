"""Fixtures for the abuse tests: a pipeline over temporary databases, rules builders, a recording sleep."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest
from abuse_support import FakeSettings

from roxy.abuse.pipeline import AbusePipeline
from roxy.config.defaults import seed_defaults
from roxy.core.clock import FakeClock
from roxy.rules.service import RulesService
from roxy.rules.store import RulesSnapshot, build_rules_snapshot


class SleepRecorder:
    """An `asyncio.sleep` stand-in that records durations and returns at once."""

    def __init__(self) -> None:
        self.calls: list[float] = []

    async def __call__(self, seconds: float) -> None:
        self.calls.append(seconds)


@pytest.fixture
def sleeps() -> SleepRecorder:
    return SleepRecorder()


@pytest.fixture
def rules_service(dbs: Any, fake_clock: FakeClock) -> RulesService:
    return RulesService(dbs.control, clock=fake_clock)


@pytest.fixture
def snapshot_of(dbs: Any, fake_clock: FakeClock) -> Callable[[], RulesSnapshot]:
    """Build a fresh rules snapshot from control.db (after the test created rules)."""

    def build() -> RulesSnapshot:
        now = fake_clock.now()
        snapshot: RulesSnapshot = dbs.control.read_sync(lambda conn: build_rules_snapshot(conn, now))
        return snapshot

    return build


@pytest.fixture
def seeded(dbs: Any, fake_clock: FakeClock) -> None:
    """The plan 15.5 default rows (the default ladder with the C5 rung 1 text, ignored paths, ...)."""
    now = int(fake_clock.now())
    dbs.control.write_sync(lambda conn: seed_defaults(conn, now))


@pytest.fixture
def make_pipeline(dbs: Any, fake_clock: FakeClock, sleeps: SleepRecorder) -> Callable[..., AbusePipeline]:
    """`make_pipeline(overrides, rules=..., **kwargs)` -> an `AbusePipeline` over the test's databases."""

    def build(overrides: dict[str, Any] | None = None, *, rules: Any = None, **kwargs: Any) -> AbusePipeline:
        kwargs.setdefault("hot_db", dbs.hot)
        kwargs.setdefault("control_db", dbs.control)
        return AbusePipeline(
            settings=FakeSettings(overrides),
            rules=rules if rules is not None else RulesSnapshot.empty(),
            clock=fake_clock,
            worker_id="test-worker",
            tarpit_sleep=sleeps,
            monotonic=fake_clock.monotonic,
            **kwargs,
        )

    return build
