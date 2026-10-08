"""Fixtures for the metrics unit tests: live settings from the catalog, outcome events, a recorder on temp databases.

`settings` answers `get(key)` from the catalog defaults plus test overrides and bumps `version` on every change, like
`RuntimeSettings`. `make_event(**fields)` builds an `OutcomeEvent` with sensible defaults (a served upstream GET).
`recorder` is a `MetricsRecorder` on the migrated temp databases (`dbs` from tests/conftest.py) with `fake_clock`.
"""

from __future__ import annotations

import random
from collections.abc import Callable
from typing import Any

import pytest

from roxy.config import catalog
from roxy.core.clock import FakeClock
from roxy.core.reasons import AuthClass, CacheState, Egress, Outcome, ReasonCode, Source
from roxy.metrics.recorder import MetricsRecorder, OutcomeEvent

TEMPLATE = "games.roblox.com/v1/games/{gameId}/votes"


class FakeSettings:
    """`get(key)` over catalog defaults plus overrides; `set()` bumps `version` like a config_version change."""

    def __init__(self, **overrides: Any) -> None:
        self.values: dict[str, Any] = catalog.defaults()
        self.values.update(overrides)
        self.version = 1

    def get(self, key: str) -> Any:
        return self.values[key]

    def set(self, **changes: Any) -> None:
        self.values.update(changes)
        self.version += 1


def build_event(clock: FakeClock, **fields: Any) -> OutcomeEvent:
    base: dict[str, Any] = {
        "at_ms": clock.now_ms(),
        "request_id": "01TESTREQUEST0000000000000",
        "endpoint_template": TEMPLATE,
        "host": "games.roblox.com",
        "method": "GET",
        "egress": Egress.DIRECT,
        "outcome": Outcome.SERVED_UPSTREAM,
        "reason": ReasonCode.UPSTREAM_OK,
        "status": 200,
        "source": Source.ROBLOX,
        "cache_state": CacheState.MISS,
        "auth_class": AuthClass.ANON,
        "caller_bytes_in": 100,
        "caller_bytes_out": 500,
        "upstream_calls": 1,
        "upstream_bytes_in": 900,
        "upstream_bytes_out": 300,
        "latency_ms": 42.0,
        "queue_wait_ms": 1.0,
        "upstream_ms": 30.0,
        "client_ip": "203.0.113.5",
        "place_id": "12345",
        "user_agent": "Roblox/WinInet",
        "bypass": False,
        "error": False,
    }
    base.update(fields)
    return OutcomeEvent(**base)


REFUSED = {
    "outcome": Outcome.REFUSED,
    "reason": ReasonCode.THROTTLE,
    "status": 429,
    "source": Source.ROXY,
    "cache_state": CacheState.NA,
    "egress": Egress.NONE,
    "upstream_calls": 0,
    "upstream_bytes_in": 0,
    "upstream_bytes_out": 0,
}
CACHE_HIT = {
    "outcome": Outcome.SERVED_CACHE,
    "reason": ReasonCode.CACHE_HIT,
    "cache_state": CacheState.HIT,
    "source": Source.CACHE,
    "egress": Egress.NONE,
    "upstream_calls": 0,
    "upstream_bytes_in": 0,
    "upstream_bytes_out": 0,
}


@pytest.fixture
def presets() -> dict[str, Any]:
    """Field sets for common outcomes (tests cannot import conftest modules by name)."""
    return {"refused": dict(REFUSED), "cache_hit": dict(CACHE_HIT), "template": TEMPLATE}


@pytest.fixture
def settings() -> FakeSettings:
    return FakeSettings()


@pytest.fixture
def settings_factory() -> Callable[..., FakeSettings]:
    return FakeSettings


@pytest.fixture
def make_event(fake_clock: FakeClock) -> Callable[..., OutcomeEvent]:
    def make(**fields: Any) -> OutcomeEvent:
        return build_event(fake_clock, **fields)

    return make


@pytest.fixture
def recorder(dbs: Any, settings: FakeSettings, fake_clock: FakeClock) -> MetricsRecorder:
    return MetricsRecorder(dbs, settings, fake_clock, rng=random.Random(7).random)


@pytest.fixture
def metrics_rows(dbs: Any) -> Callable[[str, tuple[Any, ...]], list[tuple[Any, ...]]]:
    """Run a SELECT on metrics.db (synchronously) and return plain tuples."""

    def query(sql: str, params: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
        rows: list[tuple[Any, ...]] = dbs.metrics.read_sync(
            lambda conn: [tuple(r) for r in conn.execute(sql, params).fetchall()]
        )
        return rows

    return query
