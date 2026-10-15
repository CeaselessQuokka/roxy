"""Fixtures for the upstream unit tests: a stepping clock, a fake egress, a context over real temp databases."""

from __future__ import annotations

from typing import Any

import pytest
from upstream_fakes import FakeEgress, FakeRecorder, FakeRules, FakeSettings, SteppingClock, make_ctx, make_service

from roxy.upstream.service import UpstreamService


@pytest.fixture
def clock() -> SteppingClock:
    return SteppingClock()


@pytest.fixture
def egress() -> FakeEgress:
    return FakeEgress()


@pytest.fixture
def settings() -> FakeSettings:
    return FakeSettings()


@pytest.fixture
def rules() -> FakeRules:
    return FakeRules()


@pytest.fixture
def recorder() -> FakeRecorder:
    return FakeRecorder()


@pytest.fixture
def ctx(
    dbs: Any, clock: SteppingClock, egress: FakeEgress, settings: FakeSettings, rules: FakeRules, recorder: FakeRecorder
) -> Any:
    return make_ctx(dbs, clock, egress, settings=settings, rules=rules, recorder=recorder)


@pytest.fixture
def service(ctx: Any) -> UpstreamService:
    return make_service(ctx)
