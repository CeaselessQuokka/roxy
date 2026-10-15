"""UP-UA-EXPERIMENT compares only calls made during the run (review finding brain-7): `ua_experiment_days` from the
newest recorded change of the experiment keys, when `egress/headers.py` stops splitting direct calls."""

from __future__ import annotations

import dataclasses
from typing import Any

from insights.harness import fixture_path, load
from roxy.insights.providers_rules_upstream import ua_experiment_arms

DAY_S = 86_400


def _calls(arms: dict[str, Any] | None) -> int:
    assert arms is not None
    return sum(int(arm["calls"]) for arm in arms["arms"])


async def test_ua_experiment_arms_count_only_the_run() -> None:
    state = await load(fixture_path("up_retryafter_ignored__polling_script"))  # a fresh copy: rows are added below
    try:
        base = state.engine.context(state.now)
        settings = {**dict(base.settings), "ua_experiment_enabled": 1, "ua_experiment_days": 1}

        def context() -> Any:
            return dataclasses.replace(base, settings=settings, _memo={}, _locks={})

        def switched_on(at: float) -> None:
            state.dbs.control.write_sync(
                lambda conn: conn.execute(
                    "INSERT INTO settings_history (key, old_json, new_json, changed_at, changed_by, reason, source) "
                    "VALUES ('ua_experiment_enabled', NULL, '1', ?, 'admin:owner', 'start the run', 'admin')",
                    (int(at),),
                )
            )

        whole = _calls(await ua_experiment_arms(context()))  # no record: the sample window alone bounds it
        assert whole > 0
        switched_on(state.now - 3 * DAY_S)  # a one day run that ended two days ago
        assert await ua_experiment_arms(context()) is None
        switched_on(state.now - 6 * 3600)  # a new run six hours ago: only its calls count
        assert 0 < _calls(await ua_experiment_arms(context())) <= whole
    finally:
        state.close()
