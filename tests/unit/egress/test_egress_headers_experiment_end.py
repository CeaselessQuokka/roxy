"""The User-Agent experiment splits direct calls only for `ua_experiment_days` (review finding brain-7, plan 11.5).

The run starts at the newest stored change of `UA_EXPERIMENT_KEYS` (the settings snapshot's `updated_at`); after
the days every direct call carries `direct_user_agent` again while the switch stays on. The arm assignment the
insights rule recomputes (`ua_variant`) does not change.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from roxy.core.reasons import Egress
from roxy.egress.headers import DAY_S, HeaderProfiles, experiment_started_at

STARTED = 1_760_000_000
VALUES = {
    "ua_experiment_enabled": 1,
    "ua_experiment_days": 7,
    "direct_user_agent": "Primary/1",
    "ua_experiment_alt_user_agent": "Alt/2",
}


class Settings:
    """The two things `HeaderProfiles` reads from `RuntimeSettings`: `get` and `snapshot().meta`."""

    def __init__(self, values: dict[str, Any], meta: dict[str, tuple[int, str]]) -> None:
        self._values = values
        self._snapshot = SimpleNamespace(meta=meta)

    def get(self, key: str) -> Any:
        return self._values[key]

    def snapshot(self) -> Any:
        return self._snapshot


def _alt_identity(profiles: HeaderProfiles) -> str:
    return next(f"key{i}" for i in range(200) if profiles.ua_variant(Egress.DIRECT, f"key{i}") == "alt")


def test_the_split_ends_after_the_experiment_days() -> None:
    now = [STARTED + 1.0]
    profiles = HeaderProfiles(
        Settings(VALUES, {"ua_experiment_enabled": (STARTED, "admin:owner")}), "", clock=lambda: now[0]
    )
    identity = _alt_identity(profiles)
    assert profiles.user_agent(Egress.DIRECT, identity) == "Alt/2"
    now[0] = STARTED + 7 * DAY_S - 1
    assert profiles.user_agent(Egress.DIRECT, identity) == "Alt/2"
    now[0] = STARTED + 7 * DAY_S
    assert not profiles.experiment_running()
    assert profiles.user_agent(Egress.DIRECT, identity) == "Primary/1"
    assert profiles.ua_variant(Egress.DIRECT, identity) == "alt"  # the insights rule's assignment is unchanged


def test_a_user_agent_change_starts_a_new_run_and_a_mapping_has_no_start() -> None:
    meta = {
        "ua_experiment_enabled": (STARTED, "admin:owner"),
        "ua_experiment_alt_user_agent": (STARTED + 5 * DAY_S, "admin:owner"),
        "allowed_requests_per_minute": (STARTED + 6 * DAY_S, "admin:owner"),  # not an experiment key
    }
    assert experiment_started_at(Settings(VALUES, meta)) == STARTED + 5 * DAY_S
    assert experiment_started_at(VALUES) is None
    profiles = HeaderProfiles(VALUES, "", clock=lambda: STARTED + 100 * DAY_S)
    assert profiles.experiment_running()  # no start record: the switch alone decides
