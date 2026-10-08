"""The alert gate (plan 17.7, C6): fleet-wide dedupe by cooldown key and the per-channel hourly cap.

Every rule is checked twice: on the shared hot.db gate (`gate.decide`) and on `gate.MemoryGate`, the per-worker
stand-in used while hot.db cannot be written (plan C7, finding ALERT-CAP). Both must give the same answers.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from roxy.notify import gate

Decide = Callable[..., gate.GateDecision]


@pytest.fixture(params=["hot.db", "memory"])
def decide(request: pytest.FixtureRequest, dbs: Any) -> Decide:
    """`decide(now, key=..., cooldown=..., cap=..., uncapped=..., channels=...)` on one of the two gates."""
    memory = gate.MemoryGate()

    def run(
        now: int,
        *,
        key: str | None = "k",
        cooldown: int = 300,
        cap: int = 20,
        uncapped: bool = False,
        channels: tuple[str, ...] = ("email",),
    ) -> gate.GateDecision:
        kwargs: dict[str, Any] = {
            "cooldown_key": key,
            "cooldown_s": cooldown,
            "channels": channels,
            "cap": cap,
            "uncapped": uncapped,
            "now": now,
        }
        if request.param == "memory":
            return memory.decide(**kwargs)
        result: gate.GateDecision = dbs.hot.write_sync(lambda c: gate.decide(c, **kwargs))
        return result

    return run


def test_dedupe_within_the_cooldown_and_report_what_was_held_back(decide: Decide) -> None:
    first = decide(1000)
    assert first.allowed == ("email",)
    assert first.suppressed == {"email": 0}
    for t in (1001, 1100, 1299):
        assert decide(t).deduped
    later = decide(1300)
    assert later.allowed == ("email",)
    assert later.suppressed == {"email": 3}
    assert decide(1301).deduped


def test_clock_stepping_back_does_not_resend(decide: Decide) -> None:
    assert decide(1000).allowed
    assert decide(999).deduped


def test_hourly_cap_per_channel_then_summary(decide: Decide) -> None:
    sent = [decide(1000 + i, key=f"k{i}", cap=3) for i in range(5)]
    assert [bool(d.allowed) for d in sent] == [True, True, True, False, False]
    assert sent[3].capped == ("email",)
    after = decide(1000 + 3600, key="k-new", cap=3)
    assert after.allowed == ("email",)
    assert after.suppressed == {"email": 2}
    # A key held back by the cap was not marked as sent: it goes out once the cap allows.
    retry = decide(1000 + 3601, key="k3", cap=3)
    assert retry.allowed == ("email",)
    assert retry.suppressed["email"] >= 1


def test_uncapped_alerts_ignore_the_cap(decide: Decide) -> None:
    for i in range(5):
        decide(1000 + i, key=f"k{i}", cap=2)
    leak = decide(1010, key=None, cap=2, uncapped=True)
    assert leak.allowed == ("email",)


def test_channels_are_capped_separately(decide: Decide) -> None:
    for i in range(2):
        decide(1000 + i, key=f"e{i}", cap=2, channels=("email",))
    both = decide(1005, key="both", cap=2, channels=("email", "webhook"))
    assert both.allowed == ("webhook",)
    assert both.capped == ("email",)


def test_no_channels_means_nothing_to_do(decide: Decide) -> None:
    assert decide(1000, channels=()).allowed == ()


def test_alerts_without_a_key_are_never_deduped_but_are_capped(decide: Decide) -> None:
    answers = [decide(1000, key=None, cap=2) for _ in range(4)]
    assert [bool(d.allowed) for d in answers] == [True, True, False, False]
    assert not any(d.deduped for d in answers)


def test_memory_gate_is_bounded() -> None:
    memory = gate.MemoryGate(max_keys=3)

    def allowed(key: str | None, now: int) -> bool:
        return bool(
            memory.decide(
                cooldown_key=key, cooldown_s=60, channels=("email",), cap=1000, uncapped=False, now=now
            ).allowed
        )

    assert allowed("a", 1000)
    assert not allowed("a", 1030)
    assert allowed("a", 1061)
    for key in "bcde":
        allowed(key, 1100)
    assert allowed("a", 1101)  # evicted (bounded), so allowed again
    assert len(memory._alerts) <= 3
    assert allowed(None, 1000)
    assert allowed(None, 1000)


@pytest.mark.parametrize(("cap", "workers", "share"), [(20, 1, 20), (20, 2, 10), (20, 4, 5), (20, 3, 6), (1, 4, 1)])
def test_worker_share_keeps_the_fleet_within_the_cap(cap: int, workers: int, share: int) -> None:
    assert gate.worker_share(cap, workers) == share
    assert share * workers <= max(cap, workers)  # the fleet total never exceeds the cap (unless cap < workers)
