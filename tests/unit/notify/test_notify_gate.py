"""The alert gate (plan 17.7, C6): fleet-wide dedupe by cooldown key and the per-channel hourly cap."""

from __future__ import annotations

from typing import Any

from roxy.notify import gate


def _decide(
    dbs: Any,
    now: int,
    *,
    key: str | None = "k",
    cooldown: int = 300,
    cap: int = 20,
    uncapped: bool = False,
    channels: tuple[str, ...] = ("email",),
) -> gate.GateDecision:
    return dbs.hot.write_sync(
        lambda c: gate.decide(
            c, cooldown_key=key, cooldown_s=cooldown, channels=channels, cap=cap, uncapped=uncapped, now=now
        )
    )


def test_dedupe_within_the_cooldown_and_report_what_was_held_back(dbs: Any) -> None:
    first = _decide(dbs, 1000)
    assert first.allowed == ("email",)
    assert first.suppressed == {"email": 0}
    for t in (1001, 1100, 1299):
        assert _decide(dbs, t).deduped
    later = _decide(dbs, 1300)
    assert later.allowed == ("email",)
    assert later.suppressed == {"email": 3}
    assert _decide(dbs, 1301).deduped


def test_clock_stepping_back_does_not_resend(dbs: Any) -> None:
    assert _decide(dbs, 1000).allowed
    assert _decide(dbs, 999).deduped


def test_hourly_cap_per_channel_then_summary(dbs: Any) -> None:
    sent = [_decide(dbs, 1000 + i, key=f"k{i}", cap=3) for i in range(5)]
    assert [bool(d.allowed) for d in sent] == [True, True, True, False, False]
    assert sent[3].capped == ("email",)
    after = _decide(dbs, 1000 + 3600, key="k-new", cap=3)
    assert after.allowed == ("email",)
    assert after.suppressed == {"email": 2}
    # A key held back by the cap was not marked as sent: it goes out once the cap allows.
    retry = _decide(dbs, 1000 + 3601, key="k3", cap=3)
    assert retry.allowed == ("email",)
    assert retry.suppressed["email"] >= 1


def test_uncapped_alerts_ignore_the_cap(dbs: Any) -> None:
    for i in range(5):
        _decide(dbs, 1000 + i, key=f"k{i}", cap=2)
    leak = _decide(dbs, 1010, key=None, cap=2, uncapped=True)
    assert leak.allowed == ("email",)


def test_channels_are_capped_separately(dbs: Any) -> None:
    for i in range(2):
        _decide(dbs, 1000 + i, key=f"e{i}", cap=2, channels=("email",))
    both = _decide(dbs, 1005, key="both", cap=2, channels=("email", "webhook"))
    assert both.allowed == ("webhook",)
    assert both.capped == ("email",)


def test_no_channels_means_nothing_to_do(dbs: Any) -> None:
    assert _decide(dbs, 1000, channels=()).allowed == ()


def test_memory_gate_is_bounded() -> None:
    memory = gate.MemoryGate(max_keys=3)
    assert memory.allow("a", 60, 0)
    assert not memory.allow("a", 60, 30)
    assert memory.allow("a", 60, 61)
    for key in "bcde":
        memory.allow(key, 60, 100)
    assert memory.allow("a", 60, 101)  # evicted (bounded), so allowed again
    assert memory.allow(None, 60, 0)
    assert memory.allow(None, 60, 0)
