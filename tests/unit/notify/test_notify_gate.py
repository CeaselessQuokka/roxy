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


# --- after an outage (finding mp-10) -----------------------------------------------------------------------------


def _shared(dbs: Any, now: int, key: str, cap: int = 4) -> gate.GateDecision:
    kwargs: dict[str, Any] = {"cooldown_s": 300, "channels": ("email",), "cap": cap, "uncapped": False, "now": now}
    result: gate.GateDecision = dbs.hot.write_sync(lambda c: gate.decide(c, cooldown_key=key, **kwargs))
    return result


def _merge(dbs: Any, memory: gate.MemoryGate, now: int, *, workers: int = 2, share: int = 2) -> None:
    journal = memory.take_journal()
    reported = dbs.hot.write_sync(
        lambda c: gate.merge(c, journal, now=now, workers=workers, share=share, reported=memory.reported)
    )
    memory.merged(reported)


def _row(dbs: Any, key: str) -> tuple[int, int] | None:
    query = "SELECT last_sent_at, suppressed FROM email_gate WHERE key = ?"
    row = dbs.hot.read_sync(lambda c: c.execute(query, (key,)).fetchone())
    return None if row is None else (int(row[0]), int(row[1]))


def _outage(memory: gate.MemoryGate, now: int, tag: str, count: int = 4, share: int = 2) -> int:
    sent = 0
    for n in range(count):
        decision = memory.decide(
            cooldown_key=f"{tag}:{n}", cooldown_s=300, channels=("email",), cap=share, uncapped=False, now=now
        )
        sent += bool(decision.allowed)
    return sent


def test_the_fleet_stays_within_the_cap_for_the_hour_after_an_outage(dbs: Any) -> None:
    """Two workers (cap 4, share 2) each send their share from memory; whichever reports first reserves the other's
    share, so the shared gate allows nothing more in that hour, and the second report releases the reservation."""
    a, b = gate.MemoryGate(), gate.MemoryGate()
    assert _outage(a, 1000, "a") == 2
    assert _outage(b, 1000, "b") == 2
    _merge(dbs, a, 1060)
    assert _row(dbs, "cap:email") == (1000, 2)
    assert _row(dbs, "capmem:email") == (1000, 2)  # b's share, until b reports
    assert not _shared(dbs, 1061, "after:a").allowed
    _merge(dbs, b, 1070)
    assert _row(dbs, "cap:email") == (1000, 4)
    assert _row(dbs, "capmem:email") == (1000, 0)
    assert not _shared(dbs, 1071, "after:b").allowed
    assert _shared(dbs, 1000 + gate.CAP_WINDOW_S, "next hour").allowed == ("email",)


def test_a_worker_that_sent_less_releases_what_it_did_not_use(dbs: Any) -> None:
    a, b = gate.MemoryGate(), gate.MemoryGate()
    assert _outage(a, 1000, "a") == 2
    assert _outage(b, 1000, "b", count=1) == 1
    _merge(dbs, a, 1060)
    _merge(dbs, b, 1061)
    assert _row(dbs, "cap:email") == (1000, 3)
    assert _shared(dbs, 1062, "one more").allowed == ("email",)  # 3 + 0 reserved < 4
    assert not _shared(dbs, 1063, "too many").allowed


def test_a_worker_reports_once_per_window(dbs: Any) -> None:
    """A second merge in the same window adds the new sends but never releases another worker's share twice."""
    a = gate.MemoryGate()
    _outage(a, 1000, "a", count=1)
    _merge(dbs, a, 1010)
    assert _row(dbs, "capmem:email") == (1000, 2)
    _outage(a, 1020, "again", count=1)
    _merge(dbs, a, 1030)
    assert _row(dbs, "cap:email") == (1000, 2)
    assert _row(dbs, "capmem:email") == (1000, 2)


def test_merged_keys_keep_the_later_send_and_add_what_was_held_back(dbs: Any) -> None:
    memory = gate.MemoryGate()
    assert _shared(dbs, 900, "k").allowed  # the shared gate sent k at 900
    common: dict[str, Any] = {"cooldown_key": "k", "cooldown_s": 300, "channels": ("email",), "cap": 2}
    memory.decide(**common, uncapped=False, now=1000)
    for t in (1001, 1002):  # two duplicates held back in memory
        assert memory.decide(**common, uncapped=False, now=t).deduped
    _merge(dbs, memory, 1010)
    assert _row(dbs, "alert:k") == (1000, 2)
    assert _shared(dbs, 1100, "k").deduped  # inside the gap of the memory send: no duplicate after the outage


def test_cap_holds_and_capdrops_reach_the_shared_summary(dbs: Any) -> None:
    memory = gate.MemoryGate()
    assert _outage(memory, 1000, "m", count=5) == 2  # 3 held back by this worker's share
    _merge(dbs, memory, 1010, workers=1)
    assert _row(dbs, "capdrop:email") == (1010, 3)
    assert _row(dbs, "alert:m:4") == (0, 1)  # held back, not marked as sent
    later = _shared(dbs, 1000 + gate.CAP_WINDOW_S, "fresh")
    assert later.suppressed == {"email": 3}  # "Suppressed since last alert: 3"
    assert memory.journal_empty()


def test_a_failed_merge_is_put_back_in_order() -> None:
    memory = gate.MemoryGate()
    memory.decide(cooldown_key="k", cooldown_s=300, channels=("email",), cap=1, uncapped=False, now=1000)
    memory.decide(cooldown_key="k2", cooldown_s=300, channels=("email",), cap=1, uncapped=False, now=1001)
    journal = memory.take_journal()
    assert memory.journal_empty()
    memory.decide(cooldown_key="k", cooldown_s=300, channels=("email",), cap=1, uncapped=False, now=1002)  # deduped
    memory.restore_journal(journal)
    again = memory.take_journal()
    assert again.sends == {"email": [1000]}
    assert dict(again.keys) == {"k": (1000, 1), "k2": (0, 1)}
    assert again.capdrops == {"email": 1}


def test_uncapped_sends_never_count_against_the_shared_cap(dbs: Any) -> None:
    memory = gate.MemoryGate()
    for n in range(3):
        memory.decide(cooldown_key=f"leak:{n}", cooldown_s=0, channels=("email",), cap=1, uncapped=True, now=1000)
    _merge(dbs, memory, 1010, workers=1)
    assert _row(dbs, "cap:email") is None


def test_journal_is_bounded() -> None:
    memory = gate.MemoryGate(max_keys=4, max_channels=2)
    for n in range(50):
        memory.decide(
            cooldown_key=f"k{n}", cooldown_s=0, channels=(f"c{n % 5}",), cap=10_000, uncapped=False, now=1000 + n
        )
    journal = memory.take_journal()
    assert len(journal.keys) <= 4
    assert len(journal.sends) <= 2
    assert all(len(times) <= gate.MAX_JOURNAL_SENDS for times in journal.sends.values())
