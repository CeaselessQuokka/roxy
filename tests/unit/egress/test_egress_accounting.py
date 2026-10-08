"""Usage accounting: per-request bytes reach the recorder, or wait in a bounded buffer (plan 8.3, P9).

What this is
    Unit tests for `roxy.egress.accounting`.

Why it exists
    The rotator budget and the Egress page start from these records; losing them silently or buffering them
    without bound would both be bugs.

How it works
    A fake recorder with and without `record_egress_usage`.

What to read next
    `src/roxy/egress/accounting.py`.
"""

from __future__ import annotations

from typing import Any

from roxy.core.reasons import Egress
from roxy.egress.accounting import EgressUsage, UsageAccountant, aggregate_minutes


def usage(
    at_ms: int = 60_000, egress: Egress = Egress.ROTATOR, size: int = 100, status: int | None = 200
) -> EgressUsage:
    return EgressUsage(at_ms, egress, "caller", "s1", size, size * 2, 7, 1, "socket", status)


class Recorder:
    def __init__(self) -> None:
        self.seen: list[EgressUsage] = []

    def record_egress_usage(self, item: EgressUsage) -> None:
        self.seen.append(item)


def test_hands_usage_to_the_recorder_and_tells_listeners() -> None:
    recorder = Recorder()
    accountant = UsageAccountant(lambda: recorder)
    heard: list[tuple[int, bool]] = []
    accountant.add_listener(lambda item, handed_off: heard.append((item.req_bytes, handed_off)))
    accountant.record(usage())
    assert recorder.seen
    assert accountant.buffered == 0
    assert heard == [(100, True)]
    totals = accountant.totals()["rotator"]
    assert totals == {
        "requests": 1,
        "req_bytes": 100,
        "resp_bytes": 200,
        "overhead_bytes": 7,
        "new_connections": 1,
        "failed": 0,
    }


def test_buffers_when_no_recorder_and_stays_bounded() -> None:
    holder: dict[str, Any] = {"recorder": None}
    accountant = UsageAccountant(lambda: holder["recorder"], buffer_max=3)
    heard: list[bool] = []
    accountant.add_listener(lambda item, handed_off: heard.append(handed_off))
    for index in range(5):
        accountant.record(usage(size=index + 1, status=None if index == 0 else 200))
    assert accountant.buffered == 3
    assert accountant.dropped == 2
    assert heard == [False] * 5
    assert [item.req_bytes for item in accountant.drain()] == [3, 4, 5]
    assert accountant.totals()["rotator"]["failed"] == 1
    holder["recorder"] = Recorder()
    accountant.record(usage())
    assert accountant.buffered == 0
    assert accountant.handed_off == 1


def test_a_failing_recorder_never_fails_the_request() -> None:
    class Broken:
        def record_egress_usage(self, item: EgressUsage) -> None:
            raise RuntimeError("boom")

    accountant = UsageAccountant(lambda: Broken())
    accountant.add_listener(lambda item, handed_off: (_ for _ in ()).throw(RuntimeError("listener")))
    accountant.record(usage())
    assert accountant.buffered == 1


def test_aggregate_minutes() -> None:
    rows = aggregate_minutes([usage(60_000), usage(119_999), usage(120_000, Egress.DIRECT)])
    assert rows[(60, "rotator")] == {"requests": 2, "req_bytes": 200, "resp_bytes": 400, "overhead_bytes": 14}
    assert rows[(120, "direct")]["requests"] == 1
