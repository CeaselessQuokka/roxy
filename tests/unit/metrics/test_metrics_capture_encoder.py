"""Capture rows are built off the event loop, on a bounded queue that drops instead of waiting (finding LOOP-1).

`trim_input` (on the loop) only cuts the bodies and freezes the headers; `CaptureEncoder` redacts, serializes and
compresses on its own thread and hands rows to the batch writer. These tests pin the queue bounds (count and
bytes), that a failure never stops the thread, that `drain` and `close` wait for queued work, that the thread ends
when idle and comes back, and what the recorder does when the queue is full.
"""

from __future__ import annotations

import asyncio
import threading
import time
from collections.abc import Callable
from typing import Any

import pytest

from roxy.metrics import capture
from roxy.metrics.capture import CaptureEncoder, CaptureInput, CapturePolicy, CaptureRow, build_record, trim_input
from roxy.metrics.recorder import MetricsRecorder, OutcomeEvent

POLICY = CapturePolicy(max_body=1024)


def _input(n: int = 0, **fields: Any) -> CaptureInput:
    return CaptureInput(request_id=f"REQ{n}", at_ms=1_760_000_000_000, outcome="refused", status=404, **fields)


def test_trim_input_cuts_bodies_and_keeps_their_lengths() -> None:
    headers = {"Cookie": "a=b", "Accept": "json"}
    trimmed = trim_input(_input(request_body=b"x" * 5000, response_body="y" * 10, request_headers=headers), POLICY)
    assert trimmed.request_body == b"x" * 1024
    assert trimmed.request_body_length == 5000
    assert trimmed.response_body == b"y" * 10
    assert trimmed.response_body_length is None
    assert trimmed.request_headers == (("Cookie", "a=b"), ("Accept", "json"))  # frozen: the loop may change the dict
    record = build_record(trimmed, POLICY)
    assert record["request_body_truncated"] is True
    assert record["request_body_length"] == 5000  # the length the caller sent, not the cut length
    assert record["response_body_truncated"] is False
    assert record["request_headers"]["Cookie"] == "[redacted]"
    assert record == build_record(_input(request_body=b"x" * 5000, response_body="y" * 10, request_headers=headers),
                                  POLICY)  # fmt: skip


def test_trim_with_zero_max_body_keeps_no_text() -> None:
    trimmed = trim_input(_input(request_body=b"abc"), CapturePolicy(max_body=0))
    record = build_record(trimmed, CapturePolicy(max_body=0))
    assert (record["request_body"], record["request_body_truncated"], record["request_body_length"]) == ("", True, 3)


class Gate:
    """An `encode` function that blocks until released, so the queue can be filled deterministically."""

    def __init__(self) -> None:
        self.release = threading.Event()
        self.threads: set[str] = set()

    def __call__(self, inp: CaptureInput, policy: CapturePolicy) -> CaptureRow:
        self.threads.add(threading.current_thread().name)
        self.release.wait(10)
        return capture.make_row(inp, policy)


def test_queue_is_bounded_by_count_and_drops_without_waiting() -> None:
    rows: list[CaptureRow] = []
    gate = Gate()
    encoder = CaptureEncoder(rows.append, encode=gate, max_items=3)
    started = time.monotonic()
    accepted = [encoder.submit(trim_input(_input(n), POLICY), POLICY) for n in range(10)]
    assert time.monotonic() - started < 1.0  # never waits for the busy thread
    # One is being built (taken off the queue), three wait, the rest are dropped and counted.
    assert accepted.count(True) in (3, 4)
    assert encoder.dropped == accepted.count(False)
    gate.release.set()
    assert encoder.close(5.0)
    assert len(rows) == accepted.count(True)
    assert gate.threads == {"roxy-capture-encoder"}  # built on the encoder thread, never the caller's


def test_queue_is_bounded_by_bytes() -> None:
    gate = Gate()
    encoder = CaptureEncoder(lambda row: None, encode=gate, max_items=100, max_bytes=8 * 1024)
    big = trim_input(_input(request_body=b"z" * 1024, response_body=b"z" * 1024), POLICY)
    accepted = [encoder.submit(big, POLICY) for _ in range(10)]
    assert 0 < accepted.count(True) < 10
    gate.release.set()
    encoder.close(5.0)


def test_a_failing_capture_is_counted_and_the_thread_goes_on() -> None:
    rows: list[CaptureRow] = []
    errors: list[BaseException] = []

    def encode(inp: CaptureInput, policy: CapturePolicy) -> CaptureRow:
        if inp.request_id == "REQ1":
            raise RuntimeError("bad capture")
        return capture.make_row(inp, policy)

    encoder = CaptureEncoder(rows.append, encode=encode, on_error=errors.append)
    for n in range(3):
        assert encoder.submit(trim_input(_input(n), POLICY), POLICY)
    assert encoder.close(5.0)
    assert [row.request_id for row in rows] == ["REQ0", "REQ2"]
    assert encoder.failed == 1
    assert len(errors) == 1
    assert encoder.stats()["encoded"] == 2


async def test_drain_waits_for_queued_captures_without_blocking_the_loop() -> None:
    rows: list[CaptureRow] = []
    gate = Gate()
    encoder = CaptureEncoder(rows.append, encode=gate)
    encoder.submit(trim_input(_input(1), POLICY), POLICY)
    ticks = 0

    async def ticker() -> None:
        nonlocal ticks
        while True:
            ticks += 1
            await asyncio.sleep(0.005)

    task = asyncio.create_task(ticker())
    assert await encoder.drain(0.2) is False  # still blocked: gives up at its timeout
    assert ticks >= 5  # the loop kept running while drain waited
    gate.release.set()
    assert await encoder.drain(5.0) is True
    task.cancel()
    assert len(rows) == 1
    encoder.close()


def test_idle_thread_ends_and_a_new_capture_starts_it_again(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(capture, "ENCODER_IDLE_EXIT_S", 0.05)
    rows: list[CaptureRow] = []
    encoder = CaptureEncoder(rows.append)
    assert encoder._thread is None  # nothing captured yet: no thread
    encoder.submit(trim_input(_input(1), POLICY), POLICY)
    deadline = time.monotonic() + 5
    while encoder._thread is not None and time.monotonic() < deadline:
        time.sleep(0.02)
    assert encoder._thread is None
    assert len(rows) == 1
    encoder.submit(trim_input(_input(2), POLICY), POLICY)
    assert encoder.close(5.0)
    assert len(rows) == 2


def test_closed_encoder_refuses_new_captures() -> None:
    encoder = CaptureEncoder(lambda row: None)
    encoder.close()
    assert encoder.submit(trim_input(_input(1), POLICY), POLICY) is False
    assert encoder.dropped == 1


async def test_recorder_drops_and_counts_when_the_encoder_is_full(
    recorder: MetricsRecorder,
    make_event: Callable[..., OutcomeEvent],
    presets: dict[str, Any],
    metrics_rows: Callable[..., list[tuple[Any, ...]]],
) -> None:
    gate = Gate()
    recorder.captures = CaptureEncoder(lambda row: recorder.batch.add("metrics.captures", row), encode=gate,
                                       max_items=1)  # fmt: skip
    ids = []
    for n in range(4):
        ev = make_event(request_id=f"R{n}", **presets["refused"])
        ids.append(recorder.record_outcome(ev, capture=CaptureInput(request_id=f"R{n}", at_ms=ev.at_ms)))
        if n == 0:
            # Let the thread take R0 (it then blocks in the gate), so the queue is empty again. The queue is
            # filled by another thread, so polling is the simple way to wait for it here.
            deadline = time.monotonic() + 5
            while recorder.captures._queue and time.monotonic() < deadline:  # noqa: ASYNC110
                await asyncio.sleep(0.005)
    assert ids[:2] == ["R0", "R1"]  # one being built, one queued
    assert ids[2:] == ["", ""]  # dropped: no capture id on the Live row, and the request was not held up
    assert recorder.capture_dropped == 2
    assert recorder.stats()["capture_dropped"] == 2
    gate.release.set()
    await recorder.flush()
    assert metrics_rows("SELECT count(*) FROM captures") == [(2,)]
    assert metrics_rows("SELECT sum(requests) FROM rollup_minute") == [(4,)]
    recorder.close()
