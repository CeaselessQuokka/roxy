"""Egress accounting: per-request byte usage, handed to the metrics recorder (plan 8.3).

What this is
    `EgressUsage` (one upstream call's bytes on one egress) and `UsageAccountant`, which receives one usage per call
    from `EgressClients.send`, keeps running totals per egress, and hands each usage to
    `ctx.recorder.record_egress_usage(usage)` when the recorder has that method. Until it does (the recorder is
    built in a later phase, or is briefly missing), usages wait in a bounded in-memory buffer.

Why it exists
    The rotator is billed per byte: the monthly quota, the daily cap, the budget alerts and the cost projection
    all start from these numbers. The same counts for `direct` and `credential` show the server's own transfer.
    Writing them is the metrics pipeline's job (one batched writer per worker, plan 6.3), so this module only
    produces them and never touches a database on the request path.

How it works
    `record(usage)` updates the totals, notifies listeners (the rotator budget adds rotator bytes to its local
    count at once, so a worker stops at the cap without waiting for a flush), then hands the usage to the
    recorder or buffers it. The buffer is a deque with a fixed maximum (plan P9); when full, the oldest usage is
    dropped and counted. `drain()` returns and clears the buffer (a recorder that starts late can take it), and
    `aggregate_minutes` folds usages into `egress_usage` minute rows `(bucket_start, egress) -> counts`.
    In socket metering mode `req_bytes`/`resp_bytes` are wire bytes and `overhead_bytes` is 0 (the handshake is
    already inside the wire counts); in estimate mode `overhead_bytes` holds the per-connection estimate.

What to read next
    `roxy/egress/metering.py` (where the numbers come from) and `roxy/egress/rotator.py` (the budget).
"""

from __future__ import annotations

import logging
from collections import deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

from roxy.core.reasons import Egress

log = logging.getLogger("roxy.egress.accounting")

DEFAULT_BUFFER_MAX = 10_000
"""Usages kept while no recorder takes them (about 1.5 MB at most)."""

_MAX_LISTENERS = 8


@dataclass(frozen=True, slots=True)
class EgressUsage:
    """Bytes one upstream call used on one egress (all redirect hops together)."""

    at_ms: int
    egress: Egress
    purpose: str
    session_id: str | None
    req_bytes: int
    resp_bytes: int
    overhead_bytes: int
    new_connections: int
    method: str
    status: int | None
    requests: int = 1

    @property
    def total_bytes(self) -> int:
        return self.req_bytes + self.resp_bytes + self.overhead_bytes


@dataclass(slots=True)
class EgressTotals:
    """Running totals for one egress in this worker since start."""

    requests: int = 0
    req_bytes: int = 0
    resp_bytes: int = 0
    overhead_bytes: int = 0
    new_connections: int = 0
    failed: int = 0


class UsageAccountant:
    """Receives per-request usage (see the module docstring)."""

    def __init__(self, recorder: Callable[[], Any], *, buffer_max: int = DEFAULT_BUFFER_MAX) -> None:
        self._recorder = recorder
        self._buffer: deque[EgressUsage] = deque(maxlen=max(1, buffer_max))
        self._totals: dict[Egress, EgressTotals] = {}
        self._listeners: list[Callable[[EgressUsage, bool], None]] = []
        self.dropped = 0
        self.handed_off = 0

    def add_listener(self, listener: Callable[[EgressUsage, bool], None]) -> None:
        """Call `listener(usage, handed_off)` for every recorded usage; `handed_off` says the recorder took it
        (bounded: a few internal listeners only)."""
        if len(self._listeners) >= _MAX_LISTENERS:
            raise RuntimeError("too many usage listeners")
        self._listeners.append(listener)

    def record(self, usage: EgressUsage) -> None:
        """Account one call. Never raises: accounting must not fail a request."""
        totals = self._totals.setdefault(usage.egress, EgressTotals())
        totals.requests += usage.requests
        totals.req_bytes += usage.req_bytes
        totals.resp_bytes += usage.resp_bytes
        totals.overhead_bytes += usage.overhead_bytes
        totals.new_connections += usage.new_connections
        if usage.status is None:
            totals.failed += 1
        handed_off = False
        handler = getattr(self._recorder(), "record_egress_usage", None)
        if callable(handler):
            try:
                handler(usage)
            except Exception:
                log.exception("record_egress_usage_failed")
            else:
                handed_off = True
                self.handed_off += 1
        if not handed_off:
            if len(self._buffer) == self._buffer.maxlen:
                self.dropped += 1
            self._buffer.append(usage)
        for listener in self._listeners:
            try:
                listener(usage, handed_off)
            except Exception:
                log.exception("usage_listener_failed")

    def drain(self) -> list[EgressUsage]:
        """Return and clear the buffered usages (oldest first)."""
        items = list(self._buffer)
        self._buffer.clear()
        return items

    @property
    def buffered(self) -> int:
        return len(self._buffer)

    def totals(self) -> dict[str, dict[str, int]]:
        """Totals per egress for the Egress and System pages."""
        return {
            egress.value: {
                "requests": item.requests,
                "req_bytes": item.req_bytes,
                "resp_bytes": item.resp_bytes,
                "overhead_bytes": item.overhead_bytes,
                "new_connections": item.new_connections,
                "failed": item.failed,
            }
            for egress, item in self._totals.items()
        }


def aggregate_minutes(usages: Iterable[EgressUsage]) -> dict[tuple[int, str], dict[str, int]]:
    """Fold usages into `egress_usage` minute rows: `(bucket_start_s, egress) -> {requests, req_bytes, ...}`."""
    rows: dict[tuple[int, str], dict[str, int]] = {}
    for usage in usages:
        bucket = (usage.at_ms // 60_000) * 60
        row = rows.setdefault(
            (bucket, usage.egress.value), {"requests": 0, "req_bytes": 0, "resp_bytes": 0, "overhead_bytes": 0}
        )
        row["requests"] += usage.requests
        row["req_bytes"] += usage.req_bytes
        row["resp_bytes"] += usage.resp_bytes
        row["overhead_bytes"] += usage.overhead_bytes
    return rows


__all__ = ["DEFAULT_BUFFER_MAX", "EgressTotals", "EgressUsage", "UsageAccountant", "aggregate_minutes"]
