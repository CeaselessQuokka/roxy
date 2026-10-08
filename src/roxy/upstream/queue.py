"""Priority classes and the per-worker wait queue: who may wait for an upstream slot, and who is dropped first.

What this is
    `Priority`, the five request classes of plan 7.8 (callers first, Roxy's own probes last), the setting that
    holds each class's maximum queue wait, and `WaitQueue`, a bounded list of the requests in this worker that hold
    a bucket reservation and are sleeping until their slot time.

Why it exists
    Fairness across workers does not come from this queue: it comes from the reservation horizon in
    `buckets.reserve` (an interactive caller may book a slot up to 4 s ahead, a background refresh only when the
    global bucket is under half used). What one worker still needs is a bound (plan P9: `queue_max_length`, 500
    per worker) and a rule for who loses under pressure. v1 had neither: 16 threads simply blocked.

How it works
    `enter(priority)` admits a waiter while there is room. When the queue is full, the newcomer may evict a
    waiter that is more expendable than itself, following `CANCEL_ORDER`: background refreshes go first (the
    caller already got a stale answer), then interactive requests that have a stale copy to fall back to, then
    internal probes, then admin actions; an interactive request without a fallback is never evicted. Within one
    class the newest waiter goes first (the oldest is closest to its slot). An evicted waiter's `wait()` returns
    False; its caller refunds the reservation and answers `queue_overflow` (or serves stale). A newcomer that
    cannot evict anyone is refused the same way.

What to read next
    `roxy/upstream/buckets.py` (the reservation a waiter holds) and `roxy/upstream/service.py` (`_wait_for_slot`).
"""

from __future__ import annotations

import asyncio
import contextlib
import itertools
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from enum import IntEnum
from types import MappingProxyType
from typing import Final


class Priority(IntEnum):
    """Request classes of plan 7.8 (lower value = more important)."""

    INTERACTIVE = 0  # caller miss with no stale fallback
    INTERACTIVE_STALE = 1  # caller miss that can be answered from stale instead
    BACKGROUND = 2  # stale-while-revalidate refresh
    ADMIN = 3  # admin lookups and cache refreshes
    INTERNAL = 4  # Roxy's own probes and health checks


QUEUE_WAIT_SETTING: Final[Mapping[Priority, str]] = MappingProxyType(
    {
        Priority.INTERACTIVE: "queue_wait_interactive_ms",
        Priority.INTERACTIVE_STALE: "queue_wait_stale_ms",
        Priority.BACKGROUND: "queue_wait_background_ms",
        Priority.ADMIN: "queue_wait_admin_ms",
        Priority.INTERNAL: "queue_wait_internal_ms",
    }
)
"""The catalog setting holding each class's maximum queue wait in milliseconds (plan 15.3 C)."""

CANCEL_ORDER: Final[tuple[Priority, ...]] = (
    Priority.BACKGROUND,
    Priority.INTERACTIVE_STALE,
    Priority.INTERNAL,
    Priority.ADMIN,
    Priority.INTERACTIVE,
)
"""Who is evicted first when the queue is full (plan 7.8: "background work is canceled; callers get stale")."""

_RANK: Final[Mapping[Priority, int]] = MappingProxyType({priority: rank for rank, priority in enumerate(CANCEL_ORDER)})

SleepFn = Callable[[float], Awaitable[None]]


@dataclass(eq=False, slots=True)
class QueueTicket:
    """One waiter. `evicted` is set when a more important newcomer took its place."""

    priority: Priority
    seq: int
    evicted: asyncio.Event = field(default_factory=asyncio.Event)


class WaitQueue:
    """The bounded set of this worker's requests that are sleeping until their reserved slot time."""

    def __init__(self, max_length: int | Callable[[], int]) -> None:
        self._max_length = max_length
        self._waiting: dict[Priority, dict[int, QueueTicket]] = {priority: {} for priority in Priority}
        self._seq = itertools.count()
        self.refused = 0  # newcomers turned away (queue_overflow)
        self.evicted = 0  # waiters dropped to make room

    def limit(self) -> int:
        """The current cap (a live setting when given as a callable)."""
        value = self._max_length() if callable(self._max_length) else self._max_length
        return max(1, int(value))

    def __len__(self) -> int:
        return sum(len(group) for group in self._waiting.values())

    def counts(self) -> dict[str, int]:
        """Waiters per class, for the Upstream page queue card."""
        return {priority.name.lower(): len(group) for priority, group in self._waiting.items()}

    def enter(self, priority: Priority) -> QueueTicket | None:
        """Admit a waiter of `priority`, evicting a more expendable one if full; None when refused."""
        if len(self) >= self.limit() and not self._evict_for(priority):
            self.refused += 1
            return None
        ticket = QueueTicket(priority, next(self._seq))
        self._waiting[priority][ticket.seq] = ticket
        return ticket

    def leave(self, ticket: QueueTicket) -> None:
        """Remove a waiter (its slot time came, it was evicted, or it was canceled). Safe to call twice."""
        self._waiting[ticket.priority].pop(ticket.seq, None)

    def _evict_for(self, newcomer: Priority) -> bool:
        newcomer_rank = _RANK[newcomer]
        for victim_class in CANCEL_ORDER:
            if _RANK[victim_class] >= newcomer_rank:
                return False  # nobody left who is more expendable than the newcomer
            group = self._waiting[victim_class]
            if group:
                seq = next(reversed(group))  # the newest waiter of the most expendable class
                victim = group.pop(seq)
                victim.evicted.set()
                self.evicted += 1
                return True
        return False  # pragma: no cover - the loop always returns

    async def wait(self, ticket: QueueTicket, seconds: float, sleep: SleepFn = asyncio.sleep) -> bool:
        """Sleep `seconds` (until the reserved slot). True when the slot time came, False when evicted.

        The ticket leaves the queue in every case, including cancellation (caller gone, deadline hit).
        """
        if ticket.evicted.is_set():
            self.leave(ticket)
            return False
        sleeper = asyncio.ensure_future(sleep(max(0.0, seconds)))
        eviction = asyncio.ensure_future(ticket.evicted.wait())
        try:
            await asyncio.wait({sleeper, eviction}, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for future in (sleeper, eviction):
                if not future.done():
                    future.cancel()
            for future in (sleeper, eviction):
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await future
            self.leave(ticket)
        return not ticket.evicted.is_set()


__all__ = ["CANCEL_ORDER", "QUEUE_WAIT_SETTING", "Priority", "QueueTicket", "SleepFn", "WaitQueue"]
