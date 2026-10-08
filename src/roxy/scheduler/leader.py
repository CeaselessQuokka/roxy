"""Leader election: exactly one worker in the whole fleet (both colors) runs the scheduled jobs.

What this is
    `LeaderElector` keeps trying to hold the `leader` lease in hot.db. `LeaderState` says whether this worker is
    the leader and under which epoch. `JobContext` is what a leader job receives: the epoch it started under and
    the means to prove, right before writing, that it is still the leader (`assert_still_leader`,
    `fenced_write`), plus `claim` for idempotency keys in `job_runs`.

Why it exists
    Plan 5.6 and C6: rollups, retention, probes and alert digests must run once for the fleet. Workers come and
    go (crashes, `max_requests` recycling, blue/green deploys), so "the first worker" cannot be the leader. A
    lease with an expiry is: whoever holds it leads, it renews every 5 s with a 15 s TTL, and when the leader
    dies the lease expires and another worker takes over within 15 s. Because hot.db is shared by both colors,
    there is exactly one leader across blue and green during a deploy.

How it works
    - Each tick: the leader renews; a follower tries `acquire`, which succeeds only once the lease has expired,
      and then increments the epoch (the fencing token). A follower sleeps until the current lease would expire
      (at most 5 s), so a takeover happens right after expiry.
    - Fencing: a leader whose process stalls past its lease (a long GC pause, SIGSTOP, a frozen VM) still
      *believes* it leads when it resumes. Every leader write therefore checks, inside the writing transaction,
      that the lease still names this holder and epoch; if a takeover happened, `LostLeadership` is raised and
      the write rolls back. `fenced_write` does this for any database:
        * on hot.db the check runs inside the same transaction, which holds hot.db's write lock, and a takeover
          needs that lock: nobody can take over between the check and the COMMIT, however long a stall lasts;
        * on the other files the check is a hot.db read made right before COMMIT, while the target file's write
          lock is held. A takeover is possible in between, so the check also requires the lease to have at
          least `FENCE_MARGIN_S` left: after a passing check a takeover can only happen if the process then
          stalls for longer than that margin, inside that one transaction. Even then the late COMMIT cannot
          overwrite anything the new leader wrote to that file: the new leader's own write needs the same file
          lock, so it waits until the stalled transaction ends and lands after it, and every later write of the
          old leader fails its check (the lease names the new holder).
      Non-idempotent work also claims a `job_runs` key in hot.db first (`claim`), so it never runs twice.
    - Leadership changes are logged as events (`leadership_acquired`, `leadership_lost`, `leadership_released`)
      and passed to an optional callback, which the lifespan uses to add them to the event stream.

What to read next
    `roxy/storage/leases.py` (the lease functions), then `roxy/scheduler/jobs.py` (what the leader runs).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import random
import sqlite3
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, replace
from typing import TypeVar

from roxy.core.clock import SYSTEM_CLOCK, Clock
from roxy.storage import leases
from roxy.storage.db import Database, SharedStateUnavailable

log = logging.getLogger(__name__)

T = TypeVar("T")

LEADER_LEASE = "leader"
LEADER_TTL_S = 15.0
"""A leader that stops renewing loses the lease after 15 s (plan 5.6)."""

LEADER_RENEW_S = 5.0
"""The leader renews every 5 s, so two renewals can fail before the lease is at risk."""

TAKEOVER_JITTER_S = 0.1
"""Followers wake up to this much after the expiry, at random, so they do not all hit the database at once."""

FENCE_MARGIN_S = LEADER_RENEW_S
"""A fenced write to a file other than hot.db needs at least this much lease left (see the module docstring).
A healthy leader always has 10 to 15 s left; less means two renewals in a row failed, and the leader drops out
at that point anyway (`_on_unavailable`)."""


class LostLeadership(Exception):
    """This worker is not (or no longer) the leader under the epoch the job started with. Nothing was written."""


@dataclass(frozen=True, slots=True)
class LeaderState:
    """This worker's view of the leadership. `epoch` is the fencing token of the lease it holds (0 if none)."""

    is_leader: bool = False
    epoch: int = 0
    holder: str = ""
    since: float | None = None
    expires_ms: int = 0
    last_error: str | None = None
    changes: int = 0


@dataclass(frozen=True, slots=True)
class JobContext:
    """Passed to every job run. `epoch` and `now` are fixed when the run starts.

    Leader jobs must prove they still lead before each write: use `fenced_write(db, fn)`, or call
    `assert_still_leader(conn)` on a hot.db connection inside your own hot.db transaction. Per-worker jobs get a
    context with `epoch == 0` and must not use the fencing helpers.
    """

    epoch: int
    now: float
    holder: str = ""
    hot: Database | None = None
    job_name: str = ""
    lease_name: str = LEADER_LEASE
    clock: Clock | None = None  # for the lease-margin check of fenced writes to other files (SYSTEM_CLOCK if None)
    fence_margin_ms: int = int(FENCE_MARGIN_S * 1000)

    def assert_still_leader(self, conn: sqlite3.Connection) -> None:
        """Raise `LostLeadership` unless lease `leader` in hot.db still names this holder and epoch.

        Call it on a hot.db connection. Inside a write transaction nobody can take the lease over between this
        check and your COMMIT, because a takeover needs the same write lock.
        """
        current = leases.holder_epoch(conn, self.lease_name)
        if current is None or current[0] != self.holder or current[1] != self.epoch:
            raise LostLeadership(
                f"job {self.job_name or '?'}: leader lease is now {current[:2] if current else None}, "
                f"this run started as {(self.holder, self.epoch)}"
            )

    def assert_still_leader_with_margin(self, conn: sqlite3.Connection) -> None:
        """`assert_still_leader`, and the lease must also have at least `fence_margin_ms` left.

        For checks that do NOT run inside a hot.db write transaction (fenced writes to the other files): a
        takeover can only follow such a check after the lease expired, so the margin bounds how long a stall
        between this check and the COMMIT would have to be for a takeover to slip in (module docstring).
        """
        self.assert_still_leader(conn)
        current = leases.holder_epoch(conn, self.lease_name)
        now_ms = (self.clock or SYSTEM_CLOCK).now_ms()
        if current is None or current[2] - now_ms < self.fence_margin_ms:
            left = None if current is None else max(0, current[2] - now_ms)
            raise LostLeadership(
                f"job {self.job_name or '?'}: leader lease has {left} ms left, below the "
                f"{self.fence_margin_ms} ms fencing margin for writes outside hot.db"
            )

    def _hot(self) -> Database:
        if self.hot is None or self.epoch <= 0:
            raise LostLeadership("this job context has no leader lease (per-worker job)")
        return self.hot

    async def check(self) -> None:
        """Read the lease and raise `LostLeadership` if leadership changed since this run started."""
        await self._hot().read(self.assert_still_leader)

    async def fenced_write(self, db: Database, fn: Callable[[sqlite3.Connection], T], *, immediate: bool = True) -> T:
        """`db.write(fn)`, but the transaction commits only if this run's leadership is still current.

        On hot.db the check runs first, in the same transaction. On another database it runs after `fn`, while
        that database's write lock is held, using a hot.db read on the same thread, and it also requires
        `fence_margin_ms` of lease left; the only thing between the check and the COMMIT is the COMMIT itself.
        """
        hot = self._hot()
        if db is hot or db.path == hot.path:

            def fenced_hot(conn: sqlite3.Connection) -> T:
                self.assert_still_leader(conn)
                return fn(conn)

            return await db.write(fenced_hot, immediate=immediate)

        def fenced_other(conn: sqlite3.Connection) -> T:
            result = fn(conn)
            hot.read_sync(self.assert_still_leader_with_margin)
            return result

        return await db.write(fenced_other, immediate=immediate)

    def idem_key(self, bucket: str | int) -> str:
        """`job:<name>:<bucket>`, the idempotency key of one run of this job (plan 5.6)."""
        return f"job:{self.job_name}:{bucket}"

    async def claim(self, bucket: str | int, *, retry_unfinished_after_s: float | None = None) -> bool:
        """Record `job:<name>:<bucket>` in `job_runs` before a non-idempotent action. False means a run for this
        bucket already happened (or is running), so this one must do nothing.

        With `retry_unfinished_after_s`, a claim whose run started that long ago and never finished (its leader
        crashed mid-run) may be taken over. The default is at-most-once.
        """
        key = self.idem_key(bucket)
        started = int(self.now)

        def do_claim(conn: sqlite3.Connection) -> bool:
            self.assert_still_leader(conn)
            cur = conn.execute(
                "INSERT INTO job_runs (idem_key, epoch, started_at) VALUES (?, ?, ?) ON CONFLICT (idem_key) DO NOTHING",
                (key, self.epoch, started),
            )
            if cur.rowcount == 1:
                return True
            if retry_unfinished_after_s is None:
                return False
            cur = conn.execute(
                "UPDATE job_runs SET epoch = ?, started_at = ? "
                "WHERE idem_key = ? AND finished_at IS NULL AND started_at < ?",
                (self.epoch, started, key, int(self.now - retry_unfinished_after_s)),
            )
            return cur.rowcount == 1

        return await self._hot().write(do_claim)

    async def finish(self, bucket: str | int) -> None:
        """Mark this run's idempotency key as finished."""
        key = self.idem_key(bucket)
        finished = int(self.now)

        def do_finish(conn: sqlite3.Connection) -> None:
            conn.execute(
                "UPDATE job_runs SET finished_at = max(?, started_at) WHERE idem_key = ? AND epoch = ?",
                (finished, key, self.epoch),
            )

        await self._hot().write(do_finish)


LeadershipCallback = Callable[[str, LeaderState], Awaitable[None] | None]
"""Called with ("acquired" | "lost" | "released", new state) after every leadership change."""


class LeaderElector:
    """Holds (or keeps trying to hold) the `leader` lease for one worker. Run `run(stop)` as a background task."""

    def __init__(
        self,
        hot: Database,
        holder: str,
        clock: Clock | None = None,
        *,
        ttl_s: float = LEADER_TTL_S,
        renew_s: float = LEADER_RENEW_S,
        lease_name: str = LEADER_LEASE,
        on_change: LeadershipCallback | None = None,
        jitter_s: float = TAKEOVER_JITTER_S,
    ) -> None:
        if renew_s * 2 > ttl_s:
            # Renewing less often than twice per TTL means one slow renewal loses the lease.
            raise ValueError("renew_s must be at most half of ttl_s")
        self.hot = hot
        self.holder = holder
        self.clock = clock or SYSTEM_CLOCK
        self.ttl_ms = int(ttl_s * 1000)
        self.renew_s = renew_s
        self.lease_name = lease_name
        self.on_change = on_change
        self.jitter_s = jitter_s
        self._state = LeaderState(holder=holder)

    @property
    def state(self) -> LeaderState:
        return self._state

    @property
    def is_leader(self) -> bool:
        return self._state.is_leader

    def job_context(self, job_name: str = "") -> JobContext:
        """A context for one leader job run. Raises `LostLeadership` if this worker is not the leader."""
        state = self._state
        if not state.is_leader:
            raise LostLeadership(f"{self.holder} is not the leader")
        return JobContext(
            epoch=state.epoch,
            now=self.clock.now(),
            holder=self.holder,
            hot=self.hot,
            job_name=job_name,
            lease_name=self.lease_name,
            clock=self.clock,
            fence_margin_ms=min(int(FENCE_MARGIN_S * 1000), self.ttl_ms // 3),
        )

    async def tick(self) -> float:
        """One election step. Returns how many seconds to wait before the next one."""
        try:
            if self._state.is_leader:
                if await self._renew():
                    return self.renew_s
                await self._set(
                    replace(self._state, is_leader=False, last_error="renew refused"), "lost", reason="lease_lost"
                )
            grant, current = await self.hot.write(self._try_acquire)
        except SharedStateUnavailable as exc:
            return await self._on_unavailable(exc)
        if grant is not None:
            await self._set(
                LeaderState(
                    is_leader=True,
                    epoch=grant.epoch,
                    holder=self.holder,
                    since=self.clock.now(),
                    expires_ms=grant.expires_ms,
                    changes=self._state.changes + 1,
                ),
                "acquired",
                reason="takeover" if grant.taken_over else "reacquired",
                previous=current,
            )
            return self.renew_s
        # Somebody else leads: wake up right after their lease would expire (but at least every renew_s).
        wait = self.renew_s
        if current is not None:
            remaining = (current[2] - self.clock.now_ms()) / 1000
            wait = min(self.renew_s, max(0.0, remaining) + random.uniform(0.0, self.jitter_s))
        return max(0.05, wait)

    def _try_acquire(self, conn: sqlite3.Connection) -> tuple[leases.LeaseGrant | None, tuple[str, int, int] | None]:
        previous = leases.holder_epoch(conn, self.lease_name)
        # The time is read inside the transaction, after the write lock was granted, so a slow queue cannot make
        # this worker act on a stale "now".
        grant = leases.acquire(conn, self.lease_name, self.holder, self.ttl_ms, self.clock.now_ms())
        return grant, (previous if grant is not None else leases.holder_epoch(conn, self.lease_name))

    async def _renew(self) -> bool:
        epoch = self._state.epoch

        def do_renew(conn: sqlite3.Connection) -> int | None:
            now_ms = self.clock.now_ms()
            if leases.renew(conn, self.lease_name, self.holder, self.ttl_ms, now_ms, epoch=epoch):
                return now_ms + self.ttl_ms
            return None

        expires = await self.hot.write(do_renew)
        if expires is None:
            return False
        self._state = replace(self._state, expires_ms=expires, last_error=None)
        return True

    async def _on_unavailable(self, exc: SharedStateUnavailable) -> float:
        """hot.db is unavailable: keep leading only while the last confirmed lease is surely still valid."""
        state = self._state
        log.warning("leader_tick_unavailable", extra={"fields": {"holder": self.holder, "error": str(exc)}})
        margin_ms = int(self.renew_s * 1000)
        if state.is_leader and self.clock.now_ms() >= state.expires_ms - margin_ms:
            await self._set(replace(state, is_leader=False, last_error=str(exc)), "lost", reason="unconfirmed")
        else:
            self._state = replace(state, last_error=str(exc))
        return min(self.renew_s, 1.0)

    async def release(self) -> None:
        """Give the lease up (clean shutdown) so another worker can take over at its next tick."""
        if not self._state.is_leader:
            return
        try:
            await self.hot.write(lambda conn: leases.release(conn, self.lease_name, self.holder))
        except SharedStateUnavailable as exc:
            log.warning("leader_release_failed", extra={"fields": {"holder": self.holder, "error": str(exc)}})
        await self._set(replace(self._state, is_leader=False), "released", reason="shutdown")

    async def run(self, stop: asyncio.Event) -> None:
        """Tick until `stop` is set, then release the lease."""
        try:
            while not stop.is_set():
                try:
                    wait = await self.tick()
                except Exception:
                    log.exception("leader_tick_failed", extra={"fields": {"holder": self.holder}})
                    wait = 1.0
                with contextlib.suppress(TimeoutError):  # the normal case: no stop request before the next tick
                    await asyncio.wait_for(stop.wait(), timeout=wait)
        finally:
            await self.release()

    async def _set(
        self, state: LeaderState, event: str, *, reason: str, previous: tuple[str, int, int] | None = None
    ) -> None:
        self._state = state
        fields: dict[str, object] = {"holder": self.holder, "epoch": state.epoch, "reason": reason}
        if previous is not None:
            fields["previous_holder"] = previous[0]
            fields["previous_epoch"] = previous[1]
        log.info(f"leadership_{event}", extra={"fields": fields})
        if self.on_change is None:
            return
        try:
            result = self.on_change(event, state)
            if result is not None:
                await result
        except Exception:
            log.exception("leadership_callback_failed", extra={"fields": {"event": event}})
