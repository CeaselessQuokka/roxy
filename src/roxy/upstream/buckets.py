"""GCRA token buckets in hot.db: pacing every upstream call, shared by all workers, reserved atomically.

What this is
    The Generic Cell Rate Algorithm (GCRA) math, the bucket keys and their rates (global, per egress, per Roblox
    host, per endpoint template, plan 7.3), and `reserve`, which takes one slot in every bucket an upstream call
    needs inside ONE hot.db write transaction (together with the single-flight lease, the cooldown and breaker
    re-checks, and the AIMD slot when that Tier 3 option is on). `refund` gives a slot back when a request is
    canceled before its slot time. Host and endpoint buckets are window buckets (`per_min` caps every rolling
    minute) and keep a `WindowMeter` of the calls they granted, read after a Roblox 429 (`observed_calls`).

Why it exists
    v1's "token budget" was a count of 95 calls per 65 s: all 95 could fire within one second from 16 threads,
    exactly the burst shape Roblox punishes (plan 2.5, R2), and nothing capped the total per Roblox host or
    endpoint (R7). GCRA paces calls smoothly with a small allowed burst and needs one number per bucket.

How it works
    A bucket has a rate (`per_min`) and a burst. `interval = 60000 / per_min` ms is the spacing between calls at
    the steady rate, and `tolerance = (burst - 1) x interval` is how far ahead of the schedule a burst may run.
    The only state is TAT, the "theoretical arrival time" of the next call if calls came exactly at the rate.
    A call is allowed at time `now` when `now >= TAT - tolerance`; it then moves `TAT = max(TAT, now) + interval`.

    Worked example: a plain bucket (the plan 7.3 formula, as the global and egress buckets use it) of 120 per
    minute, burst 10. interval = 500 ms, tolerance = 9 x 500 = 4500 ms.
      - The row does not exist yet, which means TAT = 0 (long past): the bucket is full.
      - At now = 10,000 ms a call arrives. Earliest allowed = max(now, TAT - tolerance) = 10,000: it goes at once,
        and TAT becomes max(0, 10,000) + 500 = 10,500.
      - Nine more calls arrive at the same instant. Before the k-th of them TAT = 10,000 + 500k, so
        TAT - tolerance = 5,500 + 500k, which is at most 10,000 for k up to 9: all nine go. TAT is now 15,000.
      - An 11th call at 10,000: earliest = 15,000 - 4,500 = 10,500, so it must wait 500 ms (one interval). From
        here on calls are spaced 500 ms apart: exactly 120 per minute.
      - After 5 s of silence (now = 20,000) TAT = 15,000 lies in the past: the full burst of 10 is available again.
    There is no window that resets (no "cliff" where 2 x limit calls fit around a window edge), and the wall
    clock stepping back a little (WSL does that) only makes `max(TAT, now)` keep the later value.

    Window buckets (host and endpoint keys): plain GCRA lets `per_min + burst - 1` calls into one rolling minute
    (a full burst, then the steady pace: 129 for 120 per minute and burst 10). Roblox counts calls per endpoint in
    a rolling window, so for the buckets that stand for Roblox's own limits (`host:` and `endpoint:`, configured or
    learned from a 429) `per_min` is the most calls any rolling minute may hold: the rate plus the burst must fit
    inside one window. With N = per_min rounded down and B = min(burst, N), the spacing becomes
    `interval = (window + margin) / (N - B + 1)`, so B calls may still leave back to back, but any span of 60 s
    (and any rolling window of 61 s) holds at most N calls: a GCRA stream fits at most
    `1 + floor((T + tolerance) / interval)` calls into a span of length T, and with this interval that is N for
    T = 60 s. The 1 s margin covers the gap between Roxy's slot times and Roblox's arrival times. Worked example:
    120 per minute, burst 10: interval = 61,000 / 111 = 549.5 ms, so 10 at once and then 109 per minute, never
    more than 120 in any minute. The global and egress buckets are Roxy's own ceilings and keep the plain formula
    of plan 7.3.

    Measuring (window buckets): the reservation also counts each granted call, at its slot time, in a small
    sliding window counter per key (`WindowMeter`, a `meter:<key>` row in the same table: the current window's
    start, its count, and the previous window's count). After a Roblox 429, `observed_calls` estimates how many
    calls Roxy made to that key in the last minute, which is what Roblox refused: the adaptive controller cuts from
    that number, not only from the configured rate (finding LOAD-1). When a window bucket's limit goes down (that
    cut, or an admin's edit), the calls of the last minute are still inside Roblox's window, so the first
    reservation under the lower limit starts from the backlog those calls make at the new pace
    (`window_backlog_tat`): the new limit holds for every window, including the ones that began before the cut.

    Several buckets at once (plan 7.3 "atomic multi-bucket reservation"): checking buckets one by one would leak
    tokens when a later bucket says no. `reserve` reads every TAT in one `BEGIN IMMEDIATE` transaction, computes
    the earliest time `t` at which ALL of them allow a call (the maximum of their earliest times, floored at now),
    and either denies without writing anything (when `t - now` exceeds the caller's queue budget for its priority
    class) or advances every TAT to `max(TAT, t) + interval` and returns the slot time `t`. The caller then sleeps
    until `t`; if it is canceled first, `refund` gives the slot back: a TAT that nobody moved since goes back to
    exactly its old value, and one that later reservations moved on loses one interval (never below now, plan
    7.3). Extra checks that must be atomic with the reservation (the single-flight lease insert, cooldown and
    breaker re-checks) run first under a SAVEPOINT, so a denial rolls all of them back: nothing is committed.
    Background refreshes may reserve only while the global bucket is less than half used, so they never take
    slots an interactive caller could need soon (plan 7.3 "priority across workers").

What to read next
    `roxy/upstream/routing.py` (which egress, and therefore which buckets), `roxy/upstream/queue.py` (waiting for
    the slot) and `roxy/upstream/service.py`.
"""

from __future__ import annotations

import math
import sqlite3
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final, Protocol

from roxy.core.reasons import Egress
from roxy.storage.db import Database

GLOBAL_KEY: Final = "global"
CREDENTIAL_PROBE_KEY: Final = "egress:credential:probe"
BACKGROUND_GLOBAL_LIMIT: Final = 0.5
"""Background refreshes reserve only while the global bucket is less than this fraction used (plan 7.3)."""

WINDOW_MS: Final = 60_000.0
"""The rolling window a window bucket's `per_min` is counted over (Roblox states its limits per minute)."""
WINDOW_MARGIN_MS: Final = 1_000.0
"""Window buckets pace as if the window were this much longer, so jitter between Roxy's slot time and the moment a
call reaches Roblox (event loop lag, the network) cannot squeeze one call too many into Roblox's minute. A safety
bound, not a tuning knob: it costs about 1.6 percent of a window bucket's steady pace."""
WINDOWED_PREFIXES: Final = ("endpoint:", "host:")
"""Bucket keys that stand for Roblox's own per-window limits: per-endpoint and per-host buckets."""
METER_PREFIX: Final = "meter:"
"""`upstream_bucket` rows with this prefix are `WindowMeter`s, not buckets (never shown, never paced on)."""

_SAVEPOINT: Final = "upstream_reserve"

LeaseHook = Callable[[sqlite3.Connection, int], bool]
"""Runs inside the reservation transaction before any bucket is touched (the single-flight lease insert, plan 6.3).
Gets `(conn, now_ms)`; returns False when the lease belongs to someone else (then nothing is reserved)."""


@dataclass(frozen=True, slots=True)
class GuardDenial:
    """A check inside the reservation transaction said no (an active cooldown, an open breaker, no AIMD slot)."""

    reason: str  # "cooldown", "breaker", "aimd", ...
    key: str
    retry_after_ms: float
    source: str = ""  # for cooldowns: the cooldown source

    @property
    def retry_after_s(self) -> float:
        return max(0.0, self.retry_after_ms / 1000)


Guard = Callable[[sqlite3.Connection, int], GuardDenial | None]
"""A check run inside the reservation transaction with `(conn, now_ms)`; returns a denial or None."""


# --- keys ------------------------------------------------------------------------------------------------------------


def egress_bucket_key(egress: Egress | str, *, probe: bool = False) -> str:
    """`egress:direct`, `egress:rotator`, `egress:credential`, or the probe sub-bucket `egress:credential:probe`."""
    value = Egress(egress)
    if value is Egress.NONE:
        raise ValueError("no bucket for egress 'none'")
    if probe and value is Egress.CREDENTIAL:
        return CREDENTIAL_PROBE_KEY
    return f"egress:{value.value}"


def host_bucket_key(host: str) -> str:
    return f"host:{host}"


def endpoint_bucket_key(template: str) -> str:
    return f"endpoint:{template}"


def is_windowed(key: str) -> bool:
    """True for the buckets whose `per_min` caps every rolling window (host and endpoint keys, see above)."""
    return key.startswith(WINDOWED_PREFIXES)


def meter_key(key: str) -> str:
    """The `upstream_bucket` row that counts the calls of window bucket `key`."""
    return METER_PREFIX + key


# --- GCRA ------------------------------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class BucketSpec:
    """One bucket: its key, its rate per minute and its burst (window semantics for host and endpoint keys)."""

    key: str
    per_min: float
    burst: int

    def __post_init__(self) -> None:
        if not self.per_min > 0:
            raise ValueError(f"bucket {self.key!r}: per_min must be positive")
        if self.burst < 1:
            raise ValueError(f"bucket {self.key!r}: burst must be at least 1")

    @property
    def windowed(self) -> bool:
        """Whether `per_min` caps every rolling window (rate plus burst inside one window)."""
        return is_windowed(self.key)

    @property
    def window_calls(self) -> int:
        """The most calls one rolling window may hold: `per_min` rounded down (a window holds whole calls), at
        least 1. The tiny epsilon keeps a value like 59.99999999 from a float product at 60."""
        return max(1, math.floor(self.per_min + 1e-9))

    @property
    def effective_burst(self) -> int:
        """The burst actually allowed: a window bucket's burst can never be larger than its whole window."""
        return min(self.burst, self.window_calls) if self.windowed else self.burst

    @property
    def interval_ms(self) -> float:
        """Spacing between calls at the steady rate.

        Plain buckets: `60000 / per_min` (plan 7.3). Window buckets: `(window + margin) / (N - B + 1)`, so the
        burst plus the steady calls of one window never exceed N (see the module docstring)."""
        if self.windowed:
            return (WINDOW_MS + WINDOW_MARGIN_MS) / (self.window_calls - self.effective_burst + 1)
        return 60_000.0 / self.per_min

    @property
    def tolerance_ms(self) -> float:
        """How far ahead of the steady schedule a burst may run: (burst - 1) x interval."""
        return (self.effective_burst - 1) * self.interval_ms

    @property
    def capacity_ms(self) -> float:
        """burst x interval: how far TAT can run ahead of now when the bucket is fully used."""
        return self.effective_burst * self.interval_ms

    @property
    def rate_per_s(self) -> float:
        """The configured rate (what the row stores and the Upstream page shows), not the steady pace."""
        return self.per_min / 60.0

    @property
    def steady_per_min(self) -> float:
        """Calls per minute once the burst is spent (equal to `per_min` for a plain bucket)."""
        return 60_000.0 / self.interval_ms


def gcra_earliest_ms(tat_ms: float, spec: BucketSpec, now_ms: float) -> float:
    """The earliest time this bucket allows a call: `max(now, TAT - tolerance)`."""
    return max(now_ms, tat_ms - spec.tolerance_ms)


def gcra_advance_ms(tat_ms: float, spec: BucketSpec, slot_ms: float) -> float:
    """TAT after a call at `slot_ms`: `max(TAT, slot) + interval`."""
    return max(tat_ms, slot_ms) + spec.interval_ms


def gcra_fill(tat_ms: float, spec: BucketSpec, now_ms: float) -> float:
    """How much of the burst is used, from 0.0 (full bucket) to 1.0 (the next call has to wait)."""
    used = max(tat_ms, now_ms) - now_ms
    return min(1.0, max(0.0, used / spec.capacity_ms))


def earliest_slot_ms(tats: Mapping[str, float], specs: Sequence[BucketSpec], now_ms: float) -> tuple[float, str]:
    """The earliest time every bucket allows a call, and the bucket that bound it ("" when none had to wait)."""
    slot, binding = float(now_ms), ""
    for spec in specs:
        earliest = gcra_earliest_ms(tats.get(spec.key, 0.0), spec, now_ms)
        if earliest > slot:
            slot, binding = earliest, spec.key
    return slot, binding


# --- measuring what a window bucket let through ----------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class WindowMeter:
    """A sliding window counter: how many calls one window bucket granted in the last `WINDOW_MS`.

    Two fixed windows of `WINDOW_MS`, the first one starting at the first call counted (so a cold start measures
    exactly): `current` counts calls in `[start, start + window)`, `previous` those in the window before it. The
    estimate for "the last minute" is all of `current` plus the part of `previous` that still lies inside the
    minute, assuming its calls were spread evenly. One row, three numbers, updated in the reservation transaction.
    Calls are counted at their slot time, so calls already booked but not yet sent are included.
    """

    start_ms: float
    current: int = 0
    previous: int = 0

    def rolled(self, at_ms: float) -> WindowMeter:
        """The meter as seen at `at_ms`: windows that ended move on (a gap of two windows empties it)."""
        if at_ms < self.start_ms + WINDOW_MS:
            return self
        if at_ms < self.start_ms + 2 * WINDOW_MS:
            return WindowMeter(self.start_ms + WINDOW_MS, 0, self.current)
        return WindowMeter(float(at_ms), 0, 0)

    def counted(self, at_ms: float) -> WindowMeter:
        """One more call at `at_ms` (a call booked a little before `start` still counts in the current window)."""
        meter = self.rolled(at_ms)
        return WindowMeter(meter.start_ms, meter.current + 1, meter.previous)

    def uncounted(self, at_ms: float) -> WindowMeter:
        """One call counted at `at_ms` given back (its reservation was refunded); no change once it aged out."""
        if at_ms >= self.start_ms:
            if self.current > 0:
                return WindowMeter(self.start_ms, self.current - 1, self.previous)
        elif at_ms >= self.start_ms - WINDOW_MS:
            if self.previous > 0:
                return WindowMeter(self.start_ms, self.current, self.previous - 1)
            if self.current > 0:  # booked a little before the window's first call, so it was counted in it
                return WindowMeter(self.start_ms, self.current - 1, self.previous)
        return self

    def estimate(self, now_ms: float) -> float:
        """Calls counted in the `WINDOW_MS` before `now_ms`."""
        meter = self.rolled(now_ms)
        elapsed = min(WINDOW_MS, max(0.0, now_ms - meter.start_ms))
        return meter.current + meter.previous * (1.0 - elapsed / WINDOW_MS)


def _read_rows(conn: sqlite3.Connection, keys: Iterable[str]) -> dict[str, tuple[float, int, float]]:
    """`(tat_ms, burst, rate_per_s)` per stored `upstream_bucket` row among `keys` (buckets and meters alike)."""
    wanted = list(dict.fromkeys(keys))
    if not wanted:
        return {}
    marks = ", ".join("?" for _ in wanted)
    rows = conn.execute(
        f"SELECT bucket_key, tat_ms, burst, rate_per_s FROM upstream_bucket WHERE bucket_key IN ({marks})",  # noqa: S608 - placeholders only
        wanted,
    ).fetchall()
    return {str(row[0]): (float(row[1]), int(row[2]), float(row[3])) for row in rows}


def _meter_of(row: tuple[float, int, float]) -> WindowMeter:
    """A meter row's columns: tat_ms is the window start, burst the current count, rate_per_s the previous count."""
    start, current, previous = row
    return WindowMeter(start, max(0, current), max(0, int(previous)))


def read_meters(conn: sqlite3.Connection, keys: Iterable[str]) -> dict[str, WindowMeter]:
    """The meter of each window bucket key that has one (stored as `meter:<key>`: start, current, previous)."""
    rows = _read_rows(conn, (meter_key(key) for key in keys))
    return {key[len(METER_PREFIX) :]: _meter_of(row) for key, row in rows.items()}


def _write_meter(conn: sqlite3.Connection, key: str, meter: WindowMeter, now_ms: int) -> None:
    # The meter reuses the bucket table's columns: tat_ms holds the window start, burst the current count and
    # rate_per_s the previous count. `updated_at` lets the idle-bucket pruning (storage/retention.py) remove it.
    conn.execute(
        "INSERT INTO upstream_bucket (bucket_key, tat_ms, burst, rate_per_s, updated_at) VALUES (?, ?, ?, ?, ?) "
        "ON CONFLICT(bucket_key) DO UPDATE SET tat_ms = excluded.tat_ms, burst = excluded.burst, "
        "rate_per_s = excluded.rate_per_s, updated_at = excluded.updated_at",
        (meter_key(key), meter.start_ms, meter.current, float(meter.previous), now_ms // 1000),
    )


def _fed_tat(tat_ms: float, count: int, first_ms: float, end_ms: float, interval_ms: float) -> float:
    """GCRA's TAT after `count` calls spread evenly over `[first, end)` (the first one at `first`), from `tat_ms`.

    Closed form of `TAT = max(TAT, t) + interval` over the times `first + k x step`: the result is the largest of
    "every call paced after the old TAT", "every call paced after the first one" and "one interval after the
    last one"."""
    step = (end_ms - first_ms) / count
    return max(
        tat_ms + count * interval_ms,
        first_ms + count * interval_ms,
        first_ms + (count - 1) * step + interval_ms,
    )


def window_backlog_tat(meter: WindowMeter, spec: BucketSpec, now_ms: float) -> float:
    """The TAT `spec` would have now had it paced the calls the meter counted (spread evenly over their windows).

    Used when a window bucket's limit went down (an adaptive cut after a 429, or an admin's edit): the calls already
    made at the old, faster pace are still inside Roblox's minute, and the new limit must hold for the windows that
    contain them too, not only for the calls that come next. Starting from this TAT, the new calls are paced as if
    the old ones had been paced by the new limit, so the GCRA guarantee covers old and new calls together. It is an
    estimate (the meter keeps counts, not times: each window's calls are taken as evenly spread from its start,
    which for a window that began with a call is that call's exact time). Booked calls not yet sent are covered by
    the stored TAT, which the caller keeps when it is later."""
    meter = meter.rolled(now_ms)
    tat = 0.0
    if meter.previous > 0:
        tat = _fed_tat(tat, meter.previous, meter.start_ms - WINDOW_MS, meter.start_ms, spec.interval_ms)
    if meter.current > 0:
        tat = _fed_tat(tat, meter.current, meter.start_ms, max(meter.start_ms, now_ms), spec.interval_ms)
    return tat


def _was_looser(row: tuple[float, int, float], spec: BucketSpec) -> bool:
    """Whether a bucket row was last written under a higher rate or a larger burst than `spec` (its limit went
    down since: the stored TAT was paced for the old limit)."""
    _tat, burst, rate_per_s = row
    return rate_per_s * 60.0 > spec.per_min + 1e-6 or burst > spec.burst


def observed_calls(conn: sqlite3.Connection, keys: Iterable[str], now_ms: float) -> dict[str, float]:
    """For each window bucket key: the calls Roxy booked through it in the last minute (fleet-wide, from hot.db).

    The adaptive controller reads this after a Roblox 429: it is the rate Roblox refused. Keys without a meter
    (never used, or idle long enough to be pruned) are absent."""
    windowed = [key for key in keys if is_windowed(key)]
    return {key: round(meter.estimate(now_ms), 2) for key, meter in read_meters(conn, windowed).items()}


# --- rates -----------------------------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class LimitPair:
    per_min: float
    burst: int


@dataclass(frozen=True, slots=True)
class BucketDefaults:
    """Every default rate of plan 7.3 / 15.3 B and C, read once per request from the runtime settings."""

    global_: LimitPair
    direct: LimitPair
    rotator: LimitPair
    credential: LimitPair  # allowlisted credential traffic: the account's rate minus the probe reservation
    credential_probe: LimitPair  # the reserved probe sub-bucket
    host: LimitPair
    endpoint: LimitPair

    @classmethod
    def from_settings(cls, settings: Any) -> BucketDefaults:
        def pair(rate_key: str, burst_key: str) -> LimitPair:
            return LimitPair(float(settings.get(rate_key)), int(settings.get(burst_key)))

        account = float(settings.get("credential_bucket_per_min"))
        reserved = float(settings.get("credential_probe_reserved_per_min"))
        burst = int(settings.get("credential_bucket_burst"))
        # The catalog cross rule keeps reserved < account; max() keeps both buckets valid even if it did not.
        return cls(
            global_=pair("global_bucket_per_min", "global_bucket_burst"),
            direct=pair("direct_bucket_per_min", "direct_bucket_burst"),
            rotator=pair("rotator_bucket_per_min", "rotator_bucket_burst"),
            credential=LimitPair(max(1.0, account - reserved), burst),
            credential_probe=LimitPair(max(1.0, reserved), max(1, min(burst, int(reserved)))),
            host=pair("host_bucket_default_per_min", "host_bucket_default_burst"),
            endpoint=pair("endpoint_bucket_default_per_min", "endpoint_bucket_default_burst"),
        )


class LimitsLookup(Protocol):
    """`RulesSnapshot.upstream_limit`: the `upstream_limits` override row for a bucket key, or None."""

    def upstream_limit(self, bucket_key: str) -> Any: ...


def _override(limits: LimitsLookup | None, key: str, default: LimitPair) -> LimitPair:
    row = limits.upstream_limit(key) if limits is not None else None
    if row is None:
        return default
    per_min = float(getattr(row, "per_min", 0) or 0)
    burst = int(getattr(row, "burst", 0) or 0)
    if per_min <= 0 or burst < 1:
        return default  # a zero row would divide by zero; the model forbids it, this is belt and braces
    return LimitPair(per_min, burst)


def specs_for(
    egress: Egress,
    host: str,
    template: str,
    defaults: BucketDefaults,
    limits: LimitsLookup | None,
    *,
    credential_probe: bool = False,
) -> tuple[BucketSpec, ...]:
    """The buckets one call through `egress` to `template` on `host` must take a slot in (plan 7.3 table).

    `credential_probe=True` (Roxy's own credential probes) uses the reserved sub-bucket instead of the shared
    credential bucket, so probes never queue behind allowlisted traffic and traffic never starves probes.
    """
    if egress is Egress.DIRECT:
        egress_pair = defaults.direct
    elif egress is Egress.ROTATOR:
        egress_pair = defaults.rotator
    elif egress is Egress.CREDENTIAL:
        egress_pair = defaults.credential_probe if credential_probe else defaults.credential
    else:
        raise ValueError("no buckets for egress 'none'")
    host_pair = _override(limits, host_bucket_key(host), defaults.host)
    endpoint_pair = _override(limits, endpoint_bucket_key(template), defaults.endpoint)
    return (
        BucketSpec(GLOBAL_KEY, defaults.global_.per_min, defaults.global_.burst),
        BucketSpec(egress_bucket_key(egress, probe=credential_probe), egress_pair.per_min, egress_pair.burst),
        BucketSpec(host_bucket_key(host), host_pair.per_min, host_pair.burst),
        BucketSpec(endpoint_bucket_key(template), endpoint_pair.per_min, endpoint_pair.burst),
    )


# --- reservations in one transaction ---------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Grant:
    """A reserved slot: the call may start at `slot_ms` (wall clock ms)."""

    slot_ms: float
    now_ms: int
    binding_key: str  # the bucket that made the call wait ("" when it may go at once)
    advanced: tuple[tuple[str, float, float, float], ...]  # (key, interval, TAT before, TAT after) for the refund

    @property
    def wait_ms(self) -> float:
        return max(0.0, self.slot_ms - self.now_ms)


@dataclass(frozen=True, slots=True)
class Denial:
    """No slot within the allowed wait. Nothing was written."""

    retry_after_ms: float
    binding_key: str
    reason: str  # "busy" (the queue budget is too short) or "background" (the global bucket is half used)

    @property
    def retry_after_s(self) -> float:
        return max(0.0, self.retry_after_ms / 1000)


def _paced_state(
    conn: sqlite3.Connection, specs: Sequence[BucketSpec], now_ms: float
) -> tuple[dict[str, float], dict[str, WindowMeter]]:
    """TATs as pacing must see them under `specs`, and the window buckets' meters, in one read.

    A window bucket whose limit went down since its row was written starts from the backlog of the calls its meter
    counted (`window_backlog_tat`), so the new limit holds for windows that still contain calls made under the old
    one (the row remembers the rate and burst of the reservation that last wrote it)."""
    windowed = [spec for spec in specs if spec.windowed]
    rows = _read_rows(conn, [spec.key for spec in specs] + [meter_key(spec.key) for spec in windowed])
    tats = {spec.key: rows[spec.key][0] for spec in specs if spec.key in rows}
    meters = {spec.key: _meter_of(rows[meter_key(spec.key)]) for spec in windowed if meter_key(spec.key) in rows}
    for spec in windowed:
        row, meter = rows.get(spec.key), meters.get(spec.key)
        if row is not None and meter is not None and _was_looser(row, spec):
            tats[spec.key] = max(tats[spec.key], window_backlog_tat(meter, spec, now_ms))
    return tats, meters


def paced_tats(conn: sqlite3.Connection, specs: Sequence[BucketSpec], now_ms: float) -> dict[str, float]:
    """TAT per bucket key as a reservation under `specs` would see it now (a lowered window bucket's backlog
    included). The routing snapshot uses it, so routing and the reservation agree on when a slot is free."""
    return _paced_state(conn, specs, now_ms)[0]


def read_tats(conn: sqlite3.Connection, keys: Iterable[str]) -> dict[str, float]:
    """TAT per bucket key (missing rows are absent: a missing row is a full bucket)."""
    wanted = list(dict.fromkeys(keys))
    if not wanted:
        return {}
    marks = ", ".join("?" for _ in wanted)
    rows = conn.execute(
        f"SELECT bucket_key, tat_ms FROM upstream_bucket WHERE bucket_key IN ({marks})",  # noqa: S608 - placeholders only
        wanted,
    ).fetchall()
    return {str(row[0]): float(row[1]) for row in rows}


def _write_tat(conn: sqlite3.Connection, spec: BucketSpec, tat_ms: float, now_ms: int) -> None:
    # tat_ms is stored as REAL when it has a fraction (SQLite keeps a REAL in an INTEGER-affinity column when the
    # conversion would lose precision), so rates like 7 per minute keep their exact 8571.43 ms spacing.
    conn.execute(
        "INSERT INTO upstream_bucket (bucket_key, tat_ms, burst, rate_per_s, updated_at) VALUES (?, ?, ?, ?, ?) "
        "ON CONFLICT(bucket_key) DO UPDATE SET tat_ms = excluded.tat_ms, burst = excluded.burst, "
        "rate_per_s = excluded.rate_per_s, updated_at = excluded.updated_at",
        (spec.key, tat_ms, spec.burst, spec.rate_per_s, now_ms // 1000),
    )


def reserve_in(
    conn: sqlite3.Connection,
    specs: Sequence[BucketSpec],
    now_ms: int,
    max_wait_ms: float,
    *,
    background_global_limit: float | None = None,
) -> Grant | Denial:
    """Reserve one slot in every bucket of `specs`, or deny without writing. Run inside a write transaction.

    Window buckets also count the call in their meter, and a window bucket whose limit went down since its row was
    written starts from the backlog of the calls its meter counted (`paced_tats`)."""
    windowed = [spec for spec in specs if spec.windowed]
    tats, meters = _paced_state(conn, specs, now_ms)
    slot, binding = earliest_slot_ms(tats, specs, now_ms)
    wait = slot - now_ms
    if wait > max_wait_ms:
        return Denial(wait, binding, "busy")
    if background_global_limit is not None:
        for spec in specs:
            if spec.key != GLOBAL_KEY:
                continue
            tat = tats.get(GLOBAL_KEY, 0.0)
            if gcra_fill(tat, spec, now_ms) >= background_global_limit:
                # Time until the used part of the global burst drops below the limit again.
                retry = (max(tat, now_ms) - now_ms) - background_global_limit * spec.capacity_ms
                return Denial(max(1.0, retry), GLOBAL_KEY, "background")
    advanced: list[tuple[str, float, float, float]] = []
    for spec in specs:
        before = tats.get(spec.key, 0.0)
        after = gcra_advance_ms(before, spec, slot)
        _write_tat(conn, spec, after, now_ms)
        advanced.append((spec.key, spec.interval_ms, before, after))
    for spec in windowed:
        # Count the call (at its slot time) in each window bucket's meter, in the same transaction.
        _write_meter(conn, spec.key, meters.get(spec.key, WindowMeter(slot)).counted(slot), now_ms)
    return Grant(slot, now_ms, binding, tuple(advanced))


def refund_in(conn: sqlite3.Connection, grant: Grant, now_ms: int) -> None:
    """Give back a slot that will not be used.

    If no other reservation moved a bucket since ours, its TAT returns to exactly what it was (a reservation that
    had to wait for another bucket also pushed this one forward to the slot time, and that is undone too).
    Otherwise later reservations depend on the current value, so it only moves back one interval, never below now.
    A window bucket's meter forgets the call as well (it never reached Roblox).
    """
    for key, interval, before, after in grant.advanced:
        row = conn.execute("SELECT tat_ms FROM upstream_bucket WHERE bucket_key = ?", (key,)).fetchone()
        if row is None:
            continue  # pruned meanwhile: an idle, full bucket, nothing to give back
        current = float(row[0])
        restored = before if abs(current - after) < 1e-6 else max(current - interval, float(now_ms))
        conn.execute(
            "UPDATE upstream_bucket SET tat_ms = ?, updated_at = ? WHERE bucket_key = ?",
            (restored, now_ms // 1000, key),
        )
    windowed = [key for key, _interval, _before, _after in grant.advanced if is_windowed(key)]
    for key, meter in read_meters(conn, windowed).items():
        _write_meter(conn, key, meter.uncounted(grant.slot_ms), now_ms)


@dataclass(frozen=True, slots=True)
class ReserveOutcome:
    """The result of `reserve`: exactly one of grant, denial, guard or lease_lost is set."""

    grant: Grant | None = None
    denial: Denial | None = None
    guard: GuardDenial | None = None
    lease_lost: bool = False

    @property
    def granted(self) -> bool:
        return self.grant is not None


def reserve_txn(
    conn: sqlite3.Connection,
    specs: Sequence[BucketSpec],
    now_ms: int,
    max_wait_ms: float,
    *,
    background_global_limit: float | None = None,
    lease_hook: LeaseHook | None = None,
    guards: Sequence[Guard] = (),
) -> ReserveOutcome:
    """The whole reservation inside the caller's write transaction: lease hook, guards, then every bucket.

    A SAVEPOINT makes any "no" roll back whatever an earlier step wrote (a lease insert, a breaker probe lease),
    so a denied reservation commits nothing (plan 7.3).
    """
    conn.execute(f"SAVEPOINT {_SAVEPOINT}")
    try:
        if lease_hook is not None and not lease_hook(conn, now_ms):
            _rollback_savepoint(conn)
            return ReserveOutcome(lease_lost=True)
        for guard in guards:
            refused = guard(conn, now_ms)
            if refused is not None:
                _rollback_savepoint(conn)
                return ReserveOutcome(guard=refused)
        result = reserve_in(conn, specs, now_ms, max_wait_ms, background_global_limit=background_global_limit)
        if isinstance(result, Denial):
            _rollback_savepoint(conn)
            return ReserveOutcome(denial=result)
        conn.execute(f"RELEASE {_SAVEPOINT}")
        return ReserveOutcome(grant=result)
    except BaseException:
        _rollback_savepoint(conn)
        raise


def _rollback_savepoint(conn: sqlite3.Connection) -> None:
    conn.execute(f"ROLLBACK TO {_SAVEPOINT}")
    conn.execute(f"RELEASE {_SAVEPOINT}")


async def reserve(
    db: Database,
    specs: Sequence[BucketSpec],
    *,
    now_ms: Callable[[], int],
    max_wait_ms: float,
    background_global_limit: float | None = None,
    lease_hook: LeaseHook | None = None,
    guards: Sequence[Guard] = (),
    busy_timeout_ms: int | None = None,
) -> ReserveOutcome:
    """One hot.db write transaction: the single-flight lease hook, the guards, and a slot in every bucket.

    The clock is read inside the transaction, after the write lock is held, so the decision uses the time at
    which no other worker can change the buckets any more.
    """

    def txn(conn: sqlite3.Connection) -> ReserveOutcome:
        return reserve_txn(
            conn,
            specs,
            now_ms(),
            max_wait_ms,
            background_global_limit=background_global_limit,
            lease_hook=lease_hook,
            guards=guards,
        )

    return await db.write(txn, busy_timeout_ms=busy_timeout_ms)


async def refund(db: Database, grant: Grant, *, now_ms: Callable[[], int]) -> None:
    """Give a reserved slot back (the request was canceled or evicted before its slot time)."""
    await db.write(lambda conn: refund_in(conn, grant, now_ms()))


# --- the dashboard view ----------------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class BucketState:
    """One bucket as the Upstream page shows it (parity row 34: fill level, next free slot)."""

    key: str
    per_min: float
    burst: int
    fill: float  # 0.0 to 1.0
    next_free_in_ms: float  # 0 when a call could go now
    tat_ms: float


def bucket_states(conn: sqlite3.Connection, now_ms: int, limit: int = 500) -> list[BucketState]:
    """Every stored bucket with its fill level, fullest first. There is no reset: buckets are never refilled by
    hand (parity row 34 fixes v1's burst unlock). Meter rows are not buckets and are left out."""
    rows = conn.execute(
        "SELECT bucket_key, tat_ms, burst, rate_per_s FROM upstream_bucket WHERE substr(bucket_key, 1, ?) != ? "
        "ORDER BY tat_ms DESC LIMIT ?",
        (len(METER_PREFIX), METER_PREFIX, max(1, limit)),
    ).fetchall()
    states: list[BucketState] = []
    for key, tat, burst, rate in rows:
        if float(rate) <= 0 or int(burst) < 1:
            continue
        spec = BucketSpec(str(key), float(rate) * 60, int(burst))
        tat_f = float(tat)
        states.append(
            BucketState(
                key=spec.key,
                per_min=spec.per_min,
                burst=spec.burst,
                fill=gcra_fill(tat_f, spec, now_ms),
                next_free_in_ms=max(0.0, gcra_earliest_ms(tat_f, spec, now_ms) - now_ms),
                tat_ms=tat_f,
            )
        )
    return states


__all__ = [
    "BACKGROUND_GLOBAL_LIMIT",
    "CREDENTIAL_PROBE_KEY",
    "GLOBAL_KEY",
    "METER_PREFIX",
    "WINDOWED_PREFIXES",
    "WINDOW_MARGIN_MS",
    "WINDOW_MS",
    "BucketDefaults",
    "BucketSpec",
    "BucketState",
    "Denial",
    "Grant",
    "Guard",
    "GuardDenial",
    "LeaseHook",
    "LimitPair",
    "LimitsLookup",
    "ReserveOutcome",
    "WindowMeter",
    "bucket_states",
    "earliest_slot_ms",
    "egress_bucket_key",
    "endpoint_bucket_key",
    "gcra_advance_ms",
    "gcra_earliest_ms",
    "gcra_fill",
    "host_bucket_key",
    "is_windowed",
    "meter_key",
    "observed_calls",
    "paced_tats",
    "read_meters",
    "read_tats",
    "refund",
    "refund_in",
    "reserve",
    "reserve_in",
    "reserve_txn",
    "specs_for",
    "window_backlog_tat",
]
