"""Rate limiting math: GCRA, the v1 fixed window, and the User-Agent cooldown, over rows of hot.db `limiter`.

What this is
    Pure functions that decide "admit or refuse" for one limiter row at one instant and say what the row becomes:
    `gcra` (the default per-IP algorithm and the flood and place limits), `fixed` (v1's window, kept for parity and
    used by throttle-all, endpoint rules and User-Agent burst rules), `cooldown` (User-Agent cooldown rules), the
    matching `*_peek` helpers for response headers, `load_rows` / `save_rows` for SQL, and `MemoryRowStore`, the
    bounded in-memory table used when hot.db is unavailable (plan C7).

Why it exists
    "L requests per W seconds" has two classic implementations. A fixed window gives everyone a full allowance at
    the start of each window, so a client can send L at the end of one window and L more right after the next one
    starts: 2L in a moment. GCRA (the generic cell rate algorithm) instead tracks one number per client, the
    theoretical arrival time (TAT) of its next request if it sent at exactly the allowed pace. It allows a burst of
    L, then exactly one request per W / L seconds, with no window edge to exploit (plan 10.2).

How it works
    GCRA for L per W: `interval = W / L`, `tolerance = (L - 1) x interval`. A request at `now` is admitted when
    `now >= TAT - tolerance`; then `TAT = max(TAT, now) + interval`. A refusal does not move TAT. The `max` also
    absorbs a wall clock that steps backwards (WSL does, about 0.9 s every 31 s). Times are integer milliseconds;
    TAT is stored rounded down and the admit test allows 1 ms of slack, so a client sending at exactly L per W is
    never refused because of rounding (the slack cannot accumulate: TAT re-anchors at `now`).
    Headers: `remaining = floor((now + tolerance - TAT) / interval) + 1` clamped to [0, L], `reset = ceil(TAT - now)`
    seconds, and on a refusal `retry_after = max(1, ceil(TAT - tolerance - now))` seconds.
    Fixed window (v1 `throttle.py`): a window opens at the first request and lasts W; a new one starts only when
    `now > end` (strict, as v1); `count >= limit` refuses without counting. The row stores the window end in
    `tat_ms`, so the retention job (which deletes idle rows whose `tat_ms` is in the past) never drops a live window.

What to read next
    `roxy/abuse/throttle.py` (the per-IP limiter with strikes), then `roxy/abuse/pipeline.py` (one transaction for
    every limiter of a request).
"""

from __future__ import annotations

import math
import sqlite3
from collections import OrderedDict
from collections.abc import Iterable
from dataclasses import dataclass, replace
from typing import Final

GCRA_SLACK_MS: Final = 1
"""Rounding slack of the admit test (see the module docstring)."""

MEMORY_ROWS_MAX: Final = 50_000
"""Bound of the per-worker degraded-mode table (plan P9); the least recently used row is evicted first."""

_EPSILON: Final = 1e-9  # floating point guard for floor() of a ratio that should be an exact integer


@dataclass(slots=True)
class LimiterRow:
    """One `limiter` row. `exists` is False for a key that has no row yet (a fresh, full allowance)."""

    key: str
    tat_ms: int = 0
    window_start: int = 0
    count: int = 0
    exists: bool = False


@dataclass(slots=True, frozen=True)
class RateDecision:
    """The outcome of one limiter for one request.

    `row` is what the limiter row becomes if this decision is committed (for a refusal it is the unchanged row).
    `remaining` and `reset_s` feed `Roxy-Requests-Left` and `Roxy-Throttle-Reset`; `retry_after_s` is at least 1 on
    a refusal and 0 when admitted.
    """

    admitted: bool
    remaining: int
    reset_s: int
    retry_after_s: int
    row: LimiterRow


def _ceil_s(ms: float) -> int:
    return max(0, math.ceil(ms / 1000 - _EPSILON))


def _floor_s(ms: float) -> int:
    return max(0, int(ms // 1000))


def gcra_params(limit: int, window_s: float) -> tuple[int, float, float]:
    """`(limit, interval_ms, tolerance_ms)` for "limit per window_s" (limit at least 1)."""
    limit = max(1, int(limit))
    interval = max(float(window_s), 0.001) * 1000.0 / limit
    return limit, interval, (limit - 1) * interval


def gcra(row: LimiterRow, limit: int, window_s: float, now_ms: int) -> RateDecision:
    """GCRA admit-or-refuse for one request (see the module docstring for the formulas)."""
    limit, interval, tolerance = gcra_params(limit, window_s)
    tat = float(row.tat_ms) if row.exists else float(now_ms)
    if now_ms + GCRA_SLACK_MS < tat - tolerance:
        retry = max(1, math.ceil((tat - tolerance - now_ms) / 1000 - _EPSILON))
        return RateDecision(False, 0, _ceil_s(tat - now_ms), retry, row)
    new_tat = max(tat, float(now_ms)) + interval
    remaining = min(limit, max(0, math.floor((now_ms + tolerance - new_tat) / interval + _EPSILON) + 1))
    new_row = replace(row, tat_ms=math.floor(new_tat), exists=True)
    return RateDecision(True, remaining, _ceil_s(new_tat - now_ms), 0, new_row)


def gcra_peek(row: LimiterRow, limit: int, window_s: float, now_ms: int) -> tuple[int, int]:
    """`(remaining, reset_s)` for a client without counting a request (headers of a refusal by another check)."""
    limit, interval, tolerance = gcra_params(limit, window_s)
    if not row.exists:
        return limit, 0
    tat = max(float(row.tat_ms), float(now_ms))
    remaining = min(limit, max(0, math.floor((now_ms + tolerance - tat) / interval + _EPSILON) + 1))
    return remaining, _ceil_s(tat - now_ms)


def _window(row: LimiterRow, window_s: float, now_ms: int) -> tuple[int, int, int]:
    """`(start, count, end)` of the window a request at `now_ms` falls in (a new one when the old one ended)."""
    if not row.exists or now_ms > row.tat_ms:
        return now_ms, 0, now_ms + max(1, round(float(window_s) * 1000))
    return row.window_start, row.count, row.tat_ms


def fixed(row: LimiterRow, limit: int, window_s: float, now_ms: int) -> RateDecision:
    """v1 fixed window: admit while `count < limit` inside the window; a refusal counts nothing."""
    limit = max(1, int(limit))
    start, count, end = _window(row, window_s, now_ms)
    if count >= limit:
        retry = max(1, math.ceil((end - now_ms) / 1000 - _EPSILON))
        return RateDecision(False, 0, _floor_s(end - now_ms), retry, row)
    count += 1
    new_row = replace(row, window_start=start, count=count, tat_ms=end, exists=True)
    return RateDecision(True, max(0, limit - count), _floor_s(end - now_ms), 0, new_row)


def fixed_peek(row: LimiterRow, limit: int, now_ms: int) -> tuple[int, int]:
    """`(remaining, reset_s)` of a fixed window without counting (v1 `headers_snapshot`)."""
    limit = max(1, int(limit))
    if not row.exists or now_ms > row.tat_ms:
        return limit, 0
    return max(0, limit - row.count), _floor_s(row.tat_ms - now_ms)


def cooldown(row: LimiterRow, cooldown_s: float, now_ms: int) -> RateDecision:
    """v1 User-Agent cooldown rule: one request per `cooldown_s`. A refusal does NOT move the last time, so a
    hammering client is not locked out forever (v1 `check_user_agent_rule`). Retry uses a true ceiling (v1 bug B12
    used `int(x + 0.999)`)."""
    cooldown_ms = max(0.0, float(cooldown_s)) * 1000
    last = row.window_start if row.exists else 0
    waited = now_ms - last
    if last and waited < cooldown_ms:
        retry = max(1, math.ceil((cooldown_ms - waited) / 1000 - _EPSILON))
        return RateDecision(False, 0, retry, retry, row)
    # v1 kept the bucket for max(cooldown, 1 s); tat_ms is that expiry (retention keeps the row until then).
    new_row = replace(row, window_start=now_ms, tat_ms=now_ms + int(max(cooldown_ms, 1000)), count=1, exists=True)
    return RateDecision(True, 0, _ceil_s(cooldown_ms), 0, new_row)


# --- SQL --------------------------------------------------------------------------------------------------------------


def load_rows(conn: sqlite3.Connection, keys: Iterable[str]) -> dict[str, LimiterRow]:
    """Every requested key as a `LimiterRow` (missing keys come back with `exists=False`). One indexed SELECT."""
    wanted = list(dict.fromkeys(keys))
    rows = {key: LimiterRow(key) for key in wanted}
    if not wanted:
        return rows
    marks = ",".join("?" for _ in wanted)
    sql = f"SELECT bucket_key, tat_ms, window_start, count FROM limiter WHERE bucket_key IN ({marks})"  # noqa: S608  # only "?" placeholders are interpolated
    for raw in conn.execute(sql, wanted).fetchall():
        rows[str(raw[0])] = LimiterRow(str(raw[0]), int(raw[1]), int(raw[2]), int(raw[3]), True)
    return rows


def save_rows(conn: sqlite3.Connection, rows: Iterable[LimiterRow], now_s: int) -> None:
    """Upsert rows (inside the caller's write transaction). `updated_at` is in seconds, `tat_ms` in milliseconds."""
    params = [(row.key, int(row.tat_ms), int(row.window_start), int(row.count), int(now_s)) for row in rows]
    if params:
        conn.executemany(
            "INSERT INTO limiter (bucket_key, tat_ms, window_start, count, updated_at) VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT (bucket_key) DO UPDATE SET tat_ms = excluded.tat_ms, window_start = excluded.window_start, "
            "count = excluded.count, updated_at = excluded.updated_at",
            params,
        )


# --- degraded mode (plan C7) -----------------------------------------------------------------------------------------


class MemoryRowStore[T]:
    """A bounded least-recently-used map from key to row, private to one worker process.

    Used when hot.db cannot be written: every limiter then runs on this worker's own copy at `limit / workers`, so
    the fleet as a whole still enforces roughly the configured limit (conservative: never more).
    """

    __slots__ = ("_rows", "max_rows")

    def __init__(self, max_rows: int = MEMORY_ROWS_MAX) -> None:
        self._rows: OrderedDict[str, T] = OrderedDict()
        self.max_rows = max_rows

    def get(self, key: str) -> T | None:
        row = self._rows.get(key)
        if row is not None:
            self._rows.move_to_end(key)
        return row

    def put(self, key: str, row: T) -> None:
        self._rows[key] = row
        self._rows.move_to_end(key)
        while len(self._rows) > self.max_rows:
            self._rows.popitem(last=False)

    def __len__(self) -> int:
        return len(self._rows)

    def clear(self) -> None:
        self._rows.clear()


def degraded_limit(limit: int, workers: int) -> int:
    """C7: the per-worker share of a limit while shared state is unavailable (at least 1)."""
    return max(1, int(limit) // max(1, int(workers)))


__all__ = [
    "GCRA_SLACK_MS",
    "LimiterRow",
    "MemoryRowStore",
    "RateDecision",
    "cooldown",
    "degraded_limit",
    "fixed",
    "fixed_peek",
    "gcra",
    "gcra_params",
    "gcra_peek",
    "load_rows",
    "save_rows",
]
