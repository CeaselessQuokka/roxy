"""Read models of the egress state for the Egress and Credential pages: rotator health, trips, budget projection.

What this is
    * `rotator_health(conn)` (hot.db): the fleet-wide rotator park row and failure streak (`egress/rotator.py`
      writes them), so every worker shows the same health, not its own snapshot.
    * `leak_trips(conn)` (control.db): which egress the leak guard disabled, when, and where it found the
      credential (`egress/clients.py` writes the `egress_disabled:<egress>` rows). Never the credential itself.
    * `rotator_store_meta(conn)` (control.db): when and by whom a UI rotator URL was set, and its masked host. It
      selects only the non-secret columns; the encrypted URL is read by `egress/rotator.py` alone.
    * `billing_cycle`, `project_cycle` and `cost_usd`: pure arithmetic of the plan 8.4 budget panel (this cycle's
      usage, a projection to the end of the cycle with a confidence band, and the cost).

Why it exists
    DESIGN.md section 13: read models live next to the data they read. These rows belong to the egress package, and
    the projection uses the same cycle rule as the rotator's hard stop (`rotator.cycle_start_for`), so the page and
    the stop never disagree about which month a byte belongs to.

How it works
    The projection (plan 8.4: "a linear projection from the trailing 7 days plus a weighted current-cycle rate,
    with a confidence band") blends two daily rates: the mean of the last (up to) 7 complete UTC days, weighted
    `TRAILING_WEIGHT`, and this cycle's average so far. Projected = used + rate x days left. The band assumes days
    vary independently around the trailing mean: over `r` days left, with `n` trailing days of standard deviation
    `s`, the spread is `Z90 x s x sqrt(r + r^2 / n)` (the day-to-day noise plus the uncertainty of the mean itself),
    a 90 percent band; its low end never goes below what is already used. With fewer than 2 complete days there is
    no band (`band_reason` says why). Bytes are decimal: 1 GB = 10^9 bytes, the provider's unit.

What to read next
    `roxy/egress/rotator.py` (usage, the hard stop, parking), `roxy/metrics/read_upstream.py`
    (`rotator_daily_bytes`), `roxy/admin/api/egress.py` (the page that shows these).
"""

from __future__ import annotations

import datetime as dt
import json
import math
import sqlite3
import statistics
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from typing import Any, Final

from roxy.egress.clients import DISABLED_KEY_PREFIX
from roxy.egress.rotator import DECIMAL_GB, PARK_KEY, STREAK_KEY, cycle_start_for

DAY_S: Final = 86_400
TRAILING_DAYS: Final = 7
TRAILING_WEIGHT: Final = 0.7
"""Weight of the trailing 7-day rate in the blended daily rate; the current cycle's own average gets the rest."""

Z90: Final = 1.6449
"""The two-sided 90 percent quantile of the normal distribution (the confidence band of the projection)."""

_TRIP_FIELDS: Final = ("reason", "since", "location", "purpose", "request_id", "worker")


# --------------------------------------------------------------------------------------------- rotator


def rotator_health(conn: sqlite3.Connection, now_ms: int) -> dict[str, Any]:
    """The fleet-wide rotator park and failure streak (hot.db rows written by `RotatorPool.record_result`)."""
    park = conn.execute("SELECT until_ms, source, set_at, hits FROM cooldown WHERE key = ?", (PARK_KEY,)).fetchone()
    streak = conn.execute("SELECT failures, window_start FROM breaker WHERE key = ?", (STREAK_KEY,)).fetchone()
    until_ms = int(park[0]) if park is not None else 0
    return {
        "parked": until_ms > now_ms,
        "parked_until_ms": until_ms if until_ms > now_ms else None,
        "park_remaining_s": round(max(0.0, (until_ms - now_ms) / 1000.0), 1),
        "times_parked": int(park[3]) if park is not None else 0,
        "failure_streak": int(streak[0]) if streak is not None else 0,
        "last_failure_at": int(streak[1]) if streak is not None and streak[1] is not None else None,
    }


def leak_trips(conn: sqlite3.Connection) -> dict[str, dict[str, Any]]:
    """`{egress: {reason, since, location, purpose, request_id, worker}}` for every egress the leak guard disabled."""
    rows = conn.execute(
        "SELECT key, value_json FROM service_state WHERE key >= ? AND key < ?",
        (DISABLED_KEY_PREFIX, DISABLED_KEY_PREFIX[:-1] + ";"),
    ).fetchall()
    out: dict[str, dict[str, Any]] = {}
    for key, value in rows:
        try:
            parsed = json.loads(value) if value else {}
        except ValueError:
            parsed = {}
        row = parsed if isinstance(parsed, dict) else {}
        out[str(key)[len(DISABLED_KEY_PREFIX) :]] = {name: row.get(name) for name in _TRIP_FIELDS}
    return out


def rotator_store_meta(conn: sqlite3.Connection) -> dict[str, Any] | None:
    """When and by whom the UI rotator URL was set, and its masked host; None when no UI value is stored."""
    row = conn.execute("SELECT set_at, set_by, masked_host FROM rotator_store WHERE id = 1").fetchone()
    if row is None:
        return None
    return {"set_at": row[0], "set_by": row[1], "masked_host": row[2]}


# ---------------------------------------------------------------------------------------------- budget


def billing_cycle(now_s: float, billing_day: int) -> tuple[int, int]:
    """`(start, end)` of the billing cycle containing `now_s`: UTC midnight of `billing_day` to the next one."""
    start = cycle_start_for(now_s, billing_day)
    first = dt.datetime.fromtimestamp(start, tz=dt.UTC)
    following = (first.replace(day=1) + dt.timedelta(days=32)).replace(day=first.day)
    return start, int(following.timestamp())


def previous_cycle(start: int, billing_day: int) -> tuple[int, int]:
    """The billing cycle before the one starting at `start`."""
    return billing_cycle(start - 1, billing_day)


def cost_usd(size_bytes: float, price_per_gb_usd: float) -> float | None:
    """The cost of `size_bytes` at `price_per_gb_usd` per decimal GB (None when no price is set, plan D12)."""
    if price_per_gb_usd <= 0:
        return None
    return round(size_bytes / DECIMAL_GB * price_per_gb_usd, 2)


@dataclass(frozen=True, slots=True)
class Projection:
    """The end-of-cycle projection of plan 8.4 (bytes; None where the data cannot say)."""

    used_bytes: int
    days_elapsed: float
    days_left: float
    trailing_days: int
    trailing_rate_bytes_per_day: float | None
    cycle_rate_bytes_per_day: float | None
    rate_bytes_per_day: float | None
    projected_bytes: int | None
    low_bytes: int | None
    high_bytes: int | None
    band: str | None
    band_reason: str | None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def project_cycle(
    *, cycle_start: int, cycle_end: int, now_s: float, used_bytes: int, trailing: Sequence[int]
) -> Projection:
    """Project this cycle's total from `used_bytes` and the `trailing` complete days (oldest first, at most 7 used).

    See the module docstring for the rule. `trailing` holds whole UTC days that ended before today.
    """
    elapsed = max((now_s - cycle_start) / DAY_S, 1.0 / 1440)  # at least a minute, so the rate is defined
    left = max(0.0, (cycle_end - now_s) / DAY_S)
    days = [max(0, int(value)) for value in trailing][-TRAILING_DAYS:]
    trailing_rate = statistics.fmean(days) if days else None
    cycle_rate = used_bytes / elapsed if used_bytes or elapsed >= 1 else None
    if trailing_rate is not None and cycle_rate is not None:
        rate: float | None = TRAILING_WEIGHT * trailing_rate + (1 - TRAILING_WEIGHT) * cycle_rate
    else:
        rate = trailing_rate if trailing_rate is not None else cycle_rate
    projected = round(used_bytes + rate * left) if rate is not None else None
    low = high = None
    band = reason = None
    if projected is None:
        reason = "no usage recorded yet"
    elif len(days) < 2:
        reason = "a band needs at least 2 complete days of usage"
    else:
        spread = Z90 * statistics.stdev(days) * math.sqrt(left + left * left / len(days))
        low = max(used_bytes, round(projected - spread))
        high = round(projected + spread)
        band = "90 percent"
    return Projection(
        used_bytes=int(used_bytes),
        days_elapsed=round(elapsed, 3),
        days_left=round(left, 3),
        trailing_days=len(days),
        trailing_rate_bytes_per_day=round(trailing_rate, 1) if trailing_rate is not None else None,
        cycle_rate_bytes_per_day=round(cycle_rate, 1) if cycle_rate is not None else None,
        rate_bytes_per_day=round(rate, 1) if rate is not None else None,
        projected_bytes=projected,
        low_bytes=low,
        high_bytes=high,
        band=band,
        band_reason=reason,
    )


def pct_of(value: float | None, whole: float) -> float | None:
    """`value` as a percent of `whole` (None when either is unknown or `whole` is 0)."""
    if value is None or whole <= 0:
        return None
    return round(value * 100.0 / whole, 2)


__all__ = [
    "TRAILING_DAYS",
    "TRAILING_WEIGHT",
    "Z90",
    "Projection",
    "billing_cycle",
    "cost_usd",
    "leak_trips",
    "pct_of",
    "previous_cycle",
    "project_cycle",
    "rotator_health",
    "rotator_store_meta",
]
