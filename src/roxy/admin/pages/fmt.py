"""Time and number formatting for page routes (the server side of `templates/components/format.html`).

What this is
    `local_time(ts, tz)`, `iso(ts)`, `ago(seconds)` and `since_text(ts, now, tz)` turn epoch seconds into the texts
    the dashboard shows ("Oct 9, 14:02:05", "12 minutes ago"); `time_cell(ts, tz, now)` is the `{"text",
    "datetime", "sub"}` cell the table macro renders as a `<time>` element.

Why it exists
    Templates format numbers with `components/format.html`, but times need a time zone and "now", which only the
    route knows. One helper keeps every page saying times the same way, in the admin's display zone, with an
    ISO 8601 `datetime` attribute screen readers and scripts can read.

How it works
    `zoneinfo` from the shared `metrics.rollups.zone` (an unknown zone falls back to UTC there). Invalid or
    missing times format as "n/a" (plan C5 replaced v1's dash placeholder).

What to read next
    `roxy/admin/pages/kit.py` (table cells), `templates/components/format.html`.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Final

from roxy.metrics.rollups import zone

MISSING: Final = "n/a"


def _valid(ts: Any) -> float | None:
    if isinstance(ts, bool) or not isinstance(ts, int | float):
        return None
    value = float(ts)
    if not 0 < value < 4_102_444_800:  # 1970 to 2100, as the API accepts
        return None
    return value


def local_time(ts: Any, tz: str, *, seconds: bool = True, date: bool = True) -> str:
    """`Oct 9, 14:02:05` in `tz` (24 hour clock); "n/a" for a missing time."""
    value = _valid(ts)
    if value is None:
        return MISSING
    moment = datetime.fromtimestamp(value, zone(tz))
    clock = moment.strftime("%H:%M:%S" if seconds else "%H:%M")
    if not date:
        return clock
    return f"{moment.strftime('%b')} {moment.day}, {moment.year}, {clock}"


def iso(ts: Any) -> str:
    """ISO 8601 in UTC with a `Z` (for `<time datetime>`), or "" for a missing time."""
    value = _valid(ts)
    if value is None:
        return ""
    return datetime.fromtimestamp(value, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def ago(seconds: Any) -> str:
    """`just now`, `45 seconds ago`, `12 minutes ago`, `3 hours ago`, `5 days ago`."""
    if isinstance(seconds, bool) or not isinstance(seconds, int | float):
        return MISSING
    s = int(seconds)
    if s < 0:
        return "in the future"
    if s < 10:
        return "just now"
    for size, unit in ((86_400, "day"), (3600, "hour"), (60, "minute")):
        if s >= size:
            n = s // size
            return f"{n} {unit}{'' if n == 1 else 's'} ago"
    return f"{s} seconds ago"


def since_text(ts: Any, now: float, tz: str) -> str:
    """`Oct 9, 2026, 14:02 (12 minutes ago)`, or "" for a missing time (the banners' "since")."""
    value = _valid(ts)
    if value is None:
        return ""
    return f"{local_time(value, tz, seconds=False)} ({ago(now - value)})"


def time_cell(ts: Any, tz: str, now: float | None = None) -> dict[str, Any] | None:
    """A table cell for a time: `{"text", "datetime", "sub"}` (None for a missing time, shown as "n/a")."""
    value = _valid(ts)
    if value is None:
        return None
    cell: dict[str, Any] = {"text": local_time(value, tz), "datetime": iso(value)}
    if now is not None:
        cell["sub"] = ago(now - value)
    return cell


__all__ = ["MISSING", "ago", "iso", "local_time", "since_text", "time_cell"]
