"""Read model of per-caller facts for the abuse rules: refusals by reason and place, and sampled upstream use.

What this is
    Plain functions over a metrics.db connection (run them inside `Database.read`):
    - `refusal_groups`: refused requests in a window grouped by (reason code, place id, endpoint template), from the
      `events` rows of type `refusal` the recorder writes for every refused request (`metrics/recorder.py
      _record_refusal_event`; beyond the per-minute event budget the recorder sums them per minute with a `count`,
      which is added back here).
    - `sampled_upstream_by`: request samples that reached Roblox (egress other than `none`) in a window, grouped by
      place id, client hash or endpoint template, plus the total; `sampled_upstream_minutes` and
      `sampled_place_templates` drill into one place.
    - `recent_user_agents`: User-Agent texts from the fingerprint table, newest first (to name the User-Agent behind
      a `<template>|<ua_hash>` SPAM-DIST detection).

Why it exists
    DESIGN 13: read models live next to their data. Several plan 11.5 rules need numbers the rollups do not keep per
    caller: FILTER-COLLATERAL needs refusals per place and per rule, PLACE-HEAVY needs each place's share of the
    upstream calls, and THROTTLE-TUNE needs to know whether a few clients take most of the upstream slots. The
    rollups have no place or client dimension, and the client tables have no reason or upstream column, but the
    refusal events and the request samples (plan 6.2, `request_sample_pct` 100 by default) carry both.

How it works
    - Every query is one indexed time range read (`events_type_at`, `request_samples_at_ms`) grouped in SQL, bounded
      by `LIMIT` (plan P9). Times are Unix seconds, windows half open `[start, end)`.
    - Samples are counted as requests that reached Roblox (one per sampled request, retries not counted); when
      `request_sample_pct` is below 100 the counts are a sample, so callers use them as shares, which sampling does
      not bias, or scale them and say so (P6).
    - Grouping columns are checked against a fixed list before they reach the SQL text.

What to read next
    `roxy/insights/providers_rules_abuse_system.py` (how the rules reach these functions), `roxy/metrics/samples.py`
    (what a sample holds), `roxy/metrics/recorder.py` (the refusal events).
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable
from typing import Any, Final

MAX_GROUPS: Final = 10_000
"""Most groups one read returns (plan P9); far above the 2,000 template vocabulary and the place table caps."""
MAX_USER_AGENTS: Final = 2_000
"""Most fingerprinted User-Agents scanned for a hash (the fingerprint table is capped like v1)."""
SAMPLE_GROUP_COLUMNS: Final[frozenset[str]] = frozenset({"place", "client_hash", "endpoint_template"})
"""`request_samples` columns `sampled_upstream_by` may group on. Nothing else reaches the SQL text."""
REFUSAL_EVENT: Final = "refusal"
"""`events.type` of a refused request (`metrics/recorder.py REFUSAL_EVENT`)."""
_REACHED_ROBLOX: Final = "egress IS NOT NULL AND egress NOT IN ('none', '')"


def _bounded(limit: int | None, ceiling: int = MAX_GROUPS) -> int:
    return ceiling if limit is None else max(1, min(int(limit), ceiling))


def refusal_groups(
    conn: sqlite3.Connection,
    start: int,
    end: int,
    *,
    reasons: Iterable[str] | None = None,
    places: Iterable[str] | None = None,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    """`[{reason, place, endpoint_template, count}]` of refused requests in `[start, end)`, largest first.

    `place` and `endpoint_template` are None when the request had none (or when the recorder folded an over-budget
    minute into its overflow row). `reasons` and `places` narrow the read.
    """
    clauses = ["type = ?", "at_ms >= ?", "at_ms < ?"]
    params: list[Any] = [REFUSAL_EVENT, int(start) * 1000, int(end) * 1000]
    wanted_reasons = sorted({str(r) for r in reasons}) if reasons is not None else []
    if reasons is not None:
        if not wanted_reasons:
            return []
        clauses.append(f"reason_code IN ({', '.join('?' for _ in wanted_reasons)})")
        params += wanted_reasons
    wanted_places = sorted({str(p) for p in places}) if places is not None else []
    if places is not None:
        if not wanted_places:
            return []
        clauses.append(f"place IN ({', '.join('?' for _ in wanted_places)})")
        params += wanted_places
    rows = conn.execute(
        "SELECT reason_code, place, endpoint_template, "  # noqa: S608 (fixed clauses; values are bound)
        "sum(coalesce(json_extract(detail_json, '$.count'), 1)) AS n FROM events "
        f"WHERE {' AND '.join(clauses)} GROUP BY reason_code, place, endpoint_template ORDER BY n DESC LIMIT ?",
        (*params, _bounded(limit)),
    ).fetchall()
    return [
        {
            "reason": row[0],
            "place": row[1],
            "endpoint_template": row[2],
            "count": int(row[3] or 0),
        }
        for row in rows
    ]


def sampled_upstream_by(
    conn: sqlite3.Connection, start: int, end: int, column: str, *, limit: int | None = None
) -> dict[str, Any]:
    """`{total, rows, groups: {value: count}}`: sampled requests that reached Roblox in `[start, end)` by `column`.

    `total` counts every such sample (also those whose `column` is null); `rows` counts every sample in the window,
    so a caller can tell "no samples at all" from "nothing reached Roblox".
    """
    if column not in SAMPLE_GROUP_COLUMNS:
        raise ValueError(f"request samples cannot be grouped by {column!r}")
    bounds = (int(start) * 1000, int(end) * 1000)
    rows_total, reached = conn.execute(
        f"SELECT count(*), sum(CASE WHEN {_REACHED_ROBLOX} THEN 1 ELSE 0 END) FROM request_samples "  # noqa: S608 (constant clause)
        "WHERE at_ms >= ? AND at_ms < ?",
        bounds,
    ).fetchone()
    groups = conn.execute(
        f"SELECT {column}, count(*) AS n FROM request_samples WHERE at_ms >= ? AND at_ms < ? "  # noqa: S608 (column checked above)
        f"AND {_REACHED_ROBLOX} AND {column} IS NOT NULL GROUP BY {column} ORDER BY n DESC LIMIT ?",
        (*bounds, _bounded(limit)),
    ).fetchall()
    return {
        "rows": int(rows_total or 0),
        "total": int(reached or 0),
        "groups": {str(row[0]): int(row[1]) for row in groups},
    }


def sampled_place_templates(conn: sqlite3.Connection, start: int, end: int, place: str) -> dict[str, int]:
    """`{endpoint_template: sampled requests that reached Roblox}` of one place in `[start, end)`."""
    rows = conn.execute(
        f"SELECT endpoint_template, count(*) AS n FROM request_samples WHERE at_ms >= ? AND at_ms < ? "  # noqa: S608 (constant clause)
        f"AND place = ? AND {_REACHED_ROBLOX} GROUP BY endpoint_template ORDER BY n DESC LIMIT ?",
        (int(start) * 1000, int(end) * 1000, str(place), MAX_GROUPS),
    ).fetchall()
    return {str(row[0]): int(row[1]) for row in rows}


def sampled_upstream_minutes(
    conn: sqlite3.Connection, start: int, end: int, *, place: str, template: str
) -> dict[int, int]:
    """`{minute start: sampled requests that reached Roblox}` of one place on one template in `[start, end)`."""
    rows = conn.execute(
        "SELECT (at_ms / 60000) * 60 AS minute, count(*) FROM request_samples WHERE at_ms >= ? AND at_ms < ? "  # noqa: S608 (constant clause)
        f"AND place = ? AND endpoint_template = ? AND {_REACHED_ROBLOX} GROUP BY minute ORDER BY minute LIMIT ?",
        (int(start) * 1000, int(end) * 1000, str(place), str(template), MAX_GROUPS),
    ).fetchall()
    return {int(row[0]): int(row[1]) for row in rows}


def recent_user_agents(conn: sqlite3.Connection, limit: int | None = None) -> list[str]:
    """User-Agent texts recorded by the fingerprint view, most recently seen first (bounded)."""
    rows = conn.execute(
        "SELECT user_agent FROM fingerprint_user_agents ORDER BY last_seen DESC LIMIT ?",
        (_bounded(limit, MAX_USER_AGENTS),),
    ).fetchall()
    return [str(row[0]) for row in rows if row[0]]


__all__ = [
    "MAX_GROUPS",
    "MAX_USER_AGENTS",
    "REFUSAL_EVENT",
    "SAMPLE_GROUP_COLUMNS",
    "recent_user_agents",
    "refusal_groups",
    "sampled_place_templates",
    "sampled_upstream_by",
    "sampled_upstream_minutes",
]
