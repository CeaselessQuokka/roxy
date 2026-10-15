"""Read model: who asks for Roblox hosts that are not on the host allowlist (HOST-ADD, plan 11.5).

What this is
    `unknown_host_callers(conn, start, end)` answers, for every host named by `host_not_allowed` refusals in
    `[start, end)`: how many refusal events name it, how many distinct client addresses (by their keyed hash) and
    distinct places sent them, and the most frequent sample paths.

Why it exists
    HOST-ADD proposes adding a host to `allowed_roblox_hosts` only when many different callers ask for it (plan 11.5:
    ">= 5 distinct places or 50 distinct IPs in 24 h"). The rollups count requests per host but not distinct
    callers; the recorder's `refusal` events (`metrics/recorder.py _record_refusal_event`) keep each refusal's
    `ip_hash`, place and path. DESIGN.md section 13: read models live next to their data, so this one lives in the
    metrics package that writes those rows.

How it works
    One SQL pass over `events` of type `refusal` with the given reason. The host is the first segment of the
    refusal's `detail.path` (the proxy records the requested target there, `host/path`), else the first segment of
    the endpoint template (the proxy files a refused target under a fixed problem template such as
    `(host_not_allowed)`, which is skipped). Distinct counts use `count(DISTINCT ...)`, which ignores NULLs: rows the
    recorder summed per minute after its per-type budget (`metrics/recorder.py _event`) carry no `ip_hash`, so the
    address count is a lower bound under a flood, never an overcount (plan P6). Results are bounded (`MAX_HOSTS`,
    `MAX_PATHS_PER_HOST`, plan P9). Run inside `Database.read`.

What to read next
    `roxy/insights/rules/egress.py` (HOST-ADD), `roxy/proxy/validate.py` (where `host_not_allowed` comes from).
"""

from __future__ import annotations

import sqlite3
from typing import Any, Final

MAX_HOSTS: Final = 200
"""Most hosts one read returns, busiest first (P9: a scanner can name many hosts)."""
MAX_PATHS_PER_HOST: Final = 3
"""Sample paths kept per host (the 11.5 evidence "sample paths")."""
MAX_PATH_ROWS: Final = 2000
"""Most (host, path) rows read for the samples."""

_HOSTED: Final = """
WITH e AS (
    SELECT coalesce(json_extract(detail_json, '$.path'), '') AS p, coalesce(endpoint_template, '') AS t,
           ip_hash, place, coalesce(json_extract(detail_json, '$.count'), 1) AS n
    FROM events
    WHERE type = 'refusal' AND reason_code = ? AND at_ms >= ? AND at_ms < ?
), r AS (
    SELECT
        lower(CASE
            WHEN instr(p, '/') > 1 THEN substr(p, 1, instr(p, '/') - 1)
            WHEN p != '' THEN p
            WHEN substr(t, 1, 1) != '(' AND instr(t, '/') > 1 THEN substr(t, 1, instr(t, '/') - 1)
            ELSE NULL
        END) AS host,
        ip_hash,
        place,
        nullif(p, '') AS path,
        n
    FROM e
)
"""
"""The refusal rows of one reason with the host each names (module docstring). The text is a constant; every value
is a bound parameter."""


def unknown_host_callers(
    conn: sqlite3.Connection, start: int, end: int, *, reason: str = "host_not_allowed"
) -> dict[str, dict[str, Any]]:
    """`{host: {refusals, ips, places, paths}}` for the refusals of `reason` in `[start, end)` (seconds)."""
    params = (reason, int(start) * 1000, int(end) * 1000)
    rows = conn.execute(
        _HOSTED + "SELECT host, sum(n) AS refusals, count(DISTINCT ip_hash) AS ips, count(DISTINCT place) AS places "
        "FROM r WHERE host IS NOT NULL AND host != '' GROUP BY host ORDER BY refusals DESC, host LIMIT ?",
        (*params, MAX_HOSTS),
    ).fetchall()
    out: dict[str, dict[str, Any]] = {
        str(row["host"]): {
            "refusals": int(row["refusals"] or 0),
            "ips": int(row["ips"] or 0),
            "places": int(row["places"] or 0),
            "paths": [],
        }
        for row in rows
    }
    if not out:
        return out
    for row in conn.execute(
        _HOSTED  # noqa: S608 (module constants only; values are bound parameters)
        + "SELECT host, path, sum(n) AS n FROM r WHERE host IS NOT NULL AND path IS NOT NULL "
        "GROUP BY host, path ORDER BY n DESC, path LIMIT ?",
        (*params, MAX_PATH_ROWS),
    ):
        item = out.get(str(row["host"]))
        if item is not None and len(item["paths"]) < MAX_PATHS_PER_HOST:
            item["paths"].append(str(row["path"]))
    return out


__all__ = ["MAX_HOSTS", "MAX_PATHS_PER_HOST", "unknown_host_callers"]
