"""Client activity: per-IP and per-place request counts over time (parity row 73, "Callers and Top Talkers").

What this is
    The vocabulary and read helpers for the client tables (`client_minute`, `client_hour`, `client_day`): the
    two client types, how a client key is normalized, the trailing-window rates Rate1, Rate5 and Rate60, and
    `client_summary` / `client_detail` for the Clients page drill-down. The write side lives in the recorder
    (per-minute counts in memory) and `rollups.write_clients`; compaction to the top N plus `other` is in
    `rollups.compact_all`.

Why it exists
    v1 kept the 400 busiest IPs and 200 busiest places per worker in memory, with rates computed from calendar
    minutes, so Rate1 dropped to zero at every minute boundary (bug B14). v2 keeps every client per minute (the
    leader trims each closed minute to the top `max_ip_activity_records` and `max_caller_records` plus one
    `other` row), so "who was busy at 03:12 last Tuesday" has an answer, and Rate1 covers a trailing 60 s.

How it works
    - Client types: `ip` (the client address as resolved behind nginx) and `place` (the self-reported
      `Roblox-Id` header, trimmed to 64 characters like v1). Activity tracking can be switched off with
      `activity_tracking`.
    - `trailing_rate` estimates the requests in the last N seconds from minute buckets: whole minutes inside the
      window count fully, the oldest partly covered minute in proportion (implemented in `queries.py`).
    - `client_detail` returns one client's totals, rates, busiest endpoint and minute timeline for the last hour.

What to read next
    `roxy/metrics/queries.py` (`client_table`, `trailing_rate`), `roxy/metrics/rollups.py` (`ClientDelta`).
"""

from __future__ import annotations

import sqlite3
from typing import Any

from roxy.core.client_ip import normalize_ip
from roxy.metrics.queries import client_timeline, trailing_rate

CLIENT_TYPES: tuple[str, ...] = ("ip", "place")
MAX_KEY_CHARS = 64
OTHER_KEY = "other"


def ip_key(ip: str | None) -> str:
    """Normalized client address (`::ffff:1.2.3.4` and `1.2.3.4` are one client), or "" when missing."""
    if not ip:
        return ""
    return (normalize_ip(ip) or ip.strip())[:MAX_KEY_CHARS]


def place_key(place_id: str | None) -> str:
    """The `Roblox-Id` header value as v1 stored it: stripped, at most 64 characters, "" when missing."""
    return str(place_id or "").strip()[:MAX_KEY_CHARS]


def client_detail(conn: sqlite3.Connection, client_type: str, key: str, now: float) -> dict[str, Any]:
    """One client's last hour: totals, Rate1/5/60, busiest endpoint and the minute timeline (row 73)."""
    if client_type not in CLIENT_TYPES:
        raise ValueError("client_type must be 'ip' or 'place'")
    start = int(now) - 3660
    timeline = client_timeline(conn, client_type, key, start - start % 60, int(now) + 60)
    per_minute = {int(r["bucket_start"]): int(r["requests"]) for r in timeline}
    totals = {"requests": 0, "refused": 0, "served": 0, "bytes": 0}
    endpoints: dict[str, int] = {}
    for row in timeline:
        for col in totals:
            totals[col] += int(row[col] or 0)
        if row["top_endpoint"]:
            endpoints[row["top_endpoint"]] = endpoints.get(row["top_endpoint"], 0) + int(row["requests"] or 0)
    return {
        "kind": client_type,
        "key": key,
        **totals,
        "refused_pct": round(totals["refused"] * 100.0 / totals["requests"], 2) if totals["requests"] else None,
        "rates": {
            "1": trailing_rate(per_minute, now, 60),
            "5": trailing_rate(per_minute, now, 300),
            "15": trailing_rate(per_minute, now, 900),
            "60": trailing_rate(per_minute, now, 3600),
        },
        "top_endpoint": max(endpoints.items(), key=lambda kv: kv[1])[0] if endpoints else None,
        "minutes": timeline,
    }
