"""Read models of the shared upstream state for the Upstream page: AIMD slots, configured bucket rates, key labels.

What this is
    * `aimd_rows(conn)` (hot.db): each adaptive concurrency key with its current limit and calls in flight (plan
      7.4, Tier 3, shown when `aimd_enabled` is on).
    * `configured_limit(key, defaults, limits)`: the rate and burst a bucket key has right now (the settings
      default, or the `upstream_limits` override and its origin), next to the bucket's stored state.
    * `describe_key(key)`: what a cooldown, breaker or bucket key is about (`kind`, `egress`, `target`), so the
      page can say "games.roblox.com through direct" instead of a raw key.

Why it exists
    `UpstreamService` already offers the bucket, cooldown and breaker snapshots; the AIMD table had no reader, and
    the snapshot rows carry the rate stored at the last reservation, not the rate an admin just configured. These
    helpers sit next to the code that writes the rows (DESIGN.md section 13) instead of in the API module.

How it works
    One bounded SELECT per call; the label and rate helpers are pure and use the key builders of `buckets.py`,
    `cooldowns.py` and `breaker.py`, so a key format change breaks a test here instead of a page silently.

What to read next
    `roxy/upstream/aimd.py`, `roxy/upstream/buckets.py`, `roxy/upstream/cooldowns.py`, `roxy/upstream/breaker.py`.
"""

from __future__ import annotations

import sqlite3
from typing import Any, Final

from roxy.core.reasons import Egress
from roxy.egress.rotator import PARK_KEY, STREAK_KEY
from roxy.upstream.buckets import (
    CREDENTIAL_PROBE_KEY,
    GLOBAL_KEY,
    BucketDefaults,
    LimitPair,
    LimitsLookup,
)
from roxy.upstream.cooldowns import CREDENTIAL_KEY

MAX_AIMD_ROWS: Final = 500
_EGRESS_VALUES: Final = frozenset(egress.value for egress in Egress)


def aimd_rows(conn: sqlite3.Connection, limit: int = MAX_AIMD_ROWS) -> list[dict[str, Any]]:
    """Every AIMD key (`<host>:<egress>`) with its limit, calls in flight and last change, busiest first."""
    rows = conn.execute(
        'SELECT key, "limit", inflight, last_change_at FROM aimd ORDER BY inflight DESC, key LIMIT ?',
        (max(1, min(int(limit), MAX_AIMD_ROWS)),),
    ).fetchall()
    out = []
    for key, value, inflight, changed in rows:
        host, _, egress = str(key).rpartition(":")
        out.append(
            {
                "key": str(key),
                "host": host,
                "egress": egress,
                "limit": round(float(value), 3),
                "slots": max(1, int(float(value))),  # whole calls allowed at once (the floor of the limit)
                "inflight": int(inflight or 0),
                "last_change_at": float(changed) if changed is not None else None,
            }
        )
    return out


def configured_limit(key: str, defaults: BucketDefaults, limits: LimitsLookup | None) -> dict[str, Any]:
    """`{per_min, burst, origin}` a bucket key has now: `origin` is `setting`, or the override row's origin."""
    pair: LimitPair | None = None
    if key == GLOBAL_KEY:
        pair = defaults.global_
    elif key == CREDENTIAL_PROBE_KEY:
        pair = defaults.credential_probe
    elif key == f"egress:{Egress.DIRECT.value}":
        pair = defaults.direct
    elif key == f"egress:{Egress.ROTATOR.value}":
        pair = defaults.rotator
    elif key == f"egress:{Egress.CREDENTIAL.value}":
        pair = defaults.credential
    elif key.startswith(("host:", "endpoint:")):
        row = limits.upstream_limit(key) if limits is not None else None
        if row is not None and float(getattr(row, "per_min", 0) or 0) > 0 and int(getattr(row, "burst", 0) or 0) >= 1:
            return {"per_min": float(row.per_min), "burst": int(row.burst), "origin": str(row.origin)}
        pair = defaults.host if key.startswith("host:") else defaults.endpoint
    if pair is None:
        return {"per_min": None, "burst": None, "origin": None}
    return {"per_min": pair.per_min, "burst": pair.burst, "origin": "setting"}


def _split_egress(rest: str) -> tuple[str, str | None]:
    target, sep, egress = rest.rpartition(":")
    if sep and egress in _EGRESS_VALUES:
        return target, egress
    return rest, None


def describe_key(key: str) -> dict[str, Any]:
    """`{kind, egress, target}` of a cooldown, breaker or bucket key (`kind` is `other` for an unknown shape)."""
    if key == CREDENTIAL_KEY:
        return {"kind": "credential", "egress": Egress.CREDENTIAL.value, "target": "the Roblox credential"}
    if key == PARK_KEY:
        return {"kind": "rotator_park", "egress": Egress.ROTATOR.value, "target": "the rotator (failure streak)"}
    if key == STREAK_KEY:
        return {"kind": "rotator_streak", "egress": Egress.ROTATOR.value, "target": "the rotator (failure streak)"}
    if key == GLOBAL_KEY:
        return {"kind": "global", "egress": None, "target": "every upstream call"}
    if key == CREDENTIAL_PROBE_KEY:
        return {"kind": "egress", "egress": Egress.CREDENTIAL.value, "target": "credential probes (reserved)"}
    kind, sep, rest = key.partition(":")
    if not sep:
        return {"kind": "other", "egress": None, "target": key}
    if kind == "egress":
        return {"kind": "egress", "egress": rest if rest in _EGRESS_VALUES else None, "target": rest}
    if kind in ("host", "endpoint"):
        target, egress = _split_egress(rest)
        return {"kind": kind, "egress": egress, "target": target}
    return {"kind": "other", "egress": None, "target": key}


__all__ = ["MAX_AIMD_ROWS", "aimd_rows", "configured_limit", "describe_key"]
