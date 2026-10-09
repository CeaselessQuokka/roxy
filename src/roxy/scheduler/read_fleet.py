"""Read model of the worker fleet for the System page: the heartbeat rows plus the host facts around them.

What this is
    `fleet_summary(rows, ...)` turns the `worker_heartbeat` rows (`scheduler.heartbeat.fleet_view`) into the
    System page's fleet header and worker list (parity row 84): per color the expected and fresh worker counts,
    the gunicorn master pids (both colors during a deploy) and the service uptime of each master, plus totals.
    `host_uptime_s()`, `boot_time_s()` and `process_started_at(pid)` read Linux's `/proc`, and
    `file_mtime(paths)` reads when the deploy last switched colors (`deployed_version`).

Why it exists
    Plan 4.5 row 84 renames and extends v1's worker registry: host uptime from `/proc/uptime`, Expected
    (`ROXY_WORKERS` per active color) against the Count of fresh heartbeats per color, both masters during a
    deploy, service uptime per color read from the master's own start time (so it survives worker recycles), and
    the time since the last deploy switch. The heartbeat rows are the scheduler package's data (DESIGN.md 13).

How it works
    Pure functions over the rows the caller read (`Database.read` with `fleet_view`), and small `/proc` reads that
    return None wherever the facts are not available (a non-Linux development machine, a pid that is gone). A
    process start time is `btime` (boot, from `/proc/stat`) plus field 22 of `/proc/<pid>/stat` in clock ticks.
    The caller runs the `/proc` reads on a worker thread (they are file reads).

What to read next
    `roxy/scheduler/heartbeat.py` (the writer), `roxy/admin/api/system.py` (the System page API).
"""

from __future__ import annotations

import os
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any, Final

MAX_WORKERS_SHOWN: Final = 256
"""Rows the fleet view returns at most (the heartbeat table is capped at 256 rows, plan 6.10)."""

_PROC: Final = Path("/proc")


def _read_text(path: Path, limit: int = 4096) -> str | None:
    try:
        with open(path, encoding="ascii", errors="replace") as handle:
            return handle.read(limit)
    except OSError:
        return None


def host_uptime_s(proc: Path = _PROC) -> float | None:
    """Seconds since the host booted (`/proc/uptime`), or None."""
    text = _read_text(proc / "uptime", 128)
    try:
        return float(text.split()[0]) if text else None
    except (ValueError, IndexError):
        return None


def boot_time_s(proc: Path = _PROC) -> int | None:
    """Unix time of the host boot (`btime` in `/proc/stat`), or None."""
    text = _read_text(proc / "stat", 1 << 16)
    if not text:
        return None
    for line in text.splitlines():
        if line.startswith("btime "):
            try:
                return int(line.split()[1])
            except (ValueError, IndexError):
                return None
    return None


def process_started_at(pid: int, *, proc: Path = _PROC, boot_s: int | None = None) -> float | None:
    """Unix time process `pid` started (from `/proc/<pid>/stat`), or None when unknown or gone."""
    if pid <= 0:
        return None
    text = _read_text(proc / str(int(pid)) / "stat", 4096)
    if not text:
        return None
    # The command name (field 2) is in parentheses and may contain spaces: split after the last ")".
    after = text.rpartition(")")[2].split()
    try:
        ticks = int(after[19])  # field 22 overall: starttime, in clock ticks since boot
    except (ValueError, IndexError):
        return None
    boot = boot_s if boot_s is not None else boot_time_s(proc)
    if boot is None:
        return None
    try:
        hertz = os.sysconf("SC_CLK_TCK")
    except (ValueError, OSError, AttributeError):
        hertz = 100
    return boot + ticks / max(1, int(hertz))


def file_mtime(paths: Iterable[Path]) -> float | None:
    """The modification time of the first of `paths` that exists (the deploy's `deployed_version`), or None."""
    for path in paths:
        try:
            return float(os.stat(path).st_mtime)
        except OSError:
            continue
    return None


def worker_row(item: Mapping[str, Any]) -> dict[str, Any]:
    """One worker of the fleet list with the parity row 84 names (snake_case)."""
    return {
        "pid": int(item.get("pid") or 0),
        "worker_id": item.get("worker_id"),
        "color": item.get("color") or "",
        "hostname": item.get("hostname"),
        "is_this_worker": bool(item.get("is_this_worker")),
        "is_leader": bool(item.get("is_leader")),
        "fresh": bool(item.get("fresh")),
        "started_at": item.get("started_at"),
        "uptime_s": item.get("uptime_s"),
        "last_seen": item.get("last_seen"),
        "rss_bytes": item.get("rss"),
        "requests": int(item.get("requests") or 0),
        "proxied": int(item.get("proxied") or 0),
        "max_requests": item.get("max_requests"),
        "counters_reset_at": item.get("counters_reset_at"),
        "loop_lag_ms_p99": item.get("loop_lag_ms_p99"),
        "open_connections": item.get("open_conns"),
        "inflight_upstream": item.get("inflight_upstream"),
        "master_pid": item.get("master_pid"),
        "version": item.get("version"),
        "cache_generation": item.get("cache_generation"),
    }


def fleet_summary(
    rows: Sequence[Mapping[str, Any]],
    *,
    now_s: float,
    expected_per_color: int,
    this_color: str,
    master_started: Mapping[int, float | None] | None = None,
) -> dict[str, Any]:
    """The fleet header and worker list from `fleet_view` rows (see the module docstring)."""
    workers = [worker_row(item) for item in list(rows)[:MAX_WORKERS_SHOWN]]
    started = dict(master_started or {})
    colors: dict[str, dict[str, Any]] = {}
    for worker in workers:
        color = worker["color"] or "unknown"
        entry = colors.setdefault(
            color,
            {"color": color, "expected": expected_per_color, "count": 0, "stale": 0, "master_pids": []},
        )
        if worker["fresh"]:
            entry["count"] += 1
            master = worker["master_pid"]
            if isinstance(master, int) and master > 0 and master not in entry["master_pids"]:
                entry["master_pids"].append(master)
        else:
            entry["stale"] += 1
    colors.setdefault(
        this_color, {"color": this_color, "expected": expected_per_color, "count": 0, "stale": 0, "master_pids": []}
    )
    for entry in colors.values():
        times = [t for t in (started.get(pid) for pid in entry["master_pids"]) if t is not None]
        entry["service_started_at"] = min(times) if times else None
        entry["service_uptime_s"] = max(0, int(now_s - min(times))) if times else None
        entry["active"] = entry["count"] > 0
        entry["short"] = entry["count"] < entry["expected"] and entry["count"] > 0
        entry["is_this_color"] = entry["color"] == this_color
    fresh = [w for w in workers if w["fresh"]]
    return {
        "colors": sorted(colors.values(), key=lambda e: (not e["is_this_color"], e["color"])),
        "workers": workers,
        "totals": {
            "fresh": len(fresh),
            "stale": len(workers) - len(fresh),
            "rss_bytes": sum(int(w["rss_bytes"] or 0) for w in fresh),
            "requests": sum(w["requests"] for w in fresh),
            "proxied": sum(w["proxied"] for w in fresh),
            "open_connections": sum(int(w["open_connections"] or 0) for w in fresh),
            "inflight_upstream": sum(int(w["inflight_upstream"] or 0) for w in fresh),
        },
        "deploying": sum(1 for e in colors.values() if e["active"]) > 1,
    }


__all__ = [
    "MAX_WORKERS_SHOWN",
    "boot_time_s",
    "file_mtime",
    "fleet_summary",
    "host_uptime_s",
    "process_started_at",
    "worker_row",
]
