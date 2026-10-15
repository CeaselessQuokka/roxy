"""Read model of the worker fleet for the System page: the heartbeat rows plus the host facts around them.

What this is
    `fleet_summary(rows, ...)` turns the `worker_heartbeat` rows (`scheduler.heartbeat.fleet_view`) into the
    System page's fleet header and worker list (parity row 84): per color the expected and fresh worker counts,
    the gunicorn master pids (both colors during a deploy) and the service uptime of each master, plus totals.
    `color_master_pids(rows, color)` and `service_since(pids, started, now)` are that uptime alone, which the
    Overview's Service uptime tile reads too (plan 14.1 row 3 homes one v1 tile on both pages: one number).
    `host_uptime_s()`, `boot_time_s()`, `process_started_at(pid)` and `master_start_times(pids)` read Linux's
    `/proc`, and `file_mtime(paths)` reads when the deploy last switched colors (`deployed_version`).
    `worker_cpu(conn, now)` reads each worker's last complete minute of CPU from `worker_minute` (metric
    `worker_cpu_pct`).

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
import sqlite3
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


def master_start_times(pids: Iterable[int], *, proc: Path = _PROC) -> dict[int, float | None]:
    """`{pid: started_at}` for each gunicorn master pid (`process_started_at`, the boot time read once), None for a
    pid whose start cannot be read. File reads: the caller runs this on a worker thread."""
    boot = boot_time_s(proc)
    return {int(pid): process_started_at(int(pid), proc=proc, boot_s=boot) for pid in pids}


def _row_color(row: Mapping[str, Any]) -> str:
    """The color a heartbeat row is grouped under (`fleet_summary`): its color, or `unknown` when it has none."""
    return str(row.get("color") or "") or "unknown"


def color_master_pids(rows: Iterable[Mapping[str, Any]], color: str) -> list[int]:
    """The gunicorn master pids named by the fresh heartbeat rows of `color`, each once, in row order.

    One pid in steady state; two only while a master is being replaced. Stale rows are left out: a worker that
    stopped beating says nothing about the master serving now.
    """
    pids: list[int] = []
    for row in rows:
        master = row.get("master_pid")
        if not row.get("fresh") or _row_color(row) != color:
            continue
        if isinstance(master, int) and master > 0 and master not in pids:
            pids.append(master)
    return pids


def service_since(
    master_pids: Iterable[int], master_started: Mapping[int, float | None], now_s: float
) -> tuple[float | None, int | None]:
    """`(service_started_at, service_uptime_s)` of one color (parity row 84): since its oldest master started.

    Read from the gunicorn master, never from a worker's age: workers recycle on purpose (`ROXY_MAX_REQUESTS`), so a
    worker's start says nothing about how long the service has run, while the master lives until a deploy or a
    restart. Both are None when no master's start is known (a non-Linux machine, a pid that is gone): unknown is
    shown as unknown, never as the age of a worker (P6).
    """
    times = [t for t in (master_started.get(pid) for pid in master_pids) if t is not None]
    if not times:
        return None, None
    started = min(times)
    return started, max(0, int(now_s - started))


def file_mtime(paths: Iterable[Path]) -> float | None:
    """The modification time of the first of `paths` that exists (the deploy's `deployed_version`), or None."""
    for path in paths:
        try:
            return float(os.stat(path).st_mtime)
        except OSError:
            continue
    return None


CPU_LOOKBACK_S: Final = 300
"""How far back `worker_cpu` looks for a worker's last complete minute (a worker writes one every minute)."""


def worker_cpu(conn: sqlite3.Connection, now_s: float) -> dict[str, dict[str, Any]]:
    """`{worker_id: {cpu_pct, cpu_pct_max, cpu_minute}}`: each worker's last complete minute of CPU use (metric
    `worker_cpu_pct`, `metrics/catalog.py`): `cpu_pct` is `worker_minute.cpu_pct_sum / samples`, the mean of the
    samples its heartbeat took in that minute (percent of one core), `cpu_pct_max` the highest sample and
    `cpu_minute` the minute's start (Unix seconds).

    The minute still open is left out (its samples are still arriving), and so is a minute older than
    `CPU_LOOKBACK_S`: a worker without a recent complete minute has no entry, which the fleet shows as unknown (P6),
    never as 0. Bounded: at most `MAX_WORKERS_SHOWN` workers times the minutes looked at.
    """
    current = int(now_s) // 60 * 60
    rows = conn.execute(
        "SELECT worker_id, bucket_start, samples, cpu_pct_sum, cpu_pct_max FROM worker_minute "
        "WHERE bucket_start >= ? AND bucket_start < ? AND samples > 0 ORDER BY bucket_start LIMIT ?",
        (current - CPU_LOOKBACK_S, current, MAX_WORKERS_SHOWN * (CPU_LOOKBACK_S // 60 + 1)),
    ).fetchall()
    out: dict[str, dict[str, Any]] = {}
    for row in rows:  # oldest first: the newest complete minute of each worker wins
        samples = int(row["samples"] or 0)
        peak = row["cpu_pct_max"]
        out[str(row["worker_id"])] = {
            "cpu_pct": round(float(row["cpu_pct_sum"] or 0.0) / samples, 1),
            "cpu_pct_max": round(float(peak), 1) if peak is not None else None,
            "cpu_minute": int(row["bucket_start"]),
        }
    return out


def worker_row(item: Mapping[str, Any]) -> dict[str, Any]:
    """One worker of the fleet list with the parity row 84 names (snake_case), plus its last complete minute of CPU
    (`cpu_pct`, `cpu_pct_max`, `cpu_minute`: None when unknown, see `worker_cpu`)."""
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
        "cpu_pct": item.get("cpu_pct"),
        "cpu_pct_max": item.get("cpu_pct_max"),
        "cpu_minute": item.get("cpu_minute"),
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
    cpu: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """The fleet header and worker list from `fleet_view` rows (see the module docstring); `cpu` is `worker_cpu`'s
    answer, joined to the rows by worker id."""
    found = dict(cpu or {})
    workers = [
        worker_row({**item, **found.get(str(item.get("worker_id")), {})}) for item in list(rows)[:MAX_WORKERS_SHOWN]
    ]
    started = dict(master_started or {})
    colors: dict[str, dict[str, Any]] = {}
    for worker in workers:
        color = _row_color(worker)
        entry = colors.setdefault(color, {"color": color, "expected": expected_per_color, "count": 0, "stale": 0})
        if worker["fresh"]:
            entry["count"] += 1
        else:
            entry["stale"] += 1
    colors.setdefault(this_color, {"color": this_color, "expected": expected_per_color, "count": 0, "stale": 0})
    for entry in colors.values():
        # The same two helpers give the Overview its Service uptime tile (plan 14.1 row 3: one v1 tile, one number).
        entry["master_pids"] = color_master_pids(workers, entry["color"])
        entry["service_started_at"], entry["service_uptime_s"] = service_since(entry["master_pids"], started, now_s)
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
    "CPU_LOOKBACK_S",
    "MAX_WORKERS_SHOWN",
    "boot_time_s",
    "color_master_pids",
    "file_mtime",
    "fleet_summary",
    "host_uptime_s",
    "master_start_times",
    "process_started_at",
    "service_since",
    "worker_cpu",
    "worker_row",
]
