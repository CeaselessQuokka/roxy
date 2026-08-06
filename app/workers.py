"""Cross-worker process registry.

The dashboard used to show "Worker Uptime" from whichever gunicorn worker
happened to answer the poll, so the number jumped around: workers are recycled
at `max_requests`, so at any moment the four of them have four different ages.
That reading is real but useless — what an admin actually wants to know is how
long the SERVICE has been up, and, separately, what each worker is doing.

So every worker heartbeats a small record (pid, start time, memory, threads,
requests served) into one flock-guarded file, exactly like every other piece of
cross-worker state here. From that the dashboard gets:

  - the fleet: one row per live worker, with its own uptime and RSS
  - service uptime: taken from the gunicorn MASTER process, which survives
    worker recycles and only changes when the service is actually restarted
  - host uptime: how long the box has been up, for "since the last reboot"

Everything is read from /proc, so there is no new dependency. On a platform
without /proc (or in a test harness) the precise values degrade to this
process's own start time rather than failing.
"""

import config
import os
import time
from threading import Lock, Thread

from lockfile import LockedJSON

_registry = LockedJSON(lambda: config.WORKERS_FILE)

_pid = os.getpid()
_started_at = time.time()  # Fallback; _proc_start_time is used when /proc is available.

# Two counters, because one number cannot answer both questions asked of it.
#
#   _requests_served - EVERY request this worker handled, dashboard polls
#       included. This is the one that matters for lifecycle: gunicorn counts
#       exactly the same set toward max_requests, so it explains why a worker
#       gets recycled and its uptime resets.
#   _proxied_served  - only requests aimed at the proxy itself (served or
#       refused). This is the one that answers "is anybody actually using it?"
#
# Reporting only the first was actively misleading: an idle proxy with the
# dashboard open still ticks up once every few seconds, which reads as traffic.
_requests_lock = Lock()
_requests_served = 0
_proxied_served = 0


def count_request():
    """Count one request served by this worker (called from an after_request hook)."""
    global _requests_served
    with _requests_lock:
        _requests_served += 1


def count_proxied():
    """Count one request aimed at the proxy route, whether it was served or refused."""
    global _proxied_served
    with _requests_lock:
        _proxied_served += 1


def _read_first_line(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8") as file:
            return file.readline()
    except OSError:
        return ""


def _boot_time() -> float:
    """Epoch seconds when the host booted, from /proc/stat. 0.0 if unavailable."""
    try:
        with open("/proc/stat", "r", encoding="utf-8") as file:
            for line in file:
                if line.startswith("btime "):
                    return float(line.split()[1])
    except (OSError, ValueError, IndexError):
        pass
    return 0.0


def _proc_start_time(pid: int) -> float:
    """Epoch seconds when `pid` started, from /proc/<pid>/stat. 0.0 if unavailable.

    Field 22 is the start time in clock ticks since boot. The comm field (2) can
    contain spaces and parentheses, so the fields are read from after the LAST
    ')' rather than by splitting the whole line — splitting naively is the
    classic way this parse breaks on a process named "(my app)".
    """
    raw = _read_first_line(f"/proc/{pid}/stat")
    boot = _boot_time()
    if not raw or not boot:
        return 0.0
    try:
        fields = raw[raw.rindex(")") + 2 :].split()
        ticks = float(fields[19])  # Field 22 overall; the split starts at field 3.
        return boot + ticks / os.sysconf("SC_CLK_TCK")
    except (ValueError, IndexError, OSError):
        return 0.0


def _rss_bytes() -> int:
    """This process's resident memory, from /proc/self/statm. 0 if unavailable."""
    raw = _read_first_line("/proc/self/statm")
    if not raw:
        return 0
    try:
        return int(raw.split()[1]) * os.sysconf("SC_PAGE_SIZE")  # Field 2 = resident pages.
    except (ValueError, IndexError, OSError):
        return 0


def _thread_count() -> int:
    try:
        return len(os.listdir(f"/proc/{_pid}/task"))
    except OSError:
        return 0


def host_uptime() -> float:
    """Seconds since the host booted. 0.0 if unavailable."""
    raw = _read_first_line("/proc/uptime")
    try:
        return float(raw.split()[0])
    except (ValueError, IndexError):
        return 0.0


def _own_start_time() -> float:
    return _proc_start_time(_pid) or _started_at


def _prune(workers: dict, now: float):
    """Drop workers that stopped heartbeating, then bound the map."""
    stale = config.WORKER_STALE_AFTER
    for key in [k for k, w in workers.items() if now - float(w.get("LastSeen", 0) or 0) > stale]:
        workers.pop(key, None)
    if len(workers) > config.MAX_TRACKED_WORKERS:
        for key, _ in sorted(workers.items(), key=lambda kv: float(kv[1].get("LastSeen", 0) or 0))[
            : len(workers) - config.MAX_TRACKED_WORKERS
        ]:
            workers.pop(key, None)


def _sync_service_identity(data: dict, now: float, workers: dict):
    """Keep ServiceStartedAt pinned to the CURRENT gunicorn master.

    A worker being recycled must not look like a restart, and a real restart must
    not inherit the old start time. The master pid is exactly the signal that
    distinguishes them: it is stable across worker recycles and necessarily
    different after a restart. When it changes, any entries still in the file
    belong to the previous service instance and are dropped.
    """
    master = os.getppid()
    if int(data.get("MasterPid", 0) or 0) != master:
        data["MasterPid"] = master
        # The master's own start time is the truth; fall back to this worker's
        # (workers start within a second of the master anyway).
        data["ServiceStartedAt"] = _proc_start_time(master) or _own_start_time()
        workers.clear()
    elif not float(data.get("ServiceStartedAt", 0) or 0):
        data["ServiceStartedAt"] = _proc_start_time(master) or _own_start_time()


def heartbeat():
    """Refresh this worker's registry entry (and prune dead siblings)."""
    now = time.time()
    with _requests_lock:
        served, proxied = _requests_served, _proxied_served
    entry = {
        "Pid": _pid,
        "StartedAt": _own_start_time(),
        "LastSeen": now,
        "RSS": _rss_bytes(),
        "Threads": _thread_count(),
        "Requests": served,
        "Proxied": proxied,
    }

    def mutate(data):
        workers = data.setdefault("Workers", {})
        if not isinstance(workers, dict):
            workers = data["Workers"] = {}
        _prune(workers, now)
        _sync_service_identity(data, now, workers)
        workers[str(_pid)] = entry

    _registry.update(mutate)


def get_state() -> dict:
    """The fleet view for the dashboard. Lock-free (atomic writes, whole-file reads)."""
    data = _registry.read()
    now = time.time()
    raw = data.get("Workers", {})
    workers = []
    if isinstance(raw, dict):
        for key, worker in raw.items():
            if not isinstance(worker, dict):
                continue
            last_seen = float(worker.get("LastSeen", 0) or 0)
            if now - last_seen > config.WORKER_STALE_AFTER:
                continue  # Gone; the next heartbeat will remove it from the file.
            started = float(worker.get("StartedAt", 0) or 0)
            workers.append(
                {
                    "Pid": int(worker.get("Pid", 0) or 0) or key,
                    "StartedAt": started,
                    "Uptime": max(0.0, now - started) if started else 0.0,
                    "LastSeen": last_seen,
                    "RSS": int(worker.get("RSS", 0) or 0),
                    "Threads": int(worker.get("Threads", 0) or 0),
                    "Requests": int(worker.get("Requests", 0) or 0),
                    "Proxied": int(worker.get("Proxied", 0) or 0),
                    "IsThisWorker": int(worker.get("Pid", 0) or 0) == _pid,
                }
            )
    workers.sort(key=lambda w: w["StartedAt"] or 0)
    service_started = float(data.get("ServiceStartedAt", 0) or 0)
    return {
        "Workers": workers,
        "Count": len(workers),
        "Expected": int(os.environ.get("ROXY_WORKERS", "4") or 4),
        "TotalRSS": sum(w["RSS"] for w in workers),
        "TotalRequests": sum(w["Requests"] for w in workers),
        "TotalProxied": sum(w["Proxied"] for w in workers),
        "ServiceStartedAt": service_started,
        # The headline number: how long the SERVICE has been up, unaffected by a
        # worker being recycled underneath it.
        "ServiceUptime": max(0.0, now - service_started) if service_started else 0.0,
        "HostUptime": host_uptime(),
        "MasterPid": int(data.get("MasterPid", 0) or 0),
        "ThisWorker": _pid,
        "MaxRequests": int(os.environ.get("ROXY_MAX_REQUESTS", "2000") or 2000),
    }


def run_loop():
    while True:
        try:
            heartbeat()
        except Exception:
            pass  # The registry is observability only; it must never take a worker down.
        time.sleep(max(1, int(config.WORKER_HEARTBEAT_INTERVAL)))


# Register immediately so a worker appears in the fleet the moment it boots,
# rather than one heartbeat interval later.
try:
    heartbeat()
except Exception:
    pass
Thread(target=run_loop, daemon=True).start()
