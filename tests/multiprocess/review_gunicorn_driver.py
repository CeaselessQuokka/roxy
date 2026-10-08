"""Review scenarios on real gunicorn masters (multi-process and failure modes lens), run in a loopback-only namespace.

What this is
    A helper program for tests/multiprocess/test_review_gunicorn_mp.py, run as
    `unshare -rn .venv/bin/python tests/multiprocess/review_gunicorn_driver.py <scenario> <workdir> <credentials> <n>`.
    It reuses the building blocks of `gunicorn_mp_driver.py` (the mock Roblox, state preparation, the `Master`
    wrapper) and prints one JSON object with what it observed.

Why it exists
    Two failure modes only show with real workers: what a worker does when it is stopped while a request is still
    being held (gunicorn's `graceful_timeout` and `timeout` are 30 s in deploy/gunicorn.conf.py, but a tarpit hold
    may last 55 s and a request 60 s), and how the whole worker behaves while another process holds hot.db's write
    lock (C7: answers must keep coming, the per-IP limit must hold fleet-wide, the credential must not be used).

How it works
    Scenarios:
    - `shutdown_hold` (1 worker, production timeouts): ten ordinary requests, then one probe that the tarpit holds
      for 45 s, then SIGTERM to the master. Reports how long the stop took, whether the worker ran its lifespan
      shutdown (`worker_stopped` in the log), what the held client saw, the metrics totals against the requests
      answered, and whether the leader lease was released.
    - `hot_locked` (n workers): a cached key is warmed, then this driver holds hot.db's write lock while 12
      requests from ONE client (fleet per-IP limit 10 per 50 s, degraded share 10 / n per worker) and 12 requests
      from distinct clients arrive at once. Reports statuses and answer times.

What to read next
    tests/multiprocess/gunicorn_mp_driver.py, roxy/worker.py, deploy/gunicorn.conf.py, roxy/abuse/pipeline.py.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import shutil
import signal
import sqlite3
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gunicorn_mp_driver import (  # the shared driver lives next to this file (sys.path line above)
    VENV_BIN,
    Addresses,
    Master,
    MockRoblox,
    base_env,
    default_behavior,
    leader_lease,
    prepare_state,
    recorded_requests,
)

REPO = Path(__file__).resolve().parents[2]
HOLD_S = 45


class ProductionTimeoutsMaster(Master):
    """`Master` with deploy/gunicorn.conf.py's `graceful_timeout = 30` and `timeout = 30`."""

    def start(self) -> None:
        handle = open(self.log, "ab")  # noqa: SIM115 (kept open for the child's lifetime)
        self.proc = subprocess.Popen(
            [
                str(VENV_BIN / "gunicorn"),
                "roxy.asgi:app",
                "--worker-class",
                "roxy.worker.RoxyUvicornWorker",
                "--workers",
                str(self.workers),
                "--bind",
                f"127.0.0.1:{self.port}",
                "--bind",
                f"unix:{self.socket}",
                "--no-control-socket",
                "--graceful-timeout",
                "30",
                "--timeout",
                "30",
            ],
            env=self.env,
            cwd=REPO,
            stdout=handle,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )


async def _shutdown_traffic(master: Master, out: dict[str, Any]) -> None:
    ips = Addresses()
    async with master.client() as client:
        answers = await asyncio.gather(
            *(
                client.get(
                    f"/users.roblox.com/v1/users/{100 + n}",
                    headers={"X-Forwarded-For": ips.next(), "User-Agent": "Roblox/Linux"},
                )
                for n in range(10)
            )
        )
        out["answered_before_stop"] = sum(1 for r in answers if r.status_code == 200)

        async def held() -> str:
            started = time.monotonic()
            try:
                response = await client.get(
                    "/evil.example.com/wp-login.php",
                    headers={"X-Forwarded-For": ips.next(), "User-Agent": "curl/8"},
                    timeout=120,
                )
                return f"status {response.status_code} after {time.monotonic() - started:.1f} s"
            except httpx.HTTPError as exc:
                return f"{type(exc).__name__} after {time.monotonic() - started:.1f} s"

        task = asyncio.ensure_future(held())
        await asyncio.sleep(2.0)  # the probe is now being held by the tarpit
        assert master.proc is not None
        stopping = time.monotonic()
        master.proc.send_signal(signal.SIGTERM)
        out["held_client_saw"] = await task
        code = await asyncio.to_thread(master.proc.wait, 90)
        out["stop_code"] = code
        out["stop_s"] = round(time.monotonic() - stopping, 1)


def scenario_shutdown_hold(work: Path, credentials: Path, workers: int) -> dict[str, Any]:
    mock = MockRoblox(default_behavior).start()
    env = base_env(work, credentials, mock)
    prepare_state(
        env,
        {
            "rotator_enabled": 0,
            "tarpit_enabled": 1,
            "tarpit_on_probe": 1,
            "tarpit_min_seconds": HOLD_S,
            "tarpit_max_seconds": HOLD_S,
        },
        [],
    )
    master = ProductionTimeoutsMaster("dev", work, env, 1)
    out: dict[str, Any] = {"hold_s": HOLD_S}
    try:
        master.start()
        out["ready"] = master.wait_ready()
        if not out["ready"]:
            out["log_tail"] = master.log_tail()
            return out
        asyncio.run(_shutdown_traffic(master, out))
        log = master.log.read_text(errors="replace")
        out["lifespan_shutdown_ran"] = '"worker_stopped"' in log
        out["worker_killed"] = "SIGKILL" in log or "WORKER TIMEOUT" in log or "Worker (pid" in log
        out["recorded"] = recorded_requests(env)
        out["proxy_requests_sent"] = out["answered_before_stop"] + 1
        lease = leader_lease(env)
        out["leader_lease_released"] = bool(lease and lease["expires_ms"] == 0)
        out["log_tail"] = master.log_tail(25)
        return out
    finally:
        master.kill()
        mock.stop()


def _hold(path: str) -> sqlite3.Connection:
    """hot.db's write lock, held by this driver process (a stalled writer, as far as the workers can tell)."""
    conn = sqlite3.connect(path, isolation_level=None, timeout=30, check_same_thread=False)
    conn.execute("BEGIN IMMEDIATE")
    return conn


def _unhold(conn: sqlite3.Connection) -> None:
    conn.execute("ROLLBACK")
    conn.close()


async def _locked_traffic(master: Master, env: dict[str, str], out: dict[str, Any]) -> None:
    ips = Addresses()
    key = "/games.roblox.com/v1/games?universeIds=99"
    async with master.client() as client:
        warm = await client.get(key, headers={"X-Forwarded-For": ips.next(), "User-Agent": "Roblox/Linux"})
        out["warm_status"] = warm.status_code
        await asyncio.sleep(1.0)
        conn = await asyncio.to_thread(_hold, env["ROXY_HOT_DB"])
        started = time.monotonic()
        try:

            async def one(path: str, ip: str) -> tuple[int, str, float]:
                response = await client.get(path, headers={"X-Forwarded-For": ip, "User-Agent": "Roblox/Linux"})
                return response.status_code, response.headers.get("roxy-refusal", ""), time.monotonic() - started

            same = "198.51.100.250"
            results = await asyncio.gather(
                *([one(key, same) for _ in range(12)] + [one(key, ips.next()) for _ in range(12)])
            )
        finally:
            await asyncio.to_thread(_unhold, conn)
    one_client, many = results[:12], results[12:]
    out["one_client"] = dict(Counter(f"{status} {refusal}".strip() for status, refusal, _ in one_client))
    out["one_client_admitted"] = sum(1 for status, _, _ in one_client if status == 200)
    out["distinct_clients"] = dict(Counter(f"{status} {refusal}".strip() for status, refusal, _ in many))
    seconds = sorted(elapsed for _, _, elapsed in results)
    out["answer_s"] = {"median": round(seconds[len(seconds) // 2], 2), "slowest": round(seconds[-1], 2)}


def scenario_hot_locked(work: Path, credentials: Path, workers: int) -> dict[str, Any]:
    mock = MockRoblox(default_behavior).start()
    env = base_env(work, credentials, mock)
    prepare_state(env, {"rotator_enabled": 0, "tarpit_enabled": 0}, [])
    master = Master("dev", work, env, workers)
    out: dict[str, Any] = {"workers": workers}
    try:
        master.start()
        out["ready"] = master.wait_ready()
        if not out["ready"]:
            out["log_tail"] = master.log_tail()
            return out
        asyncio.run(_locked_traffic(master, env, out))
        out["cookie_calls"] = sum(1 for call in mock.snapshot() if "cookie" in call.headers)
        out["stop_code"], out["stop_s"] = master.stop()
        out["log_tail"] = master.log_tail(10)
        return out
    finally:
        master.kill()
        mock.stop()


SCENARIOS = {"shutdown_hold": scenario_shutdown_hold, "hot_locked": scenario_hot_locked}


def main() -> int:
    scenario, work, credentials, workers = sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3]), int(sys.argv[4])
    ip = shutil.which("ip") or "/usr/sbin/ip"
    subprocess.run([ip, "link", "set", "lo", "up"], check=False, capture_output=True)  # a fresh namespace
    with contextlib.suppress(KeyboardInterrupt):
        result = SCENARIOS[scenario](work, credentials, workers)
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
