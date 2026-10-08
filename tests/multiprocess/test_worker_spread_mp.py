"""Connections spread over the workers with the production gunicorn configuration (wire open issue "uneven load").

What this is
    One test that starts gunicorn exactly as roxy@.service does (`gunicorn -c deploy/gunicorn.conf.py
    roxy.asgi:app`, 4 workers) inside `unshare -rn` (a namespace with nothing but loopback), sends traffic over fresh
    TCP connections and over a 16-connection keep-alive pool (what nginx keeps open to the app), and checks that
    every worker gets a fair share, that the internal Unix socket still answers (it is created once by the master
    and shared, because SO_REUSEPORT does not apply to Unix sockets), and that the master stops cleanly. This file
    is also its own driver: run as a script inside the namespace, it prints one JSON object.

Why it exists
    With one listening socket shared by every worker, the worker that went idle last accepts nearly every new
    connection (measured: 70/10/0/0 of 80 fresh connections on 4 workers, 130/30/0/0 of the requests on a
    keep-alive pool), so one CPU core does the work of all of them. `reuse_port = True` gives every worker its own
    TCP listener and the kernel spreads connections by a hash of the client address and port (measured 24/20/19/17
    and 50/50/30/30). A configuration change that loses this must fail a test.

How it works
    The driver reuses tests/multiprocess/gunicorn_mp_driver.py (mock Roblox, state preparation, `Master`); each
    worker's `proxied` heartbeat counter says how many proxy requests it served. The thresholds leave room for the
    randomness of the hash (for 80 connections on 4 workers, a worker below 5 has a probability near 1e-5).

What to read next
    deploy/gunicorn.conf.py (`reuse_port`, `on_starting`, `post_fork`), roxy/worker.py, roxy/internal_app.py.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest

REPO = Path(__file__).resolve().parents[2]
WORKERS = 4

pytestmark = [
    pytest.mark.multiprocess,
    pytest.mark.skipif(sys.platform != "linux", reason="real gunicorn workers need Linux"),
]


# ------------------------------------------------------------------------------------------------- the test


def _can_unshare() -> bool:
    try:
        result = subprocess.run(["unshare", "-rn", "true"], capture_output=True, timeout=10, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


@pytest.mark.timeout(240)
def test_worker_connections_spread_with_the_production_config(tmp_path: Path, credentials_dir: Path) -> None:
    if not _can_unshare() or not (shutil.which("ip") or Path("/usr/sbin/ip").exists()):
        pytest.skip("needs unprivileged user and network namespaces (unshare -rn) and ip")
    if not (REPO / ".venv" / "bin" / "gunicorn").exists():
        pytest.skip("gunicorn is not installed in .venv")
    quiet = tmp_path / "creds"
    quiet.mkdir(mode=0o700)
    for path in credentials_dir.iterdir():
        if path.name not in ("smtp_password", "alert_webhook_url"):  # alerts stay in the log
            (quiet / path.name).write_bytes(path.read_bytes())
            (quiet / path.name).chmod(0o600)
    work = tmp_path / "w"
    result = subprocess.run(
        ["unshare", "-rn", str(REPO / ".venv" / "bin" / "python"), __file__, str(work), str(quiet), str(WORKERS)],
        capture_output=True,
        text=True,
        timeout=220,
        check=False,
        cwd=REPO,
    )
    lines = [line for line in result.stdout.splitlines() if line.startswith("{")]
    failure = f"driver failed ({result.returncode}):\n{result.stderr[-4000:]}"
    assert result.returncode == 0, failure
    assert lines, failure
    out = json.loads(lines[-1])
    print("\n" + json.dumps({k: v for k, v in out.items() if k != "log_tail"}))
    log = out.get("log_tail", "")
    assert out["ready"], log
    assert out["worker_pids"] == WORKERS, log
    fresh = out["fresh_80"]
    assert sum(fresh) == 80, fresh
    assert len(fresh) == WORKERS, fresh
    assert min(fresh) >= 5, f"every worker takes a share of new connections: {fresh}"
    pool = out["keepalive_pool_160"]
    assert sum(pool) == 160, pool
    assert sum(1 for count in pool if count > 0) >= 3, f"nginx's keep-alive connections spread too: {pool}"
    assert max(pool) <= 120, pool
    assert out["internal_version_statuses"] == [200] * 8, "the shared internal Unix socket serves every request"
    assert out["internal_socket_mode"] == "0o660"
    assert out["stop_code"] == 0, log
    assert out["internal_socket_after_stop"] is False, "the master removes the socket file when it exits"


# ------------------------------------------------------------------------------------------------ the driver


def _driver(work: Path, credentials: Path, workers: int) -> dict[str, Any]:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import httpx
    from gunicorn_mp_driver import VENV_BIN, Addresses, Master, MockRoblox, base_env, default_behavior, prepare_state

    class ConfigMaster(Master):
        """`Master` started from deploy/gunicorn.conf.py, as roxy@.service starts it."""

        def start(self) -> None:
            self.env = {**self.env, "ROXY_DEPLOY_STATE_DIR": str(self.socket.parent)}
            handle = open(self.log, "ab")  # noqa: SIM115 (kept open for the child's lifetime)
            self.proc = subprocess.Popen(
                [str(VENV_BIN / "gunicorn"), "-c", str(REPO / "deploy" / "gunicorn.conf.py"), "roxy.asgi:app"],
                env=self.env,
                cwd=REPO,
                stdout=handle,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )

    def by_pid(master: Master) -> dict[int, int]:
        return {int(row["pid"]): int(row.get("proxied") or 0) for row in master.worker_rows()}

    async def served_since(master: Master, before: dict[int, int], expected: int) -> list[int]:
        deadline = time.monotonic() + 20
        counts: list[int] = []
        while time.monotonic() < deadline:
            now = by_pid(master)
            counts = sorted((now[pid] - before.get(pid, 0) for pid in now), reverse=True)
            if sum(counts) >= expected:
                break
            await asyncio.sleep(0.5)
        return counts

    async def traffic(master: Master, out: dict[str, Any]) -> None:
        ips = Addresses()
        numbers = iter(range(1000, 100_000))

        def headers() -> dict[str, str]:
            return {"X-Forwarded-For": ips.next(), "User-Agent": "Roblox/Linux"}

        async with master.client() as fresh:  # no keep-alive: a new connection per request
            before = by_pid(master)
            for _ in range(4):
                await asyncio.gather(
                    *(fresh.get(f"/users.roblox.com/v1/users/{next(numbers)}", headers=headers()) for _ in range(20))
                )
            out["fresh_80"] = await served_since(master, before, 80)
        limits = httpx.Limits(max_connections=16, max_keepalive_connections=16)
        async with httpx.AsyncClient(
            base_url=f"http://127.0.0.1:{master.port}", limits=limits, timeout=60, trust_env=False
        ) as pool:
            before = by_pid(master)
            for _ in range(10):
                await asyncio.gather(
                    *(pool.get(f"/users.roblox.com/v1/users/{next(numbers)}", headers=headers()) for _ in range(16))
                )
            out["keepalive_pool_160"] = await served_since(master, before, 160)
        async with master.internal_client() as internal:
            answers = await asyncio.gather(*(internal.get("/internal/version") for _ in range(8)))
            out["internal_version_statuses"] = [answer.status_code for answer in answers]

    mock = MockRoblox(default_behavior).start()
    env = base_env(work, credentials, mock)
    state = Path(env["ROXY_STATE_DIR"])
    state.mkdir(parents=True, exist_ok=True)
    state.chmod(0o750)
    prepare_state(env, {"rotator_enabled": 0, "tarpit_enabled": 0, "allowed_requests_per_minute": 1000}, [])
    master = ConfigMaster("dev", work, env, workers)
    out: dict[str, Any] = {"workers": workers}
    try:
        master.start()
        out["ready"] = master.wait_ready()
        if not out["ready"]:
            out["log_tail"] = master.log_tail()
            return out
        out["worker_pids"] = len({row["pid"] for row in master.worker_rows()})
        out["internal_socket_mode"] = oct(stat.S_IMODE(os.stat(master.socket).st_mode))
        asyncio.run(traffic(master, out))
        out["stop_code"], out["stop_s"] = master.stop()
        out["internal_socket_after_stop"] = master.socket.exists()
        out["log_tail"] = master.log_tail(15)
        return out
    finally:
        master.kill()
        mock.stop()


def main() -> int:
    work, credentials, workers = Path(sys.argv[1]), Path(sys.argv[2]), int(sys.argv[3])
    ip = shutil.which("ip") or "/usr/sbin/ip"
    subprocess.run([ip, "link", "set", "lo", "up"], check=False, capture_output=True)  # a fresh namespace
    work.mkdir(parents=True, exist_ok=True)
    print(json.dumps(_driver(work, credentials, workers)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
