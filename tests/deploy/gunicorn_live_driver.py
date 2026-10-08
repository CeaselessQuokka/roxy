"""Drive real gunicorn masters with deploy/gunicorn.conf.py inside a loopback-only network namespace.

What this is
    A helper program for tests/deploy/test_deploy_gunicorn.py, run as
    `unshare -rn .venv/bin/python tests/deploy/gunicorn_live_driver.py <scenario> <workdir> <credentials dir>`.
    It brings up the loopback interface of its private network namespace, runs deploy/prestart.py (migrations and
    defaults, as the unit's ExecStartPre does), starts one or two colors exactly as roxy@.service would
    (`gunicorn -c deploy/gunicorn.conf.py roxy.asgi:app`, ROXY_ENV=production), runs the scenario's checks, and
    prints one JSON object with what it observed. The test asserts on that JSON.

Why it exists
    These tests start the whole app. Whatever the app's background jobs do now or later (credential probes,
    rotator checks), a test must never reach Roblox or any other real system (plan 19.12), and the conftest socket
    guard only protects the pytest process, not the gunicorn processes. A fresh network namespace has nothing but
    a loopback interface, so the guarantee holds for every child process. Doing the checks from inside the same
    namespace keeps TCP and Unix socket checks simple.

How it works
    Scenarios: `sockets` (listeners, socket modes, readiness, a graceful stop), `flush` (stop the master with
    SIGTERM while eight threads keep sending requests, then compare the requests the clients saw answered with the
    totals in metrics.db), `lowmem` (start with one worker from the low-memory marker, then `gunicornc worker add`),
    `leader` (blue and green share the state directory; exactly one leader across both colors, and leadership moves
    when the leading color stops). Each process gets its own log file in the work directory; the JSON includes the
    tail of a log when something failed. The `flush` load is OPTIONS requests through the proxy route: the app
    answers them itself (204) and records each one, and they never need an upstream, which this network namespace
    does not have.

What to read next
    tests/deploy/test_deploy_gunicorn.py, deploy/gunicorn.conf.py, src/roxy/internal_app.py.
"""

from __future__ import annotations

import http.client
import json
import os
import shutil
import signal
import socket
import sqlite3
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[2]
VENV_BIN = REPO / ".venv" / "bin"
# A proxy path the app answers itself for OPTIONS (204, recorded as options_local; nothing goes upstream).
PROXY_PATH = "/games.roblox.com/v1/games?universeIds=1"


class UnixHTTPConnection(http.client.HTTPConnection):
    """http.client over a Unix socket (the internal listener)."""

    def __init__(self, path: str, timeout: float = 3.0) -> None:
        super().__init__("localhost", timeout=timeout)
        self.unix_path = path

    def connect(self) -> None:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(self.unix_path)
        self.sock = sock


def request(conn: http.client.HTTPConnection, method: str, path: str) -> tuple[int, str]:
    try:
        conn.request(method, path, headers={"Host": "roxy.example.test"})
        response = conn.getresponse()
        return response.status, response.read().decode("utf-8", "replace")
    except OSError as exc:
        return 0, str(exc)
    finally:
        conn.close()


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class Color:
    """One color: its environment, process, sockets and log."""

    def __init__(self, name: str, work: Path, credentials: Path, *, workers: int = 2) -> None:
        self.name = name
        self.work = work
        self.port = free_port()
        self.run_dir = work / "run" / f"roxy-{name}"
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.run_dir.chmod(0o750)  # what systemd's RuntimeDirectoryMode makes
        self.socket = self.run_dir / "internal.sock"
        self.log = work / f"gunicorn-{name}.log"
        self.env = {
            "PATH": f"{VENV_BIN}:/usr/bin:/bin",
            "HOME": str(work),
            "LANG": "C.UTF-8",
            "ROXY_ENV": "production",
            "ROXY_COLOR": name,
            "ROXY_WORKERS": str(workers),
            "ROXY_BIND": f"127.0.0.1:{self.port}",
            "ROXY_INTERNAL_SOCKET": str(self.socket),
            "ROXY_STATE_DIR": str(work / "state"),
            "ROXY_DEPLOY_STATE_DIR": str(work / "deploy-state"),
            "ROXY_SITE_ORIGIN": "https://roxy.example.test",
            "ROXY_LOG_LEVEL": "info",
            "ROXY_ROTATOR_IP_ECHO_URL": "http://127.0.0.1:9/ip",
            "CREDENTIALS_DIRECTORY": str(credentials),
        }
        self.proc: subprocess.Popen[bytes] | None = None

    def prestart(self) -> tuple[int, str]:
        result = subprocess.run(
            [str(VENV_BIN / "python"), str(REPO / "deploy" / "prestart.py")],
            env=self.env,
            cwd=REPO,
            capture_output=True,
            text=True,
            check=False,
        )
        return result.returncode, result.stdout + result.stderr

    def start(self) -> None:
        handle = open(self.log, "ab")  # noqa: SIM115 (kept open for the child's lifetime)
        self.proc = subprocess.Popen(
            [str(VENV_BIN / "gunicorn"), "-c", str(REPO / "deploy" / "gunicorn.conf.py"), "roxy.asgi:app"],
            env=self.env,
            cwd=REPO,
            stdout=handle,
            stderr=subprocess.STDOUT,
        )

    def ready(self) -> dict[str, Any] | None:
        status, body = request(UnixHTTPConnection(str(self.socket)), "GET", "/internal/ready")
        if status != 200:
            return None
        return dict(json.loads(body))

    def wait_ready(self, timeout: float = 40.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.proc is not None and self.proc.poll() is not None:
                return False
            if self.ready():
                return True
            time.sleep(0.2)
        return False

    def ctl(self, command: str) -> dict[str, Any]:
        result = subprocess.run(
            [str(VENV_BIN / "gunicornc"), "-s", str(self.run_dir / "gunicorn.ctl"), "-c", command, "-j"],
            capture_output=True,
            text=True,
            env=self.env,
            check=False,
        )
        if result.returncode != 0:
            return {"error": result.stderr.strip()}
        return dict(json.loads(result.stdout))

    def stop(self, timeout: float = 45.0) -> tuple[int | None, float]:
        assert self.proc is not None
        started = time.monotonic()
        self.proc.send_signal(signal.SIGTERM)
        try:
            code = self.proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            code = None
        return code, time.monotonic() - started

    def log_tail(self, lines: int = 30) -> str:
        try:
            return "\n".join(self.log.read_text(errors="replace").splitlines()[-lines:])
        except OSError:
            return ""


def heartbeats(work: Path) -> list[dict[str, Any]]:
    path = work / "state" / "metrics.db"
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5)
    try:
        rows = conn.execute("SELECT pid, color, is_leader, last_seen, worker_id FROM worker_heartbeat").fetchall()
    finally:
        conn.close()
    return [{"pid": r[0], "color": r[1], "is_leader": r[2], "last_seen": r[3], "worker_id": r[4]} for r in rows]


def recorded_requests(work: Path, method: str) -> int:
    """Requests of `method` in the per-minute rollups of metrics.db (what the recorder flushed)."""
    conn = sqlite3.connect(f"file:{work / 'state' / 'metrics.db'}?mode=ro", uri=True, timeout=5)
    try:
        row = conn.execute(
            "SELECT COALESCE(SUM(r.requests), 0) FROM rollup_minute r JOIN dims d ON d.dim_hash = r.dim_hash"
            " WHERE d.method = ?",
            (method,),
        ).fetchone()
    finally:
        conn.close()
    return int(row[0])


def lease(work: Path) -> dict[str, Any] | None:
    conn = sqlite3.connect(f"file:{work / 'state' / 'hot.db'}?mode=ro", uri=True, timeout=5)
    try:
        row = conn.execute("SELECT holder, epoch, expires_ms FROM lease WHERE name = 'leader'").fetchone()
    finally:
        conn.close()
    return None if row is None else {"holder": row[0], "epoch": row[1], "expires_ms": row[2]}


def mode(path: Path) -> str:
    try:
        return f"{stat.S_IMODE(path.lstat().st_mode):04o}"
    except OSError:
        return "missing"


# ------------------------------------------------------------------------------------------------- scenarios


def scenario_sockets(work: Path, credentials: Path) -> dict[str, Any]:
    blue = Color("blue", work, credentials)
    out: dict[str, Any] = {}
    out["prestart_code"], out["prestart_output"] = blue.prestart()
    out["prestart_again_code"], out["prestart_again_output"] = blue.prestart()
    blue.start()
    out["ready"] = blue.wait_ready()
    out["ready_body"] = blue.ready()
    out["internal_socket_mode"] = mode(blue.socket)
    out["control_socket_mode"] = mode(blue.run_dir / "gunicorn.ctl")
    # A fresh worker's first request warms caches and compiles rules, so these get the smoke test's 20 s timeout.
    status, detail = request(http.client.HTTPConnection("127.0.0.1", blue.port, timeout=20), "GET", "/internal/version")
    out["tcp_internal_version"], out["tcp_internal_version_detail"] = status, detail[:300]
    out["tcp_home"] = request(http.client.HTTPConnection("127.0.0.1", blue.port, timeout=20), "GET", "/")[0]
    out["uds_version"] = request(UnixHTTPConnection(str(blue.socket)), "GET", "/internal/version")
    out["stats"] = blue.ctl("show stats")
    version = json.loads(out["uds_version"][1]).get("Version") if out["uds_version"][0] == 200 else None
    smoke = subprocess.run(
        [
            str(VENV_BIN / "python"),
            str(REPO / "scripts" / "smoke_remote.py"),
            "--color",
            "blue",
            "--expect-version",
            str(version),
            "--bind",
            f"127.0.0.1:{blue.port}",
            "--socket",
            str(blue.socket),
            "--site-origin",
            "https://roxy.example.test",
            "--skip-proxy",
        ],
        capture_output=True,
        text=True,
        env=blue.env,
        cwd=REPO,
        check=False,
    )
    out["smoke_code"], out["smoke_output"] = smoke.returncode, smoke.stdout + smoke.stderr
    out["heartbeats_before"] = len(heartbeats(work))
    time.sleep(6)  # one heartbeat interval, so both workers have a row
    out["heartbeats_running"] = len(heartbeats(work))
    out["stop_code"], out["stop_seconds"] = blue.stop()
    out["heartbeats_after"] = len(heartbeats(work))
    log = blue.log.read_text(errors="replace")
    out["worker_stopped_lines"] = log.count('"worker_stopped"') + log.count("worker_stopped")
    out["master_ready_line"] = "roxy master ready: color=blue workers=2 of 2 (normal mode)" in log
    out["log_tail"] = blue.log_tail()
    return out


def scenario_flush(work: Path, credentials: Path) -> dict[str, Any]:
    """Plan 17.1 test_stop_flushes_metrics: stop a color under load; the metrics totals must equal the requests
    served. "Served" is what a client saw: a complete 204. A request the stopping server never took fails at the
    client and must not be counted either."""
    blue = Color("blue", work, credentials)
    out: dict[str, Any] = {}
    out["prestart_code"], out["prestart_output"] = blue.prestart()
    blue.start()
    out["ready"] = blue.wait_ready()
    served = 0
    others: dict[str, int] = {}
    lock = threading.Lock()
    done = threading.Event()

    def load() -> None:
        nonlocal served
        while not done.is_set():
            status, _ = request(http.client.HTTPConnection("127.0.0.1", blue.port, timeout=30), "OPTIONS", PROXY_PATH)
            with lock:
                if status == 204:
                    served += 1
                else:
                    others[str(status)] = others.get(str(status), 0) + 1
            if status == 0:
                time.sleep(0.02)  # stopped or not listening: no point hammering a closed port

    threads = [threading.Thread(target=load, daemon=True) for _ in range(8)]
    for thread in threads:
        thread.start()
    time.sleep(3)  # long enough for the periodic flush to have written part of the load already
    with lock:
        out["served_before_stop"] = served
    out["stop_code"], out["stop_seconds"] = blue.stop()  # SIGTERM while the threads keep sending
    done.set()
    for thread in threads:
        thread.join(timeout=40)
    out["served"] = served
    out["other_statuses"] = others
    out["recorded"] = recorded_requests(work, "OPTIONS")
    out["heartbeats_after"] = len(heartbeats(work))
    log = blue.log.read_text(errors="replace")
    out["worker_stopped_lines"] = log.count('"worker_stopped"') + log.count("worker_stopped")
    out["log_tail"] = blue.log_tail()
    return out


def scenario_lowmem(work: Path, credentials: Path) -> dict[str, Any]:
    blue = Color("blue", work, credentials)
    out: dict[str, Any] = {}
    out["prestart_code"], _ = blue.prestart()
    marker = work / "deploy-state" / "start-workers-blue"
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text("1\n")
    blue.start()
    out["ready"] = blue.wait_ready()
    out["stats_start"] = blue.ctl("show stats")
    marker.unlink()
    out["worker_add"] = blue.ctl("worker add 1")
    deadline = time.monotonic() + 30
    stats: dict[str, Any] = {}
    while time.monotonic() < deadline:
        stats = blue.ctl("show stats")
        if stats.get("workers_current") == 2:
            break
        time.sleep(0.3)
    out["stats_after"] = stats
    out["ready_after"] = blue.ready() is not None
    out["stop_code"], _ = blue.stop()
    out["master_ready_line"] = "workers=1 of 2 (low-memory mode)" in blue.log.read_text(errors="replace")
    out["log_tail"] = blue.log_tail()
    return out


def scenario_leader(work: Path, credentials: Path) -> dict[str, Any]:
    blue = Color("blue", work, credentials)
    green = Color("green", work, credentials)
    out: dict[str, Any] = {}
    out["prestart_code"], _ = blue.prestart()
    blue.start()
    green.start()
    out["ready"] = blue.wait_ready() and green.wait_ready()
    samples: list[list[dict[str, Any]]] = []
    # Steady state: both colors run 2 workers each; a heartbeat every 5 s carries each worker's leader flag.
    time.sleep(7)
    for _ in range(8):
        now = int(time.time())
        fresh = [row for row in heartbeats(work) if now - row["last_seen"] <= 12]
        samples.append(fresh)
        time.sleep(1)
    out["steady_samples"] = samples
    out["lease_before"] = lease(work)
    leader_colors = {row["color"] for sample in samples for row in sample if row["is_leader"]}
    out["leader_colors"] = sorted(leader_colors)
    leader = blue if out["leader_colors"] == ["blue"] else green
    other = green if leader is blue else blue
    out["stopped_color"] = leader.name
    out["stop_code"], out["stop_seconds"] = leader.stop()
    deadline = time.monotonic() + 30
    after: list[dict[str, Any]] = []
    while time.monotonic() < deadline:
        now = int(time.time())
        rows = [row for row in heartbeats(work) if now - row["last_seen"] <= 7]
        current = lease(work)
        if (
            current
            and current["holder"] in {row["worker_id"] for row in rows if row["color"] == other.name}
            and any(row["is_leader"] for row in rows if row["color"] == other.name)
        ):
            after = rows
            break
        time.sleep(0.5)
    out["after_rows"] = after
    out["lease_after"] = lease(work)
    out["other_color"] = other.name
    other.stop()
    out["log_tail_blue"] = blue.log_tail(15)
    out["log_tail_green"] = green.log_tail(15)
    return out


SCENARIOS = {
    "sockets": scenario_sockets,
    "flush": scenario_flush,
    "lowmem": scenario_lowmem,
    "leader": scenario_leader,
}


def main() -> int:
    scenario, work, credentials = sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3])
    ip = shutil.which("ip") or "/usr/sbin/ip"
    # A fresh namespace from `unshare -rn` has loopback down; systemd's PrivateNetwork= brings it up itself.
    subprocess.run([ip, "link", "set", "lo", "up"], check=False, capture_output=True)
    os.umask(0o027)  # the unit's UMask
    result = SCENARIOS[scenario](work, credentials)
    print(json.dumps(result, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
