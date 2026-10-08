"""Drive real gunicorn masters with `RoxyUvicornWorker` against a local mock Roblox, inside a loopback-only namespace.

What this is
    A helper program for tests/multiprocess/test_gunicorn_mp.py, run as
    `unshare -rn .venv/bin/python tests/multiprocess/gunicorn_mp_driver.py <scenario> <workdir> <credentials> <n>`.
    It prepares temporary databases (migrations, built-in defaults, the scenario's settings and rules), starts a small
    asyncio HTTP server that plays every Roblox host, starts gunicorn (`roxy.asgi:app`, worker class
    `roxy.worker.RoxyUvicornWorker`, n workers, a TCP port plus the internal Unix socket), sends the scenario's
    traffic, stops gunicorn gracefully and prints one JSON object with everything it observed. The test asserts on
    that JSON.

Why it exists
    Plan 19.3 and C6: every limit must hold with 1, 2 and 4 real worker processes, and only real gunicorn workers
    show it (the worker class, the lifespan in each worker, shared SQLite through separate processes, the shutdown
    flush). The conftest socket guard protects only the pytest process, so the whole run happens in a fresh network
    namespace that has nothing but loopback: whatever the app does, it cannot reach a real system (plan 19.12).
    Roblox hosts are never resolved: the development-only egress override (`ROXY_TEST_UPSTREAM_BASE`,
    `roxy/egress/targets.py`) sends every Roblox request to the mock after the URL was validated as the real one.

How it works
    Scenarios:
    - `fleet` (n workers): per-IP limit exactness, fleet single-flight, an upstream bucket shared by all workers, a
      settings change reaching every worker within 2 s (each worker reports its `ConfigVersion` on the internal
      socket), exactly one leader, and recorded metrics totals equal to the proxy requests sent (read after the
      graceful stop, which flushes every worker's recorder).
    - `two_masters`: two gunicorn masters (blue and green, 2 workers each) on one state directory: exactly one leader
      across both, and the other color takes over when the leading color stops.
    - `cooldown_429` (n workers): plan 19.10 row 7. The mock answers the first call of an endpoint with 429 and
      `Retry-After: 30`; traffic continues at 4 requests per second for 92 s with distinct keys.
    Requests go out on fresh connections (no keep-alive), so the kernel spreads them over the workers.

What to read next
    tests/multiprocess/test_gunicorn_mp.py (the assertions), roxy/worker.py, roxy/lifespan.py and
    tests/deploy/gunicorn_live_driver.py (the deploy variant with deploy/gunicorn.conf.py).
"""

from __future__ import annotations

import asyncio
import contextlib
import itertools
import json
import os
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import threading
import time
from collections import Counter
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx

REPO = Path(__file__).resolve().parents[2]
VENV_BIN = REPO / ".venv" / "bin"
NETS = ("192.0.2", "198.51.100", "203.0.113")  # documentation ranges (RFC 5737)
SINGLE_FLIGHT_UNIVERSE = "4242"
COOLDOWN_SETTLE_S = 1.5
"""Slack around cooldown edges: the cooldown is kept in wall-clock milliseconds, and the WSL wall clock steps."""


# ---------------------------------------------------------------------------------------------- the mock Roblox


@dataclass(frozen=True)
class Call:
    at: float  # time.monotonic() when the request arrived
    method: str
    host: str
    path: str
    query: dict[str, list[str]]
    headers: dict[str, str]


@dataclass
class Reply:
    status: int = 200
    body: bytes = b"{}"
    headers: dict[str, str] = field(default_factory=dict)
    delay_s: float = 0.0


class MockRoblox:
    """An asyncio HTTP/1.1 server (with keep-alive) on 127.0.0.1 that records every call and answers by `behavior`."""

    def __init__(self, behavior: Callable[[Call], Reply]) -> None:
        self.behavior = behavior
        self.calls: list[Call] = []
        self.lock = threading.Lock()
        self.port = 0
        self._loop = asyncio.new_event_loop()
        self._ready = threading.Event()
        self._thread = threading.Thread(target=self._run, name="mock-roblox", daemon=True)
        self._server: asyncio.AbstractServer | None = None

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def start(self) -> MockRoblox:
        self._thread.start()
        if not self._ready.wait(10):
            raise RuntimeError("the mock Roblox server did not start")
        return self

    def stop(self) -> None:
        def close() -> None:
            if self._server is not None:
                self._server.close()
            self._loop.stop()

        self._loop.call_soon_threadsafe(close)
        self._thread.join(timeout=5)

    def _run(self) -> None:
        asyncio.set_event_loop(self._loop)

        async def serve() -> None:
            self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
            self.port = int(self._server.sockets[0].getsockname()[1])
            self._ready.set()

        self._loop.run_until_complete(serve())
        self._loop.run_forever()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            while True:
                try:
                    head = await reader.readuntil(b"\r\n\r\n")
                except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, ConnectionError):
                    return
                lines = head.decode("latin-1").split("\r\n")
                method, target, _version = lines[0].split(" ", 2)
                headers = {}
                for line in lines[1:]:
                    if ":" in line:
                        name, value = line.split(":", 1)
                        headers[name.strip().lower()] = value.strip()
                length = int(headers.get("content-length") or 0)
                if length:
                    await reader.readexactly(length)
                parts = urlsplit(target)
                call = Call(
                    at=time.monotonic(),
                    method=method,
                    host=headers.get("x-roxy-test-host") or headers.get("host", ""),
                    path=parts.path,
                    query=parse_qs(parts.query),
                    headers=headers,
                )
                with self.lock:
                    self.calls.append(call)
                    reply = self.behavior(call)
                if reply.delay_s:
                    await asyncio.sleep(reply.delay_s)
                reason = {200: "OK", 404: "Not Found", 429: "Too Many Requests"}.get(reply.status, "Status")
                out = [f"HTTP/1.1 {reply.status} {reason}", "Content-Type: application/json"]
                out += [f"{name}: {value}" for name, value in reply.headers.items()]
                out.append(f"Content-Length: {len(reply.body)}")
                writer.write(("\r\n".join(out) + "\r\n\r\n").encode("latin-1") + reply.body)
                await writer.drain()
                if headers.get("connection", "").lower() == "close":
                    return
        finally:
            with contextlib.suppress(Exception):
                writer.close()

    def snapshot(self) -> list[Call]:
        with self.lock:
            return list(self.calls)

    def count(self, host: str, path_prefix: str = "", **query: str) -> int:
        def matches(call: Call) -> bool:
            if call.host != host or not call.path.startswith(path_prefix):
                return False
            return all(call.query.get(name) == [value] for name, value in query.items())

        return sum(1 for call in self.snapshot() if matches(call))


def default_behavior(call: Call) -> Reply:
    if call.host == "games.roblox.com" and call.query.get("universeIds") == [SINGLE_FLIGHT_UNIVERSE]:
        return Reply(body=b'{"data":["shared"]}', delay_s=1.0)  # slow, so every request overlaps the first
    return Reply(body=json.dumps({"path": call.path}).encode())


# --------------------------------------------------------------------------------------------------- the state


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def base_env(work: Path, credentials: Path, mock: MockRoblox) -> dict[str, str]:
    state = work / "state"
    return {
        "PATH": f"{VENV_BIN}:/usr/bin:/bin",
        "HOME": str(work),
        "LANG": "C.UTF-8",
        "ROXY_ENV": "development",  # the egress test override is refused anywhere else
        "ROXY_AUTO_MIGRATE": "0",  # migrated once below, like the deploy's prestart step
        "ROXY_STATE_DIR": str(state),
        "ROXY_CONTROL_DB": str(state / "control.db"),
        "ROXY_HOT_DB": str(state / "hot.db"),
        "ROXY_METRICS_DB": str(state / "metrics.db"),
        "ROXY_CACHE_DB": str(state / "cache.db"),
        "ROXY_LOG_LEVEL": "info",  # each worker logs `settings_reloaded` (with its pid) at info
        "ROXY_MAX_REQUESTS": "0",
        "ROXY_TRUSTED_PROXY_HOPS": "1",
        "ROXY_TRUSTED_PROXY_CIDRS": "127.0.0.1/32,::1/128",
        "ROXY_SITE_ORIGIN": "http://localhost",
        "ROXY_ROTATOR_IP_ECHO_URL": "http://127.0.0.1:9/ip",
        "ROXY_TEST_UPSTREAM_BASE": mock.base,
        "CREDENTIALS_DIRECTORY": str(credentials),
    }


def prepare_state(env: Mapping[str, str], settings: Mapping[str, Any], rules: list[tuple[str, dict[str, Any]]]) -> None:
    """Migrate the four databases, seed the defaults, and apply the scenario's settings and rules."""
    Path(env["ROXY_STATE_DIR"]).mkdir(parents=True, exist_ok=True)
    for name in [name for name in os.environ if name.startswith("ROXY_")]:
        del os.environ[name]
    os.environ.update(env)
    from roxy.config.audit import Actor
    from roxy.config.defaults import seed_control_defaults
    from roxy.config.env import EnvSettings
    from roxy.config.settings_service import SettingsService
    from roxy.rules.service import RulesService
    from roxy.storage.db import open_databases
    from roxy.storage.migrate import migrate_all

    dbs = open_databases(EnvSettings())
    migrate_all(dbs, contract=True)

    async def configure() -> None:
        await seed_control_defaults(dbs.control)
        actor = Actor("cli", "gunicorn-mp")
        if settings:
            await SettingsService(dbs.control).update(dict(settings), actor, "multi-process test")
        service = RulesService(dbs.control)
        for table, row in rules:
            await service.create(table, row, actor, "multi-process test")
        await dbs.close_all()

    asyncio.run(configure())


def change_setting(env: Mapping[str, str], key: str, value: Any) -> int:
    """Write one setting the way an admin request in some worker would; returns the new config_version."""
    from roxy.config.audit import Actor
    from roxy.config.settings_service import SettingsService
    from roxy.storage.db import Database

    async def write() -> None:
        db = Database("control", Path(env["ROXY_CONTROL_DB"]))
        try:
            await SettingsService(db).update({key: value}, Actor("admin", "gunicorn-mp"), "multi-process test")
        finally:
            await db.close()

    asyncio.run(write())
    return config_version(env)


def query(path: str, sql: str, params: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=10)
    try:
        return [tuple(row) for row in conn.execute(sql, params).fetchall()]
    finally:
        conn.close()


def config_version(env: Mapping[str, str]) -> int:
    rows = query(env["ROXY_CONTROL_DB"], "SELECT value_json FROM service_state WHERE key = 'config_version'")
    return int(json.loads(rows[0][0])) if rows else 0


def recorded_requests(env: Mapping[str, str]) -> int:
    rows = query(env["ROXY_METRICS_DB"], "SELECT coalesce(sum(requests), 0) FROM rollup_minute")
    return int(rows[0][0])


def heartbeats(env: Mapping[str, str]) -> list[dict[str, Any]]:
    rows = query(
        env["ROXY_METRICS_DB"],
        "SELECT pid, master_pid, is_leader, last_seen, worker_id, color, proxied FROM worker_heartbeat",
    )
    keys = ("pid", "master_pid", "is_leader", "last_seen", "worker_id", "color", "proxied")
    return [dict(zip(keys, row, strict=True)) for row in rows]


def leader_lease(env: Mapping[str, str]) -> dict[str, Any] | None:
    rows = query(env["ROXY_HOT_DB"], "SELECT holder, epoch, expires_ms FROM lease WHERE name = 'leader'")
    return None if not rows else {"holder": rows[0][0], "epoch": rows[0][1], "expires_ms": rows[0][2]}


# ------------------------------------------------------------------------------------------------- one master


class Master:
    """One gunicorn master: its environment, process, sockets and log."""

    def __init__(self, name: str, work: Path, env: Mapping[str, str], workers: int) -> None:
        self.name = name
        self.workers = workers
        self.port = free_port()
        self.socket = work / f"internal-{name}.sock"
        self.log = work / f"gunicorn-{name}.log"
        self.env = {
            **env,
            "ROXY_COLOR": name,
            "ROXY_WORKERS": str(workers),
            "ROXY_BIND": f"127.0.0.1:{self.port}",
            "ROXY_INTERNAL_SOCKET": str(self.socket),
        }
        self.proc: subprocess.Popen[bytes] | None = None

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
                "20",
                "--timeout",
                "60",
            ],
            env=self.env,
            cwd=REPO,
            stdout=handle,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )

    def worker_rows(self) -> list[dict[str, Any]]:
        if self.proc is None:
            return []
        return [row for row in heartbeats(self.env) if row["master_pid"] == self.proc.pid]

    def wait_ready(self, timeout_s: float = 60.0) -> bool:
        """Every worker has written its heartbeat and the TCP port answers /health."""
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            if self.proc is not None and self.proc.poll() is not None:
                return False
            with contextlib.suppress(Exception):
                if len(self.worker_rows()) >= self.workers:
                    response = httpx.get(f"http://127.0.0.1:{self.port}/health", timeout=5, trust_env=False)
                    if response.status_code == 200:
                        return True
            time.sleep(0.25)
        return False

    def stop(self, timeout_s: float = 45.0) -> tuple[int | None, float]:
        if self.proc is None:
            return None, 0.0
        started = time.monotonic()
        if self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
        try:
            code = self.proc.wait(timeout=timeout_s)
        except subprocess.TimeoutExpired:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(self.proc.pid, signal.SIGKILL)
            code = None
        return code, round(time.monotonic() - started, 2)

    def kill(self) -> None:
        if self.proc is not None and self.proc.poll() is None:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(self.proc.pid, signal.SIGKILL)

    def log_tail(self, lines: int = 40) -> str:
        try:
            return "\n".join(self.log.read_text(errors="replace").splitlines()[-lines:])
        except OSError:
            return ""

    def client(self) -> httpx.AsyncClient:
        # No keep-alive: every request is a new connection, which the kernel hands to any worker.
        limits = httpx.Limits(max_connections=200, max_keepalive_connections=0)
        return httpx.AsyncClient(base_url=f"http://127.0.0.1:{self.port}", limits=limits, timeout=60, trust_env=False)

    def internal_client(self) -> httpx.AsyncClient:
        transport = httpx.AsyncHTTPTransport(uds=str(self.socket))
        return httpx.AsyncClient(
            transport=transport,
            base_url="http://roxy",
            limits=httpx.Limits(max_keepalive_connections=0),
            timeout=10,
            trust_env=False,
        )


class Addresses:
    """Distinct client addresses from the documentation ranges, sent as X-Forwarded-For (the peer is trusted)."""

    def __init__(self) -> None:
        self._seq = itertools.count()

    def next(self) -> str:
        n = next(self._seq)
        return f"{NETS[n // 254 % len(NETS)]}.{n % 254 + 1}"


def summary(responses: list[httpx.Response]) -> dict[str, Any]:
    return {
        "statuses": dict(Counter(str(r.status_code) for r in responses)),
        "refusals": dict(Counter(r.headers.get("roxy-refusal", "") for r in responses)),
        "cache": dict(Counter(r.headers.get("roxy-cache", "") for r in responses)),
        "missing_retry_after": sum(
            1 for r in responses if r.status_code in (429, 503) and "retry-after" not in r.headers
        ),
    }


async def get_all(client: httpx.AsyncClient, requests: list[tuple[str, str]]) -> list[httpx.Response]:
    """Send every (path, client ip) at once."""
    return list(
        await asyncio.gather(
            *(client.get(path, headers={"X-Forwarded-For": ip, "User-Agent": "Roblox/Linux"}) for path, ip in requests)
        )
    )


async def versions(master: Master, *, need: int, rounds: int = 20) -> list[dict[str, Any]]:
    """Ask /internal/version over fresh Unix socket connections (in concurrent batches, so several workers accept)
    until `need` distinct workers answered or the rounds run out."""
    seen: list[dict[str, Any]] = []
    async with master.internal_client() as client:
        for _ in range(rounds):
            responses = await asyncio.gather(*(client.get("/internal/version") for _ in range(16)))
            for response in responses:
                body = response.json()
                seen.append({"worker": body.get("WorkerId"), "version": body.get("ConfigVersion")})
            if len({row["worker"] for row in seen}) >= need:
                break
    return seen


def reload_lines(master: Master, version: int) -> dict[int, float]:
    """pid -> wall time each worker logged `settings_reloaded` for `version` (JSON log lines carry pid and ts)."""
    from datetime import datetime

    seen: dict[int, float] = {}
    try:
        text = master.log.read_text(errors="replace")
    except OSError:
        return seen
    for line in text.splitlines():
        if '"settings_reloaded"' not in line:
            continue
        with contextlib.suppress(ValueError, KeyError, TypeError):
            entry = json.loads(line)
            if int(entry.get("version", -1)) == version:
                seen.setdefault(int(entry["pid"]), datetime.fromisoformat(entry["ts"]).timestamp())
    return seen


async def proxied_by_worker(master: Master, expected: int, timeout_s: float = 12.0) -> list[int]:
    """Each worker's `proxied` counter from its heartbeat, once the beats add up to `expected` (or the timeout)."""
    deadline = time.monotonic() + timeout_s
    counts: list[int] = []
    while time.monotonic() < deadline:
        counts = sorted((int(row.get("proxied") or 0) for row in master.worker_rows()), reverse=True)
        if sum(counts) >= expected:
            break
        await asyncio.sleep(0.5)
    return counts


async def wait_one_leader(env: Mapping[str, str], pids: set[int], timeout_s: float = 25.0) -> dict[str, Any]:
    """Poll until every worker in `pids` has a fresh heartbeat and leadership looks settled; report what was seen."""
    deadline = time.monotonic() + timeout_s
    last: dict[str, Any] = {}
    while time.monotonic() < deadline:
        rows = [row for row in heartbeats(env) if row["pid"] in pids]
        lease = leader_lease(env)
        leaders = [row["worker_id"] for row in rows if row["is_leader"]]
        last = {
            "workers": len(rows),
            "leaders": len(leaders),
            "lease_holder_is_the_leader": bool(lease and leaders and lease["holder"] == leaders[0]),
        }
        if len(rows) == len(pids) and len(leaders) == 1 and last["lease_holder_is_the_leader"]:
            return last
        await asyncio.sleep(0.5)
    return last


# --------------------------------------------------------------------------------------------------- scenarios


async def fleet_traffic(master: Master, env: Mapping[str, str], mock: MockRoblox, workers: int) -> dict[str, Any]:
    out: dict[str, Any] = {}
    sent = 0
    ips = Addresses()
    async with master.client() as client:
        # 1. Per-IP limit: one client, 30 requests at once over every worker, 10 per 50 s allowed (C6, plan 10.2).
        one = "198.51.100.200"
        responses = await get_all(client, [(f"/users.roblox.com/v1/users/{1000 + n}", one) for n in range(30)])
        sent += len(responses)
        out["per_ip"] = summary(responses)

        # 2. Single-flight: 20 callers for one key at once; the mock answers after 1 s.
        key = f"/games.roblox.com/v1/games?universeIds={SINGLE_FLIGHT_UNIVERSE}"
        responses = await get_all(client, [(key, ips.next()) for _ in range(20)])
        sent += len(responses)
        out["single_flight"] = {
            **summary(responses),
            "calls": mock.count("games.roblox.com", "/v1/games", universeIds=SINGLE_FLIGHT_UNIVERSE),
            "bodies": sorted({r.content.decode() for r in responses}),
        }

        # 3. An upstream bucket (6 per minute, burst 2) shared by every worker: 20 distinct keys at once.
        started = time.monotonic()
        responses = await get_all(client, [(f"/groups.roblox.com/v1/groups/{n}", ips.next()) for n in range(20)])
        sent += len(responses)
        out["bucket"] = {
            **summary(responses),
            "calls": mock.count("groups.roblox.com", "/v1/groups/"),
            "elapsed_s": round(time.monotonic() - started, 2),
        }

        # Which workers served the traffic so far (each worker's `proxied` counter, from its heartbeat).
        out["proxied_by_worker"] = await proxied_by_worker(master, sent)

        # 4. A settings change reaches every worker within 2 s. Each worker logs `settings_reloaded` with its pid
        # when its watcher picks the change up; the internal socket also reports each worker's ConfigVersion.
        before = await versions(master, need=workers)
        written_wall = time.time()
        written_at = time.monotonic()
        new_version = await asyncio.to_thread(change_setting, env, "public_cors_allow_any_origin", 1)
        await asyncio.sleep(max(0.0, 2.0 - (time.monotonic() - written_at)))
        after = await versions(master, need=workers)
        responses = await get_all(client, [(f"/users.roblox.com/v1/users/{5000 + n}", ips.next()) for n in range(10)])
        sent += len(responses)
        reloaded = reload_lines(master, new_version)
        pids = {int(row["pid"]) for row in master.worker_rows()}
        out["reload"] = {
            "new_version": new_version,
            "workers_before": len({row["worker"] for row in before}),
            "old_versions_before": sorted({row["version"] for row in before}),
            "workers_after": len({row["worker"] for row in after}),
            "versions_after": sorted({row["version"] for row in after}),
            "workers_reloaded": len(pids & set(reloaded)),
            "slowest_reload_s": round(
                max((reloaded[pid] - written_wall for pid in pids & set(reloaded)), default=-1), 3
            ),
            "cors_after": sum(1 for r in responses if r.headers.get("access-control-allow-origin") == "*"),
            "cors_checked": len(responses),
        }
    out["sent"] = sent
    return out


def scenario_fleet(work: Path, credentials: Path, workers: int) -> dict[str, Any]:
    mock = MockRoblox(default_behavior).start()
    env = base_env(work, credentials, mock)
    from roxy.metrics.templating import template_for

    groups = template_for("groups.roblox.com", "/v1/groups/1")
    prepare_state(
        env,
        {"rotator_enabled": 0, "tarpit_enabled": 0},
        [("upstream_limits", {"bucket_key": f"endpoint:{groups}", "per_min": 6, "burst": 2})],
    )
    master = Master("dev", work, env, workers)
    out: dict[str, Any] = {"workers": workers}
    try:
        master.start()
        out["ready"] = master.wait_ready()
        if not out["ready"]:
            out["log_tail"] = master.log_tail()
            return out
        pids = {row["pid"] for row in master.worker_rows()}
        out["worker_pids"] = len(pids)
        out.update(asyncio.run(fleet_traffic(master, env, mock, workers)))
        out["leader"] = asyncio.run(wait_one_leader(env, pids))
        out["stop_code"], out["stop_s"] = master.stop()
        out["recorded"] = recorded_requests(env)
        out["cookie_calls"] = sum(1 for call in mock.snapshot() if "cookie" in call.headers)
        out["heartbeats_after_stop"] = len(heartbeats(env))
        out["log_tail"] = master.log_tail()
        return out
    finally:
        master.kill()
        mock.stop()


def scenario_two_masters(work: Path, credentials: Path, workers: int) -> dict[str, Any]:
    mock = MockRoblox(default_behavior).start()
    env = base_env(work, credentials, mock)
    prepare_state(env, {"rotator_enabled": 0, "tarpit_enabled": 0}, [])
    blue = Master("blue", work, env, workers)
    green = Master("green", work, env, workers)
    out: dict[str, Any] = {}
    try:
        blue.start()
        green.start()
        out["ready"] = blue.wait_ready() and green.wait_ready()
        if not out["ready"]:
            out["log_tail"] = blue.log_tail() + "\n" + green.log_tail()
            return out
        blue_pids = {row["pid"] for row in blue.worker_rows()}
        green_pids = {row["pid"] for row in green.worker_rows()}
        out["both"] = asyncio.run(wait_one_leader(env, blue_pids | green_pids))
        lease = leader_lease(env)
        holder = lease["holder"] if lease else ""
        leading, other = (blue, green) if any(f":{pid}:" in holder for pid in blue_pids) else (green, blue)
        other_pids = green_pids if leading is blue else blue_pids
        stopped_at = time.monotonic()
        out["leader_stop_code"], _ = leading.stop()
        out["after_stop"] = asyncio.run(wait_one_leader(env, other_pids, timeout_s=30))
        out["takeover_s"] = round(time.monotonic() - stopped_at, 2)
        new_lease = leader_lease(env)
        out["epoch_moved"] = bool(lease and new_lease and new_lease["epoch"] > lease["epoch"])
        out["other_stop_code"], _ = other.stop()
        out["log_tail"] = blue.log_tail(15) + "\n" + green.log_tail(15)
        return out
    finally:
        blue.kill()
        green.kill()
        mock.stop()


def scenario_cooldown_429(work: Path, credentials: Path, workers: int) -> dict[str, Any]:
    limited: dict[str, float] = {}

    def behavior(call: Call) -> Reply:
        if call.host == "badges.roblox.com" and not limited:
            limited["at"] = call.at  # the first call of the endpoint: Roblox says "wait 30 s"
            return Reply(429, b'{"errors":[{"code":0,"message":"Too many requests"}]}', {"Retry-After": "30"})
        return default_behavior(call)

    mock = MockRoblox(behavior).start()
    env = base_env(work, credentials, mock)
    prepare_state(
        env,
        {
            "rotator_enabled": 0,
            "tarpit_enabled": 0,
            "endpoint_bucket_default_per_min": 60,
            "endpoint_bucket_default_burst": 5,
        },
        [],
    )
    master = Master("dev", work, env, workers)
    out: dict[str, Any] = {"workers": workers}
    try:
        master.start()
        out["ready"] = master.wait_ready()
        if not out["ready"]:
            out["log_tail"] = master.log_tail()
            return out
        sent = asyncio.run(paced_traffic(master, out))
        out["sent"] = sent
        t429 = limited.get("at")
        calls = [call for call in mock.snapshot() if call.host == "badges.roblox.com"]
        out["t429_seen"] = t429 is not None
        if t429 is not None:
            out["calls_during_cooldown"] = sum(1 for c in calls if t429 < c.at < t429 + 30 - COOLDOWN_SETTLE_S)
            window = [c for c in calls if t429 + 30 + COOLDOWN_SETTLE_S <= c.at <= t429 + 30 + COOLDOWN_SETTLE_S + 60]
            out["calls_in_60s_after"] = len(window)
            during = [r for r in out.pop("_responses") if t429 + 0.5 <= r["sent_at"] <= t429 + 30 - COOLDOWN_SETTLE_S]
            out["responses_during_cooldown"] = len(during)
            out["during_statuses"] = dict(Counter(str(r["status"]) for r in during))
            out["during_without_retry_after"] = sum(1 for r in during if not r["retry_after"])
        out["cookie_calls"] = sum(1 for call in mock.snapshot() if "cookie" in call.headers)
        out["stop_code"], out["stop_s"] = master.stop()
        out["recorded"] = recorded_requests(env)
        out["log_tail"] = master.log_tail()
        return out
    finally:
        master.kill()
        mock.stop()


async def paced_traffic(master: Master, out: dict[str, Any]) -> int:
    """4 requests per second for 92 s, each a new badge id from a new client address."""
    ips = Addresses()
    results: list[dict[str, Any]] = []
    started = time.monotonic()
    tasks: list[asyncio.Task[None]] = []
    async with master.client() as client:

        async def one(n: int) -> None:
            sent_at = time.monotonic()
            response = await client.get(
                f"/badges.roblox.com/v1/badges/{n}",
                headers={"X-Forwarded-For": ips.next(), "User-Agent": "Roblox/Linux"},
            )
            results.append(
                {
                    "sent_at": sent_at,
                    "status": response.status_code,
                    "retry_after": response.headers.get("retry-after"),
                    "refusal": response.headers.get("roxy-refusal", ""),
                }
            )

        n = 0
        while time.monotonic() - started < 92:
            tasks.append(asyncio.create_task(one(n)))
            n += 1
            await asyncio.sleep(max(0.0, started + n * 0.25 - time.monotonic()))
        await asyncio.gather(*tasks)
    out["_responses"] = results
    out["statuses"] = dict(Counter(str(r["status"]) for r in results))
    out["refusals"] = dict(Counter(r["refusal"] for r in results))
    out["missing_retry_after"] = sum(1 for r in results if r["status"] in (429, 503) and not r["retry_after"])
    return len(results)


SCENARIOS: dict[str, Callable[[Path, Path, int], dict[str, Any]]] = {
    "fleet": scenario_fleet,
    "two_masters": scenario_two_masters,
    "cooldown_429": scenario_cooldown_429,
}


def main() -> int:
    scenario, work, credentials, workers = sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3]), int(sys.argv[4])
    ip = shutil.which("ip") or "/usr/sbin/ip"
    # A fresh namespace from `unshare -rn` has loopback down.
    subprocess.run([ip, "link", "set", "lo", "up"], check=False, capture_output=True)
    result = SCENARIOS[scenario](work, credentials, workers)
    result.pop("_responses", None)
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
