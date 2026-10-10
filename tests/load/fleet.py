"""The system under load: fake credentials, temporary state, a production-shaped gunicorn master, and measurements.

What this is
    - `fake_credentials(directory)`: a fake systemd credentials directory (fresh random values, never committed),
      without the mail password and the webhook URL, so no alert can be sent anywhere.
    - `base_env(...)` and `prepare_state(...)`: the environment and the migrated, seeded temporary databases.
    - `Fleet`: one gunicorn master started as `roxy@.service` starts it, `gunicorn -c deploy/gunicorn.conf.py
      roxy.asgi:app` (worker class `roxy.worker.RoxyUvicornWorker`, `reuse_port`, keep-alive 75 s, 2 workers).
    - `ResourceSampler`: the peak RSS of each worker and of the whole color, and CPU per worker, read with psutil.
    - `AdminProbe`: signs in an admin through the real password and TOTP steps and samples the metrics pipeline
      card (`/admin/api/v1/system/metrics-pipeline`), the only place the server reports its flush and write times.
    - `roxy_totals(...)`, `upstream_limits(...)`: Roxy's own numbers after the stop (metrics.db rollups with the
      plan P6 definitions, the adaptive bucket rates in control.db).

Why it exists
    Plan 19.4 measures the production setting: real gunicorn, the real worker class, 2 workers (DESIGN.md section
    0), with peak memory per worker and per color. Using `deploy/gunicorn.conf.py` itself (not command line flags)
    means the load tests also cover `reuse_port` (how the kernel spreads connections over the workers) and the
    production keep-alive and timeouts.

How it works
    Two things differ from production, both needed to run on a test machine. `ROXY_ENV=development`, because the
    egress test override that sends Roblox traffic to the mock (`ROXY_TEST_UPSTREAM_BASE`) is refused anywhere
    else; and `ROXY_MAX_REQUESTS=0` (production recycles a worker after about 20,000 requests), so a recycle in the
    middle of a run cannot reset the RSS being measured. The state is migrated once before the start, as the
    deploy's prestart step does (`ROXY_AUTO_MIGRATE=0`), and the leader's scheduled health run is switched off
    (it probes every Roblox host and would add calls to the counts).

What to read next
    `scenarios.py` (how a scenario uses a `Fleet`), `deploy/gunicorn.conf.py`, `roxy/worker.py`.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import secrets
import signal
import socket
import sqlite3
import subprocess
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

import httpx
import psutil

REPO: Final = Path(__file__).resolve().parents[2]
VENV_BIN: Final = REPO / ".venv" / "bin"
GUNICORN_CONF: Final = REPO / "deploy" / "gunicorn.conf.py"

QUIET_BACKGROUND: Final[dict[str, Any]] = {"health_auto_interval_h": 0, "rotator_enabled": 0}
"""Every scenario: no scheduled health run (it probes every Roblox host) and no rotator (direct egress only; the
fake rotator URL points at a closed loopback port). Roblox's per-address limits therefore all apply to the one
server address, the hardest case for plan 19.10 row 7."""


# ------------------------------------------------------------------------------------------- credentials


def fake_credentials(directory: Path) -> Path:
    """A fake CREDENTIALS_DIRECTORY (the conftest values minus the mail password and the webhook URL)."""
    from roxy.core.redact import TOKEN_PREFIX

    values = {
        "roblox_credential": TOKEN_PREFIX + "FAKELOADTESTCREDENTIAL" + secrets.token_hex(160).upper(),
        "rotator_url": f"http://fakeuser:fake{secrets.token_hex(8)}@127.0.0.1:9",
        "alert_emails": "owner@example.invalid",
        "credential_encryption_key": secrets.token_hex(32),
        "totp_encryption_key": secrets.token_hex(32),
        "ip_hash_key": secrets.token_hex(32),
    }
    directory.mkdir(parents=True, mode=0o700, exist_ok=True)
    for name, value in values.items():
        path = directory / name
        path.write_text(value, encoding="utf-8")
        path.chmod(0o600)
    return directory


# ------------------------------------------------------------------------------------------------ state


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def base_env(
    work: Path,
    credentials: Path,
    mock_base: str,
    *,
    workers: int,
    tree: Path | None = None,
    extra: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """The environment of the gunicorn master (nothing inherited from the caller's shell).

    `tree`: a copy of the repository (`git archive` of a commit, say) whose `src/roxy` the workers import instead of
    the installed working tree, so a measurement can name the exact code it measured. `extra`: variables for a
    "what if" run (`--worker-env`, for example `MALLOC_ARENA_MAX=2`); never `ROXY_*`, which belong to the run.
    """
    state = work / "state"
    run = work / "run"
    path = {} if tree is None else {"PYTHONPATH": str(tree / "src")}  # ahead of the editable install's path
    return {
        **dict(extra or {}),
        **path,
        "PATH": f"{VENV_BIN}:/usr/bin:/bin",
        "HOME": str(work),
        "LANG": "C.UTF-8",
        "ROXY_ENV": "development",  # the egress test override is refused anywhere else
        "ROXY_AUTO_MIGRATE": "0",  # migrated once below, like the deploy's prestart step
        "ROXY_COLOR": "dev",
        "ROXY_WORKERS": str(workers),
        "ROXY_BIND": f"127.0.0.1:{free_port()}",
        "ROXY_INTERNAL_SOCKET": str(run / "internal.sock"),
        "ROXY_DEPLOY_STATE_DIR": str(work / "deploy-state"),
        "ROXY_STATE_DIR": str(state),
        "ROXY_CONTROL_DB": str(state / "control.db"),
        "ROXY_HOT_DB": str(state / "hot.db"),
        "ROXY_METRICS_DB": str(state / "metrics.db"),
        "ROXY_CACHE_DB": str(state / "cache.db"),
        "ROXY_LOG_LEVEL": "info",  # production's level: every request writes its `http_request` line
        "ROXY_MAX_REQUESTS": "0",  # no recycle in the middle of a measurement (module docstring)
        "ROXY_TRUSTED_PROXY_HOPS": "1",
        "ROXY_TRUSTED_PROXY_CIDRS": "127.0.0.1/32,::1/128",
        "ROXY_SITE_ORIGIN": "http://localhost",
        "ROXY_ROTATOR_IP_ECHO_URL": "http://127.0.0.1:9/ip",
        "ROXY_TEST_UPSTREAM_BASE": mock_base,
        "CREDENTIALS_DIRECTORY": str(credentials),
    }


def prepare_state(env: Mapping[str, str], settings: Mapping[str, Any], rules: list[tuple[str, dict[str, Any]]]) -> None:
    """Migrate the four databases, seed the built-in defaults, and apply the scenario's settings and rules."""
    state = Path(env["ROXY_STATE_DIR"])
    state.mkdir(parents=True, exist_ok=True)
    state.chmod(0o750)  # systemd's StateDirectoryMode; Roxy warns about a state directory others can read
    run = Path(env["ROXY_INTERNAL_SOCKET"]).parent
    run.mkdir(parents=True, exist_ok=True)
    run.chmod(0o750)  # what systemd's RuntimeDirectoryMode makes
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
        actor = Actor("cli", "load-test")
        values = {**QUIET_BACKGROUND, **settings}
        await SettingsService(dbs.control).update(values, actor, "load test")
        service = RulesService(dbs.control)
        for table, row in rules:
            await service.create(table, row, actor, "load test")
        await dbs.close_all()

    asyncio.run(configure())


def query(path: str, sql: str, params: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
    """Read-only rows from one database file (the workers may still hold it open)."""
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=10)
    try:
        return [tuple(row) for row in conn.execute(sql, params).fetchall()]
    finally:
        conn.close()


# ----------------------------------------------------------------------------------------------- gunicorn


class Fleet:
    """One gunicorn master with `deploy/gunicorn.conf.py`: its process, log and addresses."""

    def __init__(self, work: Path, env: Mapping[str, str], *, tree: Path | None = None) -> None:
        self.work = work
        self.env = dict(env)
        self.workers = int(env["ROXY_WORKERS"])
        self.base_url = "http://" + env["ROXY_BIND"]
        self.log = work / "gunicorn.log"
        self.proc: subprocess.Popen[bytes] | None = None
        self.tree = tree or REPO

    def start(self) -> None:
        handle = open(self.log, "ab")  # noqa: SIM115 (kept open for the child's lifetime)
        conf = self.tree / GUNICORN_CONF.relative_to(REPO)
        self.proc = subprocess.Popen(
            [str(VENV_BIN / "gunicorn"), "-c", str(conf), "roxy.asgi:app"],
            env=self.env,
            cwd=self.tree,
            stdout=handle,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )

    @property
    def master_pid(self) -> int:
        return self.proc.pid if self.proc is not None else 0

    def heartbeat_pids(self) -> set[int]:
        with contextlib.suppress(sqlite3.Error):
            rows = query(self.env["ROXY_METRICS_DB"], "SELECT pid, master_pid FROM worker_heartbeat")
            return {int(pid) for pid, master in rows if master == self.master_pid}
        return set()

    def wait_ready(self, timeout_s: float = 90.0) -> bool:
        """Every worker wrote its heartbeat and `/health` answers 200 on the TCP port."""
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            if self.proc is not None and self.proc.poll() is not None:
                return False
            with contextlib.suppress(httpx.HTTPError):
                if len(self.heartbeat_pids()) >= self.workers:
                    response = httpx.get(self.base_url + "/health", timeout=5, trust_env=False)
                    if response.status_code == 200:
                        return True
            time.sleep(0.25)
        return False

    def stop(self, timeout_s: float = 60.0) -> tuple[int | None, float]:
        """SIGTERM and wait (gunicorn's graceful stop: open requests finish, every worker flushes its metrics)."""
        if self.proc is None:
            return None, 0.0
        started = time.monotonic()
        if self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
        try:
            code = self.proc.wait(timeout=timeout_s)
        except subprocess.TimeoutExpired:
            self.kill()
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

    def log_count(self, needle: str) -> int:
        try:
            return self.log.read_text(errors="replace").count(needle)
        except OSError:
            return 0


# ----------------------------------------------------------------------------------------------- sampling


@dataclass
class _ProcessTrack:
    role: str
    peak_rss: int = 0
    peak_uss: int = 0
    cpu_marks: dict[str, float] = field(default_factory=dict)


class ResourceSampler:
    """Samples the memory of the master and its workers every `interval_s`; CPU times at named marks.

    Three memory figures, because they answer different questions:
    - RSS per process: every page the process maps that is in memory, shared ones included (what `top` shows,
      and what plan 19.4 asks for per worker).
    - USS per process: the pages only that process uses (what stopping it would give back).
    - PSS summed over the color: each shared page split between the processes that share it. Adding RSS over
      processes counts the shared interpreter and libraries once per process; PSS counts them once in total, so
      the PSS sum is the closest per-process estimate of the color's anonymous and file-backed charge against
      `MemoryHigh` and `MemoryMax` (the cgroup also charges page cache, which no per-process figure shows).
    Besides the peaks it keeps a timeline (worker RSS and color PSS every `TIMELINE_EVERY_S`), which tells a
    plateau from steady growth in a long run.
    """

    TIMELINE_EVERY_S: Final = 30.0
    """One point of the memory timeline every this many seconds (does memory level off, or keep growing?)."""
    TIMELINE_MAX: Final = 480
    """At most this many timeline points are kept (4 hours at one every 30 s; plan P9: every list is bounded)."""

    def __init__(self, master_pid: int, interval_s: float = 0.5) -> None:
        self.master_pid = master_pid
        self.interval_s = interval_s
        self.tracks: dict[int, _ProcessTrack] = {}
        self.peak_total_rss = 0
        self.peak_total_pss = 0
        self.timeline: list[dict[str, Any]] = []
        self._started = time.monotonic()
        self._next_point = 0.0
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="rss-sampler", daemon=True)
        self._lock = threading.Lock()

    def _processes(self) -> list[tuple[psutil.Process, str]]:
        try:
            master = psutil.Process(self.master_pid)
            return [(master, "master"), *((child, "worker") for child in master.children(recursive=False))]
        except psutil.Error:
            return []

    def sample(self, *, point: bool = False) -> None:
        """Read every process once; `point=True` also adds a timeline point whatever the time since the last."""
        rss_total = pss_total = 0
        workers: list[int] = []
        with self._lock:
            for process, role in self._processes():
                try:
                    info = process.memory_full_info()  # reads /proc/<pid>/smaps_rollup for USS and PSS
                except psutil.Error:
                    continue
                track = self.tracks.setdefault(process.pid, _ProcessTrack(role))
                track.peak_rss = max(track.peak_rss, int(info.rss))
                track.peak_uss = max(track.peak_uss, int(info.uss))
                rss_total += int(info.rss)
                pss_total += int(getattr(info, "pss", info.uss))
                if role == "worker":
                    workers.append(int(info.rss))
            self.peak_total_rss = max(self.peak_total_rss, rss_total)
            self.peak_total_pss = max(self.peak_total_pss, pss_total)
            elapsed = time.monotonic() - self._started
            if (point or elapsed >= self._next_point) and len(self.timeline) < self.TIMELINE_MAX:
                self._next_point = elapsed + self.TIMELINE_EVERY_S
                self.timeline.append(
                    {
                        "s": round(elapsed),
                        "worker_rss_mib": [round(rss / 2**20, 1) for rss in sorted(workers, reverse=True)],
                        "color_pss_mib": round(pss_total / 2**20, 1),
                    }
                )

    def mark(self, name: str) -> None:
        """Remember each process's CPU seconds (user plus system) under `name`."""
        with self._lock:
            for process, role in self._processes():
                try:
                    times = process.cpu_times()
                except psutil.Error:
                    continue
                track = self.tracks.setdefault(process.pid, _ProcessTrack(role))
                track.cpu_marks[name] = float(times.user + times.system)

    def cpu_percent(self, start: str, end: str, seconds: float) -> dict[int, float]:
        """Percent of one core each worker used between two marks."""
        out: dict[int, float] = {}
        with self._lock:
            for pid, track in self.tracks.items():
                if track.role == "worker" and start in track.cpu_marks and end in track.cpu_marks and seconds > 0:
                    out[pid] = round((track.cpu_marks[end] - track.cpu_marks[start]) * 100 / seconds, 1)
        return out

    def _run(self) -> None:
        while not self._stop.is_set():
            self.sample()
            self._stop.wait(self.interval_s)

    def start(self) -> ResourceSampler:
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._thread.is_alive():
            self._stop.set()
            self._thread.join(timeout=5)
            self.sample(point=True)  # one last point, so the timeline reaches the end of the run

    def summary(self) -> dict[str, Any]:
        with self._lock:
            workers = sorted(
                ((t.peak_rss, t.peak_uss) for t in self.tracks.values() if t.role == "worker"), reverse=True
            )
            master = max((t.peak_rss for t in self.tracks.values() if t.role == "master"), default=0)
            return {
                "worker_peak_rss_mib": [round(rss / 2**20, 1) for rss, _ in workers],
                "worker_peak_uss_mib": [round(uss / 2**20, 1) for _, uss in workers],
                "master_peak_rss_mib": round(master / 2**20, 1),
                "color_peak_rss_sum_mib": round(self.peak_total_rss / 2**20, 1),
                "color_peak_pss_mib": round(self.peak_total_pss / 2**20, 1),
                "timeline": list(self.timeline),
            }


class SlotSampler:
    """Counts the tarpit's valid slot leases in hot.db every `interval_s` (plan 10.6: the fleet cap).

    A hold takes one counted lease `tarpit:<n>` and gives it back when it ends (`storage/leases.py
    acquire_slot`), so the number of valid `tarpit:` rows is the number of holds in progress across every worker.
    Reading with a separate read-only connection never blocks the workers (WAL readers do not take the write lock).
    The lease times are wall clock milliseconds, like the app's.
    """

    def __init__(self, hot_db: str, prefix: str = "tarpit:", interval_s: float = 0.2) -> None:
        self.hot_db = hot_db
        self.prefix = prefix
        self.interval_s = interval_s
        self.peak = 0
        self.samples = 0
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="slot-sampler", daemon=True)

    def _run(self) -> None:
        end = self.prefix[:-1] + chr(ord(self.prefix[-1]) + 1)  # the first name after every `tarpit:` name
        sql = "SELECT count(*) FROM lease WHERE name >= ? AND name < ? AND expires_ms > ?"
        while not self._stop.is_set():
            with contextlib.suppress(sqlite3.Error):
                rows = query(self.hot_db, sql, (self.prefix, end, int(time.time() * 1000)))
                self.peak = max(self.peak, int(rows[0][0]))
                self.samples += 1
            self._stop.wait(self.interval_s)

    def start(self) -> SlotSampler:
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=5)


# ------------------------------------------------------------------------------------------- admin probe


class AdminProbe:
    """An admin session (real password and TOTP steps) that samples the metrics pipeline card of each worker."""

    PIPELINE = "/admin/api/v1/system/metrics-pipeline"

    def __init__(self, fleet: Fleet, credentials: Path) -> None:
        self.fleet = fleet
        self.credentials = credentials
        self.cookie = ""
        self.error = ""
        self.samples: list[dict[str, Any]] = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="admin-probe", daemon=True)

    def sign_in(self) -> bool:
        from roxy.admin.auth import totp
        from roxy.admin.auth.testing import LOGIN_PATH, MFA_PATH, TEST_UA, make_admin
        from roxy.storage.db import Database

        cipher = totp.load_cipher(self.credentials)
        if cipher is None:
            self.error = "no totp key"
            return False
        db = Database("control", Path(self.fleet.env["ROXY_CONTROL_DB"]))
        try:
            admin = make_admin(db, cipher=cipher, now=int(time.time()))
        finally:
            db.close_sync()
        self._headers = {
            "Origin": self.fleet.env["ROXY_SITE_ORIGIN"],
            "Sec-Fetch-Site": "same-origin",
            "User-Agent": TEST_UA,
        }
        with httpx.Client(base_url=self.fleet.base_url, timeout=20, trust_env=False) as client:
            first = client.post(
                LOGIN_PATH, json={"username": admin.username, "password": admin.password}, headers=self._headers
            )
            if first.status_code != 200 or admin.totp_secret is None:
                self.error = f"login {first.status_code}"
                return False
            code = totp.code_at(admin.totp_secret, time.time())
            second = client.post(
                MFA_PATH,
                json={"transaction": first.json()["Transaction"], "method": "totp", "code": code},
                headers=self._headers,
            )
        # The session cookie is Secure, which httpx never sends over plain http: read it and send it by hand
        # (nginx provides HTTPS in production).
        parts = [p.split(";", 1)[0] for p in second.headers.get_list("set-cookie") if "roxy_session=" in p]
        if second.status_code != 200 or not parts:
            self.error = f"mfa {second.status_code}"
            return False
        self.cookie = parts[0]
        return True

    def _run(self) -> None:
        # A fresh connection per sample, so the kernel's reuse_port hash lands on either worker over time.
        limits = httpx.Limits(max_keepalive_connections=0)
        with httpx.Client(base_url=self.fleet.base_url, timeout=10, trust_env=False, limits=limits) as client:
            while not self._stop.is_set():
                with contextlib.suppress(httpx.HTTPError, ValueError):
                    answer = client.get(self.PIPELINE, headers={**self._headers, "Cookie": self.cookie})
                    if answer.status_code == 200:
                        self.samples.append({"at": time.monotonic(), **_pipeline_sample(answer.json())})
                self._stop.wait(0.7)

    def start(self) -> AdminProbe:
        if self.cookie:
            self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        if self._thread.is_alive():
            self._thread.join(timeout=10)


def _pipeline_sample(body: Mapping[str, Any]) -> dict[str, Any]:
    recorder = body.get("recorder") or {}
    batch = recorder.get("batch") or {}
    dbs = {row.get("db"): row for row in body.get("databases") or []}
    return {
        "worker": body.get("worker_id"),
        "flushes": batch.get("flushes"),
        "last_flush_ms": batch.get("last_flush_ms"),
        "metrics_dropped": recorder.get("metrics_dropped"),
        "hot_last_write_ms": (dbs.get("hot") or {}).get("last_write_ms"),
        "hot_max_write_ms": (dbs.get("hot") or {}).get("max_write_ms"),
        "hot_writes": (dbs.get("hot") or {}).get("writes"),
        "hot_pending": _queued_writes(dbs.get("hot")),
        "metrics_pending": _queued_writes(dbs.get("metrics")),
        "cache_pending": _queued_writes(dbs.get("cache")),
    }


def _queued_writes(row: Mapping[str, Any] | None) -> int | None:
    """Writes waiting in a database's writer queue (`Database.pending()` is `{"write": n, "read": m}`)."""
    pending = (row or {}).get("pending")
    if isinstance(pending, Mapping):
        value = pending.get("write")
        return int(value) if isinstance(value, int) else None
    return int(pending) if isinstance(pending, int) else None


def write_rates(samples: list[dict[str, Any]]) -> dict[str, float]:
    """hot.db writes per second of each worker, from its first and last sample."""
    out: dict[str, float] = {}
    by_worker: dict[str, list[dict[str, Any]]] = {}
    for sample in samples:
        if sample.get("hot_writes") is not None:
            by_worker.setdefault(str(sample.get("worker")), []).append(sample)
    for worker, rows in by_worker.items():
        first, last = rows[0], rows[-1]
        if last["at"] > first["at"]:
            out[worker] = round((last["hot_writes"] - first["hot_writes"]) / (last["at"] - first["at"]), 1)
    return out


# ----------------------------------------------------------------------------------------- Roxy's numbers


def roxy_totals(env: Mapping[str, str], start_wall: float, end_wall: float) -> dict[str, Any]:
    """Every measure Roxy's dashboard would show for the run (metrics.db rollups, plan P6 definitions)."""
    from roxy.metrics.queries import resolve_window, totals_sync
    from roxy.storage.db import Database

    db = Database("metrics", Path(env["ROXY_METRICS_DB"]))
    try:
        window = resolve_window(None, now=end_wall, start=start_wall, end=end_wall, granularity="minute")
        totals = db.read_sync(lambda conn: totals_sync(conn, window))
    finally:
        db.close_sync()
    keys = (
        "requests", "demand", "served_upstream", "served_cache", "refused", "failed", "upstream_calls",
        "internal_calls", "avoided", "avoided_pct", "roblox_429", "roxy_429", "cache_hit", "cache_miss",
        "cache_coalesced", "cache_revalidating", "cache_stale", "errors_hidden", "p50_ms", "p95_ms", "p99_ms",
    )  # fmt: skip
    return {key: totals.get(key) for key in keys}


def upstream_limits(env: Mapping[str, str]) -> list[dict[str, Any]]:
    """The bucket rows in control.db after the run (the adaptive controller writes origin `adaptive`)."""
    rows = query(env["ROXY_CONTROL_DB"], "SELECT bucket_key, per_min, burst, origin FROM upstream_limits")
    return [{"bucket": b, "per_min": round(float(p), 2), "burst": int(u), "origin": o} for b, p, u, o in rows]


def worker_history(env: Mapping[str, str], since_wall: float) -> dict[str, dict[str, Any]]:
    """Per worker, from the heartbeat's minute rows (metrics.db `worker_minute`, schema 2): the worst event loop lag
    p99 a heartbeat reported, the largest open connection count and the mean CPU share, since `since_wall`."""
    rows = query(
        env["ROXY_METRICS_DB"],
        "SELECT worker_id, max(loop_lag_ms_p99), max(open_conns), sum(cpu_pct_sum), sum(samples) FROM worker_minute "
        "WHERE bucket_start >= ? GROUP BY worker_id",
        (int(since_wall) // 60 * 60,),
    )
    return {
        str(worker): {
            "loop_lag_p99_ms_max": None if lag is None else round(float(lag), 1),
            "open_conns_max": conns,
            "cpu_pct_mean": round(float(cpu) / samples, 1) if samples else None,
        }
        for worker, lag, conns, cpu, samples in rows
    }


def roblox_429_rows(env: Mapping[str, str]) -> int:
    rows = query(env["ROXY_METRICS_DB"], "SELECT count(*) FROM upstream_429")
    return int(rows[0][0]) if rows else 0


def json_line(value: Any) -> str:
    return json.dumps(value, sort_keys=True, default=str)


__all__ = [
    "GUNICORN_CONF",
    "QUIET_BACKGROUND",
    "REPO",
    "AdminProbe",
    "Fleet",
    "ResourceSampler",
    "SlotSampler",
    "base_env",
    "fake_credentials",
    "free_port",
    "json_line",
    "prepare_state",
    "query",
    "roblox_429_rows",
    "roxy_totals",
    "upstream_limits",
    "worker_history",
    "write_rates",
]
