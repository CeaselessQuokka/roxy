"""Final review finding memory-4: a color keeps a listener on its port while both of its workers recycle.

What this is
    The regression test of finding memory-4 (high), moved here by the final review gate from
    `tests/review_final/test_memory.py`: it starts real gunicorn masters with the production config, like its
    neighbors `test_rr_mp_reuse_port.py` and `test_worker_port_checks.py`, and its timing needs the quiet machine
    the gate gives `tests/multiprocess` (run alone, after the parallel shards). This file is also its own driver:
    run as a script inside `unshare -rn` with the scenario name `recycle`, it prints one JSON object.

Why it exists
    The units' memory sizing counts on recycling (`ROXY_MAX_REQUESTS` 20,000; DESIGN.md 15.7). With `reuse_port`
    each worker owns a listener, uvicorn closes it the moment the worker starts stopping, and gunicorn forks the
    replacement only after the old process exited; the kernel spreads connections evenly, so both workers reach the
    limit at about the same time, and while their stop windows overlapped nothing listened on the color's port
    (nginx has one server per color and answered 502 to every caller for 4 to 6 s). Fixed by the master's own
    `SO_REUSEPORT` listener (`deploy/gunicorn.conf.py master_tcp_listeners`), handed to every worker: while no worker
    accepts, new connections queue there and the next worker answers them.

How it works
    `gunicorn -c deploy/gunicorn.conf.py` with 2 workers inside `unshare -rn`, the request limit scaled down in the
    production ratio (300 plus a jitter of up to 30), 50 new connections a second to `/health` for 24 s plus 5 caller
    requests a second that wait 1.5 s on the mock Roblox (what a worker drains when it stops). Two measurements:
    the longest stretch in which every new connection failed (bound 0.25 s), and, sampled with `ss` every 50 ms,
    the number of sockets listening on the port (never 0 while the probe runs). The rate: the scaled limit makes each
    worker live about 11 s and stop for about 8 s (a 5 s drain and the lifespan shutdown, then a 3 s boot), so the
    color serves with both workers only part of the time. At the 100 connections a second the reproduction first
    used, the backlog queued on the master's listener during a stop reached 1,000 (the probe's own connection cap)
    and the gate measured failed stretches of 0.32 to 1.8 s in 4 of 11 runs on a quiet machine while the port never
    lost its listener (overload: connections accepted or queued at a stopping worker are dropped, the trade-off
    recorded for `reuse_port`). At 50 a second the fixed code passes every run, and the code before the fix (no
    master listener) fails at once: 5.0 and 8.0 s with no listener, 249 and 401 of 1,201 probes refused.

What to read next
    `deploy/gunicorn.conf.py` (`master_tcp_listeners`, `on_starting`, `post_fork`, `max_requests_jitter`),
    `tests/multiprocess/gunicorn_mp_driver.py`, `.remake/final_review/find_memory.md` (memory-4).
"""

from __future__ import annotations

import asyncio
import json
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

import httpx
import pytest

REPO = Path(__file__).resolve().parents[2]

RECYCLE_MAX_REQUESTS = 300
"""The production ratio scaled down: deploy/gunicorn.conf.py recycles after ROXY_MAX_REQUESTS (20,000) plus a jitter
of a tenth of it (2,000); here 300 plus up to 30."""
RECYCLE_RATE = 50
"""New connections a second to the color (fresh connections, so SO_REUSEPORT spreads them over every listener); see
the module docstring for why not 100."""
RECYCLE_SECONDS = 24.0
LISTENER_SAMPLE_S = 0.05
"""How often the driver counts the sockets listening on the color's port (`ss -ltn`)."""


def _can_unshare() -> bool:
    try:
        result = subprocess.run(["unshare", "-rn", "true"], capture_output=True, timeout=10, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


@pytest.mark.multiprocess
@pytest.mark.timeout(300)
@pytest.mark.skipif(sys.platform != "linux", reason="real gunicorn workers need Linux")
def test_memory_4_a_color_keeps_one_listener_while_its_workers_recycle(tmp_path: Path, credentials_dir: Path) -> None:
    """Both workers of a color recycle within seconds of each other; the port never loses its listener and no
    stretch of 0.25 s or more passes in which every new connection fails (finding memory-4, module docstring)."""
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
        ["unshare", "-rn", str(REPO / ".venv" / "bin" / "python"), __file__, "recycle", str(work), str(quiet)],
        capture_output=True,
        text=True,
        timeout=280,
        check=False,
        cwd=REPO,
    )
    lines = [line for line in result.stdout.splitlines() if line.startswith("{")]
    failure = f"driver failed ({result.returncode}):\n{result.stderr[-4000:]}"
    assert result.returncode == 0, failure
    assert lines, failure
    out: dict[str, Any] = json.loads(lines[-1])
    print("\n" + json.dumps({k: v for k, v in out.items() if k != "log"}))
    assert out["ready"], out.get("log", "")
    assert out["recycles"] >= 2, f"the scenario needs recycles to say anything: {out}"
    if out["listener_samples"]:
        assert out["fewest_listeners"] >= 1, (
            f"the color's port had no listener at {out['no_listener_at']} s into the probe ({out['recycles']} recycles)"
        )
    assert out["longest_refused_s"] < 0.25, (
        f"for {out['longest_refused_s']} s every new connection was refused while the workers recycled "
        f"({out['failed']} of {out['attempts']} attempts failed, {out['recycles']} recycles)"
    )


class _ListenerSampler:
    """Counts the sockets listening on one TCP port every `LISTENER_SAMPLE_S` (`ss -ltn`), from a thread."""

    def __init__(self, port: int) -> None:
        self.port = port
        self.samples: list[tuple[float, int]] = []
        self.started = time.monotonic()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self.available = shutil.which("ss") is not None

    def __enter__(self) -> _ListenerSampler:
        if self.available:
            self._thread.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self._stop.set()
        if self.available:
            self._thread.join(timeout=5)

    def _run(self) -> None:
        while not self._stop.is_set():
            answer = subprocess.run(
                ["ss", "-ltnH", f"sport = :{self.port}"], capture_output=True, text=True, check=False, timeout=5
            )
            if answer.returncode == 0:
                count = sum(1 for line in answer.stdout.splitlines() if line.strip())
                self.samples.append((round(time.monotonic() - self.started, 3), count))
            self._stop.wait(LISTENER_SAMPLE_S)


def _recycle_driver(work: Path, credentials: Path) -> dict[str, Any]:
    """Run the production config with a small `ROXY_MAX_REQUESTS` and probe it with fresh connections."""
    sys.path.insert(0, str(REPO / "tests" / "multiprocess"))
    from gunicorn_mp_driver import (  # the driver module lives beside this file
        QUIET_BACKGROUND,
        VENV_BIN,
        Master,
        MockRoblox,
        base_env,
        default_behavior,
        prepare_state,
    )

    class ConfigMaster(Master):
        """`Master` started from deploy/gunicorn.conf.py with a runtime directory of its own (/run/roxy-<color>)."""

        def __init__(self, name: str, work: Path, env: dict[str, str], workers: int) -> None:
            super().__init__(name, work, env, workers)
            runtime = work / f"run-{name}"
            runtime.mkdir(mode=0o750, parents=True, exist_ok=True)
            self.socket = runtime / "internal.sock"
            self.env = {
                **self.env,
                "ROXY_BIND": f"127.0.0.1:{self.port}",
                "ROXY_INTERNAL_SOCKET": str(self.socket),
                "ROXY_DEPLOY_STATE_DIR": str(runtime),
                "ROXY_MAX_REQUESTS": str(RECYCLE_MAX_REQUESTS),
            }

        def start(self) -> None:
            handle = open(self.log, "ab")  # noqa: SIM115 (kept open for the child's lifetime)
            self.proc = subprocess.Popen(
                [str(VENV_BIN / "gunicorn"), "-c", str(REPO / "deploy" / "gunicorn.conf.py"), "roxy.asgi:app"],
                env=self.env,
                cwd=REPO,
                stdout=handle,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )

    async def probe(port: int) -> tuple[list[tuple[float, str]], dict[str, int]]:
        outcomes: list[tuple[float, str]] = []
        proxied: dict[str, int] = {}
        limits = httpx.Limits(max_connections=1000, max_keepalive_connections=0)
        async with httpx.AsyncClient(limits=limits, timeout=60, trust_env=False) as client:

            async def one(at: float) -> None:
                try:
                    answer = await client.get(f"http://127.0.0.1:{port}/health")
                    outcomes.append((at, "ok" if answer.status_code == 200 else f"status_{answer.status_code}"))
                except httpx.ConnectError:
                    outcomes.append((at, "refused"))
                except httpx.HTTPError as exc:
                    outcomes.append((at, type(exc).__name__))

            async def call(n: int) -> None:
                # A caller's request that waits on Roblox (1.5 s here): what a worker drains when it stops.
                headers = {"X-Forwarded-For": f"198.51.100.{n % 250 + 1}", "User-Agent": "Roblox/Linux"}
                try:
                    answer = await client.get(
                        f"http://127.0.0.1:{port}/users.roblox.com/v1/users/{5000 + n}", headers=headers
                    )
                    kind = str(answer.status_code)
                except httpx.HTTPError as exc:
                    kind = type(exc).__name__
                proxied[kind] = proxied.get(kind, 0) + 1

            started = time.monotonic()
            tasks = []
            n = 0
            while (elapsed := time.monotonic() - started) < RECYCLE_SECONDS:
                due = n / RECYCLE_RATE
                if due > elapsed:
                    await asyncio.sleep(due - elapsed)
                tasks.append(asyncio.create_task(one(round(time.monotonic() - started, 4))))
                if n % 10 == 0:
                    tasks.append(asyncio.create_task(call(n // 10)))
                n += 1
            await asyncio.gather(*tasks)
        return sorted(outcomes), proxied

    def behavior(call: Any) -> Any:
        reply = default_behavior(call)
        if call.host == "users.roblox.com":
            reply.delay_s = 1.5
        return reply

    mock = MockRoblox(behavior).start()
    env = base_env(work, credentials, mock)
    state = Path(env["ROXY_STATE_DIR"])
    state.mkdir(parents=True, exist_ok=True)
    state.chmod(0o750)
    prepare_state(env, {**QUIET_BACKGROUND, "rotator_enabled": 0}, [])
    master = ConfigMaster("blue", work, env, 2)
    out: dict[str, Any] = {}
    try:
        master.start()
        out["ready"] = master.wait_ready()
        if not out["ready"]:
            out["log"] = master.log_tail()
            return out
        with _ListenerSampler(master.port) as sampler:
            outcomes, proxied = asyncio.run(probe(master.port))
        out["proxied"] = proxied
        longest, run_start, last_fail = 0.0, None, None
        for at, what in outcomes:
            if what == "ok":
                run_start = None
                continue
            run_start = at if run_start is None else run_start
            last_fail = at
            longest = max(longest, at - run_start)
        empty = [at for at, count in sampler.samples if count == 0]
        log = master.log.read_text(errors="replace")
        out.update(
            attempts=len(outcomes),
            failed=sum(1 for _, what in outcomes if what != "ok"),
            kinds={kind: sum(1 for _, what in outcomes if what == kind) for kind in {w for _, w in outcomes}},
            longest_refused_s=round(longest, 3),
            last_failure_at=last_fail,
            recycles=log.count("Maximum request limit"),
            boots=log.count("Booting worker"),
            listener_samples=len(sampler.samples),
            fewest_listeners=min((count for _, count in sampler.samples), default=None),
            no_listener_at=empty[:5],
        )
        master.stop(timeout_s=40)
        return out
    finally:
        master.kill()
        mock.stop()


def main() -> int:
    scenario, work, credentials = sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3])
    ip = shutil.which("ip") or "/usr/sbin/ip"
    subprocess.run([ip, "link", "set", "lo", "up"], check=False, capture_output=True)  # a fresh namespace
    work.mkdir(parents=True, exist_ok=True)
    if scenario != "recycle":
        raise SystemExit(f"unknown scenario {scenario!r}")
    print(json.dumps(_recycle_driver(work, credentials)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
