"""Review round, lens mp: what `reuse_port` does when a gunicorn master's TCP port is already in use.

What this is
    Reproductions (now regular tests) of two findings about deploy/gunicorn.conf.py (`reuse_port = True`, `bind` from
    ROXY_BIND). The live tests start real gunicorn masters with the production config, exactly as roxy@.service
    starts them (`gunicorn -c deploy/gunicorn.conf.py roxy.asgi:app`), inside `unshare -rn` (a namespace with nothing
    but loopback): a second master misconfigured onto a running master's port, and a master whose port another
    listener already holds. The last test loads the config the way gunicorn does and checks the address a color
    gets when ROXY_BIND is missing. This file is also its own driver: run as a script inside the namespace with a
    scenario name, it prints one JSON object.

Why it exists
    Blue and green must never share a port: nginx switches traffic by port (deploy/nginx/roxy-upstream-*.conf), and
    during a deploy the two colors may run different releases. Without `reuse_port` the master binds the port
    itself, and a taken port makes it log "Connection in use" and exit 1, so systemd and the deploy see the mistake
    at once. With `reuse_port` the master binds nothing (gunicorn's `Arbiter.start` skips `create_sockets`) and each
    worker binds its own SO_REUSEPORT listener after the fork, so the master never learns whether the port works:
    - mp-3 (two tests): a second master (a stray manual start, a copy-pasted ROXY_BIND, the other color) on a port a
      running master serves starts quietly, and the kernel spreads the port's new connections over both masters'
      listeners; a master whose port another listener (without SO_REUSEPORT) holds stays up and READY to systemd
      while every worker fails to bind, exits 1 and is respawned, forever.
    - mp-4: a color whose env file lacks ROXY_BIND falls back to 127.0.0.1:8001 whatever its color, which is blue's
      port, so green would land on blue's port (and, with mp-3, share it silently).
    The fix pass recorded "a second master on the same port shares it silently" as a trade-off of the spread fix;
    the review lens asks that a misconfiguration fail loudly instead.

How it works
    The driver reuses tests/multiprocess/gunicorn_mp_driver.py (mock Roblox, state preparation, `Master`). Each
    master gets its own runtime directory for its internal and control sockets, as /run/roxy-<color> does in
    production. Every worker's heartbeat row carries its master's pid and a `proxied` counter, which says which
    master served the requests. Fixed: `on_starting` binds the TCP address once without SO_REUSEPORT (any
    listener refuses that) and exits 1 before READY when it is taken; `pre_fork` checks again with SO_REUSEPORT
    before every worker and halts the master on a foreign listener; without ROXY_BIND a color takes its own port.

What to read next
    deploy/gunicorn.conf.py (`reuse_port`, `bind`, `on_starting`, `pre_fork`, `check_ports_free`, `port_problem`,
    `resolve_bind`), deploy/systemd/roxy@.service (where ROXY_BIND comes
    from), deploy/env/*.env.example, and gunicorn's `arbiter.spawn_worker` (each worker binds when `reuse_port`).
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

REPO = Path(__file__).resolve().parents[2]
WORKERS = 2
REQUESTS = 40

pytestmark = [
    pytest.mark.multiprocess,
    pytest.mark.skipif(sys.platform != "linux", reason="real gunicorn workers need Linux"),
]


def _can_unshare() -> bool:
    try:
        result = subprocess.run(["unshare", "-rn", "true"], capture_output=True, timeout=10, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def _load_conf(monkeypatch: pytest.MonkeyPatch, **env: str) -> ModuleType:
    """Execute deploy/gunicorn.conf.py with exactly these ROXY_* variables, as gunicorn reads it."""
    for name in list(os.environ):
        if name.startswith("ROXY_"):
            monkeypatch.delenv(name, raising=False)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    name = f"rr_mp_conf_{abs(hash(tuple(env.items())))}"
    spec = importlib.util.spec_from_file_location(name, REPO / "deploy" / "gunicorn.conf.py")
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run_driver(tmp_path: Path, credentials_dir: Path, scenario: str) -> dict[str, Any]:
    """Run this file as the driver of `scenario` inside `unshare -rn`; return its JSON report."""
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
        ["unshare", "-rn", str(REPO / ".venv" / "bin" / "python"), __file__, scenario, str(work), str(quiet)],
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
    print("\n" + json.dumps({k: v for k, v in out.items() if not k.endswith("log")}))
    return out


# ------------------------------------------------------------------------------------------------- the tests


@pytest.mark.timeout(300)
def test_rr_mp_a_second_master_on_a_served_port_fails_loudly(tmp_path: Path, credentials_dir: Path) -> None:
    """Blue serves 127.0.0.1:<port>. A second master (green, its own sockets and color, the production config)
    is started with the same ROXY_BIND, the mistake a copy-pasted /etc/roxy/green.env or a manual start makes.
    It must not serve that port: it should exit with an error (as gunicorn does without `reuse_port`), and every
    request sent to the port must reach blue. Measured today: green boots both workers and answers 23 of 40 new
    connections sent to blue's port (possibly from another release), and nothing says so."""
    out = _run_driver(tmp_path, credentials_dir, "shared")
    assert out["blue_ready"], out.get("blue_log", "")
    assert out["served"] == REQUESTS, out
    # What a loud failure looks like: the second master is gone with an error status and served nothing.
    assert out["green_proxied"] == 0, f"the second master answered {out['green_proxied']} of {REQUESTS} requests"
    assert out["green_exit"] not in (None, 0), f"the second master is still running ({out['green_workers']} workers)"


@pytest.mark.timeout(300)
def test_rr_mp_a_master_whose_port_is_taken_fails_loudly(tmp_path: Path, credentials_dir: Path) -> None:
    """Another listener (opened without SO_REUSEPORT: any other program, or a leftover process) holds the port. A
    master started on it must fail (exit non-zero, as gunicorn does without `reuse_port`), so systemd marks the
    unit failed and the deploy or roxy-boot sees it. Today the master has already told systemd READY=1 (before any
    worker exists), each worker retries the bind 5 times, exits 1 and is respawned, and the master keeps running
    with no worker ever serving."""
    out = _run_driver(tmp_path, credentials_dir, "taken")
    print(out.get("master_log", "")[-1500:])
    assert out["workers_up"] == 0, "nothing can serve a port another listener holds"
    assert out["master_exit"] not in (None, 0), "the master is still running, its workers failing in a loop"


def test_rr_mp_a_color_without_its_bind_never_takes_the_other_colors_port(monkeypatch: pytest.MonkeyPatch) -> None:
    """deploy/env/green.env.example says green is 127.0.0.1:8002, and nginx's green upstream points there. If
    /etc/roxy/green.env lacks the ROXY_BIND line, gunicorn.conf.py fell back to 127.0.0.1:8001 for green too, the
    port blue serves, which `reuse_port` then shared silently (finding mp-3). Fixed: the fallback follows the color
    (the ports of deploy/nginx/roxy-upstream-<color>.conf); an explicit ROXY_BIND still wins."""
    blue = _load_conf(monkeypatch, ROXY_COLOR="blue")
    green = _load_conf(monkeypatch, ROXY_COLOR="green")
    assert blue.bind == ["127.0.0.1:8001"]
    assert green.bind == ["127.0.0.1:8002"], f"green binds {green.bind[0]} when ROXY_BIND is missing"
    nginx = (REPO / "deploy" / "nginx" / "roxy-upstream-green.conf").read_text()
    assert f"server {green.bind[0]};" in nginx  # the address nginx's green upstream sends to
    explicit = _load_conf(monkeypatch, ROXY_COLOR="green", ROXY_BIND="127.0.0.1:9002")
    assert explicit.bind == ["127.0.0.1:9002"]


# ------------------------------------------------------------------------------------------------ the driver


def _driver(scenario: str, work: Path, credentials: Path) -> dict[str, Any]:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from gunicorn_mp_driver import VENV_BIN, Addresses, Master, MockRoblox, base_env, default_behavior, prepare_state

    class ConfigMaster(Master):
        """`Master` started from deploy/gunicorn.conf.py, with a runtime directory of its own (/run/roxy-<color>)."""

        def __init__(self, name: str, work: Path, env: dict[str, str], workers: int, port: int | None) -> None:
            super().__init__(name, work, env, workers)
            runtime = work / f"run-{name}"
            runtime.mkdir(mode=0o750, parents=True, exist_ok=True)
            self.socket = runtime / "internal.sock"
            if port is not None:
                self.port = port
            self.env = {
                **self.env,
                "ROXY_BIND": f"127.0.0.1:{self.port}",
                "ROXY_INTERNAL_SOCKET": str(self.socket),
                "ROXY_DEPLOY_STATE_DIR": str(runtime),
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

    def proxied(master: Master) -> int:
        return sum(int(row.get("proxied") or 0) for row in master.worker_rows())

    async def traffic(master: Master) -> list[int]:
        ips = Addresses()
        async with master.client() as fresh:  # no keep-alive: every request is a new connection
            answers = await asyncio.gather(
                *(
                    fresh.get(
                        f"/users.roblox.com/v1/users/{2000 + n}",
                        headers={"X-Forwarded-For": ips.next(), "User-Agent": "Roblox/Linux"},
                    )
                    for n in range(REQUESTS)
                )
            )
        return [answer.status_code for answer in answers]

    def shared(env: dict[str, str]) -> dict[str, Any]:
        blue = ConfigMaster("blue", work, env, WORKERS, None)
        green = ConfigMaster("green", work, env, WORKERS, blue.port)  # the misconfiguration: blue's port
        out: dict[str, Any] = {"port": blue.port}
        try:
            blue.start()
            out["blue_ready"] = blue.wait_ready()
            if not out["blue_ready"]:
                out["blue_log"] = blue.log_tail()
                return out
            green.start()
            deadline = time.monotonic() + 40
            while time.monotonic() < deadline:  # either it gives up (exits) or its workers come up
                if green.proc is not None and green.proc.poll() is not None:
                    break
                if len(green.worker_rows()) >= WORKERS:
                    time.sleep(1.0)  # the workers' listeners are open once their lifespan finished
                    break
                time.sleep(0.25)
            out["green_workers"] = len(green.worker_rows())
            before_blue, before_green = proxied(blue), proxied(green)
            statuses = asyncio.run(traffic(blue))
            out["served"] = len(statuses)  # answered at all (the upstream buckets may pace some of them)
            out["statuses"] = {str(code): statuses.count(code) for code in sorted(set(statuses))}
            deadline = time.monotonic() + 20  # heartbeats carry the counters a few seconds later
            while time.monotonic() < deadline:
                if proxied(blue) - before_blue + proxied(green) - before_green >= REQUESTS:
                    break
                time.sleep(0.5)
            out["blue_proxied"] = proxied(blue) - before_blue
            out["green_proxied"] = proxied(green) - before_green
            out["green_exit"] = green.proc.poll() if green.proc is not None else None
            out["green_log"] = green.log_tail(12)
            green.stop()
            blue.stop()
            return out
        finally:
            green.kill()
            blue.kill()

    def taken(env: dict[str, str]) -> dict[str, Any]:
        holder = socket.socket()  # another program's listener: no SO_REUSEPORT
        holder.bind(("127.0.0.1", 0))
        holder.listen(8)
        port = int(holder.getsockname()[1])
        master = ConfigMaster("blue", work, env, WORKERS, port)
        out: dict[str, Any] = {"port": port}
        try:
            master.start()
            deadline = time.monotonic() + 30  # far longer than gunicorn's 5 bind attempts of 1 s each
            while time.monotonic() < deadline:
                if master.proc is not None and master.proc.poll() is not None:
                    break
                time.sleep(0.25)
            out["master_exit"] = master.proc.poll() if master.proc is not None else None
            out["workers_up"] = len(master.worker_rows())
            log = master.log.read_text(errors="replace") if master.log.exists() else ""
            out["bind_failures"] = log.count("Connection in use")
            out["workers_exited"] = log.count("exited with code 1")
            out["master_log"] = "\n".join(log.splitlines()[-15:])
            master.stop(timeout_s=20)
            return out
        finally:
            master.kill()
            holder.close()

    mock = MockRoblox(default_behavior).start()
    env = base_env(work, credentials, mock)
    state = Path(env["ROXY_STATE_DIR"])
    state.mkdir(parents=True, exist_ok=True)
    state.chmod(0o750)
    prepare_state(env, {"rotator_enabled": 0, "tarpit_enabled": 0, "allowed_requests_per_minute": 1000}, [])
    try:
        return shared(env) if scenario == "shared" else taken(env)
    finally:
        mock.stop()


def main() -> int:
    scenario, work, credentials = sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3])
    ip = shutil.which("ip") or "/usr/sbin/ip"
    subprocess.run([ip, "link", "set", "lo", "up"], check=False, capture_output=True)  # a fresh namespace
    work.mkdir(parents=True, exist_ok=True)
    print(json.dumps(_driver(scenario, work, credentials)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
