"""Review round 3, lens mpjobs: leader jobs across two real gunicorn masters (a blue/green deploy).

What this is
    A real-process test: two gunicorn masters (blue and green, 2 `RoxyUvicornWorker` workers each) share one state
    directory, as during a deploy. Blue leads and writes the hourly LLM export file at start; green starts; blue
    stops; green takes the leader lease over. The test watches the export file (each atomic rename makes a new
    inode), the fleet schedule row of the export job in hot.db and the job status the leader publishes.

Why it exists
    The lens asks that leader jobs run exactly once per interval across 2 and 4 workers and two masters. The leader
    lease is fleet-wide (plan 5.6), but each worker's `JobRunner` used to keep its own schedule in memory: a worker
    that became the leader ran every job whose first run it had marked due at its own start, at once. So the hourly
    7 day full export (`llm_export_file`, about a second of CPU and a 0.3 s event loop block at its bounds, see
    finding mpjobs-6) and the 10 minute history prune ran again at every leader change: every deploy, every
    `max_requests` recycle of the leading worker, every crash (finding mpjobs-7). The schedule is now fleet-wide:
    every leader run records its start in hot.db `job_runs` (`schedule:<name>`), and a new leader schedules each
    job one interval after that start (`roxy/scheduler/jobs.py`).

How it works
    This file is also its own driver: the test runs `unshare -rn python <this file> two_masters_export <work>
    <credentials> 2`, so everything happens in a loopback-only network namespace (plan 19.12), reusing
    `gunicorn_mp_driver.py` (the mock Roblox, the state preparation, `Master`). The driver prints one JSON object.

What to read next
    `roxy/scheduler/jobs.py` (`JobRunner.sync_schedule`, `record_start`), `roxy/insights/llm_export.py`
    (`register_jobs`), `tests/multiprocess/gunicorn_mp_driver.py`.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest

REPO = Path(__file__).resolve().parents[2]
SCENARIO = "two_masters_export"

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


def _quiet_credentials(source: Path, target: Path) -> Path:
    """The fake credentials without the mail password and the webhook URL: alerts stay in the log."""
    target.mkdir(mode=0o700)
    for path in source.iterdir():
        if path.name in ("smtp_password", "alert_webhook_url"):
            continue
        copy = target / path.name
        shutil.copyfile(path, copy)
        copy.chmod(0o600)
    return target


@pytest.mark.timeout(300)
def test_r3_mpjobs_a_leader_change_does_not_rerun_the_hourly_export(tmp_path: Path, credentials_dir: Path) -> None:
    if not _can_unshare() or not (shutil.which("ip") or Path("/usr/sbin/ip").exists()):
        pytest.skip("needs unprivileged user and network namespaces (unshare -rn) and ip")
    if not (REPO / ".venv" / "bin" / "gunicorn").exists():
        pytest.skip("gunicorn is not installed in .venv")
    work = tmp_path / "work"
    work.mkdir()
    credentials = _quiet_credentials(credentials_dir, tmp_path / "quiet-credentials")
    result = subprocess.run(
        [
            "unshare",
            "-rn",
            str(REPO / ".venv" / "bin" / "python"),
            __file__,
            SCENARIO,
            str(work),
            str(credentials),
            "2",
        ],
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
    out = json.loads(lines[-1])
    log = out.get("log_tail", "")
    assert out["ready"], log
    assert out["blue_leader"]["leaders"] == 1, (out, log)
    assert out["first_export"] is not None, (out, log)
    assert out["after_stop"]["leaders"] == 1, (out, log)  # green leads now: the lease moved (plan 5.6)
    assert out["green_holds_the_lease"], out
    # Exactly once per interval across the fleet: blue wrote the hourly file a minute ago, so green must not write it
    # again until the hour is up.
    assert out["export_writes"] == 1, (out["export_writes"], out["export_inodes"], log)
    # The fleet schedule row still names blue's run: green, the leader under a newer epoch, never started the job.
    schedule = out["export_schedule"]
    assert schedule is not None, out
    assert schedule["epoch"] == out["blue_lease_epoch"], (schedule, out["blue_lease_epoch"])
    assert schedule["epoch"] < out["green_lease_epoch"], out


# ============================================================================================== the driver


def _scenario(work: Path, credentials: Path, workers: int) -> dict[str, Any]:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import gunicorn_mp_driver as d  # the driver module of this folder, only inside the namespace

    mock = d.MockRoblox(d.default_behavior).start()
    env = d.base_env(work, credentials, mock)
    d.prepare_state(env, {"rotator_enabled": 0, "tarpit_enabled": 0, **d.QUIET_BACKGROUND}, [])
    export = Path(env["ROXY_STATE_DIR"]) / "exports" / "roxy-llm-export.json"
    inodes: list[int] = []
    stop_watch = {"stop": False}

    def watch_once() -> None:
        with contextlib.suppress(OSError):
            inode = os.stat(export).st_ino
            if not inodes or inodes[-1] != inode:
                inodes.append(inode)

    async def watch(seconds: float) -> None:
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline and not stop_watch["stop"]:
            watch_once()
            await asyncio.sleep(0.1)

    blue = d.Master("blue", work, env, workers)
    green = d.Master("green", work, env, workers)
    out: dict[str, Any] = {}
    try:
        blue.start()
        out["ready"] = blue.wait_ready()
        if not out["ready"]:
            out["log_tail"] = blue.log_tail()
            return out
        blue_pids = {row["pid"] for row in blue.worker_rows()}
        out["blue_leader"] = asyncio.run(d.wait_one_leader(env, blue_pids))
        for _ in range(600):  # the hourly export runs at the leader's start
            watch_once()
            if inodes:
                break
            time.sleep(0.1)
        out["first_export"] = inodes[0] if inodes else None
        first_at = time.time()
        blue_lease = d.leader_lease(env)
        out["blue_lease_epoch"] = blue_lease["epoch"] if blue_lease else None
        green.start()
        out["ready"] = green.wait_ready()
        if not out["ready"]:
            out["log_tail"] = blue.log_tail() + "\n" + green.log_tail()
            return out
        green_pids = {row["pid"] for row in green.worker_rows()}
        asyncio.run(watch(1.0))
        out["blue_stop_code"], _ = blue.stop()  # the deploy stops the old color; green takes the lease over
        out["after_stop"] = asyncio.run(d.wait_one_leader(env, green_pids, timeout_s=30))
        lease = d.leader_lease(env)
        out["green_holds_the_lease"] = bool(lease and any(f":{pid}:" in lease["holder"] for pid in green_pids))
        out["green_lease_epoch"] = lease["epoch"] if lease else None
        asyncio.run(watch(25.0))  # well inside the hour that began with blue's export
        out["export_inodes"] = inodes
        out["export_writes"] = len(inodes)
        out["seconds_since_first_export"] = round(time.time() - first_at, 1)
        out["export_schedule"] = None
        with contextlib.suppress(sqlite3.Error):
            rows = d.query(
                env["ROXY_HOT_DB"],
                "SELECT epoch, started_at FROM job_runs WHERE idem_key = ?",
                ("schedule:llm_export_file",),
            )
            out["export_schedule"] = {"epoch": rows[0][0], "started_at": rows[0][1]} if rows else None
        with contextlib.suppress(sqlite3.Error):
            status = d.job_status(env)
            out["published"] = {
                name: status.get(name) for name in ("llm_export_file", "insights_history_prune", "insights_evaluate")
            }
        out["green_stop_code"], _ = green.stop()
        out["log_tail"] = blue.log_tail(10) + "\n" + green.log_tail(10)
        return out
    finally:
        stop_watch["stop"] = True
        blue.kill()
        green.kill()
        mock.stop()


def _main() -> int:
    scenario, work, credentials, workers = sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3]), int(sys.argv[4])
    assert scenario == SCENARIO, scenario
    ip = shutil.which("ip") or "/usr/sbin/ip"
    subprocess.run([ip, "link", "set", "lo", "up"], check=False, capture_output=True)  # a fresh namespace has lo down
    print(json.dumps(_scenario(work, credentials, workers), default=str))
    return 0


if __name__ == "__main__":
    sys.exit(_main())
