"""Real gunicorn with `RoxyUvicornWorker`: every limit holds with 1, 2 and 4 worker processes (plan 19.3, C6).

What this is
    Tests that start real gunicorn masters (through tests/multiprocess/gunicorn_mp_driver.py) over temporary
    databases, with a local asyncio server playing every Roblox host, and assert:
    - per-IP limits are exact, not multiplied by the number of workers;
    - fleet single-flight holds (20 callers of one key across the workers make one upstream call);
    - an upstream bucket holds across workers (no worker gets its own copy of the budget);
    - a settings change reaches every worker within 2 s;
    - exactly one leader, also across two gunicorn masters sharing the state (blue and green), and the other color
      takes over when the leading one stops;
    - the metrics totals recorded equal the proxy requests sent (after the graceful stop flushed every worker);
    - plan 19.10 row 7: after a Roblox 429 with `Retry-After: 30`, zero calls to that endpoint while the cooldown
      lasts, at most the bucket rate in the 60 s after it, zero calls carrying the credential, and every refused
      caller is told when to come back (`Retry-After`).

Why it exists
    Unit and integration tests run every package in one process; only real worker processes show that the shared
    state really is shared (hot.db buckets and limiters, cache.db and the single-flight leases, control.db's
    config_version) and that nothing per worker multiplies a limit.

How it works
    The driver runs inside `unshare -rn` (a private user and network namespace with only loopback), so nothing the
    app does can reach a real system; the tests are skipped where unprivileged namespaces are not available. The
    credentials are the conftest fakes without the mail password and webhook, so no alert is ever sent anywhere.
    The driver prints one JSON object; each test asserts on it and shows the gunicorn log tail when it fails.

What to read next
    tests/multiprocess/gunicorn_mp_driver.py (what each scenario does), roxy/worker.py and roxy/lifespan.py.
"""

from __future__ import annotations

import json
import math
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

REPO = Path(__file__).resolve().parents[2]
DRIVER = Path(__file__).with_name("gunicorn_mp_driver.py")

pytestmark = [
    pytest.mark.multiprocess,
    pytest.mark.skipif(sys.platform != "linux", reason="real gunicorn workers need Linux"),
]


def can_unshare() -> bool:
    try:
        result = subprocess.run(["unshare", "-rn", "true"], capture_output=True, timeout=10, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def quiet_credentials(source: Path, target: Path) -> Path:
    """The fake credentials without the mail password and the webhook URL: alerts stay in the log."""
    target.mkdir(mode=0o700)
    for path in source.iterdir():
        if path.name in ("smtp_password", "alert_webhook_url"):
            continue
        copy = target / path.name
        shutil.copyfile(path, copy)
        copy.chmod(0o600)
    return target


def run_driver(scenario: str, tmp_path: Path, credentials_dir: Path, workers: int, timeout_s: float) -> dict[str, Any]:
    if not can_unshare() or not (shutil.which("ip") or Path("/usr/sbin/ip").exists()):
        pytest.skip("needs unprivileged user and network namespaces (unshare -rn) and ip")
    if not (REPO / ".venv" / "bin" / "gunicorn").exists():
        pytest.skip("gunicorn is not installed in .venv")
    work = tmp_path / "work"
    work.mkdir()
    credentials = quiet_credentials(credentials_dir, tmp_path / "quiet-credentials")
    result = subprocess.run(
        [
            "unshare",
            "-rn",
            str(REPO / ".venv" / "bin" / "python"),
            str(DRIVER),
            scenario,
            str(work),
            str(credentials),
            str(workers),
        ],
        capture_output=True,
        text=True,
        timeout=timeout_s,
        check=False,
        cwd=REPO,
    )
    lines = [line for line in result.stdout.splitlines() if line.startswith("{")]
    failure = f"driver failed ({result.returncode}):\n{result.stderr[-4000:]}"
    assert result.returncode == 0, failure
    assert lines, failure
    return dict(json.loads(lines[-1]))


@pytest.mark.timeout(300)
@pytest.mark.parametrize("workers", [1, 2, 4])
def test_gunicorn_fleet_limits_hold(tmp_path: Path, credentials_dir: Path, workers: int) -> None:
    out = run_driver("fleet", tmp_path, credentials_dir, workers, timeout_s=280)
    log = out.get("log_tail", "")
    assert out["ready"], log
    assert out["worker_pids"] == workers, log

    # Per-IP limit: 10 per 50 s for the client, whichever worker answered (not 10 per worker).
    per_ip = out["per_ip"]
    assert per_ip["statuses"] == {"200": 10, "429": 20}, (per_ip, log)
    assert per_ip["refusals"] == {"": 10, "throttle": 20}, per_ip
    assert per_ip["missing_retry_after"] == 0

    # Single-flight: one upstream call for 20 concurrent callers of one key, across every worker.
    flight = out["single_flight"]
    assert flight["calls"] == 1, (flight, log)
    assert flight["statuses"] == {"200": 20}, flight
    assert flight["bodies"] == ['{"data":["shared"]}']
    assert set(flight["cache"]) <= {"MISS", "COALESCED", "HIT"}, flight

    # The endpoint bucket (6 per minute, burst 2) is one bucket for the fleet: no token leaks or copies.
    bucket = out["bucket"]
    allowed = 2 + math.floor(bucket["elapsed_s"] / 10)
    assert 1 <= bucket["calls"] <= allowed, (bucket, log)
    assert bucket["statuses"].get("200", 0) == bucket["calls"], bucket
    assert bucket["statuses"].get("429", 0) == 20 - bucket["calls"], bucket
    assert bucket["refusals"].get("upstream_busy", 0) == 20 - bucket["calls"], bucket
    assert bucket["missing_retry_after"] == 0

    # The traffic really was spread over the workers (each worker counts what reached its proxy route).
    served = out["proxied_by_worker"]
    assert sum(served) == 70, served
    if workers > 1:
        assert sum(1 for count in served if count > 0) >= 2, served

    # A settings change written by one process is live in every worker within 2 s (each worker logs the reload).
    reload = out["reload"]
    assert reload["workers_reloaded"] == workers, reload
    assert 0 <= reload["slowest_reload_s"] <= 2.0, reload
    assert all(version < reload["new_version"] for version in reload["old_versions_before"]), reload
    assert reload["versions_after"] == [reload["new_version"]], reload
    assert reload["cors_after"] == reload["cors_checked"], reload

    # Exactly one leader among the workers, and it holds the lease.
    assert out["leader"] == {"workers": workers, "leaders": 1, "lease_holder_is_the_leader": True}, (out, log)

    # The graceful stop flushed every worker: what was recorded equals what was sent.
    assert out["stop_code"] == 0, log
    assert out["heartbeats_after_stop"] == 0, log
    assert out["recorded"] == out["sent"], (out["recorded"], out["sent"], log)
    assert out["cookie_calls"] == 0  # no caller traffic ever carried the credential (D1, C2)


@pytest.mark.timeout(240)
def test_gunicorn_one_leader_across_two_masters(tmp_path: Path, credentials_dir: Path) -> None:
    out = run_driver("two_masters", tmp_path, credentials_dir, 2, timeout_s=220)
    log = out.get("log_tail", "")
    assert out["ready"], log
    assert out["both"] == {"workers": 4, "leaders": 1, "lease_holder_is_the_leader": True}, (out, log)
    assert out["leader_stop_code"] == 0, log
    # The color still running takes over (the stopping leader releases its lease) and the epoch moves (fencing).
    assert out["after_stop"] == {"workers": 2, "leaders": 1, "lease_holder_is_the_leader": True}, (out, log)
    assert out["epoch_moved"], out
    assert out["other_stop_code"] == 0, log


@pytest.mark.timeout(400)
def test_gunicorn_mock_429_retry_after_30(tmp_path: Path, credentials_dir: Path) -> None:
    """Plan 19.10 row 7 with two real workers (about 100 s: the cooldown and the 60 s window are real time)."""
    out = run_driver("cooldown_429", tmp_path, credentials_dir, 2, timeout_s=380)
    log = out.get("log_tail", "")
    assert out["ready"], log
    assert out["t429_seen"], (out, log)
    assert out["calls_during_cooldown"] == 0, (out, log)  # no worker called the endpoint while it cooled down
    assert out["responses_during_cooldown"] >= 80, out
    assert out["during_statuses"] == {"429": out["responses_during_cooldown"]}, out
    assert out["during_without_retry_after"] == 0, out  # every caller was told when to come back
    # After the cooldown, at most the endpoint's bucket rate (60 per minute, burst 5) over 60 s.
    assert 0 < out["calls_in_60s_after"] <= 65, (out, log)
    assert out["missing_retry_after"] == 0, out
    assert out["cookie_calls"] == 0  # zero cascades onto the credential
    assert out["stop_code"] == 0, log
    assert out["recorded"] == out["sent"], (out["recorded"], out["sent"])
