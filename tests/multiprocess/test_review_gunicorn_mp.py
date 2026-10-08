"""Adversarial review (multi-process and failure modes lens) on real gunicorn masters.

What this is
    Tests that run tests/multiprocess/review_gunicorn_driver.py inside `unshare -rn` (a namespace with nothing but
    loopback) and assert on the JSON it prints:
    - while another process holds hot.db's write lock, two real workers keep one client within the fleet limit
      (C7 degraded share `limit / workers`), never send the credential, and (finding HOT-HOL) answer slowly;
    - (finding SHUTDOWN-HOLD) a stop while the tarpit holds a request: gunicorn kills the worker after its 30 s
      graceful timeout, so the lifespan shutdown (final metrics flush, leader lease release) never runs.

Why it exists
    Plan 19.3 and 19.10 row 5 ("lifespan flushes on shutdown") need real workers: uvicorn's graceful wait, the
    gunicorn arbiter's kill, and each worker's own copy of the degraded limiter only exist there.

How it works
    Same harness as tests/multiprocess/test_gunicorn_mp.py: fake credentials without the mail password and the
    webhook, the driver in a private network namespace, one JSON object back. Tests that reproduce a finding are
    `xfail(strict=True)` with the finding id in the reason.

What to read next
    tests/multiprocess/review_gunicorn_driver.py, roxy/worker.py, deploy/gunicorn.conf.py, roxy/abuse/tarpit.py.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

REPO = Path(__file__).resolve().parents[2]
DRIVER = Path(__file__).with_name("review_gunicorn_driver.py")

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


def _run(scenario: str, tmp_path: Path, credentials_dir: Path, workers: int, timeout_s: float) -> dict[str, Any]:
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
    out = dict(json.loads(lines[-1]))
    assert out.get("ready"), out.get("log_tail", "")
    print("\n" + json.dumps({k: v for k, v in out.items() if k != "log_tail"}))
    return out


@pytest.mark.timeout(240)
def test_review_gunicorn_locked_hot_db_keeps_fleet_limits(tmp_path: Path, credentials_dir: Path) -> None:
    """C7 with 2 real workers and hot.db write-locked by another process: one client's 12 requests get at most the
    fleet limit (10; each worker allows 10 // 2 = 5 in memory), other clients are still served, and nothing is
    sent with the credential."""
    out = _run("hot_locked", tmp_path, credentials_dir, 2, timeout_s=220)
    assert out["warm_status"] == 200
    assert out["one_client_admitted"] <= 10
    assert out["one_client"].get("429 throttle", 0) >= 2
    assert out["distinct_clients"] == {"200": 12}
    assert out["cookie_calls"] == 0


@pytest.mark.timeout(240)
@pytest.mark.xfail(
    strict=True,
    reason="finding HOT-HOL: with hot.db write-locked, 24 cache hits on 2 real workers take seconds each (every "
    "abuse transaction waits its 0.5 s busy budget in turn on the single writer thread)",
)
def test_review_gunicorn_locked_hot_db_answers_stay_prompt(tmp_path: Path, credentials_dir: Path) -> None:
    out = _run("hot_locked", tmp_path, credentials_dir, 2, timeout_s=220)
    assert out["answer_s"]["slowest"] < 2.0, out["answer_s"]


@pytest.mark.timeout(240)
@pytest.mark.xfail(
    strict=True,
    reason="finding SHUTDOWN-HOLD: uvicorn waits without limit for a tarpit-held connection (no "
    "timeout_graceful_shutdown), gunicorn kills the worker after graceful_timeout (30 s), and the lifespan "
    "shutdown (final metrics flush, leader lease release) never runs",
)
def test_review_gunicorn_stop_during_a_tarpit_hold_still_flushes(tmp_path: Path, credentials_dir: Path) -> None:
    """Plan 19.10 row 5 ("lifespan flushes on shutdown"), 10.6 (holds up to 55 s) and deploy/gunicorn.conf.py
    (graceful_timeout 30): a stop while one probe is held for 45 s must still end with the lifespan shutdown: every
    answered request recorded, the held caller answered, the leader lease released."""
    out = _run("shutdown_hold", tmp_path, credentials_dir, 1, timeout_s=220)
    assert out["answered_before_stop"] == 10
    assert out["lifespan_shutdown_ran"], out.get("log_tail", "")[-2000:]
    assert out["recorded"] == out["proxy_requests_sent"]
    assert out["leader_lease_released"]
    assert out["held_client_saw"].startswith("status 404")
