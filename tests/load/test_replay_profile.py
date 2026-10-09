"""Plan 19.10 row 7, second half: a v1-like traffic profile against realistic Roblox limits, through real workers.

What this is
    One test that runs the load harness's `replay` scenario (tests/load/scenarios.py) and asserts the two numbers
    plan 19.10 row 7 sets: Roblox 429s stay below 0.1 percent of upstream calls, and the avoided-call share is at
    least 40 percent. Marked `load` (`pytest -m load tests/load`) so CI can run it; it takes about 4 minutes.

Why it exists
    The first half of row 7 (one 429 with `Retry-After: 30`, no call during the cooldown, the bucket rate after it)
    is tests/multiprocess/test_gunicorn_mp.py::test_gunicorn_mock_429_retry_after_30. This half checks the whole
    design at once on realistic traffic: cache rules, single-flight, buckets, cooldowns and adaptive rate together
    must keep a Roblox that limits each endpoint from ever having to say "too many requests", while answering most
    callers without asking Roblox at all.

How it works
    - Production settings (built-in defaults; only the scheduled health run and the rotator are off, see
      `fleet.QUIET_BACKGROUND`), real gunicorn with `deploy/gunicorn.conf.py` and 2 `RoxyUvicornWorker` workers,
      inside `unshare -rn` with the mock Roblox on loopback.
    - Traffic: `traffic.V1_LIKE_MIX` (13 endpoints, synthetic, shaped like v1's mix; no real data) at 10 requests
      a second for 200 s from 300 game server addresses, Poisson arrivals, from an empty cache.
    - The mock refuses an endpoint (429, no Retry-After, like Roblox) when Roxy's one address made more calls to
      it in the last 60 s than its threshold (30 to 150 a minute, fixed in `traffic.py` before the first run).
    - Ground truth comes from the mock: upstream calls are the calls it received for caller traffic (Roxy's own
      credential probes carry the cookie and are left out), and demand is every caller request Roxy tried to serve
      (abuse refusals left out, plan P6). Roxy's own figures (metrics.db) are in the JSON for comparison.
    - The thresholds are part of the test's definition and must not be tuned to make it pass; if it fails, the
      failure message has the per-endpoint numbers, and docs/PERFORMANCE.md the analysis.

What to read next
    tests/load/scenarios.py (`replay`, `replay_numbers`), tests/load/traffic.py (the profile and thresholds).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

TESTS_DIR = Path(__file__).resolve().parents[1]
REPO = TESTS_DIR.parent
PYTHON = REPO / ".venv" / "bin" / "python"
EXIT_NO_NAMESPACE = 3  # harness.EXIT_NO_NAMESPACE

pytestmark = [
    pytest.mark.load,
    pytest.mark.skipif(sys.platform != "linux", reason="real gunicorn workers need Linux"),
]


def run_replay(tmp_path: Path, timeout_s: float) -> dict[str, Any]:
    if not (REPO / ".venv" / "bin" / "gunicorn").exists():
        pytest.skip("gunicorn is not installed in .venv")
    out = tmp_path / "replay.json"
    env = {key: value for key, value in os.environ.items() if not key.startswith("ROXY_")}
    env["PYTHONPATH"] = str(TESTS_DIR)
    result = subprocess.run(
        [str(PYTHON), "-m", "load.harness", "replay", "--json", str(out), "--work", str(tmp_path / "work")],
        cwd=TESTS_DIR,
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout_s,
        check=False,
    )
    if result.returncode == EXIT_NO_NAMESPACE:
        pytest.skip("needs unprivileged user and network namespaces (unshare -rn)")
    assert out.exists(), f"harness exit {result.returncode}:\n{result.stdout[-3000:]}\n{result.stderr[-3000:]}"
    report = json.loads(out.read_text())
    report["stdout"] = result.stdout
    return dict(report)


@pytest.mark.timeout(300)
def test_replay_v1_profile_keeps_roblox_429s_rare_and_avoids_calls(tmp_path: Path) -> None:
    report = run_replay(tmp_path, timeout_s=290)
    scenario = report["scenarios"]["replay"]
    data = scenario["data"]
    table = report["stdout"]
    assert scenario["ok"], (data.get("log_tail") or data.get("traceback") or "", table)
    assert data["stop_code"] == 0, table
    assert data["transport_errors"] == 0, table
    # Enough upstream calls that 0.1 percent means something, and no caller traffic with the credential (D1, C2).
    assert data["upstream_calls"] >= 500, table
    assert data["cookie_calls_on_caller_endpoints"] == 0, table
    assert data["missing_retry_after"] == 0, table  # every 429 or 503 Roxy sent told the caller when to retry

    per_endpoint = json.dumps(data["per_endpoint"], indent=1)
    assert data["roblox_429_pct"] < 0.1, (
        f"Roblox answered 429 to {data['roblox_429']} of {data['upstream_calls']} upstream calls "
        f"({data['roblox_429_pct']:.3f} %), by endpoint {data['roblox_429_by_endpoint']}, "
        f"at {data['roblox_429_times_s']} s; adaptive rates {data['upstream_limits']}\n{per_endpoint}\n{table}"
    )
    assert data["avoided_pct"] >= 40.0, (
        f"avoided-call share {data['avoided_pct']:.1f} % (second half {data['avoided_pct_second_half']:.1f} %), "
        f"demand {data['demand']}, upstream calls {data['upstream_calls']}\n{per_endpoint}\n{table}"
    )
