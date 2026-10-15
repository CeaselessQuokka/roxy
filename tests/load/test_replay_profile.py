"""Plan 19.10 row 7, second half: a v1-like traffic profile against realistic Roblox limits, through real workers.

What this is
    Two tests over ONE run of the load harness's `replay` scenario (tests/load/scenarios.py), started once per
    module by the `replay` fixture, for the two numbers plan 19.10 row 7 sets:
    - `test_replay_avoids_calls_and_runs_clean`: the avoided-call share is at least 40 percent, and the run itself
      was sound (gunicorn stopped cleanly, no transport errors, enough upstream calls, no credential on caller
      traffic, a Retry-After on every 429 or 503 Roxy sent).
    - `test_replay_keeps_roblox_429s_below_a_tenth_of_a_percent`: Roblox answered 429 to fewer than 0.1 percent
      of upstream calls (finding LOAD-1, below, is fixed).
    Marked `load` (`pytest -m load tests/load`) so CI can select it; the run takes about 4 minutes (the plan's
    budget is 5), the only gunicorn start in the normal suite's tests/load.

Why it exists
    The first half of row 7 (one 429 with `Retry-After: 30`, no call during the cooldown, the bucket rate after it)
    is tests/multiprocess/test_gunicorn_mp.py::test_gunicorn_mock_429_retry_after_30. This half checks the whole
    design at once on realistic traffic: cache rules, single-flight, buckets, cooldowns and adaptive rate together
    must keep a Roblox that limits each endpoint from having to say "too many requests", while answering most
    callers without asking Roblox at all.

    Finding LOAD-1 (load lane, 2026-10-09; fixed by the pacing lane the same day): at the plan's defaults v2 used
    to get 2 Roblox 429s in about 1,020 upstream calls (0.196 percent) on this profile, in every run. The busiest
    endpoint, avatar outfits (16 percent of requests, a long tail of 20,000 user ids, so a low hit ratio, and a
    Roblox threshold of 60 calls a minute), starts at the default endpoint rate of 120 a minute; only its share of
    the direct egress bucket (300 a minute) held it near 60, and it reached 61 calls in a minute twice, because the
    adaptive controller cut the CONFIGURED rate (120 to 84, still not binding) and never the burst. Now the host
    and endpoint buckets never let a rolling minute hold more than their limit (rate plus burst inside one window),
    and a Roblox 429 cuts rate and burst from the calls the endpoint actually made in that minute (61 to about 43,
    burst 10 to 3), so the one 429 that discovers the endpoint's limit after a cold start is the only one: about 1
    in 1,020 calls, under the bar (src/roxy/upstream/buckets.py and adaptive.py). The earlier version of this test
    passed most runs only because its client and mock ran on CLOCK_MONOTONIC, which runs 9.5 percent fast on WSL 2
    (see tests/load/clock.py): the mock's minute was 55 real seconds while Roxy's buckets counted real seconds.
    Details and the numbers of the runs: docs/PERFORMANCE.md and .remake/p11_reports/pacing.md.

How it works
    - Production settings (built-in defaults; only the scheduled health run and the rotator are off, see
      `fleet.QUIET_BACKGROUND`), real gunicorn with `deploy/gunicorn.conf.py` and 2 `RoxyUvicornWorker` workers,
      inside `unshare -rn` with the mock Roblox on loopback.
    - Traffic: `traffic.V1_LIKE_MIX` (13 endpoints, synthetic, shaped like v1's mix; no real data) at 10 requests
      a second for 200 s from 300 game server addresses, Poisson arrivals, from an empty cache.
    - The mock refuses an endpoint (429, no Retry-After, like Roblox) when Roxy's one address made more calls to
      it in the last 60 s than its threshold (30 to 150 a minute, fixed in `traffic.py` before the first run).
      Client, mock and Roxy share one time line (`clock.py`), so the thresholds mean what they say.
    - Ground truth comes from the mock: upstream calls are the calls it received for caller traffic (Roxy's own
      credential probes carry the cookie and are left out), and demand is every caller request Roxy tried to serve
      (abuse refusals left out, plan P6). Roxy's own figures (metrics.db) are in the JSON for comparison.
    - The thresholds are part of the test's definition and must not be tuned to make it pass; a failure message
      carries the per-endpoint numbers, including each endpoint's busiest 60 s against its threshold.

What to read next
    tests/load/scenarios.py (`replay`, `replay_numbers`), tests/load/traffic.py (the profile and thresholds),
    docs/PERFORMANCE.md (the load lane's runs before LOAD-1 was fixed), src/roxy/upstream/buckets.py (window
    buckets and their meters) and src/roxy/upstream/adaptive.py (the cut from the calls Roblox refused).
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
RUN_TIMEOUT_S = 285.0
"""The harness run (about 230 s on a quiet machine) must end inside the tests' 300 s budget (plan: under 5 min)."""

pytestmark = [
    pytest.mark.load,
    pytest.mark.skipif(sys.platform != "linux", reason="real gunicorn workers need Linux"),
]


def run_replay(work: Path, timeout_s: float) -> dict[str, Any]:
    if not (REPO / ".venv" / "bin" / "gunicorn").exists():
        pytest.skip("gunicorn is not installed in .venv")
    out = work / "replay.json"
    env = {key: value for key, value in os.environ.items() if not key.startswith("ROXY_")}
    env["PYTHONPATH"] = str(TESTS_DIR)
    try:
        result = subprocess.run(
            [str(PYTHON), "-m", "load.harness", "replay", "--json", str(out), "--work", str(work / "work")],
            cwd=TESTS_DIR,
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout_s,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        pytest.fail(f"the replay did not finish in {timeout_s:g} s (a very busy machine?):\n{exc.stdout!r}"[-3000:])
    if result.returncode == EXIT_NO_NAMESPACE:
        pytest.skip("needs unprivileged user and network namespaces (unshare -rn)")
    assert out.exists(), f"harness exit {result.returncode}:\n{result.stdout[-3000:]}\n{result.stderr[-3000:]}"
    report = json.loads(out.read_text())
    report["stdout"] = result.stdout
    return dict(report)


@pytest.fixture(scope="module")
def replay(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    """One replay run shared by both tests (it is the 4 minutes; the assertions are instant)."""
    report = run_replay(tmp_path_factory.mktemp("replay"), timeout_s=RUN_TIMEOUT_S)
    scenario = report["scenarios"]["replay"]
    data = dict(scenario["data"])
    data["ok"] = scenario["ok"]
    data["table"] = report["stdout"]
    if "upstream_calls" in data:  # one line in the output of `pytest -rA`, for docs/PERFORMANCE.md
        print(
            f"replay: {data['upstream_calls']} upstream calls, {data['roblox_429']} Roblox 429s "
            f"({data['roblox_429_pct']:.3f} %) at {data['roblox_429_times_s']} s, avoided {data['avoided_pct']:.1f} %, "
            f"busiest 60 s against each threshold: {headroom(data)}; {scenario['seconds']} s"
        )
    return data


def headroom(data: dict[str, Any]) -> str:
    """Each endpoint's busiest 60 s against its threshold, closest first (the failure messages print it)."""
    rows = sorted(
        (row["headroom"], name, row["peak_60s"], row["limit_per_min"], row["roblox_429"])
        for name, row in data["per_endpoint"].items()
        if row.get("headroom") is not None
    )
    return "; ".join(f"{name} {peak}/{limit} ({n429} x 429)" for _, name, peak, limit, n429 in rows)


@pytest.mark.timeout(300)
def test_replay_avoids_calls_and_runs_clean(replay: dict[str, Any]) -> None:
    data = replay
    table = data["table"]
    assert data["ok"], (data.get("log_tail") or data.get("traceback") or "", table)
    assert data["stop_code"] == 0, table
    assert data["transport_errors"] == 0, table
    # Enough upstream calls that the shares mean something, and no caller traffic with the credential (D1, C2).
    assert data["upstream_calls"] >= 500, table
    assert data["cookie_calls_on_caller_endpoints"] == 0, table
    assert data["missing_retry_after"] == 0, table  # every 429 or 503 Roxy sent told the caller when to retry
    per_endpoint = json.dumps(data["per_endpoint"], indent=1)
    assert data["avoided_pct"] >= 40.0, (
        f"avoided-call share {data['avoided_pct']:.1f} % (second half {data['avoided_pct_second_half']:.1f} %), "
        f"demand {data['demand']}, upstream calls {data['upstream_calls']}\n{per_endpoint}\n{table}"
    )


@pytest.mark.timeout(300)
def test_replay_keeps_roblox_429s_below_a_tenth_of_a_percent(replay: dict[str, Any]) -> None:
    data = replay
    assert data["ok"], data["table"]
    assert data["upstream_calls"] >= 500, data["table"]
    assert data["roblox_429_pct"] < 0.1, (
        f"Roblox answered 429 to {data['roblox_429']} of {data['upstream_calls']} upstream calls "
        f"({data['roblox_429_pct']:.3f} %), by endpoint {data['roblox_429_by_endpoint']}, "
        f"at {data['roblox_429_times_s']} s; adaptive rates {data['upstream_limits']}; busiest 60 s against each "
        f"threshold: {headroom(data)}\n{data['table']}"
    )
