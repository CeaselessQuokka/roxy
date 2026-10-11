"""Each worker's CPU in the fleet view (gap G3, metric `worker_cpu_pct`): `read_fleet.worker_cpu` and the join.

What this is
    Unit tests of `scheduler/read_fleet.py`: the last complete minute of `worker_minute` per worker (the mean of its
    heartbeat's samples, and the highest), joined to the heartbeat rows by worker id in `fleet_summary`.

Why it exists
    The System page and API show every worker's CPU from one definition (`metrics/catalog.py worker_cpu_pct`); the
    minute still open and a worker that reported nothing recently stay unknown (None), never 0 (P6).

What to read next
    `roxy/scheduler/read_fleet.py`, `roxy/metrics/recorder.py` (`record_worker_sample`).
"""

from __future__ import annotations

from typing import Any

from roxy.scheduler import read_fleet

NOW = 1_760_000_130  # 2 minutes and 10 seconds into an hour


def _minute(dbs: Any, start: int, worker: str, samples: int, total: float, peak: float | None) -> None:
    dbs.metrics.write_sync(
        lambda conn: conn.execute(
            "INSERT INTO worker_minute (bucket_start, worker_id, samples, cpu_pct_sum, cpu_pct_max) "
            "VALUES (?, ?, ?, ?, ?)",
            (start, worker, samples, total, peak),
        )
    )


def test_the_last_complete_minute_of_each_worker(dbs: Any) -> None:
    current = NOW // 60 * 60
    _minute(dbs, current - 120, "w1", 12, 120.0, 30.0)  # an older minute
    _minute(dbs, current - 60, "w1", 12, 300.0, 55.5)  # the last complete minute: mean 25.0
    _minute(dbs, current, "w1", 3, 270.0, 95.0)  # still open: left out
    _minute(dbs, current - 60, "w2", 0, 0.0, None)  # no CPU sample in it: unknown
    _minute(dbs, current - read_fleet.CPU_LOOKBACK_S - 60, "w3", 12, 120.0, 20.0)  # too old
    found = dbs.metrics.read_sync(lambda conn: read_fleet.worker_cpu(conn, NOW))
    assert found == {"w1": {"cpu_pct": 25.0, "cpu_pct_max": 55.5, "cpu_minute": current - 60}}


def test_the_fleet_rows_carry_their_cpu_and_unknown_stays_none() -> None:
    rows = [
        {"pid": 11, "worker_id": "w1", "color": "blue", "fresh": True, "master_pid": 1},
        {"pid": 12, "worker_id": "w2", "color": "blue", "fresh": True, "master_pid": 1},
    ]
    cpu = {"w1": {"cpu_pct": 25.0, "cpu_pct_max": 55.5, "cpu_minute": 1_760_000_040}}
    summary = read_fleet.fleet_summary(rows, now_s=NOW, expected_per_color=2, this_color="blue", cpu=cpu)
    by_pid = {worker["pid"]: worker for worker in summary["workers"]}
    assert (by_pid[11]["cpu_pct"], by_pid[11]["cpu_pct_max"], by_pid[11]["cpu_minute"]) == (25.0, 55.5, 1_760_000_040)
    assert (by_pid[12]["cpu_pct"], by_pid[12]["cpu_pct_max"]) == (None, None)
    plain = read_fleet.fleet_summary(rows, now_s=NOW, expected_per_color=2, this_color="blue")
    assert all(worker["cpu_pct"] is None for worker in plain["workers"])
