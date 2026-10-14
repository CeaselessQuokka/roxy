"""Service uptime from the gunicorn master (parity row 84, plan 14.1 row 3; finding v1parity-2): `read_fleet`.

What this is
    Unit tests of `scheduler/read_fleet.py` `color_master_pids`, `master_start_times` and `service_since`, the
    service uptime alone, and of `fleet_summary`, which reads its per color uptime through the same two helpers.

Why it exists
    v1 pinned ServiceStartedAt to the gunicorn master, so a worker recycle (`ROXY_MAX_REQUESTS`) never restarted it.
    The Overview's Service uptime tile once read the oldest worker's age instead and restarted with every recycle,
    while System > Fleet read the master. One v1 tile has one number: both pages now read these helpers.

What to read next
    `roxy/scheduler/read_fleet.py`, `roxy/admin/api/overview.py service_uptime`, `roxy/admin/api/system.py fleet`.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from roxy.scheduler import read_fleet

NOW = 1_760_000_000


def _row(
    pid: int, master: Any, *, color: Any = "blue", fresh: bool = True, started_at: int = NOW - 60
) -> dict[str, Any]:
    """A `heartbeat.fleet_view` row (only the fields the fleet read models look at)."""
    return {
        "pid": pid,
        "worker_id": f"host:{pid}:x",
        "color": color,
        "master_pid": master,
        "fresh": fresh,
        "started_at": started_at,
        "uptime_s": NOW - started_at,
        "last_seen": NOW,
    }


def test_the_master_pids_of_a_color_are_its_fresh_rows_masters_once_each() -> None:
    rows = [
        _row(11, 100),
        _row(12, 100),  # a second worker of the same master: listed once
        _row(13, 200, fresh=False),  # a stale row says nothing about the master serving now
        _row(14, 300, color="green"),  # another color
        _row(15, 0),  # no master known
        _row(16, None),
        _row(17, 400),  # a second master of the color (while one is being replaced)
        _row(18, 500, color=None),  # no color: grouped under "unknown", as `fleet_summary` does
    ]
    assert read_fleet.color_master_pids(rows, "blue") == [100, 400]
    assert read_fleet.color_master_pids(rows, "green") == [300]
    assert read_fleet.color_master_pids(rows, "unknown") == [500]
    assert read_fleet.color_master_pids(rows, "") == []


def test_the_service_uptime_is_since_the_oldest_known_master_start() -> None:
    started = {100: NOW - 86_400.5, 400: NOW - 30.0, 600: None}
    assert read_fleet.service_since([100, 400], started, NOW) == (NOW - 86_400.5, 86_400)
    assert read_fleet.service_since([400, 600], started, NOW) == (NOW - 30.0, 30)
    # Unknown stays unknown (P6): never a worker's age, never 0.
    assert read_fleet.service_since([600], started, NOW) == (None, None)
    assert read_fleet.service_since([], started, NOW) == (None, None)
    # A master start a little after `now` (a clock step back) is 0 seconds, never negative.
    assert read_fleet.service_since([700], {700: NOW + 0.9}, NOW) == (NOW + 0.9, 0)


def test_a_recycled_worker_does_not_restart_the_fleet_uptime() -> None:
    """The finding's case: the master has run a day, its only worker was recycled a minute ago."""
    rows = [_row(11, 100, started_at=NOW - 60)]
    started = {100: float(NOW - 86_400)}
    summary = read_fleet.fleet_summary(rows, now_s=NOW, expected_per_color=1, this_color="blue", master_started=started)
    mine = next(entry for entry in summary["colors"] if entry["is_this_color"])
    assert mine["master_pids"] == [100]
    assert mine["service_uptime_s"] == 86_400
    assert summary["workers"][0]["uptime_s"] == 60  # the worker's own age is still listed with the worker
    pids = read_fleet.color_master_pids(rows, "blue")
    assert read_fleet.service_since(pids, started, NOW) == (mine["service_started_at"], mine["service_uptime_s"])


def test_the_fleet_summary_keeps_its_shape_for_every_color() -> None:
    rows = [_row(11, 100), _row(12, 200, color="green"), _row(13, 200, color="green", fresh=False)]
    summary = read_fleet.fleet_summary(
        rows, now_s=NOW, expected_per_color=2, this_color="dev", master_started={100: NOW - 10.0, 200: None}
    )
    colors = {entry["color"]: entry for entry in summary["colors"]}
    assert list(colors) == ["dev", "blue", "green"]  # this color first, then by name
    assert list(colors["blue"]) == [
        "color",
        "expected",
        "count",
        "stale",
        "master_pids",
        "service_started_at",
        "service_uptime_s",
        "active",
        "short",
        "is_this_color",
    ]
    assert (colors["blue"]["count"], colors["blue"]["stale"], colors["blue"]["service_uptime_s"]) == (1, 0, 10)
    assert (colors["green"]["count"], colors["green"]["stale"], colors["green"]["master_pids"]) == (1, 1, [200])
    assert colors["green"]["service_uptime_s"] is None  # the master's start could not be read
    assert colors["dev"]["is_this_color"] is True  # this color is listed even with no worker reporting
    assert (colors["dev"]["master_pids"], colors["dev"]["service_uptime_s"], colors["dev"]["active"]) == (
        [],
        None,
        False,
    )


def test_master_start_times_read_proc(tmp_path: Path) -> None:
    hertz = os.sysconf("SC_CLK_TCK")
    (tmp_path / "stat").write_text("cpu 1 2 3\nbtime 1700000000\n", encoding="ascii")
    master = tmp_path / "4321"
    master.mkdir()
    # Field 22 (starttime, in clock ticks since boot) is the 20th field after the command name.
    fields = ["S"] + ["0"] * 18 + [str(500 * hertz)] + ["0"] * 10
    (master / "stat").write_text("4321 (gunicorn: master [roxy]) " + " ".join(fields) + "\n", encoding="ascii")
    found = read_fleet.master_start_times([4321, 9999, 0], proc=tmp_path)
    assert found == {4321: 1_700_000_500.0, 9999: None, 0: None}
