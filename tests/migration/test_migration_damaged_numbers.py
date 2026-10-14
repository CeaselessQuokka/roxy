"""Damaged v1 numbers, the empty optional credential and the database owner (final review, lead decisions 2 to 4).

What this is
    Tests of the migrator against what a real v1 data file and a real cutover can hold: NaN and infinity anywhere in
    roxy_state.json and roxy_data.json, times far in the future or too large for SQLite, the empty `rotator_url`
    install-system.sh creates, a v1 capture limit of 0, and the database files a root-run migrator leaves.

Why it exists
    v1's cross-worker merge once grew the cache timestamps until they became infinity and then NaN (the blank
    dashboard fixed on 2026-10-09), and Python's `json.load` accepts both. Lead decision (4): the migrator rejects
    a time more than one day ahead like a negative one and tolerates NaN and infinity anywhere (finding ops-5).
    Decision (3): an existing empty optional credential file counts as absent (ops-4). Decision (2): every database
    file gets the state directory's owner and group, mode 0640 (ops-3). ops-10: a v1 capture limit of 0 meant "no
    limit". The strict reproductions of those findings live in tests/review_final/test_ops.py; these cover the
    rest of each decision.

How it works
    The fake v1 trees of tests/fixtures/v1_trees (written with `json.dumps`, which writes NaN and Infinity as v1's
    did) and the in-process migrator runner (`migrate`), then plain reads of the databases, the credential files
    and the JSON report (parsed strictly: a bare NaN fails the test).

What to read next
    `src/roxy/migration/times.py`, `runner.py` (`give_databases_to_state_owner`), `secrets_out.py` (`_place`),
    `v1_settings.py` (`zero_is_unlimited`).
"""

from __future__ import annotations

import json
import math
import os
import sqlite3
import stat
from pathlib import Path
from typing import Any

import pytest
from v1_migration_helpers import load_report

from roxy.migration.report import write_report
from roxy.migration.runner import give_databases_to_state_owner
from roxy.migration.times import (
    FUTURE_SLACK_S,
    MAX_COUNT,
    MAX_EXPIRY_S,
    bounded_count,
    finite_json,
    plausible_epoch,
    plausible_expiry,
)

NOW = 1_790_000_000


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (NOW - 10, NOW - 10),
        (float(NOW), NOW),
        (str(NOW), NOW),
        (NOW + FUTURE_SLACK_S, NOW + FUTURE_SLACK_S),
        (NOW + FUTURE_SLACK_S + 1, None),  # more than a day ahead: damage (lead decision 4)
        (0, None),
        (-5.0, None),
        (math.nan, None),
        (math.inf, None),
        (-math.inf, None),
        (1e300, None),  # on its way to infinity
        (10**400, None),  # too large even for a float
        (True, None),
        (None, None),
        ("soon", None),
        ([NOW], None),
    ],
)
def test_plausible_epoch(value: Any, expected: int | None) -> None:
    assert plausible_epoch(value, now=NOW) == expected


def test_plausible_expiry_allows_the_future_but_not_the_impossible() -> None:
    assert plausible_expiry(NOW + 10 * 365 * 86400) == NOW + 10 * 365 * 86400
    assert plausible_expiry(MAX_EXPIRY_S) == MAX_EXPIRY_S
    for bad in (MAX_EXPIRY_S + 1, 1e300, math.nan, math.inf, 0, -1, True, "x"):
        assert plausible_expiry(bad) is None, bad


def test_bounded_count_and_finite_json() -> None:
    assert [bounded_count(v) for v in (5, -3, 2.9, math.nan, math.inf, 10**30, 1e300, "7", True)] == [
        5,
        0,
        2,
        0,
        0,
        MAX_COUNT,
        MAX_COUNT,
        0,
        1,
    ]
    assert finite_json({"a": [1.5, math.nan, {"b": math.inf}], "c": (-math.inf, "NaN")}) == {
        "a": [1.5, None, {"b": None}],
        "c": [None, "NaN"],
    }


def _strict_json(text: str) -> Any:
    def refuse(name: str) -> Any:
        raise AssertionError(f"the report holds a bare {name}, which no JSON reader accepts")

    return json.loads(text, parse_constant=refuse)


async def test_nan_and_infinity_anywhere_never_stop_the_import(v1: Any, ws: Any, migrate: Any) -> None:
    """Lead decision (4): NaN and infinity in either v1 file are read as missing (a time) or 0 (a count), the
    import finishes without an error, and the JSON report stays valid JSON."""
    builder = v1.small_tree(ws.v1)
    runtime, diag = builder.runtime, builder.diagnostics
    runtime["SessionEpoch"] = math.nan
    runtime["Paused"] = True  # v1 paused at copy time: v2 starts paused (parity), with no usable "since"
    runtime["PausedSince"] = math.inf
    v1.set_setting(runtime, "cache_ttl_seconds", math.nan)  # v1 skipped an unreadable value; so does the import
    runtime["SettingsUpdated"]["cache_stale_seconds"] = -math.inf
    first_block = next(iter(runtime["EndpointBlocks"]))
    runtime["EndpointBlocks"][first_block]["Added"] = -math.inf
    diag["ClearEpochs"] = {"request_counts": math.nan, "status_sources": math.inf}
    diag["header_names"]["user-agent"]["LastSeen"] = math.inf
    diag["header_names"]["user-agent"]["Count"] = math.nan
    diag["user_agents"]["Roblox/WinInet"]["FirstSeen"] = math.nan
    diag["errors"]["ValueError: bad thing"]["Count"] = math.inf
    builder.write()
    assert "NaN" in (ws.v1 / "roxy_data.json").read_text(), "the fixture writes NaN the way v1's json did"

    report = await migrate()
    assert report.errors == [], report.errors
    assert report.status == "imported"
    json_path, _ = write_report(report, ws.report)
    document = _strict_json(json_path.read_text(encoding="utf-8"))
    session = next(item for item in document["not_migrated"] if "session epoch" in item["what"])
    assert session["count"] is None

    metrics = sqlite3.connect(f"file:{ws.state / 'metrics.db'}?mode=ro", uri=True)
    control = sqlite3.connect(f"file:{ws.state / 'control.db'}?mode=ro", uri=True)
    try:
        since = {
            key: json.loads(value)["since"]
            for key, value in metrics.execute("SELECT key, value_json FROM legacy_totals")
            if key in ("v1.requests_total", "v1.roblox_429_total")
        }
        user_agent = metrics.execute(
            "SELECT count, last_seen FROM fingerprint_headers WHERE name = 'user-agent'"
        ).fetchone()
        blocks = control.execute("SELECT count(*) FROM rules_endpoint_block").fetchone()[0]
        (pause_json,) = control.execute("SELECT value_json FROM service_state WHERE key = 'pause'").fetchone()
    finally:
        metrics.close()
        control.close()
    assert since, "the v1 baseline rows were imported"
    assert all(value is None for value in since.values()), since
    assert user_agent is not None
    assert user_agent[0] == 0
    assert 0 < user_agent[1] <= NOW + 10 * 365 * 86400
    assert blocks == 2
    pause = json.loads(pause_json)
    assert pause.get("paused") is True, pause
    assert all(not isinstance(v, float) or math.isfinite(v) for v in pause.values()), pause
    settings = {item["v1_key"]: item for item in document["settings"]}
    assert settings["cache_ttl_seconds"]["plan"] == "skip_unreadable"


async def test_an_optional_credential_the_owner_emptied_after_the_import_stays_empty(
    v1: Any, ws: Any, migrate: Any
) -> None:
    """Lead decision (3) treats an EMPTY optional file as "not configured" only before the import placed it: once
    an earlier run wrote `rotator_url`, an empty file is the owner switching the rotator off, and a rerun keeps it."""
    builder = v1.small_tree(ws.v1)
    builder.write()
    first = await migrate()
    assert next(item for item in first.credentials if item["name"] == "rotator_url")["status"] == "written"
    rotator = ws.credentials / "rotator_url"
    rotator.write_text("", encoding="utf-8")
    again = await migrate()
    item = next(entry for entry in again.credentials if entry["name"] == "rotator_url")
    assert item["status"] != "written", item
    assert rotator.read_text(encoding="utf-8") == ""


async def test_the_empty_rotator_url_is_replaced_with_mode_600_and_said_so(v1: Any, ws: Any, migrate: Any) -> None:
    builder = v1.small_tree(ws.v1)
    builder.write()
    ws.credentials.mkdir(mode=0o700)
    (ws.credentials / "rotator_url").touch(mode=0o600)
    (ws.credentials / "alert_webhook_url").touch(mode=0o600)  # optional, and not something the migrator writes
    report = await migrate()
    item = next(entry for entry in report.credentials if entry["name"] == "rotator_url")
    assert item["status"] == "written"
    assert "replaced the empty file" in item["detail"]
    assert stat.S_IMODE((ws.credentials / "rotator_url").stat().st_mode) == 0o600
    assert (ws.credentials / "alert_webhook_url").read_text(encoding="utf-8") == ""
    assert not [p.name for p in ws.credentials.iterdir() if p.name.endswith(".tmp")]


async def test_v1_zero_capture_limits_map_to_the_v2_maximum_with_a_warning(v1: Any, ws: Any, migrate: Any) -> None:
    """Finding ops-10: v1 read 0 as "no limit"; the closest v2 value is the maximum (the catalog notes say so).
    A day of captured payloads is high risk in the catalog, so the report says so as a warning."""
    builder = v1.small_tree(ws.v1)
    v1.set_setting(builder.runtime, "capture_max_body", 0)
    v1.set_setting(builder.runtime, "capture_ttl_seconds", 0)
    builder.write()
    report = await migrate()
    assert any("HIGH RISK: capture_ttl_seconds" in warning for warning in report.warnings), report.warnings
    assert not any("capture_max_body" in warning for warning in report.warnings)
    settings = {item["v1_key"]: item for item in report.settings}
    for key, maximum in (("capture_max_body", 512 * 1024), ("capture_ttl_seconds", 86400)):
        assert settings[key]["value"] == maximum
        assert any("0 meant no limit" in note for note in settings[key]["notes"]), settings[key]


async def test_a_dry_run_leaves_the_real_databases_alone(v1: Any, ws: Any, migrate: Any) -> None:
    v1.small_tree(ws.v1).write()
    await migrate()
    for path in ws.state.glob("*.db*"):
        path.chmod(0o600)
    await migrate(dry_run=True)
    assert {stat.S_IMODE(p.stat().st_mode) for p in ws.state.glob("*.db*")} == {0o600}
    await migrate()
    assert {stat.S_IMODE(p.stat().st_mode) for p in ws.state.glob("*.db*")} == {0o640}


def test_the_database_hand_over_never_follows_a_link(tmp_path: Path) -> None:
    """The state directory belongs to the service user, who could plant a link where the root-run migrator is
    about to chown and chmod: the hand-over works through O_NOFOLLOW descriptors and names what it skipped."""
    state = tmp_path / "state"
    state.mkdir(mode=0o750)
    (state / "control.db").write_bytes(b"")
    (state / "control.db").chmod(0o644)
    victim = tmp_path / "victim"
    victim.write_text("root's file\n", encoding="utf-8")
    victim.chmod(0o600)
    (state / "hot.db-shm").symlink_to(victim)
    os.mkfifo(state / "metrics.db-wal")
    problems = give_databases_to_state_owner(state)
    assert stat.S_IMODE((state / "control.db").stat().st_mode) == 0o640
    assert stat.S_IMODE(victim.stat().st_mode) == 0o600, "the link was followed"
    assert any(problem.startswith("hot.db-shm") for problem in problems), problems
    assert any(problem.startswith("metrics.db-wal") for problem in problems), problems


def test_load_report_helper_still_reads_the_strict_report(tmp_path: Path) -> None:
    """The shared helper and the strict parse agree on a clean report (guards the helper this suite relies on)."""
    from roxy.migration.report import MigrationReport

    report = MigrationReport(dry_run=True, started_at=0, v1_root="x", state_dir="y", credentials_out=None)
    report.statistics["odd"] = math.nan
    json_path, _ = write_report(report, tmp_path / "migration")
    assert _strict_json(json_path.read_text(encoding="utf-8"))["statistics"]["odd"] is None
    assert load_report(tmp_path / "migration")["statistics"]["odd"] is None
