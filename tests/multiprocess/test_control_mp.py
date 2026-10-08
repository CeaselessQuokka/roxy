"""Multi-process correctness of the control plane (plan 5.7, 19.3, C6).

Real operating system processes (multiprocessing with `spawn`, like separate gunicorn workers) share one
temporary control.db and check:

1. `test_cross_process_rule_edit`: a UA rule edited by id in process A is served by process B within 2 s (B only
   polls `config_version`, as every worker does), and a third process C that still holds a stale snapshot edits the
   same rule by id without creating a duplicate row (the v1 bug plan 5.7 names).
2. A setting changed in one process is live in two other processes within 2 s (hot reload).
3. A rule cap (MAX_HEADER_RULES) holds exactly under concurrent creates from 1, 2 and 4 processes.
4. Bans created for one IP by several processes at the same moment leave one active ban (fix pass, MP review F5).
"""

from __future__ import annotations

import asyncio
import math
import multiprocessing as mp
import os
import queue
import signal
import sqlite3
import sys
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from roxy.config.audit import Actor
from roxy.config.constants import MAX_HEADER_RULES
from roxy.config.runtime import RuntimeSettings, build_snapshot, watch_config
from roxy.config.settings_service import SettingsService
from roxy.rules.service import RuleCapReached, RulesService
from roxy.rules.store import RulesStore
from roxy.storage.db import DB_NAMES, Database
from roxy.storage.migrate import migrate_paths

pytestmark = [
    pytest.mark.multiprocess,
    pytest.mark.skipif(sys.platform == "win32", reason="needs POSIX processes"),
]

CTX = mp.get_context("spawn")
SETTING = "allowed_requests_per_minute"
VISIBLE_WITHIN_S = 2.0  # plan 5.7: "within 2 s"


@pytest.fixture
def control_path(tmp_path: Path) -> Path:
    """Migrated databases in a temp dir; returns control.db's path."""
    paths = {name: tmp_path / f"{name}.db" for name in DB_NAMES}
    migrate_paths(paths)
    return paths["control"]


@pytest.fixture
def procs() -> Iterator[list[Any]]:
    """Processes started by a test; any still alive at the end are killed."""
    started: list[Any] = []
    yield started
    for proc in started:
        if proc.is_alive():
            if proc.pid:
                os.kill(proc.pid, signal.SIGKILL)
            proc.join(5)


def _start(procs: list[Any], target: Any, *args: Any) -> Any:
    proc = CTX.Process(target=target, args=args, daemon=True)
    proc.start()
    procs.append(proc)
    return proc


def _join_all(procs: list[Any], timeout: float) -> None:
    deadline = time.monotonic() + timeout
    for proc in procs:
        proc.join(max(0.1, deadline - time.monotonic()))
    assert not [p for p in procs if p.is_alive()], "processes did not finish"
    assert all(p.exitcode == 0 for p in procs), [p.exitcode for p in procs]


def _wait_event(events: Any, predicate: Callable[[tuple[Any, ...]], bool], timeout: float) -> tuple[Any, ...]:
    deadline = time.monotonic() + timeout
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise AssertionError("timed out waiting for an event from a child process")
        try:
            event = events.get(timeout=remaining)
        except queue.Empty:
            raise AssertionError("timed out waiting for an event from a child process") from None
        if predicate(event):
            return tuple(event)


def _query(path: Path, sql: str) -> list[tuple[Any, ...]]:
    conn = sqlite3.connect(str(path), timeout=10)
    try:
        return [tuple(row) for row in conn.execute(sql).fetchall()]
    finally:
        conn.close()


# ------------------------------------------------------------------------------------- 1. cross-process rule edit


def _child_rules(path: str, name: str, watch: bool, events: Any, commands: Any) -> None:
    asyncio.run(_rules_worker(path, name, watch, events, commands))


async def _rules_worker(path: str, name: str, watch: bool, events: Any, commands: Any) -> None:
    db = Database("control", path)
    store = RulesStore(db)
    await store.reload()
    service = RulesService(db, store=store)

    def report(snapshot: Any) -> None:
        rules = {rule.id: (rule.needle, rule.note) for rule in snapshot.ua_rules}
        events.put(("rules", name, snapshot.version, rules, time.time()))

    report(store.snapshot)
    store.subscribe(report)
    stop = asyncio.Event()
    # A worker polls config_version every second (the real interval); a "stale" worker never refreshes.
    watcher = asyncio.create_task(watch_config(stop, store)) if watch else None
    try:
        while True:
            try:
                command = commands.get_nowait()
            except queue.Empty:
                await asyncio.sleep(0.02)
                continue
            if command[0] == "stop":
                break
            _kind, rule_id, note = command
            change = await service.update("rules_user_agent", rule_id, {"note": note}, Actor("admin", name), "edit")
            events.put(("edited", name, change.changed, time.time()))
    finally:
        stop.set()
        if watcher is not None:
            await watcher
        await db.close()


async def _create_rule(path: str, needle: str) -> str:
    db = Database("control", path)
    try:
        change = await RulesService(db).create("rules_user_agent", {"needle": needle}, Actor("admin", "a"))
        return str(change.key)
    finally:
        await db.close()


async def _edit_needle(path: str, rule_id: str, needle: str) -> None:
    db = Database("control", path)
    try:
        change = await RulesService(db).update("rules_user_agent", rule_id, {"needle": needle}, Actor("admin", "a"))
        assert change.changed
    finally:
        await db.close()


def test_cross_process_rule_edit(control_path: Path, procs: list[Any]) -> None:
    path = str(control_path)
    rule_id = asyncio.run(_create_rule(path, "bot-one"))  # this test process is worker A
    events = CTX.Queue()
    commands_b, commands_c = CTX.Queue(), CTX.Queue()
    _start(procs, _child_rules, path, "B", True, events, commands_b)
    _start(procs, _child_rules, path, "C", False, events, commands_c)
    initial = {}
    while len(initial) < 2:
        event = _wait_event(events, lambda e: e[0] == "rules", 60)
        initial[event[1]] = event
    for event in initial.values():
        assert event[3] == {rule_id: ("bot-one", "")}

    started = time.time()
    asyncio.run(_edit_needle(path, rule_id, "bot-two"))
    seen = _wait_event(
        events, lambda e: e[0] == "rules" and e[1] == "B" and e[3].get(rule_id, ("",))[0] == "bot-two", 10
    )
    assert seen[4] - started < VISIBLE_WITHIN_S, f"worker B saw the edit after {seen[4] - started:.2f} s"

    # C still holds the snapshot from before the edit (it never refreshes). Its edit by id is an UPDATE by primary
    # key on the stored row, so A's needle survives and no duplicate appears.
    commands_c.put(("edit_note", rule_id, "edited by C"))
    edited = _wait_event(events, lambda e: e[0] == "edited" and e[1] == "C", 30)
    assert edited[2] is True
    commands_b.put(("stop",))
    commands_c.put(("stop",))
    _join_all(procs, 30)
    assert _query(control_path, "SELECT id, needle, note FROM rules_user_agent") == [
        (rule_id, "bot-two", "edited by C")
    ]


# ------------------------------------------------------------------------------------- 2. settings hot reload


def _child_settings(path: str, name: str, events: Any, stop_flag: Any) -> None:
    asyncio.run(_settings_worker(path, name, events, stop_flag))


async def _settings_worker(path: str, name: str, events: Any, stop_flag: Any) -> None:
    db = Database("control", path)
    snapshot = await db.read(lambda conn: build_snapshot(conn, time.time()))
    settings = RuntimeSettings(db, snapshot)
    events.put(("settings", name, settings.version, settings.int(SETTING), time.time()))
    settings.subscribe(lambda snap, changed: events.put(("settings", name, snap.version, snap[SETTING], time.time())))
    stop = asyncio.Event()
    watcher = asyncio.create_task(watch_config(stop, settings))  # the real 1 s poll
    try:
        # The parent's multiprocessing Event is waited on in a thread, so the event loop keeps polling meanwhile.
        await asyncio.to_thread(stop_flag.wait, 60)
    finally:
        stop.set()
        await watcher
        await db.close()


async def _change_setting(path: str, value: int) -> None:
    db = Database("control", path)
    try:
        result = await SettingsService(db).update({SETTING: value}, Actor("admin", "a"), "load test", "admin")
        assert result.changed_keys == (SETTING,)
    finally:
        await db.close()


def test_setting_hot_reload_across_two_processes(control_path: Path, procs: list[Any]) -> None:
    path = str(control_path)
    events = CTX.Queue()
    stop_flag = CTX.Event()
    for name in ("B1", "B2"):
        _start(procs, _child_settings, path, name, events, stop_flag)
    ready = set()
    while len(ready) < 2:
        event = _wait_event(events, lambda e: e[0] == "settings", 60)
        assert event[3] == 10
        ready.add(event[1])

    started = time.time()
    asyncio.run(_change_setting(path, 37))
    seen: dict[str, float] = {}
    while len(seen) < 2:
        event = _wait_event(events, lambda e: e[0] == "settings" and e[3] == 37, 10)
        seen[event[1]] = event[4] - started
    stop_flag.set()
    _join_all(procs, 30)
    for name, delay in seen.items():
        assert delay < VISIBLE_WITHIN_S, f"{name} saw the change after {delay:.2f} s"


# ------------------------------------------------------------------------------------- 3. caps across processes


def _child_create_headers(path: str, prefix: str, count: int, results: Any) -> None:
    asyncio.run(_create_headers(path, prefix, count, results))


async def _create_headers(path: str, prefix: str, count: int, results: Any) -> None:
    db = Database("control", path)
    service = RulesService(db)
    created = capped = 0
    try:
        for index in range(count):
            try:
                await service.create("rules_header", {"needle": f"{prefix}-{index}"}, Actor("admin", prefix))
            except RuleCapReached:
                capped += 1
            else:
                created += 1
    finally:
        results.put((created, capped))
        await db.close()


@pytest.mark.parametrize("workers", [1, 2, 4])
def test_rule_cap_holds_across_processes(control_path: Path, procs: list[Any], workers: int) -> None:
    attempts = MAX_HEADER_RULES + 30
    per_worker = math.ceil(attempts / workers)
    results = CTX.Queue()
    for index in range(workers):
        _start(procs, _child_create_headers, str(control_path), f"w{index}", per_worker, results)
    _join_all(procs, 120)
    totals = [results.get(timeout=5) for _ in range(workers)]
    assert sum(created for created, _capped in totals) == MAX_HEADER_RULES
    assert sum(capped for _created, capped in totals) == per_worker * workers - MAX_HEADER_RULES
    assert _query(control_path, "SELECT count(*) FROM rules_header") == [(MAX_HEADER_RULES,)]
    # Every successful create bumped config_version exactly once.
    version = _query(control_path, "SELECT value_json FROM service_state WHERE key = 'config_version'")
    assert int(version[0][0]) == MAX_HEADER_RULES


# ------------------------------------------------------------------------- 4. one active ban per subject (MP F5)


def _child_ban(path: str, name: str, expires_in: int, start_at: float, results: Any) -> None:
    asyncio.run(_ban(path, name, expires_in, start_at, results))


async def _ban(path: str, name: str, expires_in: int, start_at: float, results: Any) -> None:
    db = Database("control", path)
    service = RulesService(db)
    try:
        await asyncio.sleep(max(0.0, start_at - time.time()))  # every process bans at the same moment
        change = await service.create(
            "bans",
            {"subject_type": "ip", "subject": "203.0.113.7", "expires_at": int(time.time()) + expires_in},
            Actor("system", f"auto:{name}"),
        )
        results.put((name, change.action, change.key))
    finally:
        await db.close()


@pytest.mark.parametrize("workers", [2, 4])
def test_concurrent_bans_on_one_ip_leave_one_ban(control_path: Path, procs: list[Any], workers: int) -> None:
    """Several detectors (in several workers) banning one IP at once: one ban row, lasting as long as the longest."""
    results = CTX.Queue()
    start_at = time.time() + 2.0
    for index in range(workers):
        _start(procs, _child_ban, str(control_path), f"d{index}", 600 * (index + 1), start_at, results)
    _join_all(procs, 60)
    outcomes = [results.get(timeout=5) for _ in range(workers)]
    rows = _query(control_path, "SELECT id, expires_at FROM bans WHERE subject = '203.0.113.7'")
    assert len(rows) == 1
    assert {key for _name, _action, key in outcomes} == {rows[0][0]}
    assert sum(1 for _name, action, _key in outcomes if action == "create") == 1
    assert rows[0][1] >= int(start_at) + 600 * workers - 5  # the longest of the bans won
