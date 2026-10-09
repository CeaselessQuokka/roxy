"""Health run storage and read models: runs, results, history, comparisons, linked recommendations, job status.

What this is
    Synchronous functions over a metrics.db connection (call them inside `db.read` or `db.write`): writing a run,
    its results and the `events` rows that stream them to the dashboard; listing runs with filters and paging;
    reading one run; comparing two runs ("what changed since the last run"); finding the open recommendation
    linked to a failing check (the "Apply fix" button); and the leader's published job status (H-LEADER).

Why it exists
    Plan 13.1: runs are stored (`health_runs`, `health_results`), listed with filters, comparable, exportable, and
    stream to the browser as each check finishes. DESIGN 13: read models live next to their data, so the API
    module stays thin and the dashboard pages read the same functions.

How it works
    - A run row is written when the run starts (`finished_at` NULL means running) and finished with a JSON
      summary: counts per status, the critical count and the worst status. A run that never finished because its
      worker died is reported as `interrupted` once it is older than `RUN_STALE_S`.
    - Each result is written in the same metrics.db transaction as its `health_result` event row, so the SSE tail
      (`metrics.live.EventTail`) delivers it within about half a second to every worker's subscribers.
    - Every read is bounded: page sizes come from the admin API list, results per run are capped by the catalog
      size (`MAX_RESULTS_PER_RUN`), and comparisons work on two runs at most.
    - The leader publishes `JobRunner.status()` every 30 s into `health_job_status` (one row per job, the 0003
      migration), so H-LEADER can tell late jobs from any worker, not only from the leader itself.

What to read next
    `roxy/health/runner.py` (who writes), `roxy/admin/api/health.py` (who reads),
    `roxy/storage/migrations/metrics/0003_health_details.sql` (the columns beyond plan 6.2).
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

from roxy.health.facts import JobFact
from roxy.health.model import STATUS_ORDER, CheckResult, Status
from roxy.metrics.recorder import EventRecord, write_events

EVENT_RUN_STARTED: Final = "health_run_started"
EVENT_RESULT: Final = "health_result"
EVENT_RUN_FINISHED: Final = "health_run_finished"
EVENT_TYPES: Final = (EVENT_RUN_STARTED, EVENT_RESULT, EVENT_RUN_FINISHED)
"""The `events` types a health run writes; the SSE stream subscribes to these for the live checklist."""

RUN_STALE_S: Final = 900
"""A run still unfinished this long after it started was interrupted (its worker stopped); it is shown so."""

MAX_RESULTS_PER_RUN: Final = 500
"""Bound on the results read for one run (the catalog has about 70 checks with every allowed host)."""

MAX_TEXT: Final = 2000
"""Longest stored value, threshold or explanation text (plan P9)."""

MAX_DETAIL_JSON: Final = 8000
"""Longest stored detail document; a longer one is replaced by a short truncation note."""

MAX_EVENT_VALUE: Final = 200

SORTS: Final[dict[str, str]] = {
    "started_at": "r.started_at",
    "id": "r.id",
    "finished_at": "r.finished_at",
}
"""Sort keys the run list accepts (the values are fixed SQL, never input)."""

LINK_RULES_DEFAULT: Final = "SYS-HEALTH-FAIL"


@dataclass(frozen=True, slots=True)
class RunFilter:
    """Filters for the run list (all optional)."""

    trigger: str | None = None
    worst: str | None = None
    since: int | None = None
    until: int | None = None
    check_id: str | None = None
    check_status: str | None = None


# ------------------------------------------------------------------------------------------------- writing


def _text(value: object, limit: int = MAX_TEXT) -> str:
    text = str(value if value is not None else "")
    return text if len(text) <= limit else text[: limit - 3] + "..."


def detail_json(detail: Mapping[str, Any]) -> str | None:
    """The stored detail document (bounded, sorted keys), None when empty."""
    if not detail:
        return None
    text = json.dumps(dict(detail), sort_keys=True, separators=(",", ":"), default=str, ensure_ascii=False)
    if len(text) > MAX_DETAIL_JSON:
        return json.dumps({"truncated": True, "bytes": len(text)})
    return text


def summarize(results: Iterable[CheckResult | Mapping[str, Any]]) -> dict[str, Any]:
    """Counts per status, the critical count and the worst status of a run."""
    counts = {status.value: 0 for status in Status}
    critical = 0
    worst = Status.PASS
    total = 0
    for item in results:
        status = Status(item.status if isinstance(item, CheckResult) else str(item["status"]))
        is_critical = item.critical if isinstance(item, CheckResult) else bool(item.get("critical"))
        counts[status.value] += 1
        critical += 1 if is_critical else 0
        total += 1
        if STATUS_ORDER[status] > STATUS_ORDER[worst]:
            worst = status
    return {**counts, "critical": critical, "total": total, "worst": worst.value if total else None}


def insert_run(
    conn: sqlite3.Connection,
    *,
    started_at: int,
    trigger: str,
    version: str,
    options: Mapping[str, Any],
    actor: str,
    at_ms: int,
    planned: int = 0,
) -> int:
    """Insert a running run (and its `health_run_started` event) and return its id."""
    cursor = conn.execute(
        "INSERT INTO health_runs (started_at, finished_at, trigger, summary, version, options_json, actor) "
        "VALUES (?, NULL, ?, NULL, ?, ?, ?)",
        (int(started_at), trigger, _text(version, 64), json.dumps(dict(options), sort_keys=True), _text(actor, 64)),
    )
    run_id = int(cursor.lastrowid or 0)
    write_events(
        conn,
        [
            EventRecord(
                at_ms=at_ms,
                type=EVENT_RUN_STARTED,
                severity="info",
                reason_code=trigger,
                ip_hash=None,
                place=None,
                endpoint_template=None,
                detail={"run_id": run_id, "trigger": trigger, "checks": int(planned)},
            )
        ],
    )
    return run_id


def insert_result(conn: sqlite3.Connection, run_id: int, result: CheckResult, *, at_ms: int) -> None:
    """Store one result and its `health_result` event in the caller's transaction (a rerun replaces it)."""
    conn.execute(
        "INSERT INTO health_results (run_id, check_id, status, value, threshold, explanation, fix_link, duration_ms, "
        "critical, measured, unit, detail_json, finished_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT (run_id, check_id) DO UPDATE SET status = excluded.status, value = excluded.value, "
        "threshold = excluded.threshold, explanation = excluded.explanation, fix_link = excluded.fix_link, "
        "duration_ms = excluded.duration_ms, critical = excluded.critical, measured = excluded.measured, "
        "unit = excluded.unit, detail_json = excluded.detail_json, finished_ms = excluded.finished_ms",
        (
            int(run_id),
            _text(result.check_id, 120),
            result.status.value,
            _text(result.value),
            _text(result.threshold),
            _text(result.explanation, 4000),
            _text(result.fix_link, 300),
            round(float(result.duration_ms), 3),
            1 if result.critical else 0,
            result.measured,
            _text(result.unit, 32),
            detail_json(result.detail),
            int(at_ms),
        ),
    )
    severity = "info"
    if result.status is Status.WARN:
        severity = "warn"
    elif result.status is Status.FAIL:
        severity = "critical" if result.critical else "warn"
    write_events(
        conn,
        [
            EventRecord(
                at_ms=at_ms,
                type=EVENT_RESULT,
                severity=severity,
                reason_code=result.status.value,
                ip_hash=None,
                place=None,
                endpoint_template=None,
                detail={
                    "run_id": int(run_id),
                    "check_id": result.check_id,
                    "status": result.status.value,
                    "value": _text(result.value, MAX_EVENT_VALUE),
                    "critical": result.critical,
                    "duration_ms": round(float(result.duration_ms), 1),
                },
            )
        ],
    )


def finish_run(
    conn: sqlite3.Connection,
    run_id: int,
    *,
    finished_at: int,
    summary: Mapping[str, Any],
    at_ms: int,
    trigger: str = "",
) -> None:
    """Close a run with its summary (and the `health_run_finished` event)."""
    conn.execute(
        "UPDATE health_runs SET finished_at = ?, summary = ? WHERE id = ?",
        (int(finished_at), json.dumps(dict(summary), sort_keys=True), int(run_id)),
    )
    worst = str(summary.get("worst") or "pass")
    write_events(
        conn,
        [
            EventRecord(
                at_ms=at_ms,
                type=EVENT_RUN_FINISHED,
                severity="warn" if worst in ("warn", "fail") else "info",
                reason_code=worst,
                ip_hash=None,
                place=None,
                endpoint_template=None,
                # Count keys avoid the bare word "pass": event details are scrubbed as text, and the scrubber
                # treats `"pass": 6` as a password field (which would also break the JSON).
                detail={
                    "run_id": int(run_id),
                    "trigger": trigger,
                    "worst": worst,
                    "total": int(summary.get("total") or 0),
                    "passed": int(summary.get("pass") or 0),
                    "warned": int(summary.get("warn") or 0),
                    "failed": int(summary.get("fail") or 0),
                    "not_applicable": int(summary.get("n/a") or 0),
                    "critical": int(summary.get("critical") or 0),
                    "interrupted": bool(summary.get("interrupted")),
                },
            )
        ],
    )


# ------------------------------------------------------------------------------------------------- reading


def _loads(text: Any) -> Any:
    if not isinstance(text, str) or not text:
        return None
    try:
        return json.loads(text)
    except ValueError:
        return None


def run_state(row: Mapping[str, Any], now: float) -> str:
    """`running`, `finished` or `interrupted` (a run whose worker stopped before it finished)."""
    if row["finished_at"] is not None:
        summary = _loads(row["summary"]) or {}
        return "interrupted" if summary.get("interrupted") else "finished"
    if now - int(row["started_at"]) > RUN_STALE_S:
        return "interrupted"
    return "running"


def run_dict(row: Mapping[str, Any], now: float) -> dict[str, Any]:
    """The API shape of one `health_runs` row (without its results)."""
    summary = _loads(row["summary"]) or {}
    options = _loads(row["options_json"]) or {}
    started = int(row["started_at"])
    finished = None if row["finished_at"] is None else int(row["finished_at"])
    return {
        "id": int(row["id"]),
        "started_at": started,
        "finished_at": finished,
        "duration_s": None if finished is None else max(0, finished - started),
        "trigger": str(row["trigger"]),
        "state": run_state(row, now),
        "version": row["version"],
        "actor": row["actor"],
        "options": options,
        "summary": summary,
    }


def result_dict(row: Mapping[str, Any]) -> dict[str, Any]:
    """The API shape of one `health_results` row."""
    return {
        "check_id": str(row["check_id"]),
        "status": str(row["status"]),
        "value": row["value"] or "",
        "threshold": row["threshold"] or "",
        "explanation": row["explanation"] or "",
        "fix_link": row["fix_link"] or "",
        "critical": bool(row["critical"]),
        "measured": row["measured"],
        "unit": row["unit"] or "",
        "detail": _loads(row["detail_json"]) or {},
        "duration_ms": row["duration_ms"],
        "finished_ms": row["finished_ms"],
    }


_RUN_COLUMNS: Final = "r.id, r.started_at, r.finished_at, r.trigger, r.summary, r.version, r.options_json, r.actor"


def _where(filters: RunFilter) -> tuple[str, list[Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    if filters.trigger:
        clauses.append("r.trigger = ?")
        params.append(filters.trigger)
    if filters.worst:
        clauses.append("json_extract(r.summary, '$.worst') = ?")
        params.append(filters.worst)
    if filters.since is not None:
        clauses.append("r.started_at >= ?")
        params.append(int(filters.since))
    if filters.until is not None:
        clauses.append("r.started_at < ?")
        params.append(int(filters.until))
    if filters.check_id:
        if filters.check_status:
            clauses.append(
                "EXISTS (SELECT 1 FROM health_results h WHERE h.run_id = r.id AND h.check_id = ? AND h.status = ?)"
            )
            params += [filters.check_id, filters.check_status]
        else:
            clauses.append("EXISTS (SELECT 1 FROM health_results h WHERE h.run_id = r.id AND h.check_id = ?)")
            params.append(filters.check_id)
    elif filters.check_status:
        clauses.append("EXISTS (SELECT 1 FROM health_results h WHERE h.run_id = r.id AND h.status = ?)")
        params.append(filters.check_status)
    return (" WHERE " + " AND ".join(clauses)) if clauses else "", params


def list_runs(
    conn: sqlite3.Connection,
    filters: RunFilter,
    *,
    page: int,
    page_size: int,
    sort: str = "started_at",
    descending: bool = True,
    now: float,
) -> tuple[list[dict[str, Any]], int]:
    """One page of runs matching `filters`, newest first by default, and the total count."""
    order = SORTS.get(sort)
    if order is None:
        raise ValueError(f"cannot sort runs by {sort!r}")
    where, params = _where(filters)
    total = int(conn.execute(f"SELECT count(*) FROM health_runs r{where}", params).fetchone()[0])  # noqa: S608 (fixed clauses)
    direction = "DESC" if descending else "ASC"
    rows = conn.execute(
        f"SELECT {_RUN_COLUMNS} FROM health_runs r{where} ORDER BY {order} {direction}, r.id {direction} "  # noqa: S608 (SORTS whitelist)
        "LIMIT ? OFFSET ?",
        (*params, int(page_size), (max(1, int(page)) - 1) * int(page_size)),
    ).fetchall()
    return [run_dict(row, now) for row in rows], total


def get_run(conn: sqlite3.Connection, run_id: int, *, now: float) -> dict[str, Any] | None:
    """One run with every result (in the order they finished), or None."""
    row = conn.execute(f"SELECT {_RUN_COLUMNS} FROM health_runs r WHERE r.id = ?", (int(run_id),)).fetchone()  # noqa: S608 (fixed)
    if row is None:
        return None
    out = run_dict(row, now)
    out["results"] = run_results(conn, run_id)
    return out


def run_results(conn: sqlite3.Connection, run_id: int) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT check_id, status, value, threshold, explanation, fix_link, duration_ms, critical, measured, unit, "
        "detail_json, finished_ms FROM health_results WHERE run_id = ? ORDER BY coalesce(finished_ms, 0), check_id "
        "LIMIT ?",
        (int(run_id), MAX_RESULTS_PER_RUN),
    ).fetchall()
    return [result_dict(row) for row in rows]


def previous_run_id(conn: sqlite3.Connection, run_id: int, *, trigger: str | None = None) -> int | None:
    """The newest finished run started before `run_id` (optionally with the same trigger), or None."""
    sql = "SELECT id FROM health_runs WHERE id < ? AND finished_at IS NOT NULL"
    params: list[Any] = [int(run_id)]
    if trigger:
        sql += " AND trigger = ?"
        params.append(trigger)
    row = conn.execute(sql + " ORDER BY id DESC LIMIT 1", params).fetchone()
    return None if row is None else int(row[0])


def latest_run_id(conn: sqlite3.Connection, *, trigger: str | None = None, finished: bool = True) -> int | None:
    sql = "SELECT id FROM health_runs"
    clauses = []
    params: list[Any] = []
    if finished:
        clauses.append("finished_at IS NOT NULL")
    if trigger:
        clauses.append("trigger = ?")
        params.append(trigger)
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    row = conn.execute(sql + " ORDER BY id DESC LIMIT 1", params).fetchone()
    return None if row is None else int(row[0])


def last_started_at(conn: sqlite3.Connection, trigger: str) -> int | None:
    row = conn.execute("SELECT max(started_at) FROM health_runs WHERE trigger = ?", (trigger,)).fetchone()
    return None if row is None or row[0] is None else int(row[0])


# ------------------------------------------------------------------------------------------------- comparing


def compare_results(previous: Sequence[Mapping[str, Any]], current: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """What changed between two runs, check by check (13.1 "what changed since the last run")."""
    before = {str(r["check_id"]): r for r in previous}
    after = {str(r["check_id"]): r for r in current}
    changes: list[dict[str, Any]] = []
    new_failures: list[str] = []
    fixed: list[str] = []
    for check_id in sorted(set(before) | set(after)):
        a, b = before.get(check_id), after.get(check_id)
        old = str(a["status"]) if a is not None else None
        new = str(b["status"]) if b is not None else None
        if old is None:
            change = "new"
        elif new is None:
            change = "missing"
        elif old == new:
            change = "same" if (a or {}).get("value") == (b or {}).get("value") else "value_changed"
        elif STATUS_ORDER.get(new, 0) > STATUS_ORDER.get(old, 0):
            change = "worse"
        else:
            change = "better"
        if new == Status.FAIL and old != Status.FAIL:
            new_failures.append(check_id)
        if old in (Status.FAIL, Status.WARN) and new == Status.PASS:
            fixed.append(check_id)
        changes.append(
            {
                "check_id": check_id,
                "change": change,
                "before": None if a is None else {"status": old, "value": a.get("value", "")},
                "after": None if b is None else {"status": new, "value": b.get("value", "")},
            }
        )
    counts: dict[str, int] = {}
    for item in changes:
        counts[item["change"]] = counts.get(item["change"], 0) + 1
    return {"new_failures": new_failures, "fixed": fixed, "counts": counts, "changes": changes}


def compare_runs(conn: sqlite3.Connection, run_id: int, other_id: int | None, *, now: float) -> dict[str, Any] | None:
    """Compare run `run_id` with `other_id` (default: the run before it). None when `run_id` does not exist."""
    current = get_run(conn, run_id, now=now)
    if current is None:
        return None
    base_id = other_id if other_id is not None else previous_run_id(conn, run_id)
    base = get_run(conn, base_id, now=now) if base_id is not None else None
    diff = compare_results(base["results"] if base else [], current["results"])
    return {
        "run": {k: v for k, v in current.items() if k != "results"},
        "previous": None if base is None else {k: v for k, v in base.items() if k != "results"},
        **diff,
    }


def failures_fingerprint(check_ids: Iterable[str]) -> str:
    """A stable short id of a set of failing checks (the alert's cooldown key, plan 17.7 `health:<fingerprint>`)."""
    text = "\n".join(sorted(set(check_ids)))
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


# ------------------------------------------------------------------------------------------------- recommendations


def linked_recommendations(
    conn: sqlite3.Connection, check_ids: Iterable[str], rules_by_check: Mapping[str, Sequence[str]]
) -> dict[str, dict[str, Any]]:
    """For each check id, the newest open recommendation that fixes it (the 13.1 "Apply fix" button).

    A recommendation is linked when its rule is one of the check's related rules (`rules_by_check`, keyed by the
    13.2 base id or the full id), or when it is a SYS-HEALTH-FAIL recommendation whose payload names the check.
    """
    wanted = [str(c) for c in check_ids]
    if not wanted:
        return {}
    rules = {LINK_RULES_DEFAULT}
    for check_id in wanted:
        rules.update(rules_by_check.get(check_id, ()))
        rules.update(rules_by_check.get(_base_id(check_id), ()))
    marks = ", ".join("?" for _ in rules)
    try:
        rows = conn.execute(
            f"SELECT id, rule_id, severity, payload_json, updated_at FROM recommendations "  # noqa: S608 (placeholders)
            f"WHERE state = 'open' AND rule_id IN ({marks}) ORDER BY updated_at DESC LIMIT 500",
            sorted(rules),
        ).fetchall()
    except sqlite3.OperationalError:
        return {}
    found: dict[str, dict[str, Any]] = {}
    for check_id in wanted:
        related = set(rules_by_check.get(check_id, ())) | set(rules_by_check.get(_base_id(check_id), ()))
        for row in rows:
            payload = _loads(row["payload_json"]) or {}
            rule_id = str(row["rule_id"])
            if rule_id == LINK_RULES_DEFAULT:
                text = " ".join(str(payload.get(k, "")) for k in ("subject", "title", "fingerprint"))
                if check_id not in text:
                    continue
            elif rule_id not in related:
                continue
            found[check_id] = {
                "id": str(row["id"]),
                "rule_id": rule_id,
                "severity": str(row["severity"]),
                "title": _text(payload.get("title", ""), 300),
                "link": f"/admin/recommendations/{row['id']}",
            }
            break
    return found


def _base_id(check_id: str) -> str:
    """`H-REACH-games.roblox.com` -> `H-REACH-<host>` (the 13.2 id a per-host result belongs to)."""
    if check_id.startswith("H-REACH-"):
        return "H-REACH-<host>"
    return check_id


# ------------------------------------------------------------------------------------------------- job status


def write_job_status(conn: sqlite3.Connection, rows: Iterable[Mapping[str, Any]], *, now: int, holder: str) -> int:
    """Publish the leader's `JobRunner.status()` (one row per job) and drop rows a day old. Returns rows written."""
    written = 0
    for row in rows:
        conn.execute(
            "INSERT INTO health_job_status (name, interval_s, last_started_at, last_finished_at, last_ok, holder, "
            "published_at) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT (name) DO UPDATE SET "
            "interval_s = excluded.interval_s, last_started_at = excluded.last_started_at, "
            "last_finished_at = excluded.last_finished_at, last_ok = excluded.last_ok, holder = excluded.holder, "
            "published_at = excluded.published_at",
            (
                _text(row.get("name", ""), 64),
                float(row.get("interval_s") or 0.0),
                row.get("last_started_at"),
                row.get("last_finished_at"),
                None if row.get("last_ok") is None else (1 if row.get("last_ok") else 0),
                _text(holder, 120),
                int(now),
            ),
        )
        written += 1
    conn.execute("DELETE FROM health_job_status WHERE published_at < ?", (int(now) - 86_400,))
    return written


def read_job_status(conn: sqlite3.Connection, since: float) -> list[JobFact]:
    """Job status the leader published at or after `since` (bounded to 100 jobs)."""
    rows = conn.execute(
        "SELECT name, interval_s, last_started_at, last_finished_at, last_ok FROM health_job_status "
        "WHERE published_at >= ? ORDER BY name LIMIT 100",
        (int(since),),
    ).fetchall()
    return [
        JobFact(
            name=str(r["name"]),
            interval_s=float(r["interval_s"] or 0.0),
            last_started_at=None if r["last_started_at"] is None else float(r["last_started_at"]),
            last_finished_at=None if r["last_finished_at"] is None else float(r["last_finished_at"]),
            last_ok=None if r["last_ok"] is None else bool(r["last_ok"]),
        )
        for r in rows
    ]


__all__ = [
    "EVENT_RESULT",
    "EVENT_RUN_FINISHED",
    "EVENT_RUN_STARTED",
    "EVENT_TYPES",
    "RUN_STALE_S",
    "SORTS",
    "RunFilter",
    "compare_results",
    "compare_runs",
    "failures_fingerprint",
    "finish_run",
    "get_run",
    "insert_result",
    "insert_run",
    "last_started_at",
    "latest_run_id",
    "linked_recommendations",
    "list_runs",
    "previous_run_id",
    "read_job_status",
    "run_dict",
    "run_results",
    "run_state",
    "summarize",
    "write_job_status",
]
