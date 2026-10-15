"""The Protection attempts tabs' read (`read_protection.refusal_attempts`): one reason's index entries, one grouping
per page (perf fix of 2026-10-14, plan 6.7).

What this is
    Unit tests over a migrated temp metrics.db (`dbs`): the read's answers against the two statements it replaced
    (copied here as they were) over several windows, sorts, searches and pages, one past the last group included,
    with the reason's message sources listed and past their bound; and the statements it runs, read as SQLite ran
    them: one grouping for a page with rows, through `events_refusal_sources` by reason, source and time
    (`EXPLAIN QUERY PLAN`), never the type and time index.

Why it exists
    Over 90 days at plan 6.6's volume the old read walked every refusal of the window (1.09 million rows) to keep one
    reason's, and did it twice (the count, then the page): 0.55 s for Request filters, 0.48 s for Endpoint blocks and
    0.37 s for Endpoint rules with no event at all, against plan 6.7's 500 ms. The numbers must not move (P6).

How it works
    Events are inserted as the recorder writes them (its column list; JSON details with the path, the method, the
    refusing rule and what a request filter matched), with folded rows (a count, no client, no path), a reason
    written both as a refusal and as a failure, and other reasons, over three days.

What to read next
    `roxy/metrics/read_protection.py` (`refusal_attempts`, `ATTEMPTS_SOURCE`), `roxy/admin/api/protection.py`
    (`attempts_answer`), tests/unit/metrics/test_metrics_event_facts.py (the other reads on the same indexes).
"""

from __future__ import annotations

import json
import random
import sqlite3
from typing import Any

import pytest

from roxy.metrics import read_protection as rp

END = 1_760_000_400  # a whole hour (UTC)
DAY_MS = 86_400_000
TABLES = {
    "header_rule": "rules_header",
    "endpoint_blocked": "rules_endpoint_block",
    "endpoint_rule": "rules_endpoint_limit",
}
PATHS = (
    "games.roblox.com/v1/games/1",
    "games.roblox.com/v1/games/2",
    "users.roblox.com/v1/users/7",
    "Users.Roblox.com/v1/users/7",  # the same path in another letter case: its own row, as before
    "catalog.roblox.com/v1/search",
)
TEMPLATES = ("games.roblox.com/v1/games/{id}", "users.roblox.com/v1/users/{id}")


def _events(seed: int = 7) -> list[tuple[Any, ...]]:
    rng = random.Random(seed)
    rows = []
    start = (END - 3 * 86_400) * 1000
    hashes = [f"{n:016x}" for n in range(30)]
    for _ in range(4000):
        at = start + rng.randrange(3 * DAY_MS)
        reason = rng.choice(("header_rule", "endpoint_blocked", "endpoint_rule", "throttle", "deadline"))
        kind = rng.choice(("refusal", "failure")) if reason == "deadline" else "refusal"
        detail: dict[str, Any] = {
            "status": 403,
            "method": rng.choice(("GET", "POST")),
            "message_source": rng.choice(("default", "custom")),
        }
        if rng.random() < 0.9:
            detail["path"] = rng.choice(PATHS)
        table = TABLES.get(reason)
        if table and rng.random() < 0.7:
            detail["rules"] = {table: str(rng.randint(1, 4))}
        if reason == "header_rule" and rng.random() < 0.6:
            detail["matched"] = {
                "header": rng.choice(("User-Agent", "X-Tool")),
                "field": rng.choice(("key", "value")),
                "text": rng.choice(("xeno", "wininet", None)),
            }
        ip: str | None = rng.choice(hashes)
        if rng.random() < 0.1:  # folded over the recorder's event budget: a count, no client, no path
            detail = {"status": 403, "message_source": detail["message_source"], "aggregated": True,
                      "count": rng.randint(2, 9)}  # fmt: skip
            ip = None
            at = at // 60_000 * 60_000
        rows.append((at, kind, "warn", reason, ip, None, rng.choice(TEMPLATES), json.dumps(detail, sort_keys=True)))
    return rows


@pytest.fixture
def events_db(dbs: Any) -> Any:
    rows = _events()

    def write(conn: sqlite3.Connection) -> None:
        conn.executemany(  # the recorder's column list (`metrics/recorder.py write_events`)
            "INSERT INTO events (at_ms, type, severity, reason_code, ip_hash, place, endpoint_template, detail_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            rows,
        )

    dbs.metrics.write_sync(write)
    return dbs


def _old_attempts(
    conn: sqlite3.Connection,
    reason: str,
    start_ms: int,
    end_ms: int,
    *,
    search: str,
    sort: str,
    descending: bool,
    limit: int,
    offset: int,
    rule_table: str | None,
) -> dict[str, Any]:
    """`refusal_attempts` as it was before 2026-10-14 (a count statement, then the page), copied, not imported."""
    order = rp.ATTEMPT_SORTS[sort]
    where = "type = ? AND reason_code = ? AND at_ms >= ? AND at_ms < ?"
    params: list[Any] = ["refusal", reason, int(start_ms), int(end_ms)]
    path_expr = "coalesce(json_extract(detail_json, '$.path'), endpoint_template, '')"
    having = " HAVING instr(lower(path), ?) > 0" if search else ""
    rule_ids = "group_concat(DISTINCT json_extract(detail_json, ?))" if rule_table is not None else "NULL"
    matched = (
        "max(printf('%015d%015d', at_ms, id) || json_extract(detail_json, '$.matched'))"
        if rule_table == "rules_header"
        else "NULL"
    )
    grouped = (
        f"SELECT {path_expr} AS path, max(endpoint_template) AS template, "
        "sum(coalesce(json_extract(detail_json, '$.count'), 1)) AS attempts, count(DISTINCT ip_hash) AS clients, "
        "sum(CASE WHEN ip_hash IS NULL THEN coalesce(json_extract(detail_json, '$.count'), 1) ELSE 0 END) "
        "AS unattributed, group_concat(DISTINCT json_extract(detail_json, '$.method')) AS methods, "
        f"{rule_ids} AS rule_ids, {matched} AS last_matched, max(at_ms) AS last_ms FROM events WHERE {where} "
        f"GROUP BY path{having}"
    )
    select_params: list[Any] = [f"$.rules.{rule_table}"] if rule_table is not None else []
    group_params = [*select_params, *params, search.lower()] if search else [*select_params, *params]
    total = int(conn.execute(f"SELECT count(*) FROM ({grouped})", group_params).fetchone()[0])
    direction = "DESC" if descending else "ASC"
    rows = conn.execute(
        f"SELECT * FROM ({grouped}) ORDER BY {order} {direction}, path LIMIT ? OFFSET ?",
        (*group_params, max(1, min(int(limit), 250)), max(0, int(offset))),
    ).fetchall()
    items = []
    for row in rows:
        item: dict[str, Any] = {
            "path": row["path"],
            "template": row["template"],
            "attempts": int(row["attempts"] or 0),
            "clients": int(row["clients"] or 0),
            "unattributed": int(row["unattributed"] or 0),
            "methods": sorted(str(m) for m in str(row["methods"] or "").split(",") if m),
            "rule_ids": sorted({str(i) for i in str(row["rule_ids"] or "").split(",") if i})[:8],
            "last_ms": int(row["last_ms"]) if row["last_ms"] is not None else None,
        }
        if rule_table == "rules_header":
            found = json.loads(str(row["last_matched"] or "")[30:] or "{}")
            for key, name in (("last_header", "header"), ("last_field", "field"), ("last_text", "text")):
                value = found.get(name)
                item[key] = str(value) if value else None
        items.append(item)
    return {"total": total, "rows": items}


WINDOWS_MS = {
    "1h": ((END - 3_600) * 1000, END * 1000),
    "24h": ((END - 86_400) * 1000, END * 1000),
    "3d": ((END - 3 * 86_400) * 1000, END * 1000 + 60_000),
    "90d": ((END - 90 * 86_400) * 1000, END * 1000 + 60_000),
}
PAGES = (("", 25, 0), ("", 2, 3), ("", 25, 10_000), ("users", 25, 0), ("games.roblox", 1, 1), ("no-such", 25, 0))


@pytest.mark.parametrize("max_sources", [rp.MAX_ATTEMPT_SOURCES, 1], ids=["sources listed", "too many sources"])
def test_the_attempts_answers_equal_the_two_statement_read(
    events_db: Any, max_sources: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(rp, "MAX_ATTEMPT_SOURCES", max_sources)  # 1: the events hold 2 sources, so every entry
    cases: list[tuple[str, tuple[int, int], dict[str, Any]]] = []
    for reason in ("header_rule", "endpoint_blocked", "endpoint_rule", "deadline", "no_such_reason"):
        for rule_table in dict.fromkeys((TABLES.get(reason), None)):
            for window in WINDOWS_MS.values():
                for sort in rp.ATTEMPT_SORTS:
                    for descending in (True, False):
                        for search, limit, offset in PAGES:
                            kwargs: dict[str, Any] = {"search": search, "sort": sort, "descending": descending}
                            kwargs.update(limit=limit, offset=offset, rule_table=rule_table)
                            cases.append((reason, window, kwargs))

    def compare(conn: sqlite3.Connection) -> int:
        checked = 0
        for reason, (start_ms, end_ms), kwargs in cases:
            new = rp.refusal_attempts(conn, reason, start_ms, end_ms, **kwargs)
            old = _old_attempts(conn, reason, start_ms, end_ms, **kwargs)
            assert new == old, (reason, start_ms, end_ms, kwargs)
            checked += 1 if new["total"] else 0
        return checked

    assert events_db.metrics.read_sync(compare) > 500  # most combinations have groups to compare


def _traced(conn: sqlite3.Connection, reason: str, offset: int) -> tuple[dict[str, Any], list[str], list[str]]:
    """The answer, the plans of its grouping statements and the plans of its source lookups."""
    start_ms, end_ms = WINDOWS_MS["90d"]
    statements: list[str] = []
    conn.set_trace_callback(statements.append)  # the SQL as SQLite ran it, values bound
    try:
        answer = rp.refusal_attempts(conn, reason, start_ms, end_ms, offset=offset, rule_table=TABLES.get(reason))
    finally:
        conn.set_trace_callback(None)

    def plan(sql: str) -> str:
        return " | ".join(str(tuple(r)[-1]) for r in conn.execute("EXPLAIN QUERY PLAN " + sql))

    groupings = [plan(sql) for sql in statements if "GROUP BY path" in sql]
    lookups = [plan(sql) for sql in statements if "min(detail_message_source)" in sql]
    return answer, groupings, lookups


def test_the_attempts_read_seeks_its_reason_and_groups_once_a_page(events_db: Any) -> None:
    def read(conn: sqlite3.Connection) -> list[tuple[dict[str, Any], list[str], list[str]]]:
        return [_traced(conn, "header_rule", 0), _traced(conn, "header_rule", 10_000), _traced(conn, "nothing", 0)]

    (page, page_plans, lookups), (past, past_plans, _lookups), (empty, empty_plans, _) = events_db.metrics.read_sync(
        read
    )
    assert page["rows"]
    assert page["total"] == len(PATHS) + len(TEMPLATES)  # folded rows group under the template
    assert len(page_plans) == 1  # the page and its count from one grouping (`count(*) OVER ()`)
    assert past["rows"] == []
    assert past["total"] == page["total"]
    assert len(past_plans) == 2  # only a page past the last group counts again
    for plan in page_plans + past_plans:
        seek = "reason_code=? AND detail_message_source=? AND at_ms>? AND at_ms<?"
        assert f"SEARCH events USING INDEX events_refusal_sources ({seek})" in plan, plan
        assert "events_type_at" not in plan, plan
    assert len(lookups) == 3  # the two sources the events hold, then the end of the list
    for plan in lookups:
        assert "events_refusal_sources" in plan, plan
    assert empty == {"total": 0, "rows": []}
    assert empty_plans == []  # a reason without a kept event never groups


def test_past_the_source_bound_the_read_still_seeks_its_reason(events_db: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(rp, "MAX_ATTEMPT_SOURCES", 1)
    answer, plans, _lookups = events_db.metrics.read_sync(lambda conn: _traced(conn, "endpoint_blocked", 0))
    assert answer["total"] == len(PATHS) + len(TEMPLATES)
    assert len(plans) == 1
    assert "SEARCH events USING INDEX events_refusal_sources (reason_code=?)" in plans[0], plans[0]
