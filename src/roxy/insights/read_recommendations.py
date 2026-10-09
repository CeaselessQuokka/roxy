"""Read models of the Recommendations page: paged lists with filters, facet counts, action history and watches.

What this is
    Plain functions over a metrics.db connection (run inside `Database.read`):
      * `list_page(conn, filters, ...)`: one page of `recommendations` rows, filtered by state, severity, rule and
        a search text, sorted on the server, with the total for the pager.
      * `facets(conn)`: how many recommendations each (state, severity, rule) holds, for the filter chips, the
        family counts and the bell.
      * `actions_of(conn, id)`: the `recommendation_actions` rows of one recommendation (apply, undo, snooze,
        dismiss, auto-apply, automatic rollback), newest first.
      * `history_page(conn, ...)`: one page of every action, joined with its recommendation's rule and title.
      * `watch_of(conn, id)`: the auto-apply watch window row (plan 11.4) of one recommendation.
      * `same_fingerprint(conn, fingerprint, ...)`: earlier recommendations with the same dedupe key (a dismissed
        or rolled-back one explains why a similar card is back).
    Rows are plain dicts; recommendation rows keep the table's columns, so `insights.engine.row_to_recommendation`
    turns them into `Recommendation` objects, and action rows carry `details_json` decoded as `details`.

Why it exists
    DESIGN.md section 13 puts read models next to their data. `InsightsEngine.list` returns every row of a state
    (for the leader's lifecycle) but cannot page, count, filter by severity or search; the admin API needs those on
    the server (plan 14.1 "All recommendations with filters (severity, family, state) ... history"), and the
    tables the engine and `insights/actions.py` write are read here, in the package that owns them.

How it works
    Parameterized SELECTs only. Sort columns come from the fixed `LIST_SORTS` and `HISTORY_SORTS` allowlists, never
    from the request; every filter value is a bound parameter; the search is a case-insensitive `instr` over the
    title, the subject and the rule id (no LIKE, so `%` and `_` are plain characters). Every result is bounded
    (`MAX_PAGE_ROWS`, `MAX_FACET_ROWS`, `MAX_ACTIONS`, `MAX_EARLIER`; plan P9). A family is not a column: the API
    turns a family filter into the rule ids of that family (`config/insight_params.py`).

What to read next
    `roxy/insights/engine.py` (who writes `recommendations`), `roxy/insights/actions.py` (who writes
    `recommendation_actions` and `recommendation_watches`), `roxy/admin/api/recommendations.py` (the API).
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Final

SEVERITY_RANK_SQL: Final = "CASE severity WHEN 'critical' THEN 2 WHEN 'warn' THEN 1 ELSE 0 END"
"""The severity order (`models.SEVERITIES`) as SQL, so "most severe first" sorts in the database."""

LIST_SORTS: Final[dict[str, str]] = {
    "severity": SEVERITY_RANK_SQL,
    "updated_at": "updated_at",
    "created_at": "created_at",
    "expires_at": "expires_at",
    "rule_id": "rule_id",
    "state": "state",
}
"""Sortable list columns (request value -> SQL expression). Anything else is refused by the API first."""

HISTORY_SORTS: Final[dict[str, str]] = {"at": "a.at", "id": "a.id", "action": "a.action", "rule_id": "r.rule_id"}
"""Sortable history columns (request value -> SQL expression)."""

ACTIONS: Final[tuple[str, ...]] = ("apply", "undo", "snooze", "dismiss", "auto_apply", "auto_rollback")
"""The `recommendation_actions.action` values (the table's CHECK constraint)."""

MAX_PAGE_ROWS: Final = 250
"""Rows one page may hold (the largest table page size, plan 14.5)."""
MAX_OFFSET: Final = 1_000_000
MAX_FACET_ROWS: Final = 5000
"""Bound of `facets`: 8 states x 3 severities x the rule catalog (about 50) is far below it."""
MAX_ACTIONS: Final = 200
"""Most actions `actions_of` returns for one recommendation."""
MAX_EARLIER: Final = 20
"""Most earlier recommendations `same_fingerprint` returns."""
MAX_FILTER_VALUES: Final = 100
"""Most values one filter may name (the API checks them against closed vocabularies first)."""

_REC_COLUMNS: Final = (
    "id, rule_id, fingerprint, state, severity, payload_json, created_at, updated_at, expires_at, snoozed_until, "
    "dismissed_reason"
)
_ACTION_COLUMNS: Final = "a.id, a.recommendation_id, a.action, a.at, a.actor, a.details_json"


@dataclass(frozen=True, slots=True)
class RecommendationFilter:
    """What the list shows: states, severities and rule ids (empty means any) and a search text."""

    states: tuple[str, ...] = ()
    severities: tuple[str, ...] = ()
    rule_ids: tuple[str, ...] = ()
    q: str = ""


def _in(column: str, values: Sequence[str], clauses: list[str], params: list[Any]) -> None:
    if not values:
        return
    chosen = list(values)[:MAX_FILTER_VALUES]
    clauses.append(f"{column} IN ({', '.join('?' for _ in chosen)})")
    params.extend(chosen)


def _where(filters: RecommendationFilter) -> tuple[str, list[Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    _in("state", filters.states, clauses, params)
    _in("severity", filters.severities, clauses, params)
    _in("rule_id", filters.rule_ids, clauses, params)
    needle = filters.q.strip().lower()
    if needle:
        # instr() instead of LIKE: the admin's text is matched literally, `%` and `_` included.
        clauses.append(
            "(instr(lower(coalesce(json_extract(payload_json, '$.title'), '')), ?) > 0"
            " OR instr(lower(coalesce(json_extract(payload_json, '$.subject'), '')), ?) > 0"
            " OR instr(lower(rule_id), ?) > 0)"
        )
        params.extend([needle, needle, needle])
    return (" AND ".join(clauses) if clauses else "1"), params


def list_page(
    conn: sqlite3.Connection,
    filters: RecommendationFilter,
    *,
    sort: str = "severity",
    descending: bool = True,
    limit: int = 25,
    offset: int = 0,
) -> tuple[list[dict[str, Any]], int]:
    """One page of recommendations and the total matching rows. Ties: newest update first, then id."""
    column = LIST_SORTS.get(sort)
    if column is None:
        raise ValueError(f"cannot sort recommendations by {sort!r}")
    where, params = _where(filters)
    total = int(conn.execute(f"SELECT count(*) FROM recommendations WHERE {where}", params).fetchone()[0])  # noqa: S608 (fixed clauses)
    direction = "DESC" if descending else "ASC"
    # A missing expiry sorts last in both orders, as the tables of metrics/queries.py do.
    nulls = f"{column} IS NULL, " if sort == "expires_at" else ""
    rows = conn.execute(
        f"SELECT {_REC_COLUMNS} FROM recommendations WHERE {where} "  # noqa: S608 (allowlisted sort, fixed clauses)
        f"ORDER BY {nulls}{column} {direction}, updated_at DESC, id DESC LIMIT ? OFFSET ?",
        (*params, max(1, min(int(limit), MAX_PAGE_ROWS)), max(0, min(int(offset), MAX_OFFSET))),
    ).fetchall()
    return [_rec_row(row) for row in rows], total


def _rec_row(row: sqlite3.Row | Sequence[Any]) -> dict[str, Any]:
    names = (
        "id",
        "rule_id",
        "fingerprint",
        "state",
        "severity",
        "payload_json",
        "created_at",
        "updated_at",
        "expires_at",
        "snoozed_until",
        "dismissed_reason",
    )
    return {name: row[index] for index, name in enumerate(names)}


def get_row(conn: sqlite3.Connection, rec_id: str) -> dict[str, Any] | None:
    """One recommendation row by id, or None."""
    row = conn.execute(f"SELECT {_REC_COLUMNS} FROM recommendations WHERE id = ?", (rec_id,)).fetchone()  # noqa: S608 (fixed columns)
    return None if row is None else _rec_row(row)


def facets(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    """`[{state, severity, rule_id, count}]` over the whole table (bounded by `MAX_FACET_ROWS`)."""
    rows = conn.execute(
        "SELECT state, severity, rule_id, count(*) FROM recommendations GROUP BY state, severity, rule_id LIMIT ?",
        (MAX_FACET_ROWS,),
    ).fetchall()
    return [{"state": str(r[0]), "severity": str(r[1]), "rule_id": str(r[2]), "count": int(r[3])} for r in rows]


def _decode(text: str | None) -> Any:
    if not text:
        return None
    try:
        return json.loads(text)
    except ValueError:
        return None


def _action_row(row: sqlite3.Row | Sequence[Any], extra: Sequence[str] = ()) -> dict[str, Any]:
    out: dict[str, Any] = {
        "id": int(row[0]),
        "recommendation_id": str(row[1]),
        "action": str(row[2]),
        "at": int(row[3]),
        "actor": str(row[4]),
        "details": _decode(row[5]),
    }
    for index, name in enumerate(extra, start=6):
        out[name] = row[index]
    return out


def actions_of(conn: sqlite3.Connection, rec_id: str, *, limit: int = MAX_ACTIONS) -> list[dict[str, Any]]:
    """Every recorded action of one recommendation, newest first (bounded)."""
    rows = conn.execute(
        f"SELECT {_ACTION_COLUMNS} FROM recommendation_actions a WHERE a.recommendation_id = ? "  # noqa: S608 (fixed columns)
        "ORDER BY a.at DESC, a.id DESC LIMIT ?",
        (rec_id, max(1, min(int(limit), MAX_ACTIONS))),
    ).fetchall()
    return [_action_row(row) for row in rows]


def history_page(
    conn: sqlite3.Connection,
    *,
    actions: Sequence[str] = (),
    rule_ids: Sequence[str] = (),
    recommendation_id: str | None = None,
    since: int | None = None,
    until: int | None = None,
    sort: str = "at",
    descending: bool = True,
    limit: int = 25,
    offset: int = 0,
) -> tuple[list[dict[str, Any]], int]:
    """One page of every recommendation action, with the rule, title, subject and state of its recommendation."""
    column = HISTORY_SORTS.get(sort)
    if column is None:
        raise ValueError(f"cannot sort recommendation history by {sort!r}")
    clauses: list[str] = []
    params: list[Any] = []
    _in("a.action", actions, clauses, params)
    _in("r.rule_id", rule_ids, clauses, params)
    if recommendation_id is not None:
        clauses.append("a.recommendation_id = ?")
        params.append(recommendation_id)
    if since is not None:
        clauses.append("a.at >= ?")
        params.append(int(since))
    if until is not None:
        clauses.append("a.at < ?")
        params.append(int(until))
    where = " AND ".join(clauses) if clauses else "1"
    joined = "FROM recommendation_actions a LEFT JOIN recommendations r ON r.id = a.recommendation_id"
    total = int(conn.execute(f"SELECT count(*) {joined} WHERE {where}", params).fetchone()[0])
    direction = "DESC" if descending else "ASC"
    rows = conn.execute(
        f"SELECT {_ACTION_COLUMNS}, r.rule_id, r.severity, r.state, "
        "json_extract(r.payload_json, '$.title'), json_extract(r.payload_json, '$.subject') "
        f"{joined} WHERE {where} ORDER BY {column} {direction}, a.id DESC LIMIT ? OFFSET ?",
        (*params, max(1, min(int(limit), MAX_PAGE_ROWS)), max(0, min(int(offset), MAX_OFFSET))),
    ).fetchall()
    extra = ("rule_id", "severity", "state", "title", "subject")
    return [_action_row(row, extra) for row in rows], total


def watch_of(conn: sqlite3.Connection, rec_id: str) -> dict[str, Any] | None:
    """The watch window row of one recommendation (plan 11.4), or None when it was never applied."""
    row = conn.execute(
        "SELECT recommendation_id, action_id, started_at, ends_at, state, baseline_json, result_json "
        "FROM recommendation_watches WHERE recommendation_id = ?",
        (rec_id,),
    ).fetchone()
    if row is None:
        return None
    return {
        "action_id": None if row[1] is None else int(row[1]),
        "started_at": int(row[2]),
        "ends_at": int(row[3]),
        "state": str(row[4]),
        "baseline": _decode(row[5]),
        "result": _decode(row[6]),
    }


def same_fingerprint(
    conn: sqlite3.Connection, fingerprint: str, *, exclude_id: str, limit: int = MAX_EARLIER
) -> list[dict[str, Any]]:
    """Other recommendations with the same fingerprint (rule and subject), newest first (bounded)."""
    rows = conn.execute(
        "SELECT id, state, severity, created_at, updated_at, dismissed_reason FROM recommendations "
        "WHERE fingerprint = ? AND id != ? ORDER BY updated_at DESC, id DESC LIMIT ?",
        (fingerprint, exclude_id, max(1, min(int(limit), MAX_EARLIER))),
    ).fetchall()
    return [
        {
            "id": str(r[0]),
            "state": str(r[1]),
            "severity": str(r[2]),
            "created_at": int(r[3]),
            "updated_at": int(r[4]),
            "dismissed_reason": r[5],
        }
        for r in rows
    ]


__all__ = [
    "ACTIONS",
    "HISTORY_SORTS",
    "LIST_SORTS",
    "MAX_ACTIONS",
    "MAX_EARLIER",
    "MAX_FACET_ROWS",
    "MAX_PAGE_ROWS",
    "SEVERITY_RANK_SQL",
    "RecommendationFilter",
    "actions_of",
    "facets",
    "get_row",
    "history_page",
    "list_page",
    "same_fingerprint",
    "watch_of",
]
