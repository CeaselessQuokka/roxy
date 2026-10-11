"""Read models for the insight history tables: bucket fill, worker samples, cache evictions, rule hits, errors.

What this is
    Plain functions over a metrics.db connection (run them inside `Database.read`) that answer the questions the
    recommendation rules ask of the schema version 2 tables (`storage/migrations/metrics/0002_insight_history.sql`):
    bucket attempts, rejections and fill peaks (`bucket_summary`, `bucket_history`), worker CPU and loop lag per
    minute (`worker_history`), shared cache stores and evictions (`cache_summary`, `eviction_passes`), when rule rows
    last matched (`rule_hits`), error occurrences (`error_counts`, `error_series`), upstream calls by attempt
    (`attempt_rows`), the admin-entered provider byte figure (`latest_provider_report`), plus `events_between` for
    the event types the rules read (breaker openings, credential probes, spam detections, logins), the version 1
    reads the rules need with groupings `metrics/queries.py` does not offer (`roblox_429_counts` per template, egress
    and minute, `upstream_429_rows`, `samples_between`, `latest_health_run`, `anomalies_between`, `heartbeats`),
    the sample aggregates the rules share (`change_estimates`, the TTL tuner in SQL; `ua_arm_counts`), the bounded
    reads of a dry run (`sample_cut`, `newest_streams`), and `prune_history`, the retention step for the version 2
    tables.

Why it exists
    DESIGN.md section 13: read models live next to their data, so the dashboard, the LLM export and the insights
    engine read one definition of each number (P6). The recorder writes these tables (`metrics/recorder.py`, batch
    kind `metrics.insight_history`); this module is the only reader.

How it works
    Every time argument is Unix seconds and every window is half open `[start, end)`. Minute tables are summed with
    one indexed range read; results are small dicts and lists, bounded by `limit` arguments (plan P9). The two
    sample reads can return tens of thousands of rows, so they return compact read-only `SampleRecord` mappings
    (one tuple per row, repeated strings shared) instead of dicts (finding LOAD-2), and take a `SampleFilter` so a
    rule reads only the rows it looks at. What a rule needs per template over a whole day (the TTL tuner) is
    computed in SQL over every row of the window and returns one small row per template (gaps_insights G7): no
    row limit cuts it, and SQLite does the work without holding Python's GIL.

What to read next
    `roxy/metrics/recorder.py` (the writers), `roxy/insights/context.py` (how rules reach these functions).
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from typing import Any, Final

MAX_ROWS: Final = 50_000
"""Most rows one history read returns (a bound, plan P9; minute tables of one week stay far below it)."""


def _bounded(limit: int | None) -> int:
    return MAX_ROWS if limit is None else max(1, min(int(limit), MAX_ROWS))


# ----------------------------------------------------------------------------------------------- buckets


def bucket_summary(
    conn: sqlite3.Connection, start: int, end: int, keys: Iterable[str] | None = None
) -> dict[str, dict[str, float]]:
    """`{bucket_key: {attempts, rejections, fill_pct_peak, minutes}}` summed over `[start, end)`."""
    wanted = sorted(set(keys)) if keys is not None else []
    clause = ""
    params: list[Any] = [int(start), int(end)]
    if wanted:
        clause = f" AND bucket_key IN ({', '.join('?' for _ in wanted)})"
        params += wanted
    rows = conn.execute(
        "SELECT bucket_key, sum(attempts) AS a, sum(rejections) AS r, max(fill_pct_peak) AS p, count(*) AS m "  # noqa: S608
        f"FROM bucket_minute WHERE bucket_start >= ? AND bucket_start < ?{clause} GROUP BY bucket_key",
        params,
    ).fetchall()
    return {
        str(r["bucket_key"]): {
            "attempts": int(r["a"] or 0),
            "rejections": int(r["r"] or 0),
            "fill_pct_peak": float(r["p"] or 0.0),
            "minutes": int(r["m"] or 0),
        }
        for r in rows
    }


def bucket_history(conn: sqlite3.Connection, bucket_key: str, start: int, end: int) -> list[dict[str, Any]]:
    """One bucket's minutes in `[start, end)`, oldest first."""
    rows = conn.execute(
        "SELECT bucket_start, attempts, rejections, fill_pct_peak FROM bucket_minute "
        "WHERE bucket_key = ? AND bucket_start >= ? AND bucket_start < ? ORDER BY bucket_start LIMIT ?",
        (bucket_key, int(start), int(end), MAX_ROWS),
    ).fetchall()
    return [dict(r) for r in rows]


# ----------------------------------------------------------------------------------------------- workers


def worker_history(conn: sqlite3.Connection, start: int, end: int) -> dict[str, list[dict[str, Any]]]:
    """`{worker_id: [{bucket_start, cpu_pct, cpu_pct_max, loop_lag_ms_p99, open_conns, rss}]}`, oldest first."""
    rows = conn.execute(
        "SELECT bucket_start, worker_id, samples, cpu_pct_sum, cpu_pct_max, loop_lag_ms_p99, open_conns, rss "
        "FROM worker_minute WHERE bucket_start >= ? AND bucket_start < ? ORDER BY bucket_start LIMIT ?",
        (int(start), int(end), MAX_ROWS),
    ).fetchall()
    out: dict[str, list[dict[str, Any]]] = {}
    for r in rows:
        samples = int(r["samples"] or 0)
        out.setdefault(str(r["worker_id"]), []).append(
            {
                "bucket_start": int(r["bucket_start"]),
                "cpu_pct": (float(r["cpu_pct_sum"]) / samples) if samples else None,
                "cpu_pct_max": r["cpu_pct_max"],
                "loop_lag_ms_p99": r["loop_lag_ms_p99"],
                "open_conns": r["open_conns"],
                "rss": r["rss"],
            }
        )
    return out


# ------------------------------------------------------------------------------------------------- cache


def cache_summary(conn: sqlite3.Connection, start: int, end: int) -> dict[str, Any]:
    """Stores, evictions, young evictions and mean eviction ages in `[start, end)`."""
    row = conn.execute(
        "SELECT sum(stores), sum(evictions), sum(young_evictions), sum(evicted_age_s_sum), sum(young_age_s_sum) "
        "FROM cache_minute WHERE bucket_start >= ? AND bucket_start < ?",
        (int(start), int(end)),
    ).fetchone()
    stores, evictions, young, age_sum, young_age_sum = (float(v or 0) for v in row)
    return {
        "stores": int(stores),
        "evictions": int(evictions),
        "young_evictions": int(young),
        "mean_eviction_age_s": round(age_sum / evictions, 1) if evictions else None,
        "mean_young_age_s": round(young_age_sum / young, 1) if young else None,
    }


def eviction_passes(conn: sqlite3.Connection, start: int, end: int, limit: int | None = None) -> list[dict[str, Any]]:
    """Eviction passes in `[start, end)`, oldest first."""
    rows = conn.execute(
        "SELECT at, entries_before, bytes_before, evicted, freed_bytes FROM cache_eviction_passes "
        "WHERE at >= ? AND at < ? ORDER BY at LIMIT ?",
        (int(start), int(end), _bounded(limit)),
    ).fetchall()
    return [dict(r) for r in rows]


# ------------------------------------------------------------------------------------------------- rules


def rule_hits(conn: sqlite3.Connection, table: str | None = None) -> dict[tuple[str, str], dict[str, int | None]]:
    """`{(table_name, rule_key): {hits, first_hit_at, last_hit_at}}` for one table or all of them."""
    if table is None:
        rows = conn.execute(
            "SELECT table_name, rule_key, hits, first_hit_at, last_hit_at FROM rule_hits LIMIT ?", (MAX_ROWS,)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT table_name, rule_key, hits, first_hit_at, last_hit_at FROM rule_hits WHERE table_name = ? LIMIT ?",
            (table, MAX_ROWS),
        ).fetchall()
    return {
        (str(r["table_name"]), str(r["rule_key"])): {
            "hits": int(r["hits"] or 0),
            "first_hit_at": r["first_hit_at"],
            "last_hit_at": r["last_hit_at"],
        }
        for r in rows
    }


# ------------------------------------------------------------------------------------------------ errors


def error_signatures(conn: sqlite3.Connection, limit: int = 2000) -> list[dict[str, Any]]:
    """Every row of the `errors` table (signature summaries), newest first."""
    rows = conn.execute(
        "SELECT signature, count, first_seen, last_seen, source, last_detail, module_line, traceback_redacted "
        "FROM errors ORDER BY last_seen DESC LIMIT ?",
        (max(1, min(int(limit), MAX_ROWS)),),
    ).fetchall()
    return [dict(r) for r in rows]


def error_counts(conn: sqlite3.Connection, start: int, end: int) -> dict[str, int]:
    """`{signature: occurrences}` in `[start, end)`."""
    rows = conn.execute(
        "SELECT signature, sum(count) AS n FROM error_minute WHERE bucket_start >= ? AND bucket_start < ? "
        "GROUP BY signature",
        (int(start), int(end)),
    ).fetchall()
    return {str(r["signature"]): int(r["n"] or 0) for r in rows}


def error_series(conn: sqlite3.Connection, signature: str, start: int, end: int) -> list[tuple[int, int]]:
    """`[(minute, count)]` of one signature in `[start, end)`, oldest first."""
    rows = conn.execute(
        "SELECT bucket_start, count FROM error_minute WHERE signature = ? AND bucket_start >= ? AND bucket_start < ? "
        "ORDER BY bucket_start LIMIT ?",
        (signature, int(start), int(end), MAX_ROWS),
    ).fetchall()
    return [(int(r[0]), int(r[1])) for r in rows]


# -------------------------------------------------------------------------------------------- attempts


def attempt_rows(conn: sqlite3.Connection, start: int, end: int, template: str | None = None) -> list[dict[str, Any]]:
    """Upstream calls by attempt in `[start, end)`, summed over minutes (one row per distinct attempt shape)."""
    clause = " AND endpoint_template = ?" if template is not None else ""
    params: list[Any] = [int(start), int(end)]
    if template is not None:
        params.append(template)
    rows = conn.execute(
        "SELECT endpoint_template, egress, attempt, kind, status, challenge, html_body, exit_id, sum(count) AS n "  # noqa: S608
        f"FROM upstream_attempt_minute WHERE bucket_start >= ? AND bucket_start < ?{clause} "
        "GROUP BY endpoint_template, egress, attempt, kind, status, challenge, html_body, exit_id LIMIT ?",
        (*params, MAX_ROWS),
    ).fetchall()
    out = []
    for r in rows:
        item = dict(r)
        item["status"] = None if int(item["status"]) < 0 else int(item["status"])
        item["challenge"] = bool(item["challenge"])
        item["html_body"] = bool(item["html_body"])
        item["count"] = int(item.pop("n") or 0)
        out.append(item)
    return out


# -------------------------------------------------------------------------------------------- provider


def latest_provider_report(conn: sqlite3.Connection) -> dict[str, Any] | None:
    """The newest admin-entered provider byte figure, or None."""
    row = conn.execute(
        "SELECT at, reported_bytes, entered_by FROM egress_provider_reports ORDER BY at DESC, id DESC LIMIT 1"
    ).fetchone()
    return dict(row) if row is not None else None


# ---------------------------------------------------------------------------------------------- events


def events_between(
    conn: sqlite3.Connection, types: Iterable[str], start: int, end: int, limit: int | None = None
) -> list[dict[str, Any]]:
    """`events` rows of the given types in `[start, end)` seconds, oldest first, `detail` parsed.

    Aggregated rows carry their `count` in the detail (the recorder sums them per minute); `count` is set to 1
    for individual rows so callers can always sum it.
    """
    wanted = sorted(set(types))
    if not wanted:
        return []
    marks = ", ".join("?" for _ in wanted)
    rows = conn.execute(
        f"SELECT id, at_ms, type, severity, reason_code, ip_hash, place, endpoint_template, detail_json FROM events "  # noqa: S608
        f"WHERE type IN ({marks}) AND at_ms >= ? AND at_ms < ? ORDER BY at_ms, id LIMIT ?",
        (*wanted, int(start) * 1000, int(end) * 1000, _bounded(limit)),
    ).fetchall()
    out = []
    for r in rows:
        try:
            detail = json.loads(r["detail_json"]) if r["detail_json"] else {}
        except ValueError:
            detail = {}
        item = dict(r)
        item.pop("detail_json", None)
        item["detail"] = detail if isinstance(detail, dict) else {}
        item["count"] = int(item["detail"].get("count", 1) or 1) if isinstance(item["detail"], dict) else 1
        out.append(item)
    return out


# ------------------------------------------------------------------------------------ 429s and samples

_429_GROUPS: Final[frozenset[str]] = frozenset({"endpoint_template", "host", "egress"})


def roblox_429_counts(
    conn: sqlite3.Connection,
    start: int,
    end: int,
    *,
    group_by: Iterable[str] = ("endpoint_template",),
    per_minute: bool = False,
    where: dict[str, Any] | None = None,
) -> dict[tuple[Any, ...], int]:
    """Roblox 429s from `upstream_429` in `[start, end)`, grouped by any of endpoint_template, host and egress (the
    egress of the attempt that got the 429), and by minute when `per_minute`. Keys are tuples in `group_by` order
    (the minute first when `per_minute`)."""
    groups = [g for g in group_by if g in _429_GROUPS]
    if len(groups) != len(list(group_by)):
        raise ValueError("upstream_429 can be grouped by endpoint_template, host and egress only")
    clauses = ["at_ms >= ?", "at_ms < ?"]
    params: list[Any] = [int(start) * 1000, int(end) * 1000]
    for key, value in (where or {}).items():
        if key not in _429_GROUPS:
            raise ValueError(f"upstream_429 cannot be filtered by {key!r}")
        values = list(value) if isinstance(value, list | tuple | set | frozenset) else [value]
        clauses.append(f"{key} IN ({', '.join('?' for _ in values)})")
        params += [str(v) for v in values]
    columns = (["(at_ms / 60000) * 60"] if per_minute else []) + groups
    select = ", ".join(columns) if columns else "NULL"
    group = f" GROUP BY {', '.join(columns)}" if columns else ""
    rows = conn.execute(
        f"SELECT {select}, count(*) FROM upstream_429 WHERE {' AND '.join(clauses)}{group} LIMIT ?",  # noqa: S608 (fixed names)
        (*params, MAX_ROWS),
    ).fetchall()
    out: dict[tuple[Any, ...], int] = {}
    for row in rows:
        group_key = tuple(row[: len(columns)]) if columns else ()
        out[group_key] = out.get(group_key, 0) + int(row[-1])
    return out


def upstream_429_rows(
    conn: sqlite3.Connection,
    start: int,
    end: int,
    template: str | None = None,
    limit: int | None = None,
    *,
    offset: int = 0,
) -> list[dict[str, Any]]:
    """`upstream_429` rows in `[start, end)` (optionally one template), oldest first (ties by row id, so pages read
    with `offset` never repeat or skip a row; the `upstream_429` export reads it page by page, finding mpjobs-5)."""
    clause = " AND endpoint_template = ?" if template is not None else ""
    params: list[Any] = [int(start) * 1000, int(end) * 1000]
    if template is not None:
        params.append(template)
    rows = conn.execute(
        "SELECT at_ms, endpoint_template, host, egress, retry_after_s, ratelimit_headers_json, request_id "  # noqa: S608
        f"FROM upstream_429 WHERE at_ms >= ? AND at_ms < ?{clause} ORDER BY at_ms, id LIMIT ? OFFSET ?",
        (*params, _bounded(limit), max(0, int(offset))),
    ).fetchall()
    return [dict(r) for r in rows]


class SampleRecord(Mapping[str, Any]):
    """One sample row as a read-only mapping that costs a tuple, not a dict (finding LOAD-2).

    A read of a day of samples returns up to `MAX_ROWS` rows, and the insights engine keeps every read of one
    evaluation until the evaluation ends. As dicts, with a fresh string for every repeated value, each row cost about
    1 KB, so one evaluation over a busy day held hundreds of MiB and the leader worker's memory kept its high water
    mark. A record keeps the row's values in one tuple next to a column index shared by every record of the read, and
    the read shares one string object per repeated value (`_Interner`): about a third of the memory, for the same
    `record["column"]`, `record.get("column")`, `in`, iteration and equality with a dict.
    """

    __slots__ = ("_columns", "_values")

    def __init__(self, columns: Mapping[str, int], values: tuple[Any, ...]) -> None:
        self._columns = columns
        self._values = values

    def __getitem__(self, key: str) -> Any:
        return self._values[self._columns[key]]

    def get(self, key: str, default: Any = None) -> Any:
        index = self._columns.get(key)
        return default if index is None else self._values[index]

    def __contains__(self, key: object) -> bool:
        return key in self._columns

    def __iter__(self) -> Iterator[str]:
        return iter(self._columns)

    def __len__(self) -> int:
        return len(self._columns)

    def __repr__(self) -> str:
        return f"SampleRecord({dict(self)!r})"


class _Interner:
    """One shared string object per distinct value of the low-cardinality columns within one read (bounded: at most
    `MAX_INTERNED` values are remembered; later new values are simply kept as they are)."""

    MAX_INTERNED: Final = 10_000

    def __init__(self) -> None:
        self._seen: dict[str, str] = {}

    def __call__(self, value: Any) -> Any:
        if not isinstance(value, str):
            return value
        found = self._seen.get(value)
        if found is not None:
            return found
        if len(self._seen) < self.MAX_INTERNED:
            self._seen[value] = value
        return value


def _records(cursor: sqlite3.Cursor, columns: tuple[str, ...], shared: frozenset[str]) -> list[SampleRecord]:
    """The cursor's rows as `SampleRecord`s, the values of the `shared` columns interned."""
    index = {name: position for position, name in enumerate(columns)}
    interned = [position for position, name in enumerate(columns) if name in shared]
    intern = _Interner()
    out: list[SampleRecord] = []
    for raw in cursor:
        values = tuple(raw)
        if interned:
            items = list(values)
            for position in interned:
                items[position] = intern(items[position])
            values = tuple(items)
        out.append(SampleRecord(index, values))
    return out


SAMPLE_COLUMNS: Final = (
    "id", "at_ms", "key_id", "endpoint_template", "method", "client_hash", "place", "cache_state", "upstream_status",
    "egress", "body_hash", "bytes", "auth_class", "sample_pct",
)  # fmt: skip
"""The `request_samples` columns `samples_between` returns, in order."""

REFUSAL_SAMPLE_COLUMNS: Final = (
    "id", "at_ms", "reason", "endpoint_template", "method", "client_hash", "place", "sample_pct",
)  # fmt: skip
"""The `refusal_samples` columns `refusal_samples_between` returns, in order."""

_SHARED_SAMPLE_VALUES: Final = frozenset(
    {"endpoint_template", "method", "place", "cache_state", "egress", "auth_class", "reason", "key_id", "client_hash"}
)
"""Columns whose values repeat from row to row (templates, methods, states; a hot key or a busy client)."""


def _sample_limit(limit: int | None) -> int:
    """A sample read's row limit: `MAX_ROWS` by default, at most `MAX_ROWS + 1` (a caller that asks for one row more
    than it keeps learns whether the bound cut the read; `insights/context.py SampleRead.complete`)."""
    return MAX_ROWS if limit is None else max(1, min(int(limit), MAX_ROWS + 1))


@dataclass(frozen=True, slots=True)
class SampleFilter:
    """Conditions a request sample read applies in SQL, so a rule reads only the rows it looks at instead of every
    row of its window (gaps_insights G7: a rule that needs a few hundred rows no longer reads, and is no longer cut
    by, the window's tens of thousands).

    - `egress`: only rows with exactly this egress (`none`: answers that made no upstream call).
    - `called`: only rows that made an upstream call (an egress that is set and is not `none`).
    - `exclude_cache_states`: leave out rows with one of these cache states (a row without a state is kept).
    - `with_client`: only rows with a client hash.
    - `key_ids`: only rows of these cache keys.
    - `statuses`: only rows with one of these upstream statuses.
    """

    egress: str | None = None
    called: bool = False
    exclude_cache_states: tuple[str, ...] = ()
    with_client: bool = False
    key_ids: tuple[str, ...] | None = None
    statuses: tuple[int, ...] | None = None

    def sql(self) -> tuple[str, list[Any]]:
        """`(" AND ..." clause, parameters)`. Lists travel as one JSON parameter (`json_each`), so a long key list
        never meets SQLite's limit on bound parameters."""
        clauses: list[str] = []
        params: list[Any] = []
        if self.egress is not None:
            clauses.append("egress = ?")
            params.append(self.egress)
        if self.called:
            clauses.append("coalesce(nullif(egress, ''), 'none') <> 'none'")
        if self.exclude_cache_states:
            clauses.append("(cache_state IS NULL OR cache_state NOT IN (SELECT value FROM json_each(?)))")
            params.append(json.dumps(sorted(self.exclude_cache_states)))
        if self.with_client:
            clauses.append("client_hash IS NOT NULL AND client_hash <> ''")
        if self.key_ids is not None:
            clauses.append("key_id IN (SELECT value FROM json_each(?))")
            params.append(json.dumps(sorted(self.key_ids)))
        if self.statuses is not None:
            clauses.append("upstream_status IN (SELECT value FROM json_each(?))")
            params.append(json.dumps(sorted(int(s) for s in self.statuses)))
        return "".join(f" AND {clause}" for clause in clauses), params


def samples_between(
    conn: sqlite3.Connection,
    start: int,
    end: int,
    templates: Iterable[str] | None = None,
    limit: int | None = None,
    *,
    where: SampleFilter | None = None,
) -> list[SampleRecord]:
    """`request_samples` rows in `[start, end)` seconds (optionally only some templates, and only the rows `where`
    admits), in time order, as compact read-only `SampleRecord` mappings (at most `MAX_ROWS`, or `MAX_ROWS + 1` when
    asked: see `_sample_limit`). The OLDEST rows come first, so a read the limit cuts is missing its newest rows:
    callers that need the newest part of a busy window use `newest_streams`."""
    wanted = sorted(set(templates)) if templates is not None else []
    clause = f" AND endpoint_template IN ({', '.join('?' for _ in wanted)})" if wanted else ""
    extra, extra_params = where.sql() if where is not None else ("", [])
    cursor = conn.cursor()
    cursor.row_factory = None  # plain tuples: the records share one column index instead of a dict per row
    cursor.execute(
        f"SELECT {', '.join(SAMPLE_COLUMNS)} FROM request_samples WHERE at_ms >= ? AND at_ms < ?{clause}{extra} "  # noqa: S608
        "ORDER BY at_ms, id LIMIT ?",
        (int(start) * 1000, int(end) * 1000, *wanted, *extra_params, _sample_limit(limit)),
    )
    return _records(cursor, SAMPLE_COLUMNS, _SHARED_SAMPLE_VALUES)


def refusal_samples_between(
    conn: sqlite3.Connection, start: int, end: int, limit: int | None = None
) -> list[SampleRecord]:
    """`refusal_samples` rows (requests a limiter refused, metrics.db schema 7) in `[start, end)` seconds, in time
    order: the refused part of the stream a limit dry run replays (`insights/simulate.py _limit_replays`). Compact
    read-only records, like `samples_between`."""
    cursor = conn.cursor()
    cursor.row_factory = None
    cursor.execute(
        f"SELECT {', '.join(REFUSAL_SAMPLE_COLUMNS)} FROM refusal_samples "  # noqa: S608
        "WHERE at_ms >= ? AND at_ms < ? ORDER BY at_ms, id LIMIT ?",
        (int(start) * 1000, int(end) * 1000, _sample_limit(limit)),
    )
    return _records(cursor, REFUSAL_SAMPLE_COLUMNS, _SHARED_SAMPLE_VALUES)


SAMPLE_TABLES: Final[frozenset[str]] = frozenset({"request_samples", "refusal_samples"})
"""The two sample tables (`sample_cut` names one; both have an `at_ms` index)."""


def sample_cut(
    conn: sqlite3.Connection, start: int, end: int, bound: int, *, table: str = "request_samples"
) -> int | None:
    """Where the newest part of `[start, end)` that holds at most `bound` rows of `table` begins (Unix seconds, on a
    whole minute), or None when the whole window holds at most `bound` rows.

    The row at offset `bound` from the newest is the newest row left out; every row from the next whole minute
    after it is among the newest `bound` (one indexed scan of `bound` index entries).
    """
    if table not in SAMPLE_TABLES:
        raise ValueError(f"not a sample table: {table!r}")
    row = conn.execute(
        f"SELECT at_ms FROM {table} WHERE at_ms >= ? AND at_ms < ? ORDER BY at_ms DESC LIMIT 1 OFFSET ?",  # noqa: S608 (SAMPLE_TABLES)
        (int(start) * 1000, int(end) * 1000, max(1, int(bound))),
    ).fetchone()
    if row is None:
        return None
    after = int(row[0]) // 1000 + 1  # the first whole second after the newest row left out
    return min(int(end), -(-after // 60) * 60)  # up to a whole minute, never past the window


def newest_streams(
    conn: sqlite3.Connection, start: int, end: int, bound: int, *, refusals: bool = False
) -> tuple[int, list[SampleRecord], list[SampleRecord]]:
    """`(cut, request samples, refusal samples)` of the newest part of `[start, end)` in which each table holds at
    most `bound` rows (`sample_cut`; `cut` is `start` when the whole window fits), read in one snapshot: the input of
    a dry run (plan 11.3), which replays one contiguous span and says so when it is shorter than asked
    (gaps_insights G7; the old read silently kept the OLDEST `MAX_ROWS` rows of a busy window). Refusal samples are
    read only with `refusals`."""
    bound = max(1, min(int(bound), MAX_ROWS))
    cut = int(start)
    for table in ("request_samples", "refusal_samples") if refusals else ("request_samples",):
        found = sample_cut(conn, cut, end, bound, table=table)
        if found is not None:
            cut = max(cut, found)
    rows = samples_between(conn, cut, end, limit=bound)
    refused = refusal_samples_between(conn, cut, end, limit=bound) if refusals else []
    return cut, rows, refused


# The TTL tuner (plan 11.3, F10) in SQL: for each template, over the fetches that carry a body (`body_hash`) of each
# cache key in time order, the keys with two fetches or more, the span between their first and last fetch, and the
# body changes (a fetch whose body differs from the key's previous fetch). `insights/simulate.py
# estimate_change_interval` is the same computation over sample rows (a parity test pins them together).
_FETCHES_SQL: Final = (
    "SELECT endpoint_template AS template, key_id, at_ms, body_hash, "
    "lag(body_hash) OVER fetch_order AS previous_hash, lag(at_ms) OVER fetch_order AS previous_ms "
    "FROM request_samples "
    "WHERE at_ms >= ? AND at_ms < ? AND key_id IS NOT NULL AND body_hash IS NOT NULL AND body_hash <> ''{clause} "
    "WINDOW fetch_order AS (PARTITION BY endpoint_template, key_id ORDER BY at_ms, id)"
)
_CHANGE_TOTALS_SQL: Final = (
    "WITH fetches AS (" + _FETCHES_SQL + "), "  # noqa: S608 (fixed SQL text; every value is a bound parameter)
    "per_key AS (SELECT template, count(*) AS fetches, max(at_ms) - min(at_ms) AS span_ms, "
    "sum(previous_hash IS NOT NULL AND previous_hash <> body_hash) AS changes FROM fetches GROUP BY template, key_id) "
    "SELECT template, count(*), sum(span_ms), sum(changes > 0), sum(changes) FROM per_key WHERE fetches >= 2 "
    "GROUP BY template"
)
# A change is placed halfway between the last fetch with the old body and the first with the new one; the gaps
# between consecutive changes of one key are the intervals, and only their median (the middle one or two of each
# template, 1-based ranks (n + 1) / 2 and (n + 2) / 2 in integer division) and their number leave the database.
_CHANGE_MEDIANS_SQL: Final = (
    "WITH fetches AS (" + _FETCHES_SQL + "), "  # noqa: S608 (fixed SQL text; every value is a bound parameter)
    "points AS (SELECT template, key_id, (previous_ms + at_ms) / 2000.0 AS point FROM fetches "
    "WHERE previous_hash IS NOT NULL AND previous_hash <> body_hash), "
    "gaps AS (SELECT template, point - lag(point) OVER (PARTITION BY template, key_id ORDER BY point) AS gap "
    "FROM points), "
    "ranked AS (SELECT template, gap, row_number() OVER (PARTITION BY template ORDER BY gap) AS rank, "
    "count(*) OVER (PARTITION BY template) AS total FROM gaps WHERE gap IS NOT NULL) "
    "SELECT template, total, gap FROM ranked WHERE rank IN ((total + 1) / 2, (total + 2) / 2) ORDER BY template, rank"
)


def change_estimates(
    conn: sqlite3.Connection, start: int, end: int, templates: Iterable[str] | None = None
) -> dict[str, dict[str, Any]]:
    """The TTL tuner's measurements per template over `[start, end)` seconds, computed in SQL over every sample of
    the window (no row limit, nothing returned per row; gaps_insights G7):
    `{template: {keys, keys_with_changes, changes, observed_ms, intervals, median_interval_s}}`.

    `keys` counts the keys with at least two fetches carrying a body, `observed_ms` sums the span between the first
    and last of them per key, `changes` counts body changes, `intervals` the gaps between consecutive changes of one
    key and `median_interval_s` is their median (None without one). Templates without a key fetched twice are
    absent. The intervals are computed only for templates that have one (a key that changed twice or more).
    """
    wanted = sorted(set(templates)) if templates is not None else None
    clause = " AND endpoint_template IN (SELECT value FROM json_each(?))" if wanted is not None else ""
    params: list[Any] = [int(start) * 1000, int(end) * 1000]
    if wanted is not None:
        params.append(json.dumps(wanted))
    out: dict[str, dict[str, Any]] = {}
    for template, keys, span_ms, with_changes, changes in conn.execute(
        _CHANGE_TOTALS_SQL.format(clause=clause), params
    ).fetchall():
        out[str(template)] = {
            "keys": int(keys),
            "keys_with_changes": int(with_changes or 0),
            "changes": int(changes or 0),
            "observed_ms": int(span_ms or 0),
            "intervals": 0,
            "median_interval_s": None,
        }
    # A template has intervals only when one of its keys changed twice or more: more changes than changing keys.
    repeated = sorted(t for t, v in out.items() if v["changes"] > v["keys_with_changes"])
    if not repeated:
        return out
    middles: dict[str, list[float]] = {}
    totals: dict[str, int] = {}
    medians_sql = _CHANGE_MEDIANS_SQL.format(clause=" AND endpoint_template IN (SELECT value FROM json_each(?))")
    for template, total, gap in conn.execute(medians_sql, (int(start) * 1000, int(end) * 1000, json.dumps(repeated))):
        middles.setdefault(str(template), []).append(float(gap))
        totals[str(template)] = int(total)
    for template, values in middles.items():
        entry = out.get(template)
        if entry is None:
            continue
        entry["intervals"] = totals[template]
        # statistics.median: the middle value, or the mean of the two middle values (the same float arithmetic).
        entry["median_interval_s"] = values[0] if len(values) == 1 else (values[0] + values[1]) / 2
    return out


def ua_arm_counts(
    conn: sqlite3.Connection, start: int, end: int, limit: int | None = None
) -> list[tuple[str, int, int]]:
    """`[(identity, calls, roblox_429s)]` of the direct calls that reached Roblox in `[start, end)` seconds, per
    User-Agent experiment identity (the cache key id, else the template; `providers_rules_upstream.arms_from_samples`
    reads the same columns from sample rows), most calls first, at most `limit` identities (`MAX_ROWS + 1` at most,
    so a caller can tell a cut read)."""
    rows = conn.execute(
        "SELECT coalesce(nullif(key_id, ''), nullif(endpoint_template, ''), '') AS identity, count(*), "
        "sum(upstream_status = 429) FROM request_samples "
        "WHERE at_ms >= ? AND at_ms < ? AND egress = 'direct' AND upstream_status IS NOT NULL "
        "GROUP BY identity ORDER BY count(*) DESC, identity LIMIT ?",
        (int(start) * 1000, int(end) * 1000, _sample_limit(limit)),
    ).fetchall()
    return [(str(r[0]), int(r[1]), int(r[2] or 0)) for r in rows]


def latest_health_run(conn: sqlite3.Connection) -> dict[str, Any] | None:
    """The newest Check Proxy Health run with its results, or None."""
    run = conn.execute(
        "SELECT id, started_at, finished_at, trigger, summary, version FROM health_runs "
        "ORDER BY started_at DESC, id DESC LIMIT 1"
    ).fetchone()
    if run is None:
        return None
    results = conn.execute(
        "SELECT check_id, status, value, threshold, explanation, fix_link, duration_ms FROM health_results "
        "WHERE run_id = ? ORDER BY check_id",
        (run["id"],),
    ).fetchall()
    out = dict(run)
    out["results"] = [dict(r) for r in results]
    return out


def anomalies_between(conn: sqlite3.Connection, start: int, end: int, limit: int | None = None) -> list[dict[str, Any]]:
    """`anomalies` rows detected in `[start, end)`, newest first."""
    rows = conn.execute(
        "SELECT id, at, metric, baseline, observed, zscore, window FROM anomalies WHERE at >= ? AND at < ? "
        "ORDER BY at DESC LIMIT ?",
        (int(start), int(end), _bounded(limit)),
    ).fetchall()
    return [dict(r) for r in rows]


def heartbeats(conn: sqlite3.Connection, fresh_after: int) -> list[dict[str, Any]]:
    """`worker_heartbeat` rows seen at or after `fresh_after` (the live fleet)."""
    rows = conn.execute(
        "SELECT * FROM worker_heartbeat WHERE last_seen >= ? ORDER BY pid LIMIT 256", (int(fresh_after),)
    ).fetchall()
    return [dict(r) for r in rows]


# --------------------------------------------------------------------------------------------- retention

HISTORY_TABLES: Final[dict[str, str]] = {
    "bucket_minute": "bucket_start",
    "worker_minute": "bucket_start",
    "cache_minute": "bucket_start",
    "cache_eviction_passes": "at",
    "error_minute": "bucket_start",
    "upstream_attempt_minute": "bucket_start",
    "egress_provider_reports": "at",
}
"""Time-keyed history tables and their time column (rule_hits is keyed by rule, pruned by idle time)."""


def prune_history(
    conn: sqlite3.Connection, now_s: float, keep_days: dict[str, float], *, limit: int = 20_000
) -> dict[str, int]:
    """Delete rows older than each table's `keep_days` entry (at most `limit` rows per table per call).

    `rule_hits` rows whose last hit is older than its `keep_days` entry are deleted too: a rule that has not
    matched for that long reads the same as one that never matched (idle since it was created).
    """
    deleted: dict[str, int] = {}
    for table, column in HISTORY_TABLES.items():
        days = keep_days.get(table)
        if days is None or days <= 0:
            continue
        cutoff = int(now_s - days * 86_400)
        if table in ("cache_eviction_passes", "egress_provider_reports"):
            sql = f"DELETE FROM {table} WHERE id IN (SELECT id FROM {table} WHERE {column} < ? LIMIT ?)"  # noqa: S608 (HISTORY_TABLES)
        else:
            # Minute tables: whole minutes at a time, the oldest first (`limit` minutes per call).
            sql = (
                f"DELETE FROM {table} WHERE {column} IN "  # noqa: S608 (HISTORY_TABLES)
                f"(SELECT DISTINCT {column} FROM {table} WHERE {column} < ? ORDER BY {column} LIMIT ?)"
            )
        deleted[table] = conn.execute(sql, (cutoff, limit)).rowcount
    days = keep_days.get("rule_hits")
    if days is not None and days > 0:
        cutoff = int(now_s - days * 86_400)
        deleted["rule_hits"] = conn.execute(
            "DELETE FROM rule_hits WHERE (table_name, rule_key) IN "
            "(SELECT table_name, rule_key FROM rule_hits WHERE last_hit_at < ? LIMIT ?)",
            (cutoff, limit),
        ).rowcount
    return deleted


__all__ = [
    "HISTORY_TABLES",
    "MAX_ROWS",
    "REFUSAL_SAMPLE_COLUMNS",
    "SAMPLE_COLUMNS",
    "SAMPLE_TABLES",
    "SampleFilter",
    "SampleRecord",
    "anomalies_between",
    "attempt_rows",
    "bucket_history",
    "bucket_summary",
    "cache_summary",
    "change_estimates",
    "error_counts",
    "error_series",
    "error_signatures",
    "events_between",
    "eviction_passes",
    "heartbeats",
    "latest_health_run",
    "latest_provider_report",
    "newest_streams",
    "prune_history",
    "refusal_samples_between",
    "roblox_429_counts",
    "rule_hits",
    "sample_cut",
    "samples_between",
    "ua_arm_counts",
    "upstream_429_rows",
    "worker_history",
]
