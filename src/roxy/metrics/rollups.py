"""Rollups: write the per-minute counters, then compact minutes into hours, days and months on the leader.

What this is
    The write side of the time series (`write_rollups`, `write_clients`, `write_egress_usage`: the batch writer
    handlers for `rollup_minute`, `client_minute` and minute rows of `egress_usage`) and the leader's compaction
    (`compact_level` with the `LevelSpec` table below): minute to hour (UTC), hour to day and day to month (in
    `ui_timezone`, each day and month row storing the zone it was computed in), the same for `egress_usage`, and
    for the client tables with the "top N plus one `other` row" rule. Plus the time helpers every reader uses
    (`bucket_floor`, `bucket_next`).

Why it exists
    Plan 6.3 and 6.4. One row per minute per active dimension combination keeps the hot path cheap (workers only
    add numbers in memory and upsert every 2 s), and compaction keeps long ranges cheap to read and small on disk:
    a year of history is 365 day rows per combination instead of 525,600 minute rows.

How it works
    - Workers upsert with `INSERT ... ON CONFLICT(bucket_start, dim_hash) DO UPDATE SET requests = requests +
      excluded.requests, ...`; histograms merge with the registered SQL function `roxy_hist_merge`. Two workers
      writing the same minute simply add up, so the totals are exact whatever the number of workers (C6).
    - Dimensions live once in `dims`, keyed by a 64-bit hash of the dimension values (`dim_hash`, computed by the
      recorder), inserted with `INSERT OR IGNORE`, so rollup rows carry 8 bytes instead of 11 text columns.
    - Compaction recomputes whole buckets: `DELETE` the target bucket, then `INSERT ... SELECT ... GROUP BY` from
      the finer level. Recomputing is idempotent (running it twice gives the same rows) and picks up late writes,
      so the job recomputes the last two compacted hours (and the last day and month in the same zone) on every
      run. A bucket is compacted only once it is closed: its end is at least `grace_s` (two flush intervals plus a
      margin) in the past for hours, and the finer level is complete up to its end for days and months.
    - Gaps are skipped with an index seek (`min(bucket_start) >= cursor`), so a leader that was down for days
      catches up at most `max_buckets` buckets per run without scanning empty time.
    - Days and months use local midnights in `ui_timezone`. A zone whose midnight is not on a UTC hour (half-hour
      zones) takes the partial hours at the edges from minute rows. After a zone change the first new day starts
      where the last old day ended, so no hour is counted twice or lost; older rows keep their old zone (plan 6.4).
    - Client tables: each closed minute keeps its top `max_ip_activity_records` IPs and `max_caller_records`
      places, the rest summed into one `other` row (reusing `storage.retention.cap_client_rows`); only then are
      minutes rolled into hours and hours into local days, each capped the same way. A third type, `pair`
      (`PAIR_CLIENT_TYPE`, key `<ip>|<place>`), records which IP called as which place (v1's peer columns) and is
      capped like the IPs.

What to read next
    `roxy/metrics/histograms.py` (the merge function), `roxy/metrics/jobs.py` (the leader job that calls
    `compact_all`), then `roxy/metrics/queries.py` (how readers combine the levels).
"""

from __future__ import annotations

import sqlite3
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from roxy.metrics.histograms import SQL_SUM, register_sql_functions
from roxy.storage import retention

HOUR_S = 3600
DAY_S = 86_400

ROLLUP_SUMS: tuple[str, ...] = (
    "requests",
    "caller_bytes_in",
    "caller_bytes_out",
    "upstream_calls",
    "upstream_bytes_in",
    "upstream_bytes_out",
    "errors",
)
ROLLUP_HISTS: tuple[str, ...] = ("latency_hist", "queue_wait_hist")
DIM_COLUMNS: tuple[str, ...] = (
    "endpoint_template",
    "template_version",
    "host",
    "method",
    "egress",
    "outcome",
    "reason_code",
    "status",
    "source",
    "cache_state",
    "auth_class",
)
CLIENT_SUMS: tuple[str, ...] = ("requests", "refused", "served", "bytes")
EGRESS_SUMS: tuple[str, ...] = ("requests", "req_bytes", "resp_bytes", "overhead_bytes")

DEFAULT_ZONE = "America/New_York"


# ------------------------------------------------------------------------------------------------- time


def zone(name: str | None) -> ZoneInfo:
    """The `ZoneInfo` for `name`, or UTC when the name is empty or unknown."""
    try:
        return ZoneInfo(name or "UTC")
    except (ZoneInfoNotFoundError, ValueError):
        return ZoneInfo("UTC")


def _local_midnight(day: date, tz: ZoneInfo) -> int:
    return int(datetime(day.year, day.month, day.day, tzinfo=tz).timestamp())


def bucket_floor(ts: float, unit: str, tz: ZoneInfo | None = None) -> int:
    """Start of the bucket containing `ts`: minute and hour in UTC, day, week (ISO, Monday), month and year at
    local midnight in `tz`."""
    t = int(ts)
    if unit == "minute":
        return t - t % 60
    if unit == "hour":
        return t - t % HOUR_S
    tz = tz or ZoneInfo("UTC")
    local = datetime.fromtimestamp(t, tz).date()
    if unit == "day":
        return _local_midnight(local, tz)
    if unit == "week":
        return _local_midnight(local - timedelta(days=local.weekday()), tz)
    if unit == "month":
        return _local_midnight(local.replace(day=1), tz)
    if unit == "year":
        return _local_midnight(local.replace(month=1, day=1), tz)
    raise ValueError(f"unknown bucket unit {unit!r}")


def bucket_next(start: float, unit: str, tz: ZoneInfo | None = None) -> int:
    """The first bucket boundary strictly after `start` (handles 23 and 25 hour days)."""
    t = int(start)
    if unit == "minute":
        return t - t % 60 + 60
    if unit == "hour":
        return t - t % HOUR_S + HOUR_S
    tz = tz or ZoneInfo("UTC")
    local = datetime.fromtimestamp(t, tz).date()
    if unit == "day":
        return _local_midnight(local + timedelta(days=1), tz)
    if unit == "week":
        return _local_midnight(local - timedelta(days=local.weekday()) + timedelta(days=7), tz)
    if unit == "month":
        nxt = date(local.year + 1, 1, 1) if local.month == 12 else date(local.year, local.month + 1, 1)
        return _local_midnight(nxt, tz)
    if unit == "year":
        return _local_midnight(date(local.year + 1, 1, 1), tz)
    raise ValueError(f"unknown bucket unit {unit!r}")


# ------------------------------------------------------------------------------------------ write side


@dataclass(slots=True)
class RollupDelta:
    """Counters for one (minute, dimension combination), as accumulated by one worker since its last flush."""

    bucket_start: int
    dim_hash: int
    dims: tuple[Any, ...]  # values in DIM_COLUMNS order
    requests: int = 0
    caller_bytes_in: int = 0
    caller_bytes_out: int = 0
    upstream_calls: int = 0
    upstream_bytes_in: int = 0
    upstream_bytes_out: int = 0
    errors: int = 0
    latency_hist: bytes | None = None
    queue_wait_hist: bytes | None = None


_ROLLUP_UPSERT = f"""
INSERT INTO rollup_minute (bucket_start, dim_hash, {", ".join(ROLLUP_SUMS)}, latency_hist, queue_wait_hist)
VALUES ({", ".join("?" for _ in range(2 + len(ROLLUP_SUMS) + 2))})
ON CONFLICT (bucket_start, dim_hash) DO UPDATE SET
    {", ".join(f"{c} = {c} + excluded.{c}" for c in ROLLUP_SUMS)},
    latency_hist = roxy_hist_merge(latency_hist, excluded.latency_hist),
    queue_wait_hist = roxy_hist_merge(queue_wait_hist, excluded.queue_wait_hist)
"""  # noqa: S608 (column names are module constants)

_DIMS_INSERT = (
    f"INSERT OR IGNORE INTO dims (dim_hash, {', '.join(DIM_COLUMNS)}) "  # noqa: S608 (module constants)
    f"VALUES ({', '.join('?' for _ in range(1 + len(DIM_COLUMNS)))})"
)


def write_rollups(conn: sqlite3.Connection, deltas: list[RollupDelta]) -> None:
    """Batch writer handler for `rollup_minute` (and the `dims` rows the deltas refer to)."""
    register_sql_functions(conn)
    seen: dict[int, tuple[Any, ...]] = {}
    for d in deltas:
        seen.setdefault(d.dim_hash, d.dims)
    conn.executemany(_DIMS_INSERT, [(h, *dims) for h, dims in seen.items()])
    conn.executemany(
        _ROLLUP_UPSERT,
        [
            (
                d.bucket_start,
                d.dim_hash,
                d.requests,
                d.caller_bytes_in,
                d.caller_bytes_out,
                d.upstream_calls,
                d.upstream_bytes_in,
                d.upstream_bytes_out,
                d.errors,
                d.latency_hist,
                d.queue_wait_hist,
            )
            for d in deltas
        ],
    )


PAIR_CLIENT_TYPE = "pair"
"""The third client type: one IP calling as one place (v1's peer columns "IPs" and "Places", finding parity-7).

Pair rows live in the same client tables as `ip` and `place` rows, so the same batch upserts, compaction, top-N caps
(`max_ip_activity_records` per bucket, the rest folded into `other`), retention and the "client activity" reset cover
them; a peer count therefore never exceeds what the caps kept (a lower bound under a flood of pairs)."""
PAIR_SEPARATOR = "|"
"""Between the IP and the place in a pair key. A normalized address never holds it; a place id (caller text) may,
so a key is split at the FIRST separator."""


def pair_key(ip: str, place: str) -> str | None:
    """The `pair` client key of one IP and one place, or None when either is missing or the IP holds the separator."""
    if not ip or not place or PAIR_SEPARATOR in ip:
        return None
    return f"{ip}{PAIR_SEPARATOR}{place}"


def split_pair(key: str) -> tuple[str, str] | None:
    """(ip, place) of a pair key, or None for the folded `other` row or any malformed key."""
    ip, sep, place = str(key).partition(PAIR_SEPARATOR)
    return (ip, place) if sep and ip and place else None


@dataclass(slots=True)
class ClientDelta:
    """One client's activity in one minute, from one worker."""

    bucket_start: int
    client_type: str  # "ip", "place" or "pair" (`PAIR_CLIENT_TYPE`)
    client_key: str
    requests: int = 0
    refused: int = 0
    served: int = 0
    bytes: int = 0
    top_endpoint: str | None = None


def write_clients(conn: sqlite3.Connection, deltas: list[ClientDelta]) -> None:
    """Batch writer handler for `client_minute`.

    `top_endpoint` across workers is approximate: a worker's batch replaces the stored value only when that batch
    alone has more requests than the row had before (the exact busiest endpoint would need per-endpoint rows).
    """
    conn.executemany(
        """
        INSERT INTO client_minute (bucket_start, client_type, client_key, requests, refused, served, bytes,
                                   top_endpoint)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (bucket_start, client_type, client_key) DO UPDATE SET
            requests = requests + excluded.requests, refused = refused + excluded.refused,
            served = served + excluded.served, bytes = bytes + excluded.bytes,
            top_endpoint = CASE WHEN excluded.requests > requests THEN excluded.top_endpoint
                                ELSE coalesce(top_endpoint, excluded.top_endpoint) END
        """,
        [
            (d.bucket_start, d.client_type, d.client_key, d.requests, d.refused, d.served, d.bytes, d.top_endpoint)
            for d in deltas
        ],
    )


@dataclass(slots=True)
class EgressDelta:
    """Byte accounting for one egress path in one minute (plan 8.3)."""

    bucket_start: int
    egress: str
    requests: int = 0
    req_bytes: int = 0
    resp_bytes: int = 0
    overhead_bytes: int = 0


def write_egress_usage(conn: sqlite3.Connection, deltas: list[EgressDelta]) -> None:
    """Batch writer handler for minute rows of `egress_usage`."""
    conn.executemany(
        """
        INSERT INTO egress_usage (bucket_start, egress, granularity, requests, req_bytes, resp_bytes, overhead_bytes)
        VALUES (?, ?, 'minute', ?, ?, ?, ?)
        ON CONFLICT (bucket_start, egress, granularity) DO UPDATE SET
            requests = requests + excluded.requests, req_bytes = req_bytes + excluded.req_bytes,
            resp_bytes = resp_bytes + excluded.resp_bytes, overhead_bytes = overhead_bytes + excluded.overhead_bytes
        """,
        [(d.bucket_start, d.egress, d.requests, d.req_bytes, d.resp_bytes, d.overhead_bytes) for d in deltas],
    )


# ------------------------------------------------------------------------------------------ compaction


@dataclass(frozen=True, slots=True)
class LevelSpec:
    """How one level is computed from the one below it.

    `src`/`dst` are table names; `src_filter`/`dst_filter` select rows of a shared table (`egress_usage` keeps all
    granularities in one table); `edge_src` is the finer table used for partial hours at the edges of a local day
    in a half-hour zone. `bare_top` names the column picked from the busiest source row (client `top_endpoint`).
    """

    name: str
    unit: str  # "hour", "day" or "month"
    src: str
    dst: str
    keys: tuple[str, ...]
    sums: tuple[str, ...]
    hists: tuple[str, ...] = ()
    has_tz: bool = False
    src_filter: str = ""
    dst_filter: str = ""
    dst_consts: tuple[tuple[str, str], ...] = ()  # (column, SQL literal) added to every inserted row
    edge_src: str | None = None
    edge_filter: str = ""
    bare_top: str | None = None
    recompute_last: int = 1


LEVELS: dict[str, LevelSpec] = {
    "rollup_hour": LevelSpec(
        "rollup_hour", "hour", "rollup_minute", "rollup_hour", ("dim_hash",), ROLLUP_SUMS, ROLLUP_HISTS,
        recompute_last=2,
    ),
    "rollup_day": LevelSpec(
        "rollup_day", "day", "rollup_hour", "rollup_day", ("dim_hash",), ROLLUP_SUMS, ROLLUP_HISTS,
        has_tz=True, edge_src="rollup_minute",
    ),
    "rollup_month": LevelSpec(
        "rollup_month", "month", "rollup_day", "rollup_month", ("dim_hash",), ROLLUP_SUMS, ROLLUP_HISTS, has_tz=True
    ),
    "client_hour": LevelSpec(
        "client_hour", "hour", "client_minute", "client_hour", ("client_type", "client_key"), CLIENT_SUMS,
        bare_top="top_endpoint", recompute_last=2,
    ),
    "client_day": LevelSpec(
        "client_day", "day", "client_hour", "client_day", ("client_type", "client_key"), CLIENT_SUMS,
        edge_src="client_minute", bare_top="top_endpoint",
    ),
    "egress_hour": LevelSpec(
        "egress_hour", "hour", "egress_usage", "egress_usage", ("egress",), EGRESS_SUMS,
        src_filter="granularity = 'minute'", dst_filter="granularity = 'hour'",
        dst_consts=(("granularity", "'hour'"),), recompute_last=2,
    ),
    "egress_day": LevelSpec(
        "egress_day", "day", "egress_usage", "egress_usage", ("egress",), EGRESS_SUMS,
        src_filter="granularity = 'hour'", dst_filter="granularity = 'day'", dst_consts=(("granularity", "'day'"),),
        edge_src="egress_usage", edge_filter="granularity = 'minute'",
    ),
    "egress_month": LevelSpec(
        "egress_month", "month", "egress_usage", "egress_usage", ("egress",), EGRESS_SUMS,
        src_filter="granularity = 'day'", dst_filter="granularity = 'month'",
        dst_consts=(("granularity", "'month'"),),
    ),
}  # fmt: skip
"""Every compaction step, by name. Table and column names here are the only identifiers interpolated into SQL."""


def _and(*clauses: str) -> str:
    parts = [c for c in clauses if c]
    return " AND ".join(parts) if parts else "1"


def watermark(conn: sqlite3.Connection, spec: LevelSpec) -> tuple[int, str | None] | None:
    """`(bucket_start, tz)` of the newest compacted bucket of this level, or None."""
    tz_col = ", tz" if spec.has_tz else ", NULL"
    row = conn.execute(
        f"SELECT bucket_start{tz_col} FROM {spec.dst} WHERE {_and(spec.dst_filter)} "  # noqa: S608 (LevelSpec)
        "ORDER BY bucket_start DESC LIMIT 1"
    ).fetchone()
    if row is None:
        return None
    return int(row[0]), (str(row[1]) if row[1] is not None else None)


def _next_source_start(conn: sqlite3.Connection, spec: LevelSpec, cursor: int | None) -> int | None:
    where = _and(spec.src_filter, "bucket_start >= ?" if cursor is not None else "")
    params: tuple[Any, ...] = (cursor,) if cursor is not None else ()
    row = conn.execute(f"SELECT min(bucket_start) FROM {spec.src} WHERE {where}", params).fetchone()  # noqa: S608
    return int(row[0]) if row is not None and row[0] is not None else None


def recompute_bucket(
    conn: sqlite3.Connection, spec: LevelSpec, start: int, end: int, tz_name: str | None = None
) -> int:
    """Replace the `spec.dst` bucket that starts at `start` with the sum of the source rows in `[start, end)`.

    Idempotent. Returns the number of rows written.
    """
    register_sql_functions(conn)
    carried = (*spec.keys, *spec.sums, *spec.hists, *((spec.bare_top,) if spec.bare_top else ()))
    inner_cols = ", ".join(carried)
    range_where = _and(spec.src_filter, "bucket_start >= ? AND bucket_start < ?")
    pieces = [f"SELECT {inner_cols} FROM {spec.src} WHERE {range_where}"]  # noqa: S608 (LevelSpec identifiers)
    inner_start, inner_end = start, end
    edge_params: list[Any] = []
    if spec.edge_src is not None and (start % HOUR_S or end % HOUR_S):
        # A local day in a half-hour zone: whole UTC hours from the hour level, the partial hours from minutes.
        inner_start = start if start % HOUR_S == 0 else start - start % HOUR_S + HOUR_S
        inner_end = end - end % HOUR_S
        edge_where = _and(
            spec.edge_filter, "((bucket_start >= ? AND bucket_start < ?) OR (bucket_start >= ? AND bucket_start < ?))"
        )
        pieces.append(f"SELECT {inner_cols} FROM {spec.edge_src} WHERE {edge_where}")  # noqa: S608
        edge_params = [start, min(inner_start, end), max(inner_end, start), end]
    # Neutral aliases (k0, v0, h0, t0) so an aggregate such as max(requests) always reads the source column.
    grouped_cols = ["? AS b"]
    grouped_cols += [f"{k} AS k{i}" for i, k in enumerate(spec.keys)]
    grouped_cols += [f"sum({c}) AS v{i}" for i, c in enumerate(spec.sums)]
    grouped_cols += [f"{SQL_SUM}({h}) AS h{i}" for i, h in enumerate(spec.hists)]
    if spec.bare_top:
        # SQLite "bare column" rule: with exactly one max() in the query, the other plain column comes from the
        # row that had the maximum, so t0 is the busiest source row's top endpoint.
        grouped_cols += ["max(requests) AS busiest", f"{spec.bare_top} AS t0"]
    keys = ", ".join(spec.keys)
    grouped = f"SELECT {', '.join(grouped_cols)} FROM ({' UNION ALL '.join(pieces)}) GROUP BY {keys}"  # noqa: S608
    out_cols = ["bucket_start", *spec.keys, *spec.sums, *spec.hists]
    picked = ["b", *(f"k{i}" for i in range(len(spec.keys))), *(f"v{i}" for i in range(len(spec.sums)))]
    picked += [f"h{i}" for i in range(len(spec.hists))]
    if spec.bare_top:
        out_cols.append(spec.bare_top)
        picked.append("t0")
    extra_params: list[Any] = []
    if spec.has_tz:
        out_cols.append("tz")
        picked.append("?")
        extra_params.append(tz_name or "UTC")
    for col, literal in spec.dst_consts:
        out_cols.append(col)
        picked.append(literal)
    conn.execute(f"DELETE FROM {spec.dst} WHERE {_and(spec.dst_filter, 'bucket_start = ?')}", (start,))  # noqa: S608
    sql = (
        f"INSERT INTO {spec.dst} ({', '.join(out_cols)}) "  # noqa: S608 (identifiers from LevelSpec)
        f"SELECT {', '.join(picked)} FROM ({grouped})"
    )
    params = [*extra_params, start, inner_start, max(inner_start, inner_end), *edge_params]
    return conn.execute(sql, params).rowcount


BucketHook = Callable[[sqlite3.Connection, int, int], Any]
"""Runs inside a bucket's compaction transaction with `(conn, start, end)` (client caps use it)."""


@dataclass(slots=True)
class LevelResult:
    """What one level's compaction did in one run."""

    level: str
    buckets: list[int] = field(default_factory=list)
    complete_until: int = 0  # every bucket ending at or before this is compacted (input for the next level)


Write = Callable[[Callable[[sqlite3.Connection], Any]], Awaitable[Any]]
"""Runs a function in a metrics.db write transaction (the leader passes a fenced write)."""


async def compact_level(
    write: Write,
    spec: LevelSpec,
    *,
    closed_until: int,
    tz_name: str | None = None,
    not_before: int | None = None,
    max_buckets: int = 48,
    prepare: BucketHook | None = None,
    finish: BucketHook | None = None,
) -> LevelResult:
    """Compact every closed bucket of `spec` that is new or due for recomputation, one transaction per bucket.

    A bucket `[start, end)` is compacted when `end <= closed_until`. `not_before` keeps recomputation away from
    source rows that retention may already have pruned. Returns the buckets written and how far the level is
    complete.
    """
    tz = zone(tz_name) if spec.unit != "hour" else None
    result = LevelResult(spec.name, complete_until=closed_until)
    mark = await write(lambda conn: watermark(conn, spec))
    cursor: int | None = None
    partial_start: int | None = None
    if mark is not None:
        last_start, last_tz = mark
        if spec.unit == "hour":
            cursor = last_start - (spec.recompute_last - 1) * HOUR_S
        elif not spec.has_tz or (last_tz or "UTC") == (tz_name or "UTC"):
            cursor = last_start  # recompute the newest bucket (late writes), then go on
        else:
            # The zone changed: start the first new bucket where the last old one ended (no overlap, no gap).
            cursor = bucket_next(last_start, spec.unit, zone(last_tz))
            partial_start = cursor
    if not_before is not None:
        floor = not_before if spec.unit != "hour" or not_before % HOUR_S == 0 else bucket_next(not_before, "hour")
        cursor = floor if cursor is None else max(cursor, floor)
    for _ in range(max_buckets):

        def step(conn: sqlite3.Connection, cursor: int | None = cursor, partial: int | None = partial_start) -> Any:
            found = _next_source_start(conn, spec, cursor)
            if found is None:
                return None
            if partial is not None and found < bucket_next(partial, spec.unit, tz):
                start = partial
            else:
                start = bucket_floor(max(found, cursor) if cursor is not None else found, spec.unit, tz)
                if cursor is not None and start < cursor:
                    start = cursor
            end = bucket_next(start, spec.unit, tz)
            if end > closed_until:
                return None
            if prepare is not None:
                prepare(conn, start, end)
            recompute_bucket(conn, spec, start, end, tz_name)
            if finish is not None:
                finish(conn, start, end)
            return start, end

        done = await write(step)
        if done is None:
            return result
        start, end = done
        result.buckets.append(start)
        cursor, partial_start = end, None
    # Stopped at max_buckets: the level is only complete up to the last bucket written.
    result.complete_until = cursor if cursor is not None else closed_until
    return result


# ------------------------------------------------------------------------------------------- client caps


@dataclass(frozen=True, slots=True)
class ClientCaps:
    """Top clients kept per bucket and type (plan 6.4, 6.10): `max_ip_activity_records`, `max_caller_records`."""

    ips: int = 500
    places: int = 500


def cap_clients(conn: sqlite3.Connection, table: str, caps: ClientCaps, start: int, end: int) -> int:
    """Fold every client beyond the top N of each bucket in `[start, end)` into that bucket's `other` row."""
    folded = 0
    while True:
        step = retention.cap_client_rows(
            conn,
            table,
            keep_top=caps.ips,
            keep_top_places=caps.places,
            closed_before=end,
            lookback_s=max(1, end - start),
            limit=retention.BATCH_ROWS,
        )
        folded += step
        if step < retention.BATCH_ROWS:
            return folded


# ------------------------------------------------------------------------------------------- one full run


@dataclass(frozen=True, slots=True)
class CompactionConfig:
    """Settings for one compaction run (read live by the job)."""

    tz_name: str = DEFAULT_ZONE
    grace_s: int = 120
    minute_retention_days: int = 14
    client_minute_retention_days: int = 3
    caps: ClientCaps = field(default_factory=ClientCaps)
    activity_tracking: bool = True
    max_buckets: int = 48


async def compact_all(write: Write, now_s: float, config: CompactionConfig) -> dict[str, list[int]]:
    """The leader's minute job: cap closed client minutes, then compact every level in dependency order."""
    report: dict[str, list[int]] = {}
    closed = int(now_s) - config.grace_s
    hour_floor = int(now_s) - config.minute_retention_days * DAY_S + HOUR_S
    client_floor = int(now_s) - config.client_minute_retention_days * DAY_S + HOUR_S

    if config.activity_tracking:
        # Recently closed minutes first, so the minute table holds at most N + 1 rows per type per minute.
        recent_end = bucket_floor(closed, "minute")
        await write(lambda conn: cap_clients(conn, "client_minute", config.caps, recent_end - 15 * 60, recent_end))

    hours = await compact_level(
        write, LEVELS["rollup_hour"], closed_until=closed, not_before=hour_floor, max_buckets=config.max_buckets
    )
    report["rollup_hour"] = hours.buckets
    days = await compact_level(
        write,
        LEVELS["rollup_day"],
        closed_until=hours.complete_until,
        tz_name=config.tz_name,
        max_buckets=config.max_buckets,
    )
    report["rollup_day"] = days.buckets
    months = await compact_level(
        write, LEVELS["rollup_month"], closed_until=days.complete_until, tz_name=config.tz_name, max_buckets=12
    )
    report["rollup_month"] = months.buckets

    egress_hours = await compact_level(
        write, LEVELS["egress_hour"], closed_until=closed, not_before=hour_floor, max_buckets=config.max_buckets
    )
    report["egress_hour"] = egress_hours.buckets
    egress_days = await compact_level(
        write,
        LEVELS["egress_day"],
        closed_until=egress_hours.complete_until,
        tz_name=config.tz_name,
        max_buckets=config.max_buckets,
    )
    report["egress_day"] = egress_days.buckets
    egress_months = await compact_level(
        write, LEVELS["egress_month"], closed_until=egress_days.complete_until, tz_name=config.tz_name, max_buckets=12
    )
    report["egress_month"] = egress_months.buckets

    if config.activity_tracking:
        client_hours = await _compact_clients(write, "client_hour", closed, None, client_floor, config)
        report["client_hour"] = client_hours.buckets
        client_days = await _compact_clients(
            write, "client_day", client_hours.complete_until, config.tz_name, None, config
        )
        report["client_day"] = client_days.buckets
    return report


async def _compact_clients(
    write: Write, level: str, closed_until: int, tz_name: str | None, not_before: int | None, config: CompactionConfig
) -> LevelResult:
    """Client levels: cap the source rows of each bucket, compact, then cap the new bucket (top N plus `other`)."""
    spec = LEVELS[level]
    caps = config.caps

    def prepare(conn: sqlite3.Connection, start: int, end: int) -> None:
        cap_clients(conn, "client_minute", caps, start, end)  # plan 6.4: minutes are capped before they roll up
        if spec.src != "client_minute":
            cap_clients(conn, spec.src, caps, start, end)

    def finish(conn: sqlite3.Connection, start: int, end: int) -> None:
        cap_clients(conn, spec.dst, caps, start, end)

    return await compact_level(
        write,
        spec,
        closed_until=closed_until,
        tz_name=tz_name,
        not_before=not_before,
        max_buckets=config.max_buckets,
        prepare=prepare,
        finish=finish,
    )
