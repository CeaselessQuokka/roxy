"""The reads moved onto the metrics schema 9 indexes give the numbers the JSON reads gave (plan 6.7, P6).

What this is
    Unit tests over temp databases (`dbs`, migrated to the newest schema) for the gaps_latency lane
    (`.remake/p11_reports/gaps_latency.md`, metrics migration `0009_dashboard_read_indexes.sql`):
    - `queries.refusal_reasons`, `message_source_split`, `returned_reasons` and `reason_counts` (message sources,
      distinct clients, unattributed counts, first and last times, the newest status and path) against the reads
      they replaced, which parsed `detail_json` of every refusal and failure event of the window;
    - the distinct client count past the seek budget (the ordered pass) equals the seek count;
    - `read_upstream.failure_log` groups, `read_clients.client_refusals` and `recent_live` against the old SQL;
    - `queries.client_table_sync` for addresses through `client_minute_ip_rows` (key order) equals the time-ordered
      read, top endpoints and ties included, and the place peers through `*_pair_place` equal the full scan;
    - each read names the index it was written for (`EXPLAIN QUERY PLAN`), so an edit that loses one fails here;
    - a detail that is not JSON (Roxy never writes one) still inserts, and reads as an absent field.

Why it exists
    Each change trades how a number is read for speed; the number must not move (one source of truth, P6). The old
    reads are copied here as they were (not imported), so the comparison does not move with the code.

How it works
    Events are inserted as the recorder writes them (its column list, JSON details), with folded rows, rows without
    a client or a message source, a reason in both types and one in one type only, over three days; client rows go
    through the batch writer's `write_clients`. Every comparison runs over several windows.

What to read next
    `roxy/storage/migrations/metrics/0009_dashboard_read_indexes.sql`, `roxy/metrics/queries.py` (`_reason_events`,
    `_reason_clients`), tests/unit/metrics/test_metrics_dashboard_latency.py (the latency lane's comparisons).
"""

from __future__ import annotations

import json
import random
import sqlite3
from typing import Any

import pytest

from roxy.metrics import queries as q
from roxy.metrics import read_client_extras, read_clients, read_upstream
from roxy.metrics.recorder import dims_hash
from roxy.metrics.rollups import ClientDelta, RollupDelta, write_clients, write_rollups

NY = "America/New_York"
END = 1_760_000_400  # a whole hour (UTC)
DAY_MS = 86_400_000
WINDOWS = ("1h", "24h", "7d")
REFUSAL_REASONS = ("throttle", "header_rule", "flood")
FAILURE_REASONS = ("upstream_5xx", "upstream_timeout")
SHARED_REASON = "deadline"  # written as a refusal and as a failure


def _row(at_ms: int, kind: str, reason: str | None, detail: Any, *, ip: str | None = None, place: str | None = None,
         template: str = "games.roblox.com/v1/x") -> tuple[Any, ...]:  # fmt: skip
    text = detail if isinstance(detail, str) or detail is None else json.dumps(detail, sort_keys=True)
    return (at_ms, kind, "warn", reason, ip, place, template, text)


def _insert(conn: sqlite3.Connection, rows: list[tuple[Any, ...]]) -> None:
    conn.executemany(  # the recorder's column list (`metrics/recorder.py write_events`): no generated column named
        "INSERT INTO events (at_ms, type, severity, reason_code, ip_hash, place, endpoint_template, detail_json) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        rows,
    )


def _events(seed: int = 21) -> list[tuple[Any, ...]]:
    rng = random.Random(seed)
    rows = []
    start = (END - 3 * 86_400) * 1000
    hashes = [f"{n:016x}" for n in range(60)]
    places = ["9100001", "9100002", "9100003", None]
    for n in range(6000):
        at = start + rng.randrange(3 * DAY_MS)
        roll = rng.random()
        if roll < 0.55:
            kind, reason = "refusal", rng.choice(REFUSAL_REASONS)
        elif roll < 0.9:
            kind, reason = "failure", rng.choice(FAILURE_REASONS)
        else:
            kind, reason = rng.choice(("refusal", "failure")), SHARED_REASON
        detail: dict[str, Any] = {"status": rng.choice([429, 403, 502, 503, 504]), "method": "GET"}
        if kind == "refusal" or rng.random() < 0.3:
            detail["message_source"] = rng.choice(["default", "custom", "roxy", "roblox"])
        if rng.random() < 0.8:
            detail["path"] = f"games.roblox.com/v1/x/{n}"
        if kind == "failure":
            if rng.random() < 0.85:
                detail["egress"] = rng.choice(["direct", "rotator", "credential"])
            if rng.random() < 0.6:
                detail["upstream_status"] = rng.choice([500, 502, 503])
        ip: str | None = rng.choice(hashes)
        if rng.random() < 0.12:  # a row folded over the event budget: a count, no client, no path
            detail = {k: v for k, v in detail.items() if k in ("status", "message_source", "egress")}
            detail.update({"aggregated": True, "count": rng.randint(2, 9)})
            ip = None
            at = at // 60_000 * 60_000
        rows.append(_row(at, kind, reason, detail, ip=ip, place=rng.choice(places)))
    rows.append(_row(start + 5, "refusal", None, {"status": 400}))  # no reason at all (never written by the recorder)
    rows.append(_row(start + 6, "failure", "upstream_connect", None))  # no detail at all
    return rows


def _rollups_for(rows: list[tuple[Any, ...]]) -> list[RollupDelta]:
    """The rollup minute of every event row (the recorder writes both), so the rollup reasons list them."""
    deltas = []
    for at_ms, kind, _severity, reason, *_rest in rows:
        if reason is None:
            continue
        outcome = "refused" if kind == "refusal" else "failed"
        dims = ("games.roblox.com/v1/x", 1, "games.roblox.com", "GET", "none", outcome, reason, 429, "roxy", "NA",
                "anon")  # fmt: skip
        minute = at_ms // 1000 - (at_ms // 1000) % 60
        deltas.append(RollupDelta(minute, dims_hash(dims), dims, requests=1))
    return deltas


@pytest.fixture
async def seeded(dbs: Any) -> Any:
    rows = _events()
    dbs.metrics.write_sync(lambda conn: _insert(conn, rows))
    deltas = _rollups_for(rows)
    dbs.metrics.write_sync(lambda conn: write_rollups(conn, deltas))
    return dbs


# ------------------------------------------------------------------------------------------- the old reads


OLD_EVENTS = "FROM events WHERE type IN ('refusal', 'failure') AND at_ms >= ? AND at_ms < ?"


def _old_split(conn: sqlite3.Connection, window: q.Window) -> dict[str, dict[str, int]]:
    split: dict[str, dict[str, int]] = {}
    for r in conn.execute(
        "SELECT reason_code, coalesce(json_extract(detail_json, '$.message_source'), '') AS src, "
        f"sum(coalesce(json_extract(detail_json, '$.count'), 1)) AS n {OLD_EVENTS} GROUP BY reason_code, src",
        (window.start * 1000, window.end * 1000),
    ):
        found = split.setdefault(str(r["reason_code"]), {})
        key = str(r["src"]) or "unknown"
        found[key] = found.get(key, 0) + int(r["n"])
    return split


def _old_facts(conn: sqlite3.Connection, window: q.Window) -> dict[str, tuple[Any, ...]]:
    return {
        str(r["reason_code"]): (int(r["clients"] or 0), int(r["unattributed"] or 0), r["first_ms"], r["last_ms"])
        for r in conn.execute(
            "SELECT reason_code, count(DISTINCT ip_hash) AS clients, min(at_ms) AS first_ms, max(at_ms) AS last_ms, "
            "sum(CASE WHEN ip_hash IS NULL THEN coalesce(json_extract(detail_json, '$.count'), 1) ELSE 0 END) "
            f"AS unattributed {OLD_EVENTS} GROUP BY reason_code",
            (window.start * 1000, window.end * 1000),
        )
    }


def _old_newest(conn: sqlite3.Connection, window: q.Window, path: str) -> dict[str, Any]:
    found = conn.execute(
        "SELECT reason_code, v FROM (SELECT reason_code, json_extract(detail_json, ?) AS v, "
        "row_number() OVER (PARTITION BY reason_code ORDER BY at_ms DESC, id DESC) AS rank FROM events "
        "WHERE type IN ('refusal', 'failure') AND at_ms >= ? AND at_ms < ? "
        "AND json_extract(detail_json, ?) IS NOT NULL) WHERE rank = 1",
        (path, window.start * 1000, window.end * 1000, path),
    ).fetchall()
    return {str(r["reason_code"]): r["v"] for r in found}


def _windows() -> list[q.Window]:
    out = [q.resolve_window(key, now=END + 30 - shift, tz=NY) for key in WINDOWS for shift in (0, 7 * 3600 + 120)]
    out.append(q.Window(END - 86_400 - 37, END - 3600 + 11, "minute", NY))  # edges inside minutes
    return out


# ------------------------------------------------------------------------------------------------ the tests


async def test_refusal_reasons_equal_the_json_reads(seeded: Any) -> None:
    def read(conn: sqlite3.Connection) -> list[tuple[Any, ...]]:
        return [
            (q.refusal_reasons(conn, w), _old_split(conn, w), _old_facts(conn, w), _old_newest(conn, w, "$.status"),
             _old_newest(conn, w, "$.path"))
            for w in _windows()
        ]  # fmt: skip

    checked = 0
    for rows, split, facts, statuses, paths in await seeded.metrics.read(read):
        assert rows
        for row in rows:
            name = str(row["reason"])
            assert row["message_source"] == split.get(name, {})
            clients, unattributed, first_ms, last_ms = facts.get(name, (0, 0, None, None))
            assert (row["clients"], row["unattributed"], row["first_ms"], row["last_ms"]) == (
                clients, unattributed, first_ms, last_ms
            )  # fmt: skip
            status = statuses.get(name)
            assert row["last_status"] == (int(status) if isinstance(status, int | float) else None)
            assert row["last_path"] == (str(paths[name])[:200] if paths.get(name) is not None else None)
            checked += 1
    assert checked > 20
    assert any(row["unattributed"] for rows, *_ in await seeded.metrics.read(read) for row in rows)


async def test_split_returned_and_last_times_equal_the_json_reads(seeded: Any) -> None:
    def read(conn: sqlite3.Connection) -> list[tuple[Any, ...]]:
        out = []
        for w in _windows():
            reasons = q.refusal_reasons(conn, w)
            listed = [str(r["reason"]) for r in reasons]
            out.append(
                (q.message_source_split(conn, w), _old_split(conn, w), q.returned_reasons(conn, w), listed,
                 q.reason_counts(conn, w, [*listed, "no_such_reason"]), _old_facts(conn, w))
            )  # fmt: skip
        return out

    results = await seeded.metrics.read(read)
    for split, old_split, returned, listed, counts, facts in results:
        assert split == old_split  # every reason of the events, the one without a reason included
        summed: dict[str, int] = {}
        for reason in listed:
            for source, count in old_split.get(reason, {}).items():
                summed[source] = summed.get(source, 0) + count
        assert returned == summed
        assert {name: row["last_ms"] for name, row in counts.items()} == {
            name: facts.get(name, (0, 0, None, None))[3] for name in listed
        }
    assert any("None" in split for split, *_rest in results)  # the row without a reason


async def test_distinct_clients_past_the_seek_budget_equal_the_seek_count(
    seeded: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    def counts(conn: sqlite3.Connection) -> list[tuple[int, int]]:
        w = q.resolve_window("7d", now=END + 30, tz=NY)
        return [q._reason_clients(conn, reason, w.start * 1000, w.end * 1000) for reason in REFUSAL_REASONS]

    seeks = await seeded.metrics.read(counts)
    monkeypatch.setattr(q, "LOOSE_SCAN_MAX_KEYS", 3)
    ordered = await seeded.metrics.read(counts)
    assert seeks == ordered
    assert all(clients > 3 for clients, _unattributed in seeks)


async def test_failure_log_groups_equal_the_json_grouping(seeded: Any) -> None:
    def read(conn: sqlite3.Connection) -> list[tuple[Any, Any]]:
        out = []
        for w in _windows():
            start, end = w.start * 1000, w.end * 1000
            old = conn.execute(
                "SELECT json_extract(detail_json, '$.egress') AS egress, reason_code AS reason, "
                "json_extract(detail_json, '$.upstream_status') AS upstream_status, "
                "sum(coalesce(json_extract(detail_json, '$.count'), 1)) AS n, min(at_ms) AS first_ms, "
                "max(at_ms) AS last_ms, sum(CASE WHEN json_extract(detail_json, '$.aggregated') THEN "
                "coalesce(json_extract(detail_json, '$.count'), 1) ELSE 0 END) AS folded FROM events "
                "WHERE type = 'failure' AND at_ms >= ? AND at_ms < ? GROUP BY 1, 2, 3",
                (start, end),
            ).fetchall()
            out.append((read_upstream.failure_log(conn, start, end), old))
        return out

    for log, old in await seeded.metrics.read(read):
        assert log
        got = {(r["egress"], r["reason"], r["upstream_status"]): (r["count"], r["first_ms"], r["last_ms"], r["folded"])
               for r in log}  # fmt: skip
        want = {(r["egress"], r["reason"], r["upstream_status"]): (r["n"], r["first_ms"], r["last_ms"], r["folded"])
                for r in old}  # fmt: skip
        assert got == want
        assert [r["count"] for r in log] == sorted((r["count"] for r in log), reverse=True)
        assert any(key[0] is None for key in got)  # the folded rows without an egress keep their own group


async def test_one_clients_refusals_and_live_rows_equal_the_json_reads(seeded: Any) -> None:
    live = []
    for n in range(300):
        place = ["9100001", "9100002", None][n % 3]
        ip = ["203.0.113.5", "2001:db8::7", "198.51.100.9"][n % 3]
        live.append(_row(END * 1000 - 600_000 + n, "live", "cache_hit", {"ip": ip, "place": place, "n": n},
                         place=place))  # fmt: skip
    seeded.metrics.write_sync(lambda conn: _insert(conn, live))

    def read(conn: sqlite3.Connection) -> list[tuple[Any, Any]]:
        out: list[tuple[Any, Any]] = []
        w = q.resolve_window("7d", now=END + 30, tz=NY)
        for column, value in (("place", "9100001"), ("place", "9100003"), ("ip_hash", f"{7:016x}")):
            old = conn.execute(
                f"SELECT reason_code, sum(coalesce(json_extract(detail_json, '$.count'), 1)) AS n, max(at_ms) "
                f"AS last_ms FROM events WHERE type = 'refusal' AND {column} = ? AND at_ms >= ? AND at_ms < ? "
                "GROUP BY reason_code ORDER BY n DESC, reason_code",
                (value, w.start * 1000, w.end * 1000),
            ).fetchall()
            kwargs: dict[str, Any] = {column: value}
            new = read_clients.client_refusals(conn, start_ms=w.start * 1000, end_ms=w.end * 1000, **kwargs)
            out.append((sorted((r["reason"], r["count"], r["last_ms"]) for r in new), sorted(tuple(r) for r in old)))
        for kind, value in (("place", "9100001"), ("place", "no-such-place"), ("ip", "2001:db8::7"), ("ip", "x")):
            where = "json_extract(detail_json, '$.ip') = ?" if kind == "ip" else "place = ?"
            old = conn.execute(
                f"SELECT detail_json FROM events WHERE type = 'live' AND {where} ORDER BY id DESC LIMIT 7",
                (value,),
            ).fetchall()
            new = read_clients.recent_live(conn, limit=7, **{kind: value})
            out.append((new, [json.loads(r[0]) for r in old]))
        return out

    results = await seeded.metrics.read(read)
    for new, old in results:
        assert new == old
    assert results[0][0]
    assert results[3][0]
    assert results[5][0]


def _clients(seed: int = 4) -> list[ClientDelta]:
    rng = random.Random(seed)
    out = []
    ips = [f"203.0.113.{n}" for n in range(40)] + ["2001:db8::1"]
    places = [str(9100000 + n) for n in range(12)]
    for minute in range(36 * 60):
        start = END - 36 * 3600 + minute * 60
        for ip in rng.sample(ips, 12):
            requests = rng.choice([1, 2, 3, 3, 5])  # ties: the busiest minute of an address is often not unique
            out.append(ClientDelta(start, "ip", ip, requests, rng.randint(0, requests), requests, requests * 700,
                                   rng.choice(["a/x", "b/y", "c/z"])))  # fmt: skip
            place = rng.choice(places)
            out.append(ClientDelta(start, "pair", f"{ip}|{place}", requests, 0, requests, 0, None))
        for place in rng.sample(places, 6):
            out.append(ClientDelta(start, "place", place, 4, 1, 3, 2000, "a/x"))
    return out


async def test_address_sums_in_key_order_equal_the_time_ordered_read(dbs: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    deltas = _clients()
    dbs.metrics.write_sync(lambda conn: write_clients(conn, deltas))

    def tables(conn: sqlite3.Connection) -> list[Any]:
        out = []
        for key in ("1h", "6h", "24h"):
            w = q.resolve_window(key, now=END + 30, tz=NY)
            page = q.Page(sort="requests", size=250)
            out.append(q.client_table_sync(conn, w, "ip", page=page, now=END + 30, extras=True))
            out.append(q.client_table_sync(conn, w, "ip", page=q.Page(sort="requests", size=10, search="113.1"),
                                           now=END + 30))  # fmt: skip
        return out

    monkeypatch.setattr(q, "IP_KEY_ORDER_MIN_S", 0)  # every window through `client_minute_ip_rows`
    keyed = await dbs.metrics.read(tables)
    monkeypatch.setattr(q, "IP_KEY_ORDER_MIN_S", 10**9)  # every window by time, as before the index
    timed = await dbs.metrics.read(tables)
    assert keyed == timed
    assert keyed[4]["total"] == 41
    assert keyed[4]["rows"][0]["top_endpoint"] in ("a/x", "b/y", "c/z")


async def test_place_peers_through_the_place_index_equal_the_full_scan(dbs: Any) -> None:
    deltas = _clients()
    dbs.metrics.write_sync(lambda conn: write_clients(conn, deltas))

    def read(conn: sqlite3.Connection) -> tuple[Any, Any, Any, list[str]]:
        w = q.resolve_window("24h", now=END + 30, tz=NY)
        pieces = read_clients.client_pieces(conn, w)
        places = [str(9100000 + n) for n in range(12)]
        fast = read_client_extras.peer_counts(conn, "place", places, pieces)
        slow = {
            str(r[0]): int(r[1])
            for r in conn.execute(
                "SELECT substr(client_key, instr(client_key, '|') + 1) AS k, "
                "count(DISTINCT substr(client_key, 1, instr(client_key, '|') - 1)) FROM client_minute NOT INDEXED "
                "WHERE client_type = 'pair' AND bucket_start >= ? AND bucket_start < ? GROUP BY k",
                (w.start, w.end),
            )
        }
        listing = read_client_extras.peer_list(conn, "place", "9100003", pieces)
        union, params = read_client_extras._union(pieces, "substr(client_key, instr(client_key, '|') + 1) = ?", ["x"])
        plan = [str(tuple(r)[-1]) for r in conn.execute("EXPLAIN QUERY PLAN " + union, params)]
        return fast, slow, listing, plan

    fast, slow, listing, plan = await dbs.metrics.read(read)
    assert fast == slow
    assert listing["total"] == slow["9100003"]
    assert any("client_minute_pair_place" in line for line in plan)


SCHEMA_9_INDEXES = (
    "events_refusal_sources",
    "events_refusal_clients",
    "events_failure_groups",
    "events_refusal_places",
    "events_live_places",
    "events_live_ips",
)


async def test_each_read_uses_the_index_it_was_written_for(seeded: Any) -> None:
    """Every events statement of these reads (traced as SQLite ran them) is a SEARCH through a schema 9 index (or
    the type index for the newest status walk's fallback), never a scan of the events table."""

    def read(conn: sqlite3.Connection) -> list[tuple[str, str]]:
        statements: list[str] = []
        conn.set_trace_callback(statements.append)
        try:
            w = q.resolve_window("7d", now=END + 30, tz=NY)
            q.refusal_reasons(conn, w)
            q.returned_reasons(conn, w)
            q.reason_counts(conn, w, ["throttle", "upstream_5xx"])
            read_upstream.failure_log(conn, w.start * 1000, w.end * 1000)
            read_clients.client_refusals(conn, start_ms=w.start * 1000, end_ms=w.end * 1000, place="9100001")
            read_clients.recent_live(conn, place="9100001")
            read_clients.recent_live(conn, ip="203.0.113.5")
        finally:
            conn.set_trace_callback(None)
        out = []
        for sql in statements:
            if "events" not in sql or not sql.lstrip().upper().startswith(("SELECT", "WITH")):
                continue
            plan = " | ".join(str(tuple(r)[-1]) for r in conn.execute("EXPLAIN QUERY PLAN " + sql))
            out.append((sql, plan))
        return out

    plans = await seeded.metrics.read(read)
    markers = ("detail_count", "detail_message_source", "detail_ip", "detail_egress", "INDEXED BY", "k.ip")
    named = [plan for sql, plan in plans if any(marker in sql for marker in markers)]
    assert len(named) > 20
    for sql, plan in plans:
        assert "SCAN events" not in plan.replace("SCAN events USING INDEX events_failure_groups", ""), (sql, plan)
    for plan in named:
        assert any(name in plan for name in SCHEMA_9_INDEXES), plan


async def test_a_detail_that_is_not_json_still_inserts_and_reads_as_absent(dbs: Any) -> None:
    rows = [_row(1_000, "refusal", "throttle", "{not json", ip="ab"), _row(2_000, "failure", "upstream_5xx", "[1,")]
    dbs.metrics.write_sync(lambda conn: _insert(conn, rows))
    found = dbs.metrics.read_sync(
        lambda conn: [
            tuple(r)
            for r in conn.execute(
                "SELECT detail_count, detail_message_source, detail_egress, detail_aggregated FROM events ORDER BY id"
            )
        ]
    )
    assert found == [(1, "", None, None), (1, "", None, None)]
