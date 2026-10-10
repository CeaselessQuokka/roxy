"""Review round 3 fixes of the dashboard pages (group admin_pages): the read models behind the new API fields.

What this is
    Unit tests, no app: the read models the Upstream, Endpoints, Protection, Security and Cache routes gained for
    findings parity-4, parity-5, parity-6, parity-11, parity-13, parity-15 and the producers lane's page requests.
    Each runs against a freshly migrated metrics.db (the `dbs` fixture) with rows written by hand, so the edge cases
    the routes cannot easily produce are pinned: rows folded over the recorder's event budget, a rollup level other
    than minutes answering "last success", a Live row outside the window, an IPv6 network key, rule hits folded into
    hour buckets.

Why it exists
    The integration tests (`tests/integration/admin_api/test_r3_parity_*.py`) check the routes end to end through the
    real recorder; these check the honesty rules (P6: unknown is None, never a guessed zero; folded rows are labeled;
    precision is reported) and the bounds (P9) of the queries themselves.

How it works
    `_write(dbs, sql_and_params...)` writes rows in one metrics.db transaction; each test then calls one read model
    inside `Database.read`. Times are built from one fixed instant on a minute boundary.

What to read next
    `roxy/metrics/read_upstream.py`, `roxy/metrics/read_dashboard.py` (`endpoint_recency`),
    `roxy/metrics/read_protection.py` (`watch_activity`, the rule hit reads), `roxy/metrics/read_security.py` (the
    per-header clears), `roxy/cache/read_browser.py` (the shared search condition).
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

import pytest

from roxy.cache import read_browser
from roxy.cache.keys import HANDOFF_SUFFIX
from roxy.metrics import read_dashboard, read_protection, read_security, read_upstream
from roxy.metrics.queries import Window

T0 = 1_760_000_040  # on a minute boundary
HOUR0 = T0 - T0 % 3600
TEMPLATE = "games.roblox.com/v1/games"

Statement = tuple[str, Sequence[Any]]


async def _write(dbs: Any, *statements: Statement) -> None:
    def run(conn: Any) -> None:
        for sql, params in statements:
            conn.execute(sql, tuple(params))

    await dbs.metrics.write(run)


def dim(
    dim_hash: int,
    *,
    egress: str = "direct",
    outcome: str = "served_upstream",
    reason: str = "upstream_ok",
    method: str = "GET",
    template: str = TEMPLATE,
    host: str = "games.roblox.com",
    status: int = 200,
) -> Statement:
    """One `dims` row (the other dimension columns get fixed values)."""
    return (
        "INSERT INTO dims (dim_hash, endpoint_template, template_version, host, method, egress, outcome, reason_code, "
        "status, source, cache_state, auth_class) VALUES (?, ?, 1, ?, ?, ?, ?, ?, ?, 'roblox', 'MISS', 'anon')",
        (dim_hash, template, host, method, egress, outcome, reason, status),
    )


def rollup(table: str, bucket: int, dim_hash: int, requests: int = 1) -> Statement:
    return (
        f"INSERT INTO {table} (bucket_start, dim_hash, requests, upstream_calls) VALUES (?, ?, ?, ?)",
        (bucket, dim_hash, requests, requests),
    )


def event(at_ms: int, event_type: str, reason: str, detail: dict[str, Any], template: str = TEMPLATE) -> Statement:
    return (
        "INSERT INTO events (at_ms, type, severity, reason_code, endpoint_template, detail_json) "
        "VALUES (?, ?, 'warn', ?, ?, ?)",
        (at_ms, event_type, reason, template, json.dumps(detail)),
    )


# ------------------------------------------------------------------------------------------- upstream


async def test_failure_log_groups_by_egress_reason_and_status_with_the_newest_details(dbs: Any) -> None:
    ms = T0 * 1000
    first = {"status": 503, "egress": "direct", "upstream_status": 503, "path": "games.roblox.com/v1/games/1"}
    newest = {**first, "path": "games.roblox.com/v1/games/2", "method": "POST", "upstream_error": "HTTP 503"}
    await _write(
        dbs,
        event(ms, "failure", "upstream_5xx", {**first, "upstream_error": "HTTP 503"}),
        event(ms + 5000, "failure", "upstream_5xx", newest),
        event(ms + 9000, "failure", "upstream_5xx", {"status": 503, "aggregated": True, "count": 5}),
        event(ms - 3_600_000, "failure", "upstream_5xx", first),  # before the window
    )
    rows = await dbs.metrics.read(lambda conn: read_upstream.failure_log(conn, ms, ms + 60_000))
    by_egress = {row["egress"]: row for row in rows}
    direct = by_egress["direct"]
    assert (direct["count"], direct["first_ms"], direct["last_ms"], direct["folded"]) == (2, ms, ms + 5000, 0)
    assert (direct["last_path"], direct["last_method"], direct["last_status"]) == (
        "games.roblox.com/v1/games/2", "POST", 503
    )  # fmt: skip
    folded = by_egress[None]
    assert (folded["count"], folded["folded"], folded["last_path"], folded["upstream_status"]) == (5, 5, None, None)
    assert [row["egress"] for row in rows] == [None, "direct"]  # busiest group first


async def test_last_outcome_uses_the_finest_level_that_has_it_and_never_counts_options_local(dbs: Any) -> None:
    await _write(
        dbs,
        dim(1),
        dim(2, outcome="failed", reason="upstream_timeout", status=504),
        dim(3, egress="rotator"),
        dim(4, egress="credential", reason="options_local"),
        rollup("rollup_minute", T0 - 120, 1),
        rollup("rollup_minute", T0, 1),
        rollup("rollup_minute", T0 - 60, 2),
        rollup("rollup_hour", HOUR0 - 7200, 3),
        rollup("rollup_minute", T0, 4),
    )
    successes = await dbs.metrics.read(lambda conn: read_upstream.last_outcome_at(conn, "egress", "served_upstream"))
    failures = await dbs.metrics.read(lambda conn: read_upstream.last_outcome_at(conn, "egress", "failed"))
    assert successes["direct"] == {"at": T0, "precision": "minute"}
    assert successes["rotator"] == {"at": HOUR0 - 7200, "precision": "hour"}
    assert "credential" not in successes  # a local OPTIONS answer reached no egress
    assert failures == {"direct": {"at": T0 - 60, "precision": "minute"}}
    hosts = await dbs.metrics.read(lambda conn: read_upstream.last_outcome_at(conn, "host", "served_upstream"))
    assert hosts["games.roblox.com"]["at"] == T0
    with pytest.raises(ValueError):
        await dbs.metrics.read(lambda conn: read_upstream.last_outcome_at(conn, "method", "failed"))


async def test_last_failure_events_by_egress_and_host_skip_folded_rows(dbs: Any) -> None:
    ms = T0 * 1000
    await _write(
        dbs,
        event(ms, "failure", "upstream_timeout", {"status": 504, "egress": "rotator", "upstream_error": "ReadTimeout"}),
        event(ms + 1000, "failure", "upstream_5xx", {"status": 503, "egress": "direct", "upstream_status": 503}),
        event(ms + 2000, "failure", "upstream_5xx", {"status": 503, "aggregated": True, "count": 3}),
        event(ms + 3000, "failure", "upstream_connect", {"status": 502, "egress": "direct"},
              template="thumbnails.roblox.com/v1/assets"),
    )  # fmt: skip
    by_egress = await dbs.metrics.read(lambda conn: read_upstream.last_failure_events(conn, "egress"))
    assert (by_egress["direct"]["at_ms"], by_egress["direct"]["reason"]) == (ms + 3000, "upstream_connect")
    assert by_egress["rotator"]["error"] == "ReadTimeout"
    by_host = await dbs.metrics.read(lambda conn: read_upstream.last_failure_events(conn, "host"))
    assert by_host["games.roblox.com"]["at_ms"] == ms + 1000  # the folded row at ms + 2000 is skipped
    assert by_host["thumbnails.roblox.com"]["status"] == 502


async def test_challenge_counts_by_egress_and_endpoint(dbs: Any) -> None:
    insert = (
        "INSERT INTO upstream_attempt_minute (bucket_start, endpoint_template, egress, attempt, kind, status, "
        "challenge, html_body, exit_id, count) VALUES (?, ?, ?, 1, 'first', ?, ?, ?, '', ?)"
    )
    await _write(
        dbs,
        (insert, (T0, TEMPLATE, "rotator", 403, 1, 0, 2)),
        (insert, (T0 + 60, TEMPLATE, "rotator", 503, 0, 1, 1)),
        (insert, (T0, TEMPLATE, "direct", 200, 0, 0, 7)),
    )
    rows = await dbs.metrics.read(lambda conn: read_upstream.challenge_counts(conn, T0, T0 + 3600))
    by_egress = {row["egress"]: row for row in rows}
    assert by_egress["rotator"] == {"egress": "rotator", "calls": 3, "challenges": 2, "html_bodies": 1,
                                    "last_at": T0 + 60}  # fmt: skip
    assert by_egress["direct"]["last_at"] is None
    by_template = await dbs.metrics.read(
        lambda conn: read_upstream.challenge_counts(conn, T0, T0 + 3600, by_template=True)
    )
    assert (by_template[0]["template"], by_template[0]["egress"]) == (TEMPLATE, "rotator")


# ------------------------------------------------------------------------------------------- endpoints


async def test_endpoint_recency_methods_and_the_newest_request(dbs: Any) -> None:
    window = Window(T0 - 3600, T0 + 60, "minute")
    await _write(
        dbs,
        dim(1),
        dim(2, method="POST", status=404),
        rollup("rollup_minute", T0 - 600, 1, 3),
        rollup("rollup_minute", T0 - 60, 2, 1),
    )
    found = await dbs.metrics.read(lambda conn: read_dashboard.endpoint_recency(conn, window, [TEMPLATE, "x/none"]))
    assert list(found) == [TEMPLATE]  # a template without rows in the window is not answered
    item = found[TEMPLATE]
    assert item["methods"] == {"GET": 3, "POST": 1}
    assert (item["last_request_ms"], item["last_request_precision"], item["last_status"]) == (
        (T0 - 60) * 1000, "minute", None
    )  # fmt: skip
    live = {"status": 404, "ip": "203.0.113.5", "place": "12345"}
    await _write(dbs, event((T0 - 30) * 1000, "live", "upstream_4xx", live))
    found = await dbs.metrics.read(lambda conn: read_dashboard.endpoint_recency(conn, window, [TEMPLATE]))
    exact = found[TEMPLATE]
    assert (exact["last_request_ms"], exact["last_request_precision"]) == ((T0 - 30) * 1000, "exact")
    assert (exact["last_status"], exact["last_caller"], exact["last_place"]) == (404, "203.0.113.5", "12345")
    earlier = Window(T0 - 3600, T0 - 120, "minute")  # the Live row lies after this window: not used
    found = await dbs.metrics.read(lambda conn: read_dashboard.endpoint_recency(conn, earlier, [TEMPLATE]))
    assert found[TEMPLATE]["last_request_precision"] == "minute"
    assert found[TEMPLATE]["methods"] == {"GET": 3}


# ------------------------------------------------------------------------------------------- protection


async def test_watch_activity_counts_from_the_since_minute_and_skips_network_keys(dbs: Any) -> None:
    insert = (
        "INSERT INTO client_minute (bucket_start, client_type, client_key, requests, refused, served, bytes, "
        "top_endpoint) VALUES (?, 'ip', ?, ?, ?, 0, 0, ?)"
    )
    ip = "203.0.113.9"
    await _write(
        dbs,
        (insert, (T0 - 120, ip, 50, 0, "a/before")),  # before the throttle-all minute: not counted
        (insert, (T0, ip, 4, 3, "a/x")),
        (insert, (T0 + 60, ip, 2, 2, "a/y")),
        (insert, (T0, "2001:db8::/64", 9, 9, "a/z")),
    )
    since = T0 + 30  # counted from its minute, T0
    found = await dbs.metrics.read(
        lambda conn: read_protection.watch_activity(conn, [ip, "2001:db8::/64"], since=since, now=T0 + 90)
    )
    assert list(found) == [ip]  # an IPv6 network key has no per-address activity (unknown, not zero)
    row = found[ip]
    assert (row["requests"], row["refused"], row["top_endpoint"], row["last_seen_ms"]) == (
        6,
        5,
        "a/x",
        (T0 + 60) * 1000,
    )
    assert row["rate1"] > 0
    assert row["rate60"] >= row["rate1"]


async def test_rule_hits_columns_totals_and_points(dbs: Any) -> None:
    hits = "INSERT INTO rule_hit_minute (bucket_start, table_name, rule_key, hits) VALUES (?, ?, ?, ?)"
    lifetime = "INSERT INTO rule_hits (table_name, rule_key, hits, first_hit_at, last_hit_at) VALUES (?, ?, ?, ?, ?)"
    await _write(
        dbs,
        (hits, (HOUR0, "rules_header", "7", 2)),
        (hits, (HOUR0 + 60, "rules_header", "7", 3)),
        (hits, (HOUR0 + 3600, "rules_header", "7", 4)),
        (hits, (HOUR0, "access_list", "1", 1)),
        (lifetime, ("rules_header", "7", 40, HOUR0 - 86_400, HOUR0 + 3600)),
    )
    columns = await dbs.metrics.read(
        lambda conn: read_protection.rule_hit_columns(conn, "rules_header", HOUR0, HOUR0 + 3600)
    )
    assert columns == {"7": {"hits": 5, "hits_total": 40, "last_hit_at": HOUR0 + 3600}}
    totals = await dbs.metrics.read(lambda conn: read_protection.rule_hit_totals(conn, HOUR0, HOUR0 + 7200))
    assert totals == {"access_list": 1, "rules_header": 9}
    window = Window(HOUR0, HOUR0 + 7200, "hour")
    points = await dbs.metrics.read(lambda conn: read_protection.rule_hit_points(conn, "rules_header", "7", window))
    assert points == [[HOUR0, 5], [HOUR0 + 3600, 4]]


# ------------------------------------------------------------------------------------------- security


async def test_per_header_clears_keep_or_drop_the_row(dbs: Any) -> None:
    await _write(
        dbs,
        ("INSERT INTO fingerprint_headers (name, count, first_seen, last_seen) VALUES ('x-test', 3, ?, ?)", (T0, T0)),
        ("INSERT INTO fingerprint_headers (name, count, first_seen, last_seen) VALUES ('accept', 2, ?, ?)", (T0, T0)),
        ("INSERT INTO fingerprint_values (value_hash, name, value, count, first_seen, last_seen) "
         "VALUES ('h1', 'x-test', 'one', 1, ?, ?), ('h2', 'x-test', 'two', 2, ?, ?)", (T0, T0, T0, T0)),
        event(T0 * 1000, "blocked_header", "xeno-fingerprint", {"count": 4, "aggregated": True}),
    )  # fmt: skip
    counts = await dbs.metrics.read(lambda conn: read_security.header_counts(conn, "X-Test"))
    assert counts == {"headers": 1, "values": 2}
    assert await dbs.metrics.write(lambda conn: read_security.clear_header_values(conn, "X-Test")) == 2
    assert await dbs.metrics.read(lambda conn: read_security.header_counts(conn, "x-test")) == {
        "headers": 1,
        "values": 0,
    }
    removed = await dbs.metrics.write(lambda conn: read_security.remove_header(conn, "x-test"))
    assert removed == {"headers": 1, "values": 0}
    assert await dbs.metrics.read(lambda conn: read_security.header_counts(conn, "accept")) == {
        "headers": 1,
        "values": 0,
    }
    assert await dbs.metrics.read(lambda conn: read_security.blocked_header_count(conn, "Xeno-Fingerprint")) == 4
    assert await dbs.metrics.write(lambda conn: read_security.remove_blocked_header(conn, "xeno-fingerprint")) == 1
    rows = await dbs.metrics.read(lambda conn: read_security.blocked_rows(conn, 0, (T0 + 60) * 1000))
    assert rows == []


# ------------------------------------------------------------------------------------------- cache browser


def test_the_browser_search_and_the_purge_share_one_condition() -> None:
    """`SEARCH_CONDITION` and `search_params` are what both `browse` and the `search` purge bind: the text is
    trimmed, lowercased and bounded, LIKE wildcards are escaped, and handoff rows are excluded."""
    assert read_browser.search_text("  Votes ") == "votes"
    assert read_browser.search_params("50%_off") == (len(HANDOFF_SUFFIX), HANDOFF_SUFFIX, "50%_off", "%50\\%\\_off%")
    assert len(read_browser.search_text("x" * 500)) == read_browser.MAX_QUERY_CHARS
    assert "lower(key) LIKE ?" in read_browser.SEARCH_CONDITION
    with pytest.raises(ValueError, match="search text"):
        read_browser.purge_scope("   ")  # an empty search would match every entry: Purge all has its own button
