"""The Endpoints API (`/admin/api/v1/endpoints`) in the real app: the template table with trends, filters and
exports, and the drill-down (totals, series, Roblox 429s, callers, concrete paths, recent requests, applicable
rules) (plan 14.1 Endpoints row, parity rows 74 and 89)."""

from __future__ import annotations

import csv
import io
from typing import Any

from roxy.config.audit import Actor
from roxy.core.reasons import CacheState, Egress, Outcome, ReasonCode, Source
from roxy.rules.service import RulesService

VOTES = "games.roblox.com/v1/games/{universeId}/votes"
USERS = "users.roblox.com/v1/users/{userId}"
BADGES = "badges.roblox.com/v1/badges/{badgeId}"
ACTOR = Actor("cli", "test")


def seed_endpoints(seed: Any) -> None:
    seed.record(3, endpoint_template=VOTES, path="games.roblox.com/v1/games/123/votes")
    seed.record(2, endpoint_template=VOTES, path="games.roblox.com/v1/games/456/votes", place_id="999",
                client_ip="198.51.100.7")  # fmt: skip
    seed.record(2, endpoint_template=USERS, host="users.roblox.com", method="POST", path="users.roblox.com/v1/users/1")
    seed.record(1, endpoint_template=BADGES, host="badges.roblox.com", path="badges.roblox.com/v1/badges/5",
                outcome=Outcome.SERVED_CACHE, reason=ReasonCode.CACHE_HIT, source=Source.CACHE,
                cache_state=CacheState.HIT, upstream_calls=0, egress=Egress.NONE)  # fmt: skip


async def test_endpoints_need_a_session(anon_api: Any) -> None:
    assert (await anon_api.get("endpoints")).status_code == 401
    assert (await anon_api.get("endpoints/detail", params={"template": VOTES})).status_code == 401


async def test_table_sorts_pages_and_trends(api: Any, api_app: Any, metrics_seed: Any, api_json: Any) -> None:
    seed_endpoints(metrics_seed)
    metrics_seed.record(4, endpoint_template=USERS, host="users.roblox.com", at_ms=api_app.clock.now_ms() - 90 * 60_000)
    await metrics_seed.flush()
    body = api_json(await api.get("endpoints", params={"range": "1h"}))
    assert body["total"] == 3
    keys = [row["key"] for row in body["items"]]
    assert keys == [VOTES, USERS, BADGES]
    rows = {row["key"]: row for row in body["items"]}
    assert rows[VOTES]["requests"] == 5
    assert rows[VOTES]["previous_requests"] == 0
    assert rows[VOTES]["trend_pct"] is None  # nothing to compare with
    assert rows[USERS]["previous_requests"] == 4
    assert rows[USERS]["trend_pct"] == -50.0
    assert rows[BADGES]["hit_ratio"] == 1.0
    assert body["compare"]["mode"] == "previous"
    assert {column["key"] for column in body["columns"]} >= {"key", "requests", "trend_pct", "roblox_429", "p95_ms"}

    page = api_json(await api.get("endpoints", params={"range": "1h", "page_size": 10, "sort": "key", "order": "asc"}))
    assert [row["key"] for row in page["items"]] == sorted(keys)
    search = api_json(await api.get("endpoints", params={"range": "1h", "q": "users"}))
    assert [row["key"] for row in search["items"]] == [USERS]
    hosts = api_json(await api.get("endpoints", params={"range": "1h", "host": "BADGES.roblox.com"}))
    assert [row["key"] for row in hosts["items"]] == [BADGES]
    assert hosts["filters"] == {"host": "badges.roblox.com"}
    post = api_json(await api.get("endpoints", params={"range": "1h", "method": "post"}))
    assert [row["key"] for row in post["items"]] == [USERS]
    assert post["items"][0]["roblox_429"] is None  # the 429 log cannot be split by method: unknown, never zero


async def test_table_refuses_bad_parameters(api: Any, section13: Any) -> None:
    fields = section13(await api.get("endpoints", params={"method": "G E T"}), 422, "validation_failed")
    assert "method" in fields
    fields = section13(await api.get("endpoints", params={"sort": "trend_pct"}), 422, "invalid_table_query")
    assert "sort" in fields
    fields = section13(await api.get("endpoints", params={"page_size": 7}), 422, "invalid_table_query")
    assert "page_size" in fields


async def test_table_export(api: Any, api_app: Any, metrics_seed: Any) -> None:
    seed_endpoints(metrics_seed)
    await metrics_seed.flush()
    download = await api.get("endpoints", params={"range": "1h", "format": "csv"})
    assert download.status_code == 200
    rows = list(csv.reader(io.StringIO(download.text)))
    assert rows[0][0] == "Endpoint"
    assert len(rows) == 4
    assert download.headers["roxy-export-rows"] == "3"

    def audited(conn: Any) -> list[Any]:
        rows: list[Any] = conn.execute("SELECT target FROM audit_log WHERE action = 'export.download'").fetchall()
        return rows

    assert [row[0] for row in await api_app.ctx.dbs.control.read(audited)] == ["table:endpoints"]


async def test_drill_down(api: Any, api_app: Any, metrics_seed: Any, api_json: Any) -> None:
    ctx = api_app.ctx
    rules = RulesService(ctx.dbs.control, clock=ctx.clock, store=ctx.rules)
    await rules.create("rules_endpoint_limit", {"pattern": "games.roblox.com/v1/games/*/votes", "limit": 5}, ACTOR)
    await rules.create("rules_cache", {"pattern": "games.roblox.com/v1/games/123/votes", "ttl": 600}, ACTOR)
    await rules.create("rules_endpoint_block", {"pattern": "users.roblox.com"}, ACTOR)
    seed_endpoints(metrics_seed)
    for _ in range(3):
        ctx.recorder.record_upstream_429(endpoint_template=VOTES, host="games.roblox.com", egress="direct",
                                         retry_after_s=10)  # fmt: skip
    await metrics_seed.flush()
    body = api_json(await api.get("endpoints/detail", params={"range": "1h", "template": VOTES}))
    assert body["template"] == VOTES
    assert body["host"] == "games.roblox.com"
    assert body["totals"]["requests"]["value"] == 5
    assert body["totals"]["roblox_429"]["value"] == 3
    assert body["upstream_429"]["total"] == 3
    assert body["upstream_429"]["by_egress"] == {"direct": 3}
    assert len(body["upstream_429"]["recent"]) == 3
    outcomes = {entry["key"]: entry for entry in body["requests_by_outcome"]["series"]}
    assert sum(point[1] for point in outcomes["requests:served_upstream"]["points"]) == 5
    assert {entry["key"] for entry in body["latency"]["series"]} == {"p50_ms", "p95_ms", "p99_ms"}

    paths = {item["path"]: item["requests"] for item in body["concrete_paths"]}
    assert paths == {"games.roblox.com/v1/games/123/votes": 3, "games.roblox.com/v1/games/456/votes": 2}
    assert len(body["recent_requests"]) == 5
    assert body["recent_requests"][0]["template"] == VOTES
    live = body["top_callers"]["last_15_minutes"]
    assert {item["ip"]: item["requests"] for item in live["ips"]} == {"203.0.113.5": 3, "198.51.100.7": 2}
    assert {item["place"] for item in live["places"]} == {"12345", "999"}
    sampled = body["top_callers"]["range"]
    assert sampled["samples"] == 5
    assert {item["place"]: item["requests"] for item in sampled["places"]} == {"12345": 3, "999": 2}
    for item in sampled["clients"]:
        assert "." not in item["client_hash"]  # keyed hashes, never addresses

    targets = {target["target"]: target for target in body["rules"]["targets"]}
    template_target = targets[VOTES]
    assert template_target["endpoint_rule"]["pattern"] == "games.roblox.com/v1/games/*/votes"
    assert template_target["cache_rule"] is None
    assert template_target["endpoint_block"] is None
    concrete = targets["games.roblox.com/v1/games/123/votes"]
    # The real winner (most specific, ties to the lowest id): the shipped `\d+/votes` regex outranks the glob.
    winner = ctx.rules.snapshot.cache_rule_for("games.roblox.com/v1/games/123/votes")
    assert concrete["cache_rule"]["id"] == winner.id
    assert concrete["cache_rule"]["origin"] == "default"
    assert concrete["endpoint_rule"]["pattern"] == "games.roblox.com/v1/games/*/votes"
    assert set(body["rules"]["upstream_limits"]) == {"host", "endpoint"}
    assert body["cache"]["rule"] is None
    assert body["cache"]["ttl_s"] == int(ctx.settings.int("cache_ttl_seconds"))

    users = api_json(await api.get("endpoints/detail", params={"range": "1h", "template": USERS}))
    assert users["rules"]["targets"][0]["endpoint_block"]["pattern"] == "users.roblox.com"


async def test_recent_and_bad_templates(api: Any, metrics_seed: Any, api_json: Any, section13: Any) -> None:
    seed_endpoints(metrics_seed)
    await metrics_seed.flush()
    recent = api_json(await api.get("endpoints/recent", params={"template": VOTES, "limit": 2}))
    assert recent["total"] == 2
    assert recent["items"][0]["template"] == VOTES
    fields = section13(await api.get("endpoints/detail"), 422, "validation_failed")
    assert "template" in fields
    fields = section13(await api.get("endpoints/detail", params={"template": "x" * 300}), 422, "validation_failed")
    assert "template" in fields
    missing = api_json(await api.get("endpoints/detail", params={"template": "nothing.roblox.com/v1/x"}))
    assert missing["totals"]["requests"]["value"] == 0
    assert missing["recent_requests"] == []
