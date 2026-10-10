"""Review round 3 (group admin_pages): the producers lane's data on the Protection, Upstream and System routes.

What this is
    Integration tests for the lane requests of `.remake/wave3b_reports/lane_producers.md` ("Admin routes"): the
    tarpit hold statistics on `GET /protection/tarpit`, per-rule hits on the rule and list tables plus
    `GET /protection/rule-hits` and the pipeline diagram, challenge and HTML answers on the Upstream cards,
    `GET /upstream/challenges` and the "why did this request wait?" explainer, every worker's metrics drops on
    `GET /system/metrics-pipeline`, and the disk growth history on `GET /system/persistence`.

Why it exists
    The producers lane records the data (schema 5 tables, `metrics/producers.py`, `metrics/disk_history.py`) and its
    own tests cover the writing side; these tests pin that the admin API answers it, in the DESIGN 13.1 shapes, so
    the P11 pages can render it.

How it works
    The admin API fixtures (`tests/integration/admin_api/conftest.py`) run the real app with a signed-in admin. The
    producer rows are written straight into metrics.db (the shapes the recorder's batch handler writes), then the
    routes are read over HTTP.

What to read next
    `roxy/admin/api/protection.py` (`tarpit_state`, `_with_rule_hits`, `rule_hit_history`), `roxy/admin/api/upstream.py`
    (`challenge_table`, `_flagged_calls`), `roxy/admin/api/system.py`, `roxy/metrics/read_producers.py`.
"""

from __future__ import annotations

from typing import Any

from roxy.core.ids import new_request_id
from roxy.core.reasons import Egress

TEMPLATE = "games.roblox.com/v1/games"


async def _metrics(api_app: Any, *statements: tuple[str, tuple[Any, ...]]) -> None:
    def run(conn: Any) -> None:
        for sql, params in statements:
            conn.execute(sql, params)

    await api_app.ctx.dbs.metrics.write(run)


def _minute(api_app: Any) -> int:
    now = int(api_app.clock.now())
    return now - now % 60


async def test_tarpit_card_has_the_fleet_hold_statistics_of_the_range(api: Any, api_app: Any, api_json: Any) -> None:
    minute = _minute(api_app)
    await _metrics(
        api_app,
        (
            "INSERT INTO tarpit_minute (bucket_start, category, kind, holds, skipped, held_s_sum, held_s_max, "
            "gaps_after_hold, gap_after_hold_s_sum, gaps_after_instant, gap_after_instant_s_sum) "
            "VALUES (?, 'probe', 'hold', 4, 1, 40.0, 15.0, 2, 30.0, 1, 2.0)",
            (minute,),
        ),
        ("INSERT INTO tarpit_hold_minute (bucket_start, category, bound_ms, holds) VALUES (?, 'probe', 10000, 4)",
         (minute,)),
    )  # fmt: skip
    body = api_json(await api.get("protection/tarpit", params={"range": "1h"}))
    history = body["history"]
    assert (body["history_scope"], body["stats_scope"]) == ("fleet", "this_worker")
    assert (history["eligible"], history["holds"], history["skipped"], history["skipped_pct"]) == (5, 4, 1, 20.0)
    assert (history["mean_hold_s"], history["max_hold_s"]) == (10.0, 15.0)
    assert (history["gap_after_hold_s"], history["gap_after_instant_s"]) == (15.0, 2.0)
    assert history["by_category"]["probe"]["holds"] == 4
    assert body["category_labels"]["probe"] == "Not a Roblox URL"
    assert body["range"]["granularity"] == "minute"


async def test_rule_tables_carry_hits_and_one_rule_has_a_hit_history(api: Any, api_app: Any, api_json: Any) -> None:
    created = api_json(await api.post("protection/header-rules", json={"needle": "xeno", "header": "user-agent"}))
    rule_id = str(created["item"]["id"])
    minute = _minute(api_app)
    await _metrics(
        api_app,
        ("INSERT INTO rule_hit_minute (bucket_start, table_name, rule_key, hits) VALUES (?, 'rules_header', ?, 3)",
         (minute - 60, rule_id)),
        ("INSERT INTO rule_hit_minute (bucket_start, table_name, rule_key, hits) VALUES (?, 'rules_header', ?, 2)",
         (minute, rule_id)),
        ("INSERT INTO rule_hits (table_name, rule_key, hits, first_hit_at, last_hit_at) "
         "VALUES ('rules_header', ?, 12, ?, ?)", (rule_id, minute - 86_400, minute + 5)),
    )  # fmt: skip
    table = api_json(await api.get("protection/header-rules", params={"range": "1h"}))
    row = next(item for item in table["items"] if str(item["id"]) == rule_id)
    assert (row["hits"], row["hits_total"], row["last_hit_at"]) == (5, 12, minute + 5)
    assert {"hits", "hits_total", "last_hit_at"} <= {column["key"] for column in table["columns"]}
    history = api_json(
        await api.get("protection/rule-hits", params={"range": "1h", "table": "header-rules", "rule_id": rule_id})
    )
    assert history["total"] == 5
    assert history["series"][0]["key"] == "hits"
    pipeline = api_json(await api.get("protection/pipeline", params={"range": "1h"}))
    assert pipeline["rule_hits"] == {"rules_header": 5}
    blocks = api_json(await api.get("protection/endpoint-blocks", params={"range": "1h"}))
    assert blocks["total"] == 0  # no blocks: the hit columns cost nothing


async def test_upstream_challenges_on_the_cards_the_table_and_the_trace(
    api: Any, api_app: Any, api_json: Any, metrics_seed: Any
) -> None:
    request_id = new_request_id(api_app.clock)
    metrics_seed.record(request_id=request_id, egress=Egress.ROTATOR, status=403, upstream_status=403)
    await metrics_seed.flush()
    insert = (
        "INSERT INTO upstream_attempt_minute (bucket_start, endpoint_template, egress, attempt, kind, status, "
        "challenge, html_body, exit_id, count) VALUES (?, ?, 'rotator', 1, 'first', 403, ?, ?, '', ?)"
    )
    minute = _minute(api_app)
    await _metrics(api_app, (insert, (minute, TEMPLATE, 1, 0, 2)), (insert, (minute, TEMPLATE, 0, 1, 1)))
    cards = api_json(await api.get("upstream/egress", params={"range": "1h"}))
    rotator = next(card for card in cards["items"] if card["egress"] == "rotator")
    assert (rotator["challenges"], rotator["html_bodies"]) == (2, 1)
    table = api_json(await api.get("upstream/challenges", params={"range": "1h"}))
    assert [(item["template"], item["challenges"], item["html_bodies"]) for item in table["items"]] == [
        (TEMPLATE, 2, 1)
    ]
    assert table["caller_text"] == ["template"]
    trace = api_json(await api.get(f"upstream/trace/{request_id}"))
    assert trace["flagged_calls"] == {"calls": 3, "challenges": 2, "html_bodies": 1}
    assert any("challenge" in sentence and "inferred" in sentence for sentence in trace["reasons"]), trace


async def test_system_shows_fleet_drops_and_the_disk_growth_history(api: Any, api_app: Any, api_json: Any) -> None:
    now = int(api_app.clock.now())
    minute = now - now % 60
    await _metrics(
        api_app,
        ("INSERT INTO metrics_pipeline_minute (bucket_start, worker_id, dropped, history_dropped, capture_dropped) "
         "VALUES (?, 'other-worker', 7, 1, 0)", (minute - 120,)),
        ("INSERT INTO metrics_pipeline_minute (bucket_start, worker_id, dropped, history_dropped, capture_dropped) "
         "VALUES (?, 'old-worker', 99, 0, 0)", (minute - 7200,)),
        ("INSERT INTO disk_samples (at, total_bytes, free_bytes, storage_bytes) VALUES (?, 1000, 600, 40)",
         (now - 7200,)),
        ("INSERT INTO disk_samples (at, total_bytes, free_bytes, storage_bytes) VALUES (?, 1000, 590, 50)",
         (now - 3600,)),
        ("INSERT INTO table_size_samples (at, db, table_name, bytes) VALUES (?, 'metrics', 'events', 4096)",
         (now - 3600,)),
    )  # fmt: skip
    pipeline = api_json(await api.get("system/metrics-pipeline"))
    drops = pipeline["fleet_drops_last_hour"]
    assert (drops["dropped"], drops["history_dropped"], list(drops["workers"])) == (7, 1, ["other-worker"])
    assert pipeline["fleet_drops_scope"] == "fleet"
    persistence = api_json(await api.get("system/persistence"))
    assert [sample["total_bytes"] for sample in persistence["growth"]] == [40, 50]  # Roxy's storage over time
    assert persistence["table_sizes"]["tables"] == {"metrics.events": 4096}
    assert persistence["growth_days"] == 30
