"""The Protection page API (`/admin/api/v1/protection`) in the real app: switches, bans, lists, limits, rules,
detectors, tarpit and the pipeline counts (plan 10, 14.1 Protection; parity rows 5, 6, 39 to 51, 75, 76, 113, 115,
118, 123, 125, 135; plan 6.8 limiter and bans resets).

Every test signs in through the real password and TOTP flow (`api` fixture) and drives the routes over HTTP; state is
checked through the same services and databases the proxy uses (control.db audit rows, hot.db limiter and strike
rows, the rules snapshot, metrics.db events).
"""

from __future__ import annotations

import csv
import io
import json
from typing import Any

import pytest

from roxy.abuse.checks import PIPELINE_ORDER
from roxy.config.audit import Actor
from roxy.core.reasons import CacheState, Outcome, ReasonCode, Source
from roxy.metrics.read_protection import CHECK_REASONS
from roxy.rules.service import RulesService

pytestmark = pytest.mark.asyncio


def ok(response: Any, api_json: Any, status: int = 200) -> Any:
    assert response.status_code == status, response.text
    return api_json(response)


async def audit_actions(api_app: Any, action: str) -> list[dict[str, Any]]:
    def read(conn: Any) -> list[dict[str, Any]]:
        rows = conn.execute(
            "SELECT action, target, after_json, reason FROM audit_log WHERE action = ? ORDER BY id", (action,)
        ).fetchall()
        return [dict(row) for row in rows]

    result: list[dict[str, Any]] = await api_app.ctx.dbs.control.read(read)
    return result


def refused(seed: Any, count: int, reason: ReasonCode, status: int, **fields: Any) -> None:
    seed.record(
        count,
        outcome=Outcome.REFUSED,
        reason=reason,
        status=status,
        source=Source.ROXY,
        cache_state=CacheState.NA,
        upstream_calls=0,
        upstream_bytes_in=0,
        upstream_bytes_out=0,
        check=str(fields.pop("check", reason.value)),
        **fields,
    )


async def flush_closed_minute(seed: Any) -> None:
    """Aggregated events are written once their minute closes: move the clock past it, then flush."""
    seed.owner.clock.advance(61)
    await seed.flush()


# ============================================================================================ guards and shapes


async def test_check_reasons_cover_every_check_of_the_pipeline() -> None:
    assert tuple(CHECK_REASONS) == PIPELINE_ORDER
    known = {code.value for code in ReasonCode}
    for codes in CHECK_REASONS.values():
        assert set(codes) <= known


async def test_guards_and_error_shapes(api: Any, anon_api: Any, section13: Any) -> None:
    response = await anon_api.get("protection/pause")
    assert response.status_code == 401
    response = await api.post("protection/pause", json={"paused": True}, csrf=False)
    assert response.status_code == 403
    fields = section13(
        await api.post("protection/pause", json={"paused": True, "unknown_field": 1}), 422, "validation_failed"
    )
    assert "unknown_field" in fields
    section13(await api.post("protection/pause", content=b"{not json", headers={"Content-Type": "application/json"}),
              400, "invalid_json")  # fmt: skip


# ============================================================================================ switches


async def test_pause_message_schedule_and_drops_since(api: Any, api_app: Any, api_json: Any, section13: Any,
                                                      metrics_seed: Any) -> None:  # fmt: skip
    state = ok(await api.get("protection/pause"), api_json)
    assert state["paused"] is False
    assert state["callers_see"]["body"] == "Service down for maintenance."
    state = ok(await api.post("protection/pause", json={"paused": True, "message": "Back in ten minutes."}), api_json)
    assert state["paused"] is True
    assert state["active"] is True
    assert state["callers_see"] == {
        "status": 503, "body": "Back in ten minutes.", "message_source": "custom", "retry_after_s": 60,
    }  # fmt: skip
    assert api_app.ctx.abuse.switches.pause.paused is True  # this worker sees its own change at once
    refused(metrics_seed, 3, ReasonCode.PAUSED, 503)
    await metrics_seed.flush()
    assert ok(await api.get("protection/pause"), api_json)["drops_since_start"] == 3
    dash = chr(0x2014)
    fields = section13(await api.post("protection/pause", json={"message": f"Back {dash} soon"}), 422,
                       "validation_failed")  # fmt: skip
    assert "message" in fields
    now = int(api_app.clock.now())
    window = {"start": now + 3600, "end": now + 7200, "message": "Planned upgrade."}
    state = ok(await api.put("protection/pause/schedule", json=window), api_json)
    assert state["scheduled"]["start"] == now + 3600
    assert state["scheduled"]["in_window"] is False
    fields = section13(await api.put("protection/pause/schedule", json={"start": now + 10, "end": now + 5}), 422,
                       "validation_failed")  # fmt: skip
    assert "end" in fields
    fields = section13(await api.put("protection/pause/schedule", json={"start": "soon", "end": now}), 422,
                       "validation_failed")  # fmt: skip
    assert "start" in fields
    state = ok(await api.delete("protection/pause/schedule"), api_json)
    assert state["scheduled"] is None
    state = ok(await api.post("protection/pause", json={"paused": False}), api_json)
    assert state["paused"] is False
    assert state["drops_since_start"] is None
    assert [row["action"] for row in await audit_actions(api_app, "pause.set")] == ["pause.set", "pause.set"]


async def test_throttle_all_limit_since_marker_and_watch(api: Any, api_app: Any, api_json: Any,
                                                         section13: Any) -> None:  # fmt: skip
    body = {"enabled": True, "message": "Slow down please.", "limit": 3, "period": 30, "reason": "attack"}
    state = ok(await api.post("protection/throttle-all", json=body), api_json)
    assert state["enabled"] is True
    assert state["limit"] == 3
    assert state["period"] == 30
    assert state["since"] == pytest.approx(api_app.clock.now())
    assert state["callers_see"]["body"] == "Slow down please."
    assert api_app.ctx.settings.int("global_throttle_limit") == 3
    fields = section13(await api.post("protection/throttle-all", json={"limit": 0}), 422, "invalid_settings")
    assert "global_throttle_limit" in fields  # v1 bug B16: a bad limit is reported, never ignored
    dash = chr(0x2014)
    fields = section13(
        await api.post("protection/throttle-all", json={"limit": 9, "message": f"Slow {dash} down"}),
        422,
        "validation_failed",
    )
    assert "message" in fields
    assert api_app.ctx.settings.int("global_throttle_limit") == 3  # nothing half applied
    now_ms = api_app.clock.now_ms()

    def seed(conn: Any) -> None:
        conn.execute(
            "INSERT INTO limiter (bucket_key, tat_ms, window_start, count, updated_at) VALUES (?, ?, ?, ?, ?)",
            ("tall:203.0.113.9", now_ms + 20_000, now_ms - 10_000, 3, now_ms // 1000),
        )

    await api_app.ctx.dbs.hot.write(seed)
    table = ok(await api.get("protection/throttle-all/watch"), api_json)
    assert table["total"] == 1
    row = table["items"][0]
    assert {key: row[key] for key in ("ip", "count", "limited", "reset_in_s")} == {
        "ip": "203.0.113.9",
        "count": 3,
        "limited": True,
        "reset_in_s": 20,
    }
    # No client activity was recorded for it, so v1's watch columns are unknown, never a guessed zero (P6).
    assert {row[key] for key in ("requests", "refused", "rate1", "top_endpoint", "last_seen_ms")} == {None}
    section13(await api.get("protection/throttle-all/watch", params={"order": "asc"}), 422, "invalid_table_query")
    state = ok(await api.post("protection/throttle-all", json={"enabled": False}), api_json)
    assert state["enabled"] is False
    assert state["since"] is None


# ============================================================================================ bans


async def test_bans_create_extend_list_evidence_lift_and_reset(api: Any, api_app: Any, api_json: Any,
                                                               section13: Any, metrics_seed: Any) -> None:  # fmt: skip
    created = ok(await api.post("protection/bans", json={
        "subject_type": "ip", "subject": "203.0.113.7", "minutes": 30, "message": "Scraping", "reason": "manual",
    }), api_json)  # fmt: skip
    ban = created["ban"]
    assert ban["active"] is True
    assert ban["expires_in_s"] == 1800
    assert ban["origin"] == "manual"
    extended = ok(await api.post("protection/bans", json={
        "subject_type": "ip", "subject": "203.0.113.7", "minutes": 60,
    }), api_json)  # fmt: skip
    assert extended["extended_existing"] is True
    assert extended["ban"]["expires_in_s"] == 3600
    section13(await api.post("protection/bans", json={"subject_type": "ip", "subject": "203.0.113.8"}), 422,
              "validation_failed")  # fmt: skip
    section13(await api.post("protection/bans", json={"subject_type": "ip", "subject": "not an ip", "minutes": 5}),
              422, "invalid_rule")  # fmt: skip
    service = RulesService(api_app.ctx.dbs.control, clock=api_app.clock, store=api_app.ctx.rules)
    now = int(api_app.clock.now())
    auto = {"subject_type": "ip", "subject": "198.51.100.20", "reason_code": "spam_probe",
            "reason_text": "SPAM-PROBE: 6 in 600 s (threshold 5)", "expires_at": now + 600}  # fmt: skip
    await service.create("bans", auto, Actor("system", "auto:spam_probe"), "automatic ban by spam_probe")
    metrics_seed.event("spam_ban", "warning", "spam", {"detector": "SPAM-PROBE", "subject": "ip:198.51.100.20",
                                                       "evidence": "SPAM-PROBE: 6 in 600 s (threshold 5)"})  # fmt: skip
    await metrics_seed.flush()
    table = ok(await api.get("protection/bans"), api_json)
    assert table["total"] == 2
    assert table["active_total"] == 2
    assert {item["subject"] for item in table["items"]} == {"203.0.113.7", "198.51.100.20"}
    autos = ok(await api.get("protection/bans", params={"origin": "auto", "detector": "spam_probe"}), api_json)
    assert [item["detector"] for item in autos["items"]] == ["spam_probe"]
    section13(await api.get("protection/bans", params={"detector": "nope"}), 422, "validation_failed")
    auto_id = autos["items"][0]["id"]
    detail = ok(await api.get(f"protection/bans/{auto_id}"), api_json)
    assert detail["evidence"]["reason_text"].startswith("SPAM-PROBE")
    assert detail["detector_events"][0]["kind"] == "spam_ban"
    section13(await api.get("protection/bans/999999"), 404, "not_found")
    preview = ok(await api.get("protection/bans/reset", params={"scope": "auto"}), api_json)
    assert preview["rows"] == 1
    assert preview["active"] == 1
    section13(await api.post("protection/bans/reset", json={"scope": "all", "reason": "cleanup"}), 422,
              "confirmation_required")  # fmt: skip
    section13(await api.post("protection/bans/reset", json={"scope": "all", "confirm": "all bans"}), 422,
              "validation_failed")  # fmt: skip
    lifted = ok(await api.post("protection/bans/lift", json={"subject_type": "ip", "subject": "203.0.113.7"}), api_json)
    assert lifted["lifted"] == 1
    section13(await api.post("protection/bans/lift", json={"subject_type": "ip", "subject": "203.0.113.7"}), 404,
              "not_found")  # fmt: skip
    result = ok(await api.post("protection/bans/reset", json={
        "scope": "all", "confirm": "all bans", "reason": "spring cleaning",
    }), api_json)  # fmt: skip
    assert result["deleted"] == 1
    assert api_app.ctx.rules.snapshot.bans.match(ip="198.51.100.20", place=None, ua_hash="", now=now) is None
    rows = await audit_actions(api_app, "bans.reset")
    assert json.loads(rows[0]["after_json"])["deleted"] == 1
    assert rows[0]["reason"] == "spring cleaning"
    marks = await api_app.ctx.dbs.metrics.read(
        lambda conn: conn.execute("SELECT kind, label FROM annotations").fetchall()
    )
    assert [tuple(mark) for mark in marks] == [("config_change", "Bans reset (all): 1 deleted")]
    one = ok(await api.post("protection/bans", json={"subject_type": "place", "subject": "1234", "permanent": True}),
             api_json)  # fmt: skip
    assert one["ban"]["permanent"] is True
    assert one["ban"]["expires_in_s"] is None
    gone = ok(await api.delete(f"protection/bans/{one['key']}", params={"reason": "mistake"}), api_json)
    assert gone["action"] == "delete"


# ============================================================================================ access lists


async def test_bypass_deny_and_bypass_my_ip(api: Any, api_app: Any, api_json: Any, section13: Any) -> None:
    api.ip = "203.0.113.50"
    added = ok(await api.post("protection/access/bypass", json={"cidr": "198.51.100.0/24", "note": "load test"}),
               api_json)  # fmt: skip
    assert added["item"]["expires_in_s"] == 24 * 3600  # bypass_default_expiry_h (plan 4.1 row 6)
    section13(await api.post("protection/access/bypass", json={"cidr": "198.51.101.0/24", "never": True}), 422,
              "confirmation_required")  # fmt: skip
    never = ok(await api.post("protection/access/bypass", json={
        "cidr": "198.51.101.0/24", "never": True, "confirm_never": True,
    }), api_json)  # fmt: skip
    assert never["item"]["expires_at"] is None
    me = ok(await api.get("protection/access/bypass/me"), api_json)
    assert me == {"ip": "203.0.113.50", "bypassed": False, "entries": [], "default_expiry_h": 24.0}
    mine = ok(await api.post("protection/access/bypass/me"), api_json)
    assert mine["ip"] == "203.0.113.50"
    assert mine["item"]["cidr"] == "203.0.113.50/32"
    assert ok(await api.get("protection/access/bypass/me"), api_json)["bypassed"] is True
    assert api_app.ctx.rules.snapshot.access.bypass.contains("203.0.113.50", api_app.clock.now())
    table = ok(await api.get("protection/access/bypass", params={"sort": "cidr", "order": "asc"}), api_json)
    assert [item["cidr"] for item in table["items"]] == ["198.51.100.0/24", "198.51.101.0/24", "203.0.113.50/32"]
    assert table["your_ip"] == "203.0.113.50"
    deny = ok(await api.post("protection/access/deny", json={"cidr": "192.0.2.0/24", "expires_in_h": 2}), api_json)
    assert deny["item"]["expires_in_s"] == 7200
    section13(await api.post("protection/access/deny", json={"cidr": "192.0.2.0/24"}), 409, "conflict")
    section13(await api.post("protection/access/deny", json={"cidr": "0.0.0.0/0"}), 422, "invalid_rule")
    section13(await api.delete(f"protection/access/bypass/{deny['key']}"), 404, "not_found")
    ok(await api.delete(f"protection/access/deny/{deny['key']}"), api_json)
    section13(await api.get("protection/access/nope"), 422, "validation_failed")


async def test_admin_allowlist_needs_fresh_mfa_and_refuses_a_self_lockout(api: Any, api_app: Any, api_json: Any,
                                                                          section13: Any) -> None:  # fmt: skip
    api.make_mfa_stale()
    section13(await api.post("protection/access/allow_admin", json={"cidr": "127.0.0.1/32"}), 403, "reauth_required")
    await api.fresh_mfa()
    entry = ok(await api.post("protection/access/allow_admin", json={"cidr": "127.0.0.1/32"}), api_json)
    await api_app.settings(admin_allowlist_enabled=1)
    table = ok(await api.get("protection/access/allow_admin"), api_json)
    assert table["allowlist_enabled"] is True
    assert table["total"] == 1
    fields = section13(await api.delete(f"protection/access/allow_admin/{entry['key']}"), 422,
                       "confirmation_required")  # fmt: skip
    assert "confirm_lockout" in fields
    done = ok(await api.delete(f"protection/access/allow_admin/{entry['key']}", params={"confirm_lockout": "true"}),
              api_json)  # fmt: skip
    assert done["action"] == "delete"
    assert (await api.get("protection/pause")).status_code == 404  # hidden now, exactly like a missing path


# ============================================================================================ settings and ladder


async def test_protection_settings_patch_reset_and_refusals(api: Any, api_app: Any, api_json: Any,
                                                            section13: Any) -> None:  # fmt: skip
    listing = ok(await api.get("protection/settings"), api_json)
    keys = {item["key"] for item in listing["items"]}
    assert {"allowed_requests_per_minute", "tarpit_enabled", "spam_dry_run", "bot_weight_probes"} <= keys
    assert "ui_timezone" not in keys
    changed = ok(await api.patch("protection/settings", json={"changes": {"allowed_requests_per_minute": 20}}),
                 api_json)  # fmt: skip
    assert changed["changed"] == ["allowed_requests_per_minute"]
    assert api_app.ctx.settings.int("allowed_requests_per_minute") == 20
    fields = section13(await api.patch("protection/settings", json={"changes": {"ui_timezone": "UTC"}}), 422,
                       "invalid_settings")  # fmt: skip
    assert "ui_timezone" in fields
    fields = section13(await api.patch("protection/settings", json={"changes": {"spam_dry_run": 0}}), 422,
                       "invalid_settings")  # fmt: skip
    assert "spam/arm" in fields["spam_dry_run"]
    section13(await api.patch("protection/settings", json={"changes": {"allowed_requests_per_minute": -1}}), 422,
              "invalid_settings")  # fmt: skip
    section13(await api.patch("protection/settings", json={"changes": {}}), 422, "validation_failed")
    reset = ok(await api.post("protection/settings/reset", json={"key": "allowed_requests_per_minute"}), api_json)
    assert reset["item"]["value"] == reset["item"]["default"]


async def test_ladder_replace_reset_and_tier_hits(api: Any, api_json: Any, section13: Any,
                                                  metrics_seed: Any) -> None:  # fmt: skip
    ladder = ok(await api.get("protection/ladder"), api_json)
    assert [rung["multiplier"] for rung in ladder["rungs"]] == [1.0, 2.0, 4.0, 8.0]
    assert ladder["rungs"][1]["wait_s"] == 2 * ladder["window_s"]
    metrics_seed.event("throttle_tier", "info", None, {"tier": 2}, aggregate=True, count=5)
    await flush_closed_minute(metrics_seed)
    ladder = ok(await api.get("protection/ladder"), api_json)
    assert [rung["hits"] for rung in ladder["rungs"]] == [0, 5, 0, 0]
    two = [{"multiplier": 1, "message": "Slow down."}, {"multiplier": 3, "message": "Slower."}]
    replaced = ok(await api.put("protection/ladder", json={"tiers": two}), api_json)
    assert [rung["multiplier"] for rung in replaced["rungs"]] == [1.0, 3.0]
    assert replaced["changed"] is True
    fields = section13(await api.put("protection/ladder", json={"tiers": [{"multiplier": 0}]}), 422, "invalid_rule")
    assert any(key.startswith("tiers.1") for key in fields)
    restored = ok(await api.post("protection/ladder/reset", json={}), api_json)
    assert restored["rungs"][0]["message"] == "Too many requests; please slow down."  # the C5 replacement, row 125
    assert len(restored["rungs"]) == 4


# ============================================================================================ strikes and limiter


async def _seed_strikes(api_app: Any, rows: list[tuple[str, int, int, int, int]]) -> None:
    def write(conn: Any) -> None:
        conn.executemany(
            "INSERT INTO strikes (ip, strikes, last_strike_at, tier, throttled_until) VALUES (?, ?, ?, ?, ?)", rows
        )

    await api_app.ctx.dbs.hot.write(write)


async def test_strike_board_forgive_watch_and_export(api: Any, api_app: Any, api_json: Any,
                                                     section13: Any) -> None:  # fmt: skip
    now = int(api_app.clock.now())
    await _seed_strikes(api_app, [("203.0.113.1", 3, now - 10, 3, now + 120), ("203.0.113.2", 1, now - 5, 1, 0)])
    board = ok(await api.get("protection/strikes"), api_json)
    assert [item["ip"] for item in board["items"]] == ["203.0.113.1", "203.0.113.2"]
    assert board["items"][0]["throttled"] is True
    assert board["items"][0]["tier"] == 3
    watch = ok(await api.get("protection/throttle/watch"), api_json)
    assert watch["items"] == [{"ip": "203.0.113.1", "strikes": 3, "tier": 3, "time_left_s": 120}]
    export = await api.get("protection/strikes", params={"format": "csv"})
    assert export.status_code == 200
    assert export.headers["roxy-export-rows"] == "2"
    text = export.content.decode()
    assert "203.0.113.1" not in text  # client addresses are hashed in exports (export_include_ips off)
    assert next(csv.reader(io.StringIO(text)))[:2] == ["Client", "Strikes"]
    section13(await api.post("protection/strikes/forgive", json={"ip": "203.0.113.1", "all": True}), 422,
              "validation_failed")  # fmt: skip
    one = ok(await api.post("protection/strikes/forgive", json={"ip": "203.0.113.1", "reason": "my test"}), api_json)
    assert one["forgiven"] == 1
    assert one["scope"] == "203.0.113.1"
    watch = ok(await api.get("protection/throttle/watch"), api_json)
    assert watch["total"] == 1  # forgiving never lifts a running penalty (v1 B19)
    everyone = ok(await api.post("protection/strikes/forgive", json={"all": True}), api_json)
    assert everyone["forgiven"] == 1
    rows = await audit_actions(api_app, "strikes.forgive")
    assert [row["target"] for row in rows] == ["strikes:203.0.113.1", "strikes:all"]


async def test_throttled_history_from_the_throttled_events(api: Any, api_json: Any, metrics_seed: Any) -> None:
    for _ in range(3):
        metrics_seed.owner.ctx.recorder.record_throttled("203.0.113.4", tier=1, strikes=1)
    metrics_seed.owner.ctx.recorder.record_throttled("203.0.113.5", tier=2, strikes=2)
    await metrics_seed.flush()
    history = ok(await api.get("protection/throttle/history"), api_json)
    assert [(item["ip"], item["count"]) for item in history["items"]] == [("203.0.113.4", 3), ("203.0.113.5", 1)]


async def test_limiter_reset_for_one_client_and_for_everyone(api: Any, api_app: Any, api_json: Any,
                                                             section13: Any) -> None:  # fmt: skip
    now = int(api_app.clock.now())
    keys = ["203.0.113.9", "flood:203.0.113.9", "tall:203.0.113.9", "ep:5|203.0.113.9", "ua:abcd1234|203.0.113.9",
            "ep:5|203.0.113.99", "flood:203.0.113.99", "tarpit_arrival:203.0.113.9"]  # fmt: skip

    def write(conn: Any) -> None:
        conn.executemany(
            "INSERT INTO limiter (bucket_key, tat_ms, window_start, count, updated_at) VALUES (?, 0, 0, 1, ?)",
            [(key, now) for key in keys],
        )

    await api_app.ctx.dbs.hot.write(write)
    await _seed_strikes(api_app, [("203.0.113.9", 2, now, 2, now + 60), ("203.0.113.99", 1, now, 1, 0)])
    preview = ok(await api.get("protection/limiter/reset", params={"scope": "client", "client": "203.0.113.9"}),
                 api_json)  # fmt: skip
    assert (preview["limiter_rows"], preview["strike_rows"]) == (5, 1)
    section13(await api.get("protection/limiter/reset", params={"scope": "client", "client": "nobody"}), 422,
              "validation_failed")  # fmt: skip
    section13(await api.post("protection/limiter/reset", json={"scope": "client", "client": "203.0.113.9"}), 422,
              "validation_failed")  # fmt: skip
    done = ok(await api.post("protection/limiter/reset", json={
        "scope": "client", "client": "203.0.113.9", "reason": "support request",
    }), api_json)  # fmt: skip
    assert (done["limiter_rows"], done["strike_rows"]) == (5, 1)
    left = await api_app.ctx.dbs.hot.read(
        lambda conn: sorted(r[0] for r in conn.execute("SELECT bucket_key FROM limiter").fetchall())
    )
    assert left == ["ep:5|203.0.113.99", "flood:203.0.113.99", "tarpit_arrival:203.0.113.9"]
    section13(await api.post("protection/limiter/reset", json={"scope": "all", "reason": "x"}), 422,
              "confirmation_required")  # fmt: skip
    everyone = ok(await api.post("protection/limiter/reset", json={
        "scope": "all", "confirm": "limiter state", "reason": "after the load test",
    }), api_json)  # fmt: skip
    assert (everyone["limiter_rows"], everyone["strike_rows"]) == (2, 1)
    left = await api_app.ctx.dbs.hot.read(
        lambda conn: [r[0] for r in conn.execute("SELECT bucket_key FROM limiter").fetchall()]
    )
    assert left == ["tarpit_arrival:203.0.113.9"]  # tarpit bookkeeping is not a limit
    rows = await audit_actions(api_app, "limiter.reset")
    assert [json.loads(row["after_json"]) for row in rows] == [
        {"limiter_rows": 5, "strike_rows": 1},
        {"limiter_rows": 2, "strike_rows": 1},
    ]


# ============================================================================================ rule tables


async def test_ua_rules_crud_order_hits_and_tester(api: Any, api_app: Any, api_json: Any, section13: Any,
                                                   metrics_seed: Any) -> None:  # fmt: skip
    first = ok(await api.post("protection/ua-rules", json={"needle": "python-requests", "kind": "cooldown",
                                                          "cooldown": 2}), api_json)  # fmt: skip
    second = ok(await api.post("protection/ua-rules", json={"needle": "GreedyScraper", "limit": 30, "period": 60}),
                api_json)  # fmt: skip
    first_id, second_id = first["key"], second["key"]
    dash = chr(0x2013)
    section13(await api.post("protection/ua-rules", json={"needle": "x", "message": f"a {dash} b"}), 422,
              "invalid_rule")  # fmt: skip
    metrics_seed.event("ua_rule_hit", "info", None, {"rule_id": first_id, "result": "refused"}, aggregate=True,
                       count=4)  # fmt: skip
    metrics_seed.event("ua_rule_hit", "info", None, {"rule_id": first_id, "result": "allowed"}, aggregate=True,
                       count=6)  # fmt: skip
    await flush_closed_minute(metrics_seed)
    table = ok(await api.get("protection/ua-rules"), api_json)
    assert [item["id"] for item in table["items"]] == [first_id, second_id]
    assert (table["items"][0]["allowed"], table["items"][0]["refused"]) == (6, 4)
    ok(await api.put("protection/ua-rules/order", json={"ids": [second_id, first_id]}), api_json)
    table = ok(await api.get("protection/ua-rules"), api_json)
    assert [item["id"] for item in table["items"]] == [second_id, first_id]
    section13(await api.put("protection/ua-rules/order", json={"ids": [first_id]}), 422, "invalid_rule")
    result = ok(await api.post("protection/ua-rules/test", json={"user_agent": "python-requests/2.31.0"}), api_json)
    assert result["limited_by"] == first_id
    assert result["limited"] is True
    draft = {"needle": "(unclosed", "mode": "regex"}
    result = ok(await api.post("protection/ua-rules/test", json={"user_agent": "curl/8", "draft": draft}), api_json)
    assert result["draft"]["valid"] is False
    assert result["limited"] is False
    section13(await api.post("protection/ua-rules/test", json={"user_agent": "  "}), 422, "validation_failed")
    ok(await api.patch("protection/settings", json={"changes": {"user_agent_rules_enabled": 0}}), api_json)
    result = ok(await api.post("protection/ua-rules/test", json={"user_agent": "python-requests/2.31.0"}), api_json)
    assert result["limited"] is False
    assert result["rules_enabled"] is False
    patched = ok(await api.patch(f"protection/ua-rules/{first_id}", json={"enabled": False}), api_json)
    assert patched["item"]["enabled"] is False
    section13(await api.patch("protection/ua-rules/ffffffff", json={"enabled": False}), 404, "not_found")
    ok(await api.delete(f"protection/ua-rules/{second_id}"), api_json)
    assert [rule.id for rule in api_app.ctx.rules.snapshot.ua_rules] == [first_id]


async def test_header_rules_crud_tester_and_presets(api: Any, api_json: Any, section13: Any,
                                                    metrics_seed: Any) -> None:  # fmt: skip
    rule = ok(await api.post("protection/header-rules", json={"needle": "Xeno", "scope": "either"}), api_json)
    section13(await api.post("protection/header-rules", json={"needle": "xeno"}), 409, "conflict")  # row 112
    text = "GET /x HTTP/1.1\nUser-Agent: Roblox/WinInet\nXeno-Fingerprint: 4f3a91c0\n"
    result = ok(await api.post("protection/header-rules/test", json={"headers": text}), api_json)
    assert result["blocked"] is True
    assert result["header_count"] == 2
    assert result["rules"][0]["matched_header"] == "Xeno-Fingerprint"
    assert result["rules"][0]["matched_field"] == "key"
    pairs = [["Accept", "*/*"]]
    draft = {"needle": "*/*", "header": "Accept", "mode": "exact"}
    result = ok(await api.post("protection/header-rules/test", json={"headers": pairs, "draft": draft}), api_json)
    assert result["blocked"] is False
    assert result["draft"]["matched"] is True
    section13(await api.post("protection/header-rules/test", json={"headers": "no colon here"}), 422,
              "validation_failed")  # fmt: skip
    many = {f"X-H{n}": "v" for n in range(201)}
    section13(await api.post("protection/header-rules/test", json={"headers": many}), 422, "validation_failed")
    metrics_seed.record(1, user_agent="SampleAgent/1.0", place_id="999")
    await metrics_seed.flush()
    presets = ok(await api.get("protection/header-rules/presets"), api_json)
    assert presets["example"].splitlines()[0] == "User-Agent: Roblox/WinInet"
    assert presets["samples"][0]["text"] == "User-Agent: SampleAgent/1.0\nRoblox-Id: 999"
    patched = ok(await api.patch(f"protection/header-rules/{rule['key']}", json={"message": "Go away."}), api_json)
    assert patched["item"]["message"] == "Go away."
    ok(await api.delete(f"protection/header-rules/{rule['key']}"), api_json)


async def test_endpoint_blocks_rules_and_attempts(api: Any, api_app: Any, api_json: Any, section13: Any,
                                                  metrics_seed: Any) -> None:  # fmt: skip
    block = ok(await api.post("protection/endpoint-blocks", json={"pattern": "games.roblox.com/v1/games",
                                                                 "note": "expensive"}), api_json)  # fmt: skip
    rule = ok(await api.post("protection/endpoint-rules", json={"pattern": "economy.roblox.com/v1", "limit": 5}),
              api_json)  # fmt: skip
    section13(await api.post("protection/endpoint-rules", json={"pattern": "economy.roblox.com/v1", "limit": 9}), 409,
              "conflict")  # fmt: skip
    section13(await api.post("protection/endpoint-blocks", json={"pattern": "(a|aa)+", "type": "regex"}), 422,
              "invalid_rule")  # fmt: skip
    for ip in ("203.0.113.30", "203.0.113.31", "203.0.113.31"):
        # The abuse verdict's matched rows ride on the refusal event (`detail.rules`, review round 3).
        refused(metrics_seed, 1, ReasonCode.ENDPOINT_BLOCKED, 403, client_ip=ip, path="games.roblox.com/v1/games/1",
                matches={"rules_endpoint_block": str(block["key"])})  # fmt: skip
    refused(metrics_seed, 2, ReasonCode.ENDPOINT_RULE, 429, client_ip="203.0.113.40", path="economy.roblox.com/v1/x",
            endpoint_template="economy.roblox.com/v1/x")  # fmt: skip
    await metrics_seed.flush()
    attempts = ok(await api.get("protection/endpoint-blocks/attempts"), api_json)
    assert attempts["total"] == 1
    item = attempts["items"][0]
    assert (item["path"], item["attempts"], item["clients"]) == ("games.roblox.com/v1/games/1", 3, 2)
    assert item["methods"] == ["GET"]
    assert item["current_rule"] == "games.roblox.com/v1/games"
    assert item["refused_by"] == ["games.roblox.com/v1/games"]  # the rule that refused, as recorded
    assert "rule_ids" not in item
    attempts = ok(await api.get("protection/endpoint-rules/attempts"), api_json)
    assert attempts["items"][0]["attempts"] == 2
    assert attempts["items"][0]["current_rule"] == "economy.roblox.com/v1"
    assert attempts["items"][0]["refused_by"] == []  # refusals that recorded no rule name none
    refused(metrics_seed, 1, ReasonCode.HEADER_RULE, 429, client_ip="203.0.113.41", path="games.roblox.com/v2/x")
    await metrics_seed.flush()
    filtered = ok(await api.get("protection/header-rules/attempts"), api_json)
    assert [(item["path"], item["current_rule"]) for item in filtered["items"]] == [("games.roblox.com/v2/x", None)]
    export = await api.get("protection/endpoint-blocks/attempts", params={"format": "json"})
    assert export.status_code == 200
    assert json.loads(export.content)["items"][0]["attempts"] == 3
    blocks = ok(await api.get("protection/endpoint-blocks"), api_json)
    assert [b["pattern"] for b in blocks["items"]] == ["games.roblox.com/v1/games"]
    ok(await api.patch(f"protection/endpoint-blocks/{block['key']}", json={"enabled": False}), api_json)
    assert api_app.ctx.rules.snapshot.endpoint_blocks[0].enabled is False
    ok(await api.delete(f"protection/endpoint-rules/{rule['key']}"), api_json)
    ok(await api.delete(f"protection/endpoint-blocks/{block['key']}"), api_json)


async def test_ignored_paths(api: Any, api_json: Any, section13: Any) -> None:
    ok(await api.post("protection/ignored-paths", json={"pattern": "wp-admin", "note": "scanner"}), api_json)
    section13(await api.post("protection/ignored-paths", json={"pattern": "games.roblox.com/v1"}), 422, "invalid_rule")
    table = ok(await api.get("protection/ignored-paths"), api_json)
    assert "wp-admin" in [item["pattern"] for item in table["items"]]
    ok(await api.delete("protection/ignored-paths", params={"pattern": "wp-admin"}), api_json)
    section13(await api.delete("protection/ignored-paths", params={"pattern": "wp-admin"}), 404, "not_found")


# ============================================================================================ detectors and heuristics


async def test_spam_states_dry_run_results_collateral_and_arming(
    api: Any, api_app: Any, api_json: Any, section13: Any, metrics_seed: Any
) -> None:
    for subject, game in (("ip:203.0.113.20", False), ("ip:203.0.113.21", False), ("ip:203.0.113.22", True)):
        metrics_seed.event("spam_would_ban", "warning", "spam", {
            "detector": "SPAM-RATE", "subject": subject, "action": "ban", "game_server": game,
            "evidence": "SPAM-RATE: 999 in 600 s (threshold 600)",
        })  # fmt: skip
    metrics_seed.record(20, client_ip="203.0.113.21")  # served: looks legitimate
    refused(metrics_seed, 20, ReasonCode.THROTTLE, 429, client_ip="203.0.113.20")  # refused: looks abusive
    await metrics_seed.flush()
    state = ok(await api.get("protection/spam"), api_json)
    assert state["dry_run"] is True
    rate = next(item for item in state["detectors"] if item["id"] == "rate")
    assert rate["decisions"] == {"spam_would_ban": 3}
    assert rate["effective_action"] == "would_ban"
    events = ok(await api.get("protection/spam/events", params={"kind": "would_ban"}), api_json)
    assert events["total"] == 3
    assert events["items"][0]["detector"] == "SPAM-RATE"
    preview = ok(await api.get("protection/spam/collateral"), api_json)
    legit = {entry["subject"]: entry for entry in preview["legitimate_looking"]}
    assert set(legit) == {"ip:203.0.113.21", "ip:203.0.113.22"}
    assert legit["ip:203.0.113.21"]["served_pct"] == 100.0
    assert any("game server" in why for why in legit["ip:203.0.113.22"]["why"])
    token = preview["token"]
    section13(await api.post("protection/spam/arm", json={"confirm_collateral": "0" * 32, "reason": "ready"}), 409,
              "conflict")  # fmt: skip
    api.make_mfa_stale()
    section13(await api.post("protection/spam/arm", json={"confirm_collateral": token, "reason": "ready"}), 403,
              "reauth_required")  # fmt: skip
    await api.fresh_mfa()
    armed = ok(await api.post("protection/spam/arm", json={"confirm_collateral": token, "reason": "reviewed"}),
               api_json)  # fmt: skip
    assert armed["dry_run"] is False
    assert armed["confirmed"] == 2
    assert api_app.ctx.settings.bool("spam_dry_run") is False
    disarmed = ok(await api.post("protection/spam/disarm", json={}), api_json)
    assert disarmed["dry_run"] is True


async def test_tarpit_state_has_the_effective_cap_fields(api: Any, api_app: Any, api_json: Any) -> None:
    await api_app.settings(tarpit_enabled=1, tarpit_max_concurrent=64, tarpit_connection_budget=100)
    state = ok(await api.get("protection/tarpit"), api_json)
    assert state["enabled"] is True
    assert (state["max_concurrent"], state["configured_concurrent"], state["clamped"]) == (25, 64, True)
    assert state["clamped_by"] == "connection_budget"
    assert state["formula"].endswith("= 25")
    assert state["active_holds"] == 0
    assert state["slots_free"] == 25
    assert state["stats_scope"] == "this_worker"
    assert set(state["category_labels"]) == set(state["all_categories"])


async def test_bot_pipeline_and_refusals_for_the_range(api: Any, api_json: Any, metrics_seed: Any) -> None:
    refused(metrics_seed, 2, ReasonCode.BANNED, 403)
    refused(metrics_seed, 1, ReasonCode.DENY_LIST, 403, check="bans")
    refused(metrics_seed, 4, ReasonCode.NOT_ROBLOX, 404)
    refused(metrics_seed, 1, ReasonCode.HOST_NOT_ALLOWED, 404, check="not_roblox")
    refused(metrics_seed, 3, ReasonCode.BOT_SCORE, 403)
    metrics_seed.record(5)
    metrics_seed.event("ua_rule_hit", "info", None, {"rule_id": "abcd1234", "result": "allowed"}, aggregate=True)
    metrics_seed.event("throttle_tier", "info", None, {"tier": 1}, aggregate=True, count=2)
    await flush_closed_minute(metrics_seed)
    diagram = ok(await api.get("protection/pipeline"), api_json)
    assert [check["name"] for check in diagram["checks"]] == list(PIPELINE_ORDER)
    by_name = {check["name"]: check["refused"] for check in diagram["checks"]}
    assert (by_name["bans"], by_name["not_roblox"], by_name["bot_score"], by_name["pause"]) == (3, 5, 3, 0)
    assert diagram["requests"] == 16
    assert diagram["refused"] == 11
    assert diagram["ua_rule_hits"]["by_rule"]["abcd1234"]["allowed"] == 1
    assert diagram["throttle_tiers"] == {"1": 2}
    bot = ok(await api.get("protection/bot"), api_json)
    assert bot["refused"]["bot_score"] == 3
    assert bot["block_enabled"] is False
    assert bot["challenge"]["available"] is True
    assert bot["tracker_scope"] == "this_worker"
    reasons = ok(await api.get("protection/refusals"), api_json)
    assert {item["reason"]: item["requests"] for item in reasons["items"]}["not_roblox"] == 4
