"""The Egress page API and the rotator URL routes, in the real app (plan 8.4, 8.5, C2 item 4, parity rows 30 to 33).

Usage is seeded through the real recorder (`record_egress_usage`, outcome events), the rotator's exit IP probe is
answered by a stand-in sender (nothing is sent), and the rotator URL routes are checked for the secret it embeds:
neither the URL nor its password, nor any long piece of them, may appear in an answer, an audit row or a log record.
"""

from __future__ import annotations

import json
import logging
import secrets
from typing import Any

import pytest

from roxy.core.reasons import Egress
from roxy.egress.read_state import project_cycle
from roxy.egress.rotator import DECIMAL_GB

DAY_MS = 86_400_000


def _audit(api_app: Any, action: str | None = None) -> list[dict[str, Any]]:
    def read(conn: Any) -> list[dict[str, Any]]:
        if action is None:
            return [dict(row) for row in conn.execute("SELECT * FROM audit_log ORDER BY id").fetchall()]
        rows = conn.execute("SELECT * FROM audit_log WHERE action = ? ORDER BY id", (action,)).fetchall()
        return [dict(row) for row in rows]

    rows: list[dict[str, Any]] = api_app.ctx.dbs.control.read_sync(read)
    return rows


def _pieces(secret: str, size: int = 24) -> list[str]:
    """Every `size` character window of `secret` (lowercased: the scan ignores ASCII case)."""
    lowered = secret.lower()
    return [lowered[start : start + size] for start in range(max(1, len(lowered) - size + 1))]


def _leaks(blob: str, secret: str) -> bool:
    folded = blob.lower()
    return secret.lower() in folded or any(piece in folded for piece in _pieces(secret))


# ================================================================================================= guards


@pytest.mark.parametrize(
    "path",
    [
        "egress/usage",
        "egress/rotator/budget",
        "egress/rotator/daily",
        "egress/bytes-per-request",
        "egress/top-endpoints",
        "egress/share",
        "egress/exit-ips",
        "egress/sessions",
        "egress/provider-report",
        "egress/trips",
        "rotator",
    ],
)
async def test_every_egress_read_needs_a_session(anon_api: Any, path: str) -> None:
    response = await anon_api.get(path)
    assert response.status_code == 401, (path, response.text)


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("POST", "egress/rotator/probe"),
        ("POST", "egress/provider-report"),
        ("POST", "egress/rotator/enable"),
        ("PUT", "rotator/url"),
        ("DELETE", "rotator/url"),
    ],
)
async def test_every_egress_write_needs_the_csrf_header(api: Any, method: str, path: str) -> None:
    response = await api.request(method, path, json={"reason": "x", "url": "http://a:b@h:1"}, csrf=False)
    assert response.status_code == 403, (method, path, response.text)


# ================================================================================================== usage


async def test_usage_per_egress_and_the_share_of_calls(
    api_app: Any, api: Any, api_json: Any, metrics_seed: Any
) -> None:
    now = api_app.clock.now_ms()
    recorder = api_app.ctx.recorder
    recorder.record_egress_usage("rotator", req_bytes=1000, resp_bytes=9000, overhead_bytes=6000, requests=4, at_ms=now)
    recorder.record_egress_usage("direct", req_bytes=500, resp_bytes=1500, requests=2, at_ms=now)
    metrics_seed.record(3)
    metrics_seed.record(1, egress=Egress.ROTATOR)
    await metrics_seed.flush()
    body = api_json(await api.get("egress/usage", params={"range": "1h"}))
    items = {item["egress"]: item for item in body["items"]}
    assert (items["rotator"]["bytes"], items["rotator"]["calls"], items["rotator"]["bytes_per_call"]) == (
        16000,
        4,
        4000.0,
    )
    assert items["direct"]["bytes"] == 2000
    assert items["credential"]["bytes"] == 0
    assert items["rotator"]["enabled"] is False
    assert items["rotator"]["disabled_reason"] == "rotator_disabled"
    assert body["metering_mode"] in ("socket", "estimate")
    assert set(body["this_worker"]) == {"meters", "usage", "guard"}

    share = api_json(await api.get("egress/share", params={"range": "1h"}))
    lines = {line["key"]: line["points"] for line in share["series"]}
    assert sum(point[1] for point in lines["calls:direct"]) == 3
    assert sum(point[1] for point in lines["calls:rotator"]) == 1
    shares = [point[1] for point in lines["share:direct"] if point[1] is not None]
    assert shares == [75.0]


async def test_bytes_per_call_histogram_and_top_endpoints(
    api_app: Any, api: Any, api_json: Any, metrics_seed: Any
) -> None:
    rotator = {"egress": Egress.ROTATOR, "upstream_calls": 2}
    metrics_seed.record(1, upstream_bytes_in=2000, upstream_bytes_out=1000, **rotator)  # 1,500 bytes per call
    metrics_seed.record(
        1, host="users.roblox.com", endpoint_template="users.roblox.com/v1/users/{userId}", upstream_bytes_in=90_000,
        upstream_bytes_out=10_000, **rotator,
    )  # fmt: skip
    await metrics_seed.flush()
    histogram = api_json(await api.get("egress/bytes-per-request", params={"range": "1h"}))
    counts = {slot["from_bytes"]: slot["calls"] for slot in histogram["slots"] if slot["calls"]}
    assert counts == {1024: 2, 32_768: 2}
    assert histogram["calls"] == 4
    assert "average" in histogram["basis"]

    top = api_json(await api.get("egress/top-endpoints", params={"range": "1h"}))
    assert [row["template"] for row in top["items"]] == [
        "users.roblox.com/v1/users/{userId}",
        "games.roblox.com/v1/games",
    ]
    assert top["items"][0]["bytes"] == 100_000
    assert top["items"][0]["share_pct"] == round(100_000 * 100 / 103_000, 2)
    assert top["egress"] == "rotator"
    direct = api_json(await api.get("egress/top-endpoints", params={"range": "1h", "egress": "direct"}))
    assert direct["total"] == 0
    export = await api.get("egress/top-endpoints", params={"range": "1h", "format": "json"})
    assert json.loads(export.content)["table"] == "egress_top_endpoints"
    (row,) = _audit(api_app, "export.download")
    assert json.loads(row["after_json"])["filters"] == {"egress": "rotator"}


# ================================================================================================= budget


def test_projection_blends_rates_and_bands_by_day_to_day_noise() -> None:
    day = 86_400
    start = 1_759_276_800  # a UTC midnight
    trailing = [100, 200, 100, 200, 100, 200, 100]
    found = project_cycle(cycle_start=start, cycle_end=start + 30 * day, now_s=start + 10 * day, used_bytes=1500,
                          trailing=trailing)  # fmt: skip
    trailing_rate = sum(trailing) / 7
    cycle_rate = 1500 / 10
    rate = 0.7 * trailing_rate + 0.3 * cycle_rate
    assert found.rate_bytes_per_day == round(rate, 1)
    assert found.projected_bytes == round(1500 + rate * 20)
    assert found.low_bytes is not None
    assert found.high_bytes is not None
    assert 1500 <= found.low_bytes < found.projected_bytes < found.high_bytes
    assert found.band == "90 percent"
    flat = project_cycle(
        cycle_start=start, cycle_end=start + 30 * day, now_s=start + day / 2, used_bytes=0, trailing=[]
    )
    assert flat.projected_bytes is None
    assert flat.band_reason == "no usage recorded yet"
    one_day = project_cycle(cycle_start=start, cycle_end=start + 30 * day, now_s=start + 2 * day, used_bytes=50,
                            trailing=[50])  # fmt: skip
    assert one_day.low_bytes is None
    assert one_day.band_reason == "a band needs at least 2 complete days of usage"


async def test_rotator_budget_tiles_projection_and_daily_bars(
    api_app: Any, api: Any, api_json: Any, metrics_seed: Any
) -> None:
    await api_app.settings(rotator_quota_gb_per_month=5, rotator_price_per_gb_usd=2, rotator_daily_cap_mb=500)
    now = api_app.clock.now_ms()
    today = now - now % DAY_MS
    recorder = api_app.ctx.recorder
    for days_back, size in ((1, 100_000_000), (2, 200_000_000), (3, 100_000_000)):
        recorder.record_egress_usage(
            "rotator", req_bytes=0, resp_bytes=size, at_ms=today - days_back * DAY_MS + 3_600_000
        )
    recorder.record_egress_usage("rotator", req_bytes=0, resp_bytes=50_000_000, at_ms=now)
    await metrics_seed.flush()
    body = api_json(await api.get("egress/rotator/budget"))
    tiles = {tile["key"]: tile for tile in body["tiles"]}
    assert tiles["rotator_cycle_bytes"]["value"] == 450_000_000
    assert tiles["rotator_remaining_bytes"]["value"] == 5 * DECIMAL_GB - 450_000_000
    assert tiles["rotator_cost_usd"]["value"] == 0.9
    assert tiles["rotator_projected_bytes"]["value"] == body["projection"]["projected_bytes"]
    projection = body["projection"]
    assert projection["trailing_days"] == 7
    assert projection["low_bytes"] <= projection["projected_bytes"] <= projection["high_bytes"]
    assert projection["sentence"].startswith("At this rate you will use ")
    assert "of 5.0 GB this cycle" in projection["sentence"]
    assert body["quota_bytes"] == 5 * DECIMAL_GB
    assert body["daily_cap_bytes"] == 500_000_000
    assert body["cycle"]["today_bytes"] == 50_000_000

    daily = api_json(await api.get("egress/rotator/daily"))
    bars = daily["days"]
    assert sum(bar["bytes"] for bar in bars) == 450_000_000
    assert bars[-1]["cumulative_bytes"] == 450_000_000
    assert bars[-1]["even_pace_bytes"] == 5 * DECIMAL_GB
    assert daily["hard_stop_bytes"] == 5 * DECIMAL_GB
    previous = api_json(await api.get("egress/rotator/daily", params={"cycle": "previous"}))
    assert previous["cycle"]["end"] == daily["cycle"]["start"]


# ================================================================================= exit IPs and sessions


async def test_exit_ips_are_masked_unless_revealed_and_the_reveal_is_audited(
    api_app: Any, api: Any, api_json: Any
) -> None:
    pool = api_app.ctx.egress.rotator

    class Answer:
        status = 200
        body = b'{"ip": "203.0.113.77"}'

    async def sender(_out: Any) -> Any:
        return Answer()

    pool.set_sender(sender)
    probed = api_json(await api.post("egress/rotator/probe"))
    assert probed["ok"] is True
    assert probed["exit_ip"] == "203.0.113.0/24"
    masked = api_json(await api.get("egress/exit-ips"))
    assert masked["masked"] is True
    assert masked["items"][0]["ip"] == "203.0.113.0/24"
    assert "203.0.113.77" not in json.dumps(masked)
    assert _audit(api_app, "egress.exit_ips_reveal") == []
    revealed = api_json(await api.get("egress/exit-ips", params={"reveal": "true"}))
    assert revealed["items"][0]["ip"] == "203.0.113.77"
    (row,) = _audit(api_app, "egress.exit_ips_reveal")
    assert json.loads(row["after_json"]) == {"count": 1}


async def test_sessions_show_mode_park_and_exits(api_app: Any, api: Any, api_json: Any) -> None:
    body = api_json(await api.get("egress/sessions", params={"range": "1h"}))
    assert body["configured"] is True
    assert body["effective_mode"] == "per_request"  # no username template yet (plan 8.2)
    assert body["mode_note"].startswith("Sticky modes need")
    assert body["health"]["parked"] is False
    now = api_app.clock.now_ms()
    await api_app.ctx.dbs.hot.write(
        lambda conn: conn.execute(
            "INSERT INTO cooldown (key, until_ms, source, set_at, hits) VALUES ('rotator:parked', ?, 'breaker', ?, 1)",
            (now + 45_000, now // 1000),
        )
    )
    parked = api_json(await api.get("egress/sessions"))
    assert parked["health"]["parked"] is True
    assert parked["health"]["park_remaining_s"] == 45.0


# ======================================================================================= provider report


async def test_provider_report_is_stored_audited_and_compared(
    api_app: Any, api: Any, api_json: Any, metrics_seed: Any, section13: Any
) -> None:
    api_app.ctx.recorder.record_egress_usage(
        "rotator", req_bytes=0, resp_bytes=1_100_000_000, at_ms=api_app.clock.now_ms()
    )
    await metrics_seed.flush()
    empty = api_json(await api.get("egress/provider-report"))
    assert empty["latest"] is None
    assert empty["diff_pct"] is None
    created = await api.post("egress/provider-report", json={"reported_gb": 1.0, "reason": "from the dashboard"})
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["latest"]["reported_bytes"] == DECIMAL_GB
    assert body["metered_bytes"] == 1_100_000_000
    assert body["diff_pct"] == 10.0
    assert body["threshold_pct"] == 10.0
    (row,) = _audit(api_app, "egress.provider_report")
    assert json.loads(row["after_json"])["reported_bytes"] == DECIMAL_GB
    section13(await api.post("egress/provider-report", json={"reported_gb": -1}), 422, "validation_failed")


# ========================================================================================= leak guard trips


async def test_reenabling_a_tripped_egress_needs_a_fresh_factor_and_a_reason(
    api_app: Any, api: Any, api_json: Any, section13: Any
) -> None:
    row = {
        "reason": "leak_guard",
        "since": 1,
        "location": "header",
        "purpose": "caller",
        "request_id": "R",
        "worker": "w",
    }
    await api_app.ctx.dbs.control.write(
        lambda conn: conn.execute(
            "INSERT INTO service_state (key, value_json, updated_at) VALUES ('egress_disabled:direct', ?, 1)",
            (json.dumps(row),),
        )
    )
    await api_app.ctx.egress.refresh()
    trips = api_json(await api.get("egress/trips"))
    (trip,) = trips["items"]
    assert (trip["egress"], trip["location"], trip["tripped_here"]) == ("direct", "header", True)
    usage = api_json(await api.get("egress/usage"))
    assert {item["egress"]: item["disabled_reason"] for item in usage["items"]}["direct"] == "leak_guard_tripped"

    api.make_mfa_stale()
    stale = await api.post("egress/direct/enable", json={"reason": "fixed the code path"})
    section13(stale, 403, "reauth_required")
    await api.fresh_mfa()
    section13(await api.post("egress/direct/enable", json={"reason": " "}), 422, "validation_failed")
    section13(await api.post("egress/credential/enable", json={"reason": "x"}), 422, "validation_failed")
    enabled = api_json(await api.post("egress/direct/enable", json={"reason": "fixed the code path"}))
    assert enabled == {"egress": "direct", "enabled": True, "disabled_reason": None}
    (audit_row,) = _audit(api_app, "egress.enable")
    assert audit_row["target"] == "egress:direct"
    assert audit_row["reason"] == "fixed the code path"
    again = await api.post("egress/direct/enable", json={"reason": "again"})
    section13(again, 409, "wrong_state")
    assert api_json(await api.get("egress/trips"))["items"] == []


# ============================================================================================ rotator URL


async def test_rotator_url_is_masked_replaced_and_reverted_without_leaking(
    api_app: Any,
    api: Any,
    api_json: Any,
    section13: Any,
    fake_secrets: dict[str, str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)
    bootstrap = fake_secrets["rotator_url"]
    password = "pw" + secrets.token_hex(12)
    new_url = f"http://gateuser:{password}@gw.example.net:823"
    state = api_json(await api.get("rotator"))
    assert (state["configured"], state["source"], state["url"]) == (True, "bootstrap", "http://127.0.0.1:9")
    assert state["can_revert"] is False

    api.make_mfa_stale()
    section13(await api.put("rotator/url", json={"url": new_url}), 403, "reauth_required")
    await api.fresh_mfa()
    bad = await api.put("rotator/url", json={"url": f"ftp://gateuser:{password}@gw.example.net"})
    section13(bad, 422, "invalid_url")
    replaced = api_json(await api.put("rotator/url", json={"url": new_url, "reason": f"new plan {new_url} {password}"}))
    assert (replaced["source"], replaced["url"], replaced["replaced"]) == ("ui", "http://gw.example.net:823", True)
    assert replaced["ui_value"]["masked_host"] == "http://gw.example.net:823"
    assert replaced["can_revert"] is True
    (audit_row,) = _audit(api_app, "rotator.replace_url")
    assert json.loads(audit_row["after_json"])["masked"] == "http://gw.example.net:823"
    assert password not in (audit_row["reason"] or "")

    reverted = api_json(await api.delete("rotator/url", json={"reason": "back to the file"}))
    assert (reverted["source"], reverted["url"], reverted["reverted"]) == ("bootstrap", "http://127.0.0.1:9", True)
    section13(await api.delete("rotator/url"), 409, "wrong_state")

    secrets_to_check = {"new url": new_url, "new password": password, "bootstrap url": bootstrap}
    answers = " ".join(response.text + json.dumps(dict(response.headers)) for response in api.sent)
    rows = json.dumps(_audit(api_app))
    logs = " ".join(f"{record.getMessage()} {record.__dict__!r}" for record in caplog.records)
    found = {
        (where, name)
        for name, value in secrets_to_check.items()
        for where, blob in (("answers", answers), ("audit", rows), ("logs", logs))
        if (value in blob if len(value) < 24 else _leaks(blob, value))
    }
    assert found == set()
