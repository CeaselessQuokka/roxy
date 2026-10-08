"""A small v1 tree, end to end (plan 19.6 "small"): every rule family, the ladder, pause state and the report."""

from __future__ import annotations

import json
import stat
from typing import Any

from v1_migration_helpers import by_key, load_report, rows

from roxy.config.defaults import DEFAULT_TIER_MESSAGE
from roxy.migration.report import ALREADY, IMPORTED, INVALID, REPLACED_DEFAULT, SKIPPED, write_report
from roxy.migration.runner import MARKER_KEY


async def test_migration_small_tree(v1: Any, ws: Any, migrate: Any, fake_clock: Any) -> None:
    builder = v1.small_tree(ws.v1)
    builder.write()
    report = await migrate()
    assert report.status == "imported"
    assert report.errors == []
    assert report.sources["control_plane"] == "roxy_state.json"
    control = ws.state / "control.db"
    now = int(fake_clock.now())

    blocks = {row["pattern"]: row for row in rows(control, "SELECT * FROM rules_endpoint_block")}
    assert set(blocks) == {"games.roblox.com/v1/games/*/servers", r"^users\.roblox\.com/v1/users/\d+/status$"}
    glob = blocks["games.roblox.com/v1/games/*/servers"]
    assert (glob["type"], glob["message"]) == ("glob", "Blocked: use the official API instead.")
    assert glob["note"] == "server list scrapers, see ticket"
    assert (glob["created_by"], glob["created_at"]) == ("import:v1", v1.V1_TIME)
    assert blocks[r"^users\.roblox\.com/v1/users/\d+/status$"]["type"] == "regex"

    (limit,) = rows(control, "SELECT * FROM rules_endpoint_limit")
    assert (limit["pattern"], limit["scope"], limit["limit"], limit["period"]) == (
        "thumbnails.roblox.com/v1/batch",
        "ip",
        30,
        60,
    )

    cache = {row["pattern"]: row for row in rows(control, "SELECT * FROM rules_cache")}
    assert cache["games.roblox.com/v1/games/*/votes"]["ttl"] == 900
    replaced = cache[r"^games\.roblox\.com/v1/games$"]  # a built-in default pattern: the v1 rule wins
    assert (replaced["ttl"], replaced["origin"], replaced["note"]) == (120, "admin", "v1 rule on a default pattern")
    rule_items = {table: by_key(items) for table, items in report.rules.items()}
    assert rule_items["rules_cache"][r"^games\.roblox\.com/v1/games$"]["status"] == REPLACED_DEFAULT

    ua = rows(control, "SELECT * FROM rules_user_agent ORDER BY position")
    assert [row["id"] for row in ua] == ["a1b2c3d4", "0f0f0f0f"]  # ids kept, v1 order kept
    second = ua[1]
    assert (second["mode"], second["kind"], second["scope"], second["cooldown"], second["enabled"]) == (
        "regex",
        "cooldown",
        "global",
        1.5,
        0,
    )
    assert second["note"] == "game servers (like the others) share one budget"

    headers = {row["canonical_key"]: row for row in rows(control, "SELECT * FROM rules_header")}
    assert set(headers) == {"|either|contains|xeno", "user-agent|value|regex|^\\d+$"}  # the v1 canonical form
    assert headers["user-agent|value|regex|^\\d+$"]["needle"] == "^\\D+$"  # the needle keeps its case
    assert headers["|either|contains|xeno"]["needle"] == "Xeno"

    params = {row["name"]: row for row in rows(control, "SELECT * FROM cache_ignored_params")}
    assert params["_cb2"]["origin"] == "import"
    assert params["t"]["origin"] == "default"
    assert rule_items["cache_ignored_params"]["t"]["status"] == ALREADY

    ignored = {row["name"]: row for row in rows(control, "SELECT * FROM ignored_value_headers")}
    assert ignored["x-amz-cf-id"]["auto"] == 1
    assert len(ignored) == 10

    access = rows(control, "SELECT * FROM access_list")
    assert [(row["kind"], row["cidr"]) for row in access] == [("bypass", "198.51.100.7/32")]
    assert access[0]["expires_at"] == now + 24 * 3600  # the default expiry (bypass_default_expiry_h)
    assert access[0]["note"] == "load test, remove later"
    bypass = rule_items["access_list"]
    assert bypass["192.0.2.1"]["status"] == SKIPPED
    assert bypass["not-an-ip"]["status"] == INVALID

    tiers = rows(control, "SELECT * FROM throttle_tiers ORDER BY position")
    assert [row["multiplier"] for row in tiers] == [1.0, 2.0, 4.0, 8.0]
    assert tiers[0]["message"] == DEFAULT_TIER_MESSAGE
    assert report.ladder["status"] == ALREADY  # the v1 default ladder, after C5, is the v2 default ladder

    state = {row["key"]: json.loads(row["value_json"]) for row in rows(control, "SELECT * FROM service_state")}
    assert state["pause"]["paused"] is False
    assert state["pause"]["reason"] == "Back soon, maintenance window"
    assert "throttle_all" not in state
    marker = state[MARKER_KEY]
    assert (marker["version"], marker["complete"], marker["completed_at"]) == (2, True, now)
    assert len(marker["ledger"]["rules"]["rules_endpoint_block"]) == 2  # hashes of the v1 keys, never the text
    assert all(len(key) == 16 and "roblox" not in key for key in marker["ledger"]["rules"]["rules_endpoint_block"])

    audits = rows(control, "SELECT action, actor, target FROM audit_log WHERE actor = 'import:v1'")
    actions = {row["action"] for row in audits}
    assert {"rule.import", "rule.update", "setting.update", "service_state.import", "v1.import"} <= actions
    imported_rules = [row for row in audits if row["action"] == "rule.import"]
    assert len(imported_rules) == 2 + 1 + 1 + 2 + 2 + 1 + 1 + 1
    assert all(row["actor"] == "import:v1" for row in audits)

    counts = report.counts()
    assert counts[IMPORTED] > 10
    not_migrated = {item["what"]: item for item in report.not_migrated}
    assert not_migrated["emailed 2FA codes"]["count"] == 1
    assert not_migrated["trusted devices"]["count"] == 1
    assert not_migrated["login challenges"]["count"] == 1
    assert not_migrated["session invalidation links"]["count"] == 1
    assert not_migrated["response cache files"]["count"] == 2

    # Trusted devices, 2FA codes, challenges, invalidation tokens and sessions: nothing in v2 (security reset).
    for table in ("trusted_devices", "invalidation_tokens", "admin_sessions"):
        assert rows(control, f"SELECT count(*) FROM {table}")[0][0] == 0

    json_path, markdown_path = write_report(report, ws.report)
    for path in (json_path, markdown_path):
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    data = load_report(ws.report)
    assert data["schema"] == "roxy.v1_migration_report/1"
    assert data["status"] == "imported"
    assert data["dry_run"] is False
    markdown = markdown_path.read_text(encoding="utf-8")
    for heading in ("## Settings", "## Rules", "## Text rewrites (plan C5)", "## Credential files", "## Not migrated"):
        assert heading in markdown


async def test_migration_bypass_entries_that_never_matched_in_v1(v1: Any, ws: Any, migrate: Any) -> None:
    """v1 looked bypass entries up by the client address as exact text, so a range never matched anyone. v2
    bypass is CIDR based and skips throttles, UA and endpoint rules and the tarpit, so importing a range would
    switch on a bypass v1 never applied; only single addresses are imported (review finding 4)."""
    builder = v1.V1TreeBuilder(ws.v1)
    builder.runtime["ThrottleBypassIps"] = {
        "198.51.100.0/24": {"Added": 1.0, "Expires": 0.0, "Note": "office"},
        "203.0.113.7/20": {"Added": 1.0, "Expires": 0.0, "Note": ""},
        "198.51.100.9/32": {"Added": 1.0, "Expires": 0.0, "Note": ""},
        " 198.51.100.10": {"Added": 1.0, "Expires": 0.0, "Note": ""},
        "198.51.100.8": {"Added": 1.0, "Expires": 0.0, "Note": "single address"},
        "2001:db8::5": {"Added": 1.0, "Expires": 0.0, "Note": ""},
    }
    builder.write()
    report = await migrate()
    stored = {row["cidr"] for row in rows(ws.state / "control.db", "SELECT cidr FROM access_list")}
    assert stored == {"198.51.100.8/32", "2001:db8::5/128"}
    items = by_key(report.rules["access_list"])
    for key in ("198.51.100.0/24", "203.0.113.7/20", "198.51.100.9/32", " 198.51.100.10"):
        assert items[key]["status"] == INVALID, key
        assert any("never matched" in note for note in items[key]["notes"]), key
    assert (items["198.51.100.8"]["status"], items["2001:db8::5"]["status"]) == (IMPORTED, IMPORTED)
