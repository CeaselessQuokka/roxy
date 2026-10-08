"""Tests for `roxy.rules.service` (DESIGN.md section 5; plan 5.7, 9.7, 9.9, 15.4; rows 40, 43 to 46, 54, 112, 125).

Every write is one transaction with an audit row and a config_version bump; updates go by primary key; header
rules keep the v1 canonical key under a unique index; caps from config/constants.py hold.
"""

from __future__ import annotations

import asyncio
import json
import math
import sqlite3
from collections.abc import Callable
from typing import Any

import pytest

from roxy.config import constants
from roxy.config.audit import Actor
from roxy.config.defaults import DEFAULT_TIER_MESSAGE
from roxy.config.runtime import read_config_version
from roxy.core.clock import FakeClock
from roxy.rules.models import RULE_TABLES
from roxy.rules.service import (
    RuleCapReached,
    RuleConflict,
    RuleNotFound,
    RulesError,
    RulesService,
    RuleValidationError,
)

ADMIN = Actor("admin", "owner", "192.0.2.50")
EM_DASH = chr(0x2014)


@pytest.fixture
def service(dbs: Any, fake_clock: FakeClock) -> RulesService:
    return RulesService(dbs.control, clock=fake_clock)


def _version(dbs: Any) -> int:
    return int(dbs.control.read_sync(read_config_version))


def _rows(dbs: Any, sql: str, params: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
    return [tuple(row) for row in dbs.control.read_sync(lambda conn: conn.execute(sql, params).fetchall())]


# --- valid rows and bulk fillers per table ----------------------------------------------------------------------------

VALID: dict[str, tuple[dict[str, Any], dict[str, Any]]] = {
    "rules_endpoint_block": ({"pattern": "new.roblox.com"}, {"pattern": "new2.roblox.com"}),
    "rules_endpoint_limit": ({"pattern": "new.roblox.com", "limit": 3}, {"pattern": "new2.roblox.com", "limit": 3}),
    "rules_cache": ({"pattern": "new.roblox.com", "ttl": 5}, {"pattern": "new2.roblox.com", "ttl": 5}),
    "rules_user_agent": ({"needle": "new-agent"}, {"needle": "new-agent-2"}),
    "rules_header": ({"needle": "new-needle"}, {"needle": "new-needle-2"}),
    "rules_routing": (
        {"pattern": "new.roblox.com", "mode": "direct_only"},
        {"pattern": "new2.roblox.com", "mode": "direct_only"},
    ),
    "upstream_limits": (
        {"bucket_key": "host:new.roblox.com", "per_min": 5, "burst": 1},
        {"bucket_key": "endpoint:new.roblox.com/v1/{id}", "per_min": 5, "burst": 1},
    ),
    "credential_allowlist": (
        {"pattern": "new.roblox.com", "cache_private": False},
        {"pattern": "new2.roblox.com", "cache_private": True},
    ),
    "cache_ignored_params": ({"name": "newparam"}, {"name": "newparam2"}),
    "ignored_value_headers": ({"name": "x-new"}, {"name": "x-new-2"}),
    "ignored_paths": ({"pattern": "new/path"}, {"pattern": "new/path2"}),
    "access_list": ({"kind": "bypass", "cidr": "192.0.2.1"}, {"kind": "bypass", "cidr": "192.0.2.2"}),
    "bans": ({"subject_type": "ip", "subject": "192.0.2.1"}, {"subject_type": "ip", "subject": "192.0.2.2"}),
}


def _filler(table: str) -> tuple[str, Callable[[int], tuple[Any, ...]]]:
    """An INSERT statement and a row generator that fill `table` quickly with distinct, valid rows."""
    fillers: dict[str, tuple[str, Callable[[int], tuple[Any, ...]]]] = {
        "rules_endpoint_block": (
            "INSERT INTO rules_endpoint_block (pattern, type, created_at, created_by) VALUES (?, 'glob', 0, 't')",
            lambda i: (f"fill{i}.roblox.com",),
        ),
        "rules_endpoint_limit": (
            'INSERT INTO rules_endpoint_limit (pattern, type, scope, "limit", period) '
            "VALUES (?, 'glob', 'ip', 1, 60)",
            lambda i: (f"fill{i}.roblox.com",),
        ),
        "rules_cache": (
            "INSERT INTO rules_cache (pattern, type, ttl) VALUES (?, 'glob', 60)",
            lambda i: (f"fill{i}.roblox.com",),
        ),
        "rules_user_agent": (
            "INSERT INTO rules_user_agent (id, needle, mode, kind, position) VALUES (?, ?, 'contains', 'burst', ?)",
            lambda i: (f"{i:08x}", f"agent{i}", i),
        ),
        "rules_header": (
            "INSERT INTO rules_header (canonical_key, scope, mode, needle, header) "
            "VALUES (?, 'either', 'contains', ?, '')",
            lambda i: (f"|either|contains|fill{i}", f"fill{i}"),
        ),
        "rules_routing": (
            "INSERT INTO rules_routing (pattern, type, mode, created_at, created_by) "
            "VALUES (?, 'glob', 'prefer_direct', 0, 't')",
            lambda i: (f"fill{i}.roblox.com",),
        ),
        "upstream_limits": (
            "INSERT INTO upstream_limits (bucket_key, per_min, burst, origin, updated_at, updated_by) "
            "VALUES (?, 10, 1, 'admin', 0, 't')",
            lambda i: (f"endpoint:fill.roblox.com/{i}",),
        ),
        "credential_allowlist": (
            "INSERT INTO credential_allowlist (pattern, type, cache_private, created_at, created_by) "
            "VALUES (?, 'glob', 1, 0, 't')",
            lambda i: (f"fill{i}.roblox.com",),
        ),
        "cache_ignored_params": ("INSERT INTO cache_ignored_params (name) VALUES (?)", lambda i: (f"fill{i}",)),
        "ignored_value_headers": ("INSERT INTO ignored_value_headers (name) VALUES (?)", lambda i: (f"x-fill{i}",)),
        "ignored_paths": ("INSERT INTO ignored_paths (pattern) VALUES (?)", lambda i: (f"fill/{i}",)),
        "access_list": (
            "INSERT INTO access_list (kind, cidr, created_by) VALUES ('bypass', ?, 't')",
            lambda i: (f"10.{i // 256}.{i % 256}.1/32",),
        ),
        "bans": (
            "INSERT INTO bans (subject_type, subject, reason_code, created_at, created_by) "
            "VALUES ('ip', ?, 'x', 0, 't')",
            lambda i: (f"10.{i // 65536 % 256}.{i // 256 % 256}.{i % 256}",),
        ),
    }
    return fillers[table]


def _fill(dbs: Any, table: str, count: int) -> None:
    sql, row = _filler(table)

    def write(conn: sqlite3.Connection) -> None:
        conn.executemany(sql, (row(i) for i in range(count)))

    dbs.control.write_sync(write)


def _cap(table: str) -> int:
    spec = RULE_TABLES[table]
    return constants.MAX_THROTTLE_BYPASS_IPS if table == "access_list" else spec.cap


# --- create, audit and config_version ---------------------------------------------------------------------------------


@pytest.mark.parametrize("table", sorted(VALID))
async def test_create_writes_row_audit_and_version(dbs: Any, service: RulesService, table: str) -> None:
    change = await service.create(table, VALID[table][0], ADMIN, "because", request_id="r1")
    assert change.changed
    assert change.action == "create"
    assert change.config_version == 1 == _version(dbs)
    stored = await service.get_row(table, change.key)
    assert stored == change.after
    audit_rows = _rows(dbs, "SELECT actor, actor_ip, action, target, before_json, reason, request_id FROM audit_log")
    assert audit_rows == [("admin:owner", "192.0.2.50", "rule.create", f"{table}:{change.key}", None, "because", "r1")]
    after = json.loads(_rows(dbs, "SELECT after_json FROM audit_log")[0][0])
    assert after[RULE_TABLES[table].pk] == change.key
    assert len(await service.list_rows(table)) == 1


@pytest.mark.parametrize("table", sorted(VALID))
async def test_caps_are_enforced(dbs: Any, service: RulesService, table: str) -> None:
    cap = _cap(table)
    _fill(dbs, table, cap - 1)
    await service.create(table, VALID[table][0], ADMIN)
    with pytest.raises(RuleCapReached) as caught:
        await service.create(table, VALID[table][1], ADMIN)
    assert caught.value.cap == cap
    assert f"limit is {cap}" in caught.value.message
    assert len(await service.list_rows(table)) == cap


def test_cap_values_come_from_constants() -> None:
    assert RULE_TABLES["rules_cache"].cap == constants.MAX_CACHE_RULES == 500
    assert RULE_TABLES["rules_endpoint_limit"].cap == constants.MAX_ENDPOINT_RULES
    assert RULE_TABLES["rules_endpoint_block"].cap == constants.MAX_ENDPOINT_BLOCKS
    assert RULE_TABLES["rules_user_agent"].cap == constants.MAX_USER_AGENT_RULES
    assert RULE_TABLES["rules_header"].cap == constants.MAX_HEADER_RULES
    assert RULE_TABLES["cache_ignored_params"].cap == constants.MAX_CACHE_IGNORED_PARAMS == 100
    assert RULE_TABLES["ignored_value_headers"].cap == constants.MAX_IGNORED_VALUE_HEADERS
    assert RULE_TABLES["throttle_tiers"].cap == constants.MAX_THROTTLE_TIERS


async def test_expired_access_entries_do_not_count_against_the_cap(
    dbs: Any, service: RulesService, fake_clock: FakeClock
) -> None:
    sql, row = _filler("access_list")
    expired_sql = sql.replace("(kind, cidr, created_by)", "(kind, cidr, created_by, expires_at)").replace(
        "'t')", "'t', 1)"
    )
    dbs.control.write_sync(lambda conn: conn.executemany(expired_sql, (row(i) for i in range(500))))
    await service.create("access_list", {"kind": "bypass", "cidr": "192.0.2.1"}, ADMIN)
    # Other kinds have their own caps.
    await service.create("access_list", {"kind": "deny", "cidr": "192.0.2.1"}, ADMIN)


# --- validation -------------------------------------------------------------------------------------------------------

INVALID = [
    ("rules_endpoint_block", {"pattern": "   "}, "pattern", "Empty endpoint pattern"),
    ("rules_endpoint_block", {"pattern": "(", "type": "regex"}, "pattern", "Invalid regular expression"),
    ("rules_endpoint_block", {"pattern": "(a+)+$", "type": "regex"}, "pattern", "Nested quantifiers"),
    ("rules_endpoint_block", {"pattern": "a.roblox.com", "type": "fuzzy"}, "type", "glob"),
    ("rules_endpoint_block", {"pattern": "a.roblox.com", "bogus": 1}, "bogus", "Unknown field"),
    ("rules_endpoint_block", {"pattern": "a.roblox.com", "message": "m" * 401}, "message", "longer than 400"),
    ("rules_endpoint_block", {"pattern": "a.roblox.com", "note": "n" * 201}, "note", "longer than 200"),
    ("rules_endpoint_block", {"pattern": "a.roblox.com", "message": f"go {EM_DASH} away"}, "message", "dash"),
    ("rules_endpoint_limit", {"pattern": "a.roblox.com", "limit": 0}, "limit", "greater than or equal to 1"),
    ("rules_endpoint_limit", {"pattern": "a.roblox.com"}, "limit", "required"),
    ("rules_endpoint_limit", {"pattern": "a.roblox.com", "limit": 5, "scope": "planet"}, "scope", "ip"),
    ("rules_user_agent", {"needle": "  "}, "needle", "Enter the User-Agent text to match"),
    ("rules_user_agent", {"needle": "(a*)*", "mode": "regex"}, "needle", "Nested quantifiers"),
    ("rules_user_agent", {"needle": "x", "mode": "fuzzy"}, "mode", "contains"),
    ("rules_user_agent", {"needle": "x", "kind": "burst", "limit": 0}, "limit", "Burst allowance"),
    ("rules_user_agent", {"needle": "x", "kind": "burst", "period": 0}, "period", "Burst window"),
    ("rules_user_agent", {"needle": "x", "kind": "cooldown", "cooldown": 0}, "cooldown", "between 0 and 3600"),
    ("rules_user_agent", {"needle": "x" * 201}, "needle", "longer than 200"),
    ("rules_header", {"needle": ""}, "needle", "Empty match text"),
    ("rules_header", {"needle": "x", "header": "bad header"}, "header", "header name"),
    ("rules_header", {"needle": "[", "mode": "regex"}, "needle", "Invalid regular expression"),
    ("rules_routing", {"pattern": "a.roblox.com", "mode": "teleport"}, "mode", "prefer_direct"),
    ("credential_allowlist", {"pattern": "a.roblox.com"}, "cache_private", "required"),
    (
        "credential_allowlist",
        {"pattern": "a.roblox.com", "cache_private": True, "methods": ["POST"]},
        "methods",
        "POST",
    ),
    ("upstream_limits", {"bucket_key": "host:evil.example", "per_min": 1, "burst": 1}, "bucket_key", "roblox.com"),
    ("upstream_limits", {"bucket_key": "nonsense", "per_min": 1, "burst": 1}, "bucket_key", "host:"),
    ("upstream_limits", {"bucket_key": "host:games.roblox.com", "per_min": math.nan, "burst": 1}, "per_min", ""),
    ("throttle_tiers", {"position": 1, "multiplier": 0}, "multiplier", "greater than 0"),
    ("throttle_tiers", {"position": 1, "multiplier": 1001}, "multiplier", "1000"),
    ("throttle_tiers", {"position": 13, "multiplier": 1}, "position", "12"),
    ("throttle_tiers", {"position": 1, "multiplier": 2, "action": "ban"}, "rule", "ban_minutes"),
    ("cache_ignored_params", {"name": " "}, "name", "Enter a query parameter name"),
    ("ignored_value_headers", {"name": "bad name"}, "name", "valid header name"),
    ("ignored_paths", {"pattern": ""}, "pattern", "Empty path"),
    ("access_list", {"kind": "deny", "cidr": "0.0.0.0/0"}, "cidr", "too wide"),
    ("access_list", {"kind": "deny", "cidr": "nope"}, "cidr", "not a valid"),
    ("access_list", {"kind": "vip", "cidr": "192.0.2.1"}, "kind", "bypass"),
    ("bans", {"subject_type": "place", "subject": "abc"}, "subject", "place id"),
    ("bans", {"subject_type": "ip", "subject": "300.1.1.1"}, "subject", "not a valid IP"),
    ("bans", {"subject_type": "ua_hash", "subject": "xyz"}, "subject", "hash"),
    ("bans", {"subject_type": "ip", "subject": "192.0.2.1", "reason_code": "Bad Code!"}, "reason_code", "reason"),
    ("rules_cache", {"pattern": "a.roblox.com", "normalize_flags": ["evil"]}, "normalize_flags", "Unknown"),
    ("rules_cache", {"pattern": "a.roblox.com", "methods": ["DELETE"]}, "methods", "not allowed"),
    ("rules_cache", {"pattern": "a.roblox.com", "ttl": 86401}, "ttl", "86400"),
]


@pytest.mark.parametrize(("table", "row", "field", "fragment"), INVALID)
async def test_validation_errors(
    dbs: Any, service: RulesService, table: str, row: dict[str, Any], field: str, fragment: str
) -> None:
    with pytest.raises(RuleValidationError) as caught:
        await service.create(table, row, ADMIN)
    fields = {error["field"]: error["message"] for error in caught.value.errors}
    assert field in fields, caught.value.errors
    assert fragment.lower() in fields[field].lower()
    assert _version(dbs) == 0
    assert _rows(dbs, "SELECT count(*) FROM audit_log") == [(0,)]


async def test_reason_is_checked(service: RulesService) -> None:
    with pytest.raises(RuleValidationError) as caught:
        await service.create("rules_endpoint_block", {"pattern": "a.roblox.com"}, ADMIN, f"x {EM_DASH} y")
    assert caught.value.errors[0]["field"] == "reason"


async def test_unknown_table(service: RulesService) -> None:
    with pytest.raises(RulesError):
        await service.create("settings", {}, ADMIN)


async def test_normalization_on_create(service: RulesService) -> None:
    block = await service.create("rules_endpoint_block", {"pattern": " /Games.Roblox.com/V1 ", "type": "GLOB"}, ADMIN)
    assert block.after["pattern"] == "games.roblox.com/v1"
    assert block.after["type"] == "glob"
    regex = await service.create(
        "rules_endpoint_block", {"pattern": r"/^games\.roblox\.com/\D+$", "type": "regex"}, ADMIN
    )
    assert regex.after["pattern"] == r"^games\.roblox\.com/\D+$"  # never lowercased
    access = await service.create("access_list", {"kind": "Bypass", "cidr": "10.1.2.3/8"}, ADMIN)
    assert access.after["cidr"] == "10.0.0.0/8"
    mapped = await service.create("bans", {"subject_type": "ip", "subject": "::ffff:192.0.2.9"}, ADMIN)
    assert mapped.after["subject"] == "192.0.2.9"
    cache = await service.create(
        "rules_cache",
        {"pattern": "c.roblox.com", "methods": "post,get", "normalize_flags": ["sort_csv:userIds"]},
        ADMIN,
    )
    assert cache.after["methods"] == "GET,POST"
    assert json.loads(cache.after["normalize_flags"]) == ["sort_csv:userIds"]
    ua = await service.create("rules_user_agent", {"needle": " Bot ", "kind": "cooldown", "cooldown": 1.23456}, ADMIN)
    assert ua.after["needle"] == "Bot"
    assert ua.after["cooldown"] == 1.235


# --- update and delete by primary key ---------------------------------------------------------------------------------


async def test_update_changes_only_the_given_fields(dbs: Any, service: RulesService, fake_clock: FakeClock) -> None:
    created = await service.create("rules_endpoint_block", {"pattern": "a.roblox.com", "note": "n"}, ADMIN)
    fake_clock.advance(60)
    other = Actor("admin", "second")
    change = await service.update("rules_endpoint_block", str(created.key), {"message": "Go away."}, other, "polite")
    assert change.changed
    assert change.config_version == 2
    assert change.after["message"] == "Go away."
    assert change.after["note"] == "n"
    assert change.after["updated_by"] == "admin:second"
    assert change.after["updated_at"] == int(fake_clock.now())
    assert change.after["created_by"] == "admin:owner"
    audit_row = _rows(dbs, "SELECT action, before_json, after_json FROM audit_log ORDER BY id DESC LIMIT 1")[0]
    assert audit_row[0] == "rule.update"
    assert json.loads(audit_row[1])["message"] == ""
    assert json.loads(audit_row[2])["message"] == "Go away."

    noop = await service.update("rules_endpoint_block", created.key, {"message": "Go away."}, ADMIN)
    assert not noop.changed
    assert noop.config_version == 2 == _version(dbs)
    assert _rows(dbs, "SELECT count(*) FROM audit_log") == [(2,)]


async def test_update_and_delete_errors(service: RulesService) -> None:
    with pytest.raises(RuleNotFound):
        await service.update("rules_endpoint_block", 99, {"message": "x"}, ADMIN)
    with pytest.raises(RuleNotFound):
        await service.delete("rules_endpoint_block", "not-a-number", ADMIN)
    created = await service.create("cache_ignored_params", {"name": "t"}, ADMIN)
    with pytest.raises(RuleValidationError) as caught:
        await service.update("cache_ignored_params", "t", {"name": "u"}, ADMIN)
    assert caught.value.errors[0]["field"] == "name"
    with pytest.raises(RuleValidationError):
        await service.update("cache_ignored_params", created.key, {"bogus": 1}, ADMIN)
    assert await service.get_row("rules_endpoint_block", "nope") is None


async def test_delete_writes_audit_and_bumps(dbs: Any, service: RulesService) -> None:
    created = await service.create("rules_header", {"needle": "xeno", "message": "No."}, ADMIN)
    change = await service.delete("rules_header", created.key, ADMIN, "false positive")
    assert change.before["needle"] == "xeno"
    assert change.after is None
    assert change.config_version == 2
    assert await service.list_rows("rules_header") == []
    action, before, after = _rows(dbs, "SELECT action, before_json, after_json FROM audit_log ORDER BY id DESC")[0]
    assert action == "rule.delete"
    assert json.loads(before)["needle"] == "xeno"
    assert after is None


async def test_stored_rules_that_fail_todays_checks_can_still_be_edited(dbs: Any, service: RulesService) -> None:
    # An imported v1 rule with a nested quantifier: v2 refuses it for new rules but keeps matching it.
    def imported(conn: sqlite3.Connection) -> None:
        conn.execute(
            "INSERT INTO rules_user_agent (id, needle, mode, kind, position) VALUES ('abcd1234', '(a+)+', 'regex', "
            "'burst', 0)"
        )

    dbs.control.write_sync(imported)
    change = await service.update("rules_user_agent", "abcd1234", {"enabled": False, "note": "imported"}, ADMIN)
    assert change.after["enabled"] == 0
    assert change.after["needle"] == "(a+)+"
    with pytest.raises(RuleValidationError):
        await service.update("rules_user_agent", "abcd1234", {"needle": "(b+)+"}, ADMIN)


# --- header rules keep the v1 canonical key (row 112) -----------------------------------------------------------------


async def test_header_rule_duplicates_are_rejected(dbs: Any, service: RulesService) -> None:
    first = await service.create("rules_header", {"needle": "Xeno", "scope": "EITHER", "mode": "Contains"}, ADMIN)
    assert first.after["canonical_key"] == "|either|contains|xeno"
    assert first.after["needle"] == "Xeno"  # stored case preserved
    with pytest.raises(RuleConflict) as caught:
        await service.create("rules_header", {"needle": "xeno"}, ADMIN)
    assert "already exists" in caught.value.message
    targeted = await service.create("rules_header", {"needle": "xeno", "header": "User-Agent", "scope": "key"}, ADMIN)
    assert targeted.after["scope"] == "value"  # a named header forces value scope (v1)
    assert targeted.after["canonical_key"] == "user-agent|value|contains|xeno"
    with pytest.raises(RuleConflict):
        await service.update("rules_header", targeted.key, {"header": "", "scope": "either"}, ADMIN)
    with pytest.raises(RulesError):
        await service.upsert("rules_header", {"needle": "xeno"}, ADMIN)
    assert _rows(dbs, "SELECT count(*) FROM rules_header") == [(2,)]


async def test_concurrent_duplicate_creates_leave_one_row(dbs: Any, service: RulesService) -> None:
    results = await asyncio.gather(
        *(service.create("rules_header", {"needle": "Synapse"}, ADMIN) for _ in range(5)), return_exceptions=True
    )
    assert sum(1 for result in results if not isinstance(result, BaseException)) == 1
    assert all(isinstance(result, RuleConflict) for result in results if isinstance(result, BaseException))
    assert _rows(dbs, "SELECT count(*) FROM rules_header") == [(1,)]


async def test_duplicate_patterns_are_rejected_per_type(service: RulesService) -> None:
    await service.create("rules_endpoint_block", {"pattern": "a.roblox.com"}, ADMIN)
    with pytest.raises(RuleConflict):
        await service.create("rules_endpoint_block", {"pattern": "/A.roblox.com"}, ADMIN)
    await service.create("rules_endpoint_block", {"pattern": "a.roblox.com", "type": "regex"}, ADMIN)
    await service.create("cache_ignored_params", {"name": "t"}, ADMIN)
    with pytest.raises(RuleConflict):
        await service.create("cache_ignored_params", {"name": "t"}, ADMIN)
    await service.create("access_list", {"kind": "deny", "cidr": "192.0.2.1"}, ADMIN)
    with pytest.raises(RuleConflict):
        await service.create("access_list", {"kind": "deny", "cidr": "192.0.2.1/32"}, ADMIN)


# --- UA rules: ids and order ------------------------------------------------------------------------------------------


async def test_user_agent_ids_positions_and_reorder(dbs: Any, service: RulesService) -> None:
    created = [await service.create("rules_user_agent", {"needle": f"bot{i}"}, ADMIN) for i in range(3)]
    ids = [change.key for change in created]
    assert all(len(rule_id) == 8 and int(rule_id, 16) >= 0 for rule_id in ids)
    assert [change.after["position"] for change in created] == [0, 1, 2]
    change = await service.reorder_user_agent_rules([ids[2], ids[0], ids[1]], ADMIN, "most specific first")
    assert change.changed
    assert change.after == [ids[2], ids[0], ids[1]]
    stored = await service.list_rows("rules_user_agent")
    assert [row["id"] for row in stored] == [ids[2], ids[0], ids[1]]
    again = await service.reorder_user_agent_rules([ids[2], ids[0], ids[1]], ADMIN)
    assert not again.changed
    with pytest.raises(RuleValidationError):
        await service.reorder_user_agent_rules([ids[0]], ADMIN)
    with pytest.raises(RuleValidationError):
        await service.reorder_user_agent_rules([ids[0], ids[0], ids[1]], ADMIN)


# --- upsert (v1 "set" semantics) --------------------------------------------------------------------------------------


async def test_upsert_creates_then_updates(dbs: Any, service: RulesService) -> None:
    first = await service.upsert("cache_ignored_params", {"name": "t", "note": "one"}, ADMIN)
    second = await service.upsert("cache_ignored_params", {"name": "t", "note": "two"}, ADMIN)
    assert (first.action, second.action) == ("create", "update")
    assert second.after["note"] == "two"
    block = await service.upsert("rules_endpoint_block", {"pattern": "a.roblox.com", "message": "one"}, ADMIN)
    same = await service.upsert("rules_endpoint_block", {"pattern": "/a.roblox.com", "message": "two"}, ADMIN)
    assert same.key == block.key
    assert same.after["message"] == "two"
    bypass = await service.upsert("access_list", {"kind": "bypass", "cidr": "192.0.2.7", "note": "office"}, ADMIN)
    extended = await service.upsert(
        "access_list", {"kind": "bypass", "cidr": "192.0.2.7", "note": "office", "expires_at": 10**10}, ADMIN
    )
    assert extended.key == bypass.key
    assert extended.after["expires_at"] == 10**10
    unchanged = await service.upsert("cache_ignored_params", {"name": "t", "note": "two"}, ADMIN)
    assert not unchanged.changed
    with pytest.raises(RulesError):
        await service.upsert("rules_user_agent", {"needle": "x"}, ADMIN)


# --- the throttle ladder (rows 40, 125) -------------------------------------------------------------------------------


async def test_replace_and_reset_the_ladder(dbs: Any, service: RulesService) -> None:
    change = await service.replace_throttle_tiers(
        [{"multiplier": 1, "message": "Slow down."}, {"multiplier": 3, "action": "ban", "ban_minutes": 60}],
        ADMIN,
        "harsher",
    )
    assert change.changed
    assert [row["position"] for row in change.after] == [1, 2]
    assert change.after[1]["action"] == "ban"
    assert change.after[1]["ban_minutes"] == 60
    flat = await service.replace_throttle_tiers([], ADMIN, "flat ladder")
    assert flat.after == []
    reset = await service.reset_throttle_tiers(ADMIN, "row 125 button")
    assert [row["multiplier"] for row in reset.after] == [1.0, 2.0, 4.0, 8.0]
    assert reset.after[0]["message"] == DEFAULT_TIER_MESSAGE
    again = await service.reset_throttle_tiers(ADMIN)
    assert not again.changed
    assert ("throttle_tiers.replace",) in _rows(dbs, "SELECT DISTINCT action FROM audit_log")


async def test_ladder_validation_uses_v1_wording(service: RulesService) -> None:
    with pytest.raises(RuleValidationError) as caught:
        await service.replace_throttle_tiers([{"multiplier": 1}] * 13, ADMIN)
    assert caught.value.errors[0]["message"] == "At most 12 rungs"
    with pytest.raises(RuleValidationError) as caught:
        await service.replace_throttle_tiers([{"multiplier": 1}, "nope", {"multiplier": math.nan}], ADMIN)
    messages = [error["message"] for error in caught.value.errors]
    assert "Rung 2 is not an object" in messages
    assert any(message.startswith("Rung 3:") for message in messages)
    with pytest.raises(RuleValidationError):
        await service.replace_throttle_tiers("not a list", ADMIN)  # type: ignore[arg-type]


async def test_rule_names_that_look_like_secret_targets_are_still_audited(dbs: Any, service: RulesService) -> None:
    created = await service.create("cache_ignored_params", {"name": "credential"}, ADMIN)
    await service.update("cache_ignored_params", created.key, {"note": "not a secret"}, ADMIN)
    await service.delete("cache_ignored_params", created.key, ADMIN)
    targets = _rows(dbs, "SELECT target, after_json FROM audit_log ORDER BY id")
    assert [target for target, _after in targets] == ["cache_ignored_params:credential"] * 3
    assert json.loads(targets[0][1])["name"] == "credential"


async def test_detector_bans_record_their_detector(service: RulesService) -> None:
    change = await service.create(
        "bans",
        {"subject_type": "ip", "subject": "192.0.2.77", "reason_code": "spam_rate", "expires_at": 10**10},
        Actor("system", "auto:spam_rate"),
    )
    assert change.after["created_by"] == "auto:spam_rate"
    assert change.after["hits"] == 0


# --- fix pass: multi-process review F5, spec review 6 and 8 -----------------------------------------------------------


async def test_concurrent_bans_on_one_subject_leave_one_ban(
    dbs: Any, service: RulesService, fake_clock: FakeClock
) -> None:
    """MP review F5: two detectors (or a double submit) banning one IP leave ONE ban, extended to the later end."""
    from roxy.rules.store import load_rules_store

    now = int(fake_clock.now())
    detector = Actor("system", "auto:spam_rate")
    expiries = [now + 600, now + 3600, now + 60, now + 1800]
    results = await asyncio.gather(
        *(
            service.create("bans", {"subject_type": "ip", "subject": "203.0.113.7", "expires_at": e}, detector)
            for e in expiries
        )
    )
    rows = _rows(dbs, "SELECT id, expires_at FROM bans WHERE subject = '203.0.113.7'")
    assert len(rows) == 1
    assert rows[0][1] == now + 3600  # the longest of the four
    assert {result.key for result in results} == {rows[0][0]}
    assert sum(1 for result in results if result.action == "create") == 1
    # Lifting it by id now really lifts it.
    await service.delete("bans", rows[0][0], ADMIN, "false positive")
    store = await load_rules_store(dbs, fake_clock)
    assert store.snapshot.bans.match(ip="203.0.113.7", now=now) is None


async def test_a_permanent_ban_is_never_shortened(dbs: Any, service: RulesService, fake_clock: FakeClock) -> None:
    now = int(fake_clock.now())
    first = await service.create("bans", {"subject_type": "ip", "subject": "198.51.100.4"}, ADMIN)
    again = await service.create(
        "bans", {"subject_type": "ip", "subject": "198.51.100.4", "expires_at": now + 60}, ADMIN
    )
    assert again.key == first.key
    assert not again.changed
    assert _rows(dbs, "SELECT expires_at FROM bans") == [(None,)]
    # An expired ban does not count as active: a new one is a new row.
    expired = await service.create("bans", {"subject_type": "place", "subject": "42", "expires_at": now - 1}, ADMIN)
    fresh = await service.create("bans", {"subject_type": "place", "subject": "42", "expires_at": now + 60}, ADMIN)
    assert fresh.key != expired.key


async def test_unban_by_subject_lifts_every_row(dbs: Any, service: RulesService, fake_clock: FakeClock) -> None:
    def imported_duplicates(conn: sqlite3.Connection) -> None:
        for _ in range(2):
            conn.execute(
                "INSERT INTO bans (subject_type, subject, reason_code, created_at, created_by) "
                "VALUES ('ip', '192.0.2.77', 'banned', 0, 'import')"
            )

    dbs.control.write_sync(imported_duplicates)
    change = await service.unban("ip", " 192.0.2.77 ", ADMIN, "appeal accepted")
    assert change.action == "delete"
    assert len(change.before) == 2
    assert _rows(dbs, "SELECT count(*) FROM bans") == [(0,)]
    with pytest.raises(RuleNotFound):
        await service.unban("ip", "192.0.2.77", ADMIN)
    with pytest.raises(RuleValidationError):
        await service.unban("ip", "not-an-ip", ADMIN)


async def test_a_second_rate_rule_on_the_same_pattern_is_refused(service: RulesService) -> None:
    """Spec review 6: only one endpoint rule (and one cache rule) per pattern can ever win, so a second is refused."""
    await service.create("rules_endpoint_limit", {"pattern": "games.roblox.com/v1/games", "limit": 5}, ADMIN)
    with pytest.raises(RuleConflict):
        await service.create(
            "rules_endpoint_limit", {"pattern": "games.roblox.com/v1/games", "limit": 50, "scope": "global"}, ADMIN
        )
    await service.create("rules_cache", {"pattern": "games.roblox.com/v1/games", "ttl": 30}, ADMIN)
    with pytest.raises(RuleConflict):
        await service.create("rules_cache", {"pattern": "games.roblox.com/v1/games", "type": "regex", "ttl": 5}, ADMIN)
    # upsert by pattern changes the existing rule (v1 "set" semantics), whatever the scope.
    change = await service.upsert(
        "rules_endpoint_limit", {"pattern": "games.roblox.com/v1/games", "limit": 50, "scope": "global"}, ADMIN
    )
    assert change.action == "update"
    assert change.after["scope"] == "global"


async def test_opposite_regex_header_rules_are_two_rules(dbs: Any, service: RulesService) -> None:
    r"""Spec review 8: `^\d+$` and `^\D+$` match opposite values, so both may exist (lead decision 3)."""
    digits = await service.create("rules_header", {"header": "X-Id", "needle": r"^\d+$", "mode": "regex"}, ADMIN)
    others = await service.create("rules_header", {"header": "X-Id", "needle": r"^\D+$", "mode": "regex"}, ADMIN)
    assert digits.after["canonical_key"] == r"x-id|value|regex|^\d+$"
    assert others.after["canonical_key"] == r"x-id|value|regex|^\D+$"
    # Literal case never mattered (matching is case-insensitive): still one rule.
    await service.create("rules_header", {"header": "X-Id", "needle": "^ABC$", "mode": "regex"}, ADMIN)
    with pytest.raises(RuleConflict):
        await service.create("rules_header", {"header": "X-Id", "needle": "^abc$", "mode": "regex"}, ADMIN)


async def test_imported_header_rule_keeps_its_v1_key_on_edit(dbs: Any, service: RulesService) -> None:
    def imported(conn: sqlite3.Connection) -> None:
        conn.execute(
            "INSERT INTO rules_header (id, canonical_key, scope, mode, needle, header) "
            r"VALUES (9, 'x-id|value|regex|^\d+$', 'value', 'regex', '^\D+$', 'X-Id')"
        )

    dbs.control.write_sync(imported)
    change = await service.update("rules_header", 9, {"note": "from v1"}, ADMIN)
    assert change.after["canonical_key"] == r"x-id|value|regex|^\d+$"  # v1 form kept
    moved = await service.update("rules_header", 9, {"needle": r"^\D{2}$"}, ADMIN)
    assert moved.after["canonical_key"] == r"x-id|value|regex|^\D{2}$"  # a real change gets the new form


async def test_ignored_paths_refuse_roblox_endpoints(service: RulesService) -> None:
    """Spec review 4: an ignored path is a silent 404 for every caller, so a Roblox endpoint is refused."""
    for pattern in ("games.roblox.com/v1/games", "/Games.Roblox.com", "*.roblox.com/v1"):
        with pytest.raises(RuleValidationError, match="Roblox endpoint"):
            await service.create("ignored_paths", {"pattern": pattern}, ADMIN)
    change = await service.create("ignored_paths", {"pattern": "/.well-known/security.txt"}, ADMIN)
    assert change.after["pattern"] == ".well-known/security.txt"
