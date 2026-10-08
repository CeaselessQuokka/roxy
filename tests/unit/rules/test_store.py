"""Tests for `roxy.rules.store` (DESIGN.md section 5; plan 5.7, 10.5, rows 111, 113): the compiled snapshot."""

from __future__ import annotations

import ipaddress
import sqlite3
from typing import Any

import pytest

from roxy.config.audit import Actor
from roxy.config.runtime import bump_config_version
from roxy.core.clock import FakeClock
from roxy.rules.service import RulesService
from roxy.rules.store import (
    AccessLists,
    BanIndex,
    CidrSet,
    RulesSnapshot,
    RulesStore,
    build_rules_snapshot,
    load_rules_store,
    parse_ip,
)
from roxy.storage.db import SharedStateUnavailable

ADMIN = Actor("admin", "owner")


def _snapshot(dbs: Any, now: float = 1_000.0) -> RulesSnapshot:
    return dbs.control.read_sync(lambda conn: build_rules_snapshot(conn, now))


@pytest.fixture
def service(dbs: Any, fake_clock: FakeClock) -> RulesService:
    return RulesService(dbs.control, clock=fake_clock)


def test_empty_database_gives_an_empty_snapshot(dbs: Any) -> None:
    snapshot = _snapshot(dbs)
    assert snapshot.version == 0
    assert set(snapshot.counts().values()) == {0}
    assert snapshot.endpoint_block_for("games.roblox.com/v1/games") is None
    assert snapshot.bans.match(ip="1.2.3.4", now=0) is None
    assert RulesSnapshot.empty().counts() == snapshot.counts()


async def test_most_specific_rule_wins_and_disabled_rules_are_ignored(dbs: Any, service: RulesService) -> None:
    await service.create("rules_endpoint_block", {"pattern": "games.roblox.com", "message": "host"}, ADMIN)
    specific = await service.create(
        "rules_endpoint_block", {"pattern": "/games.roblox.com/v1/games", "message": "games"}, ADMIN
    )
    await service.create(
        "rules_endpoint_block", {"pattern": "games.roblox.com/v1/games/*/votes", "enabled": False}, ADMIN
    )
    snapshot = _snapshot(dbs)
    assert snapshot.version == 3
    hit = snapshot.endpoint_block_for("/Games.Roblox.com/v1/games/123/votes")
    assert hit is not None
    assert hit.id == specific.key
    assert hit.message == "games"
    assert snapshot.endpoint_block_for("games.roblox.com/v2/other").message == "host"
    assert snapshot.endpoint_block_for("users.roblox.com/v1/users") is None
    assert len(snapshot.endpoint_blocks) == 3
    assert len(snapshot.endpoint_block_index) == 2


async def test_rule_families_load_in_order(dbs: Any, service: RulesService) -> None:
    second = await service.create("rules_user_agent", {"needle": "python-requests", "position": 5}, ADMIN)
    first = await service.create("rules_user_agent", {"needle": "curl", "position": 1}, ADMIN)
    disabled = await service.create("rules_user_agent", {"needle": "wget", "enabled": False}, ADMIN)
    await service.create("rules_header", {"needle": "xeno"}, ADMIN)
    await service.create("rules_header", {"needle": "synapse", "header": "User-Agent"}, ADMIN)
    await service.create("rules_endpoint_limit", {"pattern": "games.roblox.com", "limit": 5}, ADMIN)
    await service.create("rules_routing", {"pattern": "thumbnails.roblox.com", "mode": "prefer_rotator"}, ADMIN)
    await service.create("upstream_limits", {"bucket_key": "host:games.roblox.com", "per_min": 120, "burst": 10}, ADMIN)
    await service.create("cache_ignored_params", {"name": "_"}, ADMIN)
    await service.create("ignored_value_headers", {"name": "X-Trace"}, ADMIN)
    await service.create("ignored_paths", {"pattern": "/robots.txt"}, ADMIN)
    snapshot = _snapshot(dbs)
    assert [rule.id for rule in snapshot.ua_rules] == [first.key, second.key, disabled.key]
    assert [rule.id for rule in snapshot.enabled_ua_rules] == [first.key, second.key]
    assert [rule.needle for rule in snapshot.header_rules] == ["xeno", "synapse"]
    assert snapshot.header_rules[1].scope == "value"
    assert snapshot.endpoint_limit_for("games.roblox.com/v1/x").limit == 5
    assert snapshot.routing_rule_for("thumbnails.roblox.com/v1/batch").mode == "prefer_rotator"
    assert snapshot.upstream_limit("host:games.roblox.com").per_min == 120
    assert snapshot.cache_ignored_params == frozenset({"_"})
    assert snapshot.ignored_value_headers == frozenset({"x-trace"})
    assert snapshot.is_ignored_path("robots.txt")
    assert not snapshot.is_ignored_path("robots.txt.bak")


async def test_credential_allowlist_checks_the_method(dbs: Any, service: RulesService) -> None:
    await service.create(
        "credential_allowlist",
        {"pattern": "users.roblox.com/v1/users/authenticated", "cache_private": True, "methods": ["GET", "HEAD"]},
        ADMIN,
    )
    await service.create(
        "credential_allowlist", {"pattern": "economy.roblox.com/v1/user", "cache_private": True}, ADMIN
    )
    snapshot = _snapshot(dbs)
    rule = snapshot.credential_rule_for("users.roblox.com/v1/users/authenticated", "head")
    assert rule is not None
    assert rule.methods == ("GET", "HEAD")
    assert rule.cache_private is True
    assert snapshot.credential_rule_for("economy.roblox.com/v1/user/currency", "HEAD") is None
    assert snapshot.credential_rule_for("economy.roblox.com/v1/user/currency", "GET") is not None
    assert snapshot.credential_rule_for("games.roblox.com/v1/games", "GET") is None


def test_cidr_set_prefers_the_most_specific_active_network() -> None:
    cidrs: CidrSet[str] = CidrSet(
        [
            ("10.0.0.0/8", "wide", None),
            ("10.1.0.0/16", "narrow", None),
            ("10.1.2.3/32", "expired host", 500),
            ("2001:db8::/64", "v6", None),
        ]
    )
    assert len(cidrs) == 4
    assert cidrs.match("10.1.2.3", now=1_000) == "narrow"
    assert cidrs.match("10.1.2.3", now=100) == "expired host"
    assert cidrs.match("10.9.9.9", now=0) == "wide"
    assert cidrs.match("::ffff:10.9.9.9", now=0) == "wide"
    assert cidrs.match("2001:db8::1", now=0) == "v6"
    assert cidrs.match("2001:db9::1", now=0) is None
    assert cidrs.match("not an ip", now=0) is None
    assert cidrs.contains(ipaddress.ip_address("10.0.0.1"), now=0)
    assert parse_ip("::ffff:1.2.3.4") == ipaddress.ip_address("1.2.3.4")
    assert parse_ip("nope") is None


async def test_access_lists_are_cidr_aware_and_expire(dbs: Any, service: RulesService, fake_clock: FakeClock) -> None:
    now = int(fake_clock.now())
    await service.create("access_list", {"kind": "bypass", "cidr": "203.0.113.0/24", "expires_at": now + 60}, ADMIN)
    await service.create("access_list", {"kind": "deny", "cidr": "198.51.100.7"}, ADMIN)
    await service.create("access_list", {"kind": "allow_admin", "cidr": "2001:db8::/48"}, ADMIN)
    snapshot = _snapshot(dbs, now)
    assert snapshot.access.bypass.contains("203.0.113.50", now=now)
    assert not snapshot.access.bypass.contains("203.0.113.50", now=now + 61)
    assert snapshot.access.deny.match("198.51.100.7", now=now).cidr == "198.51.100.7/32"
    assert snapshot.access.allow_admin.contains("2001:db8:0:1::5", now=now)
    assert not snapshot.access.deny.contains("198.51.100.8", now=now)
    # An entry that already expired is not even loaded.
    later = _snapshot(dbs, now + 120)
    assert len(later.access.bypass) == 0
    assert len(later.access.rows) == 2


async def test_bans_match_by_ip_cidr_place_and_ua_hash(dbs: Any, service: RulesService, fake_clock: FakeClock) -> None:
    now = int(fake_clock.now())
    await service.create("bans", {"subject_type": "ip", "subject": "192.0.2.10", "expires_at": now + 30}, ADMIN)
    await service.create("bans", {"subject_type": "cidr", "subject": "192.0.2.0/24"}, ADMIN)
    await service.create("bans", {"subject_type": "place", "subject": "123456", "expires_at": now + 30}, ADMIN)
    await service.create("bans", {"subject_type": "place", "subject": "123456"}, ADMIN)
    await service.create("bans", {"subject_type": "ua_hash", "subject": "AB" * 8, "expires_at": now - 1}, ADMIN)
    snapshot = _snapshot(dbs, now)
    # The expired ua ban is not loaded, and the second place ban extended the first (one active ban per subject).
    assert len(snapshot.bans) == 3
    assert snapshot.bans.match(ip="192.0.2.10", now=now).subject == "192.0.2.10"
    assert snapshot.bans.match(ip="192.0.2.99", now=now).subject == "192.0.2.0/24"
    assert snapshot.bans.match(ip="192.0.2.10", now=now + 31).subject == "192.0.2.0/24"
    assert snapshot.bans.match(place="123456", now=now).expires_at is None  # the permanent ban outlasts
    assert snapshot.bans.match(ua_hash="ab" * 8, now=now) is None
    assert snapshot.bans.match(ip="203.0.113.1", place="999", now=now) is None


def test_ban_index_and_access_lists_build_from_rows() -> None:
    assert len(BanIndex()) == 0
    lists = AccessLists.build([])
    assert len(lists.bypass) == len(lists.deny) == len(lists.allow_admin) == 0


def test_invalid_rows_are_skipped_not_fatal(dbs: Any) -> None:
    def corrupt(conn: sqlite3.Connection) -> None:
        conn.execute("INSERT INTO rules_cache (pattern, type, ttl) VALUES ('games.roblox.com', 'glob', 'abc')")
        conn.execute("INSERT INTO rules_cache (pattern, type, ttl) VALUES ('users.roblox.com', 'glob', 60)")

    dbs.control.write_sync(corrupt)
    snapshot = _snapshot(dbs)
    assert [rule.pattern for rule in snapshot.cache_rules] == ["users.roblox.com"]
    assert snapshot.invalid_rows == ("rules_cache:1",)


async def test_store_reloads_on_config_version_change(dbs: Any, service: RulesService, fake_clock: FakeClock) -> None:
    store = await load_rules_store(dbs, fake_clock)
    seen: list[int] = []
    store.subscribe(lambda snapshot: seen.append(snapshot.version))
    assert store.version == 0
    assert await store.refresh_if_changed() is False
    await service.create("rules_endpoint_block", {"pattern": "games.roblox.com"}, ADMIN)
    assert await store.refresh_if_changed() is True
    assert store.version == 1
    assert seen == [1]
    assert store.snapshot.endpoint_block_for("games.roblox.com/x") is not None
    assert await store.refresh_if_changed() is False


async def test_service_reloads_its_own_store(dbs: Any, fake_clock: FakeClock) -> None:
    store = await load_rules_store(dbs, fake_clock)
    service = RulesService(dbs.control, clock=fake_clock, store=store)
    await service.create("rules_endpoint_block", {"pattern": "games.roblox.com"}, ADMIN)
    assert store.version == 1  # no wait for the watcher


async def test_store_follows_the_database_version_even_when_lower(dbs: Any) -> None:
    # Reloads are serialized, so a lower version can only mean the counter really went down (MP review F6):
    # the database is the truth, and a worker that kept its higher-numbered snapshot would never update again.
    store = await load_rules_store(dbs)
    dbs.control.write_sync(lambda conn: bump_config_version(conn, 1))
    await store.reload()
    store._snapshot = RulesSnapshot.empty(version=99)
    assert (await store.reload()).version == 1


class _UnavailableDb:
    async def read(self, fn: Any) -> Any:
        raise SharedStateUnavailable("control", "database is locked")


async def test_unreadable_database_keeps_the_last_snapshot(dbs: Any) -> None:
    good = await load_rules_store(dbs)
    store = RulesStore(_UnavailableDb(), good.snapshot)  # type: ignore[arg-type]
    assert await store.refresh_if_changed() is False
    assert await store.refresh_if_changed() is False
    assert store.snapshot is good.snapshot
    with pytest.raises(SharedStateUnavailable):
        await store.reload()


async def test_async_subscribers_and_errors(dbs: Any) -> None:
    store = await load_rules_store(dbs)
    seen: list[int] = []

    async def listener(snapshot: RulesSnapshot) -> None:
        seen.append(snapshot.version)

    def broken(snapshot: RulesSnapshot) -> None:
        raise RuntimeError("boom")

    store.subscribe(broken)
    unsubscribe = store.subscribe(listener)
    dbs.control.write_sync(lambda conn: bump_config_version(conn, 1))
    assert await store.refresh_if_changed() is True
    assert seen == [1]
    unsubscribe()
    dbs.control.write_sync(lambda conn: bump_config_version(conn, 2))
    await store.refresh_if_changed()
    assert seen == [1]


async def test_rules_follow_a_lower_config_version(dbs: Any, service: RulesService) -> None:
    """MP review F6: a restore that lowers config_version must not freeze the rules on every worker."""
    import json

    for i in range(5):
        await service.create("rules_endpoint_block", {"pattern": f"games.roblox.com/v{i}"}, ADMIN)
    store = await load_rules_store(dbs)
    assert store.version == 5
    assert len(store.snapshot.endpoint_blocks) == 5

    def restore(conn: sqlite3.Connection) -> None:
        conn.execute("DELETE FROM rules_endpoint_block WHERE id > 1")
        conn.execute("UPDATE service_state SET value_json = ? WHERE key = 'config_version'", (json.dumps(1),))

    dbs.control.write_sync(restore)
    assert await store.refresh_if_changed() is True
    assert store.version == 1
    assert len(store.snapshot.endpoint_blocks) == 1
    assert await store.refresh_if_changed() is False
