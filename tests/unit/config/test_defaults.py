"""Tests for `roxy.config.defaults` (plan 15.5, 9.10, rows 40, 50, 54, 79, 125): the shipped data and its seed."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from roxy.config import catalog, defaults
from roxy.config.defaults import (
    CACHE_RULES,
    DEFAULT_TIER_MESSAGE,
    ID_LIST_NORMALIZATION,
    IGNORED_CACHE_PARAMS,
    IGNORED_PATHS,
    IGNORED_VALUE_HEADERS,
    POST_CACHE_ALLOWLIST,
    SEED_MARKER_KEY,
    THROTTLE_TIERS,
    IdListNormalization,
    cache_rule_rows,
    seed_control_defaults,
    seed_defaults,
    throttle_tier_rows,
)
from roxy.config.runtime import read_config_version
from roxy.core.clock import FakeClock
from roxy.rules.models import CacheRuleIn, ThrottleTierIn
from roxy.rules.store import build_rules_snapshot

PLAN_9_10_HOSTS = [
    "games",
    "users",
    "thumbnails",
    "groups",
    "catalog",
    "economy",
    "badges",
    "presence",
    "friends",
    "inventory",
    "avatar",
    "apis",
    "develop",
    "accountinformation",
    "accountsettings",
    "premiumfeatures",
    "followings",
    "translations",
    "locale",
    "gamejoin",
    "trades",
    "notifications",
    "points",
    "billing",
    "itemconfiguration",
    "contacts",
    "privatemessages",
    "clientsettings",
    "assetdelivery",
    "auth",
    "search",
    "engagementpayouts",
    "voice",
]


def _count(dbs: Any, table: str) -> int:
    return int(dbs.control.read_sync(lambda conn: conn.execute(f"SELECT count(*) FROM {table}").fetchone()[0]))


def _seed(dbs: Any, now: int = 1_000) -> defaults.SeedReport:
    return dbs.control.write_sync(lambda conn: seed_defaults(conn, now))


def test_ignored_params_are_the_v1_suggestions_without_v() -> None:
    assert IGNORED_CACHE_PARAMS == ("t", "_", "ts", "cb", "cachebust", "cache_bust", "rand", "random", "nocache")
    assert "v" not in IGNORED_CACHE_PARAMS


def test_allowed_hosts_match_plan_9_10_and_the_catalog() -> None:
    assert tuple(f"{name}.roblox.com" for name in PLAN_9_10_HOSTS) == defaults.ALLOWED_ROBLOX_HOSTS
    assert list(defaults.ALLOWED_ROBLOX_HOSTS) == catalog.DEFAULTS["allowed_roblox_hosts"]


def test_throttle_ladder_is_v1_with_the_c5_message() -> None:
    assert [tier.multiplier for tier in THROTTLE_TIERS] == [1.0, 2.0, 4.0, 8.0]
    assert THROTTLE_TIERS[0].message == DEFAULT_TIER_MESSAGE == "Too many requests; please slow down."
    assert THROTTLE_TIERS[3].note == "Fourth strike and beyond: the last rung repeats."
    rows = throttle_tier_rows()
    assert [row["position"] for row in rows] == [1, 2, 3, 4]
    for row in rows:
        model = ThrottleTierIn(**row)
        assert model.action == "throttle"
        assert model.ban_minutes is None


def test_v1_value_headers_and_paths() -> None:
    assert len(IGNORED_VALUE_HEADERS) == 9
    assert IGNORED_VALUE_HEADERS[0] == "traceparent"
    assert [pattern for pattern, _note in IGNORED_PATHS] == [
        ".well-known/appspecific/com.chrome.devtools.json",
        "favicon.ico",
    ]


def test_every_default_cache_rule_validates_and_has_a_note() -> None:
    for row in cache_rule_rows():
        model = CacheRuleIn(**row)
        assert model.note
        assert model.origin == "default"
        assert model.pattern.startswith("^"), "anchored, never covers sub-resources"
        assert model.pattern.endswith("$"), "anchored, never covers sub-resources"
    ttl = {rule.pattern: rule.ttl for rule in CACHE_RULES}
    assert ttl[r"^games\.roblox\.com/v1/games$"] == 300
    assert ttl[r"^apis\.roblox\.com/universes/v1/places/\d+/universe$"] == 86_400
    assert ttl[r"^thumbnails\.roblox\.com/v1/batch$"] == 600
    assert ttl[r"^users\.roblox\.com/v1/users/\d+$"] == 600
    assert ttl[r"^groups\.roblox\.com/v1/groups/\d+$"] == 600
    assert ttl[r"^badges\.roblox\.com/v1/badges/\d+$"] == 3600
    presence = next(rule for rule in CACHE_RULES if "presence" in rule.pattern)
    assert (presence.ttl, presence.stale_ttl, presence.methods) == (15, 15, ("POST",))


def test_post_allowlist_is_read_only_lookups() -> None:
    assert set(POST_CACHE_ALLOWLIST) == {
        r"^users\.roblox\.com/v1/users$",
        r"^users\.roblox\.com/v1/usernames/users$",
        r"^thumbnails\.roblox\.com/v1/batch$",
        r"^presence\.roblox\.com/v1/presence/users$",
    }


def test_id_list_normalization_applies_only_when_verified() -> None:
    assert all(not candidate.verified for candidate in ID_LIST_NORMALIZATION)
    assert all(not row["normalize_flags"] for row in cache_rule_rows())
    verified = IdListNormalization(r"^games\.roblox\.com/v1/games$", ("universeIds",), "recorded", verified=True)
    rows = cache_rule_rows(normalization=[verified])
    games = next(row for row in rows if row["pattern"] == r"^games\.roblox\.com/v1/games$")
    assert games["normalize_flags"] == ["sort_csv:universeIds"]
    assert CacheRuleIn(**games).normalize_flags == ("sort_csv:universeIds",)


def test_texts_have_no_dash_characters() -> None:
    texts = [tier.message for tier in THROTTLE_TIERS] + [tier.note for tier in THROTTLE_TIERS]
    texts += [rule.note for rule in CACHE_RULES] + [note for _p, note in IGNORED_PATHS]
    texts += [candidate.note for candidate in ID_LIST_NORMALIZATION]
    for text in texts:
        assert chr(0x2014) not in text
        assert chr(0x2013) not in text


def test_seed_inserts_every_default_once(dbs: Any) -> None:
    report = _seed(dbs)
    assert not report.already_seeded
    assert report.inserted == {
        "cache_ignored_params": 9,
        "ignored_value_headers": 9,
        "ignored_paths": 2,
        "throttle_tiers": 4,
        "rules_cache": len(CACHE_RULES),
    }
    assert report.config_version == 1 == dbs.control.read_sync(read_config_version)
    origins = dbs.control.read_sync(
        lambda conn: {
            row[0]
            for row in conn.execute(
                "SELECT DISTINCT origin FROM rules_cache UNION ALL SELECT DISTINCT origin FROM cache_ignored_params"
            )
        }
    )
    assert origins == {"default"}
    marker = dbs.control.read_sync(
        lambda conn: conn.execute("SELECT value_json FROM service_state WHERE key = ?", (SEED_MARKER_KEY,)).fetchone()
    )
    assert json.loads(marker[0])["version"] == defaults.SEED_VERSION
    actions = dbs.control.read_sync(lambda conn: [r[0] for r in conn.execute("SELECT action FROM audit_log")])
    assert actions == ["defaults.seed"]

    again = _seed(dbs, now=2_000)
    assert again.already_seeded
    assert again.total_inserted == 0
    assert dbs.control.read_sync(read_config_version) == 1
    assert _count(dbs, "audit_log") == 1


def test_a_deleted_default_stays_deleted(dbs: Any) -> None:
    _seed(dbs)
    dbs.control.write_sync(lambda conn: conn.execute("DELETE FROM cache_ignored_params WHERE name = 'rand'"))
    _seed(dbs)
    names = dbs.control.read_sync(lambda conn: {r[0] for r in conn.execute("SELECT name FROM cache_ignored_params")})
    assert "rand" not in names
    assert len(names) == 8


def test_seed_keeps_imported_rows(dbs: Any) -> None:
    def imported(conn: sqlite3.Connection) -> None:
        conn.execute("INSERT INTO throttle_tiers (position, multiplier, message) VALUES (1, 3.0, 'imported')")
        conn.execute("INSERT INTO cache_ignored_params (name, note, origin) VALUES ('t', 'from v1', 'import')")
        conn.execute(
            "INSERT INTO rules_cache (pattern, type, ttl, origin) VALUES (?, 'regex', 5, 'admin')",
            (r"^games\.roblox\.com/v1/games$",),
        )

    dbs.control.write_sync(imported)
    report = _seed(dbs)
    assert report.inserted.get("throttle_tiers", 0) == 0
    assert report.skipped["throttle_tiers"] == 4
    assert report.inserted["cache_ignored_params"] == 8
    assert report.skipped["rules_cache"] == 1
    rows = dbs.control.read_sync(lambda conn: conn.execute("SELECT multiplier, message FROM throttle_tiers").fetchall())
    assert [tuple(row) for row in rows] == [(3.0, "imported")]
    note = dbs.control.read_sync(
        lambda conn: conn.execute("SELECT note FROM cache_ignored_params WHERE name = 't'").fetchone()[0]
    )
    assert note == "from v1"


def test_seeded_rules_work_in_the_snapshot(dbs: Any) -> None:
    _seed(dbs)
    snapshot = dbs.control.read_sync(lambda conn: build_rules_snapshot(conn, 1_000.0))
    assert snapshot.cache_rule_for("games.roblox.com/v1/games").ttl == 300
    assert snapshot.cache_rule_for("GAMES.roblox.com/v1/games/123/votes").ttl == 300
    assert snapshot.cache_rule_for("games.roblox.com/v1/games/123/servers/Public") is None
    assert snapshot.is_ignored_path("favicon.ico")
    assert snapshot.cache_ignored_params == frozenset(IGNORED_CACHE_PARAMS)
    assert "traceparent" in snapshot.ignored_value_headers
    assert [tier.multiplier for tier in snapshot.throttle_tiers] == [1.0, 2.0, 4.0, 8.0]


async def test_async_seed_and_cli(dbs: Any, fake_clock: FakeClock, tmp_path: Path, capsys: Any) -> None:
    report = await seed_control_defaults(dbs.control, fake_clock)
    assert report.total_inserted > 0

    from roxy.storage.db import DB_NAMES
    from roxy.storage.migrate import migrate_paths

    state = tmp_path / "cli_state"
    state.mkdir()
    migrate_paths({name: state / f"{name}.db" for name in DB_NAMES})
    assert defaults.main(["--seed", "--state-dir", str(state)]) == 0
    printed = json.loads(capsys.readouterr().out)
    assert printed["already_seeded"] is False
    assert printed["inserted"]["throttle_tiers"] == 4
    assert defaults.main(["--seed", "--state-dir", str(state)]) == 0
    assert json.loads(capsys.readouterr().out)["already_seeded"] is True
    with pytest.raises(SystemExit):
        defaults.main(["--state-dir", str(state)])
