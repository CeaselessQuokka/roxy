"""Built-in defaults: the data Roxy ships with, and the one-time seed that puts it into control.db.

What this is
    The default rule data of plan 15.5 and the v1 defaults that were data rather than settings: ignored cache
    parameters, default cache rules (each with a note saying why), the POST caching allowlist, the id-list
    normalization candidates, the allowed Roblox hosts (plan 9.10), the default throttle ladder (with the C5
    replacement message), and the default ignored paths and ignored value headers from v1. `seed_defaults(conn,
    now)` inserts the table-backed ones as rows with origin `default`, exactly once per database.

Why it exists
    v1 kept these in `config.py` and seeded them into memory at import, so "Restore defaults" buttons each carried
    their own copy (the dashboard had a second copy of the ladder, dash included). Here there is one copy, the
    seed records that it ran in `service_state`, and a default the admin deleted stays deleted: seeding again does
    nothing. Rules seeded here are ordinary rows the admin can edit or remove; the ladder's "reset to defaults"
    (parity row 125) and similar buttons read the same tuples.

How it works
    - Each default row is validated through the same input model an admin edit uses (`rules/models.py`), so a
      default can never be something the API would refuse.
    - `seed_defaults` runs inside the caller's write transaction. It does nothing when the marker row
      `service_state.defaults_seeded` says this seed version already ran. Otherwise it inserts every default that
      is not already present (INSERT OR IGNORE for name-keyed tables, a pattern check for cache rules, the ladder
      only when the table is empty so an imported v1 ladder wins), respects every table cap, writes one audit row,
      writes the marker, and bumps `config_version` when anything was inserted.
    - Call it from the migration step (`ROXY_AUTO_MIGRATE=1` in development, `deploy.sh` and `MIGRATION.md` in
      production) or `python -m roxy.config.defaults --seed --state-dir DIR`. Workers never seed on their own.
    - `allowed_roblox_hosts` is a setting (catalog default), not a table, so it is re-exported, not seeded.
    - Id-list normalization (sorting `universeIds=3,1,2`) is shipped as candidates with `verified=False`: plan
      15.5 allows it only on endpoints proven (with a recorded response) to answer the same for any order. A
      candidate becomes a `sort_csv:<param>` flag on its default cache rule only once `verified=True`.

What to read next
    `roxy/config/constants.py` (fixed bounds), `roxy/rules/models.py` (the validation every row passes) and
    `roxy/rules/service.py` (how the ladder reset reuses `THROTTLE_TIERS`).
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, Final

from roxy.config import audit
from roxy.config.audit import SYSTEM_ACTOR, Actor
from roxy.config.constants import SUGGESTED_CACHE_IGNORED_PARAMS
from roxy.config.runtime import bump_config_version
from roxy.config.settings.routing import DEFAULT_ALLOWED_ROBLOX_HOSTS
from roxy.core.clock import SYSTEM_CLOCK, Clock
from roxy.rules.models import (
    RULE_TABLES,
    CacheIgnoredParamIn,
    CacheRuleIn,
    IgnoredPathIn,
    IgnoredValueHeaderIn,
    ThrottleTierIn,
    to_columns,
)
from roxy.storage.db import Database

# --- Ignored cache parameters (plan 15.5) -----------------------------------------------------------------------------

# Cache busters: a caller appending a changing value (a timestamp, a random number) makes every request a new key,
# so the cache stores constantly and never hits. These names carry no meaning for Roblox APIs. `v` is NOT here:
# some Roblox APIs use it meaningfully, so it stays a suggestion only (constants.SUGGESTED_CACHE_IGNORED_PARAMS).
IGNORED_CACHE_PARAMS: Final[tuple[str, ...]] = tuple(name for name in SUGGESTED_CACHE_IGNORED_PARAMS if name != "v")
IGNORED_CACHE_PARAM_NOTE: Final = "Built-in default: a cache-busting parameter that never changes a Roblox answer."

# --- Allowed hosts (plan 9.10) ----------------------------------------------------------------------------------------

# One copy: the catalog default of the `allowed_roblox_hosts` setting (config/settings/routing.py), full host names.
ALLOWED_ROBLOX_HOSTS: Final[tuple[str, ...]] = DEFAULT_ALLOWED_ROBLOX_HOSTS

# --- Fingerprint value suppression (v1 config.DEFAULT_IGNORED_VALUE_HEADERS) ----------------------------------------

# Headers that carry a unique value on every request (tracing ids): their names are still counted, but recording
# every distinct value would be unbounded work with no diagnostic value. v1's note for these rows was "default".
IGNORED_VALUE_HEADERS: Final[tuple[str, ...]] = (
    "traceparent",
    "tracestate",
    "x-request-id",
    "request-id",
    "x-correlation-id",
    "x-amzn-trace-id",
    "x-b3-traceid",
    "x-b3-spanid",
    "x-b3-parentspanid",
)
IGNORED_VALUE_HEADER_NOTE: Final = "default"

# --- Ignored paths (v1 index.py path_ignore_set, parity row 50) ------------------------------------------------------

IGNORED_PATHS: Final[tuple[tuple[str, str], ...]] = (
    (".well-known/appspecific/com.chrome.devtools.json", "Chrome DevTools asks every site for this file."),
    ("favicon.ico", "Served by its own route; kept as a guard in case a request reaches the proxy path."),
)

# --- Throttle ladder (v1 config.DEFAULT_THROTTLE_TIERS, rows 40 and 125) --------------------------------------------


@dataclass(frozen=True, slots=True)
class DefaultTier:
    """One shipped rung: the throttle duration multiplier, the caller-facing message and the admin note."""

    multiplier: float
    message: str
    note: str


# The v1 rung 1 message contained an em dash; plan C5's exceptions table gives this replacement.
DEFAULT_TIER_MESSAGE: Final = "Too many requests; please slow down."

THROTTLE_TIERS: Final[tuple[DefaultTier, ...]] = (
    DefaultTier(1.0, DEFAULT_TIER_MESSAGE, "First strike: probably just fast."),
    DefaultTier(
        2.0,
        "You are about to be severely throttled. Please respect the proxy's limits.",
        "Second strike: a warning they can still act on.",
    ),
    DefaultTier(
        4.0,
        "You have been harshly throttled due to bot behavior. The proxy is happy for you to scrape data, but please "
        "respect its limits. If you need more request bandwidth, contact CeaselessQuokka.",
        "Third strike: says what to do about it.",
    ),
    DefaultTier(
        8.0,
        "You are still ignoring the proxy's limits, so the wait has been extended again. Contact CeaselessQuokka if "
        "you need more request bandwidth.",
        "Fourth strike and beyond: the last rung repeats.",
    ),
)


def throttle_tier_rows() -> list[dict[str, Any]]:
    """The default ladder as `throttle_tiers` input rows (rung 1 at position 1); no ban rung (plan 10.4)."""
    return [
        {"position": index, "multiplier": tier.multiplier, "message": tier.message, "note": tier.note}
        for index, tier in enumerate(THROTTLE_TIERS, start=1)
    ]


# --- Cache rules and the POST allowlist (plan 15.5) ------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class DefaultCacheRule:
    """One shipped cache rule. Patterns are anchored regexes so a rule never covers a sub-resource by accident
    (a glob for `games.roblox.com/v1/games` would also cover the fast-changing server lists below it)."""

    pattern: str
    ttl: int
    note: str
    type: str = "regex"
    stale_ttl: int = 0
    negative_ttl: int = 0
    methods: tuple[str, ...] = ("GET",)
    normalize_flags: tuple[str, ...] = ()


CACHE_RULES: Final[tuple[DefaultCacheRule, ...]] = (
    DefaultCacheRule(
        r"^games\.roblox\.com/v1/games$",
        300,
        "Game details (name, description, player counts) for a list of universes. Five minutes keeps player "
        "counts reasonably fresh while absorbing repeated lookups.",
    ),
    DefaultCacheRule(
        r"^games\.roblox\.com/v1/games/votes$",
        300,
        "Up and down votes for a list of universes. Votes move slowly, so five minutes is safe.",
    ),
    DefaultCacheRule(
        r"^games\.roblox\.com/v1/games/\d+/votes$",
        300,
        "Votes for one universe; same reasoning as the list form.",
    ),
    DefaultCacheRule(
        r"^apis\.roblox\.com/universes/v1/places/\d+/universe$",
        86_400,
        "Maps a place to its universe. A place never moves to another universe, so the answer is effectively "
        "immutable; one day is the longest TTL a rule may have.",
    ),
    DefaultCacheRule(
        r"^thumbnails\.roblox\.com/v1/batch$",
        600,
        "Batch thumbnail lookup: a read-only POST whose body is part of the cache key. Thumbnail URLs change rarely.",
        methods=("POST",),
    ),
    DefaultCacheRule(
        r"^users\.roblox\.com/v1/users/\d+$",
        600,
        "One user's profile basics (name, display name, description, join date); profiles change rarely.",
    ),
    DefaultCacheRule(
        r"^users\.roblox\.com/v1/users$",
        600,
        "Batch user lookup by id: a read-only POST, keyed by a hash of its body.",
        methods=("POST",),
    ),
    DefaultCacheRule(
        r"^users\.roblox\.com/v1/usernames/users$",
        600,
        "Batch user lookup by user name: a read-only POST, keyed by a hash of its body.",
        methods=("POST",),
    ),
    DefaultCacheRule(
        r"^groups\.roblox\.com/v1/groups/\d+$",
        600,
        "Group information (name, owner, member count); changes rarely.",
    ),
    DefaultCacheRule(
        r"^badges\.roblox\.com/v1/badges/\d+$",
        3600,
        "Badge metadata (name, description, icon) is set by the creator and rarely edited; one hour.",
    ),
    DefaultCacheRule(
        r"^catalog\.roblox\.com/v1/catalog/items/\d+/details$",
        600,
        "Catalog item details (name, price, creator). Prices change occasionally, so ten minutes.",
    ),
    DefaultCacheRule(
        r"^economy\.roblox\.com/v2/assets/\d+/details$",
        600,
        "Asset details (name, price, creator). Prices change occasionally, so ten minutes.",
    ),
    DefaultCacheRule(
        r"^presence\.roblox\.com/v1/presence/users$",
        15,
        "Online status for a list of users: a read-only POST. Presence changes fast, so 15 seconds, plus 15 "
        "seconds of stale serving while one refresh runs in the background.",
        stale_ttl=15,
        methods=("POST",),
    ),
)

# POST requests are cached (body-hash keyed) only for these read-only lookups when `cache_post_requests` is
# `allowlist` (the default). Plan 15.5 also listed games.roblox.com/v1/games/multiget-place-details; it is left out
# because that endpoint is a GET (and needs a signed-in account), so it is not a POST lookup at all.
POST_CACHE_ALLOWLIST: Final[tuple[str, ...]] = tuple(rule.pattern for rule in CACHE_RULES if "POST" in rule.methods)

# Query parameters that carry comma separated id lists (plan 15.5).
ID_LIST_PARAMS: Final[tuple[str, ...]] = ("universeIds", "userIds", "placeIds", "assetIds")


@dataclass(frozen=True, slots=True)
class IdListNormalization:
    """A candidate for sorting an id list in the cache key. Only `verified` entries are applied (see docstring)."""

    pattern: str
    params: tuple[str, ...]
    note: str
    verified: bool = False
    type: str = "regex"

    @property
    def flags(self) -> tuple[str, ...]:
        return tuple(f"sort_csv:{param}" for param in self.params)


ID_LIST_NORMALIZATION: Final[tuple[IdListNormalization, ...]] = (
    IdListNormalization(
        r"^games\.roblox\.com/v1/games$",
        ("universeIds",),
        "Needs a recorded response showing the data order does not follow the request order.",
    ),
    IdListNormalization(
        r"^games\.roblox\.com/v1/games/votes$",
        ("universeIds",),
        "Needs a recorded response showing the data order does not follow the request order.",
    ),
    IdListNormalization(
        r"^thumbnails\.roblox\.com/v1/games/icons$",
        ("universeIds",),
        "Needs a recorded response; no default cache rule covers this endpoint yet.",
    ),
    IdListNormalization(
        r"^thumbnails\.roblox\.com/v1/users/avatar-headshot$",
        ("userIds",),
        "Needs a recorded response; no default cache rule covers this endpoint yet.",
    ),
    IdListNormalization(
        r"^thumbnails\.roblox\.com/v1/assets$",
        ("assetIds",),
        "Needs a recorded response; no default cache rule covers this endpoint yet.",
    ),
)


def cache_rule_rows(
    rules: Sequence[DefaultCacheRule] = CACHE_RULES,
    normalization: Sequence[IdListNormalization] = ID_LIST_NORMALIZATION,
) -> list[dict[str, Any]]:
    """The default cache rules as `rules_cache` input rows (origin `default`), with verified id-list flags."""
    rows: list[dict[str, Any]] = []
    for rule in rules:
        flags = list(rule.normalize_flags)
        for candidate in normalization:
            if candidate.verified and candidate.pattern == rule.pattern and candidate.type == rule.type:
                flags += [flag for flag in candidate.flags if flag not in flags]
        rows.append(
            {
                "type": rule.type,
                "pattern": rule.pattern,
                "ttl": rule.ttl,
                "stale_ttl": rule.stale_ttl,
                "negative_ttl": rule.negative_ttl,
                "methods": list(rule.methods),
                "normalize_flags": flags,
                "note": rule.note,
                "origin": "default",
            }
        )
    return rows


# --- The seed --------------------------------------------------------------------------------------------------------

SEED_MARKER_KEY: Final = "defaults_seeded"
SEED_VERSION: Final = 1


@dataclass(slots=True)
class SeedReport:
    """What `seed_defaults` did: per table, how many default rows it inserted and how many it skipped."""

    already_seeded: bool = False
    inserted: dict[str, int] = field(default_factory=dict)
    skipped: dict[str, int] = field(default_factory=dict)
    config_version: int | None = None

    @property
    def total_inserted(self) -> int:
        return sum(self.inserted.values())

    def as_dict(self) -> dict[str, Any]:
        return {
            "already_seeded": self.already_seeded,
            "inserted": dict(self.inserted),
            "skipped": dict(self.skipped),
            "config_version": self.config_version,
        }


def _insert(conn: sqlite3.Connection, table: str, columns: dict[str, Any], ignore: bool) -> bool:
    names = list(columns)
    verb = "INSERT OR IGNORE" if ignore else "INSERT"
    placeholders = ", ".join("?" for _ in names)
    quoted = ", ".join(f'"{name}"' for name in names)
    cursor = conn.execute(
        f"{verb} INTO {table} ({quoted}) VALUES ({placeholders})",
        [columns[name] for name in names],
    )
    return cursor.rowcount > 0


def _room(conn: sqlite3.Connection, table: str) -> int:
    count = int(conn.execute(f"SELECT count(*) FROM {table}").fetchone()[0])  # noqa: S608 (fixed table name)
    return RULE_TABLES[table].cap - count


def seed_defaults(conn: sqlite3.Connection, now_s: int, actor: Actor = SYSTEM_ACTOR) -> SeedReport:
    """Insert the built-in default rows once (inside the caller's write transaction). See the module docstring."""
    report = SeedReport()
    marker = conn.execute("SELECT value_json FROM service_state WHERE key = ?", (SEED_MARKER_KEY,)).fetchone()
    if marker is not None:
        try:
            seeded_version = int(json.loads(marker[0]).get("version", 0))
        except (ValueError, TypeError, AttributeError):
            seeded_version = 0
        if seeded_version >= SEED_VERSION:
            report.already_seeded = True
            return report

    def count(table: str, inserted: bool) -> None:
        bucket = report.inserted if inserted else report.skipped
        bucket[table] = bucket.get(table, 0) + 1

    # Name-keyed tables: INSERT OR IGNORE, so an admin's (or the v1 import's) row with the same name is kept.
    simple: list[tuple[str, list[dict[str, Any]]]] = [
        (
            "cache_ignored_params",
            [
                to_columns(
                    RULE_TABLES["cache_ignored_params"],
                    CacheIgnoredParamIn(name=name, note=IGNORED_CACHE_PARAM_NOTE, origin="default"),
                )
                for name in IGNORED_CACHE_PARAMS
            ],
        ),
        (
            "ignored_value_headers",
            [
                to_columns(
                    RULE_TABLES["ignored_value_headers"],
                    IgnoredValueHeaderIn(name=name, note=IGNORED_VALUE_HEADER_NOTE),
                )
                for name in IGNORED_VALUE_HEADERS
            ],
        ),
        (
            "ignored_paths",
            [
                to_columns(RULE_TABLES["ignored_paths"], IgnoredPathIn(pattern=pattern, note=note))
                for pattern, note in IGNORED_PATHS
            ],
        ),
    ]
    for table, rows in simple:
        for columns in rows:
            if _room(conn, table) <= 0:
                count(table, False)
                continue
            count(table, _insert(conn, table, columns, ignore=True))

    # The ladder only when there is none: an imported v1 ladder (or a deliberately flat one) wins.
    tiers_table = RULE_TABLES["throttle_tiers"]
    has_tiers = conn.execute("SELECT 1 FROM throttle_tiers LIMIT 1").fetchone() is not None
    for row in throttle_tier_rows():
        if has_tiers:
            count("throttle_tiers", False)
            continue
        count("throttle_tiers", _insert(conn, "throttle_tiers", to_columns(tiers_table, ThrottleTierIn(**row)), False))

    # Cache rules: skip a default whose pattern and type already exist (edited or imported).
    cache_table = RULE_TABLES["rules_cache"]
    for row in cache_rule_rows():
        model = CacheRuleIn(**row)
        exists = conn.execute(
            "SELECT 1 FROM rules_cache WHERE pattern = ? AND type = ?", (model.pattern, model.type)
        ).fetchone()
        if exists is not None or _room(conn, "rules_cache") <= 0:
            count("rules_cache", False)
            continue
        columns = to_columns(cache_table, model)
        columns.update(created_at=int(now_s), created_by=actor.label)
        count("rules_cache", _insert(conn, "rules_cache", columns, ignore=False))

    conn.execute(
        "INSERT INTO service_state (key, value_json, updated_at) VALUES (?, ?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json, updated_at = excluded.updated_at",
        (SEED_MARKER_KEY, json.dumps({"version": SEED_VERSION, "at": int(now_s)}), int(now_s)),
    )
    audit.record(
        conn,
        actor,
        "defaults.seed",
        "defaults",
        None,
        report.as_dict(),
        "Built-in defaults shipped with v2 (plan 15.5)",
        None,
        at=int(now_s),
    )
    if report.total_inserted:
        report.config_version = bump_config_version(conn, int(now_s))
    return report


async def seed_control_defaults(db: Database, clock: Clock | None = None, actor: Actor = SYSTEM_ACTOR) -> SeedReport:
    """`seed_defaults` in its own control.db write transaction (async callers)."""
    now = int((clock or SYSTEM_CLOCK).now())
    return await db.write(lambda conn: seed_defaults(conn, now, actor))


def main(argv: Sequence[str] | None = None) -> int:
    """`python -m roxy.config.defaults --seed [--state-dir DIR]`: seed control.db once and print the report."""
    from roxy.storage.db import resolve_db_paths

    parser = argparse.ArgumentParser(description="Insert Roxy's built-in default rows into control.db (once).")
    parser.add_argument("--seed", action="store_true", help="insert the defaults (required; a guard against typos)")
    parser.add_argument("--state-dir", help="directory holding control.db (default: ROXY_STATE_DIR or ROXY_*_DB)")
    args = parser.parse_args(argv)
    if not args.seed:
        parser.error("nothing to do; pass --seed")
    env: dict[str, str] = {"ROXY_STATE_DIR": args.state_dir} if args.state_dir else dict(os.environ)
    _state_dir, paths = resolve_db_paths(env)
    db = Database("control", paths["control"])
    try:
        report = db.write_sync(lambda conn: seed_defaults(conn, int(time.time()), Actor("cli", "defaults")))
    finally:
        db.close_sync()
    sys.stdout.write(json.dumps(report.as_dict(), sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())


__all__ = [
    "ALLOWED_ROBLOX_HOSTS",
    "CACHE_RULES",
    "DEFAULT_TIER_MESSAGE",
    "ID_LIST_NORMALIZATION",
    "ID_LIST_PARAMS",
    "IGNORED_CACHE_PARAMS",
    "IGNORED_PATHS",
    "IGNORED_VALUE_HEADERS",
    "POST_CACHE_ALLOWLIST",
    "SEED_MARKER_KEY",
    "SEED_VERSION",
    "THROTTLE_TIERS",
    "DefaultCacheRule",
    "DefaultTier",
    "IdListNormalization",
    "SeedReport",
    "cache_rule_rows",
    "seed_control_defaults",
    "seed_defaults",
    "throttle_tier_rows",
]
