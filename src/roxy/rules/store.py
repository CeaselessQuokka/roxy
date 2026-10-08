"""The rules store: one immutable, precompiled snapshot of every rule table, reloaded when config_version moves.

What this is
    `RulesSnapshot` holds every rule family of control.db (endpoint blocks and rate rules, cache rules, UA rules,
    header filters, routing rules, upstream limits, the credential allowlist, the throttle ladder, ignored
    params, headers and paths, the access lists and the active bans) as frozen row models plus the lookup
    structures the hot path needs: specificity-sorted `PatternIndex`es, ordered tuples, sets, and CIDR indexes.
    `RulesStore` owns the current snapshot of one worker and swaps in a new one when `config_version` changes.

Why it exists
    Plan 5.7: rule edits land in control.db with a `config_version` bump, and every worker reloads within a second.
    Requests read only the in-memory snapshot, never the database. Building the snapshot once per change (compiling
    every pattern, sorting by specificity, indexing CIDRs by prefix length) keeps per-request matching to a few
    dictionary lookups and compiled regex calls. Because a snapshot is immutable and swapped in one assignment, a
    request that grabbed it sees one consistent set of rules even if a reload happens halfway through.

How it works
    - `build_rules_snapshot(conn, now)` runs inside ONE read transaction (`db.read`), reading `config_version` and
      every table together, on a reader thread, so compiling patterns never blocks the event loop.
    - Expired access-list entries and bans are skipped at load and checked again at lookup time (`now`), so an
      entry that expires between reloads stops matching on time.
    - A row that no longer fits its row model (only possible by editing the database by hand) is skipped and
      logged, and listed in `snapshot.invalid_rows`; one bad row never stops the others from loading.
    - Matching helpers take a request target `host/path` (as `rules/match.py` expects) and normalize it.
    - `refresh_if_changed()` reads only the version; on `SharedStateUnavailable` the last good snapshot stays.

What to read next
    `roxy/rules/models.py` (the row models), `roxy/rules/match.py` (pattern semantics), and
    `roxy/rules/service.py` (how rules are written).
"""

from __future__ import annotations

import asyncio
import inspect
import ipaddress
import logging
import sqlite3
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Final, Protocol

from pydantic import ValidationError

from roxy.config.runtime import read_config_version
from roxy.core.clock import SYSTEM_CLOCK, Clock
from roxy.rules import re_compat
from roxy.rules.match import PatternIndex, precompile_text_regex
from roxy.rules.models import (
    RULE_TABLES,
    AccessListRow,
    BanRow,
    CacheIgnoredParamRow,
    CacheRuleRow,
    CredentialAllowlistRow,
    EndpointBlockRow,
    EndpointLimitRow,
    HeaderRuleRow,
    IgnoredPathRow,
    IgnoredValueHeaderRow,
    RoutingRuleRow,
    RuleTable,
    ThrottleTierRow,
    UpstreamLimitRow,
    UserAgentRuleRow,
)
from roxy.storage.db import Database, Databases, SharedStateUnavailable

log = logging.getLogger(__name__)

MAX_SUBSCRIBERS: Final = 256
LOAD_LIMIT_FACTOR: Final = 2  # read at most 2 x cap rows per table, so a hand-edited table cannot exhaust memory

RulesListener = Callable[["RulesSnapshot"], Any]
IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


# --- CIDR index -------------------------------------------------------------------------------------------------------


def parse_ip(value: str | IPAddress) -> IPAddress | None:
    """An address object (IPv4-mapped IPv6 addresses become IPv4), or None when `value` is not an IP address."""
    if isinstance(value, ipaddress.IPv4Address | ipaddress.IPv6Address):
        address: IPAddress = value
    else:
        try:
            address = ipaddress.ip_address(value.strip())
        except ValueError:
            return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


class CidrSet[T]:
    """Networks with payloads and optional expiry, matched in O(number of distinct prefix lengths).

    For each IP version and prefix length present, a dictionary maps the network's leading bits to its entries.
    A lookup shifts the address once per prefix length (longest first) and does one dictionary lookup, so the
    most specific active network wins. This is the "indexed CIDR match, not a scan" of plan 15.4.
    """

    __slots__ = ("_count", "_tables")

    def __init__(self, entries: Iterable[tuple[str, T, int | None]] = ()) -> None:
        tables: dict[int, dict[int, dict[int, list[tuple[float, T]]]]] = {4: {}, 6: {}}
        count = 0
        for cidr, payload, expires_at in entries:
            try:
                network = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                log.warning("rules_cidr_invalid", extra={"fields": {"cidr": str(cidr)[:64]}})
                continue
            bits = network.max_prefixlen
            key = int(network.network_address) >> (bits - network.prefixlen)
            expiry = float("inf") if expires_at is None else float(expires_at)
            tables[network.version].setdefault(network.prefixlen, {}).setdefault(key, []).append((expiry, payload))
            count += 1
        for by_prefix in tables.values():
            for buckets in by_prefix.values():
                for items in buckets.values():
                    items.sort(key=lambda item: -item[0])  # longest-lasting entry first
        # Longest prefix first: the most specific network is checked (and wins) first.
        self._tables: dict[int, tuple[tuple[int, int, dict[int, list[tuple[float, T]]]], ...]] = {
            version: tuple(
                (prefix, (32 if version == 4 else 128) - prefix, by_prefix[prefix])
                for prefix in sorted(by_prefix, reverse=True)
            )
            for version, by_prefix in tables.items()
        }
        self._count = count

    def match(self, ip: str | IPAddress, now: float | None = None) -> T | None:
        """The payload of the most specific active network containing `ip`, or None."""
        address = parse_ip(ip)
        if address is None:
            return None
        moment = time.time() if now is None else now
        value = int(address)
        for _prefix, shift, buckets in self._tables[address.version]:
            items = buckets.get(value >> shift)
            if not items:
                continue
            for expiry, payload in items:
                if expiry > moment:
                    return payload
        return None

    def contains(self, ip: str | IPAddress, now: float | None = None) -> bool:
        """Whether any active network contains `ip`."""
        return self.match(ip, now) is not None

    def __len__(self) -> int:
        return self._count


@dataclass(frozen=True, slots=True)
class AccessLists:
    """The three access lists (plan 10.5) as CIDR indexes, plus the rows for the dashboard."""

    bypass: CidrSet[AccessListRow]
    allow_admin: CidrSet[AccessListRow]
    deny: CidrSet[AccessListRow]
    rows: tuple[AccessListRow, ...] = ()

    @classmethod
    def build(cls, rows: Iterable[AccessListRow]) -> AccessLists:
        items = tuple(rows)

        def of(kind: str) -> CidrSet[AccessListRow]:
            return CidrSet((row.cidr, row, row.expires_at) for row in items if row.kind == kind)

        return cls(of("bypass"), of("allow_admin"), of("deny"), items)


def _lasts_longer(row: BanRow, other: BanRow) -> bool:
    """Whether `row` ends after `other` (a permanent ban, `expires_at` NULL, outlasts every temporary one)."""
    if other.expires_at is None:
        return False
    return row.expires_at is None or row.expires_at > other.expires_at


class BanIndex:
    """Active bans by IP and CIDR (one CIDR index), place id and User-Agent hash (plan 10.5)."""

    __slots__ = ("_networks", "_places", "_ua", "rows")

    def __init__(self, bans: Iterable[BanRow] = ()) -> None:
        self.rows: tuple[BanRow, ...] = tuple(bans)
        self._networks: CidrSet[BanRow] = CidrSet(
            (row.subject, row, row.expires_at) for row in self.rows if row.subject_type in ("ip", "cidr")
        )
        self._places: dict[str, list[BanRow]] = {}
        self._ua: dict[str, list[BanRow]] = {}
        for row in self.rows:
            if row.subject_type == "place":
                self._places.setdefault(row.subject, []).append(row)
            elif row.subject_type == "ua_hash":
                self._ua.setdefault(row.subject.lower(), []).append(row)

    @staticmethod
    def _active(rows: list[BanRow] | None, now: float) -> BanRow | None:
        best: BanRow | None = None
        for row in rows or ():
            if row.expires_at is not None and row.expires_at <= now:
                continue
            if best is None or _lasts_longer(row, best):
                best = row
        return best

    def match(
        self,
        *,
        ip: str | IPAddress | None = None,
        place: str | None = None,
        ua_hash: str | None = None,
        now: float | None = None,
    ) -> BanRow | None:
        """The active ban covering this client, checking IP or CIDR first, then place, then User-Agent hash."""
        moment = time.time() if now is None else now
        if ip is not None:
            hit = self._networks.match(ip, moment)
            if hit is not None:
                return hit
        if place:
            hit = self._active(self._places.get(place), moment)
            if hit is not None:
                return hit
        if ua_hash:
            return self._active(self._ua.get(ua_hash.lower()), moment)
        return None

    def __len__(self) -> int:
        return len(self.rows)


# --- the snapshot -----------------------------------------------------------------------------------------------------


class _PatternRow(Protocol):
    """A row keyed by an endpoint pattern (blocks, endpoint rules, cache rules, routing, credential allowlist)."""

    @property
    def id(self) -> int: ...

    @property
    def pattern(self) -> str: ...

    @property
    def type(self) -> str: ...

    @property
    def enabled(self) -> bool: ...


def _index[R: _PatternRow](rows: Iterable[R], *, on_timeout: bool = False) -> PatternIndex[R]:
    """Enabled rows only, sorted by specificity (then id) so the first match is v1's winner.

    `on_timeout=True` for rules that refuse or limit traffic: a pattern match cut off by the regex timeout then
    counts as a match, so a slow pattern can never be used to slip past them (security review M4).
    """
    return PatternIndex(((row.id, row.pattern, row.type, row) for row in rows if row.enabled), on_timeout=on_timeout)


@dataclass(frozen=True, slots=True)
class RulesSnapshot:
    """Every rule family at one `config_version` (DESIGN.md section 5). Immutable; share it freely."""

    version: int
    loaded_at: float
    endpoint_blocks: tuple[EndpointBlockRow, ...] = ()
    endpoint_limits: tuple[EndpointLimitRow, ...] = ()
    cache_rules: tuple[CacheRuleRow, ...] = ()
    ua_rules: tuple[UserAgentRuleRow, ...] = ()  # evaluation order (position, then creation)
    header_rules: tuple[HeaderRuleRow, ...] = ()  # insertion order (id), the v1 order
    routing_rules: tuple[RoutingRuleRow, ...] = ()
    upstream_limits: Mapping[str, UpstreamLimitRow] = field(default_factory=lambda: MappingProxyType({}))
    credential_allowlist: tuple[CredentialAllowlistRow, ...] = ()
    throttle_tiers: tuple[ThrottleTierRow, ...] = ()  # rung 1 first
    cache_ignored_param_rows: tuple[CacheIgnoredParamRow, ...] = ()
    ignored_value_header_rows: tuple[IgnoredValueHeaderRow, ...] = ()
    ignored_path_rows: tuple[IgnoredPathRow, ...] = ()
    access: AccessLists = field(default_factory=lambda: AccessLists(CidrSet(), CidrSet(), CidrSet()))
    bans: BanIndex = field(default_factory=BanIndex)
    invalid_rows: tuple[str, ...] = ()
    # Derived lookup structures (built in __post_init__).
    endpoint_block_index: PatternIndex[EndpointBlockRow] = field(init=False)
    endpoint_limit_index: PatternIndex[EndpointLimitRow] = field(init=False)
    cache_rule_index: PatternIndex[CacheRuleRow] = field(init=False)
    routing_index: PatternIndex[RoutingRuleRow] = field(init=False)
    credential_index: PatternIndex[CredentialAllowlistRow] = field(init=False)
    ignored_path_index: PatternIndex[IgnoredPathRow] = field(init=False)
    enabled_ua_rules: tuple[UserAgentRuleRow, ...] = field(init=False)
    enabled_header_rules: tuple[HeaderRuleRow, ...] = field(init=False)
    cache_ignored_params: frozenset[str] = field(init=False)
    ignored_value_headers: frozenset[str] = field(init=False)

    def __post_init__(self) -> None:
        # object.__setattr__ because the dataclass is frozen; these are computed once, here, and never change.
        set_ = object.__setattr__
        set_(self, "endpoint_block_index", _index(self.endpoint_blocks, on_timeout=True))
        set_(self, "endpoint_limit_index", _index(self.endpoint_limits, on_timeout=True))
        set_(self, "cache_rule_index", _index(self.cache_rules))
        set_(self, "routing_index", _index(self.routing_rules))
        set_(self, "credential_index", _index(self.credential_allowlist))
        set_(
            self,
            "ignored_path_index",
            PatternIndex((i, row.pattern, "glob", row) for i, row in enumerate(self.ignored_path_rows)),
        )
        set_(self, "enabled_ua_rules", tuple(rule for rule in self.ua_rules if rule.enabled))
        set_(self, "enabled_header_rules", tuple(rule for rule in self.header_rules if rule.enabled))
        # Regex needles are compiled here (a reader thread during reload), not on the first request that needs them.
        needles = [(rule.mode, rule.needle) for rule in self.enabled_ua_rules]
        needles += [(rule.mode, rule.needle) for rule in self.enabled_header_rules]
        for mode, needle in needles:
            if mode == "regex":
                precompile_text_regex(needle)
        set_(self, "cache_ignored_params", frozenset(row.name for row in self.cache_ignored_param_rows))
        set_(self, "ignored_value_headers", frozenset(row.name.lower() for row in self.ignored_value_header_rows))

    @classmethod
    def empty(cls, version: int = 0, loaded_at: float = 0.0) -> RulesSnapshot:
        """A snapshot with no rules at all (tests, and the store before its first load)."""
        return cls(version=version, loaded_at=loaded_at)

    # ---- lookups (target = "host/path"; normalized here exactly like v1) ----

    def endpoint_block_for(self, target: str) -> EndpointBlockRow | None:
        """The most specific enabled endpoint block covering `target` (v1 `match_endpoint_block`)."""
        return self.endpoint_block_index.best(target)

    def endpoint_limit_for(self, target: str) -> EndpointLimitRow | None:
        """The most specific enabled endpoint rate rule covering `target` (v1 `match_endpoint_rule`)."""
        return self.endpoint_limit_index.best(target)

    def cache_rule_for(self, target: str) -> CacheRuleRow | None:
        """The most specific enabled cache rule covering `target` (v1 `match_cache_rule`)."""
        return self.cache_rule_index.best(target)

    def routing_rule_for(self, target: str) -> RoutingRuleRow | None:
        """The most specific enabled routing rule covering `target` (plan 7.2 step 2)."""
        return self.routing_index.best(target)

    def credential_rule_for(self, target: str, method: str) -> CredentialAllowlistRow | None:
        """The allowlist entry letting `method` on `target` use the credential, or None (plan 7.2 step 1).

        The most specific matching entry decides: if it does not list the method, the answer is None (a less
        specific entry never widens a more specific one).
        """
        rule = self.credential_index.best(target)
        if rule is None or method.upper() not in rule.methods:
            return None
        return rule

    def is_ignored_path(self, path: str) -> bool:
        """Whether `path` (without the leading slash) is answered 404 without logging (row 50)."""
        return self.ignored_path_index.any_match(path)

    def upstream_limit(self, bucket_key: str) -> UpstreamLimitRow | None:
        """The override for `host:<host>` or `endpoint:<template>`, if any (plan 7.3)."""
        return self.upstream_limits.get(bucket_key)

    def counts(self) -> dict[str, int]:
        """Rows per family, for the System page and logs."""
        return {
            "endpoint_blocks": len(self.endpoint_blocks),
            "endpoint_limits": len(self.endpoint_limits),
            "cache_rules": len(self.cache_rules),
            "ua_rules": len(self.ua_rules),
            "header_rules": len(self.header_rules),
            "routing_rules": len(self.routing_rules),
            "upstream_limits": len(self.upstream_limits),
            "credential_allowlist": len(self.credential_allowlist),
            "throttle_tiers": len(self.throttle_tiers),
            "cache_ignored_params": len(self.cache_ignored_param_rows),
            "ignored_value_headers": len(self.ignored_value_header_rows),
            "ignored_paths": len(self.ignored_path_rows),
            "access_list": len(self.access.rows),
            "bans": len(self.bans),
        }


def _quoted(columns: Iterable[str]) -> str:
    # Every column is quoted because `limit` is an SQL keyword.
    return ", ".join(f'"{column}"' for column in columns)


def load_rows(
    conn: sqlite3.Connection,
    table: RuleTable,
    invalid: list[str],
    where: str = "",
    params: tuple[Any, ...] = (),
) -> list[Any]:
    """Every row of `table` as its row model, in the table's evaluation order; invalid rows are skipped."""
    columns = table.columns
    limit = max(table.cap, 1000) * LOAD_LIMIT_FACTOR
    sql = f"SELECT {_quoted(columns)} FROM {table.name} {where} ORDER BY {table.order_by} LIMIT ?"  # noqa: S608  # table names and columns come from the RULE_TABLES registry, never from input
    rows: list[Any] = []
    for raw in conn.execute(sql, (*params, limit)).fetchall():
        data = dict(zip(columns, tuple(raw), strict=True))
        try:
            rows.append(table.row_model.model_validate(data))
        except ValidationError as exc:
            key = f"{table.name}:{data.get(table.pk)}"
            invalid.append(key)
            log.error("rules_row_invalid", extra={"fields": {"row": key, "errors": exc.error_count()}})
    return rows


def build_rules_snapshot(conn: sqlite3.Connection, now: float) -> RulesSnapshot:
    """Read `config_version` and every rule table in the caller's read transaction; build the snapshot."""
    # The matcher's one-time Unicode tables, built here on the reader thread rather than on the event loop the first
    # time an admin pattern is validated (no cost after the first call).
    re_compat.warm_up()
    version = read_config_version(conn)
    invalid: list[str] = []
    active = ("WHERE expires_at IS NULL OR expires_at > ?", (int(now),))

    def rows(name: str, where: tuple[str, tuple[Any, ...]] | None = None) -> list[Any]:
        clause, params = where or ("", ())
        return load_rows(conn, RULE_TABLES[name], invalid, clause, params)

    upstream = {row.bucket_key: row for row in rows("upstream_limits")}
    snapshot = RulesSnapshot(
        version=version,
        loaded_at=now,
        endpoint_blocks=tuple(rows("rules_endpoint_block")),
        endpoint_limits=tuple(rows("rules_endpoint_limit")),
        cache_rules=tuple(rows("rules_cache")),
        ua_rules=tuple(rows("rules_user_agent")),
        header_rules=tuple(rows("rules_header")),
        routing_rules=tuple(rows("rules_routing")),
        upstream_limits=MappingProxyType(upstream),
        credential_allowlist=tuple(rows("credential_allowlist")),
        throttle_tiers=tuple(rows("throttle_tiers")),
        cache_ignored_param_rows=tuple(rows("cache_ignored_params")),
        ignored_value_header_rows=tuple(rows("ignored_value_headers")),
        ignored_path_rows=tuple(rows("ignored_paths")),
        access=AccessLists.build(rows("access_list", active)),
        bans=BanIndex(rows("bans", active)),
        invalid_rows=tuple(invalid),
    )
    return snapshot


# --- the live store ---------------------------------------------------------------------------------------------------


class RulesStore:
    """The current rules snapshot of one worker (DESIGN.md section 5), swapped atomically on reload."""

    def __init__(self, db: Database, snapshot: RulesSnapshot | None = None, *, clock: Clock | None = None) -> None:
        self._db = db
        self._clock = clock or SYSTEM_CLOCK
        self._snapshot = snapshot or RulesSnapshot.empty(version=-1)
        self._listeners: list[RulesListener] = []
        self._reload_lock = asyncio.Lock()
        self._failing = False

    @property
    def snapshot(self) -> RulesSnapshot:
        """The current snapshot. Grab it once per request and use that object throughout."""
        return self._snapshot

    @property
    def version(self) -> int:
        """The `config_version` of the current snapshot."""
        return self._snapshot.version

    def subscribe(self, callback: RulesListener) -> Callable[[], None]:
        """Call `callback(snapshot)` after every reload (it may be async). Returns an unsubscribe function."""
        if len(self._listeners) >= MAX_SUBSCRIBERS:
            raise RuntimeError("too many rules subscribers")
        self._listeners.append(callback)

        def unsubscribe() -> None:
            if callback in self._listeners:
                self._listeners.remove(callback)

        return unsubscribe

    async def reload(self) -> RulesSnapshot:
        """Rebuild the snapshot from control.db now. Raises `SharedStateUnavailable` (old snapshot kept)."""
        async with self._reload_lock:
            now = self._clock.now()
            # Reloads are serialized by the lock, so this read never sees an older control.db than the snapshot it
            # replaces: a lower version means the counter really went down (a restore), and the database wins.
            new = await self._db.read(lambda conn: build_rules_snapshot(conn, now))
            if new.version < self._snapshot.version:
                log.warning(
                    "config_version_went_down",
                    extra={"fields": {"from": self._snapshot.version, "to": new.version, "store": "rules"}},
                )
            self._snapshot = new
        log.info("rules_reloaded", extra={"fields": {"version": new.version, "counts": new.counts()}})
        for callback in list(self._listeners):
            try:
                result = callback(new)
                if inspect.isawaitable(result):
                    await result
            except Exception:
                log.exception("rules_subscriber_failed", extra={"fields": {"callback": repr(callback)[:120]}})
        return new

    async def refresh_if_changed(self) -> bool:
        """Reload when `config_version` moved (polled every second by `config.runtime.watch_config`)."""
        try:
            version = await self._db.read(read_config_version)
            if version == self._snapshot.version:
                self._recovered()
                return False
            await self.reload()
        except SharedStateUnavailable as exc:
            if not self._failing:
                log.warning("rules_refresh_failed", extra={"fields": {"error": str(exc)[:200]}})
            self._failing = True
            return False
        self._recovered()
        return True

    def _recovered(self) -> None:
        if self._failing:
            log.info("rules_refresh_recovered", extra={"fields": {"version": self._snapshot.version}})
        self._failing = False


async def load_rules_store(dbs: Databases, clock: Clock | None = None) -> RulesStore:
    """Build the worker's `RulesStore` from control.db (the lifespan's "rules" step, DESIGN.md section 1)."""
    store = RulesStore(dbs.control, clock=clock)
    await store.reload()
    return store


__all__ = [
    "AccessLists",
    "BanIndex",
    "CidrSet",
    "RulesListener",
    "RulesSnapshot",
    "RulesStore",
    "build_rules_snapshot",
    "load_rows",
    "load_rules_store",
    "parse_ip",
]
