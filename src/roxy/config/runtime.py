"""Runtime settings: the live, in-memory values of every catalog setting, hot-reloaded across worker processes.

What this is
    `RuntimeSettings` holds one immutable `SettingsSnapshot`: every key of `config/catalog.py`, with the catalog
    default replaced by the admin's override wherever control.db's `settings` table has one. Code reads it with
    `ctx.settings.int("allowed_requests_per_minute")` (or `get`, `float`, `bool`, `str`, `list`) and never touches
    the database to do so. Also here: the `config_version` helpers shared by every control-plane writer, and the
    per-worker `watch_config` loop.

Why it exists
    Plan 5.7: settings, rules, bans and access lists live in control.db, shared by every worker. One counter,
    `service_state.config_version`, is bumped in the same transaction as any change. Each worker polls that
    counter once a second and, when it moved, reloads. So a change made on one worker is live on every worker
    within about a second, and nothing is ever read from the database on the request path. v1 instead re-read a
    whole JSON file when its mtime changed and validated writes against memory up to a second stale.

How it works
    - A snapshot is built from ONE read transaction that reads `config_version` and every override together, so
      the version always describes exactly the values it came with. Each stored value is validated again against
      the current catalog: an override that no longer validates (a range was tightened in a new release) or names
      a key that no longer exists is ignored and logged, and the default applies. Renamed v1 keys are accepted.
    - Snapshots are immutable: list values are stored as tuples and the mappings are read-only views, so a reader
      can keep a snapshot for a whole request and never see a half-applied change.
    - `refresh_if_changed()` reads only the version (one tiny indexed read on a reader thread) and rebuilds the
      snapshot when it differs. Subscribers are called with the new snapshot and the set of keys whose values
      changed. If control.db cannot be read the last good snapshot stays in force (plan C7) and the error is
      logged once per streak.
    - Writes do NOT happen here: `config/settings_service.py` validates, audits and publishes changes.

What to read next
    `roxy/config/settings_service.py` (how a change is written), `roxy/rules/store.py` (the rules side of the
    same `config_version` mechanism), and `roxy/lifespan.py` (where the watcher loop is started).
"""

from __future__ import annotations

import asyncio
import builtins
import inspect
import json
import logging
import sqlite3
from collections.abc import Callable, Iterable, Iterator, Mapping
from types import MappingProxyType
from typing import Any, Final, Protocol

from roxy.config import catalog
from roxy.config.spec import SettingSpec
from roxy.core.clock import SYSTEM_CLOCK, Clock
from roxy.storage.db import Database, Databases, SharedStateUnavailable

log = logging.getLogger(__name__)

CONFIG_VERSION_KEY: Final = "config_version"
CONFIG_POLL_INTERVAL_S: Final = 1.0
"""How often each worker checks `config_version` (plan 5.6 per-worker jobs, 5.7)."""

MAX_SUBSCRIBERS: Final = 256
"""Bound on change callbacks per process (plan P9); subscribers are long-lived components, not requests."""

SettingsListener = Callable[["SettingsSnapshot", frozenset[str]], Any]


# --- config_version helpers (used by every control.db writer) ---------------------------------------------------------


def read_config_version(conn: sqlite3.Connection) -> int:
    """The current `service_state.config_version` (0 when the row is missing)."""
    row = conn.execute("SELECT value_json FROM service_state WHERE key = ?", (CONFIG_VERSION_KEY,)).fetchone()
    if row is None:
        return 0
    try:
        return int(json.loads(row[0]))
    except (TypeError, ValueError):
        log.error("config_version_unreadable", extra={"fields": {"value": str(row[0])[:40]}})
        return 0


def bump_config_version(conn: sqlite3.Connection, now_s: int) -> int:
    """Increment `config_version` inside the caller's write transaction and return the new value (plan 5.7).

    Call it in the SAME transaction as the change it announces: then a worker that sees the new version is
    guaranteed to also see the change, and a rolled back change never announces anything.
    """
    return raise_config_version(conn, read_config_version(conn) + 1, now_s)


def raise_config_version(conn: sqlite3.Connection, at_least: int, now_s: int) -> int:
    """Set `config_version` to at least `at_least` (and always above its current value); return the new value.

    Code that restores old control.db content (a snapshot undo, a backup restore, a factory reset) must call this
    with a value above the highest version any worker may have seen, in the same transaction as the restore.
    Workers reload whenever the version differs from theirs, so a lower version is still picked up, but a counter
    that later climbs back to exactly the version a worker holds would hide the change from that worker.
    """
    new = max(read_config_version(conn) + 1, int(at_least))
    conn.execute(
        "INSERT INTO service_state (key, value_json, updated_at) VALUES (?, ?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json, updated_at = excluded.updated_at",
        (CONFIG_VERSION_KEY, json.dumps(new), int(now_s)),
    )
    return new


# --- the snapshot -----------------------------------------------------------------------------------------------------


def freeze(value: Any) -> Any:
    """Lists become tuples so a snapshot value can never be changed in place by a reader."""
    if isinstance(value, list | tuple):
        return tuple(freeze(item) for item in value)
    return value


def thaw(value: Any) -> Any:
    """The JSON shape of a value (tuples back to lists), for comparing and storing."""
    if isinstance(value, list | tuple):
        return [thaw(item) for item in value]
    return value


def same_value(left: Any, right: Any) -> bool:
    """Whether two canonical setting values are equal (lists and tuples compare by content)."""
    return json.dumps(thaw(left), sort_keys=True) == json.dumps(thaw(right), sort_keys=True)


class SettingsSnapshot(Mapping[str, Any]):
    """An immutable view of every setting at one `config_version`. Behaves as a read-only mapping key -> value."""

    __slots__ = ("_values", "invalid", "loaded_at", "meta", "overrides", "version")

    def __init__(
        self,
        version: int,
        values: Mapping[str, Any],
        overrides: Mapping[str, Any],
        meta: Mapping[str, tuple[int, str]],
        loaded_at: float,
        invalid: tuple[str, ...] = (),
    ) -> None:
        self.version = version
        self._values: Mapping[str, Any] = MappingProxyType({key: freeze(value) for key, value in values.items()})
        self.overrides: Mapping[str, Any] = MappingProxyType({key: freeze(v) for key, v in overrides.items()})
        self.meta: Mapping[str, tuple[int, str]] = MappingProxyType(dict(meta))  # key -> (updated_at, updated_by)
        self.loaded_at = loaded_at
        self.invalid = invalid  # stored override keys that were ignored (unknown or no longer valid)

    def __getitem__(self, key: str) -> Any:
        return self._values[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._values)

    def __len__(self) -> int:
        return len(self._values)

    def is_overridden(self, key: str) -> bool:
        """Whether `key` has an admin override (otherwise it is at its catalog default)."""
        return key in self.overrides

    def changed_keys(self, other: SettingsSnapshot) -> frozenset[str]:
        """Keys whose value differs between this snapshot and `other`."""
        keys = set(self._values) | set(other._values)
        return frozenset(
            key
            for key in keys
            if key not in self._values or key not in other._values or not same_value(self[key], other[key])
        )

    def __repr__(self) -> str:
        return f"SettingsSnapshot(version={self.version}, overrides={len(self.overrides)})"


def decode_overrides(
    rows: Iterable[tuple[str, str, int | None, str | None]],
    specs: Mapping[str, SettingSpec],
    aliases: Mapping[str, str] | None = None,
) -> tuple[dict[str, Any], dict[str, tuple[int, str]], list[str]]:
    """Validate stored `settings` rows against the catalog.

    Returns (overrides, meta, invalid keys). Unknown keys are mapped through `aliases` (v1 names) or ignored;
    values are re-validated with the catalog's own validator, so a stored value is always canonical.
    """
    alias_map = catalog.ALIASES if aliases is None else aliases
    overrides: dict[str, Any] = {}
    meta: dict[str, tuple[int, str]] = {}
    invalid: list[str] = []
    for raw_key, value_json, updated_at, updated_by in rows:
        key = raw_key if raw_key in specs else alias_map.get(raw_key, raw_key)
        spec = specs.get(key)
        if spec is None:
            invalid.append(raw_key)
            continue
        try:
            value = catalog.validate_spec_value(spec, json.loads(value_json))
        except (ValueError, TypeError):  # SettingValidationError is a ValueError; bad JSON too
            invalid.append(raw_key)
            continue
        overrides[key] = value
        meta[key] = (int(updated_at or 0), str(updated_by or ""))
    return overrides, meta, invalid


def build_snapshot(
    conn: sqlite3.Connection,
    loaded_at: float,
    specs: Mapping[str, SettingSpec] | None = None,
    defaults: Mapping[str, Any] | None = None,
) -> SettingsSnapshot:
    """Read the version and every override in the caller's read transaction and build a snapshot."""
    catalog_specs = catalog.CATALOG if specs is None else specs
    default_values = catalog.DEFAULTS if defaults is None else defaults
    version = read_config_version(conn)
    rows = conn.execute("SELECT key, value_json, updated_at, updated_by FROM settings").fetchall()
    overrides, meta, invalid = decode_overrides(((r[0], r[1], r[2], r[3]) for r in rows), catalog_specs)
    values = {key: default_values.get(key, spec.default) for key, spec in catalog_specs.items()}
    values.update(overrides)
    if invalid:
        log.warning("settings_overrides_ignored", extra={"fields": {"keys": invalid[:50], "count": len(invalid)}})
    issues = catalog.validate_cross(overrides, catalog=catalog_specs) if overrides else []
    if issues:
        # Writes are cross-validated, so this only happens after a release changed a rule; warn, keep serving.
        log.warning(
            "settings_cross_rules_broken",
            extra={"fields": {"issues": [issue.message for issue in issues[:10]], "version": version}},
        )
    return SettingsSnapshot(version, values, overrides, meta, loaded_at, tuple(invalid))


# --- the live store ---------------------------------------------------------------------------------------------------


class RuntimeSettings:
    """The live settings of one worker (DESIGN.md section 4). Reads are dictionary lookups; reloads are atomic.

    The method names `int`, `float`, `bool`, `str` and `list` shadow the builtins inside this class body, so the
    annotations here spell the builtins as `builtins.int` and so on.
    """

    def __init__(
        self,
        db: Database,
        snapshot: SettingsSnapshot,
        *,
        clock: Clock | None = None,
        specs: Mapping[builtins.str, SettingSpec] | None = None,
    ) -> None:
        self._db = db
        self._clock = clock or SYSTEM_CLOCK
        self._specs = catalog.CATALOG if specs is None else specs
        self._snapshot = snapshot
        self._listeners: builtins.list[SettingsListener] = []
        self._reload_lock = asyncio.Lock()
        self._failing = False  # True while reads keep failing, so the error is logged once per streak

    # ---- reading ----

    def snapshot(self) -> SettingsSnapshot:
        """The current immutable snapshot (keep it for a whole request to read consistent values)."""
        return self._snapshot

    @property
    def version(self) -> builtins.int:
        """The `config_version` the current values belong to."""
        return self._snapshot.version

    def get(self, key: builtins.str) -> Any:
        """The current value of `key` (lists are tuples). Unknown keys raise KeyError: a typo must fail loudly."""
        return self._snapshot[key]

    def int(self, key: builtins.str) -> builtins.int:
        """`key` as an int (bool settings give 0 or 1)."""
        return builtins.int(self._snapshot[key])

    def float(self, key: builtins.str) -> builtins.float:
        """`key` as a float."""
        return builtins.float(self._snapshot[key])

    def bool(self, key: builtins.str) -> builtins.bool:
        """`key` as a bool (settings store booleans as 0 or 1, like v1)."""
        return builtins.bool(self._snapshot[key])

    def str(self, key: builtins.str) -> builtins.str:
        """`key` as a string."""
        return builtins.str(self._snapshot[key])

    def list(self, key: builtins.str) -> builtins.list[Any]:
        """`key` as a new list (safe to modify; the snapshot keeps its own tuple)."""
        return builtins.list(self._snapshot[key])

    def spec(self, key: builtins.str) -> SettingSpec:
        """The catalog entry for `key`."""
        return self._specs[key]

    def is_overridden(self, key: builtins.str) -> builtins.bool:
        """Whether `key` differs from its catalog default because an admin set it."""
        return self._snapshot.is_overridden(key)

    # ---- reloading ----

    def subscribe(self, callback: SettingsListener) -> Callable[[], None]:
        """Call `callback(snapshot, changed_keys)` after every reload that changed at least one value.

        Returns a function that removes the subscription. A callback may be async; exceptions are logged and
        never stop the reload or other callbacks.
        """
        if len(self._listeners) >= MAX_SUBSCRIBERS:
            raise RuntimeError("too many settings subscribers")
        self._listeners.append(callback)

        def unsubscribe() -> None:
            if callback in self._listeners:
                self._listeners.remove(callback)

        return unsubscribe

    async def reload(self) -> SettingsSnapshot:
        """Rebuild the snapshot from control.db now and notify subscribers of changed keys.

        Raises `SharedStateUnavailable` when control.db cannot be read; the old snapshot then stays in force.
        """
        async with self._reload_lock:
            loaded_at = self._clock.now()
            specs = self._specs
            # The read starts only after any earlier reload finished (the lock), so it never sees an older state of
            # control.db than the snapshot it replaces. A LOWER version therefore means the counter really went
            # down (a restored backup, a reset); the database is the truth, so the new snapshot is taken anyway.
            # Refusing it would freeze this worker on stale values until the counter climbed past the old one.
            new = await self._db.read(lambda conn: build_snapshot(conn, loaded_at, specs))
            old = self._snapshot
            if new.version < old.version:
                log.warning("config_version_went_down", extra={"fields": {"from": old.version, "to": new.version}})
            self._snapshot = new
            changed = new.changed_keys(old)
        if changed:
            log.info("settings_reloaded", extra={"fields": {"version": new.version, "changed": sorted(changed)[:50]}})
            await self._notify(new, changed)
        return new

    async def refresh_if_changed(self) -> builtins.bool:
        """Reload when `config_version` moved (called every second by `watch_config`). True when it reloaded."""
        try:
            version = await self._db.read(read_config_version)
            if version == self._snapshot.version:
                self._recovered()
                return False
            await self.reload()
        except SharedStateUnavailable as exc:
            if not self._failing:
                log.warning("settings_refresh_failed", extra={"fields": {"error": str(exc)[:200]}})
            self._failing = True
            return False
        self._recovered()
        return True

    def _recovered(self) -> None:
        if self._failing:
            log.info("settings_refresh_recovered", extra={"fields": {"version": self._snapshot.version}})
        self._failing = False

    async def _notify(self, snapshot: SettingsSnapshot, changed: frozenset[builtins.str]) -> None:
        for callback in builtins.list(self._listeners):
            try:
                result = callback(snapshot, changed)
                if inspect.isawaitable(result):
                    await result
            except Exception:
                log.exception("settings_subscriber_failed", extra={"fields": {"callback": repr(callback)[:120]}})


async def load_runtime_settings(dbs: Databases, clock: Clock | None = None) -> RuntimeSettings:
    """Build the worker's `RuntimeSettings` from control.db (the lifespan's "settings" step, DESIGN.md section 1).

    Raises `SharedStateUnavailable` if control.db cannot be read: a worker that cannot see its configuration
    must not start. The lifespan retries for a while, then the worker exits with an ordinary error status and
    gunicorn starts a new one (`roxy.worker` keeps that from looking like a boot error, which would stop the master).
    """
    used_clock = clock or SYSTEM_CLOCK
    loaded_at = used_clock.now()
    snapshot = await dbs.control.read(lambda conn: build_snapshot(conn, loaded_at))
    log.info(
        "settings_loaded",
        extra={"fields": {"version": snapshot.version, "overrides": len(snapshot.overrides), "keys": len(snapshot)}},
    )
    return RuntimeSettings(dbs.control, snapshot, clock=used_clock)


# --- the per-worker watcher -------------------------------------------------------------------------------------------


class Refreshable(Protocol):
    """Anything with `refresh_if_changed()`: `RuntimeSettings` and `rules.store.RulesStore`."""

    async def refresh_if_changed(self) -> bool: ...


async def watch_config(
    stop: asyncio.Event,
    *targets: Refreshable,
    interval_s: float = CONFIG_POLL_INTERVAL_S,
) -> None:
    """Poll every target's `refresh_if_changed()` every `interval_s` until `stop` is set (plan 5.6, 5.7).

    Wire it in the lifespan as `_start_loop(ctx, stack, "config_watcher", lambda stop: watch_config(stop,
    ctx.settings, ctx.rules))`. One failing target never stops the loop or the others.
    """
    while not stop.is_set():
        for target in targets:
            try:
                await target.refresh_if_changed()
            except Exception:
                log.exception("config_watch_failed", extra={"fields": {"target": type(target).__name__}})
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval_s)
        except TimeoutError:
            continue


__all__ = [
    "CONFIG_POLL_INTERVAL_S",
    "CONFIG_VERSION_KEY",
    "Refreshable",
    "RuntimeSettings",
    "SettingsListener",
    "SettingsSnapshot",
    "build_snapshot",
    "bump_config_version",
    "decode_overrides",
    "freeze",
    "load_runtime_settings",
    "raise_config_version",
    "read_config_version",
    "same_value",
    "thaw",
    "watch_config",
]
