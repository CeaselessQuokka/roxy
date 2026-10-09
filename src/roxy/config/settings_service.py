"""The settings service: the one way a runtime setting is changed, validated, audited and published fleet-wide.

What this is
    `SettingsService.update(changes, actor, reason, source)` and its relatives: `revert(history_id)`,
    `reset_to_default(key)`, `export_overrides()`, `preview_import(document)` and `import_overrides(document)`,
    plus `history()` for the editor. Every write is one control.db transaction that upserts or deletes the
    `settings` rows, appends `settings_history`, appends `audit_log` and bumps `service_state.config_version`.

Why it exists
    Plan 15.2 and 5.7. The editor sends only the keys an admin actually changed (v1 posted all 71 settings on every
    save and wrote the state file once per key). Every value is validated against the catalog, the whole result is
    checked against the cross-field rules (for example `tarpit_min_seconds <= tarpit_max_seconds`), and either
    every change lands or none does. History rows make one-click revert possible; audit rows say who, from where
    and why. Bumping `config_version` in the same transaction is what makes every worker reload within a second.

How it works
    1. Outside the transaction: resolve v1 key aliases, validate each value with `catalog.validate_value`
       (all problems are collected, not just the first), require a reason for high-risk values, check `source`.
    2. Inside one `BEGIN IMMEDIATE` write: read the current overrides (so the decision never uses a stale cached
       copy), keep only DIRTY keys (whose stored override actually changes), run the cross-field rules on the
       merged result (only issues that involve a changed key block the change), then write settings, history,
       audit and the version bump. A value equal to its catalog default deletes the override, so `settings` keeps
       holding only real overrides (plan 6.2) and a future change of the default applies.
    3. After the commit, this worker's `RuntimeSettings` reloads at once; the others follow within a second.
    In history rows, `old_json` and `new_json` hold the OVERRIDE as JSON, and NULL means "no override, the
    catalog default". Sensitive settings (`spec.sensitive`) are stored as `{fingerprint, masked}` in history and
    audit, never as the value (plan 6.2).

What to read next
    `roxy/config/catalog.py` (validation and cross rules), `roxy/config/runtime.py` (how the change is picked up)
    and `roxy/config/audit.py` (what an audit row holds).
"""

from __future__ import annotations

import json
import logging
import re
import secrets
import sqlite3
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Final, Literal

from roxy.config import audit, catalog
from roxy.config.audit import Actor
from roxy.config.catalog import CrossIssue, SettingValidationError
from roxy.config.constants import MAX_REASON_LENGTH
from roxy.config.runtime import (
    RuntimeSettings,
    bump_config_version,
    decode_overrides,
    freeze,
    read_config_version,
    same_value,
    thaw,
)
from roxy.config.spec import Apply, Risk, SettingSpec
from roxy.core.clock import SYSTEM_CLOCK, Clock
from roxy.core.redact import MASK
from roxy.storage.db import Database, SharedStateUnavailable

log = logging.getLogger(__name__)

EXPORT_SCHEMA: Final = "roxy.settings_overrides/1"
MAX_HISTORY_PAGE: Final = 500
MAX_IMPORT_KEYS: Final = 2000  # far above the catalog size; bounds one import document (plan P9)
FIXED_SOURCES: Final[frozenset[str]] = frozenset({"admin", "auto_apply", "import", "revert", "cli", "system"})
_RECOMMENDATION_SOURCE = re.compile(r"recommendation:[A-Za-z0-9_.:-]{1,64}")
_DASHES = (catalog.EM_DASH, catalog.EN_DASH)


class _Reset:
    """Marker for "remove the override" in a change plan (the key goes back to its catalog default)."""

    def __repr__(self) -> str:
        return "RESET"


RESET: Final = _Reset()
_MISSING: Final = object()


class SettingsUpdateError(ValueError):
    """A change was refused. `errors` maps key -> message; `cross` lists broken cross-field rules.

    Both are written for the admin and safe to show as is. Nothing was written when this is raised.
    """

    def __init__(self, errors: Mapping[str, str] | None = None, cross: Sequence[CrossIssue] = ()) -> None:
        self.errors: dict[str, str] = dict(errors or {})
        self.cross: list[CrossIssue] = list(cross)
        parts = [f"{key}: {message}" for key, message in self.errors.items()]
        parts += [issue.message for issue in self.cross]
        super().__init__("; ".join(parts) or "settings change refused")


class HistoryNotFound(LookupError):
    """`revert` was given a history id that does not exist."""


@dataclass(frozen=True, slots=True)
class SettingChange:
    """One key that changed: the effective value before and after, and whether an override exists after."""

    key: str
    old: Any
    new: Any
    overridden: bool
    history_id: int
    audit_id: int


@dataclass(frozen=True, slots=True)
class UpdateResult:
    """What an update did. `changes` is empty (and nothing was written) when no key was dirty."""

    changes: tuple[SettingChange, ...]
    unchanged: tuple[str, ...]
    config_version: int
    warnings: tuple[str, ...] = ()

    @property
    def changed_keys(self) -> tuple[str, ...]:
        return tuple(change.key for change in self.changes)


@dataclass(frozen=True, slots=True)
class HistoryEntry:
    """One `settings_history` row, decoded (`old`/`new` are overrides; None means the catalog default)."""

    id: int
    key: str
    old: Any
    new: Any
    changed_at: int
    changed_by: str
    reason: str | None
    source: str


ImportStatus = Literal["change", "same", "reset", "invalid", "unknown", "skipped"]


@dataclass(frozen=True, slots=True)
class ImportItem:
    """One key of an import preview: what it is now, what the import would make it, and whether that is allowed."""

    key: str
    status: ImportStatus
    current: Any = None
    new: Any = None
    default: Any = None
    message: str = ""


@dataclass(frozen=True, slots=True)
class ImportPreview:
    """The diff an import would apply (plan 15.2: "validates, shows diff, applies atomically with a reason")."""

    items: tuple[ImportItem, ...]
    cross: tuple[CrossIssue, ...]
    catalog_version_matches: bool
    plan: Mapping[str, Any] = field(default_factory=dict)  # key -> value or RESET (internal, used by apply)

    @property
    def ok(self) -> bool:
        """True when the import can be applied as is."""
        return not self.cross and all(item.status not in ("invalid", "unknown") for item in self.items)

    @property
    def changes(self) -> tuple[ImportItem, ...]:
        return tuple(item for item in self.items if item.status in ("change", "reset"))


@dataclass(slots=True)
class _Plan:
    """A validated change plan ready for the write transaction."""

    values: dict[str, Any]  # key -> canonical value, or RESET
    action: str
    source: str
    warnings: list[str] = field(default_factory=list)


def check_source(source: str) -> str:
    """`source` must be one of the `settings_history.source` values of plan 6.2."""
    if source in FIXED_SOURCES or _RECOMMENDATION_SOURCE.fullmatch(source):
        return source
    raise SettingsUpdateError({"source": f"Unknown change source {source[:40]!r}"})


def check_reason(reason: str | None) -> str:
    """Reasons are free text, bounded, without control characters or dash characters (plan C5)."""
    text = (reason or "").strip()
    if len(text) > MAX_REASON_LENGTH:
        raise SettingsUpdateError({"reason": f"The reason is longer than {MAX_REASON_LENGTH} characters"})
    if any(dash in text for dash in _DASHES):
        raise SettingsUpdateError({"reason": catalog.DASH_MESSAGE})
    if re.search(r"[\x00-\x08\x0b-\x1f\x7f]", text):
        raise SettingsUpdateError({"reason": "The reason contains a control character"})
    return text


class SettingsService:
    """Validated, audited, atomic writes to the runtime settings (DESIGN.md section 4)."""

    def __init__(
        self,
        db: Database,
        *,
        runtime: RuntimeSettings | None = None,
        clock: Clock | None = None,
        specs: Mapping[str, SettingSpec] | None = None,
        fingerprint_key: bytes | None = None,
    ) -> None:
        self._db = db
        self._runtime = runtime
        self._clock = clock or SYSTEM_CLOCK
        self._specs = catalog.CATALOG if specs is None else specs
        self._defaults = {key: catalog.DEFAULTS.get(key, spec.default) for key, spec in self._specs.items()}
        # Keyed fingerprints for sensitive values. Without a configured key a per-process random key still hides
        # the value; fingerprints then only compare within one process.
        self._fingerprint_key = fingerprint_key or secrets.token_bytes(32)

    # ---- public API --------------------------------------------------------------------------------------------

    async def update(
        self,
        changes: Mapping[str, Any],
        actor: Actor,
        reason: str,
        source: str = "admin",
        *,
        request_id: str | None = None,
    ) -> UpdateResult:
        """Validate `changes` (key -> raw value) and apply the dirty ones in one transaction.

        Raises `SettingsUpdateError` with every problem found; nothing is written then.
        """
        reason_text = check_reason(reason)
        plan = self._plan(changes, reason_text, source, action="setting.update")
        return await self._apply(plan, actor, reason_text, request_id)

    async def reset_to_default(
        self,
        key: str,
        actor: Actor,
        reason: str,
        source: str = "admin",
        *,
        request_id: str | None = None,
    ) -> UpdateResult:
        """Remove the override of `key` so it follows its catalog default again (parity row 124)."""
        resolved = catalog.resolve_key(key) if self._specs is catalog.CATALOG else key
        if resolved is None or resolved not in self._specs:
            raise SettingsUpdateError({key: "Unknown setting"})
        plan = _Plan({resolved: RESET}, "setting.reset", check_source(source))
        return await self._apply(plan, actor, check_reason(reason), request_id)

    async def revert(
        self,
        history_id: int,
        actor: Actor,
        reason: str,
        *,
        request_id: str | None = None,
    ) -> UpdateResult:
        """Put a key back to the value it had before history row `history_id` (itself audited, source `revert`)."""
        entry = await self._db.read(lambda conn: _history_row(conn, history_id))
        if entry is None:
            raise HistoryNotFound(history_id)
        if entry.key not in self._specs:
            raise SettingsUpdateError({entry.key: "This setting no longer exists"})
        if self._specs[entry.key].sensitive and entry.old is not None:
            # History holds only {fingerprint, masked} for sensitive values, so there is nothing to restore.
            raise SettingsUpdateError({entry.key: "Sensitive values are not kept in history; enter the value again"})
        if entry.old is None:
            target: Any = RESET
        else:
            try:
                target = catalog.validate_spec_value(self._specs[entry.key], entry.old)
            except SettingValidationError as exc:
                raise SettingsUpdateError({entry.key: f"The earlier value is no longer valid: {exc.message}"}) from None
        plan = _Plan({entry.key: target}, "setting.revert", "revert")
        current = self._runtime.snapshot().overrides.get(entry.key, _MISSING) if self._runtime else _MISSING
        if self._runtime is not None and not _same_override(current, _override_or_missing(entry.new)):
            plan.warnings.append(f"{entry.key} was changed again after history entry {history_id}")
        return await self._apply(plan, actor, check_reason(reason), request_id)

    async def history(
        self, key: str | None = None, *, limit: int = 50, before_id: int | None = None
    ) -> list[HistoryEntry]:
        """Newest first; one key or every key; paged with `before_id` (bounded to 500 per page)."""
        page = max(1, min(int(limit), MAX_HISTORY_PAGE))
        return await self._db.read(lambda conn: _history_rows(conn, key, page, before_id))

    async def export_overrides(self) -> dict[str, Any]:
        """Every current override as a JSON document (plan 15.2), with the catalog version for drift detection.

        Sensitive values are replaced by `[redacted]`; an import skips them.
        """
        rows = await self._db.read(_read_override_rows)
        overrides, _meta, _invalid = _decode(rows, self._specs)
        version = await self._db.read(_read_version)
        exported: dict[str, Any] = {}
        for key in sorted(overrides):
            exported[key] = MASK if self._specs[key].sensitive else thaw(overrides[key])
        return {
            "schema": EXPORT_SCHEMA,
            "catalog_version": catalog.catalog_version(self._specs),
            "config_version": version,
            "exported_at": int(self._clock.now()),
            "overrides": exported,
        }

    async def preview_import(self, document: Any, *, replace: bool = False) -> ImportPreview:
        """Validate an export document and show what importing it would change (nothing is written).

        `replace=True` also resets every current override the document does not mention.
        """
        overrides_raw, catalog_matches = _parse_document(document)
        rows = await self._db.read(_read_override_rows)
        current, _meta, _invalid = _decode(rows, self._specs)
        items: list[ImportItem] = []
        plan: dict[str, Any] = {}
        seen: set[str] = set()
        for raw_key, raw_value in overrides_raw.items():
            key = str(raw_key)
            resolved = catalog.resolve_key(key) if self._specs is catalog.CATALOG else key
            if resolved is None or resolved not in self._specs:
                items.append(ImportItem(key, "unknown", message="Unknown setting"))
                continue
            seen.add(resolved)
            spec = self._specs[resolved]
            default = self._defaults[resolved]
            now_value = thaw(current.get(resolved, default))
            if spec.sensitive and raw_value == MASK:
                items.append(ImportItem(resolved, "skipped", default=None, message="Sensitive value not exported"))
                continue
            try:
                value = catalog.validate_spec_value(spec, raw_value)
            except SettingValidationError as exc:
                items.append(
                    ImportItem(resolved, "invalid", current=now_value, default=thaw(default), message=exc.message)
                )
                continue
            new_override = _MISSING if same_value(value, default) else value
            if _same_override(current.get(resolved, _MISSING), new_override):
                items.append(ImportItem(resolved, "same", current=now_value, new=thaw(value), default=thaw(default)))
                continue
            plan[resolved] = value
            items.append(ImportItem(resolved, "change", current=now_value, new=thaw(value), default=thaw(default)))
        if replace:
            for key in sorted(set(current) - seen):
                plan[key] = RESET
                items.append(
                    ImportItem(
                        key,
                        "reset",
                        current=thaw(current[key]),
                        new=thaw(self._defaults[key]),
                        default=thaw(self._defaults[key]),
                    )
                )
        merged = dict(current)
        for key, value in plan.items():
            if value is RESET:
                merged.pop(key, None)
            else:
                merged[key] = value
        cross = _relevant_cross(catalog.validate_cross(merged, catalog=self._specs), set(plan))
        return ImportPreview(tuple(items), tuple(cross), catalog_matches, dict(plan))

    async def import_overrides(
        self,
        document: Any,
        actor: Actor,
        reason: str,
        *,
        replace: bool = False,
        request_id: str | None = None,
    ) -> UpdateResult:
        """Apply an export document atomically (source `import`). Refused entirely if any entry is invalid."""
        preview = await self.preview_import(document, replace=replace)
        errors = {item.key: item.message for item in preview.items if item.status in ("invalid", "unknown")}
        if errors or preview.cross:
            raise SettingsUpdateError(errors, preview.cross)
        reason_text = check_reason(reason)
        plan = _Plan(dict(preview.plan), "settings.import", "import")
        if not preview.catalog_version_matches:
            plan.warnings.append("The export was made with a different settings catalog version")
        self._require_reason_for_risk(plan.values, reason_text)
        return await self._apply(plan, actor, reason_text, request_id)

    # ---- planning ----------------------------------------------------------------------------------------------

    def _plan(self, changes: Mapping[str, Any], reason: str, source: str, *, action: str) -> _Plan:
        errors: dict[str, str] = {}
        values: dict[str, Any] = {}
        if not isinstance(changes, Mapping):
            raise SettingsUpdateError({"changes": "Expected an object of setting keys and values"})
        if len(changes) > MAX_IMPORT_KEYS:
            raise SettingsUpdateError({"changes": "Too many settings in one change"})
        for raw_key, raw_value in changes.items():
            key = str(raw_key)
            resolved = catalog.resolve_key(key) if self._specs is catalog.CATALOG else key
            if resolved is None or resolved not in self._specs:
                errors[key] = "Unknown setting"
                continue
            try:
                values[resolved] = catalog.validate_spec_value(self._specs[resolved], raw_value)
            except SettingValidationError as exc:
                errors[resolved] = exc.message
        try:
            check_source(source)
        except SettingsUpdateError as exc:
            errors.update(exc.errors)
        if errors:
            raise SettingsUpdateError(errors)
        self._require_reason_for_risk(values, reason)
        plan = _Plan(values, action, source)
        for key in values:
            if self._specs[key].apply is Apply.RESTART:
                plan.warnings.append(f"{key} takes effect after a restart")
        return plan

    def _require_reason_for_risk(self, values: Mapping[str, Any], reason: str | None) -> None:
        """Plan 15.1: high-risk settings and high-risk values need a reason."""
        if (reason or "").strip():
            return
        risky = {}
        for key, value in values.items():
            spec = self._specs[key]
            why = None if value is RESET else spec.is_high_risk_value(value)
            if spec.risk is Risk.HIGH or why:
                risky[key] = why or "This is a high-risk setting; explain the change in the reason field"
        if risky:
            raise SettingsUpdateError({key: f"A reason is required: {why}" for key, why in risky.items()})

    # ---- the write transaction ---------------------------------------------------------------------------------

    async def _apply(self, plan: _Plan, actor: Actor, reason: str, request_id: str | None) -> UpdateResult:
        now = int(self._clock.now())
        specs = self._specs
        defaults = self._defaults

        def summarize(key: str, value: Any) -> Any:
            if value is _MISSING:
                return None
            if specs[key].sensitive:
                text = json.dumps(thaw(value))
                # No characters of the value at all (security review L7): a tail of a password or a webhook token
                # is part of the secret. The keyed fingerprint still tells two values apart.
                return audit.secret_summary(text, self._fingerprint_key)
            return thaw(value)

        def write(conn: sqlite3.Connection) -> UpdateResult:
            rows = _read_override_rows(conn)
            current, _meta, _invalid = _decode(rows, specs)
            stored_keys = {row[0] for row in rows}
            dirty: dict[str, tuple[Any, Any]] = {}  # key -> (old override or _MISSING, new override or _MISSING)
            unchanged: list[str] = []
            for key, value in plan.values.items():
                old = current.get(key, _MISSING)
                if value is RESET:
                    new: Any = _MISSING
                    if key not in stored_keys:
                        unchanged.append(key)
                        continue
                else:
                    new = _MISSING if same_value(value, defaults[key]) else value
                    if _same_override(old, new) and (new is not _MISSING or key not in stored_keys):
                        unchanged.append(key)
                        continue
                dirty[key] = (old, new)
            if not dirty:
                return UpdateResult((), tuple(unchanged), _read_version(conn), tuple(plan.warnings))
            merged = dict(current)
            for key, (_old, new) in dirty.items():
                if new is _MISSING:
                    merged.pop(key, None)
                else:
                    merged[key] = new
            issues = _relevant_cross(catalog.validate_cross(merged, catalog=specs), set(dirty))
            if issues:
                raise SettingsUpdateError(cross=issues)
            results: list[SettingChange] = []
            for key, (old, new) in dirty.items():
                if new is _MISSING:
                    conn.execute("DELETE FROM settings WHERE key = ?", (key,))
                else:
                    conn.execute(
                        "INSERT INTO settings (key, value_json, updated_at, updated_by) VALUES (?, ?, ?, ?) "
                        "ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json, "
                        "updated_at = excluded.updated_at, updated_by = excluded.updated_by",
                        (key, json.dumps(thaw(new)), now, actor.label),
                    )
                old_hist, new_hist = summarize(key, old), summarize(key, new)
                cursor = conn.execute(
                    "INSERT INTO settings_history (key, old_json, new_json, changed_at, changed_by, reason, source) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        key,
                        None if old is _MISSING else json.dumps(old_hist),
                        None if new is _MISSING else json.dumps(new_hist),
                        now,
                        actor.label,
                        reason or None,
                        plan.source,
                    ),
                )
                history_id = int(cursor.lastrowid or 0)
                old_effective = defaults[key] if old is _MISSING else old
                new_effective = defaults[key] if new is _MISSING else new
                audit_id = audit.record(
                    conn,
                    actor,
                    plan.action,
                    f"setting:{key}",
                    {"value": summarize(key, old_effective), "overridden": old is not _MISSING},
                    {"value": summarize(key, new_effective), "overridden": new is not _MISSING},
                    reason or None,
                    request_id,
                    at=now,
                    secret=False,
                )
                results.append(
                    SettingChange(
                        key,
                        freeze(old_effective),
                        freeze(new_effective),
                        new is not _MISSING,
                        history_id,
                        audit_id,
                    )
                )
            version = bump_config_version(conn, now)
            return UpdateResult(tuple(results), tuple(unchanged), version, tuple(plan.warnings))

        result = await self._db.write(write)
        if result.changes and self._runtime is not None:
            # This worker sees its own change at once; the others reload within CONFIG_POLL_INTERVAL_S.
            try:
                await self._runtime.reload()
            except SharedStateUnavailable as exc:  # the change is committed; the watcher catches up
                log.warning("settings_reload_after_write_failed", extra={"fields": {"error": str(exc)[:200]}})
        return result


FINGERPRINT_CONTEXT: Final = "settings-fingerprint"
"""`derived_key` context of the key that fingerprints sensitive setting values in history and audit rows."""


def service_for(ctx: Any) -> SettingsService:
    """The settings service of a worker's `AppContext`: its control.db, runtime settings and clock, with sensitive
    values fingerprinted under a key derived from the `ip_hash_key` credential when it exists, so the same value
    has the same fingerprint in every worker and across restarts (without the credential each service draws a
    random key). Every writer of settings in a running worker (the settings API, the Protection page, applied
    recommendations) builds its service here, so their history and audit rows compare."""
    from roxy.core.iphash import derived_key  # local import: the core helper is only needed with a context

    key = getattr(ctx, "ip_hash_key", None)
    fingerprint_key = derived_key(key, FINGERPRINT_CONTEXT) if key else None
    return SettingsService(ctx.dbs.control, runtime=ctx.settings, clock=ctx.clock, fingerprint_key=fingerprint_key)


# --- helpers (pure functions over a connection, usable inside other transactions) ------------------------------------


def _read_override_rows(conn: sqlite3.Connection) -> list[tuple[str, str, int | None, str | None]]:
    rows = conn.execute("SELECT key, value_json, updated_at, updated_by FROM settings").fetchall()
    return [(str(r[0]), str(r[1]), r[2], r[3]) for r in rows]


def _read_version(conn: sqlite3.Connection) -> int:
    return read_config_version(conn)


def _decode(
    rows: list[tuple[str, str, int | None, str | None]], specs: Mapping[str, SettingSpec]
) -> tuple[dict[str, Any], dict[str, tuple[int, str]], list[str]]:
    aliases = catalog.ALIASES if specs is catalog.CATALOG else {}
    return decode_overrides(rows, specs, aliases)


def _override_or_missing(value: Any) -> Any:
    return _MISSING if value is None else value


def _same_override(left: Any, right: Any) -> bool:
    if left is _MISSING or right is _MISSING:
        return left is right
    return same_value(left, right)


def _relevant_cross(issues: Sequence[CrossIssue], keys: set[str]) -> list[CrossIssue]:
    """Only the cross-field problems that involve a key being changed (an old problem never blocks new edits)."""
    return [issue for issue in issues if keys.intersection(issue.keys)]


def _decode_json(text: str | None) -> Any:
    if text is None:
        return None
    try:
        return json.loads(text)
    except ValueError:
        return text


def _history_row(conn: sqlite3.Connection, history_id: int) -> HistoryEntry | None:
    row = conn.execute(
        "SELECT id, key, old_json, new_json, changed_at, changed_by, reason, source FROM settings_history WHERE id = ?",
        (int(history_id),),
    ).fetchone()
    return None if row is None else _history_entry(row)


def _history_entry(row: sqlite3.Row) -> HistoryEntry:
    return HistoryEntry(
        id=int(row[0]),
        key=str(row[1]),
        old=_decode_json(row[2]),
        new=_decode_json(row[3]),
        changed_at=int(row[4]),
        changed_by=str(row[5]),
        reason=row[6],
        source=str(row[7]),
    )


def _history_rows(conn: sqlite3.Connection, key: str | None, limit: int, before_id: int | None) -> list[HistoryEntry]:
    clauses: list[str] = []
    params: list[Any] = []
    if key is not None:
        clauses.append("key = ?")
        params.append(key)
    if before_id is not None:
        clauses.append("id < ?")
        params.append(int(before_id))
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    # The clauses are fixed strings chosen above; every value is a bound parameter.
    columns = "id, key, old_json, new_json, changed_at, changed_by, reason, source"
    sql = f"SELECT {columns} FROM settings_history {where} ORDER BY id DESC LIMIT ?"  # noqa: S608
    rows = conn.execute(sql, (*params, limit)).fetchall()
    return [_history_entry(row) for row in rows]


def _parse_document(document: Any) -> tuple[Mapping[str, Any], bool]:
    """The overrides mapping of an export document (or a bare key -> value mapping) and catalog version match."""
    if not isinstance(document, Mapping):
        raise SettingsUpdateError({"document": "Expected a JSON object exported from the settings editor"})
    schema = document.get("schema")
    if schema is not None and schema != EXPORT_SCHEMA:
        raise SettingsUpdateError({"document": f"Unsupported export format {str(schema)[:40]!r}"})
    overrides = document.get("overrides") if schema is not None or "overrides" in document else document
    if not isinstance(overrides, Mapping):
        raise SettingsUpdateError({"document": "The document has no overrides object"})
    if len(overrides) > MAX_IMPORT_KEYS:
        raise SettingsUpdateError({"document": "Too many settings in one import"})
    matches = document.get("catalog_version") in (None, catalog.CATALOG_VERSION)
    return overrides, matches


__all__ = [
    "EXPORT_SCHEMA",
    "FINGERPRINT_CONTEXT",
    "RESET",
    "HistoryEntry",
    "HistoryNotFound",
    "ImportItem",
    "ImportPreview",
    "SettingChange",
    "SettingsService",
    "SettingsUpdateError",
    "UpdateResult",
    "check_reason",
    "check_source",
    "service_for",
]
