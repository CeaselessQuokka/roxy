"""The rules service: create, update and delete for every rule table, each one audited, atomic transaction.

What this is
    `RulesService.create(table, row, actor, reason)`, `update(table, key, changes, ...)`, `delete(table, key, ...)`
    for the rule tables of `rules/models.py RULE_TABLES`, plus `upsert` for tables whose rows have a natural
    identity (v1 "set" semantics), `replace_throttle_tiers` / `reset_throttle_tiers` for the ladder (v1 replaced
    the whole list), and `reorder_user_agent_rules` for UA rule evaluation order.

Why it exists
    Plan 5.7 and DESIGN.md section 5. In v1 every worker validated an edit against its own in-memory copy of the
    rules, up to a second stale, and then wrote the whole state file; a worker that had not yet seen a new UA rule
    created a duplicate when asked to edit it by id. Here every change is SQL by primary key inside one
    `BEGIN IMMEDIATE` transaction on control.db: the row is read, validated, written, audited, and
    `config_version` is bumped, all or nothing. Caps (plan 15.4) and duplicate checks run inside the same
    transaction, so they hold across any number of workers (C6), not just within one.

How it works
    - Input is validated with the table's input model before the transaction; validation problems become
      `RuleValidationError` with one `{field, message}` per problem, written for the admin.
    - `update` reads the stored row inside the transaction, merges the changed fields, validates the result
      (untouched fields are trusted, see `rules/models.py`), and writes only the columns that differ with
      `UPDATE <table> SET ... WHERE <pk> = ?`. Nothing changed means nothing is written or audited.
    - Header rules keep the v1 canonical key `header|scope|mode|needle` under a unique index; adding the same
      filter twice is refused with `RuleConflict` (plan row 112), never silently overwritten.
    - Bans: one active ban per subject. Creating a ban for a subject that already has an active one EXTENDS that
      ban (the later expiry wins, a permanent ban outlasts any temporary one) in the same transaction, instead of
      adding a second row; otherwise two detectors banning one IP at once left two bans, and deleting one by id
      kept the IP banned. `unban(subject_type, subject)` lifts every ban of a subject at once.
    - After the commit this worker's `RulesStore` reloads at once; other workers follow within a second.

What to read next
    `roxy/rules/models.py` (validation and the table registry), `roxy/rules/store.py` (the snapshot), and
    `roxy/config/audit.py` (the audit row).
"""

from __future__ import annotations

import logging
import re
import secrets
import sqlite3
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Final, Literal

from pydantic import ValidationError

from roxy.config import audit
from roxy.config.audit import Actor
from roxy.config.catalog import DASH_MESSAGE, EM_DASH, EN_DASH
from roxy.config.constants import MAX_REASON_LENGTH, MAX_THROTTLE_TIERS
from roxy.config.runtime import bump_config_version, read_config_version
from roxy.core.clock import SYSTEM_CLOCK, Clock
from roxy.rules.models import (
    ACCESS_LIST_CAPS,
    RULE_TABLES,
    BanIn,
    RuleTable,
    ThrottleTierIn,
    row_to_input,
    to_columns,
)
from roxy.rules.store import RulesStore
from roxy.storage.db import Database, SharedStateUnavailable

log = logging.getLogger(__name__)

RuleAction = Literal["create", "update", "delete", "replace", "reorder"]
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
_UA_ID_ATTEMPTS: Final = 16
# Tables whose rows have no natural identity besides their generated id: `upsert` makes no sense for them, and for
# header rules it would bring back v1's silent overwrite that plan row 112 replaced with a refusal.
_NO_UPSERT: Final = frozenset({"rules_user_agent", "rules_header", "bans"})
_HEADER_IDENTITY: Final = (
    "header",
    "scope",
    "mode",
    "needle",
)  # the fields a header rule's canonical key is built from


# --- errors -----------------------------------------------------------------------------------------------------------


class RulesError(Exception):
    """Base of every refusal from this service. `message` is written for the admin and safe to show as is."""

    def __init__(self, table: str, message: str) -> None:
        super().__init__(message)
        self.table = table
        self.message = message


class RuleValidationError(RulesError, ValueError):
    """The row failed validation. `errors` lists `{"field": ..., "message": ...}` for every problem."""

    def __init__(self, table: str, errors: Sequence[Mapping[str, str]]) -> None:
        self.errors = [dict(error) for error in errors]
        summary = "; ".join(f"{error['field']}: {error['message']}" for error in self.errors) or "invalid rule"
        super().__init__(table, summary)


class RuleNotFound(RulesError, LookupError):
    """No row with that key."""


class RuleCapReached(RulesError):
    """The table (or access-list kind) is at its cap (plan 15.4)."""

    def __init__(self, table: str, message: str, cap: int) -> None:
        super().__init__(table, message)
        self.cap = cap


class RuleConflict(RulesError):
    """The same rule already exists (duplicate pattern, header filter canonical key, name, or CIDR)."""


@dataclass(frozen=True, slots=True)
class RuleChange:
    """What a write did. `changed` is False (and nothing was written) when an update changed nothing."""

    table: str
    key: Any
    action: RuleAction
    before: Any
    after: Any
    changed: bool
    config_version: int
    audit_id: int | None = None
    warnings: tuple[str, ...] = field(default_factory=tuple)


# --- pure helpers over a connection -----------------------------------------------------------------------------------


def validation_errors(exc: ValidationError) -> list[dict[str, str]]:
    """Pydantic errors as `{field, message}` pairs with plain messages (no "Value error, " prefix)."""
    errors: list[dict[str, str]] = []
    for error in exc.errors(include_url=False):
        location = ".".join(str(part) for part in error.get("loc", ())) or "rule"
        kind = error.get("type", "")
        if kind == "value_error" and "error" in error.get("ctx", {}):
            message = str(error["ctx"]["error"])
        elif kind == "extra_forbidden":
            message = "Unknown field"
        elif kind == "missing":
            message = "This field is required"
        else:
            message = str(error.get("msg", "Invalid value"))
        errors.append({"field": location, "message": message})
    return errors


def check_reason(table: str, reason: str | None) -> str:
    """Reasons are bounded free text without control or dash characters (plan C5)."""
    text = (reason or "").strip()
    problem = None
    if len(text) > MAX_REASON_LENGTH:
        problem = f"The reason is longer than {MAX_REASON_LENGTH} characters"
    elif EM_DASH in text or EN_DASH in text:
        problem = DASH_MESSAGE
    elif _CONTROL.search(text):
        problem = "The reason contains a control character"
    if problem:
        raise RuleValidationError(table, [{"field": "reason", "message": problem}])
    return text


def _quoted(names: Sequence[str]) -> str:
    return ", ".join(f'"{name}"' for name in names)  # `limit` is an SQL keyword, so every column is quoted


def fetch_row(conn: sqlite3.Connection, table: RuleTable, key: Any) -> dict[str, Any] | None:
    """One stored row by primary key, as a column -> value dict (None when absent)."""
    row = conn.execute(
        f'SELECT {_quoted(table.columns)} FROM {table.name} WHERE "{table.pk}" = ?',  # noqa: S608 (registry names)
        (key,),
    ).fetchone()
    return None if row is None else dict(zip(table.columns, tuple(row), strict=True))


def fetch_all(conn: sqlite3.Connection, table: RuleTable) -> list[dict[str, Any]]:
    """Every stored row of `table` in its evaluation order (bounded by the table cap)."""
    cap = table.cap or sum(ACCESS_LIST_CAPS.values())  # the access list caps per kind
    limit = max(cap, 1) * 2  # expired bans and access entries still sit in the table until retention prunes them
    rows = conn.execute(
        f"SELECT {_quoted(table.columns)} FROM {table.name} ORDER BY {table.order_by} LIMIT ?",  # noqa: S608
        (limit,),
    ).fetchall()
    return [dict(zip(table.columns, tuple(row), strict=True)) for row in rows]


def _cap(table: RuleTable, columns: Mapping[str, Any], now: int) -> tuple[int, str, str, tuple[Any, ...]]:
    """(cap, label, WHERE clause, params) for the rows that count against the cap of a new row."""
    if table.name == "access_list":
        kind = str(columns["kind"])
        labels = {"bypass": "bypass entries", "allow_admin": "admin allowlist entries", "deny": "deny list entries"}
        return (
            ACCESS_LIST_CAPS[kind],
            labels[kind],
            "WHERE kind = ? AND (expires_at IS NULL OR expires_at > ?)",
            (kind, now),
        )
    if table.name == "bans":
        return table.cap, table.label, "WHERE expires_at IS NULL OR expires_at > ?", (now,)
    return table.cap, table.label, "", ()


def check_cap(conn: sqlite3.Connection, table: RuleTable, columns: Mapping[str, Any], now: int) -> None:
    """Refuse a new row when its table (or access-list kind) is full. Runs inside the write transaction."""
    cap, label, where, params = _cap(table, columns, now)
    count = int(conn.execute(f"SELECT count(*) FROM {table.name} {where}", params).fetchone()[0])  # noqa: S608
    if count >= cap:
        raise RuleCapReached(table.name, f"Too many {label} (the limit is {cap})", cap)


def find_duplicate(conn: sqlite3.Connection, table: RuleTable, columns: Mapping[str, Any], exclude: Any = None) -> Any:
    """The key of an existing row that is "the same rule" as `columns` (by `duplicate_of`), or None."""
    if not table.duplicate_of:
        return None
    where = " AND ".join(f'"{name}" = ?' for name in table.duplicate_of)
    params: list[Any] = [columns[name] for name in table.duplicate_of]
    if exclude is not None:
        where += f' AND "{table.pk}" != ?'
        params.append(exclude)
    row = conn.execute(f'SELECT "{table.pk}" FROM {table.name} WHERE {where} LIMIT 1', params).fetchone()  # noqa: S608
    return None if row is None else row[0]


def find_active_ban(conn: sqlite3.Connection, subject_type: str, subject: str, now: int) -> dict[str, Any] | None:
    """The oldest active ban on exactly this subject (normalized as `BanIn` stores it), or None."""
    table = RULE_TABLES["bans"]
    row = conn.execute(
        f"SELECT {_quoted(table.columns)} FROM bans "  # noqa: S608 (registry column names)
        "WHERE subject_type = ? AND subject = ? AND (expires_at IS NULL OR expires_at > ?) ORDER BY id LIMIT 1",
        (subject_type, subject, now),
    ).fetchone()
    return None if row is None else dict(zip(table.columns, tuple(row), strict=True))


def later_expiry(first: int | None, second: int | None) -> int | None:
    """The expiry that lasts longer; None (permanent) outlasts every time."""
    if first is None or second is None:
        return None
    return max(first, second)


def _duplicate_message(table: RuleTable) -> str:
    if table.name == "rules_header":
        return "A filter with the same header, scope, mode and match text already exists"
    if table.name == "access_list":
        return "That network is already on this list"
    return f"The same rule already exists in {table.label}"


def _insert(conn: sqlite3.Connection, table: RuleTable, columns: Mapping[str, Any]) -> Any:
    names = list(columns)
    try:
        cursor = conn.execute(
            f"INSERT INTO {table.name} ({_quoted(names)}) VALUES ({', '.join('?' for _ in names)})",  # noqa: S608
            [columns[name] for name in names],
        )
    except sqlite3.IntegrityError as exc:
        raise RuleConflict(table.name, _integrity_message(table, exc)) from exc
    return cursor.lastrowid if table.pk_auto else columns[table.pk]


def _integrity_message(table: RuleTable, exc: sqlite3.IntegrityError) -> str:
    text = str(exc).lower()
    if "unique" in text or "primary key" in text:
        return _duplicate_message(table) if table.duplicate_of else f"That entry already exists in {table.label}"
    return f"The row was refused by the database ({text[:120]})"


def _coerce_key(table: RuleTable, key: Any) -> Any:
    """Primary keys arrive from URLs as text; integer keys are converted (a bad one is simply not found)."""
    if table.pk_auto or table.name == "throttle_tiers":
        try:
            return int(key)
        except (TypeError, ValueError):
            raise RuleNotFound(table.name, f"No such entry in {table.label}") from None
    return str(key)


def _new_user_agent_id(conn: sqlite3.Connection) -> str:
    """A fresh 8 hex character id, as v1 minted (`secrets.token_hex(4)`), unique in the table."""
    for _ in range(_UA_ID_ATTEMPTS):
        candidate = secrets.token_hex(4)
        if conn.execute("SELECT 1 FROM rules_user_agent WHERE id = ?", (candidate,)).fetchone() is None:
            return candidate
    raise RuleConflict("rules_user_agent", "Could not allocate a rule id; try again")  # pragma: no cover


# --- the service ------------------------------------------------------------------------------------------------------


class RulesService:
    """Audited CRUD for every rule table (DESIGN.md section 5). Safe to share across tasks in one worker."""

    def __init__(self, db: Database, *, clock: Clock | None = None, store: RulesStore | None = None) -> None:
        self._db = db
        self._clock = clock or SYSTEM_CLOCK
        self._store = store

    @staticmethod
    def table(name: str) -> RuleTable:
        """The registry entry for `name`; unknown tables raise `RulesError`."""
        spec = RULE_TABLES.get(name)
        if spec is None:
            raise RulesError(name, f"Unknown rule table {name[:60]!r}")
        return spec

    # ---- reads (straight from control.db, for the admin API; the hot path uses the snapshot) ----

    async def get_row(self, table: str, key: Any) -> dict[str, Any] | None:
        """One stored row by primary key, or None."""
        spec = self.table(table)
        try:
            coerced = _coerce_key(spec, key)
        except RuleNotFound:
            return None
        return await self._db.read(lambda conn: fetch_row(conn, spec, coerced))

    async def list_rows(self, table: str) -> list[dict[str, Any]]:
        """Every stored row of `table`, in evaluation order."""
        spec = self.table(table)
        return await self._db.read(lambda conn: fetch_all(conn, spec))

    # ---- writes ----

    def _validate(self, spec: RuleTable, data: Mapping[str, Any], unchanged: frozenset[str] = frozenset()) -> Any:
        if not isinstance(data, Mapping):
            raise RuleValidationError(spec.name, [{"field": "rule", "message": "Expected an object"}])
        try:
            return spec.input_model.model_validate(dict(data), context={"unchanged": unchanged})
        except ValidationError as exc:
            raise RuleValidationError(spec.name, validation_errors(exc)) from None

    def _creator(self, spec: RuleTable, actor: Actor) -> str:
        # Detectors act as Actor("system", "auto:<detector>"); bans record them as `auto:<detector>` (plan 6.2).
        if spec.name == "bans" and actor.name.startswith("auto:"):
            return actor.name
        return actor.label

    def _create_in(
        self,
        conn: sqlite3.Connection,
        spec: RuleTable,
        columns: dict[str, Any],
        actor: Actor,
        reason: str,
        request_id: str | None,
        now: int,
    ) -> RuleChange:
        if spec.name == "bans":
            # Inside the write transaction (BEGIN IMMEDIATE), so two workers banning one subject at the same moment
            # end with one ban: the second sees the first and extends it (MP review F5).
            active = find_active_ban(conn, str(columns["subject_type"]), str(columns["subject"]), now)
            if active is not None:
                return self._extend_ban_in(conn, spec, active, columns, actor, reason, request_id, now)
        check_cap(conn, spec, columns, now)
        if find_duplicate(conn, spec, columns) is not None:
            raise RuleConflict(spec.name, _duplicate_message(spec))
        if spec.name == "rules_user_agent":
            columns["id"] = _new_user_agent_id(conn)
            if columns.get("position") is None:
                columns["position"] = int(
                    conn.execute("SELECT COALESCE(MAX(position), -1) + 1 FROM rules_user_agent").fetchone()[0]
                )
        elif not spec.pk_auto and fetch_row(conn, spec, columns[spec.pk]) is not None:
            raise RuleConflict(spec.name, f"That entry already exists in {spec.label}")
        if spec.created:
            columns["created_at"] = now
            columns["created_by"] = self._creator(spec, actor)
        if spec.name == "upstream_limits":
            columns["updated_at"] = now
            columns["updated_by"] = actor.label
        key = _insert(conn, spec, columns)
        after = fetch_row(conn, spec, key)
        audit_id = audit.record(
            conn,
            actor,
            "rule.create",
            f"{spec.name}:{key}",
            None,
            after,
            reason or None,
            request_id,
            at=now,
            # Rule rows are never secrets; without this a param or path named like a secret target (for example
            # an ignored parameter called "credential") would trip the secret-summary rule of config/audit.py.
            secret=False,
        )
        version = bump_config_version(conn, now)
        return RuleChange(spec.name, key, "create", None, after, True, version, audit_id)

    def _extend_ban_in(
        self,
        conn: sqlite3.Connection,
        spec: RuleTable,
        active: dict[str, Any],
        columns: Mapping[str, Any],
        actor: Actor,
        reason: str,
        request_id: str | None,
        now: int,
    ) -> RuleChange:
        """Fold a new ban into the subject's active one: the later expiry wins, the newer reason is kept."""
        key = active["id"]
        expires_at = later_expiry(active["expires_at"], columns.get("expires_at"))
        if expires_at == active["expires_at"]:
            # The active ban already lasts at least as long: nothing to write (the caller's ban is in force).
            return RuleChange(spec.name, key, "update", active, active, False, read_config_version(conn))
        conn.execute(
            "UPDATE bans SET expires_at = ?, reason_code = ?, reason_text = ? WHERE id = ?",
            (expires_at, columns["reason_code"], columns.get("reason_text") or "", key),
        )
        after = fetch_row(conn, spec, key)
        audit_id = audit.record(
            conn,
            actor,
            "rule.update",
            f"{spec.name}:{key}",
            active,
            after,
            f"extended an active ban; {reason}" if reason else "extended an active ban",
            request_id,
            at=now,
            secret=False,
        )
        version = bump_config_version(conn, now)
        return RuleChange(spec.name, key, "update", active, after, True, version, audit_id)

    def _update_in(
        self,
        conn: sqlite3.Connection,
        spec: RuleTable,
        key: Any,
        before: dict[str, Any],
        new_columns: Mapping[str, Any],
        actor: Actor,
        reason: str,
        request_id: str | None,
        now: int,
    ) -> RuleChange:
        diff = {name: value for name, value in new_columns.items() if before.get(name) != value}
        diff.pop(spec.pk, None)
        if not diff:
            return RuleChange(spec.name, key, "update", before, before, False, read_config_version(conn))
        merged = {**before, **diff}
        if find_duplicate(conn, spec, merged, exclude=key) is not None:
            raise RuleConflict(spec.name, _duplicate_message(spec))
        if spec.updated:
            diff["updated_at"] = now
            diff["updated_by"] = actor.label
        assignments = ", ".join(f'"{name}" = ?' for name in diff)
        try:
            # By primary key, never a read-modify-write of a cached copy (plan 5.7).
            conn.execute(
                f'UPDATE {spec.name} SET {assignments} WHERE "{spec.pk}" = ?',  # noqa: S608 (registry names)
                [*diff.values(), key],
            )
        except sqlite3.IntegrityError as exc:
            raise RuleConflict(spec.name, _integrity_message(spec, exc)) from exc
        after = fetch_row(conn, spec, key)
        audit_id = audit.record(
            conn,
            actor,
            "rule.update",
            f"{spec.name}:{key}",
            before,
            after,
            reason or None,
            request_id,
            at=now,
            secret=False,
        )
        version = bump_config_version(conn, now)
        return RuleChange(spec.name, key, "update", before, after, True, version, audit_id)

    async def create(
        self, table: str, row: Mapping[str, Any], actor: Actor, reason: str = "", *, request_id: str | None = None
    ) -> RuleChange:
        """Validate and insert one rule. Raises RuleValidationError, RuleConflict or RuleCapReached."""
        spec = self.table(table)
        reason_text = check_reason(table, reason)
        columns = to_columns(spec, self._validate(spec, row))
        now = int(self._clock.now())
        change = await self._db.write(
            lambda conn: self._create_in(conn, spec, dict(columns), actor, reason_text, request_id, now)
        )
        await self._refresh()
        return change

    async def update(
        self,
        table: str,
        key: Any,
        changes: Mapping[str, Any],
        actor: Actor,
        reason: str = "",
        *,
        request_id: str | None = None,
    ) -> RuleChange:
        """Change some fields of the row with primary key `key` (only the columns that actually differ)."""
        spec = self.table(table)
        reason_text = check_reason(table, reason)
        coerced = _coerce_key(spec, key)
        if not isinstance(changes, Mapping):
            raise RuleValidationError(table, [{"field": "rule", "message": "Expected an object"}])
        if spec.pk in changes and str(changes[spec.pk]) != str(coerced):
            raise RuleValidationError(
                table, [{"field": spec.pk, "message": "This field identifies the entry; delete it and add a new one"}]
            )
        now = int(self._clock.now())

        def write(conn: sqlite3.Connection) -> RuleChange:
            before = fetch_row(conn, spec, coerced)
            if before is None:
                raise RuleNotFound(table, f"No such entry in {spec.label}")
            current = row_to_input(spec, before)
            unchanged = frozenset(
                name for name in spec.input_fields if name not in changes or changes[name] == current.get(name)
            )
            model = self._validate(spec, {**current, **changes}, unchanged)
            new_columns = to_columns(spec, model)
            if spec.name == "rules_header" and all(
                (before.get(name) or "") == (new_columns.get(name) or "") for name in _HEADER_IDENTITY
            ):
                # Same filter: keep the id it was stored with (an imported v1 row keeps its v1 form, lead decision 3).
                new_columns["canonical_key"] = before["canonical_key"]
            return self._update_in(conn, spec, coerced, before, new_columns, actor, reason_text, request_id, now)

        change = await self._db.write(write)
        if change.changed:
            await self._refresh()
        return change

    async def delete(
        self, table: str, key: Any, actor: Actor, reason: str = "", *, request_id: str | None = None
    ) -> RuleChange:
        """Delete the row with primary key `key`. Raises RuleNotFound when there is none."""
        spec = self.table(table)
        reason_text = check_reason(table, reason)
        coerced = _coerce_key(spec, key)
        now = int(self._clock.now())

        def write(conn: sqlite3.Connection) -> RuleChange:
            before = fetch_row(conn, spec, coerced)
            if before is None:
                raise RuleNotFound(table, f"No such entry in {spec.label}")
            conn.execute(f'DELETE FROM {spec.name} WHERE "{spec.pk}" = ?', (coerced,))  # noqa: S608
            audit_id = audit.record(
                conn,
                actor,
                "rule.delete",
                f"{spec.name}:{coerced}",
                before,
                None,
                reason_text or None,
                request_id,
                at=now,
                secret=False,
            )
            version = bump_config_version(conn, now)
            return RuleChange(spec.name, coerced, "delete", before, None, True, version, audit_id)

        change = await self._db.write(write)
        await self._refresh()
        return change

    async def unban(
        self,
        subject_type: str,
        subject: str,
        actor: Actor,
        reason: str = "",
        *,
        request_id: str | None = None,
    ) -> RuleChange:
        """Lift every ban (active or expired) on one subject, in one transaction. RuleNotFound when there is none.

        Deleting by id lifts one row; this lifts the subject, which is what "unban this IP" means even if an older
        import left more than one row for it.
        """
        table = "bans"
        spec = self.table(table)
        reason_text = check_reason(table, reason)
        try:
            ban = BanIn.model_validate({"subject_type": subject_type, "subject": subject})
        except ValidationError as exc:
            raise RuleValidationError(table, validation_errors(exc)) from None
        now = int(self._clock.now())
        label = f"{ban.subject_type}:{ban.subject}"

        def write(conn: sqlite3.Connection) -> RuleChange:
            rows = [
                dict(zip(spec.columns, tuple(row), strict=True))
                for row in conn.execute(
                    f"SELECT {_quoted(spec.columns)} FROM bans WHERE subject_type = ? AND subject = ? ORDER BY id",  # noqa: S608
                    (ban.subject_type, ban.subject),
                ).fetchall()
            ]
            if not rows:
                raise RuleNotFound(table, f"{label} is not banned")
            conn.execute("DELETE FROM bans WHERE subject_type = ? AND subject = ?", (ban.subject_type, ban.subject))
            audit_id = audit.record(
                conn,
                actor,
                "rule.delete",
                f"bans:{label}"[:200],
                rows,
                None,
                reason_text or None,
                request_id,
                at=now,
                secret=False,
            )
            version = bump_config_version(conn, now)
            return RuleChange(table, label, "delete", rows, None, True, version, audit_id)

        change = await self._db.write(write)
        await self._refresh()
        return change

    async def upsert(
        self, table: str, row: Mapping[str, Any], actor: Actor, reason: str = "", *, request_id: str | None = None
    ) -> RuleChange:
        """Create the rule, or update the existing row with the same identity (v1 "set" semantics).

        Identity is the natural key (a param name, a bucket key, a path, a rung position) or the table's
        duplicate columns (the pattern, kind and CIDR). Not available for UA rules, header rules and bans.
        """
        spec = self.table(table)
        if spec.name in _NO_UPSERT:
            raise RulesError(table, f"{spec.label} are added with create, never overwritten")
        reason_text = check_reason(table, reason)
        model = self._validate(spec, row)
        columns = to_columns(spec, model)
        now = int(self._clock.now())

        def write(conn: sqlite3.Connection) -> RuleChange:
            existing = find_duplicate(conn, spec, columns) if spec.pk_auto else columns[spec.pk]
            before = None if existing is None else fetch_row(conn, spec, existing)
            if before is None:
                return self._create_in(conn, spec, dict(columns), actor, reason_text, request_id, now)
            return self._update_in(conn, spec, existing, before, columns, actor, reason_text, request_id, now)

        change = await self._db.write(write)
        if change.changed:
            await self._refresh()
        return change

    # ---- the throttle ladder (v1 replaced the whole list; rows 40 and 125) ----

    async def replace_throttle_tiers(
        self, tiers: Sequence[Mapping[str, Any]], actor: Actor, reason: str = "", *, request_id: str | None = None
    ) -> RuleChange:
        """Replace the whole ladder; rung positions follow list order (1, 2, ...). An empty list is a flat ladder."""
        table = "throttle_tiers"
        spec = self.table(table)
        reason_text = check_reason(table, reason)
        if not isinstance(tiers, Sequence) or isinstance(tiers, str | bytes):
            raise RuleValidationError(table, [{"field": "tiers", "message": "Expected a list of rungs"}])
        if len(tiers) > MAX_THROTTLE_TIERS:
            raise RuleValidationError(table, [{"field": "tiers", "message": f"At most {MAX_THROTTLE_TIERS} rungs"}])
        rows: list[dict[str, Any]] = []
        errors: list[dict[str, str]] = []
        for index, raw in enumerate(tiers, start=1):
            if not isinstance(raw, Mapping):
                errors.append({"field": f"tiers.{index}", "message": f"Rung {index} is not an object"})
                continue
            data = {**raw, "position": index}
            try:
                rows.append(to_columns(spec, ThrottleTierIn.model_validate(data)))
            except ValidationError as exc:
                errors += [
                    {"field": f"tiers.{index}.{error['field']}", "message": f"Rung {index}: {error['message']}"}
                    for error in validation_errors(exc)
                ]
        if errors:
            raise RuleValidationError(table, errors)
        now = int(self._clock.now())

        def write(conn: sqlite3.Connection) -> RuleChange:
            before = fetch_all(conn, spec)
            if before == rows:
                return RuleChange(table, None, "replace", before, before, False, read_config_version(conn))
            conn.execute("DELETE FROM throttle_tiers")
            for columns in rows:
                _insert(conn, spec, columns)
            after = fetch_all(conn, spec)
            audit_id = audit.record(
                conn,
                actor,
                "throttle_tiers.replace",
                "throttle_tiers",
                before,
                after,
                reason_text or None,
                request_id,
                at=now,
                secret=False,
            )
            version = bump_config_version(conn, now)
            return RuleChange(table, None, "replace", before, after, True, version, audit_id)

        change = await self._db.write(write)
        if change.changed:
            await self._refresh()
        return change

    async def reset_throttle_tiers(
        self, actor: Actor, reason: str = "", *, request_id: str | None = None
    ) -> RuleChange:
        """Restore the four shipped rungs (parity row 125, with the C5 replacement message)."""
        from roxy.config.defaults import throttle_tier_rows  # defaults imports this package's models, not this module

        return await self.replace_throttle_tiers(throttle_tier_rows(), actor, reason, request_id=request_id)

    # ---- UA rule order ----

    async def reorder_user_agent_rules(
        self, ids: Sequence[str], actor: Actor, reason: str = "", *, request_id: str | None = None
    ) -> RuleChange:
        """Set the evaluation order of the UA rules: `ids` must list every rule exactly once, first match first."""
        table = "rules_user_agent"
        spec = self.table(table)
        reason_text = check_reason(table, reason)
        wanted = [str(item) for item in ids]
        if len(set(wanted)) != len(wanted):
            raise RuleValidationError(table, [{"field": "ids", "message": "A rule is listed twice"}])
        now = int(self._clock.now())

        def write(conn: sqlite3.Connection) -> RuleChange:
            rows = fetch_all(conn, spec)
            before = [row["id"] for row in rows]
            if set(before) != set(wanted):
                raise RuleValidationError(table, [{"field": "ids", "message": "List every User-Agent rule once"}])
            positions = {row["id"]: row["position"] for row in rows}
            if before == wanted and all(positions[rule_id] == index for index, rule_id in enumerate(wanted)):
                return RuleChange(table, None, "reorder", before, before, False, read_config_version(conn))
            for index, rule_id in enumerate(wanted):
                conn.execute(
                    "UPDATE rules_user_agent SET position = ?, updated_at = ?, updated_by = ? WHERE id = ?",
                    (index, now, actor.label, rule_id),
                )
            audit_id = audit.record(
                conn,
                actor,
                "rule.reorder",
                table,
                before,
                wanted,
                reason_text or None,
                request_id,
                at=now,
                secret=False,
            )
            version = bump_config_version(conn, now)
            return RuleChange(table, None, "reorder", before, wanted, True, version, audit_id)

        change = await self._db.write(write)
        if change.changed:
            await self._refresh()
        return change

    async def _refresh(self) -> None:
        """Let this worker see its own change at once (the others reload within a second)."""
        if self._store is None:
            return
        try:
            await self._store.reload()
        except SharedStateUnavailable as exc:  # the change is committed; the watcher catches up
            log.warning("rules_reload_after_write_failed", extra={"fields": {"error": str(exc)[:200]}})


__all__ = [
    "RuleAction",
    "RuleCapReached",
    "RuleChange",
    "RuleConflict",
    "RuleNotFound",
    "RuleValidationError",
    "RulesError",
    "RulesService",
    "check_cap",
    "check_reason",
    "fetch_all",
    "fetch_row",
    "find_active_ban",
    "find_duplicate",
    "later_expiry",
    "validation_errors",
]
