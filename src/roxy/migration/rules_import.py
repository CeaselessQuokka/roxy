"""Importing the v1 rules, the escalation ladder and the pause and throttle-all state into control.db.

What this is
    `build_rule_plans(runtime, ...)` turns the v1 `Runtime` blob into one validated row per rule (endpoint blocks,
    endpoint rules, cache rules, User-Agent rules, header rules, ignored cache parameters, ignored value headers,
    bypass entries). `apply_rule_table(conn, table, plans, ...)` writes one table inside one control.db write
    transaction. `import_ladder` replaces the ladder through `RulesService.replace_throttle_tiers`, and
    `import_service_state` writes the pause and throttle-all state.

Why it exists
    Plan 18.3: every rule is imported, UA rule ids are kept, header rules keep their v1 canonical id (lead decision
    3), admin text gets the C5 rewrite, bypass IPs become CIDR `access_list` rows with the default expiry. The
    rules service creates one rule per call and gives every new UA rule a fresh id, and it judges every regex
    again; an import must keep the v1 ids and must not refuse a pattern v1 stored and used (CHANGES.md: "Stored v1
    patterns are not judged again"). So this module composes the service's public pieces instead: the same input
    models, `to_columns`, `check_cap`, `find_duplicate`, `fetch_row`, one `audit_log` row per written rule and one
    `config_version` bump per table, all in the table's transaction, exactly as `RulesService` does per call.

How it works
    - Validation first with the normal input model. If the only problem is that today's rules would refuse a
      stored pattern or needle (a regex complexity rule), the row is validated again with that field marked as
      stored (the models' `unchanged` context): it is normalized, kept, and the report says so.
    - Idempotent: a row that already exists with the same identity (pattern, id, canonical key, name, network) is
      never overwritten. Same content is "already imported"; different content is "kept existing" with the fields
      that differ. One exception: a built-in default cache rule (origin `default`) with the same pattern as a v1
      rule takes the v1 values, because the owner's v1 choice wins over a shipped default.
    - Never twice: a v1 rule the import ledger names (an earlier run placed it) is never inserted again, so a rule
      the owner deleted in v2 after the import stays deleted ("removed in v2"). The same holds for the ladder and
      for the pause and throttle-all state, which only the first run imports (`roxy/migration/ledger.py`).
    - Rows whose identity repeats inside the v1 data (possible only in a hand-edited file) are reported as
      duplicates, never inserted twice.
    - A secret value read from the v1 files (say, the app password pasted into a note) is replaced in admin text,
      ladder text and pause reasons before the text is cut to its v2 limit (so no first part of a secret survives
      the cut), and a rule whose match text holds one is refused, so control.db never receives a v1 secret.
    - Bypass entries: v1 compared them with the client address as exact text, so only an entry that is a single
      address ever matched; a range or anything else is reported, never turned into an active network bypass.

What to read next
    `roxy/rules/models.py` (the input models), `roxy/rules/service.py` (the per-call equivalent) and
    `roxy/migration/text.py` (the C5 rewrite).
"""

from __future__ import annotations

import hashlib
import ipaddress
import math
import re
import sqlite3
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Final

from pydantic import ValidationError

from roxy.abuse.messages import MAX_STATE_REASON
from roxy.abuse.pause import STATE_KEY as PAUSE_KEY
from roxy.abuse.pause import PauseState
from roxy.abuse.state import read_state_value, write_state_value
from roxy.abuse.throttle_all import STATE_KEY as THROTTLE_ALL_KEY
from roxy.abuse.throttle_all import ThrottleAllState
from roxy.config import audit
from roxy.config.audit import Actor
from roxy.config.constants import MAX_RULE_MESSAGE, MAX_RULE_NOTE, MAX_THROTTLE_TIERS
from roxy.config.defaults import IGNORED_VALUE_HEADER_NOTE, IGNORED_VALUE_HEADERS, throttle_tier_rows
from roxy.config.runtime import bump_config_version
from roxy.migration.report import (
    ALREADY,
    DUPLICATE,
    IMPORTED,
    INVALID,
    KEPT,
    REMOVED,
    REPLACED_DEFAULT,
    SKIPPED,
    MigrationReport,
)
from roxy.migration.text import CleanText, clean_admin_text
from roxy.migration.v1_settings import v1_int
from roxy.rules.match import header_rule_canonical_key
from roxy.rules.models import RULE_TABLES, RuleTable, ThrottleTierIn, to_columns
from roxy.rules.service import (
    RuleCapReached,
    RulesService,
    check_cap,
    fetch_all,
    fetch_row,
    find_duplicate,
    validation_errors,
)
from roxy.storage.db import Database

IMPORT_ACTOR: Final = Actor("import", "v1")
IMPORT_REASON: Final = "Imported from Roxy v1 by scripts/migrate_from_v1.py (plan 18.3)"

RULE_ORDER: Final[tuple[str, ...]] = (
    "rules_endpoint_block",
    "rules_endpoint_limit",
    "rules_cache",
    "rules_user_agent",
    "rules_header",
    "cache_ignored_params",
    "ignored_value_headers",
    "access_list",
)
"""Tables imported row by row, in this order (the ladder and the pause state have their own functions)."""

PLACED: Final = frozenset({IMPORTED, ALREADY, KEPT, REPLACED_DEFAULT, REMOVED})
"""Row statuses that put the v1 key in the import ledger: the row reached v2 (or did, and v2 removed it since).
Invalid, skipped and duplicate rows are judged again by the next run."""

# Columns that never decide whether an existing row "is the same rule" (bookkeeping, order, or a value the import
# computes from the clock, such as a bypass expiry).
_IGNORED_IN_COMPARISON: Final = frozenset(
    {"created_at", "created_by", "updated_at", "updated_by", "position", "expires_at", "id"}
)
# Name-only lists: a parameter or header that is already on the list does the same job whatever its note says (a
# built-in default `t` and a v1 `t` both keep `t` out of cache keys).
_NAME_ONLY_EXTRA: Final[dict[str, frozenset[str]]] = {
    "cache_ignored_params": frozenset({"note", "origin"}),
    "ignored_value_headers": frozenset({"note", "auto"}),
}
_UA_ID = re.compile(r"[0-9a-f]{8}")


@dataclass(slots=True)
class RowPlan:
    """One v1 rule on its way into a v2 table."""

    table: str
    v1_key: str
    data: dict[str, Any] = field(default_factory=dict)
    stored_fields: frozenset[str] = frozenset()
    created_at: int | None = None
    columns: dict[str, Any] | None = None
    error: str | None = None
    status: str | None = None  # set early for rows that are skipped before the database is consulted
    notes: list[str] = field(default_factory=list)
    rewrites: list[dict[str, Any]] = field(default_factory=list)
    v2_id: Any = None

    def report_item(self) -> dict[str, Any]:
        # An invalid row shows only why it was refused; notes about how it would have been stored do not apply.
        notes = [self.error] if self.error else list(self.notes)
        item: dict[str, Any] = {"v1_key": self.v1_key, "status": self.status, "notes": notes}
        if self.v2_id is not None:
            item["id"] = self.v2_id
        return item


# --- planning (no database) ------------------------------------------------------------------------------------------


def _items(value: Any) -> list[tuple[str, dict[str, Any]]]:
    """v1 stores (`{key: {...}}`) as (key, record) pairs, skipping records that are not objects, as v1 did."""
    if not isinstance(value, Mapping):
        return []
    return [(str(key), dict(record)) for key, record in value.items() if isinstance(record, Mapping)]


def _epoch(value: Any) -> int | None:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(number) or number <= 0:
        return None
    return int(number)


def _no_scrub(text: str) -> str:
    return text


@dataclass(frozen=True, slots=True)
class PlanContext:
    """What every planner needs: the report, and `scrub`, which replaces any secret value read from the v1 tree
    (an admin who pasted the app password into a note must not get it copied into control.db)."""

    report: MigrationReport
    scrub: Callable[[str], str] = _no_scrub


def clean_scrubbed(value: Any, limit: int, scrub: Callable[[str], str]) -> tuple[CleanText, bool]:
    """Admin text ready for v2: secrets removed FIRST, then the C5 rewrite and the cut to `limit` (review finding 9:
    cutting first could leave the first part of a secret that no longer matches the whole value). Returns the
    cleaned text and whether a secret was removed."""
    raw = "" if value is None else str(value)
    safe = scrub(raw)
    return clean_admin_text(safe, limit), safe != raw


def _text(plan: RowPlan, ctx: PlanContext, field_name: str, value: Any, limit: int) -> str:
    """Admin text for the v2 row: secrets removed, C5 rewrite, repairs; each change recorded in the report."""
    report = ctx.report
    clean, secret_removed = clean_scrubbed(value, limit, ctx.scrub)
    before = len(report.text_rewrites)
    report.note_rewrite(plan.table, plan.v1_key, field_name, clean)
    if len(report.text_rewrites) > before:
        entry = report.text_rewrites[-1]
        entry["v1_key"] = plan.v1_key
        plan.rewrites.append(entry)
    if clean.truncated:
        plan.notes.append(f"{field_name} shortened to {limit} characters")
    if secret_removed:
        plan.notes.append(f"a secret value was removed from the {field_name}")
        report.warn(f"{plan.table} {plan.v1_key[:60]!r}: a secret value was removed from its {field_name}")
    return clean.text


def _messages(exc: ValidationError) -> str:
    return "; ".join(f"{error['field']}: {error['message']}" for error in validation_errors(exc))


def _validate(plan: RowPlan) -> None:
    """Validate `plan.data` with the table's input model (see the module docstring) and fill `plan.columns`."""
    spec = RULE_TABLES[plan.table]
    try:
        model = spec.input_model.model_validate(plan.data)
    except ValidationError as exc:
        fields = {error["field"] for error in validation_errors(exc)}
        if not plan.stored_fields or not fields <= plan.stored_fields:
            plan.error = _messages(exc)
            return
        try:
            model = spec.input_model.model_validate(plan.data, context={"unchanged": plan.stored_fields})
        except ValidationError as again:
            plan.error = _messages(again)
            return
        plan.notes.append(f"kept as v1 stored it, although v2 would refuse it as a new rule ({_messages(exc)})")
    columns = to_columns(spec, model)
    pattern_field = "pattern" if "pattern" in columns else "needle" if "needle" in columns else None
    kind = columns.get("type", columns.get("mode"))
    if pattern_field is not None:
        text = str(columns[pattern_field] or "")
        if not text:
            plan.error = "Empty endpoint pattern" if pattern_field == "pattern" else "Empty match text"
            return
        if kind == "regex":
            try:
                re.compile(text)  # v1 accepted only patterns its `re` could compile; keep that guarantee
            except re.error:
                plan.error = "Invalid regular expression"
                return
    plan.columns = columns


def _pattern_kind(record: Mapping[str, Any]) -> str:
    # v1: the kind is "regex" only when exactly "regex"; anything else (or a missing Type) is a glob.
    return "regex" if record.get("Type") == "regex" else "glob"


def _plan_blocks(runtime: Mapping[str, Any], ctx: PlanContext) -> list[RowPlan]:
    plans = []
    for pattern, record in _items(runtime.get("EndpointBlocks")):
        plan = RowPlan("rules_endpoint_block", pattern, stored_fields=frozenset({"pattern", "type"}))
        plan.created_at = _epoch(record.get("Added"))
        plan.data = {
            "type": _pattern_kind(record),
            "pattern": pattern,
            "note": _text(plan, ctx, "note", record.get("Note"), MAX_RULE_NOTE),
            "message": _text(plan, ctx, "message", record.get("Message"), MAX_RULE_MESSAGE),
        }
        plans.append(plan)
    return plans


def _plan_endpoint_rules(runtime: Mapping[str, Any], ctx: PlanContext) -> list[RowPlan]:
    plans = []
    for pattern, record in _items(runtime.get("EndpointRules")):
        plan = RowPlan("rules_endpoint_limit", pattern, stored_fields=frozenset({"pattern", "type"}))
        plan.created_at = _epoch(record.get("Added"))
        limit, period = v1_int(record.get("Limit")), v1_int(record.get("Period", 60))
        if limit is None or period is None:
            plan.error = "Limit and period must be whole numbers"
        plan.data = {
            "type": _pattern_kind(record),
            "pattern": pattern,
            "scope": "ip",  # v1 counted endpoint rules per client IP (throttle.check_endpoint_limit)
            "limit": limit,
            "period": period,
            "message": _text(plan, ctx, "message", record.get("Message"), MAX_RULE_MESSAGE),
            "note": _text(plan, ctx, "note", record.get("Note"), MAX_RULE_NOTE),
        }
        plans.append(plan)
    return plans


def _plan_cache_rules(runtime: Mapping[str, Any], ctx: PlanContext) -> list[RowPlan]:
    plans = []
    for pattern, record in _items(runtime.get("CacheRules")):
        plan = RowPlan("rules_cache", pattern, stored_fields=frozenset({"pattern", "type"}))
        plan.created_at = _epoch(record.get("Added"))
        ttl = v1_int(record.get("TTL"))
        if ttl is None:
            plan.error = "TTL must be a whole number of seconds"
        plan.data = {
            "type": _pattern_kind(record),
            "pattern": pattern,
            "ttl": ttl,
            "note": _text(plan, ctx, "note", record.get("Note"), MAX_RULE_NOTE),
            "origin": "admin",
        }
        plans.append(plan)
    return plans


def _plan_user_agent_rules(runtime: Mapping[str, Any], ctx: PlanContext) -> list[RowPlan]:
    plans = []
    for index, (rule_id, record) in enumerate(_items(runtime.get("UserAgentRules"))):
        plan = RowPlan("rules_user_agent", rule_id, stored_fields=frozenset({"needle", "mode"}))
        plan.created_at = _epoch(record.get("Added"))
        try:
            cooldown = float(record.get("Cooldown", 2.0))
        except (TypeError, ValueError):
            cooldown = math.nan
        limit, period = v1_int(record.get("Limit", 10)), v1_int(record.get("Period", 60))
        if limit is None or period is None or not math.isfinite(cooldown):
            plan.error = "Limit, period and cooldown must be numbers"
        plan.data = {
            "mode": record.get("Mode", "contains"),
            "needle": str(record.get("Needle", "") or ""),
            "kind": record.get("Kind", "burst"),
            "scope": record.get("Scope", "ip"),
            "limit": limit,
            "period": period,
            "cooldown": cooldown,
            "message": _text(plan, ctx, "message", record.get("Message"), MAX_RULE_MESSAGE),
            "note": _text(plan, ctx, "note", record.get("Note"), MAX_RULE_NOTE),
            "enabled": bool(record.get("Enabled", True)),  # v1 used Python truthiness
            "position": index,
        }
        plans.append(plan)
    return plans


def _plan_header_rules(runtime: Mapping[str, Any], ctx: PlanContext) -> list[RowPlan]:
    plans = []
    for rule_id, record in _items(runtime.get("HeaderRules")):
        plan = RowPlan("rules_header", rule_id, stored_fields=frozenset({"needle", "mode"}))
        plan.created_at = _epoch(record.get("Added"))
        plan.data = {
            "header": str(record.get("Header", "") or ""),
            "scope": record.get("Scope", "either"),
            "mode": record.get("Mode", "contains"),
            "needle": str(record.get("Needle", "") or ""),
            "message": _text(plan, ctx, "message", record.get("Message"), MAX_RULE_MESSAGE),
            "note": _text(plan, ctx, "note", record.get("Note"), MAX_RULE_NOTE),
        }
        plans.append(plan)
    return plans


def _plan_ignored_params(runtime: Mapping[str, Any], ctx: PlanContext) -> list[RowPlan]:
    plans = []
    for name, record in _items(runtime.get("CacheIgnoredParams")):
        plan = RowPlan("cache_ignored_params", name)
        plan.data = {
            "name": name,
            "note": _text(plan, ctx, "note", record.get("Note"), MAX_RULE_NOTE),
            "origin": "import",
        }
        plans.append(plan)
    return plans


def _plan_ignored_value_headers(runtime: Mapping[str, Any], ctx: PlanContext) -> list[RowPlan]:
    stored = runtime.get("IgnoredValueHeaders")
    if not isinstance(stored, Mapping):
        return []  # absent: v1 used its 9 seeded defaults, which v2 seeds too
    plans = []
    for name, record in _items(stored):
        plan = RowPlan("ignored_value_headers", name.lower())
        plan.data = {
            "name": name,
            "note": _text(plan, ctx, "note", record.get("Note"), MAX_RULE_NOTE),
            "auto": bool(record.get("Auto", False)),
        }
        plans.append(plan)
    names = {str(name).lower() for name in stored}
    removed = [name for name in IGNORED_VALUE_HEADERS if name not in names]
    if removed:
        ctx.report.warn(
            "v1 had stopped ignoring the values of "
            + ", ".join(removed)
            + "; v2 ignores them by default. Remove them on the Clients page if you want their values recorded."
        )
    return plans


def _single_address(text: str) -> bool:
    """Whether a v1 bypass key is one IP address. v1 runtime.is_throttle_bypassed looked the client address up in
    a dict, as exact text, so a range (`198.51.100.0/24`), an address with spaces or a host name never matched
    anyone in v1. v2 bypass is CIDR based and skips throttles, UA and endpoint rules and the tarpit, so importing
    such an entry would switch on a bypass v1 never applied (review finding 4)."""
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


def _plan_bypass(runtime: Mapping[str, Any], ctx: PlanContext, now: int, expiry_hours: int) -> list[RowPlan]:
    plans = []
    default_expiry = now + expiry_hours * 3600 if expiry_hours > 0 else None
    for address, record in _items(runtime.get("ThrottleBypassIps")):
        plan = RowPlan("access_list", address)
        plan.created_at = _epoch(record.get("Added"))
        if not _single_address(address):
            plan.error = (
                "not a single IP address: v1 compared bypass entries with the client address as exact text, so this "
                "entry never matched anyone in v1; not imported (add a range on the Access page if you want one)"
            )
            ctx.report.warn(
                f"v1 bypass entry {address[:60]!r} is not a single IP address and never matched in v1; not imported"
            )
        v1_expiry = _epoch(record.get("Expires"))
        if v1_expiry is not None and v1_expiry <= now:
            plan.status = SKIPPED
            plan.notes.append("expired in v1 already")
        expires_at = default_expiry
        if v1_expiry is not None and (expires_at is None or v1_expiry < expires_at):
            expires_at = v1_expiry
        if expires_at is None:
            plan.notes.append("never expires (bypass_default_expiry_h is 0)")
        elif v1_expiry is None or expires_at != v1_expiry:
            plan.notes.append(f"expires after {expiry_hours} h (the v2 default; v1 entries never expired)")
        plan.data = {
            "kind": "bypass",
            "cidr": address,
            "note": _text(plan, ctx, "note", record.get("Note"), MAX_RULE_NOTE),
            "expires_at": expires_at,
        }
        plans.append(plan)
    return plans


_MATCH_FIELDS: Final[tuple[str, ...]] = ("pattern", "needle", "header", "name", "cidr")


def build_rule_plans(
    runtime: Mapping[str, Any],
    report: MigrationReport,
    *,
    now: int,
    bypass_expiry_hours: int,
    scrub: Callable[[str], str] = _no_scrub,
) -> dict[str, list[RowPlan]]:
    """Validated plans for every row-by-row rule table (no database access)."""
    ctx = PlanContext(report, scrub)
    plans = {
        "rules_endpoint_block": _plan_blocks(runtime, ctx),
        "rules_endpoint_limit": _plan_endpoint_rules(runtime, ctx),
        "rules_cache": _plan_cache_rules(runtime, ctx),
        "rules_user_agent": _plan_user_agent_rules(runtime, ctx),
        "rules_header": _plan_header_rules(runtime, ctx),
        "cache_ignored_params": _plan_ignored_params(runtime, ctx),
        "ignored_value_headers": _plan_ignored_value_headers(runtime, ctx),
        "access_list": _plan_bypass(runtime, ctx, now, bypass_expiry_hours),
    }
    for table_plans in plans.values():
        for plan in table_plans:
            for name in _MATCH_FIELDS:
                value = plan.data.get(name)
                # A match field is the rule itself: it cannot be redacted, so a rule holding a secret is refused.
                if isinstance(value, str) and scrub(value) != value and plan.error is None:
                    plan.error = f"the {name} holds a secret value read from the v1 files; not imported"
            if plan.status is None and plan.error is None:
                _validate(plan)
            if plan.table == "rules_header" and plan.columns is not None:
                _apply_v1_header_key(plan)
    return plans


def _apply_v1_header_key(plan: RowPlan) -> None:
    """Header rules keep v1's canonical id form (needle lowercased), lead decision 3."""
    columns = plan.columns or {}
    v1_key = header_rule_canonical_key(columns["scope"], columns["mode"], columns["needle"], columns["header"])
    columns["canonical_key"] = v1_key
    if v1_key != plan.v1_key:
        plan.notes.append(f"the v1 id did not match its fields; stored under {v1_key!r}")


# --- applying (inside one control.db write transaction per table) ----------------------------------------------------


def _identity(spec: RuleTable, columns: Mapping[str, Any]) -> tuple[Any, ...]:
    if spec.duplicate_of:
        return tuple(columns[name] for name in spec.duplicate_of)
    return (columns[spec.pk],)


def _existing(conn: sqlite3.Connection, spec: RuleTable, columns: Mapping[str, Any]) -> dict[str, Any] | None:
    if spec.duplicate_of:
        key = find_duplicate(conn, spec, columns)
        return None if key is None else fetch_row(conn, spec, key)
    return fetch_row(conn, spec, columns[spec.pk])


def _differences(table: str, existing: Mapping[str, Any], columns: Mapping[str, Any]) -> list[str]:
    """The columns (that matter for `table`) where an existing row differs from the imported one."""
    ignored = _IGNORED_IN_COMPARISON | _NAME_ONLY_EXTRA.get(table, frozenset())

    def normal(value: Any) -> Any:
        return "" if value is None else value

    return sorted(
        name for name, value in columns.items() if name not in ignored and normal(existing.get(name)) != normal(value)
    )


def _insert(conn: sqlite3.Connection, spec: RuleTable, columns: Mapping[str, Any]) -> Any:
    names = list(columns)
    quoted = ", ".join(f'"{name}"' for name in names)
    placeholders = ", ".join("?" for _ in names)
    cursor = conn.execute(
        f"INSERT INTO {spec.name} ({quoted}) VALUES ({placeholders})",  # noqa: S608 (registry table and columns)
        [columns[name] for name in names],
    )
    return cursor.lastrowid if spec.pk_auto else columns[spec.pk]


def stable_user_agent_id(v1_id: str) -> str:
    """The id for a v1 UA rule whose id is not 8 hex characters (a hand-edited file): derived from the v1 id, so a
    rerun finds the row it wrote the first time instead of importing the rule again."""
    return hashlib.sha256(v1_id.encode("utf-8")).hexdigest()[:8]


def apply_rule_table(
    conn: sqlite3.Connection,
    table: str,
    plans: list[RowPlan],
    *,
    now: int,
    actor: Actor = IMPORT_ACTOR,
    placed_before: Callable[[str], bool] = lambda _key: False,
) -> int:
    """Write the new rows of one table, audit each, bump `config_version` once. Returns the rows written.

    `placed_before(v1_key)` says whether an earlier run placed that v1 rule (the import ledger). Such a rule is
    never inserted again and never replaces a built-in default: when its row is gone, the owner deleted it in v2.
    """
    spec = RULE_TABLES[table]
    written = 0
    seen: set[tuple[Any, ...]] = set()
    next_position = 0
    if table == "rules_user_agent":
        # New rules go after every existing one, in v1 order (v1 evaluated UA rules in insertion order).
        row = conn.execute("SELECT COALESCE(MAX(position), -1) + 1 FROM rules_user_agent").fetchone()
        next_position = int(row[0])
    for plan in plans:
        if plan.status is not None:
            continue
        if plan.error is not None or plan.columns is None:
            plan.status = INVALID
            continue
        columns = dict(plan.columns)
        if table == "rules_user_agent":
            rule_id = plan.v1_key
            if not _UA_ID.fullmatch(rule_id):
                rule_id = stable_user_agent_id(rule_id)
                plan.notes.append(f"the v1 id is not 8 hex characters; stored as {rule_id}")
            columns["id"] = rule_id
        identity = _identity(spec, columns)
        if identity in seen:
            plan.status = DUPLICATE
            plan.notes.append("the same rule appears earlier in the v1 data")
            continue
        seen.add(identity)
        existing = _existing(conn, spec, columns)
        earlier = placed_before(plan.v1_key)
        if existing is not None:
            plan.v2_id = existing[spec.pk]
            differs = _differences(table, existing, columns)
            if not differs:
                plan.status = ALREADY
                if existing.get("origin") == "default" or existing.get("note") == IGNORED_VALUE_HEADER_NOTE:
                    plan.notes.append("a built-in v2 default already covers it")
            elif table == "rules_cache" and existing.get("origin") == "default" and not earlier:
                _replace_default(conn, spec, existing, columns, differs, now, actor)
                plan.status = REPLACED_DEFAULT
                plan.notes.append("a built-in default rule had the same pattern; the v1 values replaced it")
                written += 1
            else:
                plan.status = KEPT
                plan.notes.append("an existing v2 row differs in " + ", ".join(differs) + "; it was not changed")
            continue
        if earlier:
            plan.status = REMOVED
            plan.notes.append(
                "an earlier run imported it and it was deleted (or edited) in v2 since; it was not imported again"
            )
            continue
        if table == "rules_user_agent":
            columns["position"] = next_position + int(plan.data.get("position") or 0)
        try:
            check_cap(conn, spec, columns, now)
        except RuleCapReached as exc:
            plan.status = SKIPPED
            plan.notes.append(exc.message)
            continue
        if spec.created:
            columns["created_at"] = plan.created_at or now
            columns["created_by"] = actor.label
        try:
            key = _insert(conn, spec, columns)
        except sqlite3.IntegrityError as exc:
            plan.status = INVALID
            plan.notes.append(f"the database refused the row ({str(exc)[:120]})")
            continue
        after = fetch_row(conn, spec, key)
        audit.record(
            conn, actor, "rule.import", f"{spec.name}:{key}", None, after, IMPORT_REASON, None, at=now, secret=False
        )
        plan.v2_id = key
        plan.status = IMPORTED
        written += 1
    for plan in plans:
        for entry in plan.rewrites:
            if plan.v2_id is not None:
                entry["id"] = str(plan.v2_id)
    if written:
        bump_config_version(conn, now)
    return written


def _replace_default(
    conn: sqlite3.Connection,
    spec: RuleTable,
    existing: Mapping[str, Any],
    columns: Mapping[str, Any],
    differs: list[str],
    now: int,
    actor: Actor,
) -> None:
    changes = {name: columns[name] for name in differs}
    changes["updated_at"] = now
    changes["updated_by"] = actor.label
    assignments = ", ".join(f'"{name}" = ?' for name in changes)
    conn.execute(
        f'UPDATE {spec.name} SET {assignments} WHERE "{spec.pk}" = ?',  # noqa: S608 (registry names)
        [*changes.values(), existing[spec.pk]],
    )
    after = fetch_row(conn, spec, existing[spec.pk])
    audit.record(
        conn,
        actor,
        "rule.update",
        f"{spec.name}:{existing[spec.pk]}",
        dict(existing),
        after,
        IMPORT_REASON,
        None,
        at=now,
        secret=False,
    )


# --- the ladder ------------------------------------------------------------------------------------------------------


async def import_ladder(
    db: Database,
    runtime: Mapping[str, Any],
    report: MigrationReport,
    service: RulesService,
    *,
    scrub: Callable[[str], str] = _no_scrub,
    imported_before: bool = False,
) -> tuple[int, bool]:
    """Replace the v2 ladder with the v1 one, unless v1 used its defaults, the v2 ladder was edited, or an earlier
    run already imported it (`imported_before`, from the import ledger: a ladder the owner flattened or changed in
    v2 after the import stays as it is). Returns (rows changed, whether the ladder counts as handled)."""
    tiers = runtime.get("ThrottleTiers")
    if not isinstance(tiers, list):
        report.ladder = {
            "status": SKIPPED,
            "detail": "v1 used its built-in ladder; the v2 built-in ladder (same rungs, C5 message) stays.",
        }
        return 0, False
    spec = RULE_TABLES["throttle_tiers"]
    notes: list[str] = []
    rows: list[dict[str, Any]] = []
    if len(tiers) > MAX_THROTTLE_TIERS:
        notes.append(f"v1 had {len(tiers)} rungs; only the first {MAX_THROTTLE_TIERS} were kept")
    for index, raw in enumerate(tiers[:MAX_THROTTLE_TIERS], start=1):
        if not isinstance(raw, Mapping):
            notes.append(f"rung {index} is not an object; left out")
            continue
        label = f"rung {index}"
        texts: dict[str, str] = {}
        for field_name, key, limit in (("message", "Message", MAX_RULE_MESSAGE), ("note", "Note", MAX_RULE_NOTE)):
            # Scrubbed like rule text (review finding 3). The rung stays: leaving it out would shift every later
            # multiplier, and a rule message gets the same `[redacted]` in place of the secret.
            clean, secret_removed = clean_scrubbed(raw.get(key), limit, scrub)
            report.note_rewrite("throttle_tiers", label, field_name, clean)
            if secret_removed:
                notes.append(f"a secret value was removed from the {field_name} of {label}")
                report.warn(f"throttle_tiers {label!r}: a secret value was removed from its {field_name}")
            texts[field_name] = clean.text
        try:
            multiplier = float(raw.get("Multiplier", 1))
        except (TypeError, ValueError):
            multiplier = math.nan
        data = {"position": len(rows) + 1, "multiplier": multiplier, **texts}
        try:
            rows.append(to_columns(spec, ThrottleTierIn.model_validate(data)))
        except ValidationError as exc:
            notes.append(f"rung {index} left out: {_messages(exc)}")
    current = await db.read(lambda conn: fetch_all(conn, spec))
    defaults = [to_columns(spec, ThrottleTierIn.model_validate(row)) for row in throttle_tier_rows()]
    detail = "; ".join(notes)
    if current == rows:
        report.ladder = {"status": ALREADY, "rungs": len(rows), "detail": detail or "the v2 ladder matches v1"}
        return 0, True
    if imported_before:
        report.ladder = {
            "status": KEPT,
            "rungs": len(rows),
            "detail": "an earlier run imported the ladder and it was changed in v2 since; it was not replaced. "
            + detail,
        }
        return 0, True
    if current and current != defaults:
        report.ladder = {
            "status": KEPT,
            "rungs": len(rows),
            "detail": "the v2 ladder was edited after the built-in defaults were seeded; it was not replaced. "
            + detail,
        }
        return 0, True
    await service.replace_throttle_tiers(
        [{key: row[key] for key in ("position", "multiplier", "message", "note")} for row in rows],
        IMPORT_ACTOR,
        IMPORT_REASON,
    )
    flat = " (a flat ladder: v1 had deliberately emptied it)" if not rows else ""
    report.ladder = {
        "status": IMPORTED,
        "rungs": len(rows),
        "detail": (f"{len(rows)} rung(s){flat}. " + detail).strip(),
    }
    return 1, True


# --- pause and throttle-all ------------------------------------------------------------------------------------------


def plan_service_state(
    runtime: Mapping[str, Any], report: MigrationReport, scrub: Callable[[str], str] = _no_scrub
) -> list[tuple[str, dict[str, Any], str]]:
    """(service_state key, value, v1 summary) for the pause and throttle-all state worth importing.

    The values are built with the abuse package's own `PauseState` and `ThrottleAllState`, so they have exactly
    the shape the pause and throttle-all checks read.
    """
    plans: list[tuple[str, dict[str, Any], str]] = []
    for key, flag_name, since_name, reason_name in (
        (PAUSE_KEY, "Paused", "PausedSince", "PauseReason"),
        (THROTTLE_ALL_KEY, "ThrottleAll", "ThrottleAllSince", "ThrottleAllReason"),
    ):
        flag = bool(runtime.get(flag_name, False))  # v1 restore: bool(...)
        clean, secret_removed = clean_scrubbed(runtime.get(reason_name), MAX_STATE_REASON, scrub)
        report.note_rewrite("service_state", key, "reason", clean)
        reason = clean.text
        if secret_removed:
            report.warn(f"a secret value was removed from the v1 {key} reason")
        summary = "on" if flag else "off"
        if clean.original:
            summary += f", reason {clean.original[:80]!r}"
        if not flag and not reason:
            report.service_state.append({"key": key, "v1": summary, "status": SKIPPED, "notes": ["nothing to import"]})
            continue
        since = float(_epoch(runtime.get(since_name)) or 0) if flag else 0.0
        if key == PAUSE_KEY:
            value = PauseState(paused=flag, reason=reason, since=since).to_json()
        else:
            value = ThrottleAllState(enabled=flag, reason=reason, since=since).to_json()
        plans.append((key, value, summary))
    return plans


def _is_default_state(key: str, stored: Any) -> bool:
    """True when nothing was ever switched on in v2 (no stored state, or an off switch without a reason)."""
    if stored is None:
        return True
    if key == PAUSE_KEY:
        return PauseState.from_json(stored).to_json() == PauseState().to_json()
    return ThrottleAllState.from_json(stored).to_json() == ThrottleAllState().to_json()


def _normalized(key: str, stored: Any) -> dict[str, Any]:
    if key == PAUSE_KEY:
        return PauseState.from_json(stored).to_json()
    return ThrottleAllState.from_json(stored).to_json()


async def import_service_state(
    db: Database,
    plans: list[tuple[str, dict[str, Any], str]],
    report: MigrationReport,
    *,
    now: int,
    imported_before: bool = False,
) -> int:
    """Write the planned pause and throttle-all state (never over a different state set in v2).

    Each write goes through the abuse package's `write_state_value`, which also writes the audit row and bumps
    `config_version`, exactly like the top-bar switches.

    Only the first run imports this state (`imported_before` comes from the import ledger). After the cutover the
    state v1 had when it was copied means nothing, and switching the pause off without a reason stores exactly
    the "never set" state, so a rerun could not tell it from untouched and would pause production again (review
    finding 1). A rerun only reports how v2 compares.
    """
    if not plans:
        return 0
    items: list[dict[str, Any]] = []

    def compare(conn: sqlite3.Connection) -> int:
        items.clear()
        for key, value, summary in plans:
            same = _normalized(key, read_state_value(conn, key)) == value
            note = (
                "only the first import sets this state; v2 has its own state now (switch it from the top bar)"
                if not same
                else "imported by an earlier run"
            )
            items.append({"key": key, "v1": summary, "status": ALREADY if same else KEPT, "notes": [note]})
        return 0

    def write(conn: sqlite3.Connection) -> int:
        items.clear()
        written = 0
        for key, value, summary in plans:
            stored = read_state_value(conn, key)
            item: dict[str, Any] = {"key": key, "v1": summary, "notes": []}
            items.append(item)
            if not _is_default_state(key, stored):
                if _normalized(key, stored) == value:
                    item["status"] = ALREADY
                else:
                    item["status"] = KEPT
                    item["notes"].append("v2 already has a different state; it was not changed")
                continue
            write_state_value(conn, key, value, IMPORT_ACTOR, "service_state.import", stored, IMPORT_REASON, None, now)
            item["status"] = IMPORTED
            if value.get("paused") or value.get("enabled"):
                what = "paused" if key == PAUSE_KEY else "throttling every IP (throttle-all)"
                item["notes"].append(f"v1 was {what} when it was copied, so v2 starts that way too")
                item["warning"] = f"v2 will start {what}, as v1 was; switch it off from the top bar after the cutover"
            written += 1
        return written

    written = await (db.read(compare) if imported_before else db.write(write))
    for item in items:  # recorded only after the transaction committed
        warning = item.pop("warning", None)
        if warning:
            report.warn(warning)
        report.service_state.append(item)
    return written


__all__ = [
    "IMPORT_ACTOR",
    "IMPORT_REASON",
    "PAUSE_KEY",
    "PLACED",
    "RULE_ORDER",
    "THROTTLE_ALL_KEY",
    "RowPlan",
    "apply_rule_table",
    "build_rule_plans",
    "clean_scrubbed",
    "import_ladder",
    "import_service_state",
    "plan_service_state",
]
