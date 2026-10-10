"""Recommendation actions (plan 11.3): preview, apply, undo, snooze and dismiss.

What this is
    `RecommendationActions` with `preview(id)` (the validated diff), `apply(id, actor, reason)`, `undo(id, actor,
    reason)`, `snooze(id, actor, duration)` and `dismiss(id, actor, reason, text)`, plus `guard_metrics`, the four
    numbers a watch window compares (error rate, Roblox 429 rate, p95 latency, refused rate; plan 11.4).

Why it exists
    Plan 11.3 and P4: a recommendation is applied exactly as previewed, through the same audited services an admin
    uses (settings service, rules service), with `source = recommendation:<id>` (or `auto_apply`), and it can be
    undone exactly: the stored before values are put back, and only while nothing changed the same key since.

How it works
    - Every change is validated before anything is written: settings with `catalog.validate_value` and, together,
      the cross-field rules; rule rows with their table's input model. A `manual` change cannot be applied.
    - Changes are applied one service call at a time (each call is one control.db transaction with its audit row
      and its `config_version` bump). If a later change fails, or the record of the apply cannot be written, the
      ones already applied are reverted in reverse order (compensation), so the recommendation is applied
      completely or not at all. A single transaction across both services needs transaction-composable service
      APIs; see the integrator requests in the P10 report.
    - What was applied (each change's before and after, the settings history id or the rule key) is stored in the
      `recommendation_actions` row; `undo` reads it back. A setting is superseded when its newest history row is not
      the one the apply wrote; a rule row when it no longer equals what the apply wrote. Undo refuses (409) then.
    - State changes, the action row, the watch window row and the SSE event are one metrics.db transaction.
    - One action at a time per recommendation in the whole fleet: apply, undo, snooze and dismiss each hold the
      hot.db lease `insights:action:<id>` while they read the state and act, so two workers (or a click and the
      auto-applier) can never apply the same recommendation twice; the second one gets `ActionError("busy")` (409).
      A hot.db that cannot be written is not a busy lease: `SharedStateUnavailable` propagates (503 in the API, a
      retry for the watch job; C7).
    - Exactly what was judged is applied (plan 11.3, P4): `apply(expected_digest=)` compares the stored changes with
      the digest the admin previewed (or the auto-applier judged) inside the lease, so an evaluation that rewrote
      the proposal in between is refused (`ActionError("changed")`, 409 `changed_since_preview`).
    - A list setting change (`host_add` and every `list[...]` setting) is applied as a delta: the items the rule
      added to the list it saw are added to the live list and the items it dropped are removed, so an admin's later
      edit of the list is never written over (plan 11.2: `host_add` "adds to `allowed_roblox_hosts`").
    - With `auto=True` (D7) nothing is applied unless every live value still equals the `current` the rule judged
      (a setting, a bucket's effective rate, a rule row's columns): the step guardrail was measured from it.
    - With `fence` (a leader job's context) the lease is taken only while the leader lease is still this run's, and
      every service write first proves it again with the fencing margin, so a deposed leader writes nothing (5.6).

What to read next
    `roxy/insights/autoapply.py` (D7, which calls `apply` with `auto=True` and `undo` on a regression),
    `roxy/config/settings_service.py`, `roxy/rules/service.py`.
"""

from __future__ import annotations

import contextlib
import json
import logging
import secrets
import sqlite3
from collections.abc import AsyncIterator, Callable, Mapping, Sequence
from dataclasses import asdict, dataclass, field
from typing import Any, Final, TypeVar

from roxy.config import catalog
from roxy.config.audit import Actor
from roxy.config.settings_service import SettingsService, SettingsUpdateError, check_reason, service_for
from roxy.config.spec import SettingType
from roxy.core.clock import SYSTEM_CLOCK, Clock
from roxy.insights.engine import InsightsEngine, publish, row_to_recommendation, write_recommendation
from roxy.insights.models import DISMISS_REASONS, SNOOZE_DURATIONS_S, ProposedChange, Recommendation, changes_digest
from roxy.metrics import queries
from roxy.metrics.queries import Window
from roxy.rules.models import RULE_TABLES, row_to_input
from roxy.rules.service import RulesError, RulesService
from roxy.scheduler.leader import JobContext, LostLeadership
from roxy.storage import leases
from roxy.storage.db import SharedStateUnavailable

log = logging.getLogger(__name__)

T = TypeVar("T")

MAX_REASON_CHARS: Final = 500
ACTION_LEASE_PREFIX: Final = "insights:action:"
ACTION_LEASE_TTL_MS: Final = 120_000
"""How long an action may hold its recommendation's lease (an apply is a few service writes; a holder that died
frees it after this)."""
BUSY_MESSAGE: Final = "Another request is changing this recommendation right now; reload it and try again."
CHANGED_MESSAGE: Final = "This recommendation changed since you previewed it; review the new changes and apply again."
"""`ActionError("changed")`: the stored changes are not the ones the caller judged (409 `changed_since_preview`)."""
GUARD_METRICS: Final[tuple[str, ...]] = ("error_rate", "roblox_429_rate", "p95_ms", "refused_rate")
"""The guard metrics of plan 11.4, all "lower is better"."""
_SETTING_KINDS: Final = frozenset({"setting", "host_add", "tarpit_category"})
_LIST_TYPES: Final = frozenset({SettingType.LIST_STR, SettingType.LIST_INT, SettingType.LIST_CIDR})
"""Setting types whose recommendation changes are applied as a delta against the live list (`list_delta`)."""
_BOOKKEEPING_COLUMNS: Final = frozenset({"updated_at", "updated_by", "created_at", "created_by", "hits", "last_hit_at"})
"""Rule row columns that change on their own (every write, every hit); never part of a comparison."""
_DELETE_KINDS: Final = frozenset({"rule_delete", "filter_remove", "bypass_remove", "credential_allowlist_remove"})
_TABLE_OF: Final[dict[str, str]] = {
    "bucket_override": "upstream_limits",
    "routing_rule": "rules_routing",
    "ignored_param_add": "cache_ignored_params",
    "credential_allowlist_remove": "credential_allowlist",
    "ban_add": "bans",
    "ban_remove": "bans",
    "bypass_add": "access_list",
    "bypass_remove": "access_list",
}


class ActionError(Exception):
    """An action that cannot be done. `code` maps to the API status: `not_found` 404; `conflict` (the
    recommendation's state does not allow it), `busy` (another holder has its action lease right now: worth a retry),
    `changed` (not the changes the caller judged) and `superseded` (a value changed since) 409; `invalid` and
    `manual` 422."""

    def __init__(self, code: str, message: str, fields: Mapping[str, str] | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.fields = dict(fields or {})


def fenced(fence: JobContext | None) -> bool:
    """Whether `fence` is a leader job's context whose writes must be fenced (an admin's request passes None; a
    per-worker or test context has epoch 0)."""
    return fence is not None and fence.epoch > 0


async def still_leader(fence: JobContext | None) -> None:
    """Raise `LostLeadership` unless `fence` still holds the leader lease with the fencing margin (plan 5.6).

    Called right before each audited service write of a leader job: the services write control.db in their own
    transactions, so (as for `JobContext.fenced_write` to a file other than hot.db) a takeover could only slip in
    after this check if the run stalled longer than the margin. Not fenced: does nothing."""
    if fence is None or not fenced(fence):
        return
    if fence.hot is None:
        raise LostLeadership(f"job {fence.job_name or '?'}: this context has no leader lease to check")
    await fence.hot.read(fence.assert_still_leader_with_margin)


def list_delta(live: Any, seen: Sequence[Any], proposed: Sequence[Any]) -> list[Any]:
    """A list setting change as a delta: the items the rule added to the list it `seen` are added to the `live`
    list, the items it dropped are removed from it, and every other live item stays where it is (so an admin's
    edit made after the evaluation survives; plan 11.2 `host_add` "adds to `allowed_roblox_hosts`")."""
    added = [item for item in proposed if item not in seen]
    removed = [item for item in seen if item not in proposed]
    kept = [item for item in (live or []) if item not in removed]
    return kept + [item for item in added if item not in kept]


def same_value(live: Any, seen: Any) -> bool:
    """Whether a live value still equals the value a rule saw (numbers by value, a list equal to its comma text)."""
    if isinstance(live, int | float) and isinstance(seen, int | float):
        return float(live) == float(seen)
    if isinstance(live, list | tuple) and isinstance(seen, list | tuple):
        return [str(v) for v in live] == [str(v) for v in seen]
    if isinstance(live, list | tuple) and isinstance(seen, str):
        return ",".join(str(v) for v in live) == seen
    if isinstance(seen, list | tuple) and isinstance(live, str):
        return ",".join(str(v) for v in seen) == live
    return bool(live == seen)


def effective_bucket(bucket_key: str | None, row: Mapping[str, Any] | None, snap: Mapping[str, Any]) -> dict[str, Any]:
    """`{per_min, burst}` a `host:` or `endpoint:` bucket runs at: its `upstream_limits` row, else the catalog
    default (the same reading as `InsightContext.bucket_limit`, which is what a rule's `current` shows)."""
    if row is not None:
        return {"per_min": row.get("per_min"), "burst": row.get("burst")}
    kind = "endpoint" if str(bucket_key or "").startswith("endpoint:") else "host"
    return {"per_min": snap.get(f"{kind}_bucket_default_per_min"), "burst": snap.get(f"{kind}_bucket_default_burst")}


@dataclass(slots=True)
class PreviewItem:
    """One line of the diff an admin sees before Apply."""

    kind: str
    target: str
    before: Any
    after: Any
    valid: bool = True
    message: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class AppliedChange:
    """What one applied change did, enough to undo it exactly."""

    kind: str
    target: str
    table: str | None = None
    key: Any = None  # setting key, or the rule row's primary key
    before: Any = None  # the effective setting value, or the row (None when the apply created it)
    after: Any = None  # the value or row the apply wrote (None when it deleted the row)
    history_id: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ActionResult:
    recommendation: Recommendation
    action: str
    changes: list[AppliedChange] = field(default_factory=list)
    action_id: int | None = None


# ---------------------------------------------------------------------------------------------- guard metrics


def guard_metrics_sync(conn: sqlite3.Connection, start: int, end: int) -> dict[str, float | None]:
    """Error rate, Roblox 429 rate, p95 latency and refused rate over `[start, end)` (plan 11.4 guard metrics)."""
    totals = queries.totals_sync(conn, Window(int(start), int(end), "minute", "UTC"))
    demand = int(totals.get("demand") or 0)
    requests = int(totals.get("requests") or 0)
    calls = int(totals.get("upstream_calls") or 0)
    roblox_429 = totals.get("roblox_429") or 0
    return {
        "error_rate": round(int(totals.get("errors") or 0) / demand, 6) if demand else None,
        "roblox_429_rate": round(int(roblox_429) / calls, 6) if calls else None,
        "p95_ms": totals.get("p95_ms"),
        "refused_rate": round(int(totals.get("refused") or 0) / requests, 6) if requests else None,
        "requests": requests,
    }


# ------------------------------------------------------------------------------------------------- actions


class RecommendationActions:
    """Apply, undo, snooze and dismiss (see the module docstring)."""

    def __init__(
        self,
        *,
        engine: InsightsEngine,
        settings_service: SettingsService,
        rules_service: RulesService,
        clock: Clock | None = None,
    ) -> None:
        self.engine = engine
        self.dbs = engine.dbs
        self.settings_service = settings_service
        self.rules_service = rules_service
        self.clock = clock or engine.clock or SYSTEM_CLOCK

    @classmethod
    def from_context(cls, ctx: Any, engine: InsightsEngine) -> RecommendationActions:
        """The worker's actions from its `AppContext` (the services are built over the worker's stores)."""
        settings_service = service_for(ctx)  # keyed like the settings API, so audit fingerprints compare
        rules_service = RulesService(ctx.dbs.control, clock=ctx.clock, store=ctx.rules)
        return cls(engine=engine, settings_service=settings_service, rules_service=rules_service, clock=ctx.clock)

    # ---- reads ----

    async def _get(self, rec_id: str) -> Recommendation:
        rec = await self.engine.get(rec_id)
        if rec is None:
            raise ActionError("not_found", "No such recommendation")
        return rec

    def _snapshot(self) -> Mapping[str, Any]:
        return self.engine.context().settings

    # ---- preview ----

    async def preview(self, rec_id: str) -> list[PreviewItem]:
        """The validated diff of a recommendation (nothing is written)."""
        rec = await self._get(rec_id)
        return await self._preview(rec)

    async def preview_of(self, rec: Recommendation) -> list[PreviewItem]:
        """The validated diff of a recommendation the caller already read (nothing is written), so a decision made
        from the diff (high-risk confirmation, fresh second factor) is about exactly the changes the caller holds."""
        return await self._preview(rec)

    async def _preview(self, rec: Recommendation) -> list[PreviewItem]:
        snap = self._snapshot()
        items: list[PreviewItem] = []
        settings_after: dict[str, Any] = {}
        for change in rec.changes:
            if change.kind == "manual":
                items.append(
                    PreviewItem("manual", "manual", None, change.text, False, "A manual change; nothing to apply")
                )
                continue
            if change.kind in _SETTING_KINDS:
                key, value = self._setting_target(change, snap)
                item = PreviewItem(change.kind, f"setting:{key}", snap.get(key), value)
                try:
                    settings_after[key] = catalog.validate_value(key, value)
                except (catalog.SettingValidationError, KeyError) as exc:
                    item.valid, item.message = False, str(exc)
                items.append(item)
                continue
            table = self._table(change)
            item = PreviewItem(change.kind, change.target, change.current, change.proposed)
            try:
                existing = await self._find_row(change, table)
                item.before = existing
                if change.kind not in _DELETE_KINDS and change.kind != "ban_remove":
                    data = self._row_for(change, table, existing)
                    RULE_TABLES[table].input_model.model_validate(data)
                    item.after = data
                elif existing is None:
                    item.valid, item.message = False, "The row to remove no longer exists"
                else:
                    item.after = None
            except Exception as exc:
                item.valid, item.message = False, str(exc)[:300]
            items.append(item)
        if settings_after:
            merged = {**dict(snap), **settings_after}
            for issue in catalog.validate_cross(merged):
                if set(issue.keys) & set(settings_after):
                    items.append(PreviewItem("setting", ",".join(issue.keys), None, None, False, issue.message))
        return items

    # ---- one action at a time ----

    @contextlib.asynccontextmanager
    async def _exclusive(self, rec_id: str, fence: JobContext | None = None) -> AsyncIterator[None]:
        """Hold the fleet-wide lease of one recommendation while an action reads its state and acts (C6).

        A lease another holder has is `ActionError("busy")`; a hot.db that cannot be written raises
        `SharedStateUnavailable` (it is not "another request"; C7). With a leader job's `fence`, the lease is
        granted only in a hot.db transaction that also proves the leader lease is still this run's (plan 5.6)."""
        name = f"{ACTION_LEASE_PREFIX}{rec_id}"[:200]
        holder = secrets.token_hex(8)
        now_ms = int(self.clock.now() * 1000)

        def acquire(conn: sqlite3.Connection) -> Any:
            if fence is not None and fenced(fence):
                fence.assert_still_leader(conn)  # same transaction: no takeover between the check and the grant
            return leases.acquire(conn, name, holder, ACTION_LEASE_TTL_MS, now_ms)

        grant = await self.dbs.hot.write(acquire)
        if grant is None:
            raise ActionError("busy", BUSY_MESSAGE)
        try:
            yield
        finally:
            with contextlib.suppress(SharedStateUnavailable):  # otherwise it expires after ACTION_LEASE_TTL_MS
                await self.dbs.hot.write(lambda conn: leases.release(conn, name, holder, delete=True))

    async def _write_metrics(self, fn: Callable[[sqlite3.Connection], T], fence: JobContext | None) -> T:
        """One metrics.db write transaction, fenced when a leader job acts (it commits only while it still leads)."""
        if fence is not None and fenced(fence):
            return await fence.fenced_write(self.dbs.metrics, fn)
        result: T = await self.dbs.metrics.write(fn)
        return result

    # ---- apply ----

    async def apply(
        self,
        rec_id: str,
        actor: Actor,
        reason: str = "",
        *,
        auto: bool = False,
        request_id: str | None = None,
        expected_digest: str | None = None,
        fence: JobContext | None = None,
    ) -> ActionResult:
        """Apply every change of an open recommendation, all or nothing (module docstring).

        `expected_digest` is the `changes_digest` the caller judged (the admin's preview, the auto-applier's
        guardrails); it is compared inside the lease, so exactly those changes are applied or `ActionError("changed")`
        is raised. `auto` (D7) also refuses (`superseded`) when a live value is no longer the `current` the rule
        judged. `fence` is the leader job's context: every write first proves the run still leads (plan 5.6)."""
        async with self._exclusive(rec_id, fence):
            return await self._apply(
                rec_id, actor, reason, auto=auto, request_id=request_id, expected_digest=expected_digest, fence=fence
            )

    async def _apply(
        self,
        rec_id: str,
        actor: Actor,
        reason: str,
        *,
        auto: bool,
        request_id: str | None,
        expected_digest: str | None,
        fence: JobContext | None,
    ) -> ActionResult:
        rec = await self._get(rec_id)
        if expected_digest is not None and changes_digest(rec.changes) != expected_digest:
            raise ActionError("changed", CHANGED_MESSAGE)
        if rec.state not in ("open", "snoozed"):
            raise ActionError("conflict", f"This recommendation is {rec.state}; only open ones can be applied")
        if any(change.kind == "manual" for change in rec.changes):
            raise ActionError("manual", "This recommendation needs a manual change; there is nothing to apply")
        items = await self._preview(rec)
        invalid = {item.target: item.message for item in items if not item.valid}
        if invalid:
            raise ActionError("invalid", "A change is no longer valid; nothing was applied", invalid)
        if auto:
            snap = self._snapshot()
            for change, item in zip(rec.changes, items, strict=False):
                problem = self._stale_problem(change, item.before, snap)
                if problem is not None:
                    raise ActionError("superseded", problem)
        text = _reason(reason)
        note = f"recommendation:{rec.id}" + (f" {text}" if text else "")
        source = "auto_apply" if auto else f"recommendation:{rec.id}"
        now = self.clock.now()
        baseline_window = float(self._snapshot()["auto_apply_watch_minutes"]) * 60
        baseline = await self.dbs.metrics.read(lambda c: guard_metrics_sync(c, int(now - baseline_window), int(now)))
        state = "auto_applied" if auto else "applied"
        action = "auto_apply" if auto else "apply"
        watch_until = now + baseline_window
        applied: list[AppliedChange] = []

        def write(conn: sqlite3.Connection) -> int:
            details = {"changes": [a.to_dict() for a in applied], "reason": text, "baseline": baseline}
            action_id = _action_row(conn, rec.id, action, now, actor, details)
            rec.state, rec.updated_at = state, now
            write_recommendation(conn, rec)
            conn.execute(
                "INSERT INTO recommendation_watches (recommendation_id, action_id, started_at, ends_at, state, "
                "baseline_json) VALUES (?, ?, ?, ?, 'watching', ?) ON CONFLICT (recommendation_id) DO UPDATE SET "
                "action_id = excluded.action_id, started_at = excluded.started_at, ends_at = excluded.ends_at, "
                "state = 'watching', baseline_json = excluded.baseline_json, result_json = NULL",
                (rec.id, action_id, int(now), int(watch_until), json.dumps(baseline)),
            )
            publish(conn, rec, action, now)
            return action_id

        try:
            for change in rec.changes:
                await still_leader(fence)
                applied.append(await self._apply_one(change, actor, note, source, request_id))
            # The record is part of "all or nothing": changes nobody can see or undo must not stay applied.
            action_id = await self._write_metrics(write, fence)
        except Exception as exc:
            # A fence failure compensates too: the action lease keeps this recommendation exclusive, and putting the
            # before values back leaves nothing half applied for the new leader (or an admin) to trip over.
            await self._compensate(applied, actor, f"rolled back: {note}"[:MAX_REASON_CHARS])
            if isinstance(exc, (SettingsUpdateError, RulesError)):
                raise ActionError("invalid", f"A change was refused; nothing was applied: {exc}") from exc
            raise
        return ActionResult(rec, action, applied, action_id)

    def _stale_problem(self, change: ProposedChange, before: Any, snap: Mapping[str, Any]) -> str | None:
        """Why the live value is no longer the `current` the rule judged (auto-apply only), or None.

        `before` is what the preview found live: a setting's value, or the stored row (None when there is none).
        The D7 step limit was measured from `current`, so a value an admin changed since must not be overwritten by
        an unattended apply; the next evaluation proposes from the new value."""
        stale = f"{change.target} changed since the recommendation was evaluated; it waits for a fresh evaluation"
        if change.kind in _SETTING_KINDS:
            return None if same_value(before, change.current) else stale
        if change.kind == "bucket_override":
            live = effective_bucket(change.bucket_key, before, snap)
            seen = change.current if isinstance(change.current, Mapping) else {}
            if not seen:
                return None if before is None else stale
            changed = any(not same_value(live.get(col), seen[col]) for col in ("per_min", "burst") if col in seen)
            return stale if changed else None
        if not isinstance(change.current, Mapping):
            return None if before is None else stale  # the rule saw no row; one exists now
        if before is None:
            return stale  # the rule saw a row; it is gone
        proposed = change.proposed if isinstance(change.proposed, Mapping) else {}
        columns = (set(proposed) or set(change.current)) - _BOOKKEEPING_COLUMNS
        for column in sorted(columns):
            if column in change.current and column in before and not same_value(before[column], change.current[column]):
                return stale
        return None

    def _setting_target(self, change: ProposedChange, snap: Mapping[str, Any]) -> tuple[str, Any]:
        """The setting key a change writes and the value it writes there now (a list setting as a delta)."""
        if change.kind == "tarpit_category":
            key, value = f"tarpit_on_{change.category}", change.proposed
        elif change.kind == "host_add":
            key, value = str(change.key or "allowed_roblox_hosts"), change.proposed
        else:
            key, value = str(change.key), change.proposed
        spec = catalog.CATALOG.get(key)
        listed = isinstance(change.current, list | tuple) and isinstance(value, list | tuple)
        if spec is not None and spec.type in _LIST_TYPES and listed:
            value = list_delta(snap.get(key), list(change.current), list(value))
        return key, value

    @staticmethod
    def _table(change: ProposedChange) -> str:
        table = change.table or _TABLE_OF.get(change.kind)
        if table is None or table not in RULE_TABLES:
            raise ActionError("invalid", f"Unknown table for a {change.kind} change")
        return table

    async def _find_row(self, change: ProposedChange, table: str) -> dict[str, Any] | None:
        """The stored row a change addresses: by primary key from `current`, else by its natural key (`match`)."""
        spec = RULE_TABLES[table]
        if change.kind == "bucket_override":
            return await self.rules_service.get_row(table, change.bucket_key)
        if isinstance(change.current, Mapping) and change.current.get(spec.pk) is not None:
            return await self.rules_service.get_row(table, change.current[spec.pk])
        match = dict(change.match or {})
        if not match and isinstance(change.proposed, Mapping):
            match = {k: v for k, v in change.proposed.items() if k in (spec.duplicate_of or (spec.pk,))}
        if not match:
            return None
        if spec.pk in match:
            return await self.rules_service.get_row(table, match[spec.pk])
        wanted = {k: v for k, v in match.items() if k != "type"} if table != "access_list" else match
        for row in await self.rules_service.list_rows(table):
            if all(str(row.get(k)) == str(v) for k, v in wanted.items()):
                return row
        return None

    def _row_for(self, change: ProposedChange, table: str, existing: Mapping[str, Any] | None) -> dict[str, Any]:
        """The input-model fields the change would store."""
        spec = RULE_TABLES[table]
        base = row_to_input(spec, existing) if existing is not None else {}
        if change.kind == "bucket_override":
            proposed = dict(change.proposed or {})
            data = {
                **base,
                "bucket_key": change.bucket_key,
                "per_min": proposed.get("per_min"),
                "burst": proposed.get("burst"),
                "origin": "recommendation",
            }
        else:
            data = {**base, **{k: v for k, v in (change.match or {}).items() if k in spec.input_fields}}
            data.update({k: v for k, v in dict(change.proposed or {}).items() if k in spec.input_fields})
            if "origin" in spec.input_fields and existing is None and table != "upstream_limits":
                data.setdefault("origin", "recommendation")
        return {k: v for k, v in data.items() if k in spec.input_fields}

    async def _apply_one(
        self, change: ProposedChange, actor: Actor, note: str, source: str, request_id: str | None
    ) -> AppliedChange:
        if change.kind in _SETTING_KINDS:
            key, value = self._setting_target(change, self._snapshot())  # a list delta reads the live list now
            result = await self.settings_service.update({key: value}, actor, note, source, request_id=request_id)
            if not result.changes:
                current = self._snapshot().get(key)
                return AppliedChange(change.kind, f"setting:{key}", None, key, current, current, None)
            done = result.changes[0]
            return AppliedChange(change.kind, f"setting:{key}", None, key, done.old, done.new, done.history_id)
        table = self._table(change)
        spec = RULE_TABLES[table]
        existing = await self._find_row(change, table)
        if change.kind == "ban_remove":
            proposed = dict(change.match or {})
            ruled = await self.rules_service.unban(
                str(proposed.get("subject_type")), str(proposed.get("subject")), actor, note, request_id=request_id
            )
            return AppliedChange(change.kind, change.target, table, ruled.key, ruled.before, None)
        if change.kind in _DELETE_KINDS:
            if existing is None:
                raise ActionError("conflict", f"{change.target} no longer exists")
            ruled = await self.rules_service.delete(table, existing[spec.pk], actor, note, request_id=request_id)
            return AppliedChange(change.kind, change.target, table, existing[spec.pk], ruled.before, None)
        data = self._row_for(change, table, existing)
        if existing is None:
            ruled = await self.rules_service.create(table, data, actor, note, request_id=request_id)
        else:
            changes = {k: v for k, v in data.items() if k != spec.pk}
            ruled = await self.rules_service.update(
                table, existing[spec.pk], changes, actor, note, request_id=request_id
            )
        return AppliedChange(change.kind, change.target, table, ruled.key, existing, ruled.after)

    async def _revert_one(self, applied: AppliedChange, actor: Actor, note: str) -> None:
        """Put one applied change back to its stored before value (through the same audited services)."""
        if applied.kind in _SETTING_KINDS:
            if applied.history_id is not None:  # None: the apply found the value already in place
                await self.settings_service.revert(applied.history_id, actor, note)
            return
        table = str(applied.table)
        spec = RULE_TABLES[table]
        if applied.kind == "ban_remove":
            for row in applied.before or []:
                await self.rules_service.create(table, row_to_input(spec, row), actor, note)
            return
        if applied.after is None:  # the apply deleted the row: create it again
            if applied.before is not None:
                await self.rules_service.create(table, row_to_input(spec, applied.before), actor, note)
            return
        if applied.before is None:  # the apply created the row: delete it
            if await self.rules_service.get_row(table, applied.key) is not None:
                await self.rules_service.delete(table, applied.key, actor, note)
            return
        restore = {k: v for k, v in row_to_input(spec, applied.before).items() if k != spec.pk}
        await self.rules_service.update(table, applied.key, restore, actor, note)

    async def _compensate(self, applied: Sequence[AppliedChange], actor: Actor, note: str) -> None:
        for item in reversed(applied):
            try:
                await self._revert_one(item, actor, note)
            except Exception:
                log.exception("recommendation_compensation_failed", extra={"fields": {"target": item.target}})

    # ---- undo ----

    async def undo(
        self,
        rec_id: str,
        actor: Actor,
        reason: str = "",
        *,
        auto: bool = False,
        result: Mapping[str, Any] | None = None,
        fence: JobContext | None = None,
    ) -> ActionResult:
        """Revert exactly what the last apply wrote (module docstring). `auto` marks an automatic rollback; `fence`
        is the leader job's context (the watch job): every write first proves the run still leads (plan 5.6)."""
        async with self._exclusive(rec_id, fence):
            return await self._undo(rec_id, actor, reason, auto=auto, result=result, fence=fence)

    async def _undo(
        self,
        rec_id: str,
        actor: Actor,
        reason: str,
        *,
        auto: bool,
        result: Mapping[str, Any] | None,
        fence: JobContext | None,
    ) -> ActionResult:
        rec = await self._get(rec_id)
        if rec.state not in ("applied", "auto_applied"):
            raise ActionError("conflict", f"This recommendation is {rec.state}; only applied ones can be undone")

        def last_apply(conn: sqlite3.Connection) -> dict[str, Any] | None:
            row = conn.execute(
                "SELECT details_json FROM recommendation_actions WHERE recommendation_id = ? AND action IN "
                "('apply', 'auto_apply') ORDER BY at DESC, id DESC LIMIT 1",
                (rec.id,),
            ).fetchone()
            return json.loads(row[0]) if row and row[0] else None

        details = await self.dbs.metrics.read(last_apply)
        if details is None:
            raise ActionError("conflict", "No applied changes are recorded for this recommendation")
        applied = [AppliedChange(**item) for item in details.get("changes", [])]
        text = _reason(reason)
        note = f"undo recommendation:{rec.id}" + (f" {text}" if text else "")
        # First prove nothing was superseded, then revert in reverse order.
        for item in applied:
            await self._check_not_superseded(item)
        for item in reversed(applied):
            await still_leader(fence)
            await self._revert_one(item, actor, note)
        now = self.clock.now()
        action = "auto_rollback" if auto else "undo"

        def write(conn: sqlite3.Connection) -> int:
            action_id = _action_row(conn, rec.id, action, now, actor, {"reason": text, "result": dict(result or {})})
            rec.state, rec.updated_at = "rolled_back", now
            write_recommendation(conn, rec)
            # A window still open ends here. One the watch job already closed keeps its verdict (kept, with what it
            # measured); this later undo is in the action history. The watch job leaves a window open while the
            # rollback only waits for this lease, so an admin's undo racing it cancels the window, never "kept".
            conn.execute(
                "UPDATE recommendation_watches SET state = ?, result_json = ? WHERE recommendation_id = ? "
                "AND state = 'watching'",
                ("rolled_back" if auto else "canceled", json.dumps(dict(result or {}), default=str), rec.id),
            )
            publish(conn, rec, action, now)
            return action_id

        action_id = await self._write_metrics(write, fence)
        return ActionResult(rec, action, applied, action_id)

    async def _check_not_superseded(self, item: AppliedChange) -> None:
        if item.kind in _SETTING_KINDS:
            if item.history_id is None:
                return
            latest = await self.settings_service.history(str(item.key), limit=1)
            if not latest or latest[0].id != item.history_id:
                raise ActionError("superseded", f"{item.key} was changed again after this recommendation")
            return
        if item.after is None or item.kind == "ban_remove":
            return
        current = await self.rules_service.get_row(str(item.table), item.key)
        if current is None or _comparable(current) != _comparable(item.after):
            raise ActionError("superseded", f"{item.target} was changed again after this recommendation")

    # ---- snooze and dismiss ----

    async def snooze(
        self, rec_id: str, actor: Actor, *, duration: str | None = "1d", until: float | None = None
    ) -> Recommendation:
        """Hide an open recommendation until a time (1 h, 1 day, 1 week, or `until`)."""
        async with self._exclusive(rec_id):
            return await self._snooze(rec_id, actor, duration=duration, until=until)

    async def _snooze(self, rec_id: str, actor: Actor, *, duration: str | None, until: float | None) -> Recommendation:
        rec = await self._get(rec_id)
        if rec.state not in ("open", "snoozed"):
            raise ActionError("conflict", f"This recommendation is {rec.state}; only open ones can be snoozed")
        now = self.clock.now()
        if until is None:
            if duration not in SNOOZE_DURATIONS_S:
                raise ActionError("invalid", "Snooze for 1h, 1d or 1w", {"duration": "Choose 1h, 1d or 1w"})
            until = now + SNOOZE_DURATIONS_S[str(duration)]
        if until <= now:
            raise ActionError("invalid", "The snooze must end in the future", {"until": "Choose a later time"})

        def write(conn: sqlite3.Connection) -> None:
            _action_row(conn, rec.id, "snooze", now, actor, {"until": int(until)})
            rec.state, rec.snoozed_until, rec.updated_at = "snoozed", float(until), now
            write_recommendation(conn, rec)
            publish(conn, rec, "snoozed", now)

        await self.dbs.metrics.write(write)
        return rec

    async def dismiss(self, rec_id: str, actor: Actor, reason: str, text: str = "") -> Recommendation:
        """Close a recommendation with a reason (11.3); its fingerprint stays quiet for `dismiss_cooldown_days`."""
        async with self._exclusive(rec_id):
            return await self._dismiss(rec_id, actor, reason, text)

    async def _dismiss(self, rec_id: str, actor: Actor, reason: str, text: str) -> Recommendation:
        rec = await self._get(rec_id)
        if rec.state not in ("open", "snoozed"):
            raise ActionError("conflict", f"This recommendation is {rec.state}; only open ones can be dismissed")
        if reason not in DISMISS_REASONS:
            raise ActionError("invalid", "Choose a dismiss reason", {"reason": ", ".join(DISMISS_REASONS)})
        detail = _reason(text)
        if reason == "other" and not detail:
            raise ActionError("invalid", "Say why in the text box", {"text": "Required for Other"})
        now = self.clock.now()

        def write(conn: sqlite3.Connection) -> None:
            _action_row(conn, rec.id, "dismiss", now, actor, {"reason": reason, "text": detail})
            rec.state, rec.updated_at = "dismissed", now
            rec.dismissed_reason = f"{reason}: {detail}" if detail else reason
            write_recommendation(conn, rec)
            publish(conn, rec, "dismissed", now)

        await self.dbs.metrics.write(write)
        return rec


def _reason(text: str | None) -> str:
    """A reason or dismiss text checked like a settings reason (bounded, no control or dash characters, C5)."""
    try:
        return check_reason(text)[:MAX_REASON_CHARS]
    except SettingsUpdateError as exc:
        raise ActionError("invalid", str(exc), exc.errors) from None


def _comparable(row: Mapping[str, Any]) -> dict[str, Any]:
    """A rule row without its bookkeeping columns (updated_at and friends differ after every write)."""
    return {k: v for k, v in row.items() if k not in _BOOKKEEPING_COLUMNS}


def _action_row(
    conn: sqlite3.Connection, rec_id: str, action: str, now: float, actor: Actor, details: Mapping[str, Any]
) -> int:
    cursor = conn.execute(
        "INSERT INTO recommendation_actions (recommendation_id, action, at, actor, details_json) "
        "VALUES (?, ?, ?, ?, ?)",
        (rec_id, action, int(now), actor.label, json.dumps(dict(details), default=str, sort_keys=True)),
    )
    return int(cursor.lastrowid or 0)


def load_recommendation(conn: sqlite3.Connection, rec_id: str) -> Recommendation | None:
    """One stored recommendation inside a caller's transaction."""
    row = conn.execute("SELECT * FROM recommendations WHERE id = ?", (rec_id,)).fetchone()
    return None if row is None else row_to_recommendation(row)


__all__ = [
    "BUSY_MESSAGE",
    "CHANGED_MESSAGE",
    "GUARD_METRICS",
    "ActionError",
    "ActionResult",
    "AppliedChange",
    "PreviewItem",
    "RecommendationActions",
    "effective_bucket",
    "fenced",
    "guard_metrics_sync",
    "list_delta",
    "load_recommendation",
    "same_value",
    "still_leader",
]
