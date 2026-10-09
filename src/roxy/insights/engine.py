"""The insights engine: evaluates the recommendation rules and keeps each recommendation's lifecycle.

What this is
    `InsightsEngine` with three entry points:
    - `evaluate_rule(rule_id, now=...)`: ONE rule through the full pipeline the leader uses: the global switch
      (`insights_enabled`), the per-rule switch (`insight_<slug>_enabled`), the rule's own `evaluate`, the evidence
      minimum, the severity override (`insight_<slug>_severity`), `safe_auto` from the change kinds, and the
      fingerprint. The fixture harness and the API call this; nothing is written.
    - `run_once(...)`: the leader job (every `insights_interval_s`, plan 11.1): evaluates every enabled rule over one
      shared context, then in ONE fenced metrics.db transaction applies the lifecycle (11.1) and publishes changes to
      the SSE stream as `events` rows of type `recommendation` (the live tail delivers them to every worker).
    - `check_triggers(...)`: a short leader poll that starts an early run on trigger events (a Roblox 429 burst, a
      breaker opening, a credential status change, a settings or rule change, a ban, a failed health check).

Why it exists
    Plan 11.1: rules decide, the engine does everything that must behave the same for every rule: switches,
    severity overrides, evidence minimums, dedupe by fingerprint, lifecycle states, expiry, and delivery. Running
    on the leader only (C6) means one evaluation per interval fleet-wide; trigger detection reads shared tables
    (events, upstream_429, config_version, health_runs), so an event seen by any worker reaches the leader.

How it works (lifecycle, plan 11.1 and 11.3)
    - Before matching: open recommendations past `expires_at` become `expired`; snoozed ones past `snoozed_until`
      become `open` again.
    - A result whose fingerprint has an `open` or `snoozed` row updates that row's evidence, changes and severity
      (re-evaluation never creates a duplicate). It is published when its severity, title or changes changed.
    - A fingerprint `dismissed` or `rolled_back` within `dismiss_cooldown_days` stays quiet unless the severity
      rose above the dismissed one (then a new `open` recommendation is created).
    - A fingerprint `applied` or `auto_applied` within the watch window (`auto_apply_watch_minutes`) stays quiet:
      its change is being watched.
    - Anything else opens a new recommendation (`rec_<ulid>`, `expires_at = now + recommendation_expiry_days`).
    - `open` and `snoozed` rows of a rule that ran successfully whose condition is gone become `resolved`.
    Every state change is an `events` row of type `recommendation` in the same transaction, so a dashboard never
    sees a state the table does not hold.

What to read next
    `roxy/insights/rules/base.py` (rules), `roxy/insights/context.py` (what rules read), `roxy/insights/actions.py`
    (apply, undo, snooze, dismiss), `roxy/insights/autoapply.py` (D7).
"""

from __future__ import annotations

import asyncio
import json
import logging
import sqlite3
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, Final

from roxy.core.clock import SYSTEM_CLOCK, Clock
from roxy.core.ids import new_id
from roxy.insights import simulate
from roxy.insights.context import DefaultProviders, InsightContext, InsightProviders
from roxy.insights.models import (
    ACTIVE_STATES,
    APPLIED_STATES,
    QUIET_STATES,
    Recommendation,
    changes_digest,
    make_fingerprint,
    severity_rank,
)
from roxy.insights.rules import Rule, load_rules

log = logging.getLogger(__name__)

RECOMMENDATION_EVENT: Final = "recommendation"
"""`events.type` of a recommendation change (the SSE stream's `event: recommendation`, plan 11.1, 14.11)."""
MAX_PER_RULE: Final = 50
"""Most recommendations one rule may return per run (the highest severities are kept; plan P9)."""
MAX_LOOKUP_ROWS: Final = 5000
"""Most stored rows read per rule when matching fingerprints."""
MAX_EVENTS_PER_RUN: Final = 500
"""Most SSE events one run publishes (a burst beyond it is summarized in one event)."""
TRIGGER_POLL_S: Final = 5.0
"""How often the leader looks for trigger events."""
TRIGGER_MIN_GAP_S: Final = 5.0
"""Least time between two evaluation runs started by triggers (a burst of events starts one run, not many)."""
TRIGGER_EVENT_TYPES: Final[dict[str, str]] = {
    "breaker_open": "breaker_open",
    "credential_cooldown": "credential_status",
    "credential_rotated": "credential_status",
    "credential_replaced": "credential_status",
    "credential_rejected": "credential_status",
    "leak_blocked": "credential_status",  # a leak guard trip: CRED-ROTATOR-GUARD runs at once, not 30 s later
    "spam_ban": "ban_created",
}
"""`events.type` values that are trigger events, and the trigger kind they start (plan 11.1)."""
TRIGGER_KINDS: Final[frozenset[str]] = frozenset(
    {"roblox_429_burst", "breaker_open", "credential_status", "settings_change", "ban_created", "health_fail"}
)


@dataclass(slots=True)
class RuleOutcome:
    """What one rule produced in one evaluation."""

    rule_id: str
    recommendations: list[Recommendation] = field(default_factory=list)
    skipped: str | None = None  # "insights_disabled", "rule_disabled", "unknown_rule"
    error: str | None = None
    duration_ms: float = 0.0

    @property
    def ran(self) -> bool:
        """The rule ran to completion (its absent fingerprints may be resolved)."""
        return self.skipped is None and self.error is None


@dataclass(slots=True)
class RunReport:
    """What one `run_once` did (the System page "jobs" card and the job status)."""

    trigger: str
    evaluated: int = 0
    failed: list[str] = field(default_factory=list)
    opened: int = 0
    updated: int = 0
    reopened: int = 0
    resolved: int = 0
    expired: int = 0
    unsnoozed: int = 0
    quiet: int = 0
    published: int = 0
    duration_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in self.__slots__}


def _snapshot_of(source: Any) -> Any:
    """A snapshot from a store (`snapshot()` method or `snapshot` property) or the snapshot itself."""
    snap = getattr(source, "snapshot", None)
    if snap is None:
        return source
    return snap() if callable(snap) else snap


class InsightsEngine:
    """Rule evaluation, dedupe and lifecycle (see the module docstring)."""

    def __init__(
        self,
        *,
        dbs: Any,
        settings: Any,
        rules: Any,
        clock: Clock | None = None,
        providers: InsightProviders | None = None,
        rule_set: Mapping[str, Rule] | None = None,
    ) -> None:
        self.dbs = dbs
        self.settings = settings
        self.rules_source = rules
        self.clock = clock or SYSTEM_CLOCK
        self.providers = providers or InsightProviders()
        self.rules: dict[str, Rule] = dict(rule_set) if rule_set is not None else load_rules()
        self._last_trigger_run = 0.0
        self._trigger_cursor: dict[str, Any] = {}
        self._pending_triggers: set[str] = set()
        self._run_lock = asyncio.Lock()
        self.last_report: RunReport | None = None

    @classmethod
    def from_context(cls, ctx: Any) -> InsightsEngine:
        """The worker's engine from its `AppContext` (built in every worker; only the leader runs the jobs)."""
        env = getattr(ctx, "env", None)
        paths = getattr(ctx.dbs, "paths", None) or {}
        providers = DefaultProviders(
            state_dir=getattr(env, "state_dir", None), db_paths=paths, recorder=getattr(ctx, "recorder", None)
        )
        return cls(dbs=ctx.dbs, settings=ctx.settings, rules=ctx.rules, clock=ctx.clock, providers=providers)

    # ---- settings ----

    def _settings_snapshot(self) -> Mapping[str, Any]:
        return _snapshot_of(self.settings)  # type: ignore[no-any-return]

    def interval_s(self) -> float:
        """`insights_interval_s`, or 0 (the job is off) while `insights_enabled` is 0."""
        snap = self._settings_snapshot()
        return float(snap["insights_interval_s"]) if int(snap["insights_enabled"]) else 0.0

    # ---- evaluation ----

    def context(self, now: float | None = None, *, trigger: str = "schedule") -> InsightContext:
        """A fresh read-only context at `now` (default: the clock), with this run's settings and rules snapshots."""
        return InsightContext(
            now=float(self.clock.now() if now is None else now),
            dbs=self.dbs,
            settings=self._settings_snapshot(),
            rules=_snapshot_of(self.rules_source),
            providers=self.providers,
            clock=self.clock,
            trigger=trigger,
        )

    async def evaluate_rule(
        self, rule_id: str, *, now: float | None = None, ctx: InsightContext | None = None
    ) -> RuleOutcome:
        """One rule through the leader's pipeline (module docstring); nothing is written."""
        ctx = ctx or self.context(now)
        outcome = RuleOutcome(rule_id)
        rule = self.rules.get(rule_id)
        if rule is None:
            outcome.skipped = "unknown_rule"
            return outcome
        if not int(ctx.setting("insights_enabled")):
            outcome.skipped = "insights_disabled"
            return outcome
        if not int(ctx.setting(f"insight_{rule.slug}_enabled")):
            outcome.skipped = "rule_disabled"
            return outcome
        started = time.perf_counter()
        try:
            raw = await rule.evaluate(ctx)
        except Exception as exc:
            outcome.error = f"{type(exc).__name__}: {exc}"[:300]
            log.exception("insight_rule_failed", extra={"fields": {"rule": rule_id}})
            return outcome
        finally:
            outcome.duration_ms = round((time.perf_counter() - started) * 1000, 2)
        outcome.recommendations = self._finalize(rule, ctx, raw)
        return outcome

    def _finalize(self, rule: Rule, ctx: InsightContext, raw: Iterable[Recommendation]) -> list[Recommendation]:
        forced = str(ctx.setting(f"insight_{rule.slug}_severity"))
        minimum = rule.minimum_evidence(ctx)
        best: dict[str, Recommendation] = {}
        for rec in raw:
            if rec.evidence.sample_size < minimum:
                continue  # plan 11.1: below the rule's evidence minimum, never shown
            rec.rule_id = rule.id
            rec.family = rule.family
            rec.fingerprint = make_fingerprint(rule.id, rec.subject)
            rec.computed_severity = rec.severity
            if forced != "auto":
                rec.severity = forced
            # 11.2: safe to auto-apply only if the rule allows it and every change is scoped to one row.
            rec.safe_auto = bool(rule.safe_auto and rec.safe_auto and rec.all_scoped)
            rec.dry_run_available = simulate.can_simulate(rec)
            if rec.evidence.window_to is None:
                rec.evidence.window_to = ctx.now
            kept = best.get(rec.fingerprint)
            if kept is None or severity_rank(rec.severity) > severity_rank(kept.severity):
                best[rec.fingerprint] = rec
        ordered = sorted(best.values(), key=lambda r: (-severity_rank(r.severity), r.subject))
        return ordered[:MAX_PER_RULE]

    async def evaluate(
        self, rule_ids: Iterable[str] | None = None, *, now: float | None = None, trigger: str = "schedule"
    ) -> dict[str, RuleOutcome]:
        """Several rules over one shared context (reads are memoized for the run). Nothing is written."""
        ctx = self.context(now, trigger=trigger)
        wanted = list(rule_ids) if rule_ids is not None else list(self.rules)
        out: dict[str, RuleOutcome] = {}
        for rule_id in wanted:
            out[rule_id] = await self.evaluate_rule(rule_id, ctx=ctx)
        return out

    # ---- the leader run ----

    async def run_once(
        self,
        *,
        now: float | None = None,
        trigger: str = "schedule",
        job: Any = None,
        rule_ids: Iterable[str] | None = None,
    ) -> RunReport:
        """Evaluate and persist (module docstring). `job` is the leader `JobContext`: writes are fenced by it."""
        async with self._run_lock:
            started = time.perf_counter()
            when = float(self.clock.now() if now is None else now)
            report = RunReport(trigger)
            outcomes = await self.evaluate(rule_ids, now=when, trigger=trigger)
            report.evaluated = sum(1 for o in outcomes.values() if o.ran)
            report.failed = [rule_id for rule_id, o in outcomes.items() if o.error]
            snap = self._settings_snapshot()
            policy = LifecyclePolicy.from_settings(snap)

            def write(conn: sqlite3.Connection) -> RunReport:
                return persist(conn, outcomes, when, policy, report, self.clock)

            if job is not None and getattr(job, "epoch", 0) > 0:
                await job.fenced_write(self.dbs.metrics, write)
            else:
                await self.dbs.metrics.write(write)
            report.duration_ms = round((time.perf_counter() - started) * 1000, 2)
            self.last_report = report
            if report.failed:
                log.warning("insight_rules_failed", extra={"fields": {"rules": report.failed[:20]}})
            return report

    # ---- triggers ----

    async def check_triggers(self, *, job: Any = None, now: float | None = None) -> RunReport | None:
        """Start an early run when a trigger event happened since the last poll (module docstring)."""
        if self.interval_s() <= 0:
            return None
        when = float(self.clock.now() if now is None else now)
        # Kinds seen during the minimum gap wait here, so a burst starts one run, not none.
        self._pending_triggers |= await self._trigger_kinds(when)
        kinds = set(self._pending_triggers)
        if not kinds or when - self._last_trigger_run < TRIGGER_MIN_GAP_S:
            return None
        self._pending_triggers.clear()
        self._last_trigger_run = when
        wanted = [rid for rid, rule in self.rules.items() if not rule.triggers or rule.triggers & kinds]
        return await self.run_once(now=when, trigger=",".join(sorted(kinds)), job=job, rule_ids=wanted)

    async def _trigger_kinds(self, now: float) -> set[str]:
        cursor = self._trigger_cursor
        snap = self._settings_snapshot()
        burst = int(snap["insight_up_429_endpoint_min_429s"])  # a "429 burst" is what UP-429-ENDPOINT calls enough
        types = sorted(TRIGGER_EVENT_TYPES)
        after = int(cursor.get("event_id", -1))
        since_ms = int(cursor.get("since_ms", int(now * 1000)))
        last_health = int(cursor.get("health_id", -1))

        def read(conn: sqlite3.Connection) -> tuple[int, list[str], int, int, str | None]:
            top = int(conn.execute("SELECT coalesce(max(id), 0) FROM events").fetchone()[0])
            found: list[str] = []
            if after >= 0:
                marks = ", ".join("?" for _ in types)
                found = [
                    str(r[0])
                    for r in conn.execute(
                        f"SELECT DISTINCT type FROM events WHERE id > ? AND type IN ({marks}) LIMIT 50",  # noqa: S608
                        (after, *types),
                    )
                ]
            n429 = int(conn.execute("SELECT count(*) FROM upstream_429 WHERE at_ms >= ?", (since_ms,)).fetchone()[0])
            row = conn.execute("SELECT id, summary FROM health_runs ORDER BY id DESC LIMIT 1").fetchone()
            return top, found, n429, int(row[0]) if row else 0, (row[1] if row else None)

        top, found, n429, health_id, summary = await self.dbs.metrics.read(read)
        kinds = {TRIGGER_EVENT_TYPES[t] for t in found}
        if n429 >= burst > 0 and "since_ms" in cursor:
            kinds.add("roblox_429_burst")
        version = getattr(self.settings, "version", None)
        if "config_version" in cursor and version is not None and version != cursor["config_version"]:
            kinds.add("settings_change")
        if last_health >= 0 and health_id > last_health and _health_failed(summary):
            kinds.add("health_fail")
        cursor.update(event_id=top, since_ms=int(now * 1000), health_id=health_id, config_version=version)
        return kinds

    # ---- reads for the API and the actions ----

    async def get(self, rec_id: str) -> Recommendation | None:
        """One stored recommendation by id, or None."""

        def read(conn: sqlite3.Connection) -> Recommendation | None:
            row = conn.execute("SELECT * FROM recommendations WHERE id = ?", (rec_id,)).fetchone()
            return None if row is None else row_to_recommendation(row)

        found: Recommendation | None = await self.dbs.metrics.read(read)
        return found

    async def list(
        self, *, states: Iterable[str] = ("open",), rule_id: str | None = None, limit: int = 200
    ) -> list[Recommendation]:
        """Stored recommendations in the given states, most severe and newest first (bounded)."""
        wanted = sorted(set(states))

        def read(conn: sqlite3.Connection) -> list[Recommendation]:
            marks = ", ".join("?" for _ in wanted)
            params: list[Any] = [*wanted]
            clause = ""
            if rule_id is not None:
                clause = " AND rule_id = ?"
                params.append(rule_id)
            rows = conn.execute(
                f"SELECT * FROM recommendations WHERE state IN ({marks}){clause} "  # noqa: S608
                "ORDER BY updated_at DESC LIMIT ?",
                (*params, max(1, min(int(limit), MAX_LOOKUP_ROWS))),
            ).fetchall()
            recs = [row_to_recommendation(r) for r in rows]
            recs.sort(key=lambda r: (-severity_rank(r.severity), -(r.updated_at or 0)))
            return recs

        found: list[Recommendation] = await self.dbs.metrics.read(read)
        return found

    async def dry_run(self, rec: Recommendation | str, *, window_s: int = simulate.DEFAULT_WINDOW_S) -> Any:
        """The 11.3 dry-run report of a recommendation (by object or id)."""
        found = await self.get(rec) if isinstance(rec, str) else rec
        if found is None:
            raise LookupError("no such recommendation")
        return await simulate.dry_run(self.context(), found, window_s=window_s)


# ---------------------------------------------------------------------------------------------- persistence


@dataclass(frozen=True, slots=True)
class LifecyclePolicy:
    """The settings the lifecycle reads (plan 15.3 J)."""

    expiry_s: float
    dismiss_cooldown_s: float
    watch_s: float

    @classmethod
    def from_settings(cls, snap: Mapping[str, Any]) -> LifecyclePolicy:
        return cls(
            expiry_s=float(snap["recommendation_expiry_days"]) * 86_400,
            dismiss_cooldown_s=float(snap["dismiss_cooldown_days"]) * 86_400,
            watch_s=float(snap["auto_apply_watch_minutes"]) * 60,
        )


def row_to_recommendation(row: sqlite3.Row | Mapping[str, Any]) -> Recommendation:
    """A stored row as a `Recommendation` (the payload plus the authoritative columns)."""
    payload = json.loads(row["payload_json"])
    rec = Recommendation.from_payload(payload)
    rec.id = str(row["id"])
    rec.rule_id = str(row["rule_id"])
    rec.fingerprint = str(row["fingerprint"])
    rec.state = str(row["state"])
    rec.severity = str(row["severity"])
    rec.created_at = float(row["created_at"])
    rec.updated_at = float(row["updated_at"])
    rec.expires_at = None if row["expires_at"] is None else float(row["expires_at"])
    rec.snoozed_until = None if row["snoozed_until"] is None else float(row["snoozed_until"])
    rec.dismissed_reason = row["dismissed_reason"]
    return rec


def publish(
    conn: sqlite3.Connection, rec: Recommendation, action: str, now: float, *, detail: Mapping[str, Any] | None = None
) -> None:
    """One `events` row of type `recommendation` (the SSE stream, plan 11.1), in the caller's transaction."""
    body: dict[str, Any] = {
        "id": rec.id,
        "rule_id": rec.rule_id,
        "subject": rec.subject[:200],
        "state": rec.state,
        "severity": rec.severity,
        "title": rec.title[:200],
        "action": action,
    }
    if detail:
        body.update(detail)
    conn.execute(
        "INSERT INTO events (at_ms, type, severity, reason_code, ip_hash, place, endpoint_template, detail_json) "
        "VALUES (?, ?, ?, ?, NULL, NULL, NULL, ?)",
        (int(now * 1000), RECOMMENDATION_EVENT, rec.severity, rec.rule_id, json.dumps(body, sort_keys=True)),
    )


def write_recommendation(conn: sqlite3.Connection, rec: Recommendation) -> None:
    """Insert or replace one recommendation row from the object (payload and columns)."""
    conn.execute(
        "INSERT INTO recommendations (id, rule_id, fingerprint, state, severity, payload_json, created_at, updated_at, "
        "expires_at, snoozed_until, dismissed_reason) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT (id) DO UPDATE SET state = excluded.state, severity = excluded.severity, "
        "payload_json = excluded.payload_json, updated_at = excluded.updated_at, expires_at = excluded.expires_at, "
        "snoozed_until = excluded.snoozed_until, dismissed_reason = excluded.dismissed_reason",
        (
            rec.id,
            rec.rule_id,
            rec.fingerprint,
            rec.state,
            rec.severity,
            json.dumps(rec.to_payload(), sort_keys=True, default=str),
            int(rec.created_at or 0),
            int(rec.updated_at or 0),
            None if rec.expires_at is None else int(rec.expires_at),
            None if rec.snoozed_until is None else int(rec.snoozed_until),
            rec.dismissed_reason,
        ),
    )


class _Publisher:
    """Bounded publishing for one run: at most `MAX_EVENTS_PER_RUN` events, then one summary event."""

    def __init__(self, conn: sqlite3.Connection, now: float, report: RunReport) -> None:
        self.conn = conn
        self.now = now
        self.report = report
        self.suppressed = 0

    def __call__(self, rec: Recommendation, action: str) -> None:
        if self.report.published >= MAX_EVENTS_PER_RUN:
            self.suppressed += 1
            return
        publish(self.conn, rec, action, self.now)
        self.report.published += 1

    def close(self) -> None:
        if self.suppressed:
            summary = Recommendation(
                rule_id="*", family="system", subject="*", title="Many recommendations changed", severity="info"
            )
            publish(self.conn, summary, "bulk", self.now, detail={"suppressed": self.suppressed})


def persist(
    conn: sqlite3.Connection,
    outcomes: Mapping[str, RuleOutcome],
    now: float,
    policy: LifecyclePolicy,
    report: RunReport,
    clock: Clock,
) -> RunReport:
    """Apply one evaluation to the `recommendations` table (module docstring "lifecycle"). One transaction."""
    out = _Publisher(conn, now, report)
    stamp = int(now)
    # Expiry and the end of snoozes, for every rule (also those that did not run this time).
    for row in conn.execute(
        "SELECT * FROM recommendations WHERE state = 'open' AND expires_at IS NOT NULL AND expires_at <= ? LIMIT ?",
        (stamp, MAX_LOOKUP_ROWS),
    ).fetchall():
        rec = row_to_recommendation(row)
        rec.state, rec.updated_at = "expired", now
        write_recommendation(conn, rec)
        report.expired += 1
        out(rec, "expired")
    for row in conn.execute(
        "SELECT * FROM recommendations WHERE state = 'snoozed' AND snoozed_until IS NOT NULL AND snoozed_until <= ? "
        "LIMIT ?",
        (stamp, MAX_LOOKUP_ROWS),
    ).fetchall():
        rec = row_to_recommendation(row)
        rec.state, rec.snoozed_until, rec.updated_at = "open", None, now
        write_recommendation(conn, rec)
        report.unsnoozed += 1
        out(rec, "unsnoozed")
    horizon = int(now - max(policy.dismiss_cooldown_s, policy.watch_s))
    for rule_id, outcome in outcomes.items():
        if not outcome.ran:
            continue
        rows = conn.execute(
            "SELECT * FROM recommendations WHERE rule_id = ? AND (state IN ('open', 'snoozed') OR "
            "(state IN ('dismissed', 'rolled_back', 'applied', 'auto_applied') AND updated_at >= ?)) "
            "ORDER BY updated_at, rowid LIMIT ?",
            (rule_id, horizon, MAX_LOOKUP_ROWS),
        ).fetchall()
        latest: dict[str, Recommendation] = {}
        for row in rows:  # oldest first: the newest row per fingerprint wins
            stored = row_to_recommendation(row)
            latest[stored.fingerprint] = stored
        seen: set[str] = set()
        for rec in outcome.recommendations:
            seen.add(rec.fingerprint)
            existing = latest.get(rec.fingerprint)
            _apply_result(conn, rec, existing, now, policy, report, out, clock)
        for fingerprint, stored in latest.items():
            if fingerprint in seen or stored.state not in ACTIVE_STATES:
                continue
            stored.state, stored.updated_at = "resolved", now
            write_recommendation(conn, stored)
            report.resolved += 1
            out(stored, "resolved")
    out.close()
    return report


def _apply_result(
    conn: sqlite3.Connection,
    rec: Recommendation,
    existing: Recommendation | None,
    now: float,
    policy: LifecyclePolicy,
    report: RunReport,
    out: Callable[[Recommendation, str], None],
    clock: Clock,
) -> None:
    if existing is not None and existing.state in ACTIVE_STATES:
        changed = (
            existing.severity != rec.severity
            or existing.title != rec.title
            or changes_digest(existing.changes) != changes_digest(rec.changes)
        )
        rec.id, rec.state, rec.created_at = existing.id, existing.state, existing.created_at
        rec.expires_at, rec.snoozed_until, rec.updated_at = existing.expires_at, existing.snoozed_until, now
        write_recommendation(conn, rec)
        report.updated += 1
        if changed and rec.state == "open":
            out(rec, "updated")
        return
    if existing is not None and existing.state in QUIET_STATES:
        quiet_until = (existing.updated_at or 0) + policy.dismiss_cooldown_s
        if now < quiet_until and severity_rank(rec.severity) <= severity_rank(existing.severity):
            report.quiet += 1
            return
    if existing is not None and existing.state in APPLIED_STATES and now < (existing.updated_at or 0) + policy.watch_s:
        report.quiet += 1
        return
    rec.id = new_id("rec", clock)
    rec.state = "open"
    rec.created_at = rec.updated_at = now
    rec.expires_at = now + policy.expiry_s
    rec.snoozed_until = None
    rec.dismissed_reason = None
    write_recommendation(conn, rec)
    if existing is not None:
        report.reopened += 1
        out(rec, "reopened")
    else:
        report.opened += 1
        out(rec, "opened")


def _health_failed(summary: Any) -> bool:
    try:
        data = json.loads(summary) if isinstance(summary, str) else summary
    except ValueError:
        return False
    return isinstance(data, Mapping) and int(data.get("fail") or 0) > 0


__all__ = [
    "RECOMMENDATION_EVENT",
    "TRIGGER_EVENT_TYPES",
    "TRIGGER_KINDS",
    "InsightsEngine",
    "LifecyclePolicy",
    "RuleOutcome",
    "RunReport",
    "persist",
    "publish",
    "row_to_recommendation",
    "write_recommendation",
]
