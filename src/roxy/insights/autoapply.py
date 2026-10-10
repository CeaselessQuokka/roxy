"""Auto-apply mode (plan 11.4, owner decision D7): Roxy applies its own safe recommendations, carefully.

What this is
    `AutoApplier.run()` applies open recommendations that are `safe_auto` and `risk` low, within the D7
    guardrails; `AutoApplier.watch()` closes watch windows: when a guard metric got worse by more than
    `auto_apply_rollback_threshold_pct` the change is rolled back automatically (state `rolled_back`) and the admin
    is notified; otherwise the change is kept. `guardrail_problem(rec, settings, ...)` says why a recommendation may
    not be auto-applied (the Recommendations page can show it).

Why it exists
    `insights_auto_apply` is 0 by default. When the owner turns it on, small scoped changes (a cache rule, an
    endpoint bucket) can take effect at 3 a.m. without waiting for a click, but never a change an admin would want
    to weigh: nothing global, nothing security related, nothing big, nothing stale, and nothing that stays if it
    hurts without the admin being told.

How it works (the guardrails, plan 11.4)
    - Only rules whose class allows it (`Rule.safe_auto`) and that are switched on (`insight_<rule>_enabled`; an
      admin who switched a rule off has withdrawn its proposals), recommendations whose every change is scoped to
      one row (the engine sets `safe_auto` from the change kinds) and `risk == "low"`.
    - Only freshly evaluated proposals: the card must have been refreshed by an evaluation within
      `FRESH_EVALUATIONS` evaluation intervals (`insights_interval_s`); a card its rule stopped refreshing (switched
      off, failing, cut by the per-rule cap) waits.
    - Only the proposal as judged: `RecommendationActions.apply(auto=True, expected_digest=...)` re-checks, inside
      the recommendation's action lease, that the stored changes are the ones judged here and that every live value
      (a bucket's effective rate, a rule row's columns, a setting) still equals the `current` the step limit was
      measured from; otherwise nothing is applied and the next evaluation proposes from the new value.
    - At most `auto_apply_max_per_hour` changes per rolling hour (counted from `recommendation_actions`, shared by
      every worker).
    - A setting must have `auto_apply_bounds` in the catalog, stay inside them, and move at most
      `auto_apply_max_step_pct` percent per change; security, admin and credential settings are never touched.
      Numeric rule values (a bucket's rate, a cache rule's TTL) obey the same step limit against their current value.
    - Never a ban of more than one address, never the credential allowlist, never a bypass entry, never the
      rotator quota.
    - Every apply starts a watch window of `auto_apply_watch_minutes` with a baseline of the same length before it;
      `watch()` compares error rate, Roblox 429 rate, p95 latency and refused rate after the change with that
      baseline. A rollback that only waits (another holder has the action lease, or hot.db is busy) leaves the window
      open, so the next pass (every `WATCH_INTERVAL_S`) tries again; a rollback that is refused for good (an admin
      changed the row since, so the undo is `superseded`) closes the window as kept with `rollback_refused` in its
      result and alerts the admin (critical): a regression nobody can roll back automatically must reach a person.

Leadership (plan 5.6)
    Both jobs run on the leader only and take its `JobContext`: `run` first claims `job:insights_auto_apply:<interval
    number>` in hot.db (a second pass for the same interval, by this leader or the next, does nothing), and every
    apply and rollback is fenced (the action lease is granted only while the leader lease is still this run's, and
    every service write proves it again), so a leader that stalled past its lease writes nothing. Closing a window
    is a fenced metrics.db write that changes the row only while it is `watching`, and an alert goes out only from
    the pass whose write closed it, so a leadership change never rolls back or alerts twice.

What to read next
    `roxy/insights/actions.py` (apply and undo), `roxy/config/settings/insights.py` (the D7 settings),
    `roxy/scheduler/leader.py` (fencing).
"""

from __future__ import annotations

import json
import logging
import sqlite3
from collections.abc import Callable, Mapping
from typing import Any, Final, TypeVar

from roxy.config import catalog
from roxy.config.audit import Actor
from roxy.config.spec import Group
from roxy.core.clock import Clock
from roxy.insights.actions import (
    GUARD_METRICS,
    ActionError,
    RecommendationActions,
    fenced,
    guard_metrics_sync,
)
from roxy.insights.engine import InsightsEngine
from roxy.insights.models import SCOPED_KINDS, Recommendation, changes_digest, severity_rank
from roxy.scheduler.leader import JobContext, LostLeadership
from roxy.storage.db import SharedStateUnavailable

log = logging.getLogger(__name__)

T = TypeVar("T")

AUTO_ACTOR: Final = Actor("auto_apply", "insights")
AUTO_REASON: Final = "auto-apply (D7)"
ROLLBACK_REASON: Final = "guard metric got worse"
NEVER_GROUPS: Final = frozenset({Group.ADMIN_SECURITY, Group.CREDENTIAL})
"""Setting groups auto-apply never touches (plan 11.4: no security settings, never the credential)."""
NEVER_KEYS_PREFIXES: Final = ("rotator_quota", "rotator_daily_cap", "rotator_url", "insight", "auto_apply")
"""Never the rotator quota, and never the engine's own guardrails or rules (they have no bounds anyway)."""
NEVER_KINDS: Final = frozenset({"credential_allowlist_remove", "bypass_add", "bypass_remove", "manual"})
SINGLE_ADDRESS_PREFIXES: Final = frozenset({32, 128})
RATE_METRICS: Final = frozenset({"error_rate", "roblox_429_rate", "refused_rate"})
FRESH_EVALUATIONS: Final = 2
"""A card is auto-applied only when an evaluation refreshed it within this many `insights_interval_s` (the
evaluation and the auto-apply jobs share the interval, so a live card is at most about one interval old)."""
MAX_WATCHES_PER_PASS: Final = 100
"""Watch windows one `watch()` pass closes (the oldest first; the rest wait for the next pass; plan P9)."""
MAX_REFUSALS_SHOWN: Final = 50
"""Refused recommendations listed in one pass's job result (the result stays small)."""
ROLLBACK_ALERT: Final = "auto_apply_rollback"
ROLLBACK_FAILED_ALERT: Final = "auto_apply_rollback_failed"
"""The alert for a rollback that was refused for good ("Roxy: auto-applied change could not be rolled back",
critical; `notify.alerts.ALERT_SPECS`), with a summary that says the change is still in place."""
JUDGED_AGAIN: Final = "it changed while it was being judged; the next pass judges it again"


def _step_problem(current: Any, proposed: Any, max_step_pct: float, what: str) -> str | None:
    try:
        old, new = float(current), float(proposed)
    except (TypeError, ValueError):
        return f"{what} is not a number"
    if old == 0:
        return f"{what} moves from 0 (no relative step can be judged)"
    step = abs(new - old) * 100.0 / abs(old)
    return None if step <= max_step_pct else f"{what} moves {step:.0f}%, more than {max_step_pct:g}%"


def guardrail_problem(
    rec: Recommendation,
    settings: Mapping[str, Any],
    *,
    rule_allows: bool = True,
    rule_enabled: bool = True,
    now: float | None = None,
) -> str | None:
    """Why `rec` may not be auto-applied, or None when every guardrail holds (module docstring).

    `rule_allows` is the rule class's `safe_auto`, `rule_enabled` its live `insight_<rule>_enabled` switch; with
    `now`, a card no evaluation refreshed within `FRESH_EVALUATIONS` intervals is refused as stale. The live-value
    check (has an admin changed the row since?) needs the stores and runs inside the apply."""
    if not rule_enabled:
        return "its rule is switched off (insight_<rule>_enabled is 0)"
    if not rule_allows or not rec.safe_auto:
        return "not safe to auto-apply (a change is not scoped to one endpoint or row)"
    if rec.risk != "low":
        return f"risk is {rec.risk}"
    if now is not None:
        age = float(now) - float(rec.updated_at or 0)
        if age > FRESH_EVALUATIONS * float(settings["insights_interval_s"]):
            return f"not evaluated in the last {age:.0f} s; it waits for a fresh evaluation"
    max_step = float(settings["auto_apply_max_step_pct"])
    for change in rec.changes:
        if change.kind in NEVER_KINDS:
            return f"{change.kind} changes are never auto-applied"
        if change.kind == "setting":
            key = str(change.key)
            spec = catalog.CATALOG.get(key)
            if spec is None or spec.group in NEVER_GROUPS or spec.sensitive or key.startswith(NEVER_KEYS_PREFIXES):
                return f"{key} is never auto-applied"
            if spec.auto_apply_bounds is None:
                return f"{key} has no auto-apply bounds in the catalog"
            low, high = spec.auto_apply_bounds
            if not low <= float(change.proposed) <= high:
                return f"{key} would leave its auto-apply bounds {low:g} to {high:g}"
            problem = _step_problem(settings.get(key), change.proposed, max_step, key)
            if problem:
                return problem
            continue
        if change.kind not in SCOPED_KINDS:
            return f"{change.kind} changes are global"
        if change.kind == "ban_add":
            proposed = dict(change.proposed or {})
            subject_type = str(proposed.get("subject_type"))
            subject = str(proposed.get("subject", ""))
            single = subject_type == "ip" or (
                subject_type == "cidr"
                and subject.rsplit("/", 1)[-1].isdigit()
                and int(subject.rsplit("/", 1)[-1]) in SINGLE_ADDRESS_PREFIXES
            )
            if not single:
                return "a ban of more than one address is never auto-applied"
        # The step of a row value is measured from the card's `current`; the apply refuses (superseded) unless the
        # live row still holds exactly that value, so this is also the step from the live value.
        if change.kind == "bucket_override" and isinstance(change.current, Mapping):
            problem = _step_problem(
                change.current.get("per_min"), dict(change.proposed or {}).get("per_min"), max_step, "the bucket rate"
            )
            if problem:
                return problem
        if (
            change.kind == "rule_upsert"
            and isinstance(change.current, Mapping)
            and isinstance(change.proposed, Mapping)
        ):
            for column in ("ttl", "limit", "period"):
                if column in change.proposed and change.current.get(column) is not None:
                    problem = _step_problem(change.current[column], change.proposed[column], max_step, column)
                    if problem:
                        return problem
    return None


def worse(baseline: Mapping[str, Any], after: Mapping[str, Any], threshold_pct: float) -> dict[str, dict[str, Any]]:
    """Guard metrics that got worse by more than `threshold_pct` percent (all four are "lower is better")."""
    out: dict[str, dict[str, Any]] = {}
    for name in GUARD_METRICS:
        before, now = baseline.get(name), after.get(name)
        if before is None or now is None:
            continue
        if float(before) == 0:
            # A rate that was zero and is not any more is a regression; a latency of 0 means "no traffic".
            if name in RATE_METRICS and float(now) > 0:
                out[name] = {"before": before, "after": now, "change_pct": None}
            continue
        change = (float(now) - float(before)) * 100.0 / float(before)
        if change > threshold_pct:
            out[name] = {"before": before, "after": now, "change_pct": round(change, 1)}
    return out


class AutoApplier:
    """The two D7 leader jobs: `run` (apply) and `watch` (keep or roll back)."""

    def __init__(
        self,
        *,
        engine: InsightsEngine,
        actions: RecommendationActions,
        notifier: Any = None,
        clock: Clock | None = None,
    ) -> None:
        self.engine = engine
        self.actions = actions
        self.notifier = notifier
        self.clock = clock or engine.clock

    def _settings(self) -> Mapping[str, Any]:
        return self.engine.context().settings

    async def _write(self, fn: Callable[[sqlite3.Connection], T], job: JobContext | None) -> T:
        """A metrics.db write, fenced when the leader job runs it (it commits only while the run still leads)."""
        if job is not None and fenced(job):
            return await job.fenced_write(self.engine.dbs.metrics, fn)
        result: T = await self.engine.dbs.metrics.write(fn)
        return result

    def _rule_enabled(self, rec: Recommendation, settings: Mapping[str, Any]) -> bool:
        rule = self.engine.rules.get(rec.rule_id)
        if rule is None:
            return False
        return bool(int(settings.get(f"insight_{rule.slug}_enabled", 0) or 0))  # a missing switch is off

    async def run(self, *, now: float | None = None, job: JobContext | None = None) -> dict[str, Any]:
        """Apply eligible recommendations within the hourly budget. Returns what it did (job status).

        `job` is the leader job's context: the pass claims its idempotency key first and every apply is fenced
        (module docstring "Leadership"); a deposed leader gets `LostLeadership` before it writes anything."""
        settings = self._settings()
        if not int(settings["insights_enabled"]) or not int(settings["insights_auto_apply"]):
            return {"skipped": "auto_apply_off"}
        when = float(self.clock.now() if now is None else now)
        bucket: int | None = None
        if job is not None and fenced(job):
            # Plan 5.6: auto-apply is a non-idempotent job; claimed only once it will really act (a pass while the
            # feature is off writes nothing).
            bucket = int(when // max(1.0, float(settings["insights_interval_s"])))
            if not await job.claim(bucket):
                return {"skipped": "already_ran", "bucket": bucket}
        budget = int(settings["auto_apply_max_per_hour"])
        used = await self.engine.dbs.metrics.read(lambda conn: _changes_auto_applied(conn, when - 3600))
        applied: list[str] = []
        refused: dict[str, str] = {}
        candidates = await self.engine.list(states=("open",))
        candidates.sort(key=lambda r: (-severity_rank(r.severity), r.created_at or 0))
        for rec in candidates:
            rule = self.engine.rules.get(rec.rule_id)
            problem = guardrail_problem(
                rec,
                settings,
                rule_allows=bool(rule is not None and rule.safe_auto),
                rule_enabled=self._rule_enabled(rec, settings),
                now=when,
            )
            if problem is not None:
                refused[rec.id] = problem
                continue
            if used + len(rec.changes) > budget:
                refused[rec.id] = f"the hourly budget of {budget} auto-applied changes is used"
                break
            try:
                await self.actions.apply(
                    rec.id,
                    AUTO_ACTOR,
                    AUTO_REASON,
                    auto=True,
                    expected_digest=changes_digest(rec.changes),  # exactly what the guardrails judged
                    fence=job,
                )
            except ActionError as exc:
                refused[rec.id] = JUDGED_AGAIN if exc.code == "changed" else exc.message
                continue
            used += len(rec.changes)
            applied.append(rec.id)
        if job is not None and bucket is not None:
            await job.finish(bucket)
        shown = dict(list(refused.items())[:MAX_REFUSALS_SHOWN])
        return {"applied": applied, "refused": shown, "used_this_hour": used}

    async def watch(self, *, now: float | None = None, job: JobContext | None = None) -> dict[str, Any]:
        """Close every watch window that ended: keep the change, or roll an auto-applied one back.

        Returns the recommendation ids per outcome: `kept`, `rolled_back`, `rollback_refused` (refused for good,
        window closed, admin alerted) and `rollback_pending` (the rollback waits for the action lease or hot.db;
        the window stays open and the next pass tries again)."""
        settings = self._settings()
        when = float(self.clock.now() if now is None else now)
        threshold = float(settings["auto_apply_rollback_threshold_pct"])

        def due(conn: sqlite3.Connection) -> list[tuple[str, int, int, str | None, str | None]]:
            return [
                (str(r[0]), int(r[1]), int(r[2]), r[3], r[4])
                for r in conn.execute(
                    "SELECT recommendation_id, started_at, ends_at, baseline_json, result_json "
                    "FROM recommendation_watches WHERE state = 'watching' AND ends_at <= ? ORDER BY ends_at LIMIT ?",
                    (int(when), MAX_WATCHES_PER_PASS),
                )
            ]

        report: dict[str, list[str]] = {"kept": [], "rolled_back": [], "rollback_refused": [], "rollback_pending": []}
        for rec_id, started, ends, baseline_json, previous_json in await self.engine.dbs.metrics.read(due):
            baseline = _loads(baseline_json)
            after = await self.engine.dbs.metrics.read(lambda conn, s=started, e=ends: guard_metrics_sync(conn, s, e))
            regressions = worse(baseline, after, threshold)
            rec = await self.engine.get(rec_id)
            result: dict[str, Any] = {"baseline": baseline, "after": after, "worse": regressions}
            if not (regressions and rec is not None and rec.state == "auto_applied"):
                await self._close(rec_id, result, job)
                report["kept"].append(rec_id)
                continue
            outcome, message = await self._roll_back(rec_id, result, job)
            if outcome == "rolled_back":
                report["rolled_back"].append(rec_id)
                self._notify(rec, regressions)
            elif outcome == "pending":
                attempts = int(_loads(previous_json).get("rollback_attempts") or 0) + 1
                result.update(rollback_pending=message, rollback_attempts=attempts)
                await self._mark_pending(rec_id, result, job)
                report["rollback_pending"].append(rec_id)
            else:
                result.update(rollback_refused=message)
                if await self._close(rec_id, result, job):  # only the pass that closed the window alerts
                    self._notify_refused(rec, regressions, message)
                report["rollback_refused"].append(rec_id)
        return report

    async def _roll_back(self, rec_id: str, result: Mapping[str, Any], job: JobContext | None) -> tuple[str, str]:
        """Try the automatic rollback: `("rolled_back", "")`, `("pending", why)` when it only has to wait, or
        `("refused", why)` when it will not succeed by waiting."""
        try:
            await self.actions.undo(rec_id, AUTO_ACTOR, ROLLBACK_REASON, auto=True, result=result, fence=job)
        except LostLeadership:
            raise  # a deposed leader stops here; the window stays open for the new leader's pass
        except SharedStateUnavailable as exc:
            return "pending", f"shared state is unavailable: {exc}"[:300]
        except ActionError as exc:
            if exc.code == "busy":  # another holder has the action lease (it lives at most ACTION_LEASE_TTL_MS)
                return "pending", exc.message
            return "refused", exc.message
        except Exception as exc:
            log.exception("auto_apply_rollback_error", extra={"fields": {"recommendation": rec_id}})
            return "refused", f"the rollback failed: {type(exc).__name__}: {exc}"[:300]
        return "rolled_back", ""

    async def _close(self, rec_id: str, result: Mapping[str, Any], job: JobContext | None) -> bool:
        """Close a window as kept (only while it is still `watching`). True when this call closed it."""
        text = json.dumps(dict(result), default=str)

        def close(conn: sqlite3.Connection) -> int:
            return int(
                conn.execute(
                    "UPDATE recommendation_watches SET state = 'kept', result_json = ? WHERE recommendation_id = ? "
                    "AND state = 'watching'",
                    (text, rec_id),
                ).rowcount
            )

        return bool(await self._write(close, job))

    async def _mark_pending(self, rec_id: str, result: Mapping[str, Any], job: JobContext | None) -> None:
        """Record a rollback that waits in the open window's result (the Recommendations page shows it)."""
        text = json.dumps(dict(result), default=str)

        def mark(conn: sqlite3.Connection) -> None:
            conn.execute(
                "UPDATE recommendation_watches SET result_json = ? WHERE recommendation_id = ? AND state = 'watching'",
                (text, rec_id),
            )

        try:
            await self._write(mark, job)
        except SharedStateUnavailable:
            log.warning("auto_apply_rollback_pending_not_recorded", extra={"fields": {"recommendation": rec_id}})

    def _notify(self, rec: Recommendation, regressions: Mapping[str, Any]) -> None:
        if self.notifier is None:
            return
        try:
            from roxy.notify.alerts import make_alert

            alert = make_alert(
                ROLLBACK_ALERT,
                summary=f"An auto-applied change ({rec.title}) made a guard metric worse and was rolled back.",
                fields={"Recommendation": rec.id, "Rule": rec.rule_id, "Worse": ", ".join(sorted(regressions))},
                link="/admin/recommendations",
                rec_id=rec.id,
            )
            self.notifier.notify(alert)
        except Exception:
            log.exception("auto_apply_rollback_alert_failed")

    def _notify_refused(self, rec: Recommendation, regressions: Mapping[str, Any], reason: str) -> None:
        """Tell the admin (critical) that a regression stays in place because the rollback was refused (11.4)."""
        if self.notifier is None:
            return
        try:
            from roxy.notify.alerts import make_alert

            alert = make_alert(
                ROLLBACK_FAILED_ALERT,
                summary=(
                    f"An auto-applied change ({rec.title}) made a guard metric worse, and the automatic rollback was "
                    f"refused, so the change is still in place: {reason}. Review it and undo it by hand."
                ),
                fields={
                    "Recommendation": rec.id,
                    "Rule": rec.rule_id,
                    "Worse": ", ".join(sorted(regressions)),
                    "Rollback": "refused",
                },
                link="/admin/recommendations",
                severity="critical",
                rec_id=rec.id,
            )
            self.notifier.notify(alert)
        except Exception:
            log.exception("auto_apply_rollback_alert_failed")


def _loads(text: str | None) -> dict[str, Any]:
    """A stored JSON object, or {} (a missing or broken value never stops a watch pass)."""
    if not text:
        return {}
    try:
        value = json.loads(text)
    except ValueError:
        return {}
    return value if isinstance(value, dict) else {}


def _changes_auto_applied(conn: sqlite3.Connection, since: float) -> int:
    total = 0
    for (details,) in conn.execute(
        "SELECT details_json FROM recommendation_actions WHERE action = 'auto_apply' AND at >= ? LIMIT 1000",
        (int(since),),
    ):
        try:
            total += len(json.loads(details or "{}").get("changes", []))
        except ValueError:
            total += 1
    return total


__all__ = [
    "AUTO_ACTOR",
    "FRESH_EVALUATIONS",
    "ROLLBACK_FAILED_ALERT",
    "AutoApplier",
    "guardrail_problem",
    "worse",
]
