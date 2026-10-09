"""Auto-apply mode (plan 11.4, owner decision D7): Roxy applies its own safe recommendations, carefully.

What this is
    `AutoApplier.run()` applies open recommendations that are `safe_auto` and `risk` low, within the D7
    guardrails; `AutoApplier.watch()` closes watch windows: when a guard metric got worse by more than
    `auto_apply_rollback_threshold_pct` the change is rolled back automatically (state `rolled_back`) and the admin
    is notified; otherwise the change is kept. `guardrail_problem(rec, settings)` says why a recommendation may not
    be auto-applied (the Recommendations page shows it).

Why it exists
    `insights_auto_apply` is 0 by default. When the owner turns it on, small scoped changes (a cache rule, an
    endpoint bucket) can take effect at 3 a.m. without waiting for a click, but never a change an admin would want
    to weigh: nothing global, nothing security related, nothing big, and nothing that stays if it hurts.

How it works (the guardrails, plan 11.4)
    - Only rules whose class allows it (`Rule.safe_auto`), recommendations whose every change is scoped to one row
      (the engine sets `safe_auto` from the change kinds) and `risk == "low"`.
    - At most `auto_apply_max_per_hour` changes per rolling hour (counted from `recommendation_actions`).
    - A setting must have `auto_apply_bounds` in the catalog, stay inside them, and move at most
      `auto_apply_max_step_pct` percent per change; security, admin and credential settings are never touched.
      Numeric rule values (a bucket's rate, a cache rule's TTL) obey the same step limit against their current value.
    - Never a ban of more than one address, never the credential allowlist, never a bypass entry, never the
      rotator quota.
    - Every apply starts a watch window of `auto_apply_watch_minutes` with a baseline of the same length before it;
      `watch()` compares error rate, Roblox 429 rate, p95 latency and refused rate after the change with that
      baseline.
    Both jobs run on the leader only and are idempotent by data (an applied recommendation is no longer open; a
    closed watch is no longer `watching`).

What to read next
    `roxy/insights/actions.py` (apply and undo), `roxy/config/settings/insights.py` (the D7 settings).
"""

from __future__ import annotations

import json
import logging
import sqlite3
from collections.abc import Mapping
from typing import Any, Final

from roxy.config import catalog
from roxy.config.audit import Actor
from roxy.config.spec import Group
from roxy.core.clock import Clock
from roxy.insights.actions import GUARD_METRICS, ActionError, RecommendationActions, guard_metrics_sync
from roxy.insights.engine import InsightsEngine
from roxy.insights.models import SCOPED_KINDS, Recommendation, severity_rank

log = logging.getLogger(__name__)

AUTO_ACTOR: Final = Actor("auto_apply", "insights")
NEVER_GROUPS: Final = frozenset({Group.ADMIN_SECURITY, Group.CREDENTIAL})
"""Setting groups auto-apply never touches (plan 11.4: no security settings, never the credential)."""
NEVER_KEYS_PREFIXES: Final = ("rotator_quota", "rotator_daily_cap", "rotator_url", "insight", "auto_apply")
"""Never the rotator quota, and never the engine's own guardrails or rules (they have no bounds anyway)."""
NEVER_KINDS: Final = frozenset({"credential_allowlist_remove", "bypass_add", "bypass_remove", "manual"})
SINGLE_ADDRESS_PREFIXES: Final = frozenset({32, 128})
RATE_METRICS: Final = frozenset({"error_rate", "roblox_429_rate", "refused_rate"})


def _step_problem(current: Any, proposed: Any, max_step_pct: float, what: str) -> str | None:
    try:
        old, new = float(current), float(proposed)
    except (TypeError, ValueError):
        return f"{what} is not a number"
    if old == 0:
        return f"{what} moves from 0 (no relative step can be judged)"
    step = abs(new - old) * 100.0 / abs(old)
    return None if step <= max_step_pct else f"{what} moves {step:.0f}%, more than {max_step_pct:g}%"


def guardrail_problem(rec: Recommendation, settings: Mapping[str, Any], *, rule_allows: bool = True) -> str | None:
    """Why `rec` may not be auto-applied, or None when every guardrail holds (module docstring)."""
    if not rule_allows or not rec.safe_auto:
        return "not safe to auto-apply (a change is not scoped to one endpoint or row)"
    if rec.risk != "low":
        return f"risk is {rec.risk}"
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

    async def run(self, *, now: float | None = None, job: Any = None) -> dict[str, Any]:
        """Apply eligible recommendations within the hourly budget. Returns what it did (job status)."""
        del job  # writes go through the services; idempotent by data (applied ones are no longer open)
        settings = self._settings()
        if not int(settings["insights_enabled"]) or not int(settings["insights_auto_apply"]):
            return {"skipped": "auto_apply_off"}
        when = float(self.clock.now() if now is None else now)
        budget = int(settings["auto_apply_max_per_hour"])
        used = await self.engine.dbs.metrics.read(lambda conn: _changes_auto_applied(conn, when - 3600))
        applied: list[str] = []
        refused: dict[str, str] = {}
        candidates = await self.engine.list(states=("open",))
        candidates.sort(key=lambda r: (-severity_rank(r.severity), r.created_at or 0))
        for rec in candidates:
            rule = self.engine.rules.get(rec.rule_id)
            problem = guardrail_problem(rec, settings, rule_allows=bool(rule is not None and rule.safe_auto))
            if problem is not None:
                refused[rec.id] = problem
                continue
            if used + len(rec.changes) > budget:
                refused[rec.id] = f"the hourly budget of {budget} auto-applied changes is used"
                break
            try:
                await self.actions.apply(rec.id, AUTO_ACTOR, "auto-apply (D7)", auto=True)
            except ActionError as exc:
                refused[rec.id] = exc.message
                continue
            used += len(rec.changes)
            applied.append(rec.id)
        return {"applied": applied, "refused": dict(list(refused.items())[:50]), "used_this_hour": used}

    async def watch(self, *, now: float | None = None, job: Any = None) -> dict[str, Any]:
        """Close every watch window that ended: keep the change, or roll an auto-applied one back."""
        del job
        settings = self._settings()
        when = float(self.clock.now() if now is None else now)
        threshold = float(settings["auto_apply_rollback_threshold_pct"])

        def due(conn: sqlite3.Connection) -> list[tuple[str, int, int, str | None]]:
            return [
                (str(r[0]), int(r[1]), int(r[2]), r[3])
                for r in conn.execute(
                    "SELECT recommendation_id, started_at, ends_at, baseline_json FROM recommendation_watches "
                    "WHERE state = 'watching' AND ends_at <= ? ORDER BY ends_at LIMIT 100",
                    (int(when),),
                )
            ]

        kept: list[str] = []
        rolled_back: list[str] = []
        for rec_id, started, ends, baseline_json in await self.engine.dbs.metrics.read(due):
            baseline = json.loads(baseline_json) if baseline_json else {}
            after = await self.engine.dbs.metrics.read(lambda conn, s=started, e=ends: guard_metrics_sync(conn, s, e))
            regressions = worse(baseline, after, threshold)
            rec = await self.engine.get(rec_id)
            result = {"baseline": baseline, "after": after, "worse": regressions}
            if regressions and rec is not None and rec.state == "auto_applied":
                try:
                    await self.actions.undo(rec_id, AUTO_ACTOR, "guard metric got worse", auto=True, result=result)
                    rolled_back.append(rec_id)
                    self._notify(rec, regressions)
                    continue
                except ActionError as exc:
                    result["rollback_refused"] = exc.message
            await self.engine.dbs.metrics.write(lambda conn, r=rec_id, res=result: _close_watch(conn, r, res))
            kept.append(rec_id)
        return {"kept": kept, "rolled_back": rolled_back}

    def _notify(self, rec: Recommendation, regressions: Mapping[str, Any]) -> None:
        if self.notifier is None:
            return
        try:
            from roxy.notify.alerts import make_alert

            alert = make_alert(
                "auto_apply_rollback",
                summary=f"An auto-applied change ({rec.title}) made a guard metric worse and was rolled back.",
                fields={"Recommendation": rec.id, "Rule": rec.rule_id, "Worse": ", ".join(sorted(regressions))},
                link="/admin/recommendations",
                rec_id=rec.id,
            )
            self.notifier.notify(alert)
        except Exception:
            log.exception("auto_apply_rollback_alert_failed")


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


def _close_watch(conn: sqlite3.Connection, rec_id: str, result: Mapping[str, Any]) -> None:
    conn.execute(
        "UPDATE recommendation_watches SET state = 'kept', result_json = ? WHERE recommendation_id = ? "
        "AND state = 'watching'",
        (json.dumps(dict(result), default=str), rec_id),
    )


__all__ = ["AUTO_ACTOR", "AutoApplier", "guardrail_problem", "worse"]
