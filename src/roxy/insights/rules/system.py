"""The system rules of plan 11.5: SYS-DISK, SYS-WORKER-SAT, SYS-LOOP-LAG, SYS-METRICS-DROP, SYS-CHANGE-REGRESSION and
SYS-HEALTH-FAIL.

What this is
    Six recommendation rules about Roxy's own health: storage against its budget and the disk, worker CPU and event
    loop lag, dropped metrics, a settings or rule change followed by worse numbers, and failing health checks. Each
    class docstring is the rule's help text on the Recommendations page.

Why it exists
    These are the problems an owner of a small server finds too late: a full disk, a blocked worker, a change that
    quietly made things worse. Plan 11.5 turns each into a recommendation with its evidence and, where a setting is
    the remedy, the exact change (always a global setting or a manual step, so never safe to auto-apply, 11.2).

How it works
    - Disk facts and the metrics drop counter come from the provider seams (`InsightProviders.disk`,
      `metrics_pipeline`); worker CPU and loop lag from the per-minute worker history (`worker_minute`); changes from
      `settings_history` and the rule audit rows (`InsightContext.recent_changes`); health from the latest run.
    - "For N minutes" means every minute of the last N is over the threshold (sustained), the reading the fixtures
      use; a missing minute breaks the run.
    - A regression is judged per change: the hours before it against the time since, on three rates (caller errors
      per request, Roblox 429s per upstream call, p95 latency). A rate whose baseline is zero is not compared (a
      percentage of nothing says nothing).

What to read next
    `roxy/insights/rules/base.py` (the authoring guide), `roxy/insights/context.py` (the reads),
    `roxy/config/read_changes.py` (what a change looks like), `tests/insights/test_rules_abuse_system.py`.
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from typing import Any, Final

from roxy.config import catalog
from roxy.insights.context import InsightContext, minute_floor
from roxy.insights.models import Evidence, ProposedChange, Recommendation, iso
from roxy.insights.rules.abuse import highest_safe, setting_change
from roxy.insights.rules.base import Rule, register
from roxy.metrics.queries import Window
from roxy.rules.models import RULE_TABLES, row_to_input

GB: Final = 1_000_000_000
"""`storage_total_budget_gb` is read as decimal gigabytes (the catalog unit is GB)."""
PROJECTION_DAYS: Final = 30
"""SYS-DISK "30-day projection" (11.5 row)."""
DAY_S: Final = 86_400
RETENTION_OF: Final[dict[str, str]] = {
    "metrics.rollup_minute": "retention_minute_days",
    "metrics.rollup_hour": "retention_hour_days",
    "metrics.client_minute": "retention_client_minute_days",
    "metrics.client_hour": "retention_client_hour_days",
    "metrics.client_day": "retention_client_day_days",
    "metrics.events": "retention_events_days",
    "metrics.upstream_429": "retention_upstream_429_days",
    "metrics.request_samples": "request_sample_hours",
    "metrics.errors": "retention_errors_days",
    "metrics.fingerprint_values": "retention_fingerprints_days",
    "metrics.fingerprint_user_agents": "retention_fingerprints_days",
    "exports": "retention_exports_days",
    "snapshots": "retention_snapshots_days",
}
"""Which retention setting shrinks each table or folder SYS-DISK may name (plan 6.10)."""
FILE_RETENTION_OF: Final[dict[str, str]] = {"metrics.db": "retention_minute_days"}
"""When the disk provider knows no table sizes (production measures files only), metrics.db stands for its largest
part, the minute rollups (plan 6.6)."""
RETENTION_SHARE: Final = 0.5
"""SYS-DISK halves the retention of the largest table (a clear step the admin can repeat)."""
QUEUE_GROWTH: Final = 2
"""SYS-METRICS-DROP doubles `metrics_queue_max` (bounded by its high-risk value)."""
FLUSH_SHARE: Final = 0.5
"""SYS-METRICS-DROP halves `metrics_flush_interval_ms` when the queue cannot grow (the queue drains twice as often)."""
MAX_SERIES_POINTS: Final = 240
"""Most per-minute points one worker's evidence chart holds (the longest sustain window is 240 minutes)."""
SYSTEM_LINK: Final = "/admin/system"
HEALTH_LINK: Final = "/admin/health"


# ------------------------------------------------------------------------------------------------ SYS-DISK


def sentence(parts: Sequence[str]) -> str:
    """Clauses joined with semicolons as one sentence (first letter upper case, a final period)."""
    text = "; ".join(parts)
    return (text[:1].upper() + text[1:] + ".") if text else ""


def storage_bytes(disk: Mapping[str, Any]) -> int:
    """Roxy's storage: database files plus WAL plus the export and snapshot folders (README `state.disk`)."""
    return sum(int(v.get("bytes") or 0) + int(v.get("wal_bytes") or 0) for v in (disk.get("files") or {}).values())


def projected_bytes(disk: Mapping[str, Any], now_bytes: int, days: float = PROJECTION_DAYS) -> int | None:
    """Storage `days` from now on the straight line through the first and last growth points, or None."""
    points = sorted(
        ((float(p["at"]), int(p["total_bytes"])) for p in disk.get("growth") or [] if p.get("at") is not None),
        key=lambda p: p[0],
    )
    if len(points) <= 1 or points[-1][0] <= points[0][0]:
        return None
    slope = (points[-1][1] - points[0][1]) / (points[-1][0] - points[0][0])
    return round(now_bytes + max(0.0, slope) * days * DAY_S)


@register
class SysDisk(Rule):
    """Roxy's storage is growing toward its budget, or the disk is nearly full.

    Fires when Roxy's databases and files use more than `budget_pct` percent of `storage_total_budget_gb`, when the
    last weeks' growth carried 30 days forward passes the budget, when less than `free_disk_pct` percent of the state
    volume is free, or when the 7-day average of new metric rows per minute passes `dims_per_minute`. The change halves
    the retention of the largest table; when only the disk is full (Roxy itself is small) it is a manual clean-up of
    what else fills the volume. VACUUM after lowering retention returns the space to the disk.
    """

    id = "SYS-DISK"
    triggers = frozenset({"health_fail", "settings_change"})

    async def evaluate(self, ctx: InsightContext) -> list[Recommendation]:
        disk = await ctx.providers.disk()
        if not disk:
            return []
        used = storage_bytes(disk)
        budget = float(ctx.setting("storage_total_budget_gb")) * GB
        total = int(disk.get("total_bytes") or 0)
        free = int(disk.get("free_bytes") or 0)
        projected = projected_bytes(disk, used)
        dims = disk.get("dims_per_minute_7d_avg")
        reasons: list[str] = []
        if budget and used * 100.0 / budget > self.param(ctx, "budget_pct"):
            reasons.append(
                f"Roxy uses {used / GB:.1f} GB, {used * 100.0 / budget:.0f}% of its {budget / GB:g} GB budget"
            )
        if budget and projected is not None and projected > budget:
            reasons.append(f"at the current growth it reaches {projected / GB:.1f} GB in {PROJECTION_DAYS} days")
        free_low = bool(total) and free * 100.0 / total < self.param(ctx, "free_disk_pct")
        if free_low:
            reasons.append(f"only {free * 100.0 / total:.0f}% of the disk is free")
        if dims is not None and float(dims) > self.param(ctx, "dims_per_minute"):
            reasons.append(f"metrics add {float(dims):,.0f} new dimension rows a minute (7-day average)")
        if not reasons:
            return []
        evidence = Evidence(window_to=ctx.now, sample_size=1)
        evidence.add("storage_bytes", used, "bytes")
        evidence.add("budget_bytes", round(budget), "bytes")
        if budget:
            evidence.add("budget_used_pct", round(used * 100.0 / budget, 2), "percent")
        if projected is not None:
            evidence.add("projected_30d_bytes", projected, "bytes")
        if total:
            evidence.add("free_disk_pct", round(free * 100.0 / total, 2), "percent")
        if dims is not None:
            evidence.add("dims_per_minute_7d_avg", float(dims), "rows per minute")
        evidence.details["files"] = dict(disk.get("files") or {})
        evidence.details["tables"] = dict(disk.get("tables") or {})
        evidence.details["growth"] = [
            {"at": iso(p.get("at")), "total_bytes": p.get("total_bytes")} for p in (disk.get("growth") or [])[-60:]
        ]
        evidence.links.append(f"{SYSTEM_LINK}#disk")
        only_disk = free_low and len(reasons) == 1
        change, saving = (None, 0) if only_disk else self._retention_change(ctx, disk)
        if only_disk:
            advice = (
                f" Roxy itself uses {used / GB:.1f} GB ({used * 100.0 / budget:.0f}% of its budget), so the space is "
                "taken by other files on the volume: lowering Roxy's retention would free little."
                if budget
                else " Free space outside Roxy's databases."
            )
        else:
            advice = (
                " Lowering retention shrinks the largest tables; raising storage_total_budget_gb only moves the "
                "warning while the disk has room."
            )
        if change is None:
            changes = [
                ProposedChange(
                    "manual",
                    text=(
                        "Free space on the state volume (old log archives, backups and files outside Roxy), then run "
                        "VACUUM from System > Data if Roxy's own files shrank."
                    ),
                )
            ]
            impact = "The disk stays writable; Roxy's own data is untouched."
        else:
            changes = [change]
            impact = (
                f"About {saving / GB:.1f} GB less once retention has run and the next VACUUM returns the space "
                f"({change.key} from {change.current} to {change.proposed})."
            )
        return [
            self.recommendation(
                ctx,
                subject="storage",
                title="Disk space is running out" if free_low else "Roxy's storage is growing toward its budget",
                severity="critical" if free_low else "warn",
                confidence="high",
                explanation=sentence(reasons) + advice,
                evidence=evidence,
                changes=changes,
                expected_impact=impact,
                risk="medium",
            )
        ]

    def _retention_change(self, ctx: InsightContext, disk: Mapping[str, Any]) -> tuple[ProposedChange | None, int]:
        """Halve the retention of the largest table or folder with a retention setting; `(change, bytes saved)`."""
        tables = {str(k): int(v or 0) for k, v in (disk.get("tables") or {}).items()}
        sizes = dict(tables)
        for name, value in (disk.get("files") or {}).items():
            if name in RETENTION_OF or (not tables and name in FILE_RETENTION_OF):
                sizes[str(name)] = int(value.get("bytes") or 0)
        for name, size in sorted(sizes.items(), key=lambda kv: -kv[1]):
            key = RETENTION_OF.get(name) or FILE_RETENTION_OF.get(name)
            if key is None or size <= 0:
                continue
            spec = catalog.CATALOG[key]
            current = int(ctx.setting(key))
            proposed = max(int(spec.min or 1), math.floor(current * RETENTION_SHARE))
            if proposed >= current or not current or spec.is_high_risk_value(proposed):
                continue
            return setting_change(ctx, key, proposed), round(size * (1 - proposed / current))
        return None, 0


# ------------------------------------------------------------------------------------------------ workers


def sustained_workers(
    history: Mapping[str, Sequence[Mapping[str, Any]]], field: str, threshold: float, window: Window
) -> dict[str, list[float]]:
    """`{worker: values}` for workers whose `field` is above `threshold` in EVERY minute of the window."""
    minutes = set(range(minute_floor(window.start), window.end, 60))
    out: dict[str, list[float]] = {}
    for worker, rows in history.items():
        values = {int(r["bucket_start"]): r.get(field) for r in rows if int(r["bucket_start"]) in minutes}
        if set(values) != minutes or not minutes:
            continue
        numbers = [float(v) for v in values.values() if v is not None]
        if len(numbers) == len(minutes) and all(value > threshold for value in numbers):
            out[worker] = numbers
    return out


class _SustainedWorkerRule(Rule):
    """Shared shape of SYS-WORKER-SAT and SYS-LOOP-LAG (a per-minute worker figure over a threshold, sustained)."""

    field_name: str = ""
    threshold_param: str = ""
    unit: str = ""

    async def evaluate(self, ctx: InsightContext) -> list[Recommendation]:
        window = ctx.window(minutes=self.param(ctx, "window_min"))
        threshold = self.param(ctx, self.threshold_param)
        history = await ctx.worker_history(window)
        hot = sustained_workers(history, self.field_name, threshold, window)
        if not hot:
            return []
        minutes = round((window.end - window.start) / 60)
        evidence = Evidence(window_from=window.start, window_to=window.end, sample_size=sum(map(len, hot.values())))
        evidence.add("workers_over_threshold", len(hot), "workers")
        evidence.add("minutes", minutes, "minutes")
        evidence.add(f"highest_{self.field_name}", round(max(max(v) for v in hot.values()), 1), self.unit)
        evidence.add(f"lowest_{self.field_name}", round(min(min(v) for v in hot.values()), 1), self.unit)
        evidence.details["workers"] = {
            worker: {
                "min": min(values),
                "max": max(values),
                "open_conns_max": max((int(r.get("open_conns") or 0) for r in history.get(worker, [])), default=0),
                # The chart of the evidence: this figure for every minute of the window, oldest first.
                "series": [[int(r["bucket_start"]), r.get(self.field_name)] for r in history.get(worker, [])][
                    -MAX_SERIES_POINTS:
                ],
            }
            for worker, values in sorted(hot.items())
        }
        evidence.links.append(f"{SYSTEM_LINK}#fleet")
        return [self.build(ctx, evidence, sorted(hot), threshold, minutes)]

    def build(
        self, ctx: InsightContext, evidence: Evidence, workers: Sequence[str], threshold: float, minutes: int
    ) -> Recommendation:
        raise NotImplementedError


@register
class SysWorkerSat(_SustainedWorkerRule):
    """Worker processes are saturated.

    Fires when a worker's CPU use has been above `cpu_pct` percent in every minute of the last `window_min` minutes
    (from the per-minute worker history). Responses slow down when a worker is busy all the time. The change is
    manual: more workers (`ROXY_WORKERS`, which needs a restart and memory on a 1 GB server) or finding what is
    using the CPU. Open connections are shown as evidence; 11.5 names no connection limit to compare them with.
    """

    id = "SYS-WORKER-SAT"
    triggers = frozenset({"health_fail", "settings_change"})
    field_name = "cpu_pct"
    threshold_param = "cpu_pct"
    unit = "percent"

    def build(
        self, ctx: InsightContext, evidence: Evidence, workers: Sequence[str], threshold: float, minutes: int
    ) -> Recommendation:
        return self.recommendation(
            ctx,
            subject="workers:cpu",
            title=f"{len(workers)} worker(s) above {threshold:g}% CPU for {minutes} minutes",
            severity="warn",
            confidence="medium",
            explanation=(
                f"Worker(s) {', '.join(workers)} used more than {threshold:g}% CPU in every minute of the last "
                f"{minutes} minutes, so requests wait for a busy worker. Either add a worker (ROXY_WORKERS, a restart; "
                "check the memory budget first) or find what is using the CPU (Live, the slow-path log)."
            ),
            evidence=evidence,
            changes=[
                ProposedChange(
                    "manual", text="Raise ROXY_WORKERS (restart) if memory allows, or investigate the CPU use."
                )
            ],
            expected_impact=(
                f"Lower latency under load once the workers drop below {threshold:g}% CPU (now up to "
                f"{evidence.metric('highest_cpu_pct')}%)."
            ),
            risk="low",
        )


@register
class SysLoopLag(_SustainedWorkerRule):
    """The event loop is lagging: something is blocking a worker.

    Fires when a worker's p99 event loop lag has been above `p99_ms` in every minute of the last `window_min` minutes.
    Lag with moderate CPU means a call blocks the loop (file or database work on the loop, a large capture compressed
    inline) and every request on that worker waits. The change is manual: find the blocking code through the
    slow-path log; smaller capture bodies help when captures are on.
    """

    id = "SYS-LOOP-LAG"
    triggers = frozenset({"health_fail", "settings_change"})
    field_name = "loop_lag_ms_p99"
    threshold_param = "p99_ms"
    unit = "ms"

    def build(
        self, ctx: InsightContext, evidence: Evidence, workers: Sequence[str], threshold: float, minutes: int
    ) -> Recommendation:
        return self.recommendation(
            ctx,
            subject="workers:loop_lag",
            title=f"Event loop lag above {threshold:g} ms for {minutes} minutes on {len(workers)} worker(s)",
            severity="warn",
            confidence="medium",
            explanation=(
                f"Worker(s) {', '.join(workers)} had a p99 event loop lag above {threshold:g} ms in every minute of "
                f"the last {minutes} minutes: something blocks the loop and every request on that worker waits for it. "
                "Find the blocking call in the slow-path log (System); if captures are on, a smaller capture_max_body "
                f"(now {ctx.setting('capture_max_body')} bytes) makes their compression cheaper."
            ),
            evidence=evidence,
            changes=[ProposedChange("manual", text="Find the blocking code through the slow-path log (System).")],
            expected_impact=(
                "Requests on the affected worker stop waiting up to "
                f"{evidence.metric('highest_loop_lag_ms_p99')} ms (p99) for the loop once the blocking call is gone."
            ),
            risk="low",
        )


# ------------------------------------------------------------------------------------------------ SYS-METRICS-DROP


@register
class SysMetricsDrop(Rule):
    """The metrics queue is dropping items.

    Fires on any dropped metrics item (the batch writer drops the oldest low-priority items when a worker's queue
    passes `metrics_queue_max`). Dashboards then miss numbers. The change doubles `metrics_queue_max` while that stays
    out of its high-risk range (more memory per worker), else halves `metrics_flush_interval_ms` so the queue drains
    sooner.
    """

    id = "SYS-METRICS-DROP"
    triggers = frozenset({"settings_change"})

    async def evaluate(self, ctx: InsightContext) -> list[Recommendation]:
        pipeline = await ctx.providers.metrics_pipeline()
        dropped = int((pipeline or {}).get("dropped") or 0)
        if dropped <= 0:
            return []
        scope = str((pipeline or {}).get("scope") or "fleet")
        span = "since this worker started" if scope == "worker" else "in the last hour"
        current = int(ctx.setting("metrics_queue_max"))
        proposed = int(highest_safe("metrics_queue_max", current * QUEUE_GROWTH))
        if proposed > current:
            change = setting_change(ctx, "metrics_queue_max", proposed)
            what = f"raises metrics_queue_max from {current:,} to {proposed:,} items"
        else:
            interval = int(ctx.setting("metrics_flush_interval_ms"))
            spec = catalog.CATALOG["metrics_flush_interval_ms"]
            faster = max(int(spec.min or 1), math.floor(interval * FLUSH_SHARE))
            if faster >= interval:
                return []
            change = setting_change(ctx, "metrics_flush_interval_ms", faster)
            what = f"halves metrics_flush_interval_ms from {interval} ms to {faster} ms"
        evidence = Evidence(window_from=ctx.now - 3600, window_to=ctx.now, sample_size=dropped)
        evidence.add("dropped_items", dropped, "items")
        evidence.details["scope"] = scope
        evidence.links.append(f"{SYSTEM_LINK}#metrics-pipeline")
        return [
            self.recommendation(
                ctx,
                subject="metrics_queue",
                title=f"The metrics queue dropped {dropped:,} items",
                severity="warn",
                confidence="high",
                explanation=(
                    f"The metrics batch writer dropped {dropped:,} items {span} because its queue was full, so some "
                    f"charts and tables miss data. The change {what}."
                ),
                evidence=evidence,
                changes=[change],
                expected_impact=f"No more dropped metrics in bursts like the last one ({dropped:,} items lost).",
                risk="low",
            )
        ]


# ------------------------------------------------------------------------------------------------ SYS-CHANGE-REGRESSION


def regression_rates(totals: Mapping[str, Any]) -> dict[str, float | None]:
    """The three guard rates SYS-CHANGE-REGRESSION compares (lower is better)."""
    requests = int(totals.get("requests") or 0)
    calls = int(totals.get("upstream_calls") or 0)
    roblox_429 = totals.get("roblox_429")
    p95 = totals.get("p95_ms")
    return {
        "error_rate": int(totals.get("errors") or 0) / requests if requests else None,
        "roblox_429_rate": int(roblox_429 or 0) / calls if calls and roblox_429 is not None else None,
        "p95_ms": float(p95) if p95 is not None and requests else None,
    }


def worse_by(before: Mapping[str, float | None], after: Mapping[str, float | None]) -> dict[str, float]:
    """`{metric: percent worse}` for every rate with a non-zero baseline and a value since."""
    out: dict[str, float] = {}
    for name, base in before.items():
        value = after.get(name)
        if base is None or value is None or base <= 0:
            continue
        out[name] = (value - base) * 100.0 / base
    return out


@register
class SysChangeRegression(Rule):
    """Errors, Roblox 429s or latency got worse right after a settings or rule change.

    For each change made in the last `watch_min` minutes (by an admin, the CLI or a recommendation, not by Roxy's own
    automatic actions), compares the time since the change with the `baseline_h` hours before it: caller errors per
    request, Roblox 429s per upstream call and p95 latency. When any of them is more than `worse_pct` percent worse,
    the change is to revert exactly that change (one click). A rate that was zero before is not compared.
    """

    id = "SYS-CHANGE-REGRESSION"
    triggers = frozenset({"settings_change", "roblox_429_burst"})

    async def evaluate(self, ctx: InsightContext) -> list[Recommendation]:
        watch_s = self.param(ctx, "watch_min") * 60
        baseline_s = self.param(ctx, "baseline_h") * 3600
        worse_pct = self.param(ctx, "worse_pct")
        end = ctx.window(seconds=60).end
        latest: dict[str, dict[str, Any]] = {}
        for change in await ctx.recent_changes(ctx.now - watch_s):
            if str(change.get("by") or "").startswith("system"):
                continue  # Roxy's own automatic actions (detector bans, adaptive limits) are not config changes
            latest[str(change["target"])] = change  # oldest first: the newest change of each target wins
        out: list[Recommendation] = []
        for change in latest.values():
            start = minute_floor(float(change["at"]))
            after_start = start if float(change["at"]) == start else start + 60
            if after_start >= end:
                continue  # not one whole minute since the change yet
            before = Window(int(start - baseline_s), start, "minute", "UTC")
            after = Window(after_start, end, "minute", "UTC")
            rates_before = regression_rates(await ctx.totals(before))
            rates_after = regression_rates(await ctx.totals(after))
            worse = {k: v for k, v in worse_by(rates_before, rates_after).items() if v > worse_pct}
            if not worse:
                continue
            revert = self._revert(ctx, change)
            if revert is None:
                continue
            out.append(self._recommend(ctx, change, revert, before, after, rates_before, rates_after, worse))
        return out

    def _revert(self, ctx: InsightContext, change: Mapping[str, Any]) -> ProposedChange | None:
        """The change that undoes `change`, or None when it was superseded or cannot be expressed."""
        if change["kind"] == "setting":
            key = str(change["key"])
            if key not in catalog.CATALOG or catalog.CATALOG[key].sensitive:
                return None
            current = ctx.setting(key)
            if catalog.validate_value(key, change["after"]) != current:
                return None  # changed again since: the newer change is the one to judge
            return ProposedChange(
                "setting", key=key, current=current, proposed=catalog.validate_value(key, change["before"])
            )
        table = str(change["target"]).split(":", 1)[0]
        spec = RULE_TABLES.get(table)
        if spec is None:
            return None
        action = str(change.get("action") or "")
        before, after = change.get("before"), change.get("after")
        if action == "rule.create" and isinstance(after, Mapping):
            return ProposedChange("rule_delete", table=table, match={spec.pk: after.get(spec.pk)}, current=dict(after))
        if action == "rule.delete" and isinstance(before, Mapping):
            return ProposedChange("rule_upsert", table=table, current=None, proposed=row_to_input(spec, before))
        if action == "rule.update" and isinstance(before, Mapping) and isinstance(after, Mapping):
            restore = {k: v for k, v in row_to_input(spec, before).items() if k != spec.pk}
            return ProposedChange(
                "rule_upsert", table=table, match={spec.pk: after.get(spec.pk)}, current=dict(after), proposed=restore
            )
        return None

    def _recommend(
        self,
        ctx: InsightContext,
        change: Mapping[str, Any],
        revert: ProposedChange,
        before: Window,
        after: Window,
        rates_before: Mapping[str, float | None],
        rates_after: Mapping[str, float | None],
        worse: Mapping[str, float],
    ) -> Recommendation:
        target = str(change["target"])
        name = str(change["key"]) if change["kind"] == "setting" else target
        what = (
            f"{change['key']} from {change['before']!r} to {change['after']!r}"
            if change["kind"] == "setting"
            else f"{change.get('action')} on {target}"
        )
        evidence = Evidence(window_from=before.start, window_to=after.end, sample_size=1)
        for name, value in rates_before.items():
            if value is not None:
                evidence.add(f"{name}_before", round(value, 6))
        for name, value in rates_after.items():
            if value is not None:
                evidence.add(f"{name}_after", round(value, 6))
        for name, pct in worse.items():
            evidence.add(f"{name}_worse_pct", round(pct, 1), "percent")
        evidence.details["change"] = {k: change.get(k) for k in ("kind", "target", "before", "after", "by", "reason")}
        evidence.details["changed_at"] = iso(change["at"])
        evidence.links.append("/admin/audit")
        labels = {
            "error_rate": "caller errors per request",
            "roblox_429_rate": "Roblox 429s per call",
            "p95_ms": "p95 latency",
        }
        summary = ", ".join(f"{labels[name]} {pct:+.0f}%" for name, pct in sorted(worse.items()))
        minutes = round((after.end - after.start) / 60)
        hours = (before.end - before.start) / 3600
        return self.recommendation(
            ctx,
            subject=f"{target} at {iso(change['at'])}",
            title=f"Things got worse after the change to {name}: revert it",
            severity="warn",
            confidence="medium",
            explanation=(
                f"At {iso(change['at'])} {change.get('by') or 'someone'} changed {what}. In the {minutes} minutes "
                f"since, compared with the {hours:g} hours before: {summary}. The change reverts exactly that change."
            ),
            evidence=evidence,
            changes=[revert],
            expected_impact=f"Back to the baseline before the change ({summary} undone).",
            risk="low",
        )


# ------------------------------------------------------------------------------------------------ SYS-HEALTH-FAIL


@register
class SysHealthFail(Rule):
    """A health check is failing.

    Fires once per check that failed in the latest Check Proxy Health run (a warning is not a failure, and older runs
    do not count). The change is the check's own fix: follow its fix link (always a manual step).
    """

    id = "SYS-HEALTH-FAIL"
    triggers = frozenset({"health_fail"})

    async def evaluate(self, ctx: InsightContext) -> list[Recommendation]:
        run = await ctx.health_latest()
        if not run:
            return []
        out: list[Recommendation] = []
        for result in run.get("results") or []:
            if str(result.get("status")) != "fail":
                continue
            check = str(result.get("check_id"))
            evidence = Evidence(window_from=float(run["started_at"]), window_to=ctx.now, sample_size=1)
            evidence.add("value", result.get("value"))
            evidence.add("threshold", result.get("threshold"))
            evidence.details.update(
                {"run_id": run.get("id"), "trigger": run.get("trigger"), "started_at": iso(run["started_at"])}
            )
            link = str(result.get("fix_link") or HEALTH_LINK)
            evidence.links += [link, HEALTH_LINK]
            out.append(
                self.recommendation(
                    ctx,
                    subject=check,
                    title=f"Health check {check} is failing: {result.get('value')}",
                    severity="critical",
                    confidence="high",
                    explanation=(
                        f"The latest health run ({run.get('trigger')}, {iso(run['started_at'])}) failed {check} with "
                        f"{result.get('value')} (threshold: {result.get('threshold')}). "
                        f"{str(result.get('explanation') or '').strip()} The fix link shows what to do."
                    ).strip(),
                    evidence=evidence,
                    changes=[ProposedChange("manual", text=f"Follow the fix for {check}: {link}")],
                    expected_impact=f"{check} passes on the next run.",
                    risk="low",
                )
            )
        return out


__all__ = [
    "SysChangeRegression",
    "SysDisk",
    "SysHealthFail",
    "SysLoopLag",
    "SysMetricsDrop",
    "SysWorkerSat",
    "projected_bytes",
    "regression_rates",
    "storage_bytes",
    "sustained_workers",
    "worse_by",
]
