"""The proof rules of the framework: UP-429-ENDPOINT, CACHE-TTL-TUNE and SYS-ERRORS (plan 11.5, 11.6).

What this is
    Three complete rules, one per family the engine must handle (upstream pacing with a multi-change
    recommendation, cache tuning from samples and observations, and a manual-only system rule), written exactly as
    the guide in `rules/base.py` says, so authors of the other families can copy their shape.

Why it exists
    UP-429-ENDPOINT is the plan's headline example: the 11.6 card (412 x 429 on POST users.roblox.com/v1/users)
    must come out of fixture data unchanged. CACHE-TTL-TUNE exercises the 11.3 TTL tuner. SYS-ERRORS turns Roxy's
    own bugs into a manual recommendation with the redacted traceback the LLM export needs.

How it works
    - Every threshold is read with `self.param(ctx, ...)`. The few fixed numbers below are not 11.5 thresholds but
      constants the plan names elsewhere (the 80% bucket headroom of 11.5's change column, the hour and the 7-day
      baseline written into the SYS-ERRORS row); each has a docstring.
    - UP-429-ENDPOINT fires per template when its Roblox 429s in the window reach `min_429s`, or exceed
      `share_pct` percent of its upstream calls. The changes are scoped to that endpoint where possible: a cache
      rule with the tuner's TTL and stale-while-revalidate (POST methods for a batch lookup, plus
      `cache_post_requests` off -> allowlist when POST caching is off, the 11.6 plan conflict recorded in the
      fixture), `fallback_on_429` 1 -> 0 when Roxy retried this endpoint's 429s on the rotator, and an endpoint
      bucket override at 80% of the highest rate the endpoint sustained without a 429 (never a global default).
    - CACHE-TTL-TUNE reads `change_observations` over `window_h` hours: at least `min_refetches` refetches with at
      least `identical_raise_pct` percent identical bodies raises the endpoint's TTL to the tuner's median change
      interval (capped by `ttl_tuner_max_s`, the cap itself when bodies never changed); under
      `identical_lower_pct` percent lowers it to the lifetime at which, if bodies change at random (a Poisson
      process), the identical share would reach `identical_lower_pct` (at the default 50% this is the median
      change interval the plan names).
    - SYS-ERRORS fires per error signature first seen in the last hour, per known signature whose last hour exceeds
      `baseline_multiple` times its hourly mean over the previous 7 days, and once for Roxy's own caller-facing 500s
      (`internal_error`) above `caller_500_pct` percent of requests over `window_min` minutes.

What to read next
    `roxy/insights/rules/base.py` (the guide), `tests/fixtures/insights/up_429_endpoint__before_after_11_6.yaml`,
    `roxy/insights/simulate.py` (the tuner and the replay).
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from typing import Any, Final
from urllib.parse import quote

from roxy.config.constants import MAX_CACHE_RULE_STALE_TTL_S, MAX_CACHE_RULE_TTL_S
from roxy.core.redact import redact_text
from roxy.insights import simulate
from roxy.insights.context import InsightContext, minute_floor
from roxy.insights.models import Evidence, ProposedChange, Recommendation
from roxy.insights.rules.base import Rule, register
from roxy.metrics.templating import OTHER

BUCKET_HEADROOM: Final = 0.8
"""Plan 11.5 UP-429-ENDPOINT: the endpoint bucket goes to 80% of the highest 429-free sustained rate."""
SUSTAIN_MINUTES: Final = 5
"""How many consecutive 429-free minutes a rate must hold to count as "sustained" (plan 7.3 bounded probing uses
whole minutes; five keeps one quiet minute from passing for a sustainable rate)."""
SWR_SHARE_OF_TTL: Final = 0.2
"""Stale-while-revalidate proposed with a new TTL: a fifth of it (11.6 pairs TTL 600 s with SWR 120 s), never less
than the live `cache_swr_seconds`."""
HOUR_S: Final = 3600
"""SYS-ERRORS: "first seen in the last hour" and "hourly count" (fixed by the 11.5 row, not a threshold)."""
BASELINE_DAYS: Final = 7
"""SYS-ERRORS: the baseline is the signature's hourly mean over the previous 7 days (11.5 row)."""
TRACEBACK_FRAMES: Final = 5
"""SYS-ERRORS evidence: the last 5 frames of the redacted traceback (11.5 row)."""
ERRORS_LINK: Final = "/admin/system#errors"


# ------------------------------------------------------------------------------------------- shared helpers


def highest_sustained_rate(calls: Mapping[int, int], refused_minutes: set[int], start: int, end: int) -> float | None:
    """The highest per-minute call count held for `SUSTAIN_MINUTES` consecutive minutes without a Roblox 429.

    `calls` maps minute starts to upstream calls; minutes in `refused_minutes` had at least one 429 and break a run.
    The rate of a run is its lowest minute (a rate is sustained only if every minute reached it). None when no run
    of 429-free minutes is long enough.
    """
    minutes = list(range(minute_floor(start), end, 60))
    best: float | None = None
    for index in range(len(minutes) - SUSTAIN_MINUTES + 1):
        run = minutes[index : index + SUSTAIN_MINUTES]
        if any(minute in refused_minutes for minute in run):
            continue
        floor = min(calls.get(minute, 0) for minute in run)
        if floor and (best is None or floor > best):
            best = float(floor)
    return best


def rule_columns(row: Any) -> dict[str, Any]:
    """A cache rule row as the plain columns a change's `current` shows (methods as stored text)."""
    data = row.model_dump() if hasattr(row, "model_dump") else dict(row)
    methods = data.get("methods")
    if isinstance(methods, list | tuple):
        data["methods"] = ",".join(str(m) for m in methods)
    flags = data.get("normalize_flags")
    if isinstance(flags, tuple):
        data["normalize_flags"] = list(flags)
    return data


def own_cache_rule(ctx: InsightContext, template: str) -> tuple[Any, Any]:
    """`(rule covering the template now, the rule whose pattern names exactly this template or None)`.

    The own rule is the covering one when that names the template (`simulate.names_template`: the exact regex
    a recommendation writes, or the legacy v1 glob), else any row that names it, the exact regex first
    (`simulate.own_template_row`; finding insights-8).
    """
    covering = ctx.rules.cache_rule_for(template)
    if covering is not None and simulate.names_template(covering.pattern, covering.type, template):
        return covering, covering
    return covering, simulate.own_template_row(ctx.rules.cache_rules, template)


def effective_ttl(ctx: InsightContext, covering: Any) -> int:
    """The lifetime the cache gives the template today: its rule's TTL, else `cache_ttl_seconds`."""
    return int(covering.ttl) if covering is not None else int(ctx.setting("cache_ttl_seconds"))


def per_hour_text(count: float, window_s: float) -> str:
    return f"{round(count * HOUR_S / window_s):,}" if window_s else "0"


# -------------------------------------------------------------------------------------------- UP-429-ENDPOINT


@register
class Up429Endpoint(Rule):
    """Roblox is rate-limiting (429) one endpoint far more than others.

    Fires for each endpoint template with at least `min_429s` Roblox 429 responses in the look-back window, or
    whose 429s exceed `share_pct` percent of its upstream calls. The recommendation is scoped to that endpoint: a
    longer cache lifetime from the TTL tuner with stale-while-revalidate (and POST caching for a batch lookup), an
    endpoint bucket at 80% of the highest rate it sustained without a 429, and turning `fallback_on_429` off when
    Roxy retried that endpoint's 429s on the rotator. A global default is never changed.
    """

    id = "UP-429-ENDPOINT"
    safe_auto = True
    triggers = frozenset({"roblox_429_burst", "breaker_open", "settings_change"})

    async def evaluate(self, ctx: InsightContext) -> list[Recommendation]:
        window = ctx.window(minutes=self.param(ctx, "window_min"))
        counts = await ctx.roblox_429(window)
        total = sum(counts.values())
        if not total:
            return []
        rows = await ctx.by_template(window)
        min_429s = self.param(ctx, "min_429s")
        share_pct = self.param(ctx, "share_pct")
        out: list[Recommendation] = []
        for (template,), n in sorted(counts.items(), key=lambda kv: -kv[1]):
            if template == OTHER or template.startswith("("):
                continue  # no single endpoint to scope a change to
            row = rows.get(template, {})
            calls = max(int(row.get("upstream_calls") or 0), n)
            share = n * 100.0 / calls
            if n >= min_429s or share > share_pct:
                out.append(await self._recommend(ctx, window, template, n, total, share, row))
        return out

    async def _recommend(
        self, ctx: InsightContext, window: Any, template: str, n: int, total: int, share: float, row: Mapping[str, Any]
    ) -> Recommendation:
        methods = await ctx.by(window, "method", {"endpoint_template": template})
        method = max(methods, key=lambda m: methods[m].get("requests") or 0) if methods else "GET"
        by_egress = await ctx.roblox_429(window, group_by=("egress",), where={"endpoint_template": template})
        egress = max(by_egress, key=lambda k: by_egress[k])[0] if by_egress else "direct"
        demand = int(row.get("demand") or 0)
        hit_ratio = round(int(row.get("served_cache") or 0) / demand, 4) if demand else 0.0
        evidence = Evidence(window_from=window.start, window_to=window.end, sample_size=n)
        evidence.add("roblox_429", n, "responses")
        evidence.add("share_of_all_roblox_429", round(n / total, 4))
        evidence.add("share_of_upstream_calls_pct", round(share, 2), "percent")
        evidence.add("upstream_calls", int(row.get("upstream_calls") or 0), "calls")
        evidence.add("requests", int(row.get("requests") or 0), "requests")
        evidence.add("cache_hit_ratio", hit_ratio)
        evidence.add("caller_failures", int(row.get("failed") or 0), "requests")
        evidence.details["roblox_429_by_egress"] = {k[0]: v for k, v in by_egress.items()}
        evidence.details["method"] = method
        rows_429 = await ctx.upstream_429_rows(window, template)
        retry = [float(r["retry_after_s"]) for r in rows_429 if r.get("retry_after_s") is not None]
        if retry:
            evidence.add("retry_after_avg_s", round(sum(retry) / len(retry), 1), "seconds")
        evidence.links.append(f"/admin/upstream?endpoint={quote(template, safe='')}")

        changes: list[ProposedChange] = []
        cache_change = await self._cache_change(ctx, template, method, evidence)
        if cache_change is not None:
            changes.append(cache_change)
        if method == "POST" and str(ctx.setting("cache_post_requests")) == "off":
            # 11.6 plan conflict (fixture header): with `off` a POST cache rule has no effect, so POST caching moves
            # to `allowlist` (rules that list POST), never to `all`.
            changes.append(ProposedChange("setting", key="cache_post_requests", current="off", proposed="allowlist"))
        retried = await self._rotator_retries(ctx, window, template)
        if retried:
            evidence.add("roblox_429_retried_on_rotator", retried, "calls")
            evidence.add("retried_share_of_429", round(retried / n, 4))
            if int(ctx.setting("fallback_on_429")):
                changes.append(ProposedChange("setting", key="fallback_on_429", current=1, proposed=0))
        bucket_change = await self._bucket_change(ctx, window, template, evidence)
        if bucket_change is not None:
            changes.append(bucket_change)

        severity = "critical" if int(row.get("failed") or 0) else "warn"
        confidence = "high" if n >= self.param(ctx, "high_confidence_n") else "medium"
        rec = self.recommendation(
            ctx,
            subject=template,
            title=f"Roblox is rate-limiting {template} ({method}) on the {egress} path",
            severity=severity,
            confidence=confidence,
            explanation=(
                f"In the last {round((window.end - window.start) / 60)} minutes Roblox returned {n:,} rate-limit "
                f"responses (429) for {method} {template}, {round(100 * n / total)}% of all 429s and "
                f"{share:.1f}% of this endpoint's upstream calls. Its cache hit ratio is {hit_ratio:.0%}. The changes "
                "below are scoped to this endpoint: fewer calls reach Roblox (a longer cache lifetime with "
                "stale-while-revalidate) and the calls that remain are paced below the rate that drew 429s."
            ),
            evidence=evidence,
            changes=changes,
            risk="low",
        )
        report = await simulate.dry_run(ctx, rec, window_s=window.end - window.start)
        if report.avoided_calls is not None:
            rec.expected_impact = (
                f"About {per_hour_text(report.avoided_calls, report.window_s)} fewer upstream calls per hour on this "
                f"endpoint (simulated over {report.sample_size:,} request samples of the last "
                f"{round(report.window_s / 60)} minutes), and fewer 429s with them."
            )
        else:
            rec.expected_impact = "Fewer Roblox 429s on this endpoint; the bucket keeps its calls below the 429 rate."
        return rec

    async def _cache_change(
        self, ctx: InsightContext, template: str, method: str, evidence: Evidence
    ) -> ProposedChange | None:
        covering, own = own_cache_rule(ctx, template)
        current_ttl = effective_ttl(ctx, covering)
        if covering is not None and covering.ttl == 0:
            return None  # the admin chose "never cache this endpoint"
        evidence.add("current_ttl_s", current_ttl, "seconds")
        ttl = current_ttl
        if int(ctx.setting("ttl_tuner_enabled")):
            hours = float(ctx.setting("request_sample_hours"))
            samples = await ctx.samples(ctx.window(hours=hours), [template])
            estimate = simulate.estimate_change_interval(samples)
            tuned = simulate.proposed_ttl(estimate, cap_s=float(ctx.setting("ttl_tuner_max_s")))
            evidence.details["ttl_tuner"] = estimate.to_dict()
            if tuned is not None:
                ttl = max(ttl, min(tuned, MAX_CACHE_RULE_TTL_S))
        observed = await ctx.change_observations(ctx.now - 86_400, ctx.now)
        refetches, identical = observed.get(template, (0, 0))
        if refetches:
            evidence.add("median_body_unchanged_on_refetch", round(identical / refetches, 4))
        base = own if own is not None else None
        current_swr = int(base.stale_ttl) if base is not None else 0
        swr = current_swr or min(
            MAX_CACHE_RULE_STALE_TTL_S, max(int(ctx.setting("cache_swr_seconds")), round(ttl * SWR_SHARE_OF_TTL))
        )
        methods = list(base.methods) if base is not None else ["GET"]
        if method in ("GET", "POST") and method not in methods:
            methods.append(method)
        proposed: dict[str, Any] = {"ttl": int(ttl), "stale_ttl": int(swr), "methods": ",".join(methods)}
        if base is not None:
            current = rule_columns(base)
            if all(current.get(k) == v for k, v in proposed.items()):
                return None
            proposed = {k: v for k, v in proposed.items() if current.get(k) != v}
            match = {"pattern": base.pattern, "type": base.type}  # the own row, as stored
        else:
            current = None
            # A new rule for exactly this template (the anchored regex, never the v1 glob that also covers
            # every path below it; finding insights-8).
            match = simulate.template_match(template)
            proposed = {**match, **proposed, "origin": "recommendation"}
        return ProposedChange(
            "rule_upsert",
            table="rules_cache",
            match=dict(match),
            current=current,
            proposed=proposed,
        )

    async def _rotator_retries(self, ctx: InsightContext, window: Any, template: str) -> int:
        """Calls Roxy spent retrying this endpoint's 429s on the rotator (`fallback_on_429`)."""
        egress_rows = await ctx.by(window, "egress", {"endpoint_template": template})
        rotator = egress_rows.get("rotator") or {}
        from_rollups = max(0, int(rotator.get("upstream_calls") or 0) - int(rotator.get("requests") or 0))
        attempts = await ctx.attempts(window, template)
        from_attempts = sum(int(a["count"]) for a in attempts if a["kind"] == "fallback_429")
        return max(from_rollups, from_attempts)

    async def _bucket_change(
        self, ctx: InsightContext, window: Any, template: str, evidence: Evidence
    ) -> ProposedChange | None:
        key = ctx.endpoint_bucket(template)
        current = ctx.bucket_limit(key)
        minutes = await ctx.per_minute(window, {"endpoint_template": template})
        calls = {minute: int(values.get("upstream_calls") or 0) for minute, values in minutes.items()}
        refused = await ctx.roblox_429(
            window, group_by=("endpoint_template",), per_minute=True, where={"endpoint_template": template}
        )
        refused_minutes = {int(minute) for (minute, _template) in refused}
        sustained = highest_sustained_rate(calls, refused_minutes, window.start, window.end)
        history = await ctx.bucket_summary(window, [key])
        if key in history:
            evidence.add("bucket_fill_peak_pct", history[key]["fill_pct_peak"], "percent")
        evidence.add("bucket_per_min", current["per_min"], "per minute")
        if sustained is None:
            return None
        evidence.add("highest_429_free_rate_per_min", sustained, "per minute")
        proposed = max(1, math.floor(sustained * BUCKET_HEADROOM))
        if proposed >= current["per_min"]:
            return None
        return ProposedChange(
            "bucket_override",
            bucket_key=key,
            current={"per_min": current["per_min"], "burst": current["burst"]},
            proposed={"per_min": proposed, "burst": current["burst"]},
        )


# --------------------------------------------------------------------------------------------- CACHE-TTL-TUNE


@register
class CacheTtlTune(Rule):
    """An endpoint's cache time can safely rise, or must fall.

    Reads the cache's refetch observations over `window_h` hours. When at least `min_refetches` refetches returned
    an identical body at least `identical_raise_pct` percent of the time, the endpoint's rule TTL rises to the
    median interval between body changes measured in the request samples (capped by `ttl_tuner_max_s`). When fewer
    than `identical_lower_pct` percent were identical, callers are being served outdated bodies and the TTL falls.
    Nothing is proposed while `ttl_tuner_enabled` is 0, and a rule with TTL 0 ("never cache") is left alone.
    """

    id = "CACHE-TTL-TUNE"
    safe_auto = True

    def minimum_evidence(self, ctx: InsightContext) -> int:
        return self.int_param(ctx, "min_refetches")

    async def evaluate(self, ctx: InsightContext) -> list[Recommendation]:
        if not int(ctx.setting("ttl_tuner_enabled")):
            return []
        hours = self.param(ctx, "window_h")
        observed = await ctx.change_observations(ctx.now - hours * 3600, ctx.now)
        raise_pct = self.param(ctx, "identical_raise_pct")
        lower_pct = self.param(ctx, "identical_lower_pct")
        minimum = self.param(ctx, "min_refetches")
        cap = float(ctx.setting("ttl_tuner_max_s"))
        out: list[Recommendation] = []
        for template, (refetches, identical) in sorted(observed.items()):
            if refetches < minimum or template == OTHER:
                continue
            share = identical * 100.0 / refetches
            if share >= raise_pct:
                rec = await self._raise(ctx, template, refetches, identical, share, cap, hours)
            elif share < lower_pct:
                rec = self._lower(ctx, template, refetches, identical, share, lower_pct, hours)
            else:
                rec = None
            if rec is not None:
                out.append(rec)
        return out

    def _evidence(self, ctx: InsightContext, refetches: int, identical: int, hours: float) -> Evidence:
        evidence = Evidence(window_from=ctx.now - hours * 3600, window_to=ctx.now, sample_size=refetches)
        evidence.add("refetches", refetches, "refetches")
        evidence.add("identical_bodies", identical, "refetches")
        evidence.add("identical_share", round(identical / refetches, 4))
        evidence.links.append("/admin/cache#settings")
        return evidence

    def _change(self, ctx: InsightContext, template: str, ttl: int) -> ProposedChange:
        covering, own = own_cache_rule(ctx, template)
        if own is not None:
            return ProposedChange(
                "rule_upsert",
                table="rules_cache",
                match={"pattern": own.pattern, "type": own.type},
                current=rule_columns(own),
                proposed={"ttl": ttl},
            )
        methods = ",".join(covering.methods) if covering is not None else "GET"
        match = simulate.template_match(template)  # exactly this template (finding insights-8)
        return ProposedChange(
            "rule_upsert",
            table="rules_cache",
            match=dict(match),
            current=None,
            proposed={**match, "ttl": ttl, "methods": methods, "origin": "recommendation"},
        )

    async def _raise(
        self, ctx: InsightContext, template: str, refetches: int, identical: int, share: float, cap: float, hours: float
    ) -> Recommendation | None:
        covering, _own = own_cache_rule(ctx, template)
        if covering is not None and covering.ttl == 0:
            return None
        current = effective_ttl(ctx, covering)
        sample_hours = min(hours, float(ctx.setting("request_sample_hours")))
        samples = await ctx.samples(ctx.window(hours=sample_hours), [template])
        estimate = simulate.estimate_change_interval(samples)
        tuned = simulate.proposed_ttl(estimate, cap_s=cap)
        if tuned is None:
            # No samples to measure: the observations alone, read as random (Poisson) body changes, give the
            # median change interval current_ttl * ln 2 / ln(1 / share); all identical means "at least the cap".
            fraction = identical / refetches
            tuned = int(cap) if identical >= refetches else round(current * math.log(2) / math.log(1 / fraction))
        ttl = int(min(tuned, cap, MAX_CACHE_RULE_TTL_S))
        if ttl <= current:
            return None
        evidence = self._evidence(ctx, refetches, identical, hours)
        evidence.add("current_ttl_s", current, "seconds")
        evidence.add("proposed_ttl_s", ttl, "seconds")
        if estimate.change_interval_s is not None:
            evidence.add("median_change_interval_s", round(estimate.change_interval_s, 1), "seconds")
        evidence.details["ttl_tuner"] = estimate.to_dict()
        never = (
            " Bodies never changed in the samples, so the proposal is the tuner cap." if estimate.never_changed else ""
        )
        return self.recommendation(
            ctx,
            subject=template,
            title=f"Cache {template} longer: {current} s to {ttl} s",
            severity="info",
            confidence="high",
            explanation=(
                f"{share:.1f}% of {refetches:,} refetches of {template} in the last {hours:g} hours returned the "
                f"same body, so the cache throws away good answers after {current} s.{never} A lifetime of {ttl} s "
                "matches how often the body really changes."
            ),
            evidence=evidence,
            changes=[self._change(ctx, template, ttl)],
            expected_impact=f"Fewer refetches of {template}: most answers are reused instead of fetched again.",
            risk="low",
        )

    def _lower(
        self,
        ctx: InsightContext,
        template: str,
        refetches: int,
        identical: int,
        share: float,
        lower_pct: float,
        hours: float,
    ) -> Recommendation | None:
        covering, _own = own_cache_rule(ctx, template)
        if covering is not None and covering.ttl == 0:
            return None
        current = effective_ttl(ctx, covering)
        fraction = identical / refetches
        # If bodies change at random, a refetch after `current` s is identical with probability exp(-current / tau);
        # the lifetime at which that probability reaches the lower threshold is current * ln(1/q) / ln(1/p).
        target = lower_pct / 100.0
        ttl = round(current * math.log(1 / target) / math.log(1 / fraction)) if fraction else 1
        ttl = max(1, min(int(ttl), current - 1))
        if ttl >= current:
            return None
        evidence = self._evidence(ctx, refetches, identical, hours)
        evidence.add("current_ttl_s", current, "seconds")
        evidence.add("proposed_ttl_s", ttl, "seconds")
        return self.recommendation(
            ctx,
            subject=template,
            title=f"Cache {template} for less time: {current} s to {ttl} s",
            severity="warn",
            confidence="high",
            explanation=(
                f"Only {share:.1f}% of {refetches:,} refetches of {template} in the last {hours:g} hours returned the "
                f"same body: callers are served outdated answers for most of the {current} s lifetime. At {ttl} s "
                f"about {lower_pct:g}% of refetches would still find the same body."
            ),
            evidence=evidence,
            changes=[self._change(ctx, template, ttl)],
            expected_impact="Fresher answers for callers, at the cost of more upstream calls on this endpoint.",
            risk="low",
            safe_auto=False,  # lowering a TTL adds upstream calls: an admin decides
        )


# ------------------------------------------------------------------------------------------------- SYS-ERRORS


def traceback_excerpt(text: str | None, frames: int = TRACEBACK_FRAMES) -> str:
    """The last `frames` frames of a redacted traceback plus its final line (the exception)."""
    lines = (text or "").rstrip().splitlines()
    starts = [i for i, line in enumerate(lines) if line.lstrip().startswith("File ")]
    if len(starts) > frames:
        lines = lines[starts[-frames] :]
    return "\n".join(lines)[-4000:]


@register
class SysErrors(Rule):
    """Roxy's own server errors.

    Fires for an error signature first seen in the last hour, for a known signature whose count in the last hour
    exceeds `baseline_multiple` times its hourly mean over the previous 7 days, and when Roxy's own caller-facing
    500s (`internal_error`, not Roblox's 5xx relayed to the caller) exceed `caller_500_pct` percent of requests over
    `window_min` minutes. The change is manual: a code fix in the module named by the traceback (the LLM export
    carries the full redacted traceback).
    """

    id = "SYS-ERRORS"
    safe_auto = False

    async def evaluate(self, ctx: InsightContext) -> list[Recommendation]:
        out: list[Recommendation] = []
        hour_start = ctx.now - HOUR_S
        baseline_start = ctx.now - BASELINE_DAYS * 86_400
        recent = await ctx.error_counts(hour_start, ctx.now)
        earlier = await ctx.error_counts(baseline_start, hour_start)
        multiple = self.param(ctx, "baseline_multiple")
        for row in await ctx.error_signatures():
            signature = str(row["signature"])
            count = int(recent.get(signature, 0))
            first_seen = float(row["first_seen"])
            if first_seen >= hour_start:
                out.append(self._signature(ctx, row, count, None, "new"))
                continue
            span_start = max(baseline_start, first_seen - first_seen % HOUR_S)
            hours = (hour_start - span_start) / HOUR_S
            if hours <= 0:
                continue
            baseline = earlier.get(signature, 0) / hours
            if count and count > multiple * baseline:
                out.append(self._signature(ctx, row, count, baseline, "spike"))
        caller = await self._caller_500s(ctx, recent)
        if caller is not None:
            out.append(caller)
        return out

    def _signature(
        self, ctx: InsightContext, row: Mapping[str, Any], count: int, baseline: float | None, why: str
    ) -> Recommendation:
        signature = str(row["signature"])
        where = str(row.get("module_line") or "")
        subject = signature if not where or where in signature else f"{signature} ({where})"
        evidence = Evidence(window_from=ctx.now - HOUR_S, window_to=ctx.now, sample_size=max(1, count))
        evidence.add("occurrences_last_hour", count, "errors")
        evidence.add("total_count", int(row.get("count") or 0), "errors")
        if baseline is not None:
            evidence.add("baseline_per_hour", round(baseline, 2), "errors")
            evidence.add("ratio_to_baseline", round(count / baseline, 2) if baseline else None)
        evidence.details.update(
            {
                "signature": signature,
                "module_line": where,
                "first_seen": int(row["first_seen"]),
                "last_seen": int(row["last_seen"]),
                # Redacted when recorded; redacted again here because recommendations reach the LLM export (12.3).
                "last_detail": redact_text(str(row.get("last_detail") or ""))[:500],
                "traceback_excerpt": redact_text(traceback_excerpt(row.get("traceback_redacted"))),
            }
        )
        evidence.links.append(ERRORS_LINK)
        if why == "new":
            title = f"New error in Roxy: {signature}"
            detail = f"first seen {round((ctx.now - float(row['first_seen'])) / 60)} minutes ago"
        elif baseline:
            title = f"Error spiking in Roxy: {signature}"
            detail = f"{count} times in the last hour, about {count / baseline:.1f} times its usual hourly count"
        else:
            title = f"Error spiking in Roxy: {signature}"
            detail = f"{count} times in the last hour after a quiet week"
        return self.recommendation(
            ctx,
            subject=subject,
            title=title,
            severity="warn",
            confidence="high",
            explanation=(
                f"Roxy's own code raised {signature} ({detail}). This is a bug in Roxy, not a Roblox problem; the "
                f"traceback points at {where or 'the frame shown'}. The LLM export includes the full redacted "
                "traceback and asks for a code fix in that module."
            ),
            evidence=evidence,
            changes=[ProposedChange("manual", text=f"Fix the code at {where or signature} (see the traceback).")],
            expected_impact="The error stops; callers and background jobs that hit it work again.",
            risk="low",
        )

    async def _caller_500s(self, ctx: InsightContext, recent: Mapping[str, int]) -> Recommendation | None:
        window = ctx.window(minutes=self.param(ctx, "window_min"))
        totals = await ctx.totals(window)
        requests = int(totals.get("requests") or 0)
        if not requests:
            return None
        own = await ctx.totals(window, {"reason_code": "internal_error"})
        failures = int(own.get("requests") or 0)
        share = failures * 100.0 / requests
        if not failures or share <= self.param(ctx, "caller_500_pct"):
            return None
        evidence = Evidence(window_from=window.start, window_to=window.end, sample_size=requests)
        evidence.add("caller_500s", failures, "requests")
        evidence.add("requests", requests, "requests")
        evidence.add("caller_500_pct", round(share, 3), "percent")
        top = sorted(recent.items(), key=lambda kv: -kv[1])[:5]
        evidence.details["top_signatures_last_hour"] = [{"signature": s, "count": n} for s, n in top]
        evidence.links.append(ERRORS_LINK)
        minutes = round((window.end - window.start) / 60)
        return self.recommendation(
            ctx,
            subject="caller_500s",
            title=f"Roxy answered {share:.2f}% of requests with its own 500 error",
            severity="critical",
            confidence="high",
            explanation=(
                f"In the last {minutes} minutes Roxy itself failed {failures:,} of {requests:,} caller requests "
                "with 500 Internal Server Error (Roblox errors relayed to callers are not counted). The signatures "
                "below show where; the fix is a code change."
            ),
            evidence=evidence,
            changes=[ProposedChange("manual", text="Fix the code behind the top error signatures (System > Errors).")],
            expected_impact="Callers stop receiving Roxy's own 500 errors.",
            risk="low",
        )


__all__ = [
    "BASELINE_DAYS",
    "BUCKET_HEADROOM",
    "HOUR_S",
    "SUSTAIN_MINUTES",
    "SWR_SHARE_OF_TTL",
    "CacheTtlTune",
    "SysErrors",
    "Up429Endpoint",
    "highest_sustained_rate",
    "traceback_excerpt",
]
