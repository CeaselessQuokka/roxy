"""The egress and host rules of plan 11.5: EGR-BURN, EGR-UNDERUSE, EGR-POOL-BURNED, EGR-CALIBRATE and HOST-ADD.

What this is
    Four rules about the paid rotating proxy (plan 8: its monthly quota, where it helps, when its exit addresses are
    burned, whether Roxy's byte meter agrees with the provider's bill) and one about which Roblox hosts Roxy may
    reach (a host many callers ask for that is missing from `allowed_roblox_hosts`), written on the engine framework
    (`rules/base.py`).

Why it exists
    Plan 8.6 asks for exactly these recommendations, each with its numbers: a quota projection that will run out,
    endpoints the rotator handles better than the server's own address, a rotator pool Roblox already limits, and a
    meter that drifted from the bill. HOST-ADD (plan 9.10, 11.5) lets legitimate callers reach a new Roblox host
    without ever opening the allowlist to probing: a host must be asked for by many callers and resolve publicly.

How it works
    - Thresholds come from `self.param(ctx, ...)` only (plan 11.1); the module constants are fixed choices the plan
      leaves open, each documented.
    - The cycle numbers come from the same arithmetic as the Egress page (`egress/read_state.py billing_cycle` and
      `project_cycle`, through `insights/providers_rules_cache_egress.py rotator_budget`), so a recommendation and
      the budget panel never disagree.
    - No egress rule ever moves or touches the credential (plan C1, C2): the rotator only carries anonymous calls,
      and the changes here are the rotator's weight, session mode and daily cap, per-endpoint routing rules (never
      `rotator_only` and never a global weight raise), and the metering constant. The quota itself is never
      changed (plan 11.4).
    - Every global setting change is `safe_auto = False`; `host_add` is one click and never automatic.

What to read next
    `roxy/egress/read_state.py` (the projection), `roxy/egress/rotator.py` (quota, hard stop, daily cap),
    `tests/fixtures/insights/egr_*.yaml` and `host_add__*.yaml`.
"""

from __future__ import annotations

import math
import re
from collections.abc import Mapping
from typing import Any, Final

from roxy.config import catalog
from roxy.core.redact import redact_text
from roxy.egress.read_state import billing_cycle
from roxy.egress.rotator import DECIMAL_GB
from roxy.insights import providers_rules_cache_egress as extra
from roxy.insights import simulate
from roxy.insights.context import InsightContext
from roxy.insights.models import Evidence, ProposedChange, Recommendation
from roxy.insights.rules.base import Rule, register
from roxy.insights.rules.cache import MAX_EVIDENCE_ROWS, named_template

EGRESS_LINK: Final = "/admin/egress#budget"
ROTATOR_LINK: Final = "/admin/egress#rotator"
ROTATOR: Final = "rotator"
DIRECT: Final = "direct"
DECIMAL_MB: Final = 1_000_000
TOO_MANY_REQUESTS: Final = 429
"""The HTTP status of Roblox's rate-limit answer (a protocol value, not a threshold)."""

TOP_ENDPOINT_HOURS: Final = 24
"""EGR-BURN: the endpoints named in the evidence are the top rotator byte users of the last day."""
UNDERUSE_WINDOW_MIN: Final = 60
"""EGR-UNDERUSE: the 429 rates are measured over the last hour (11.5 gives the row no window; the UP-429-ENDPOINT
window)."""
WEIGHT_CUT: Final = 0.5
"""EGR-POOL-BURNED: "lower weight" halves `rotator_weight` (the largest step auto-apply would allow, 11.4)."""
STICKY_MODE: Final = "sticky_until_429"
PREFERRED_MODE: Final = "prefer_rotator"
ROTATOR_MODES: Final = frozenset({"prefer_rotator", "rotator_only"})
HOST_REASON: Final = "host_not_allowed"
MAX_DNS_LOOKUPS: Final = 10
"""HOST-ADD: most hosts resolved per run (only hosts that already pass the caller tests are looked up; P9)."""
_HOST_NAME: Final = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*roblox\.com")
"""A plain DNS name under roblox.com (labels of letters, digits and inner hyphens)."""


def _gb(size: float) -> str:
    return f"{size / DECIMAL_GB:,.2f} GB"


def _setting_bounds(key: str) -> tuple[float, float]:
    spec = catalog.CATALOG[key]
    low = float(spec.min) if spec.min is not None else -math.inf
    high = float(spec.max) if spec.max is not None else math.inf
    return low, high


# ------------------------------------------------------------------------------------------------------ EGR-BURN


@register
class EgrBurn(Rule):
    """The rotating proxy is on course to use up this cycle's quota.

    Projects the billing cycle's rotator use the way the Egress page does (plan 8.4: the trailing 7 days blended
    with this cycle's own rate) and fires when the projection exceeds `projected_pct` percent of
    `rotator_quota_gb_per_month` (nothing is projected while no quota is set). The change brings the projection
    back to that line: a lower `rotator_weight` in proportion while the rotator takes a weighted share of traffic,
    otherwise a `rotator_daily_cap_mb` that spreads what is left over the days left. The endpoints that use the
    most rotator bytes are named, so their cache lifetimes can be raised. The quota itself is never changed.
    """

    id = "EGR-BURN"
    safe_auto = False

    async def evaluate(self, ctx: InsightContext) -> list[Recommendation]:
        budget = await extra.rotator_budget(ctx)
        projection = budget.projection
        quota = budget.quota_bytes
        if quota <= 0 or projection.projected_bytes is None:
            return []
        projected = int(projection.projected_bytes)
        pct = projected * 100.0 / quota
        line = self.param(ctx, "projected_pct")
        if pct <= line:
            return []
        target = quota * line / 100.0
        left_rate = projected - budget.used_bytes  # bytes the rest of the cycle would add at the current rate
        room = max(0.0, target - budget.used_bytes)
        weight = int(ctx.setting("rotator_weight"))
        changes: list[ProposedChange] = []
        remedy = ""
        if weight > 0 and left_rate > 0:
            factor = min(1.0, room / left_rate)
            new_weight = min(weight - 1, math.floor(weight * factor))
            changes.append(ProposedChange("setting", key="rotator_weight", current=weight, proposed=max(0, new_weight)))
            remedy = (
                f"Lowering rotator_weight from {weight} to {max(0, new_weight)} sends the rotator about "
                f"{1 - factor:.0%} less of its weighted share, which keeps the rest of the cycle near {_gb(target)}."
            )
        else:
            days_left = max(projection.days_left, 1 / 24)
            cap_mb = max(1, math.floor(room / days_left / DECIMAL_MB))
            current_cap = int(ctx.setting("rotator_daily_cap_mb"))
            if current_cap and current_cap <= cap_mb:
                return []  # the cap already holds the rest of the cycle under the line
            changes.append(ProposedChange("setting", key="rotator_daily_cap_mb", current=current_cap, proposed=cap_mb))
            remedy = (
                f"rotator_weight is {weight}, so the rotator only takes spillover and routed endpoints; a daily cap "
                f"of {cap_mb:,} MB spreads the {_gb(room)} left under the line over the {projection.days_left:.1f} "
                "days left."
            )
        top = await ctx.by(ctx.window(hours=TOP_ENDPOINT_HOURS), "endpoint_template", {"egress": ROTATOR})
        users = sorted(
            (
                (str(t), int(r.get("upstream_bytes_in") or 0) + int(r.get("upstream_bytes_out") or 0))
                for t, r in top.items()
                if named_template(str(t))
            ),
            key=lambda item: (-item[1], item[0]),
        )[:MAX_EVIDENCE_ROWS]
        evidence = Evidence(window_from=budget.cycle_start, window_to=ctx.now, sample_size=max(1, budget.requests))
        evidence.add("used_bytes", budget.used_bytes, "bytes")
        evidence.add("projected_bytes", projected, "bytes")
        evidence.add("quota_bytes", quota, "bytes")
        evidence.add("projected_pct_of_quota", round(pct, 2), "percent")
        evidence.add("days_left", projection.days_left, "days")
        if projection.rate_bytes_per_day is not None:
            evidence.add("rate_bytes_per_day", projection.rate_bytes_per_day, "bytes")
        evidence.details["projection"] = projection.as_dict()
        evidence.details["top_rotator_endpoints"] = [{"endpoint": t, "bytes": b} for t, b in users]
        evidence.links.append(EGRESS_LINK)
        named = ", ".join(t for t, _b in users[:3])
        price = float(ctx.setting("rotator_price_per_gb_usd"))
        cost = f", about {projected / DECIMAL_GB * price:,.2f} USD" if price > 0 else ""
        hard_stop = float(ctx.setting("rotator_hard_stop_pct"))
        return [
            self.recommendation(
                ctx,
                subject=f"rotator quota cycle {extra.utc_text(budget.cycle_start)[:10]}",
                title=f"The rotator is on course for {pct:.0f}% of its monthly quota",
                severity="critical" if hard_stop > 0 and pct >= hard_stop else "warn",
                confidence="high",
                explanation=(
                    f"At this rate the rotator will use {_gb(projected)} of its {_gb(quota)} quota this cycle "
                    f"({pct:.1f}%{cost}); {_gb(budget.used_bytes)} is used and {projection.days_left:.1f} days are "
                    f"left. {remedy}"
                    + (
                        f" The endpoints using the most rotator bytes are {named}: longer cache lifetimes there save "
                        "quota too."
                        if named
                        else ""
                    )
                ),
                evidence=evidence,
                changes=changes,
                expected_impact=(
                    f"The projection falls from {_gb(projected)} to about {_gb(max(target, budget.used_bytes))} "
                    f"({line:g}% of the quota), so the rotator stays in budget until the cycle ends."
                ),
                risk="low",
            )
        ]


# -------------------------------------------------------------------------------------------------- EGR-UNDERUSE


@register
class EgrUnderuse(Rule):
    """The rotating proxy could take load off specific endpoints.

    Over the last hour, fires for each endpoint whose direct-path calls get Roblox 429s above `direct_429_pct`
    percent while the rotator's own calls to that endpoint stay under `rotator_429_max_pct` percent, as long as the
    rotator is on, not tripped by the leak guard, and has used under `quota_used_max_pct` percent of a set quota.
    The change is a `prefer_rotator` routing rule for that endpoint only, never a global weight change. It moves
    load off the server's address for that endpoint; it does not lower Roblox's limit, so caching and pacing still
    matter.
    """

    id = "EGR-UNDERUSE"
    safe_auto = False  # routing more traffic through the rotator spends paid quota

    async def evaluate(self, ctx: InsightContext) -> list[Recommendation]:
        if not ctx.flag("rotator_enabled") or ROTATOR in await extra.leak_trips(ctx):
            return []
        budget = await extra.rotator_budget(ctx)
        used_pct = budget.used_pct
        if used_pct is None or used_pct >= self.param(ctx, "quota_used_max_pct"):
            return []  # no quota to measure against, or too much of it is used already
        window = ctx.window(minutes=UNDERUSE_WINDOW_MIN)
        direct = await ctx.by(window, "endpoint_template", {"egress": DIRECT})
        rotator = await ctx.by(window, "endpoint_template", {"egress": ROTATOR})
        counts = await ctx.roblox_429(window, group_by=("endpoint_template", "egress"))
        direct_line = self.param(ctx, "direct_429_pct")
        rotator_line = self.param(ctx, "rotator_429_max_pct")
        out: list[Recommendation] = []
        for template in sorted(direct, key=str):
            name = str(template)
            if not named_template(name):
                continue
            d_calls = int(direct[template].get("upstream_calls") or 0)
            r_calls = int((rotator.get(template) or {}).get("upstream_calls") or 0)
            if d_calls <= 0 or r_calls <= 0:
                continue  # no direct calls, or no rotator calls to show the rotator handles it
            d_429 = int(counts.get((name, DIRECT), 0))
            r_429 = int(counts.get((name, ROTATOR), 0))
            d_rate = d_429 * 100.0 / d_calls
            r_rate = r_429 * 100.0 / r_calls
            if d_rate <= direct_line or r_rate >= rotator_line:
                continue
            rec = self._recommend(ctx, window, name, d_calls, d_429, d_rate, r_calls, r_429, r_rate, budget, rotator)
            if rec is not None:
                out.append(rec)
        return out

    def _recommend(
        self,
        ctx: InsightContext,
        window: Any,
        template: str,
        d_calls: int,
        d_429: int,
        d_rate: float,
        r_calls: int,
        r_429: int,
        r_rate: float,
        budget: extra.RotatorBudget,
        rotator: Mapping[Any, Mapping[str, Any]],
    ) -> Recommendation | None:
        covering = ctx.rules.routing_rule_for(template)
        if covering is not None and covering.enabled and covering.mode in ROTATOR_MODES:
            return None  # already routed to the rotator
        own = simulate.own_template_row(ctx.rules.routing_rules, template)
        if own is not None:
            current: dict[str, Any] | None = own.model_dump()
            match = {"pattern": own.pattern, "type": own.type}
            proposed: dict[str, Any] = {"mode": PREFERRED_MODE, "enabled": True}
        else:
            current = None
            # Plan 11.5 "for the named templates only": exactly this template (finding insights-8).
            match = simulate.template_match(template)
            proposed = {
                **match,
                "mode": PREFERRED_MODE,
                "note": "EGR-UNDERUSE: Roblox limits the direct path here, the rotator is healthy.",
            }
        row = rotator.get(template) or {}
        size = int(row.get("upstream_bytes_in") or 0) + int(row.get("upstream_bytes_out") or 0)
        per_call = size / r_calls if r_calls else 0.0
        extra_bytes = per_call * d_calls
        evidence = Evidence(window_from=window.start, window_to=window.end, sample_size=d_calls)
        evidence.add("direct_calls", d_calls, "calls")
        evidence.add("direct_roblox_429", d_429, "responses")
        evidence.add("direct_429_pct", round(d_rate, 2), "percent")
        evidence.add("rotator_calls", r_calls, "calls")
        evidence.add("rotator_roblox_429", r_429, "responses")
        evidence.add("rotator_429_pct", round(r_rate, 2), "percent")
        evidence.add("quota_used_pct", budget.used_pct, "percent")
        evidence.details["routing_rule"] = current
        evidence.links.append(ROTATOR_LINK)
        minutes = round((window.end - window.start) / 60)
        return self.recommendation(
            ctx,
            subject=template,
            title=f"Prefer the rotator for {template}: {d_rate:.1f}% direct 429s, {r_rate:.1f}% on the rotator",
            severity="warn",
            confidence="medium",
            explanation=(
                f"In the last {minutes} minutes Roblox answered {d_429:,} of {d_calls:,} direct calls to {template} "
                f"with 429 ({d_rate:.1f}%), while the rotator's {r_calls:,} calls to it saw {r_rate:.1f}%. The rotator "
                f"has used {budget.used_pct:.1f}% of its quota this cycle. A prefer_rotator routing rule for this "
                "endpoint only moves its calls off the server's own address; it does not raise Roblox's limit."
            ),
            evidence=evidence,
            changes=[
                ProposedChange("routing_rule", table="rules_routing", match=match, current=current, proposed=proposed)
            ],
            expected_impact=(
                f"About {d_calls:,} calls per {minutes} minutes leave the direct path, where {d_rate:.1f}% drew 429s, "
                f"for a path that saw {r_rate:.1f}%; at {per_call:,.0f} bytes per call that spends about "
                f"{extra_bytes / DECIMAL_MB:,.1f} MB of rotator quota per {minutes} minutes."
            ),
            risk="low",
        )


# ----------------------------------------------------------------------------------------------- EGR-POOL-BURNED


@register
class EgrPoolBurned(Rule):
    """Roblox already rate-limits the rotating proxy's exit addresses.

    Fires when more than `rotator_429_pct` percent of the rotator's calls over the last `window_min` minutes were
    answered 429. When sticky sessions are available (a `rotator_session_username_template` is set) and the
    session mode is not `sticky_until_429`, the change is that mode, which keeps healthy exits and drops burned
    ones. Otherwise (the mode would change nothing) it halves `rotator_weight`. Per exit 429 rates are shown when
    the attempt trace records exits.
    """

    id = "EGR-POOL-BURNED"
    safe_auto = False

    async def evaluate(self, ctx: InsightContext) -> list[Recommendation]:
        window = ctx.window(minutes=self.param(ctx, "window_min"))
        by_egress = await ctx.by(window, "egress")
        row = by_egress.get(ROTATOR) or {}
        calls = int(row.get("upstream_calls") or 0)
        if calls <= 0:
            return []
        refused = int((await ctx.roblox_429(window, group_by=("egress",))).get((ROTATOR,), 0))
        rate = refused * 100.0 / calls
        if rate <= self.param(ctx, "rotator_429_pct"):
            return []
        mode = str(ctx.setting("rotator_session_mode"))
        template_set = bool(str(ctx.setting("rotator_session_username_template") or "").strip())
        weight = int(ctx.setting("rotator_weight"))
        if template_set and mode != STICKY_MODE:
            changes = [ProposedChange("setting", key="rotator_session_mode", current=mode, proposed=STICKY_MODE)]
            remedy = (
                f"rotator_session_mode is {mode}, so Roxy keeps using exits Roblox has already limited; "
                f"{STICKY_MODE} keeps a healthy exit and moves on as soon as Roblox answers it with 429."
            )
        elif weight > 0:
            new_weight = max(0, min(weight - 1, math.floor(weight * WEIGHT_CUT)))
            changes = [ProposedChange("setting", key="rotator_weight", current=weight, proposed=new_weight)]
            reason = (
                "sticky sessions need rotator_session_username_template, which is not set"
                if not template_set
                else f"the session mode is already {STICKY_MODE}"
            )
            remedy = (
                f"Changing the session mode would not help ({reason}), so lowering rotator_weight from {weight} to "
                f"{new_weight} sends less traffic to a pool Roblox is limiting."
            )
        else:
            changes = [
                ProposedChange(
                    "manual",
                    text=(
                        "Reduce rotator use: review the prefer_rotator routing rules, or ask the provider for new "
                        "exits."
                    ),
                )
            ]
            remedy = "rotator_weight is already 0, so the remaining rotator calls come from routing rules or spillover."
        exits = self._exits(await ctx.attempts(window))
        size = int(row.get("upstream_bytes_in") or 0) + int(row.get("upstream_bytes_out") or 0)
        wasted = size * refused / calls
        evidence = Evidence(window_from=window.start, window_to=window.end, sample_size=calls)
        evidence.add("rotator_calls", calls, "calls")
        evidence.add("rotator_roblox_429", refused, "responses")
        evidence.add("rotator_429_pct", round(rate, 2), "percent")
        evidence.add("wasted_bytes_estimate", round(wasted), "bytes")
        evidence.details["per_exit"] = exits
        evidence.details["session_mode"] = mode
        evidence.details["session_template_set"] = template_set
        evidence.links.append(ROTATOR_LINK)
        minutes = round((window.end - window.start) / 60)
        return [
            self.recommendation(
                ctx,
                subject="rotator pool",
                title=f"Roblox answered {rate:.0f}% of rotator calls with 429",
                severity="warn",
                confidence="medium",
                explanation=(
                    f"In the last {minutes} minutes {refused:,} of {calls:,} rotator calls ({rate:.1f}%) were "
                    f"answered 429: the provider's exit addresses are already limited by Roblox. {remedy}"
                ),
                evidence=evidence,
                changes=changes,
                expected_impact=(
                    f"Fewer of the rotator's calls are refused; the 429 answers of the last {minutes} minutes cost "
                    f"about {wasted / DECIMAL_MB:,.1f} MB of quota for nothing."
                ),
                risk="low",
            )
        ]

    @staticmethod
    def _exits(attempts: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Per exit calls, 429s and their share, worst first (from the attempt trace; empty when exits are not
        recorded)."""
        per: dict[str, list[int]] = {}
        for item in attempts:
            exit_id = str(item.get("exit_id") or "")
            if item.get("egress") != ROTATOR or not exit_id:
                continue
            slot = per.setdefault(exit_id, [0, 0])
            slot[0] += int(item.get("count") or 0)
            if item.get("status") == TOO_MANY_REQUESTS:
                slot[1] += int(item.get("count") or 0)
        ranked = sorted(per.items(), key=lambda item: (-(item[1][1] / item[1][0] if item[1][0] else 0.0), item[0]))
        return [
            {"exit": exit_id, "calls": c, "roblox_429": n, "pct": round(n * 100.0 / c, 1) if c else None}
            for exit_id, (c, n) in ranked[: MAX_EVIDENCE_ROWS * 2]
        ]


# ------------------------------------------------------------------------------------------------ EGR-CALIBRATE


@register
class EgrCalibrate(Rule):
    """Roxy's rotator byte count differs from the provider's bill.

    Compares the newest provider figure the admin entered (it covers the current billing cycle up to the moment it
    was read) with Roxy's metered rotator bytes over the same span, and fires when they differ by more than
    `diff_pct` percent of the provider's figure. With the fallback estimate metering (each new connection counted
    as `rotator_tls_overhead_bytes`), the change is the overhead constant that closes the gap. With exact socket
    metering the constant is not used, so the change is a manual check for traffic outside Roxy or a provider
    billing rule (plan 8.6). The quota is never changed.
    """

    id = "EGR-CALIBRATE"
    safe_auto = False

    async def evaluate(self, ctx: InsightContext) -> list[Recommendation]:
        report = await ctx.provider_report()
        if not report or int(report.get("reported_bytes") or 0) <= 0:
            return []
        reported = int(report["reported_bytes"])
        at = int(report["at"])
        start, _end = billing_cycle(ctx.now, int(ctx.setting("rotator_billing_day")))
        if at < start:
            return []  # a figure from an earlier cycle says nothing about this one
        split = await extra.egress_split(ctx, ROTATOR, start, at)
        metered = int(split["total_bytes"])
        gap = reported - metered
        diff_pct = abs(gap) * 100.0 / reported
        if diff_pct <= self.param(ctx, "diff_pct"):
            return []
        metering = await ctx.providers.egress_metering()
        overhead = int(split["overhead_bytes"])
        # Estimate mode writes the per-connection overhead into `overhead_bytes`; socket mode always writes 0
        # (`egress/accounting.py`), so the rows themselves say which mode counted them.
        estimate = str(metering.get("metering_mode")) == "estimate" or overhead > 0
        key = "rotator_tls_overhead_bytes"
        current = int(ctx.setting(key))
        changes: list[ProposedChange] = []
        connections = overhead / current if estimate and current > 0 else 0.0
        if connections > 0:
            low, high = _setting_bounds(key)
            proposed = int(min(high, max(low, round(current + gap / connections))))
            if proposed != current:
                changes.append(ProposedChange("setting", key=key, current=current, proposed=proposed))
        evidence = Evidence(window_from=start, window_to=at, sample_size=max(1, int(split["requests"])))
        evidence.add("provider_bytes", reported, "bytes")
        evidence.add("metered_bytes", metered, "bytes")
        evidence.add("difference_bytes", gap, "bytes")
        evidence.add("difference_pct_of_provider", round(diff_pct, 2), "percent")
        evidence.add("overhead_bytes", overhead, "bytes")
        evidence.details["metering_mode"] = "estimate" if estimate else "socket"
        evidence.details["provider_reported_at"] = extra.utc_text(at)
        evidence.links.append(EGRESS_LINK)
        lead = (
            f"The provider's figure for this cycle up to {extra.utc_text(at)} is {_gb(reported)}; Roxy metered "
            f"{_gb(metered)} over the same span, {abs(gap) / DECIMAL_GB:,.2f} GB "
            f"{'less' if gap > 0 else 'more'} ({diff_pct:.1f}% of the provider's figure). "
        )
        if changes:
            proposed = int(changes[0].proposed)
            evidence.add("connections_estimate", round(connections), "connections")
            explanation = lead + (
                f"Metering runs in estimate mode, which counts each of the about {round(connections):,} new "
                f"connections as {current:,} bytes of TLS overhead. {proposed:,} bytes per connection closes the gap."
            )
            impact = (
                f"Roxy's rotator count matches the provider's within rounding, so the quota projection and the "
                f"budget alerts use the real figure ({_gb(reported)} instead of {_gb(metered)})."
            )
        else:
            changes = [
                ProposedChange(
                    "manual",
                    text=(
                        "Look for rotator traffic outside Roxy (exit IP checks, other tools) or a provider billing "
                        "rule."
                    ),
                )
            ]
            explanation = lead + (
                "Metering counts the bytes on the wire exactly (socket mode), so rotator_tls_overhead_bytes is not "
                "used and changing it would do nothing. A gap usually means traffic through the same proxy account "
                "from outside Roxy, or a billing rule of the provider (minimum charges, rounding per request)."
            )
            impact = "The cause of the gap is found, so the quota projection can be trusted again."
        return [
            self.recommendation(
                ctx,
                subject=f"rotator metering cycle {extra.utc_text(start)[:10]}",
                title=f"Roxy's rotator byte count is {diff_pct:.0f}% off the provider's figure",
                severity="info",
                confidence="high",
                explanation=explanation,
                evidence=evidence,
                changes=changes,
                expected_impact=impact,
                risk="low",
            )
        ]


# ----------------------------------------------------------------------------------------------------- HOST-ADD


@register
class HostAdd(Rule):
    """A real Roblox host is missing from the host allowlist.

    Fires for a host under roblox.com that is not in `allowed_roblox_hosts` when, over the last `window_h` hours,
    its refused requests came from at least `min_places` distinct experiences or at least `min_ips` distinct client
    addresses, and it resolves to public addresses only. The change adds that one host (one click, never
    automatic). Hosts outside roblox.com, hosts that do not resolve, and hosts with any private or loopback
    answer are never proposed: that is what host probing looks like (plan 9.10). The allowlist itself is never
    switched off.
    """

    id = "HOST-ADD"
    safe_auto = False

    async def evaluate(self, ctx: InsightContext) -> list[Recommendation]:
        if not ctx.flag("strict_host_allowlist"):
            return []  # without the strict allowlist no roblox.com host is refused for being unlisted
        window = ctx.window(hours=self.param(ctx, "window_h"))
        allowed = [str(h) for h in (ctx.setting("allowed_roblox_hosts") or [])]
        listed = {h.lower() for h in allowed}
        refused = await ctx.by(window, "host", {"reason_code": HOST_REASON})
        callers = await extra.host_callers(ctx, window)
        min_places = self.param(ctx, "min_places")
        min_ips = self.param(ctx, "min_ips")
        candidates: list[tuple[str, dict[str, Any], int]] = []
        for host in sorted(set(callers) | {str(h) for h in refused}):
            name = host.lower()
            if name in listed or not _HOST_NAME.fullmatch(name):
                continue
            seen = callers.get(host) or {"ips": 0, "places": 0, "refusals": 0, "paths": []}
            if seen["places"] < min_places and seen["ips"] < min_ips:
                continue
            requests = int((refused.get(host) or {}).get("requests") or seen["refusals"])
            candidates.append((name, seen, requests))
        candidates.sort(key=lambda item: (-item[2], item[0]))
        out: list[Recommendation] = []
        for name, seen, requests in candidates[:MAX_DNS_LOOKUPS]:
            dns = await ctx.providers.dns(name)
            answers = [str(a) for a in (dns or {}).get("answers") or []]
            if not answers or (dns or {}).get("error"):
                continue  # does not resolve
            if any(ctx.providers.classify_address(a) != "public" for a in answers):
                continue  # a private, loopback or reserved answer: never an allowlist entry
            out.append(self._recommend(ctx, window, name, seen, requests, answers, allowed))
        return out

    def _recommend(
        self,
        ctx: InsightContext,
        window: Any,
        host: str,
        seen: Mapping[str, Any],
        requests: int,
        answers: list[str],
        allowed: list[str],
    ) -> Recommendation:
        hours = round((window.end - window.start) / 3600)
        evidence = Evidence(window_from=window.start, window_to=window.end, sample_size=max(1, requests))
        evidence.add("refused_requests", requests, "requests")
        evidence.add("distinct_ips", int(seen["ips"]), "addresses")
        evidence.add("distinct_places", int(seen["places"]), "places")
        evidence.details["sample_paths"] = [redact_text(str(p))[:200] for p in seen.get("paths") or []]
        evidence.details["dns_answers"] = answers[:MAX_EVIDENCE_ROWS]
        evidence.links.append("/admin/settings#allowed_roblox_hosts")
        return self.recommendation(
            ctx,
            subject=host,
            title=f"Allow the Roblox host {host}: {int(seen['ips']):,} callers asked for it",
            severity="warn",
            confidence="medium",
            explanation=(
                f"In the last {hours} hours Roxy refused {requests:,} requests for {host} because it is not in "
                f"allowed_roblox_hosts. They came from at least {int(seen['ips']):,} different addresses and "
                f"{int(seen['places']):,} experiences, and the name resolves to public addresses only, so it looks "
                "like a real Roblox service callers need. Adding it is one click and never automatic; check the "
                "sample paths first."
            ),
            evidence=evidence,
            changes=[
                ProposedChange("host_add", key="allowed_roblox_hosts", current=list(allowed), proposed=[*allowed, host])
            ],
            expected_impact=(
                f"About {round(requests * 24 / max(1, hours)):,} requests a day for {host} are served instead of "
                "refused with 404."
            ),
            risk="medium",
        )


__all__ = ["EgrBurn", "EgrCalibrate", "EgrPoolBurned", "EgrUnderuse", "HostAdd"]
