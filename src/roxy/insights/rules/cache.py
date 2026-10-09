"""The cache rules of plan 11.5: CACHE-LOW-HIT, CACHE-KEYSPLIT, CACHE-PRESSURE, CACHE-OFF, CACHE-NEG and HOT-ENDPOINT.

What this is
    Six recommendation rules about how well Roxy's cache keeps calls away from Roblox, written on the engine
    framework (`rules/base.py`): a busy endpoint that is rarely answered from the cache, a query parameter that
    splits the cache into single-use keys, a cache too small for its entries' lifetimes, the cache switched off, the
    same Roblox 404 fetched again and again, and a newly busy endpoint without a cache rule.

Why it exists
    Every request answered from the cache is a call Roblox never sees (plan P8). These rules turn the cache's own
    measurements (hit ratios, the v1 key spread diagnostic, eviction ages, request samples, the TTL tuner) into one
    concrete, scoped change each, with the numbers that justify it (plan P2, P6).

How it works
    - Every threshold is read with `self.param(ctx, ...)` (plan 11.1); the module constants below are not 11.5
      thresholds but fixed choices the plan leaves open, each documented where it is defined.
    - Changes are scoped to one endpoint where the plan allows: a cache rule for that endpoint (`rule_upsert` on
      `rules_cache`, an update of the endpoint's own rule when it has one), an ignored parameter, a normalization
      flag. Global settings (`cache_enabled`, `cache_max_bytes`, `cache_error_ttl_seconds`) are never `safe_auto`.
    - New cache lifetimes come from the TTL tuner (`insights/simulate.py estimate_change_interval` over request
      samples, capped by `ttl_tuner_max_s`) or, without a measurement, the standard new-rule lifetime
      (`config/constants.py DEFAULT_CACHE_RULE_TTL`, 300 s; the `ttl_tuner_enabled` catalog text).
    - The key spread is the v1 Suspect rule of `cache/spread.py compute_spread` over cache.db, read through
      `insights/providers_rules_cache_egress.py`. Ignoring a parameter is proposed only when it is shaped like a
      cache buster (a timestamp, a random number or token) and its name is not an id parameter; an id list that
      only differs in order gets a `sort_csv:<param>` normalization instead; anything else is reported as a manual
      check, because ignoring a meaningful parameter would serve one caller's answer to another.
    - Expected impact comes from the 11.3 dry run (`simulate.dry_run`) when request samples exist, otherwise from
      the evidence numbers.

What to read next
    `roxy/insights/rules/core.py` (the shared cache helpers this module reuses), `roxy/cache/spread.py`,
    `roxy/insights/simulate.py`, `tests/fixtures/insights/cache_*.yaml` and `hot_endpoint__*.yaml`.
"""

from __future__ import annotations

import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Final

from roxy.cache.keys import SORT_CSV_FLAG, sort_csv
from roxy.cache.policy import post_allowed
from roxy.cache.spread import SpreadGroup, SpreadRow, compute_spread
from roxy.cache.spread import thresholds as spread_thresholds
from roxy.config import catalog
from roxy.config.constants import DEFAULT_CACHE_RULE_TTL, MAX_CACHE_RULE_STALE_TTL_S, MAX_CACHE_RULE_TTL_S
from roxy.config.defaults import ID_LIST_PARAMS
from roxy.core.redact import redact_text
from roxy.insights import providers_rules_cache_egress as extra
from roxy.insights import simulate
from roxy.insights.context import InsightContext
from roxy.insights.models import Evidence, ProposedChange, Recommendation
from roxy.insights.rules.base import Rule, register
from roxy.insights.rules.core import HOUR_S, SWR_SHARE_OF_TTL, per_hour_text, rule_columns
from roxy.metrics.queries import Window
from roxy.metrics.templating import OTHER, template_for

CACHE_LINK: Final = "/admin/cache#settings"
SPREAD_LINK: Final = "/admin/cache#key-spread"
DAY_S: Final = 86_400
CACHEABLE_METHODS: Final = frozenset({"GET", "POST"})
"""Methods a cache rule may list (plan 15.3 D: GET, and POST for read-only lookups)."""

MAX_SPLIT_GROUPS: Final = 200
"""Most key spread groups examined per run, Suspect first (P9; `cache/spread.py compute_spread` sorts them)."""
SPREAD_ROWS: Final = 20_000
"""Newest cache.db entries the key spread reads per evaluation run (the Cache page reads up to 100,000 on demand;
the leader evaluates every `insights_interval_s`, so a run reads a bounded, recent slice: a cache buster makes many
new entries, which are the newest)."""
MAX_EVIDENCE_ROWS: Final = 5
"""Rows of per-key or per-endpoint detail shown in one recommendation's evidence."""
OFF_WINDOW_MIN: Final = 60
"""CACHE-OFF: "with traffic" is measured over the last hour (11.5 gives the row no window)."""
OFF_LOOKBACK_DAYS: Final = 30
"""CACHE-OFF: how far back the settings history is searched for when the cache was switched off (evidence only)."""
NEG_WINDOW_S: Final = HOUR_S
"""CACHE-NEG: the row counts refetches "per hour", so the window is the last hour."""
HOT_WINDOW_MIN: Final = 60
"""HOT-ENDPOINT: endpoints are ranked by their upstream calls over the last hour (the CACHE-LOW-HIT window)."""
SPAM_BUST_LOOKBACK_S: Final = HOUR_S
"""CACHE-KEYSPLIT: SPAM-BUST detections of the last hour count as the row's second trigger."""
SPAM_BUST_DETECTOR: Final = "SPAM-BUST"
SPAM_EVENT_TYPES: Final[tuple[str, ...]] = (
    "spam_detected",
    "spam_would_ban",
    "spam_ban",
    "spam_strike",
    "spam_tarpit",
    "spam_throttle",
)
"""Event types `abuse/spam.py` records for a detection (`spam_detected` for `recommend`, else `spam_<action>`)."""
CAP_GROWTH: Final = 2.0
"""CACHE-PRESSURE: the binding cap is doubled (11.5 names no size). The step is bounded and repeatable: the rule
fires again while early evictions stay above the threshold."""
DISK_SHARE_MAX: Final = 0.5
"""CACHE-PRESSURE: a larger `cache_max_bytes` may take at most half of the free disk ("disk is plentiful", but a
proposal must never fill it; plan 9.14 and SYS-DISK)."""
ERROR_TTL_GROWTH: Final = 2
"""CACHE-NEG: below the catalog default the error lifetime returns to the default, above it the lifetime doubles."""

_BUSTER_VALUE: Final = re.compile(
    r"[0-9]{4,20}(?:\.[0-9]{1,9})?|0?\.[0-9]{4,20}|(?=[0-9a-fA-F-]*[0-9])[0-9a-fA-F-]{8,64}"
)
"""Values a cache buster carries: a number of 4 or more digits (a timestamp, a random counter or `Math.random()`)
or a hex token or UUID. Short numbers are left out on purpose: page numbers and limits (`page=3`) select different
answers."""
_ID_NAME: Final = re.compile(r"(?i)(?:^|[a-z_])ids?$")
"""Parameter names that name ids (`id`, `userId`, `universeIds`): never ignored, they select different answers."""


# ------------------------------------------------------------------------------------------- shared helpers


def named_template(template: str) -> bool:
    """A real endpoint template (not the `other` bucket and not a `(problem)` bucket of refused targets)."""
    return bool(template) and template != OTHER and not template.startswith("(")


def dominant_method(methods: Mapping[Any, Mapping[str, Any]]) -> str:
    """The method with the most requests in a `ctx.by(..., "method", ...)` answer (GET when there is none)."""
    if not methods:
        return "GET"
    return str(max(sorted(methods), key=lambda m: int(methods[m].get("requests") or 0)))


def rule_for(ctx: InsightContext, template: str, method: str = "GET") -> tuple[Any, Any]:
    """`(the rule the cache applies to this template and method, the rule whose pattern names exactly this
    template or None)`. The second may be disabled; a second rule with the same pattern would be refused."""
    covering = ctx.cache_rule_for(template, method)
    pattern = simulate.template_pattern(template)
    own = next((row for row in ctx.rules.cache_rules if row.pattern == pattern and row.type == "glob"), None)
    return covering, own


def effective_ttl(ctx: InsightContext, covering: Any) -> int:
    """The lifetime the cache gives the template today: its rule's TTL, else `cache_ttl_seconds`."""
    return int(covering.ttl) if covering is not None else int(ctx.setting("cache_ttl_seconds"))


def swr_for(ctx: InsightContext, ttl: int) -> int:
    """Stale-while-revalidate proposed with a new lifetime (the UP-429-ENDPOINT choice, `core.SWR_SHARE_OF_TTL`)."""
    return int(
        min(MAX_CACHE_RULE_STALE_TTL_S, max(int(ctx.setting("cache_swr_seconds")), round(ttl * SWR_SHARE_OF_TTL)))
    )


async def tuned_ttl(ctx: InsightContext, template: str) -> tuple[int | None, simulate.ChangeEstimate]:
    """The TTL tuner's lifetime for one template (None without a measurement or while the tuner is off)."""
    if not int(ctx.setting("ttl_tuner_enabled")):
        return None, simulate.ChangeEstimate()
    samples = await ctx.samples(ctx.window(hours=float(ctx.setting("request_sample_hours"))), [template])
    estimate = simulate.estimate_change_interval(samples)
    tuned = simulate.proposed_ttl(estimate, cap_s=float(ctx.setting("ttl_tuner_max_s")))
    return (None if tuned is None else int(min(tuned, MAX_CACHE_RULE_TTL_S))), estimate


def rule_change(template: str, own: Any, columns: Mapping[str, Any]) -> ProposedChange | None:
    """A `rules_cache` change giving `template` the `columns`: an update of its own rule (only the columns that
    differ; None when nothing differs), else a new rule for exactly this template."""
    if own is None:
        return new_rule(template, columns)
    current = rule_columns(own)
    proposed = {k: v for k, v in columns.items() if current.get(k) != v}
    if not proposed:
        return None
    return ProposedChange(
        "rule_upsert",
        table="rules_cache",
        match={"pattern": own.pattern, "type": own.type},
        current=current,
        proposed=proposed,
    )


def new_rule(template: str, columns: Mapping[str, Any]) -> ProposedChange:
    """A new `rules_cache` row for exactly this template (`origin` recommendation)."""
    pattern = simulate.template_pattern(template)
    return ProposedChange(
        "rule_upsert",
        table="rules_cache",
        match={"pattern": pattern, "type": "glob"},
        current=None,
        proposed={"pattern": pattern, "type": "glob", **columns, "origin": "recommendation"},
    )


def setting_max(key: str) -> float:
    """The catalog maximum of a numeric setting."""
    spec = catalog.CATALOG[key]
    return float(spec.max) if spec.max is not None else math.inf


async def impact_from_dry_run(ctx: InsightContext, rec: Recommendation, window_s: int, scope: str) -> str | None:
    """`About N fewer upstream calls per hour ...` from the 11.3 dry run, or None when no samples cover it."""
    report = await simulate.dry_run(ctx, rec, window_s=window_s)
    if report.avoided_calls is None or not report.sample_size:
        return None
    note = f" {report.note}" if report.note else ""
    return (
        f"About {per_hour_text(report.avoided_calls, report.window_s)} fewer upstream calls per hour {scope} "
        f"(simulated over {report.sample_size:,} request samples of the last {round(report.window_s / 60)} "
        f"minutes).{note}"
    )


# ----------------------------------------------------------------------------------------- key spread helper


@dataclass(slots=True)
class SplitFinding:
    """One key spread group whose top parameter splits it, with the safest fix for it."""

    method: str
    template: str
    group: SpreadGroup
    param: str
    values: list[str]
    fix: str  # "ignore", "sort", "manual" or "known" (already ignored)
    collapsed_keys: int | None = None
    sorted_distinct: int | None = None
    rows: list[SpreadRow] = field(default_factory=list)

    @property
    def subject(self) -> str:
        return split_subject(self.method, self.template)

    @property
    def fixable(self) -> bool:
        return self.fix in ("ignore", "sort")


def split_subject(method: str, template: str) -> str:
    """The subject of a key split: the template, with the method when it is not GET."""
    return template if method == "GET" else f"{method} {template}"


def _group_key(row: SpreadRow) -> str:
    """The key `cache/spread.py compute_spread` groups by (`METHOD host/path`)."""
    method = row.method or "GET"
    return f"{method} {row.host}/{row.path}" if row.path else f"{method} {row.host}"


def is_id_name(name: str) -> bool:
    """A parameter that names ids (`id`, `placeId`, `universeIds`, the 15.5 id list parameters)."""
    return name in ID_LIST_PARAMS or bool(_ID_NAME.search(name))


def looks_like_buster(name: str, values: Sequence[str]) -> bool:
    """A cache buster: not an id parameter, and every value is a number or a hex token (module docstring)."""
    if not values or is_id_name(name):
        return False
    return all(_BUSTER_VALUE.fullmatch(value) for value in values)


def _param_values(rows: Sequence[SpreadRow], name: str) -> list[str]:
    return ["\0".join(v for n, v in row.params if n == name) for row in rows if any(n == name for n, _ in row.params)]


def _collapsed(rows: Sequence[SpreadRow], name: str, sort_values: bool) -> int:
    """How many distinct keys the rows leave when `name` is ignored (or, with `sort_values`, its id list sorted)."""
    keys: set[tuple[tuple[str, str], ...]] = set()
    for row in rows:
        pairs = []
        for n, v in row.params:
            if n == name:
                if not sort_values:
                    continue
                v = sort_csv(v)
            pairs.append((n, v))
        keys.add(tuple(sorted(pairs)))
    return len(keys)


async def split_findings(ctx: InsightContext, limits: Mapping[str, float]) -> list[SplitFinding]:
    """Every Suspect key spread group (v1 rule, `limits` from CACHE-KEYSPLIT's parameters) with its fix."""

    async def make() -> list[SplitFinding]:
        rows = await extra.spread(ctx, SPREAD_ROWS)
        if not rows:
            return []
        groups = compute_spread(
            rows,
            min_entries=limits["min_entries"],
            distinct_pct=limits["distinct_pct"],
            max_hit_pct=limits["max_hit_pct"],
            limit=MAX_SPLIT_GROUPS,
        )
        suspects = {group.key: group for group in groups if group.suspect and group.suspect_param}
        if not suspects:
            return []
        members: dict[str, list[SpreadRow]] = {}
        for row in rows:
            key = _group_key(row)
            if key in suspects:
                members.setdefault(key, []).append(row)
        ignored = frozenset(ctx.rules.cache_ignored_params)
        out: list[SplitFinding] = []
        for key, group in suspects.items():
            group_rows = members.get(key, [])
            param = group.suspect_param
            values = _param_values(group_rows, param)
            template = template_for(group.host, group.path)
            finding = SplitFinding(group.method, template, group, param, values, "manual", rows=group_rows)
            if param in ignored:
                finding.fix = "known"
            elif looks_like_buster(param, values):
                finding.fix = "ignore"
                finding.collapsed_keys = _collapsed(group_rows, param, sort_values=False)
            elif param in ID_LIST_PARAMS:
                sorted_distinct = len({sort_csv(value) for value in values})
                finding.sorted_distinct = sorted_distinct
                # Sorting fixes the split when the sorted lists would no longer pass the Suspect distinct test.
                if sorted_distinct * 100 < limits["distinct_pct"] * max(1, group.entries):
                    finding.fix = "sort"
                    finding.collapsed_keys = _collapsed(group_rows, param, sort_values=True)
            out.append(finding)
        out.sort(key=lambda f: (-f.group.entries, f.subject))
        return out

    frozen = tuple(sorted(limits.items()))
    return await ctx._cached(("rules_cache_egress", "split", frozen), make)


def split_change(ctx: InsightContext, finding: SplitFinding) -> ProposedChange:
    """The change for a fixable finding: an ignored parameter, or a sort normalization on the endpoint's rule."""
    if finding.fix == "ignore":
        return ProposedChange(
            "ignored_param_add",
            table="cache_ignored_params",
            match={"name": finding.param},
            current=None,
            proposed={
                "name": finding.param,
                "origin": "recommendation",
                "note": f"Cache buster on {finding.template} (CACHE-KEYSPLIT)."[:200],
            },
        )
    flag = f"{SORT_CSV_FLAG}{finding.param}"
    covering, own = rule_for(ctx, finding.template, finding.method)
    if own is not None:
        flags = [*own.normalize_flags]
        if flag not in flags:
            flags.append(flag)
        change = rule_change(finding.template, own, {"normalize_flags": flags})
        if change is not None:
            return change
    base = covering if covering is not None else None
    columns: dict[str, Any] = {
        "ttl": effective_ttl(ctx, base),
        "methods": ",".join(base.methods) if base is not None else finding.method,
        "normalize_flags": [*(base.normalize_flags if base is not None else ()), flag],
    }
    if base is not None and base.stale_ttl:
        columns["stale_ttl"] = int(base.stale_ttl)
    return new_rule(finding.template, columns)


def split_evidence(evidence: Evidence, finding: SplitFinding) -> None:
    """The 11.5 KEYSPLIT evidence: the parameter, its distinct ratio, and a few sample values (truncated)."""
    group = finding.group
    top = next((v for v in group.varying if v.name == finding.param), None)
    evidence.add("cache_entries", group.entries, "entries")
    evidence.add("entry_hits", group.hits, "hits")
    evidence.add("hit_pct_of_entries", round(group.hits * 100.0 / group.entries, 2) if group.entries else 0, "percent")
    if top is not None:
        evidence.add("distinct_values", top.values, "values")
        evidence.add("distinct_ratio", round(top.ratio, 4))
    if finding.collapsed_keys is not None:
        evidence.add("keys_after_fix", finding.collapsed_keys, "keys")
    evidence.details["split"] = {
        "group": group.key,
        "param": finding.param,
        "fix": finding.fix,
        # Caller text: redacted like a log line and cut (cache/spread.py already cut each to 40 characters).
        "sample_values": [redact_text(sample) for sample in (top.samples if top is not None else ())],
        "varying": [{"name": v.name, "values": v.values, "ratio": round(v.ratio, 3)} for v in group.varying],
    }
    evidence.links.append(SPREAD_LINK)


def split_explanation(finding: SplitFinding) -> str:
    group = finding.group
    entries, hits = extra.counted(group.entries, "cache entry"), extra.counted(group.hits, "hit")
    if finding.fix == "ignore":
        return (
            f"The parameter `{finding.param}` takes a different value on almost every request to {finding.template}: "
            f"its {entries} have {hits} between them, so each one is stored once and never used again. Its values "
            f"are numbers or tokens (a cache buster such as a timestamp), so leaving it out of the cache key merges "
            f"them into {extra.counted(finding.collapsed_keys or 0, 'key')}. Only apply this if `{finding.param}` "
            "never changes Roblox's answer."
        )
    if finding.fix == "sort":
        return (
            f"Callers list the same ids of `{finding.param}` in different orders, which splits {finding.template} into "
            f"{entries} with {hits}. Sorted, the lists collapse to "
            f"{extra.counted(finding.sorted_distinct or 0, 'distinct value')}. A `sort_csv:{finding.param}` "
            "normalization on this endpoint's cache rule makes each set of ids one key; check that Roblox's answer "
            "does not depend on the order before applying."
        )
    return (
        f"The parameter `{finding.param}` makes almost every cache entry of {finding.template} unique ({entries}, "
        f"{hits}), but its values do not look like a cache buster (it may name ids, search terms or pages), so Roxy "
        "does not propose ignoring it. If it is a cache buster, add it to the ignored parameters; if it carries real "
        "data, the keys are naturally unique and a cache cannot help."
    )


# ----------------------------------------------------------------------------------------------- CACHE-LOW-HIT


@register
class CacheLowHit(Rule):
    """A busy endpoint is rarely answered from the cache.

    Looks at the `top_n` endpoints with the most caller requests over the last `window_min` minutes and fires for
    each one whose share of requests answered from the cache is below `max_hit_ratio_pct` percent. The change
    names the cause it can see: a cache-busting parameter that splits the endpoint's keys (ignore it, or sort an
    id list; high confidence), a read-only POST lookup that is never cached (a cache rule for that endpoint that
    lists POST), or a lifetime shorter than the TTL tuner measured (raise that endpoint's rule). Without such
    evidence it asks for a manual look. Endpoints whose rule says "never cache" (TTL 0) are left alone, and no
    global cache setting is changed.
    """

    id = "CACHE-LOW-HIT"
    safe_auto = True
    triggers = frozenset({"settings_change"})

    async def evaluate(self, ctx: InsightContext) -> list[Recommendation]:
        window = ctx.window(minutes=self.param(ctx, "window_min"))
        rows = await ctx.by_template(window)
        ranked = sorted((t for t in rows if named_template(str(t))), key=lambda t: (-int(rows[t]["requests"] or 0), t))
        top = ranked[: self.int_param(ctx, "top_n")]
        limit_pct = self.param(ctx, "max_hit_ratio_pct")
        out: list[Recommendation] = []
        for rank, template in enumerate(top, start=1):
            row = rows[template]
            demand = int(row.get("demand") or 0)
            if demand <= 0:
                continue
            ratio = int(row.get("served_cache") or 0) / demand
            if ratio * 100 >= limit_pct:
                continue
            rec = await self._recommend(ctx, window, str(template), rank, row, ratio)
            if rec is not None:
                out.append(rec)
        return out

    async def _recommend(
        self, ctx: InsightContext, window: Window, template: str, rank: int, row: Mapping[str, Any], ratio: float
    ) -> Recommendation | None:
        methods = await ctx.by(window, "method", {"endpoint_template": template})
        method = dominant_method(methods)
        if method not in CACHEABLE_METHODS:
            return None  # writes are never cached: a low hit ratio is expected
        covering, own = rule_for(ctx, template, method)
        if covering is not None and int(covering.ttl) == 0:
            return None  # the admin chose "never cache this endpoint"
        if own is not None and not own.enabled:
            return None  # the admin switched this endpoint's own rule off
        private = ctx.rules.credential_rule_for(template, method)
        if private is not None and private.cache_private:
            return None  # answers fetched with the credential are never cached (plan 6.9)
        minutes = round((window.end - window.start) / 60)
        requests = int(row.get("requests") or 0)
        evidence = Evidence(window_from=window.start, window_to=window.end, sample_size=int(row.get("demand") or 0))
        evidence.add("cache_hit_ratio", round(ratio, 4))
        evidence.add("requests", requests, "requests")
        evidence.add("served_from_cache", int(row.get("served_cache") or 0), "requests")
        evidence.add("upstream_calls", int(row.get("upstream_calls") or 0), "calls")
        evidence.add("rank_by_requests", rank)
        evidence.add("current_ttl_s", effective_ttl(ctx, covering), "seconds")
        evidence.details["method"] = method
        evidence.details["rule"] = rule_columns(covering) if covering is not None else None
        evidence.links.append(CACHE_LINK)
        served = f"only {ratio:.0%} of them were" if ratio > 0 else "none of them was"
        lead = (
            f"{template} is number {rank} by caller requests ({requests:,} in the last {minutes} minutes), but "
            f"{served} answered from the cache. "
        )
        limits = spread_thresholds(ctx.settings)
        findings = [
            f
            for f in await split_findings(ctx, limits)
            if f.template == template and f.method == method and f.fix != "known"
        ]
        fixable = next((f for f in findings if f.fixable), None)
        if fixable is not None:
            split_evidence(evidence, fixable)
            rec = self.recommendation(
                ctx,
                subject=template,
                title=f"{template} has a {ratio:.0%} cache hit ratio: its keys are split by `{fixable.param}`",
                severity="warn",
                confidence="high",
                explanation=lead + split_explanation(fixable),
                evidence=evidence,
                changes=[split_change(ctx, fixable)],
                risk="medium",
                safe_auto=False,  # ignoring a parameter or reordering ids is judged by an admin
            )
            rec.expected_impact = await impact_from_dry_run(ctx, rec, window.end - window.start, f"on {template}") or (
                f"{extra.counted(fixable.group.entries, 'single-use cache entry')} of {template} become "
                f"{extra.counted(fixable.collapsed_keys or 0, 'reusable key')}; most of its {requests:,} requests per "
                f"{minutes} minutes can then be answered from the cache instead of Roblox."
            )
            return rec
        if method == "POST":
            post = await self._post(ctx, window, template, own, ratio, evidence, lead)
            if post is not None:
                return post
        return await self._ttl_or_manual(ctx, window, template, method, own, covering, ratio, evidence, lead, findings)

    async def _post(
        self,
        ctx: InsightContext,
        window: Window,
        template: str,
        own: Any,
        ratio: float,
        evidence: Evidence,
        lead: str,
    ) -> Recommendation | None:
        """The 11.5 "for POST batch, enable POST caching per rule" branch (None when POST is already cacheable)."""
        mode = str(ctx.setting("cache_post_requests"))
        if mode == "all" or post_allowed(template, ctx.cache_rule_for(template, "POST"), mode):
            return None
        observed = await ctx.change_observations(ctx.now - DAY_S, ctx.now)
        refetches, identical = observed.get(template, (0, 0))
        tuned, estimate = await tuned_ttl(ctx, template)
        evidence.details["ttl_tuner"] = estimate.to_dict()
        lower_pct = float(ctx.setting("insight_cache_ttl_tune_identical_lower_pct"))
        repeat_share = identical / refetches if refetches else None
        if repeat_share is not None:
            evidence.add("identical_refetch_share", round(repeat_share, 4))
        # A cacheable lookup answers the same question with the same body: refetch observations at or above
        # CACHE-TTL-TUNE's "too often outdated" line, or tuner keys whose bodies repeat.
        repeats = (repeat_share is not None and repeat_share * 100 >= lower_pct) or tuned is not None
        if not repeats:
            return None
        ttl = tuned if tuned is not None else DEFAULT_CACHE_RULE_TTL
        methods = list(own.methods) if own is not None else ["GET"]
        if "POST" not in methods:
            methods.append("POST")
        columns: dict[str, Any] = {"ttl": int(ttl), "stale_ttl": swr_for(ctx, int(ttl)), "methods": ",".join(methods)}
        if own is not None:
            # The endpoint's own rule keeps its lifetime unless the tuner measured a longer one.
            ttl = max(int(own.ttl), int(ttl))
            columns = {"methods": ",".join(methods), "ttl": ttl}
        change = rule_change(template, own, columns)
        if change is None:
            return None
        changes = [change]
        if mode == "off":
            # With `off` a POST cache rule has no effect: POST caching moves to `allowlist` (never `all`), the
            # UP-429-ENDPOINT choice recorded for the 11.6 card.
            changes.append(ProposedChange("setting", key="cache_post_requests", current="off", proposed="allowlist"))
        shown = (
            f"{repeat_share:.0%} of refetches returned an identical body"
            if repeat_share is not None
            else ("the request samples show repeated identical answers")
        )
        rec = self.recommendation(
            ctx,
            subject=template,
            title=f"Cache the POST lookup {template} (hit ratio {ratio:.0%})",
            severity="info",
            confidence="medium",
            explanation=(
                lead + f"It is a POST and no cache rule lists POST for it, so every request goes to Roblox; {shown}. "
                f"A cache rule for this endpoint only, listing POST, with a {ttl} s lifetime, caches it. Apply it only "
                "if this POST is a read-only lookup (a write must never be cached)."
            ),
            evidence=evidence,
            changes=changes,
            risk="medium",
            safe_auto=False,
        )
        rec.expected_impact = await impact_from_dry_run(ctx, rec, window.end - window.start, f"on {template}") or (
            f"Repeated POST lookups of {template} are answered from the cache for {ttl} s instead of reaching Roblox."
        )
        return rec

    async def _ttl_or_manual(
        self,
        ctx: InsightContext,
        window: Window,
        template: str,
        method: str,
        own: Any,
        covering: Any,
        ratio: float,
        evidence: Evidence,
        lead: str,
        findings: Sequence[SplitFinding],
    ) -> Recommendation:
        current = effective_ttl(ctx, covering)
        tuned, estimate = await tuned_ttl(ctx, template)
        evidence.details["ttl_tuner"] = estimate.to_dict()
        change: ProposedChange | None = None
        if tuned is not None and tuned > current:
            evidence.add("proposed_ttl_s", tuned, "seconds")
            if estimate.change_interval_s is not None:
                evidence.add("median_change_interval_s", round(estimate.change_interval_s, 1), "seconds")
            if own is not None:
                change = rule_change(template, own, {"ttl": tuned})
            else:
                # A new rule keeps every method the cache serves today for this endpoint (a POST lookup on the
                # built-in POST allowlist stays cached as POST).
                methods = list(covering.methods) if covering is not None else ["GET"]
                if method in CACHEABLE_METHODS and method not in methods:
                    methods.append(method)
                change = new_rule(
                    template, {"ttl": tuned, "stale_ttl": swr_for(ctx, tuned), "methods": ",".join(methods)}
                )
        minutes = round((window.end - window.start) / 60)
        if change is not None:
            rec = self.recommendation(
                ctx,
                subject=template,
                title=f"Cache {template} longer: {current} s to {tuned} s (hit ratio {ratio:.0%})",
                severity="info",
                confidence="medium",
                explanation=(
                    lead + f"Its answers are kept for {current} s, while the TTL tuner measured about "
                    f"{tuned} s between real changes of its bodies, so the cache throws good answers away. A "
                    f"{tuned} s lifetime for this endpoint only matches how often the data really changes."
                ),
                evidence=evidence,
                changes=[change],
                risk="low",
            )
            rec.expected_impact = await impact_from_dry_run(ctx, rec, window.end - window.start, f"on {template}") or (
                f"Answers of {template} are reused for {tuned} s instead of {current} s."
            )
            return rec
        known = next((f for f in findings if not f.fixable), None)
        if known is not None:
            split_evidence(evidence, known)
            detail = split_explanation(known)
        else:
            detail = (
                "Roxy found no cache-busting parameter in its cache entries and has no lifetime measurement for it "
                "yet (the TTL tuner needs request samples with repeated fetches). Check on the Cache page whether its "
                "keys are naturally unique (every request asks for different ids) or whether a longer lifetime would "
                "be safe; CACHE-TTL-TUNE and CACHE-KEYSPLIT fire on their own once the evidence exists."
            )
        return self.recommendation(
            ctx,
            subject=template,
            title=f"{template} is busy but only {ratio:.0%} of its requests are cache hits",
            severity="info",
            confidence="medium",
            explanation=lead + detail,
            evidence=evidence,
            changes=[ProposedChange("manual", text=f"Review the cache rule and the keys of {template} (Cache page).")],
            expected_impact=(
                f"Unknown until the cause is found; every 10 points of hit ratio on {template} would keep about "
                f"{round(int(evidence.metric('requests', 0)) / 10):,} of its calls per {minutes} minutes away from "
                "Roblox."
            ),
            risk="low",
        )


# --------------------------------------------------------------------------------------------- CACHE-KEYSPLIT


@dataclass(slots=True)
class _BustDetection:
    client: str
    value: Any
    threshold: Any
    window_s: Any
    at_ms: int
    template: str | None


@register
class CacheKeysplit(Rule):
    """A query parameter splits the cache into single-use keys (cache busting).

    Fires on the v1 Suspect rule of the key spread (an endpoint with at least `min_entries` cache entries, whose
    most varied parameter has a distinct value in at least `distinct_pct` percent of them, with hits on at most
    `max_hit_pct` percent of them), and on a SPAM-BUST detection of the last hour. A parameter shaped like a cache
    buster (a timestamp, a random number or token) is proposed as an ignored parameter; an id list that differs
    only in order gets a `sort_csv` normalization on that endpoint's cache rule; a parameter that may carry real
    data (ids, search terms) is reported for a manual check and never ignored. Nothing here bans or filters a
    client: abusive clients are ABUSE-SPAM's concern.
    """

    id = "CACHE-KEYSPLIT"
    safe_auto = False  # an ignored parameter applies to every endpoint; a sort changes what Roblox receives

    async def evaluate(self, ctx: InsightContext) -> list[Recommendation]:
        limits = {
            "min_entries": self.param(ctx, "min_entries"),
            "distinct_pct": self.param(ctx, "distinct_pct"),
            "max_hit_pct": self.param(ctx, "max_hit_pct"),
        }
        findings = [f for f in await split_findings(ctx, limits) if f.fix != "known"]
        busts = await self._bust_detections(ctx)
        out: list[Recommendation] = []
        seen: set[str] = set()
        for finding in findings:
            if finding.subject in seen:
                continue  # several concrete paths of one template: the first (largest) group speaks for it
            seen.add(finding.subject)
            related = [b for b in busts if b.template == finding.template]
            out.append(self._from_finding(ctx, finding, related))
        by_template: dict[str, list[_BustDetection]] = {}
        for bust in busts:
            subject = bust.template or f"ip:{bust.client}"
            if bust.template is not None and split_subject("GET", bust.template) in seen:
                continue
            by_template.setdefault(subject, []).append(bust)
        for subject, detections in sorted(by_template.items()):
            out.append(await self._from_busts(ctx, subject, detections))
        for rec in out:
            if any(change.kind != "manual" for change in rec.changes):
                rec.expected_impact = (
                    await impact_from_dry_run(ctx, rec, SPAM_BUST_LOOKBACK_S, "on the affected endpoints")
                    or rec.expected_impact
                )
        return out

    async def _bust_detections(self, ctx: InsightContext) -> list[_BustDetection]:
        window = ctx.window(seconds=SPAM_BUST_LOOKBACK_S)
        events = await ctx.events(SPAM_EVENT_TYPES, window)
        detections = [e for e in events if str((e.get("detail") or {}).get("detector")) == SPAM_BUST_DETECTOR]
        if not detections:
            return []
        clients = {str(c["key"]): c for c in await ctx.clients(window, "ip")}
        out: dict[str, _BustDetection] = {}
        for event in detections:
            detail = event["detail"]
            subject = str(detail.get("subject") or "")
            client = subject[len("ip:") :] if subject.startswith("ip:") else subject
            row = clients.get(client)
            template = str(row["top_endpoint"]) if row is not None and row.get("top_endpoint") else None
            if template is None and named_template(str(event.get("endpoint_template") or "")):
                template = str(event["endpoint_template"])
            if template is not None and not named_template(template):
                template = None
            # One detection per client: the newest one.
            out[client] = _BustDetection(
                client, detail.get("value"), detail.get("threshold"), detail.get("window_s"), int(event["at_ms"]),
                template,
            )  # fmt: skip
        return sorted(out.values(), key=lambda b: (b.template or "", b.client))

    def _from_finding(
        self, ctx: InsightContext, finding: SplitFinding, busts: Sequence[_BustDetection]
    ) -> Recommendation:
        group = finding.group
        evidence = Evidence(window_to=ctx.now, sample_size=group.entries)
        split_evidence(evidence, finding)
        if busts:
            evidence.details["spam_bust"] = [self._bust_detail(b) for b in busts[:MAX_EVIDENCE_ROWS]]
        if finding.fixable:
            changes = [split_change(ctx, finding)]
            title = (
                f"Ignore the cache buster `{finding.param}` on {finding.template}"
                if finding.fix == "ignore"
                else f"Sort the id list `{finding.param}` in the cache keys of {finding.template}"
            )
            impact = (
                f"{extra.counted(group.entries, 'cache entry')} with {extra.counted(group.hits, 'hit')} become "
                f"{extra.counted(finding.collapsed_keys or 0, 'reusable key')}, so repeat requests to "
                f"{finding.template} are answered from the cache instead of Roblox."
            )
        else:
            changes = [
                ProposedChange(
                    "manual", text=f"Check whether `{finding.param}` on {finding.template} is a cache buster."
                )
            ]
            title = f"The parameter `{finding.param}` makes the cache keys of {finding.template} unique"
            impact = "None until the parameter is identified; a cache cannot help keys that are really unique."
        return self.recommendation(
            ctx,
            subject=finding.subject,
            title=title,
            severity="warn",
            confidence="high" if finding.fixable else "medium",
            explanation=split_explanation(finding),
            evidence=evidence,
            changes=changes,
            expected_impact=impact,
            risk="medium" if finding.fixable else "low",
        )

    async def _from_busts(self, ctx: InsightContext, subject: str, busts: Sequence[_BustDetection]) -> Recommendation:
        """A SPAM-BUST detection without a Suspect group: the parameter is shown when the entries can tell."""
        template = busts[0].template
        evidence = Evidence(window_to=ctx.now, sample_size=len(busts))
        evidence.add("spam_bust_detections", len(busts), "detections")
        evidence.details["spam_bust"] = [self._bust_detail(b) for b in busts[:MAX_EVIDENCE_ROWS]]
        evidence.links.append(SPREAD_LINK)
        candidate = await self._buster_on(ctx, template) if template is not None else None
        where = template or "an endpoint the detection does not name"
        if candidate is not None:
            split_evidence(evidence, candidate)
            changes = [split_change(ctx, candidate)]
            detail = split_explanation(candidate)
            title = f"Ignore the cache buster `{candidate.param}` on {template} (SPAM-BUST)"
            confidence = "high"
        else:
            changes = [
                ProposedChange(
                    "manual",
                    text=f"Find the parameter that changes on every request to {where} (Live page) and ignore it.",
                )
            ]
            detail = (
                "Roxy's cache entries do not show which parameter changes (the shared cache tier may be off, or the "
                "entries already expired), so the parameter is a manual check on the Live page."
            )
            title = f"A client is busting the cache on {where} (SPAM-BUST)"
            confidence = "medium"
        clients = ", ".join(b.client for b in busts[:MAX_EVIDENCE_ROWS])
        return self.recommendation(
            ctx,
            subject=subject,
            title=title,
            severity="warn",
            confidence=confidence,
            explanation=(
                f"The SPAM-BUST detector saw {extra.counted(len(busts), 'client')} ({clients}) send almost every "
                f"request to {where} "
                f"with a different query in the last {round(SPAM_BUST_LOOKBACK_S / 60)} minutes, so each request is a "
                f"cache miss that reaches Roblox. {detail} Blocking the client is ABUSE-SPAM's decision, not this one."
            ),
            evidence=evidence,
            changes=changes,
            expected_impact=(
                f"Requests from busting clients to {where} are answered from the cache once the busting parameter is "
                "ignored."
            ),
            risk="medium" if candidate is not None else "low",
        )

    async def _buster_on(self, ctx: InsightContext, template: str) -> SplitFinding | None:
        """A buster-shaped, mostly distinct top parameter of any key spread group of `template` (not only Suspect
        groups: SPAM-BUST already says the keys are busted)."""
        host = template.split("/", 1)[0]
        rows = [
            row
            for row in await extra.spread(ctx, SPREAD_ROWS)
            if row.host == host and template_for(row.host, row.path) == template
        ]
        if not rows:
            return None
        groups = compute_spread(rows, min_entries=1, distinct_pct=0, max_hit_pct=100, limit=MAX_SPLIT_GROUPS)
        distinct_pct = self.param(ctx, "distinct_pct")
        ignored = frozenset(ctx.rules.cache_ignored_params)
        for group in groups:
            top = group.varying[0] if group.varying else None
            if top is None or top.name in ignored or top.ratio * 100 < distinct_pct:
                continue
            members = [row for row in rows if _group_key(row) == group.key]
            values = _param_values(members, top.name)
            if looks_like_buster(top.name, values):
                return SplitFinding(
                    group.method, template, group, top.name, values, "ignore",
                    collapsed_keys=_collapsed(members, top.name, sort_values=False), rows=members,
                )  # fmt: skip
        return None

    @staticmethod
    def _bust_detail(bust: _BustDetection) -> dict[str, Any]:
        return {
            "client": bust.client,
            "value": bust.value,
            "threshold": bust.threshold,
            "window_s": bust.window_s,
            "at": extra.utc_text(bust.at_ms / 1000),
            "endpoint": bust.template,
        }


# --------------------------------------------------------------------------------------------- CACHE-PRESSURE


@register
class CachePressure(Rule):
    """The shared cache is too small: it pushes entries out before their lifetime ends.

    Fires when, over the last `window_min` minutes, the entries evicted while still younger than their lifetime
    are more than `young_eviction_pct` percent of the entries stored. The eviction passes show which cap forced
    them out (`cache_max_bytes` or `cache_max_entries`), and only that cap is raised: doubled, within its catalog
    range and, for bytes, within half of the free disk. Both caps are global settings, so this is never applied
    automatically.
    """

    id = "CACHE-PRESSURE"
    safe_auto = False

    async def evaluate(self, ctx: InsightContext) -> list[Recommendation]:
        window = ctx.window(minutes=self.param(ctx, "window_min"))
        summary = await ctx.cache_summary(window)
        stores = int(summary.get("stores") or 0)
        young = int(summary.get("young_evictions") or 0)
        if stores <= 0 or not young:
            return []
        share = young * 100.0 / stores
        if share <= self.param(ctx, "young_eviction_pct"):
            return []
        passes = await ctx.eviction_passes(window)
        max_bytes = int(ctx.setting("cache_max_bytes"))
        max_entries = int(ctx.setting("cache_max_entries"))
        by_bytes = sum(1 for p in passes if max_bytes > 0 and int(p["bytes_before"]) > max_bytes)
        by_entries = sum(1 for p in passes if max_entries > 0 and int(p["entries_before"]) > max_entries)
        if by_entries > by_bytes and max_entries > 0:
            key, current = "cache_max_entries", max_entries
        elif max_bytes > 0:
            key, current = "cache_max_bytes", max_bytes
        else:
            return []  # both caps unlimited: early evictions come from somewhere else
        proposed = int(min(setting_max(key), math.ceil(current * CAP_GROWTH)))
        disk = await ctx.providers.disk() if key == "cache_max_bytes" else None
        if disk and disk.get("free_bytes") is not None:
            proposed = int(min(proposed, current + float(disk["free_bytes"]) * DISK_SHARE_MAX))
        if proposed <= current:
            return []
        minutes = round((window.end - window.start) / 60)
        evidence = Evidence(window_from=window.start, window_to=window.end, sample_size=stores)
        evidence.add("stores", stores, "entries")
        evidence.add("evictions", int(summary.get("evictions") or 0), "entries")
        evidence.add("young_evictions", young, "entries")
        evidence.add("young_eviction_pct", round(share, 2), "percent")
        if summary.get("mean_young_age_s") is not None:
            evidence.add("mean_young_eviction_age_s", summary["mean_young_age_s"], "seconds")
        if summary.get("mean_eviction_age_s") is not None:
            evidence.add("mean_eviction_age_s", summary["mean_eviction_age_s"], "seconds")
        evidence.add("passes_over_byte_cap", by_bytes, "passes")
        evidence.add("passes_over_entry_cap", by_entries, "passes")
        evidence.add(key, current, "bytes" if key == "cache_max_bytes" else "entries")
        if disk and disk.get("free_bytes") is not None:
            evidence.add("disk_free_bytes", int(disk["free_bytes"]), "bytes")
        evidence.links.append(CACHE_LINK)
        what = "bytes" if key == "cache_max_bytes" else "entries"
        return [
            self.recommendation(
                ctx,
                subject=key,
                title=f"The cache evicts fresh entries: raise {key} from {current:,} to {proposed:,}",
                severity="warn",
                confidence="high",
                explanation=(
                    f"In the last {minutes} minutes {young:,} of the {stores:,} entries stored in the shared cache "
                    f"({share:.1f}%) were pushed out before their lifetime ended. {max(by_bytes, by_entries)} of "
                    f"{len(passes)} eviction passes started over the {what} cap, so {key} is the cap that binds. A "
                    f"larger cap lets entries live their full lifetime."
                ),
                evidence=evidence,
                changes=[ProposedChange("setting", key=key, current=current, proposed=proposed)],
                expected_impact=(
                    f"About {per_hour_text(young, window.end - window.start)} entries per hour stop being evicted "
                    "early, so the requests that would have found them are answered from the cache instead of Roblox."
                ),
                risk="low",
            )
        ]


# -------------------------------------------------------------------------------------------------- CACHE-OFF


@register
class CacheOff(Rule):
    """The cache is switched off while callers are being served.

    Fires when `cache_enabled` is 0 and callers made requests in the last hour (Roxy's own health checks and
    probes are not caller traffic). The change turns the cache back on; it is a global setting, so it is never
    applied automatically. A cache that only has its shared disk tier off (`cache_disk_enabled` 0) is still on.
    """

    id = "CACHE-OFF"
    safe_auto = False
    triggers = frozenset({"settings_change"})

    async def evaluate(self, ctx: InsightContext) -> list[Recommendation]:
        if ctx.flag("cache_enabled"):
            return []
        window = ctx.window(minutes=OFF_WINDOW_MIN)
        totals = await ctx.totals(window)
        demand = int(totals.get("demand") or 0)
        if demand <= 0:
            return []
        calls = int(totals.get("upstream_calls") or 0)
        roblox_429 = int(totals.get("roblox_429") or 0)
        evidence = Evidence(window_from=window.start, window_to=window.end, sample_size=demand)
        evidence.add("requests", int(totals.get("requests") or 0), "requests")
        evidence.add("upstream_calls", calls, "calls")
        evidence.add("avoided_calls", demand - calls, "calls")
        evidence.add("roblox_429", roblox_429, "responses")
        evidence.links.append(CACHE_LINK)
        since = await self._switched_off_at(ctx)
        before = ""
        if since is not None:
            evidence.details["switched_off_at"] = extra.utc_text(since)
            earlier = await ctx.totals(ctx.window(seconds=HOUR_S, end=since))
            earlier_demand = int(earlier.get("demand") or 0)
            if earlier_demand > 0:
                share = int(earlier.get("served_cache") or 0) / earlier_demand
                evidence.add("hit_ratio_before_off", round(share, 4))
                before = (
                    f" In the hour before it was switched off ({extra.utc_text(since)}), {share:.0%} of requests were "
                    "answered from the cache."
                )
        impact = (
            f"At the hit ratio it had before, about {round(calls * float(evidence.metric('hit_ratio_before_off'))):,} "
            "of these calls per hour would be answered from the cache."
            if evidence.metric("hit_ratio_before_off") is not None
            else f"Repeat requests are answered from the cache again instead of all {calls:,} reaching Roblox."
        )
        minutes = round((window.end - window.start) / 60)
        return [
            self.recommendation(
                ctx,
                subject="cache_enabled",
                title="The cache is switched off: every request goes to Roblox",
                severity="critical" if roblox_429 else "warn",
                confidence="high",
                explanation=(
                    f"cache_enabled is 0, and in the last {minutes} minutes callers made {demand:,} requests, every "
                    f"one sent to Roblox ({calls:,} upstream calls, {roblox_429:,} of them answered 429).{before} "
                    "Turning the cache on lets repeat requests be answered without Roblox."
                ),
                evidence=evidence,
                changes=[ProposedChange("setting", key="cache_enabled", current=0, proposed=1)],
                expected_impact=impact,
                risk="low",
            )
        ]

    @staticmethod
    async def _switched_off_at(ctx: InsightContext) -> float | None:
        """When `cache_enabled` was last set to 0 (settings history), or None."""
        changes = await ctx.recent_changes(ctx.now - OFF_LOOKBACK_DAYS * DAY_S)
        found: float | None = None
        for change in changes:
            if change.get("key") == "cache_enabled" and not int(change.get("after") or 0):
                found = float(change["at"])
        return found


# -------------------------------------------------------------------------------------------------- CACHE-NEG


@register
class CacheNeg(Rule):
    """Callers keep fetching the same Roblox 404 or 400 answer.

    Counts, over the last hour, how often Roxy asked Roblox again for a cache key whose answer was already a 404
    or 400 (request samples, scaled up when only a share of requests is sampled). Fires when those identical
    refetches exceed `min_404_per_hour`, and proposes a longer `cache_error_ttl_seconds` (back to the catalog
    default when it is lower, else doubled), so an error answer is remembered instead of fetched again. Different
    missing items asked once each are not refetches. The setting is global, so it is never applied automatically.
    """

    id = "CACHE-NEG"
    safe_auto = False

    async def evaluate(self, ctx: InsightContext) -> list[Recommendation]:
        sample_pct = float(ctx.setting("request_sample_pct"))
        if sample_pct <= 0:
            return []  # no samples: refetches per key cannot be counted
        scale = 100.0 / sample_pct
        window = ctx.window(seconds=NEG_WINDOW_S)
        groups = [g for g in await extra.error_refetches(ctx, window) if named_template(g["endpoint_template"])]
        refetches = 0.0
        repeated = []
        for group in groups:
            fetches = int(group["fetches"])
            # Only keys sampled more than once count: a key sampled once may have been fetched only once, and
            # scaling it up would invent refetches (plan P6: numbers never flatter the rule).
            if fetches > 1:
                refetches += fetches * scale - 1
                repeated.append(group)
        refetches = round(refetches)
        if refetches <= self.param(ctx, "min_404_per_hour"):
            return []
        key = "cache_error_ttl_seconds"
        current = int(ctx.setting(key))
        default = int(catalog.CATALOG[key].default)
        highest = int(setting_max(key))
        proposed = default if current < default else min(highest, current * ERROR_TTL_GROWTH)
        evidence = Evidence(window_from=window.start, window_to=window.end, sample_size=refetches)
        evidence.add("identical_error_refetches_per_hour", refetches, "refetches")
        evidence.add("repeated_keys", len(repeated), "keys")
        evidence.add("cache_error_ttl_seconds", current, "seconds")
        if scale != 1:
            evidence.add("request_sample_pct", sample_pct, "percent")
        evidence.details["keys"] = [
            {"endpoint": g["endpoint_template"], "status": g["status"], "fetches": round(int(g["fetches"]) * scale)}
            for g in repeated[:MAX_EVIDENCE_ROWS]
        ]
        evidence.links.append(CACHE_LINK)
        top = repeated[0]
        lead = (
            f"In the last hour Roxy asked Roblox {refetches:,} times for an answer it had just received as an error: "
            f"{extra.counted(len(repeated), 'cache key')} fetched repeatedly, the busiest {top['endpoint_template']} "
            f"({round(int(top['fetches']) * scale):,} times, status {top['status']}). "
        )
        if proposed <= current:
            return [
                self.recommendation(
                    ctx,
                    subject=key,
                    title="Callers keep refetching the same Roblox error answers",
                    severity="info",
                    confidence="high",
                    explanation=lead + f"cache_error_ttl_seconds is already at its maximum ({current} s).",
                    evidence=evidence,
                    changes=[
                        ProposedChange(
                            "manual",
                            text=f"Add a cache rule with a longer negative_ttl for {top['endpoint_template']}.",
                        )
                    ],
                    expected_impact="Fewer repeated error calls on the named endpoints.",
                    risk="low",
                )
            ]
        rec = self.recommendation(
            ctx,
            subject=key,
            title=f"Remember Roblox error answers longer: cache_error_ttl_seconds {current} s to {proposed} s",
            severity="info",
            confidence="high",
            explanation=lead
            + (
                f"cache_error_ttl_seconds is {current} s, so the cache forgets an error answer "
                + ("at once" if current == 0 else f"after {current} s")
                + f". At {proposed} s a missing item is fetched at most once per {proposed} s per key."
            ),
            evidence=evidence,
            changes=[ProposedChange("setting", key=key, current=current, proposed=proposed)],
            risk="low",
        )
        rec.expected_impact = await self._impact(ctx, window, repeated, proposed, scale)
        return [rec]

    @staticmethod
    async def _impact(
        ctx: InsightContext, window: Window, repeated: Sequence[Mapping[str, Any]], ttl: int, scale: float
    ) -> str:
        """Replay the repeated error fetches under the proposed lifetime (plan 11.3 cache replay)."""
        keys = {str(g["key_id"]) for g in repeated}
        statuses = {int(g["status"]) for g in repeated}
        samples = await ctx.samples(window, sorted({str(g["endpoint_template"]) for g in repeated}))
        rows = [
            s
            for s in samples
            if str(s.get("key_id")) in keys
            and s.get("upstream_status") in statuses
            and str(s.get("egress") or "none") != "none"
        ]
        replay = simulate.cache_replay(rows, ttl_s=ttl)
        avoided = round(replay.avoided_calls * scale)
        return (
            f"About {avoided:,} of the {round(replay.requests * scale):,} repeated error calls of the last hour would "
            f"have been answered from the cache (replayed over {replay.requests:,} request samples)."
        )


# ----------------------------------------------------------------------------------------------- HOT-ENDPOINT


@register
class HotEndpoint(Rule):
    """A newly busy endpoint has no cache rule.

    Ranks endpoints by their upstream calls over the last hour and fires for each of the `top_n` busiest that no
    cache rule covers (so it is cached only at the global `cache_ttl_seconds`). The change is a cache rule for
    that endpoint alone, with the lifetime the TTL tuner measured (or the standard new-rule lifetime of 300 s
    while the tuner is off or has no measurement); when that would not be longer than what the endpoint gets
    today, nothing is proposed. The evidence shows the volume trend against the previous hour and day. POST
    endpoints are left to CACHE-LOW-HIT and UP-429-ENDPOINT, which check that the POST is a lookup.
    """

    id = "HOT-ENDPOINT"
    safe_auto = True

    async def evaluate(self, ctx: InsightContext) -> list[Recommendation]:
        window = ctx.window(minutes=HOT_WINDOW_MIN)
        rows = await ctx.by_template(window)
        ranked = sorted(
            (t for t in rows if named_template(str(t)) and int(rows[t].get("upstream_calls") or 0) > 0),
            key=lambda t: (-int(rows[t]["upstream_calls"] or 0), t),
        )
        top = ranked[: self.int_param(ctx, "top_n")]
        if not top:
            return []
        previous = await ctx.by_template(ctx.window(minutes=HOT_WINDOW_MIN, end=window.start))
        day = await ctx.by_template(ctx.window(days=1, end=window.start))
        previous_rank = {
            t: i
            for i, t in enumerate(
                sorted(previous, key=lambda t: (-int(previous[t].get("upstream_calls") or 0), t)), start=1
            )
        }
        out: list[Recommendation] = []
        for rank, template in enumerate(top, start=1):
            rec = await self._recommend(ctx, window, str(template), rank, rows[template], previous, day, previous_rank)
            if rec is not None:
                out.append(rec)
        return out

    async def _recommend(
        self,
        ctx: InsightContext,
        window: Window,
        template: str,
        rank: int,
        row: Mapping[str, Any],
        previous: Mapping[Any, Mapping[str, Any]],
        day: Mapping[Any, Mapping[str, Any]],
        previous_rank: Mapping[Any, int],
    ) -> Recommendation | None:
        methods = await ctx.by(window, "method", {"endpoint_template": template})
        method = dominant_method(methods)
        if method != "GET":
            return None
        covering, own = rule_for(ctx, template, method)
        if covering is not None or own is not None:
            return None  # it has a cache rule (or a switched-off one the admin chose)
        private = ctx.rules.credential_rule_for(template, method)
        if private is not None and private.cache_private:
            return None
        current = effective_ttl(ctx, None)
        tuned, estimate = await tuned_ttl(ctx, template)
        ttl = tuned if tuned is not None else DEFAULT_CACHE_RULE_TTL
        if ttl <= current:
            return None  # a rule would not keep answers longer than the global lifetime does
        calls = int(row.get("upstream_calls") or 0)
        before = int((previous.get(template) or {}).get("upstream_calls") or 0)
        per_day = int((day.get(template) or {}).get("upstream_calls") or 0)
        evidence = Evidence(window_from=window.start, window_to=window.end, sample_size=calls)
        evidence.add("upstream_calls", calls, "calls")
        evidence.add("rank_by_upstream_calls", rank)
        evidence.add("upstream_calls_previous_hour", before, "calls")
        evidence.add("upstream_calls_previous_day_per_hour", round(per_day / 24, 1), "calls")
        evidence.add("current_ttl_s", current, "seconds")
        evidence.add("proposed_ttl_s", ttl, "seconds")
        if estimate.change_interval_s is not None:
            evidence.add("median_change_interval_s", round(estimate.change_interval_s, 1), "seconds")
        evidence.details["ttl_tuner"] = estimate.to_dict()
        evidence.details["previous_rank"] = previous_rank.get(template)
        evidence.links.append(CACHE_LINK)
        source = (
            f"the TTL tuner measured about {ttl} s between body changes"
            if tuned is not None
            else f"the standard new-rule lifetime is {ttl} s"
        )
        trend = (
            "it had no upstream calls in the hour before"
            if not before
            else f"up from {before:,} calls in the hour before"
            if calls > before
            else f"{before:,} calls in the hour before"
        )
        change = new_rule(template, {"ttl": ttl, "stale_ttl": swr_for(ctx, ttl), "methods": "GET"})
        rec = self.recommendation(
            ctx,
            subject=template,
            title=f"New busy endpoint {template} has no cache rule",
            severity="info",
            confidence="medium",
            explanation=(
                f"{template} is number {rank} by upstream calls ({calls:,} in the last hour; {trend}) and no cache "
                f"rule covers it, so its answers are kept only {current} s (cache_ttl_seconds). A rule for this "
                f"endpoint with a {ttl} s lifetime ({source}) keeps repeat requests away from Roblox."
            ),
            evidence=evidence,
            changes=[change],
            risk="low",
        )
        rec.expected_impact = await impact_from_dry_run(ctx, rec, window.end - window.start, f"on {template}") or (
            f"Answers of {template} are reused for {ttl} s instead of {current} s."
        )
        return rec


__all__ = [
    "CAP_GROWTH",
    "DISK_SHARE_MAX",
    "CacheKeysplit",
    "CacheLowHit",
    "CacheNeg",
    "CacheOff",
    "CachePressure",
    "HotEndpoint",
    "SplitFinding",
    "is_id_name",
    "looks_like_buster",
    "named_template",
    "rule_change",
    "split_findings",
]
