"""The upstream recommendation rules of plan 11.5, from UP-429-HOST to UP-BREAKER-FLAP (UP-429-ENDPOINT is in core.py).

What this is
    Fourteen rules about how Roblox answers Roxy and how Roxy paces, routes and retries its calls: 429s spread over
    a host, on the credential, or multiplied by retries; callers ignoring Retry-After; 4xx spikes; CSRF handshakes
    that do not settle; challenge pages; the User-Agent experiment; 5xx spikes; timeouts; latency; queue saturation;
    bucket sizing; and flapping circuit breakers. Each class docstring is the rule's help text in the dashboard.

Why it exists
    Plan 7 builds the mechanisms (buckets, cooldowns, breakers, routing, retries); these rules watch what the
    mechanisms produce and propose the next adjustment with its evidence, so the admin never tunes blind (P2, P4).

How it works
    - Thresholds come only from `self.param(ctx, ...)` (plan 11.1, 15.3 J2). Parameters named `min_*` are inclusive
      minimums ("at least N", as their catalog text says); rates and percentages must be exceeded ("> N"). The
      few fixed numbers are algorithm constants named and documented below, never 11.5 thresholds.
    - Data comes from the `InsightContext` read models: rollups (`by`, `per_minute`, `totals`, with the latency and
      queue wait histograms), the Roblox 429 log, upstream attempts by kind (`upstream_attempt_minute`), bucket
      history, events, samples, rule tables and settings. Two facts the context lacks (rotator budget and health,
      the User-Agent experiment arms) come from `insights/providers_rules_upstream.py`.
    - Calls versus requests (P6): "calls" are upstream HTTP calls (`upstream_calls`, retries included, Roxy's own
      probes excluded), "requests" are caller requests. Per-call statuses come from the attempts table; where an
      attempt row is missing, the caller rollups give a lower bound (for example every call of a request that
      failed with `upstream_5xx` was a 5xx), and the larger of the two is used.
    - Changes are scoped wherever the plan allows (`bucket_override`, `rule_upsert`, `routing_rule`,
      `credential_allowlist_remove`); global settings appear only where 11.5 names one, and then the engine marks the
      recommendation not `safe_auto`. The credential is never a fallback target (7.9), places are never banned, and
      no rule here ever proposes moving traffic onto the credential.

What to read next
    `roxy/insights/rules/base.py` (the authoring guide), `roxy/insights/rules/core.py` (UP-429-ENDPOINT and the
    shared cache helpers), `tests/fixtures/insights/up_*.yaml` (the scenarios each rule must pass).
"""

from __future__ import annotations

import bisect
import math
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from http import HTTPStatus
from types import MappingProxyType
from typing import Any, Final
from urllib.parse import quote

from roxy.config import catalog
from roxy.config.constants import (
    CACHEABLE_ERROR_STATUSES,
    MAX_CACHE_RULE_STALE_TTL_S,
    MAX_CACHE_RULE_TTL_S,
    TARPIT_CATEGORIES,
)
from roxy.core.reasons import CacheState, Egress, ReasonCode
from roxy.insights import simulate
from roxy.insights.context import InsightContext
from roxy.insights.models import MAX_CHANGES, Evidence, ProposedChange, Recommendation, iso
from roxy.insights.providers_rules_upstream import RotatorStatus, rotator_status, span_window, ua_experiment_arms
from roxy.insights.rules.base import Rule, register
from roxy.insights.rules.core import (
    BUCKET_HEADROOM,
    HOUR_S,
    SWR_SHARE_OF_TTL,
    effective_ttl,
    own_cache_rule,
    rule_columns,
)
from roxy.metrics import histograms
from roxy.metrics.queries import Window
from roxy.metrics.templating import OTHER
from roxy.upstream import adaptive, breaker
from roxy.upstream.buckets import GLOBAL_KEY, egress_bucket_key

# ------------------------------------------------------------------------------------------------ constants

DAY_S: Final = 86_400
DIRECT: Final = Egress.DIRECT.value
ROTATOR: Final = Egress.ROTATOR.value
CREDENTIAL: Final = Egress.CREDENTIAL.value
UPSTREAM_EGRESSES: Final[tuple[str, ...]] = (DIRECT, ROTATOR, CREDENTIAL)
ACCOUNT_EGRESSES: Final[tuple[str, ...]] = (DIRECT, CREDENTIAL)
"""Egresses whose 429s limit Roxy's own IP or account (7.3 attribution; a rotator 429 burns one exit only)."""
WENT_UPSTREAM: Final[Mapping[str, Any]] = MappingProxyType({"egress": list(UPSTREAM_EGRESSES)})
"""Rollup filter: caller requests whose final attempt reached Roblox (cache serves and refusals have egress none)."""
WRITE_METHODS: Final[tuple[str, ...]] = ("POST", "PATCH", "PUT", "DELETE")
"""The write methods of UP-CSRF-LOOP (11.5): Roblox asks for a CSRF token on these."""
REJECTION_STATUSES: Final[tuple[int, ...]] = (
    int(HTTPStatus.BAD_REQUEST),
    int(HTTPStatus.UNAUTHORIZED),
    int(HTTPStatus.FORBIDDEN),
)
RELAYED_SOURCES: Final[tuple[str, ...]] = ("relay", "roblox")
"""Rollup sources of answers that came from Roblox (Roxy's own refusals with the same status are `roxy`)."""
COMPARED_SOURCES: Final[tuple[str, ...]] = (*RELAYED_SOURCES, "internal")
"""Relayed answers plus Roxy's own calls (admin lookups, probes): the UP-4XX-SPIKE path comparison."""
CACHE_SERVES: Final = frozenset(
    {CacheState.HIT.value, CacheState.STALE.value, CacheState.REVALIDATING.value, CacheState.COALESCED.value}
)
SUCCESS: Final = frozenset(range(int(HTTPStatus.OK), int(HTTPStatus.MULTIPLE_CHOICES)))
SERVER_ERRORS: Final = frozenset(range(int(HTTPStatus.INTERNAL_SERVER_ERROR), 600))
TOO_MANY_REQUESTS: Final = int(HTTPStatus.TOO_MANY_REQUESTS)
UNAUTHORIZED: Final = int(HTTPStatus.UNAUTHORIZED)
FORBIDDEN: Final = int(HTTPStatus.FORBIDDEN)
DROP_REASONS: Final[tuple[str, ...]] = (ReasonCode.QUEUE_OVERFLOW.value, ReasonCode.UPSTREAM_BUSY.value)
"""Requests dropped from the upstream queue (UP-QUEUE-SAT): the cap was full, or no slot came within the budget."""
TARPIT_RETRY_CATEGORY: Final = "upstream_cooldown_retry"
"""10.6: the tarpit category for callers retrying a key that is cooling down (jitter type)."""
if TARPIT_RETRY_CATEGORY not in TARPIT_CATEGORIES:  # a renamed category must fail loudly at import
    raise RuntimeError(f"tarpit category {TARPIT_RETRY_CATEGORY!r} is not in config/constants.py")
EXPERIMENT_ARMS: Final[tuple[str, ...]] = ("primary", "alt")
"""The two User-Agent experiment arms (`egress/headers.py HeaderProfiles.ua_variant`)."""

CREDENTIAL_LOOKBACK_S: Final = DAY_S
"""UP-429-CREDENTIAL has no window parameter (15.3 J2): a credential 429 is reported for a day, so the admin sees it
after the cooldown ended (the fixture reads "at most 7 days")."""
EPISODE_LOOKBACK_S: Final = HOUR_S
"""UP-429-AMPLIFY, UP-QUEUE-SAT, UP-BUCKET-TUNE (too loose) and UP-BREAKER-FLAP have no window parameter either:
they look at the last hour, the 60 minute default of UP-429-ENDPOINT and the "per hour" of 11.5."""
BASELINE_DAYS: Final = 7
"""UP-4XX-SPIKE: the endpoint's rejection rate over the 7 days before the window (11.5 "7-day baseline")."""
TTL_RAISE_FACTOR: Final = 2
""""Raise TTL" (UP-LATENCY, UP-QUEUE-SAT) when the TTL tuner has no samples to measure: double it, never above
`ttl_tuner_max_s`. With samples the tuner's median change interval is used, as in UP-429-ENDPOINT."""
SWR_RAISE_FACTOR: Final = 2
""""Enable SWR or raise stale window" (UP-5XX, UP-LATENCY): double the window the endpoint has now (its rule's
`stale_ttl`, else `cache_swr_seconds`), at least `SWR_SHARE_OF_TTL` of the TTL."""
TIMEOUT_RAISE_FACTOR: Final = 1.5
""""Raise request_timeout modestly" (UP-TIMEOUT): by half, and only as far as the plan 5.2 owner deadline allows."""
WEIGHT_CUT_FACTOR: Final = 0.5
""""Lower rotator weight" (UP-TIMEOUT): halve it."""
BREAKER_OPEN_RAISE_FACTOR: Final = 2
""""Raise breaker_open_s" (UP-BREAKER-FLAP): double it, capped at the breaker's own 600 s maximum (7.10)."""
QUEUE_DOMINANCE: Final = 0.5
"""UP-LATENCY "queue wait dominates": the p95 queue wait is at least half of the p95 latency."""
SIGNIFICANCE_Z: Final = 1.96
"""UP-UA-EXPERIMENT: a two-proportion z of 1.96 is the 95% level the evidence's confidence intervals use."""
WAIT_RESOLUTION_MS: Final = float(histograms.BOUNDS_MS[0])
"""A p95 queue wait inside the first histogram bucket (0 to 5 ms, plan 6.4) cannot be told from no wait at all, so
an endpoint "queues" only above it."""
TOP_ENDPOINTS: Final = 5
""""Top slow endpoints", "top miss endpoints" (UP-LATENCY, UP-QUEUE-SAT): at most this many get a change."""
MAX_LISTED: Final = 20
"""Most rows an evidence table holds (plan P9)."""
TIMELINE_POINTS: Final = 120
"""Most minutes an evidence timeline holds (the newest; plan P9)."""
HISTORY_HOURS: Final = 24
"""Hours of bucket fill history an UP-BUCKET-TUNE card shows."""
NAMES_SHOWN: Final = 5
"""Most endpoint names an explanation sentence lists (the evidence table has them all)."""
MAX_ATTRIBUTED_429S: Final = 5000
"""Most 429 rows UP-BUCKET-TUNE attributes per run (newest kept; plan P9)."""
CACHEABLE_METHODS: Final[tuple[str, ...]] = ("GET", "POST")
"""Methods the cache can store (`cache/policy.py`); a cache rule for any other method changes nothing."""
EGRESS_BUCKET_SETTINGS: Final[dict[str, str]] = {
    egress_bucket_key(Egress.DIRECT): "direct_bucket_per_min",
    egress_bucket_key(Egress.ROTATOR): "rotator_bucket_per_min",
    egress_bucket_key(Egress.CREDENTIAL): "credential_bucket_per_min",
    GLOBAL_KEY: "global_bucket_per_min",
}
"""Buckets whose rate is a setting (7.3 table) rather than an `upstream_limits` row."""


# ---------------------------------------------------------------------------------------------- helpers


def real_template(template: Any) -> bool:
    """A concrete endpoint template a change can be scoped to (not empty, `other`, or a `(...)` group)."""
    text = str(template or "")
    return bool(text) and text != OTHER and not text.startswith("(")


def host_of(template: str) -> str:
    return template.split("/", 1)[0]


def pct(part: float, whole: float) -> float:
    """`part` as a percentage of `whole` (0 for an empty whole)."""
    return part * 100.0 / whole if whole else 0.0


def number(row: Mapping[str, Any] | None, name: str) -> float:
    """A measure of a rollup row as a number (missing or None is 0)."""
    if not row:
        return 0.0
    value = row.get(name)
    return float(value) if value is not None else 0.0


def endpoint_link(template: str) -> str:
    return f"/admin/upstream?endpoint={quote(template, safe='')}"


def minute_runs(minutes: Iterable[int]) -> list[tuple[int, int]]:
    """Consecutive minutes as half open `(start, end)` runs, oldest first."""
    runs: list[tuple[int, int]] = []
    for minute in sorted(set(minutes)):
        if runs and runs[-1][1] == minute:
            runs[-1] = (runs[-1][0], minute + 60)
        else:
            runs.append((minute, minute + 60))
    return runs


def proposal_text(changes: Sequence[ProposedChange]) -> str:
    """`Proposed: a; b.` for the appliable changes, or "" when there are none."""
    parts = [change_summary(change) for change in changes if change.kind != "manual"]
    return f"Proposed: {'; '.join(parts)}." if parts else ""


def setting_change(ctx: InsightContext, key: str, proposed: Any) -> ProposedChange:
    return ProposedChange("setting", key=key, current=ctx.setting(key), proposed=proposed)


def manual(text: str) -> ProposedChange:
    return ProposedChange("manual", text=text)


def clamp_setting(key: str, value: float) -> float:
    """`value` inside the catalog range of `key`."""
    spec = catalog.CATALOG[key]
    if spec.max is not None:
        value = min(value, float(spec.max))
    if spec.min is not None:
        value = max(value, float(spec.min))
    return value


def settings_valid(ctx: InsightContext, changes: Mapping[str, Any]) -> bool:
    """The changed values pass `validate_value` and, merged with the run's settings, the cross-field rules."""
    try:
        checked = {key: catalog.validate_value(key, value) for key, value in changes.items()}
    except (catalog.SettingValidationError, KeyError):
        return False
    merged = {**dict(ctx.settings), **checked}
    return not any(set(issue.keys) & set(checked) for issue in catalog.validate_cross(merged))


def routing_change(ctx: InsightContext, template: str, mode: str, note: str) -> ProposedChange | None:
    """A `routing_rule` change that gives `template` the routing `mode` (None when it already has it)."""
    pattern = simulate.template_pattern(template)
    own = next((row for row in ctx.rules.routing_rules if row.pattern == pattern), None)
    if own is not None:
        if own.mode == mode and own.enabled:
            return None
        proposed: dict[str, Any] = {"mode": mode}
        if not own.enabled:
            proposed["enabled"] = True
        return ProposedChange(
            "routing_rule",
            table="rules_routing",
            match={"pattern": own.pattern, "type": own.type},
            current=rule_columns(own),
            proposed=proposed,
        )
    return ProposedChange(
        "routing_rule",
        table="rules_routing",
        match={"pattern": pattern, "type": "glob"},
        current=None,
        proposed={"pattern": pattern, "type": "glob", "mode": mode, "note": note[:200]},
    )


def routing_mode(ctx: InsightContext, template: str) -> str | None:
    """The routing rule mode that applies to `template` today, or None."""
    row = ctx.rules.routing_rule_for(template)
    return str(row.mode) if row is not None and row.enabled else None


async def cache_change(
    ctx: InsightContext,
    template: str,
    *,
    raise_ttl: bool,
    raise_swr: bool,
    method: str = "GET",
    evidence: Evidence | None = None,
) -> ProposedChange | None:
    """A `rules_cache` change for one endpoint: a longer TTL (the tuner's, else `TTL_RAISE_FACTOR` times) and/or a
    longer stale-while-revalidate window (`SWR_RAISE_FACTOR` times the window it has now), covering the endpoint's
    `method`. None when the endpoint is "never cache" (a rule with TTL 0), when the cache never stores that method
    (`cache/policy.py`: GET always, POST unless `cache_post_requests` is off), or when nothing would change."""
    if method not in CACHEABLE_METHODS or (method == "POST" and str(ctx.setting("cache_post_requests")) == "off"):
        return None  # a rule would change nothing for this method
    covering, own = own_cache_rule(ctx, template)
    if covering is not None and int(covering.ttl) == 0:
        return None  # the admin chose "never cache this endpoint"
    current_ttl = effective_ttl(ctx, covering)
    cap = min(float(ctx.setting("ttl_tuner_max_s")), float(MAX_CACHE_RULE_TTL_S))
    ttl = current_ttl
    if raise_ttl:
        tuned: int | None = None
        if ctx.flag("ttl_tuner_enabled"):
            samples = await ctx.samples(ctx.window(hours=float(ctx.setting("request_sample_hours"))), [template])
            estimate = simulate.estimate_change_interval(samples)
            tuned = simulate.proposed_ttl(estimate, cap_s=cap)
            if evidence is not None and estimate.keys:
                evidence.details.setdefault("ttl_tuner", {})[template] = estimate.to_dict()
        if tuned is None:
            ttl = int(min(cap, current_ttl * TTL_RAISE_FACTOR))
        elif tuned > current_ttl:
            ttl = int(min(cap, tuned))
        ttl = max(ttl, current_ttl)  # bodies that change faster than the TTL keep it (the tuner said so)
    stored_swr = int(own.stale_ttl) if own is not None else 0
    rule_swr = int(covering.stale_ttl) if covering is not None else 0
    effective_swr = rule_swr if rule_swr > 0 else int(ctx.setting("cache_swr_seconds"))
    swr = stored_swr if own is not None else rule_swr
    if raise_swr:
        wanted = max(effective_swr * SWR_RAISE_FACTOR, round(ttl * SWR_SHARE_OF_TTL), 1)
        swr = int(min(MAX_CACHE_RULE_STALE_TTL_S, max(swr, wanted)))
    pattern = simulate.template_pattern(template)
    base = own if own is not None else covering
    methods = [str(m) for m in base.methods] if base is not None else ["GET"]
    if method not in methods:
        methods.append(method)
    methods_text = ",".join(methods)
    if own is not None:
        current = rule_columns(own)
        wanted_columns = (("ttl", ttl), ("stale_ttl", swr), ("methods", methods_text))
        proposed = {name: value for name, value in wanted_columns if current.get(name) != value}
        if not proposed:
            return None
        return ProposedChange(
            "rule_upsert",
            table="rules_cache",
            match={"pattern": own.pattern, "type": own.type},
            current=current,
            proposed=proposed,
        )
    if covering is not None and ttl == current_ttl and swr == rule_swr and method in covering.methods:
        return None
    return ProposedChange(
        "rule_upsert",
        table="rules_cache",
        match={"pattern": pattern, "type": "glob"},
        current=None,
        proposed={
            "pattern": pattern,
            "type": "glob",
            "ttl": ttl,
            "stale_ttl": swr,
            "methods": methods_text,
            "origin": "recommendation",
        },
    )


async def dominant_method(ctx: InsightContext, window: Window, template: str) -> str:
    """The method most of the endpoint's requests used in the window (GET when it had none)."""
    methods = await ctx.by(window, "method", {"endpoint_template": template})
    return str(max(methods, key=lambda m: number(methods[m], "requests"))) if methods else "GET"


def change_summary(change: ProposedChange) -> str:
    """One short phrase for an explanation (`ttl 60 to 120 s` style)."""
    if change.kind == "rule_upsert" and change.table == "rules_cache":
        proposed = dict(change.proposed or {})
        current = dict(change.current or {})
        parts = []
        if "ttl" in proposed:
            parts.append(
                f"TTL {current.get('ttl', 'default')} to {proposed['ttl']} s" if current else f"TTL {proposed['ttl']} s"
            )
        if "stale_ttl" in proposed:
            parts.append(f"stale-while-revalidate {proposed['stale_ttl']} s")
        label = (change.match or {}).get("pattern", "")
        return f"{label}: " + ", ".join(parts)
    if change.kind == "routing_rule":
        return f"{(change.match or {}).get('pattern', '')}: {dict(change.proposed or {}).get('mode')}"
    if change.kind == "setting":
        return f"{change.key} {change.current} to {change.proposed}"
    if change.kind == "bucket_override":
        current = dict(change.current or {})
        proposed = dict(change.proposed or {})
        return f"{change.bucket_key} {current.get('per_min')} to {proposed.get('per_min')} per minute"
    if change.kind == "tarpit_category":
        return f"tarpit category {change.category} {change.current} to {change.proposed}"
    return change.target


def probe_text(meta: Mapping[str, Any] | None) -> str:
    """The credential's status and last probe, as a sentence end (never the credential itself)."""
    if not meta:
        return "no credential status is recorded."
    probe = meta.get("last_probe_result")
    if isinstance(probe, Mapping):
        answer = f"{probe.get('result')} (HTTP {probe.get('status')})"
    else:
        answer = str(probe or "nothing yet")
    return f"its status is {meta.get('status')} and its last probe answered {answer}."


def timeline(points: Mapping[int, Mapping[str, Any]], *names: str) -> dict[str, Any]:
    """`{minute (ISO): value}` (one measure) or `{minute: {measure: value}}`, the newest `TIMELINE_POINTS`."""
    out: dict[str, Any] = {}
    for minute, values in sorted(points.items())[-TIMELINE_POINTS:]:
        if len(names) == 1:
            out[str(iso(minute))] = int(number(values, names[0]))
        else:
            out[str(iso(minute))] = {name: int(number(values, name)) for name in names}
    return out


async def fill_history(ctx: InsightContext, key: str, window: Window) -> dict[str, dict[str, float]]:
    """A bucket's fill history (plan 7.3, parity row 77) by hour: attempts, rejections and the peak fill."""
    hours: dict[int, list[float]] = {}
    for row in await ctx.bucket_history(key, window):
        start = int(row["bucket_start"])
        acc = hours.setdefault(start - start % HOUR_S, [0.0, 0.0, 0.0])
        acc[0] += float(row["attempts"] or 0)
        acc[1] += float(row["rejections"] or 0)
        acc[2] = max(acc[2], float(row["fill_pct_peak"] or 0))
    return {
        str(iso(hour)): {"attempts": a, "rejections": r, "fill_pct_peak": f}
        for hour, (a, r, f) in sorted(hours.items())[-HISTORY_HOURS:]
    }


# -------------------------------------------------------------------------------------------- buckets


def bucket_rate(ctx: InsightContext, key: str) -> float | None:
    """The rate (per minute) a bucket runs at: its override row or default, or its setting; None if unknown."""
    if key.startswith(("endpoint:", "host:")):
        return float(ctx.bucket_limit(key)["per_min"])
    setting = EGRESS_BUCKET_SETTINGS.get(key)
    return float(ctx.setting(setting)) if setting is not None else None


def bucket_change(ctx: InsightContext, key: str, per_min: int) -> ProposedChange:
    """A `bucket_override` (endpoint and host keys) or the bucket's setting (egress and global keys)."""
    if key.startswith(("endpoint:", "host:")):
        current = ctx.bucket_limit(key)
        return ProposedChange(
            "bucket_override",
            bucket_key=key,
            current={"per_min": current["per_min"], "burst": current["burst"]},
            proposed={"per_min": per_min, "burst": current["burst"]},
        )
    return setting_change(ctx, EGRESS_BUCKET_SETTINGS[key], per_min)


def bucket_floor(ctx: InsightContext, key: str) -> float:
    """The lowest rate a cut may reach: `adaptive_min_per_min`, and for the credential bucket more than the probe
    reservation (the `validate_cross` rule `credential_probe_reserved_per_min` < `credential_bucket_per_min`)."""
    floor = float(ctx.setting("adaptive_min_per_min"))
    if key == egress_bucket_key(Egress.CREDENTIAL):
        floor = max(floor, float(ctx.setting("credential_probe_reserved_per_min")) + 1)
    return floor


def lowered_rate(ctx: InsightContext, key: str, current: float, cut_pct: float) -> int | None:
    """`current` cut by `cut_pct` percent with the 7.3 arithmetic (`adaptive.decreased_rate`), floored, rounded
    down to a whole rate; None when nothing would be lower."""
    floor = bucket_floor(ctx, key)
    value = math.floor(adaptive.decreased_rate(current, cut_pct, floor))
    value = max(value, math.ceil(floor))
    setting = EGRESS_BUCKET_SETTINGS.get(key)
    if setting is not None:
        value = int(clamp_setting(setting, value))
    return value if value < current else None


def raised_rate(ctx: InsightContext, key: str, current: float, raise_pct: float) -> int | None:
    """`current` raised by `raise_pct` percent (`adaptive.increased_rate`, capped by `adaptive_max_per_min`),
    rounded up to a whole rate; None when nothing would be higher."""
    ceiling = float(ctx.setting("adaptive_max_per_min"))
    value = math.ceil(adaptive.increased_rate(current, raise_pct, ceiling))
    setting = EGRESS_BUCKET_SETTINGS.get(key)
    if setting is not None:
        value = int(clamp_setting(setting, value))
    return value if value > current else None


def key_matches_429(key: str, template: str, host: str, egress: str) -> bool:
    """Whether a Roblox 429 on (template, host, egress) belongs to the bucket `key` (7.3 table)."""
    if key == GLOBAL_KEY:
        return True
    if key.startswith("endpoint:"):
        return key == f"endpoint:{template}"
    if key.startswith("host:"):
        return key == f"host:{host}"
    return key == egress_bucket_key(egress) if egress in UPSTREAM_EGRESSES else False


@dataclass(slots=True)
class TightBucket:
    """UP-BUCKET-TUNE's "too tight" verdict for one bucket key: clean of 429s, turning real demand away."""

    key: str
    attempts: int
    rejections: int
    fill_pct_peak: float
    clean_hours: float
    current: float
    proposed: int

    @property
    def rejection_pct(self) -> float:
        return pct(self.rejections, self.attempts)


def controller_manages(ctx: InsightContext, key: str) -> bool:
    """While `adaptive_rate_enabled` is 1, the 7.3 controller raises endpoint buckets that run at the default or at
    a rate it set itself (`upstream/adaptive.py`); a recommendation would only race it."""
    if not ctx.flag("adaptive_rate_enabled") or not key.startswith("endpoint:"):
        return False
    row = ctx.rules.upstream_limit(key)
    return row is None or row.origin == "adaptive"


async def tight_bucket(ctx: InsightContext, key: str) -> TightBucket | None:
    """Plan 7.3 bounded probing as UP-BUCKET-TUNE judges it: zero Roblox 429s on `key` for `clean_hours` and
    bucket rejections above `rejection_pct` of its attempts. UP-LATENCY and UP-QUEUE-SAT raise a bucket only on
    this evidence ("never as a latency fix alone")."""
    if controller_manages(ctx, key):
        return None
    tune = UpBucketTune()
    hours = tune.param(ctx, "clean_hours")
    window = ctx.window(hours=hours)
    summary = (await ctx.bucket_summary(window)).get(key)  # every key in one memoized read
    if not summary or not summary["attempts"] or not summary["rejections"]:
        return None  # a bucket that never turns anyone away is never raised: no evidence above it
    share = pct(summary["rejections"], summary["attempts"])
    if share <= tune.param(ctx, "rejection_pct"):
        return None
    counts = await ctx.roblox_429(window, group_by=("endpoint_template", "host", "egress"))
    if any(key_matches_429(key, str(t), str(h), str(e)) for (t, h, e) in counts):
        return None
    current = bucket_rate(ctx, key)
    if current is None:
        return None
    proposed = raised_rate(ctx, key, current, tune.param(ctx, "raise_pct"))
    if proposed is None:
        return None
    return TightBucket(
        key,
        int(summary["attempts"]),
        int(summary["rejections"]),
        float(summary["fill_pct_peak"]),
        hours,
        current,
        proposed,
    )


# ------------------------------------------------------------------------------------------ UP-429-HOST


@register
class Up429Host(Rule):
    """Roblox 429s are spread across many endpoints of one host.

    Fires for each Roblox host with at least `min_templates` endpoint templates that got a Roblox 429 (on the direct
    path or the credential) within the last `window_min` minutes: the limit is on the host, not on one endpoint.
    The recommendation lowers that host's bucket (a `bucket_override` for `host:<host>` only, never a global
    default): to 80% of the call rate that drew the 429s, at most the cut the adaptive controller makes
    (`adaptive_decrease_pct`). When the rotator is available (switched on, not parked, inside a configured monthly
    quota) and has fewer 429s than the direct path, it also shifts share to the rotator with a `prefer_rotator`
    routing rule for each affected endpoint. It never moves traffic onto the credential.
    """

    id = "UP-429-HOST"
    triggers = frozenset({"roblox_429_burst", "settings_change"})

    async def evaluate(self, ctx: InsightContext) -> list[Recommendation]:
        window = ctx.window(minutes=self.param(ctx, "window_min"))
        counts = await ctx.roblox_429(
            window, group_by=("host", "endpoint_template"), where={"egress": list(ACCOUNT_EGRESSES)}
        )
        by_host: dict[str, dict[str, int]] = {}
        for (host, template), n in counts.items():
            if real_template(template):
                by_host.setdefault(str(host), {})[str(template)] = n
        minimum = self.int_param(ctx, "min_templates")
        out: list[Recommendation] = []
        for host, templates in sorted(by_host.items()):
            if len(templates) >= minimum:
                out.append(await self._recommend(ctx, window, host, templates))
        return out

    async def _recommend(
        self, ctx: InsightContext, window: Window, host: str, templates: Mapping[str, int]
    ) -> Recommendation:
        total = sum(templates.values())
        key = ctx.host_bucket(host)
        current = ctx.bucket_limit(key)
        # Calls from the server IP (direct and credential): the ones Roblox limited, so the rate that drew the 429s.
        minutes = await ctx.per_minute(window, {"host": host, "egress": list(ACCOUNT_EGRESSES)})
        limited = await ctx.roblox_429(
            window, group_by=("host",), per_minute=True, where={"host": host, "egress": list(ACCOUNT_EGRESSES)}
        )
        limited_minutes = sorted({int(minute) for (minute, _host) in limited})
        peak = max((number(minutes.get(m), "upstream_calls") for m in limited_minutes), default=0.0)
        evidence = Evidence(window_from=window.start, window_to=window.end, sample_size=total)
        evidence.add("roblox_429", total, "responses")
        evidence.add("templates_with_429", len(templates), "endpoints")
        evidence.add("host_bucket_per_min", current["per_min"], "per minute")
        evidence.add("peak_calls_per_min_with_429", peak, "per minute")
        evidence.details["per_template_429"] = dict(sorted(templates.items(), key=lambda kv: -kv[1])[:MAX_LISTED])
        evidence.details["host"] = host
        evidence.links.extend(endpoint_link(t) for t in sorted(templates)[:NAMES_SHOWN])

        changes: list[ProposedChange] = []
        cut = lowered_rate(ctx, key, current["per_min"], float(ctx.setting("adaptive_decrease_pct")))
        proposed = cut
        if peak and cut is not None:
            # The rate that drew the 429s, with the same headroom UP-429-ENDPOINT keeps (11.5).
            at_peak = max(math.ceil(bucket_floor(ctx, key)), math.floor(peak * BUCKET_HEADROOM))
            proposed = min(cut, at_peak)
        if proposed is not None and proposed < current["per_min"]:
            changes.append(bucket_change(ctx, key, proposed))
            evidence.add("proposed_host_bucket_per_min", proposed, "per minute")

        rotator = await rotator_status(ctx)
        evidence.details["rotator"] = rotator.to_dict()
        shifted = await self._rotator_share(ctx, window, host, total, rotator, templates, evidence)
        changes.extend(shifted[: MAX_CHANGES - len(changes)])

        window_min = round((window.end - window.start) / 60)
        shown = sorted(templates)[:NAMES_SHOWN]
        names = ", ".join(shown) + (" and more" if len(templates) > len(shown) else "")
        explanation = (
            f"In the last {window_min} minutes Roblox answered {len(templates)} different {host} endpoints with "
            f"429 ({total:,} responses: {names}). When several endpoints of one host are limited together, Roblox is "
            "limiting the host as a whole, so slowing a single endpoint does not help. "
        )
        if proposed is not None and changes and changes[0].kind == "bucket_override":
            why = (
                f"{round(BUCKET_HEADROOM * 100)}% of the {peak:g} calls per minute that drew the 429s"
                if proposed != cut
                else f"the adaptive controller's {ctx.setting('adaptive_decrease_pct')}% cut"
            )
            explanation += (
                f"The host bucket {key} drops from {current['per_min']:g} to {proposed} calls per minute ({why})."
            )
        if shifted:
            explanation += (
                f" The rotator is available ({rotator.quota_used_pct}% of its monthly quota used) and drew fewer "
                "429s, so the affected endpoints prefer it until the host recovers."
            )
        elif rotator.reasons:
            explanation += f" No share moves to the rotator: {rotator.reasons[0]}."
        if not changes:
            changes.append(manual(f"Lower the request rate to {host} (its bucket is already at its floor)."))
        return self.recommendation(
            ctx,
            subject=key,
            title=f"Roblox is rate-limiting {len(templates)} endpoints of {host}",
            severity="warn",
            confidence="medium",
            explanation=explanation,
            evidence=evidence,
            changes=changes,
            expected_impact=(
                f"Host-level relief: calls to {host} stay under the rate that drew {total:,} Roblox 429s in "
                f"{window_min} minutes"
                + (", and part of them leave from rotator exits instead of the server IP." if shifted else ".")
            ),
            risk="low",
        )

    async def _rotator_share(
        self,
        ctx: InsightContext,
        window: Window,
        host: str,
        total: int,
        rotator: RotatorStatus,
        templates: Mapping[str, int],
        evidence: Evidence,
    ) -> list[ProposedChange]:
        """`prefer_rotator` routing rules for the affected endpoints when the rotator is available and healthier."""
        if not rotator.available:
            return []
        host_calls = number(
            await ctx.totals(window, {"host": host, "egress": list(ACCOUNT_EGRESSES)}), "upstream_calls"
        )
        hour = ctx.window(seconds=HOUR_S)
        rotator_calls = number(await ctx.totals(hour, {"egress": ROTATOR}), "upstream_calls")
        rotator_429 = sum((await ctx.roblox_429(hour, group_by=(), where={"egress": ROTATOR})).values())
        direct_rate = pct(total, max(host_calls, total))
        rotator_rate = pct(rotator_429, max(rotator_calls, rotator_429))
        evidence.add("host_429_rate_pct", round(direct_rate, 2), "percent")
        evidence.add("rotator_429_rate_pct_last_hour", round(rotator_rate, 2), "percent")
        if rotator_rate >= direct_rate:
            return []
        out: list[ProposedChange] = []
        note = f"UP-429-HOST: {host} is rate-limited on the server IP"
        for template in sorted(templates, key=lambda t: -templates[t]):
            if routing_mode(ctx, template) in ("direct_only", "rotator_only", "prefer_rotator"):
                continue  # an admin pinned it, or it already prefers the rotator
            change = routing_change(ctx, template, "prefer_rotator", note)
            if change is not None:
                out.append(change)
        return out


# ------------------------------------------------------------------------------------ UP-429-CREDENTIAL


@register
class Up429Credential(Rule):
    """Roblox is rate-limiting calls made with the credential.

    Fires when calls made with the Roblox account got at least `min_429s` Roblox 429s within the last day. Each one
    means Roblox is limiting the account itself, so the recommendation lowers `credential_bucket_per_min` (by
    `adaptive_decrease_pct`, always above the rate reserved for Roxy's own probes) and, for each limited endpoint
    whose allowlist row records that anonymous calls return the identical body, removes it from the credential
    allowlist. The credential is never replaced or switched (C1); `credential_bucket_per_min` is a global
    setting, so this is never applied automatically.
    """

    id = "UP-429-CREDENTIAL"
    triggers = frozenset({"roblox_429_burst", "credential_status"})

    async def evaluate(self, ctx: InsightContext) -> list[Recommendation]:
        window = ctx.window(seconds=CREDENTIAL_LOOKBACK_S)
        counts = await ctx.roblox_429(window, where={"egress": CREDENTIAL})
        total = sum(counts.values())
        if not total or total < self.int_param(ctx, "min_429s"):
            return []
        per_template = {str(t): n for (t,), n in counts.items()}
        rows = [r for r in await ctx.upstream_429_rows(window) if r.get("egress") == CREDENTIAL]
        evidence = Evidence(window_from=window.start, window_to=window.end, sample_size=total)
        evidence.add("credential_429", total, "responses")
        retry = [float(r["retry_after_s"]) for r in rows if r.get("retry_after_s") is not None]
        if retry:
            evidence.add("retry_after_max_s", max(retry), "seconds")
            evidence.add("retry_after_avg_s", round(sum(retry) / len(retry), 1), "seconds")
        last = max((int(r["at_ms"]) for r in rows), default=None)
        evidence.details["per_template_429"] = dict(sorted(per_template.items(), key=lambda kv: -kv[1])[:MAX_LISTED])
        evidence.details["last_429_at"] = iso(last / 1000) if last is not None else None
        bucket_key = egress_bucket_key(Egress.CREDENTIAL)
        fill = (await ctx.bucket_summary(window, [bucket_key])).get(bucket_key)
        if fill:
            evidence.add("credential_bucket_fill_peak_pct", fill["fill_pct_peak"], "percent")
            evidence.add("credential_bucket_rejections", fill["rejections"], "attempts")
        meta = await ctx.credential_meta()
        if meta:
            evidence.details["credential_status"] = meta.get("status")
        evidence.links.append("/admin/credential#budget")

        changes: list[ProposedChange] = []
        current = float(ctx.setting("credential_bucket_per_min"))
        cut = lowered_rate(ctx, bucket_key, current, float(ctx.setting("adaptive_decrease_pct")))
        if cut is not None and settings_valid(ctx, {"credential_bucket_per_min": cut}):
            changes.append(setting_change(ctx, "credential_bucket_per_min", cut))
        removed: list[str] = []
        for template in sorted(per_template, key=lambda t: -per_template[t]):
            row = ctx.rules.credential_rule_for(template, "GET")
            if row is None or not row.identical_anonymous or len(changes) >= MAX_CHANGES:
                continue
            removed.append(template)
            changes.append(
                ProposedChange(
                    "credential_allowlist_remove",
                    table="credential_allowlist",
                    match={"pattern": row.pattern, "type": row.type},
                    current=rule_columns(row),
                )
            )
        if not changes:
            changes.append(
                manual("Reduce the allowlisted credential traffic: the credential bucket is already at its floor.")
            )
        names = ", ".join(sorted(per_template)[:NAMES_SHOWN])
        explanation = (
            f"In the last 24 hours Roblox answered {total:,} calls made with the Roblox account with 429 ({names}). "
            "The account is rate-limited separately from the server IP, and repeated limits put it at risk. "
        )
        if cut is not None:
            explanation += (
                f"Lowering credential_bucket_per_min from {current:g} to {cut} paces allowlisted calls below that "
                f"limit (Roxy's own probes keep their reserved {ctx.setting('credential_probe_reserved_per_min')} per "
                "minute). "
            )
        if removed:
            explanation += (
                f"{', '.join(removed)} returns the identical body without the account, so it should not use the "
                "credential at all."
            )
        return [
            self.recommendation(
                ctx,
                subject="credential",
                title=f"Roblox rate-limited the Roblox account {total:,} times in the last day",
                severity="critical",
                confidence="high",
                explanation=explanation,
                evidence=evidence,
                changes=changes,
                expected_impact=(
                    "Protects the account: fewer calls per minute carry the credential"
                    + (f", and {len(removed)} endpoint(s) stop using it." if removed else ".")
                ),
                risk="low",
            )
        ]


# -------------------------------------------------------------------------------------- UP-429-AMPLIFY


@register
class Up429Amplify(Rule):
    """Retries are multiplying Roblox 429s.

    Looks at the minutes of the last hour in which Roblox answered 429 (the 429 episodes) and divides the upstream
    calls by the caller requests that went upstream in those minutes. Above `calls_per_request`, retries add load
    exactly when Roblox is limiting Roxy: the recommendation turns `fallback_on_429` off when 429s were retried on
    another egress, and lowers `upstream_max_attempts` by one when 5xx or timeout retries happened in the episode.
    Both are global settings, so this is never applied automatically. The evidence includes the attempts
    histogram (calls by attempt number and kind).
    """

    id = "UP-429-AMPLIFY"
    triggers = frozenset({"roblox_429_burst", "settings_change"})

    async def evaluate(self, ctx: InsightContext) -> list[Recommendation]:
        window = ctx.window(seconds=EPISODE_LOOKBACK_S)
        limited = await ctx.roblox_429(window, group_by=(), per_minute=True)
        episode = sorted({int(key[0]) for key in limited})
        if not episode:
            return []
        minutes = await ctx.per_minute(window, WENT_UPSTREAM)
        requests = sum(number(minutes.get(m), "requests") for m in episode)
        calls = sum(number(minutes.get(m), "upstream_calls") for m in episode)
        if not requests:
            return []
        ratio = calls / requests
        if ratio <= self.param(ctx, "calls_per_request"):
            return []
        histogram: dict[str, int] = {}
        by_kind: dict[str, int] = {}
        for start, end in minute_runs(episode):
            for row in await ctx.attempts(span_window(start, end)):
                histogram[str(row["attempt"])] = histogram.get(str(row["attempt"]), 0) + int(row["count"])
                by_kind[str(row["kind"])] = by_kind.get(str(row["kind"]), 0) + int(row["count"])
        rotator = await ctx.per_minute(window, {"egress": ROTATOR})
        rotator_extra = sum(
            max(0.0, number(rotator.get(m), "upstream_calls") - number(rotator.get(m), "requests")) for m in episode
        )
        fallback_calls = max(by_kind.get("fallback_429", 0), int(rotator_extra))
        retry_calls = by_kind.get("retry_5xx", 0)
        total_429 = sum(limited.values())

        changes: list[ProposedChange] = []
        if ctx.flag("fallback_on_429") and fallback_calls:
            changes.append(setting_change(ctx, "fallback_on_429", 0))
        attempts_now = int(ctx.setting("upstream_max_attempts"))
        lowered = int(clamp_setting("upstream_max_attempts", attempts_now - 1))
        if retry_calls and lowered < attempts_now and settings_valid(ctx, {"upstream_max_attempts": lowered}):
            changes.append(setting_change(ctx, "upstream_max_attempts", lowered))
        if not changes:
            return []  # the extra calls are not retries these settings control (CSRF handshakes, redirects)

        evidence = Evidence(window_from=episode[0], window_to=episode[-1] + 60, sample_size=int(requests))
        evidence.add("calls_per_request", round(ratio, 3), "calls per request")
        evidence.add("upstream_calls", int(calls), "calls")
        evidence.add("requests_upstream", int(requests), "requests")
        evidence.add("roblox_429", total_429, "responses")
        evidence.add("episode_minutes", len(episode), "minutes")
        evidence.add("fallback_429_calls", fallback_calls, "calls")
        evidence.add("retry_5xx_calls", retry_calls, "calls")
        evidence.details["attempts_histogram"] = dict(sorted(histogram.items()))
        evidence.details["attempts_by_kind"] = dict(sorted(by_kind.items()))
        evidence.links.append("/admin/upstream#retries")
        extra = int(calls - requests)
        return [
            self.recommendation(
                ctx,
                subject="429_episodes",
                title=f"Retries made {ratio:.2f} upstream calls per request while Roblox was rate-limiting Roxy",
                severity="warn",
                confidence="high",
                explanation=(
                    f"In the {len(episode)} minutes of the last hour with Roblox 429s ({total_429:,} of them), "
                    f"Roxy made {int(calls):,} upstream calls for {int(requests):,} caller requests: {ratio:.2f} per "
                    f"request, above the {self.param(ctx, 'calls_per_request'):g} threshold. Retrying while Roblox "
                    "limits Roxy adds load and keeps the limit in place. " + proposal_text(changes)
                ),
                evidence=evidence,
                changes=changes,
                expected_impact=(
                    f"Up to {extra:,} fewer upstream calls per comparable episode (the retries made in this one), "
                    "so Roblox sees less load while it is limiting Roxy."
                ),
                risk="low",
            )
        ]


# ---------------------------------------------------------------------------------- UP-RETRYAFTER-IGNORED


@register
class UpRetryAfterIgnored(Rule):
    """Callers retry before the Retry-After time they were given.

    While an endpoint cools down after a Roblox 429, Roxy answers its callers 429 with a Retry-After. This rule
    counts, per client and cache key, the requests made inside that advertised time after the first answer (early
    retries), from the request samples of the last `window_min` minutes. When any client makes at least
    `min_retries` early retries, the recommendation turns on the tarpit category `upstream_cooldown_retry`
    (10.6, jitter) or, if that is already on, `throttle_strike_on_retry`. Roblox is not contacted during a
    cooldown either way, so this reduces Roxy's load, not Roblox 429s. Both switches are global, so this is never
    applied automatically; no client is banned.
    """

    id = "UP-RETRYAFTER-IGNORED"
    triggers = frozenset({"roblox_429_burst", "settings_change"})

    async def evaluate(self, ctx: InsightContext) -> list[Recommendation]:
        window = ctx.window(minutes=self.param(ctx, "window_min"))
        intervals = await self._intervals(ctx, window)
        if not intervals:
            return []
        samples = await ctx.samples(window, sorted(intervals))
        per_slot: dict[tuple[str, str, str, int], int] = {}
        for sample in samples:
            template = str(sample.get("endpoint_template") or "")
            client = sample.get("client_hash")
            if not client or sample.get("egress") != Egress.NONE.value or sample.get("cache_state") in CACHE_SERVES:
                continue  # only answers that made no call and served nothing: the caller was told to wait
            at = int(sample["at_ms"]) / 1000
            for index, (start, end) in enumerate(intervals.get(template, ())):
                if start <= at < end:
                    key = str(sample.get("key_id") or template)
                    slot = (str(client), key, template, index)
                    per_slot[slot] = per_slot.get(slot, 0) + 1
                    break
        per_key: dict[tuple[str, str], int] = {}
        keys: dict[str, set[str]] = {}
        for (client, key, template, _index), count in per_slot.items():
            # The first answer of each cooldown is when the client was told to wait; the rest came early.
            per_key[(client, key)] = per_key.get((client, key), 0) + count - 1
            keys.setdefault(client, set()).add(template)
        early: dict[str, int] = {}
        for (client, _key), n in per_key.items():
            early[client] = max(early.get(client, 0), n)  # 11.5: the same client on the same key
        minimum = self.int_param(ctx, "min_retries")
        offenders = {client: n for client, n in early.items() if n and n >= minimum}
        if not offenders:
            return []
        changes = self._changes(ctx)
        if not changes:
            return []  # both remedies 11.5 names are already in place
        worst = sorted(offenders.items(), key=lambda kv: -kv[1])
        evidence = Evidence(window_from=window.start, window_to=window.end, sample_size=sum(offenders.values()))
        evidence.add("clients_retrying_early", len(offenders), "clients")
        evidence.add("early_retries", sum(offenders.values()), "requests")
        evidence.add("most_early_retries_one_client", worst[0][1], "requests")
        evidence.add("request_sample_pct", float(ctx.setting("request_sample_pct")), "percent")
        evidence.details["clients"] = [
            {"client_hash": client, "early_retries": n, "endpoints": sorted(keys[client])[:NAMES_SHOWN]}
            for client, n in worst[:MAX_LISTED]
        ]
        evidence.links.append("/admin/protection#tarpit")
        minutes = round((window.end - window.start) / 60)
        return [
            self.recommendation(
                ctx,
                subject="early_retries",
                title=f"{len(offenders)} client(s) retry before the Retry-After they were given",
                severity="info",
                confidence="medium",
                explanation=(
                    f"In the last {minutes} minutes {len(offenders)} client(s) asked again for a key that was cooling "
                    f"down before the advertised Retry-After had passed, the busiest {worst[0][1]:,} times on one key "
                    "(counted in the request samples, so a lower bound when sampling is below 100%). Roxy does not "
                    "contact Roblox during a cooldown, so these requests cost only Roxy's own work. "
                    + proposal_text(changes)
                ),
                evidence=evidence,
                changes=changes,
                expected_impact=(
                    f"Less caller pressure during cooldowns: about {sum(offenders.values()):,} early requests per "
                    f"{minutes} minutes are slowed down. Roblox 429s do not change (Roblox is not contacted during a "
                    "cooldown)."
                ),
                risk="low",
            )
        ]

    async def _intervals(self, ctx: InsightContext, window: Window) -> dict[str, list[tuple[float, float]]]:
        """Per template, the times callers were told to wait: each Roblox 429 plus its Retry-After (clamped to the
        cooldown range), and each cooldown that is still active."""
        low, high = float(ctx.setting("cooldown_min_s")), float(ctx.setting("cooldown_max_s"))
        default = float(ctx.setting("cooldown_default_s"))
        earlier = span_window(window.start - high, window.end)
        spans: dict[str, list[tuple[float, float]]] = {}
        for row in await ctx.upstream_429_rows(earlier):
            template = str(row.get("endpoint_template") or "")
            if not real_template(template):
                continue
            wait = row.get("retry_after_s")
            seconds = min(high, max(low, float(wait if wait is not None else default)))
            start = int(row["at_ms"]) / 1000
            spans.setdefault(template, []).append((start, start + seconds))
        for row in await ctx.cooldowns():
            if row.key.startswith("endpoint:"):
                template = row.key[len("endpoint:") :].rsplit(":", 1)[0]
                spans.setdefault(template, []).append((float(row.set_at), row.until_ms / 1000))
        merged: dict[str, list[tuple[float, float]]] = {}
        for template, items in spans.items():
            out: list[tuple[float, float]] = []
            for start, end in sorted(items):
                if out and start <= out[-1][1]:
                    out[-1] = (out[-1][0], max(out[-1][1], end))
                else:
                    out.append((start, end))
            merged[template] = [(s, e) for s, e in out if e > window.start and s < window.end]
        return {template: items for template, items in merged.items() if items}

    def _changes(self, ctx: InsightContext) -> list[ProposedChange]:
        tarpit_on = ctx.flag("tarpit_enabled")
        category_on = ctx.flag(f"tarpit_on_{TARPIT_RETRY_CATEGORY}")
        strike_on = ctx.flag("throttle_strike_on_retry")
        if not category_on and tarpit_on:
            return [ProposedChange("tarpit_category", category=TARPIT_RETRY_CATEGORY, current=0, proposed=1)]
        if not strike_on:
            return [setting_change(ctx, "throttle_strike_on_retry", 1)]
        if not tarpit_on:
            # The category is useless while the whole tarpit is off; turning it on is the larger step, so last.
            out = [setting_change(ctx, "tarpit_enabled", 1)]
            if not category_on:
                out.append(ProposedChange("tarpit_category", category=TARPIT_RETRY_CATEGORY, current=0, proposed=1))
            return out
        return []


# --------------------------------------------------------------------------------------------- UP-4XX-SPIKE


@register
class Up4xxSpike(Rule):
    """Roblox is rejecting Roxy with 403, 401 or 400 more than usual.

    For each endpoint template with at least `min_calls` upstream calls in the last `window_min` minutes, compares
    the share of calls Roblox answered 400, 401 or 403 (CSRF challenges excluded) with the same share over the 7
    days before. It fires when the share exceeds `baseline_multiple` times the baseline with at least
    `min_responses` such answers. The fix depends on which path fails: an allowlisted credential endpoint that
    answers 401 is removed from the allowlist (check the credential too); when only the anonymous path fails and
    the credential path works for the same template, the owner decides about the allowlist (manual, never
    automatic); when every path fails, the endpoint gets a negative cache rule (so callers stop paying for the
    error) or, for answers the cache cannot store (401), an endpoint block with a clear message.
    """

    id = "UP-4XX-SPIKE"
    triggers = frozenset({"settings_change"})

    async def evaluate(self, ctx: InsightContext) -> list[Recommendation]:
        window = ctx.window(minutes=self.param(ctx, "window_min"))
        baseline = span_window(window.start - BASELINE_DAYS * DAY_S, window.start, "hour")
        now_calls = await ctx.by_template(window)
        now_rejected = await self._rejections(ctx, window)
        base_calls = await ctx.by_template(baseline)
        base_rejected = await self._rejections(ctx, baseline)
        min_calls = self.param(ctx, "min_calls")
        min_responses = self.param(ctx, "min_responses")
        multiple = self.param(ctx, "baseline_multiple")
        out: list[Recommendation] = []
        for template, rejected in sorted(now_rejected.items()):
            if not real_template(template):
                continue
            calls = max(number(now_calls.get(template), "upstream_calls"), rejected)
            if calls < min_calls or rejected < min_responses:
                continue
            rate = pct(rejected, calls)
            base_n = base_rejected.get(template, 0)
            base_rate = pct(base_n, max(number(base_calls.get(template), "upstream_calls"), base_n))
            if rate <= multiple * base_rate:
                continue
            out.append(await self._recommend(ctx, window, str(template), rejected, calls, rate, base_rate))
        return out

    async def _rejections(self, ctx: InsightContext, window: Window) -> dict[str, int]:
        """Relayed 400, 401 and 403 answers per template, minus the CSRF retries that were answered 403 again (a
        failed CSRF handshake reaches the caller as a 403 and belongs to UP-CSRF-LOOP)."""
        rows = await ctx.by(
            window, "endpoint_template", {"status": list(REJECTION_STATUSES), "source": list(RELAYED_SOURCES)}
        )
        csrf: dict[str, int] = {}
        for attempt in await ctx.attempts(window):
            if attempt["kind"] == "csrf_retry" and attempt["status"] == FORBIDDEN:
                template = str(attempt["endpoint_template"])
                csrf[template] = csrf.get(template, 0) + int(attempt["count"])
        return {
            str(t): max(0, int(number(row, "requests")) - csrf.get(str(t), 0))
            for t, row in rows.items()
            if number(row, "requests")
        }

    async def _paths(self, ctx: InsightContext, window: Window, template: str) -> dict[str, dict[str, int]]:
        """Per egress: calls (caller and Roxy's own), successes, rejections and 401s for the template."""
        base = {"endpoint_template": template, "source": list(COMPARED_SOURCES)}
        everything = await ctx.by(window, "egress", base)
        ok = await ctx.by(window, "egress", {**base, "status_class": "2xx"})
        rejected = await ctx.by(window, "egress", {**base, "status": list(REJECTION_STATUSES)})
        unauthorized = await ctx.by(window, "egress", {**base, "status": UNAUTHORIZED})

        def answered(row: Mapping[str, Any] | None) -> int:
            # A caller row counts its requests; Roxy's own calls have no requests, only `internal_calls`.
            return int(number(row, "requests") + number(row, "internal_calls"))

        return {
            str(egress): {
                "calls": int(number(row, "upstream_calls") + number(row, "internal_calls")),
                "ok": answered(ok.get(egress)),
                "rejected": answered(rejected.get(egress)),
                "unauthorized": answered(unauthorized.get(egress)),
            }
            for egress, row in everything.items()
            if egress in UPSTREAM_EGRESSES
        }

    async def _recommend(
        self,
        ctx: InsightContext,
        window: Window,
        template: str,
        rejected: int,
        calls: float,
        rate: float,
        base_rate: float,
    ) -> Recommendation:
        statuses = await ctx.by(
            window,
            "status",
            {"endpoint_template": template, "status": list(REJECTION_STATUSES), "source": list(RELAYED_SOURCES)},
        )
        split = {str(status): int(number(row, "requests")) for status, row in statuses.items()}
        paths = await self._paths(ctx, window, template)
        method = await dominant_method(ctx, window, template)
        evidence = Evidence(window_from=window.start, window_to=window.end, sample_size=rejected)
        evidence.add("rejections", rejected, "responses")
        evidence.add("upstream_calls", int(calls), "calls")
        evidence.add("rejection_rate_pct", round(rate, 2), "percent")
        evidence.add("baseline_rate_pct", round(base_rate, 2), "percent")
        evidence.add("ratio_to_baseline", round(rate / base_rate, 2) if base_rate else None)
        evidence.details["status_split"] = split
        evidence.details["paths"] = paths
        evidence.details["method"] = method
        rejected_minutes = await ctx.per_minute(
            window,
            {"endpoint_template": template, "status": list(REJECTION_STATUSES), "source": list(RELAYED_SOURCES)},
        )
        evidence.details["timeline"] = timeline(rejected_minutes, "requests")
        evidence.links.append(endpoint_link(template))

        anonymous = {e: paths[e] for e in (DIRECT, ROTATOR) if e in paths}
        anon_rejected = sum(p["rejected"] for p in anonymous.values())
        cred = paths.get(CREDENTIAL, {"calls": 0, "ok": 0, "rejected": 0, "unauthorized": 0})
        allow_row = ctx.rules.credential_rule_for(template, method) or ctx.rules.credential_rule_for(template, "GET")
        dominant = max(split, key=lambda s: split[s]) if split else str(UNAUTHORIZED)
        changes: list[ProposedChange]
        if allow_row is not None and cred["unauthorized"]:
            branch = "credential_401"
            changes = [
                ProposedChange(
                    "credential_allowlist_remove",
                    table="credential_allowlist",
                    match={"pattern": allow_row.pattern, "type": allow_row.type},
                    current=rule_columns(allow_row),
                )
            ]
            meta = await ctx.credential_meta()
            explanation = (
                f"The allowlisted endpoint {template} answered {cred['unauthorized']:,} credential calls with 401 in "
                f"the last {round(window.span / 60)} minutes ({rate:.1f}% rejected against {base_rate:.1f}% over the "
                "previous 7 days). Removing it from the credential allowlist stops sending the account to an endpoint "
                "that refuses it. Check the credential too: " + probe_text(meta)
            )
        elif anon_rejected and cred["ok"] and not cred["rejected"]:
            branch = "anonymous_only"
            changes = [
                manual(
                    f"Decide whether {template} belongs on the credential allowlist: anonymous calls are refused "
                    "while calls with the account succeed. Roxy never adds an endpoint to the allowlist on its own."
                )
            ]
            explanation = (
                f"Roblox refused {anon_rejected:,} anonymous calls to {template} ({rate:.1f}% of calls, "
                f"{base_rate:.1f}% over the previous 7 days), while {cred['ok']:,} calls made with the account "
                "succeeded: the endpoint now needs a login. Whether the account may be used for it is the owner's "
                "decision (C1, D1), so nothing changes automatically."
            )
        else:
            branch = "every_path"
            change = await self._stop_paying(ctx, template, method, dominant)
            changes = [change]
            what = "a negative cache rule" if change.table == "rules_cache" else "an endpoint block"
            explanation = (
                f"Roblox rejected {rejected:,} of {int(calls):,} calls to {template} with {', '.join(sorted(split))} "
                f"in the last {round(window.span / 60)} minutes ({rate:.1f}%, against {base_rate:.1f}% over the "
                f"previous 7 days), and no path succeeds for it. {what.capitalize()} stops callers from paying a "
                "Roblox call for the same refusal; remove it once Roblox answers normally again."
            )
        evidence.details["branch"] = branch
        return self.recommendation(
            ctx,
            subject=template,
            title=f"Roblox rejects {rate:.0f}% of calls to {template} (usually {base_rate:.0f}%)",
            severity="warn",
            confidence="medium",
            explanation=explanation,
            evidence=evidence,
            changes=changes,
            expected_impact=(
                f"Fewer wasted calls: about {rejected:,} rejected calls per {round(window.span / 60)} minutes stop "
                "reaching Roblox, and the cause is named."
                if branch == "every_path"
                else "The cause is named; the account stops being sent where it is refused."
                if branch == "credential_401"
                else "The cause is named; the owner decides about the account."
            ),
            risk="medium" if branch == "every_path" else "low",
        )

    async def _stop_paying(self, ctx: InsightContext, template: str, method: str, status: str) -> ProposedChange:
        """A negative cache rule when the cache can store the refusal (7.7: 400, 403, 404, 410 on GET), else a
        block of the endpoint with a clear message."""
        pattern = simulate.template_pattern(template)
        if method == "GET" and status.isdigit() and int(status) in CACHEABLE_ERROR_STATUSES:
            covering, own = own_cache_rule(ctx, template)
            effective = int(own.negative_ttl) if own is not None and int(own.negative_ttl) > 0 else 0
            effective = effective or int(ctx.setting("cache_error_ttl_seconds"))
            negative = int(min(MAX_CACHE_RULE_TTL_S, max(effective * SWR_RAISE_FACTOR, effective_ttl(ctx, covering))))
            if own is not None and int(own.ttl) != 0:
                return ProposedChange(
                    "rule_upsert",
                    table="rules_cache",
                    match={"pattern": own.pattern, "type": own.type},
                    current=rule_columns(own),
                    proposed={"negative_ttl": negative},
                )
            if covering is None or int(covering.ttl) != 0:
                return ProposedChange(
                    "rule_upsert",
                    table="rules_cache",
                    match={"pattern": pattern, "type": "glob"},
                    current=None,
                    proposed={
                        "pattern": pattern,
                        "type": "glob",
                        "ttl": effective_ttl(ctx, covering),
                        "negative_ttl": negative,
                        "methods": "GET",
                        "origin": "recommendation",
                    },
                )
        existing = next((row for row in ctx.rules.endpoint_blocks if row.pattern == pattern), None)
        message = f"Roblox currently refuses this endpoint ({status}); Roxy blocks it until Roblox accepts it again."
        if existing is not None:
            return ProposedChange(
                "rule_upsert",
                table="rules_endpoint_block",
                match={"pattern": existing.pattern, "type": existing.type},
                current=rule_columns(existing),
                proposed={"enabled": True, "message": message},
            )
        return ProposedChange(
            "rule_upsert",
            table="rules_endpoint_block",
            match={"pattern": pattern, "type": "glob"},
            current=None,
            proposed={"pattern": pattern, "type": "glob", "message": message, "note": "UP-4XX-SPIKE"},
        )


# --------------------------------------------------------------------------------------------- UP-CSRF-LOOP


@register
class UpCsrfLoop(Rule):
    """The CSRF token handshake with Roblox keeps failing to settle.

    Roblox asks write requests (POST, PATCH, PUT, DELETE) for a CSRF token: a 403 with a new `x-csrf-token`, after
    which Roxy repeats the call once with the token. This rule fires when such retries exceed `retry_pct` percent of
    the write requests sent upstream in the last `window_min` minutes (cached tokens go stale: lower
    `csrf_token_cache_s`, back to its default or by half), and, whatever the share, for each endpoint whose retry
    got a second 403 with yet another token. If no retry on that endpoint ever succeeded, callers cannot succeed
    anonymously, and the endpoint gets a block with a clear message; otherwise the token cache is shortened.
    """

    id = "UP-CSRF-LOOP"
    triggers = frozenset({"settings_change"})

    async def evaluate(self, ctx: InsightContext) -> list[Recommendation]:
        window = ctx.window(minutes=self.param(ctx, "window_min"))
        retries: dict[str, int] = {}
        failed: dict[str, int] = {}
        egresses: dict[str, set[str]] = {}
        for row in await ctx.attempts(window):
            if row["kind"] != "csrf_retry" or not real_template(row["endpoint_template"]):
                continue
            template = str(row["endpoint_template"])
            retries[template] = retries.get(template, 0) + int(row["count"])
            egresses.setdefault(template, set()).add(str(row["egress"]))
            if row["status"] == FORBIDDEN:
                failed[template] = failed.get(template, 0) + int(row["count"])
        if not retries:
            return []
        writes = await ctx.by_template(window, {"method": list(WRITE_METHODS), "egress": list(UPSTREAM_EGRESSES)})
        total_writes = sum(number(row, "requests") for row in writes.values())
        total_retries = sum(retries.values())
        share = pct(total_retries, max(total_writes, total_retries))
        out: list[Recommendation] = []
        if share > self.param(ctx, "retry_pct"):
            rec = self._share(ctx, window, share, total_retries, total_writes, retries, writes, failed)
            if rec is not None:
                out.append(rec)
        for template, n in sorted(failed.items()):
            out.append(
                self._second_403(ctx, window, template, n, retries[template], writes.get(template), egresses[template])
            )
        return out

    def _token_cache_change(self, ctx: InsightContext) -> ProposedChange | None:
        """`csrf_token_cache_s` back to its default when it was raised above it, else halved."""
        current = int(ctx.setting("csrf_token_cache_s"))
        default = int(catalog.DEFAULTS["csrf_token_cache_s"])
        proposed = default if current > default else int(clamp_setting("csrf_token_cache_s", current // 2))
        if proposed >= current:
            return None
        return setting_change(ctx, "csrf_token_cache_s", proposed)

    def _share(
        self,
        ctx: InsightContext,
        window: Window,
        share: float,
        total_retries: int,
        total_writes: float,
        retries: Mapping[str, int],
        writes: Mapping[str, Mapping[str, Any]],
        failed: Mapping[str, int],
    ) -> Recommendation | None:
        change = self._token_cache_change(ctx)
        if change is None:
            return None
        evidence = Evidence(window_from=window.start, window_to=window.end, sample_size=int(total_writes))
        evidence.add("csrf_retries", total_retries, "calls")
        evidence.add("write_requests", int(total_writes), "requests")
        evidence.add("csrf_retry_pct", round(share, 2), "percent")
        evidence.add("csrf_token_cache_s", int(ctx.setting("csrf_token_cache_s")), "seconds")
        evidence.details["templates"] = [
            {
                "endpoint_template": t,
                "csrf_retries": n,
                "write_requests": int(number(writes.get(t), "requests")),
                "second_403": failed.get(t, 0),
            }
            for t, n in sorted(retries.items(), key=lambda kv: -kv[1])[:MAX_LISTED]
        ]
        evidence.links.append("/admin/upstream#retries")
        minutes = round(window.span / 60)
        return self.recommendation(
            ctx,
            subject="csrf_token_cache",
            title=f"{share:.0f}% of write requests needed a second call for a CSRF token",
            severity="warn",
            confidence="medium",
            explanation=(
                f"In the last {minutes} minutes {total_retries:,} of {int(total_writes):,} write requests sent to "
                "Roblox were answered 403 with a new CSRF token and had to be sent again. Roblox replaces its "
                f"tokens sooner than Roxy's cache keeps them ({ctx.setting('csrf_token_cache_s')} s), so cached "
                "tokens go stale. " + change_summary(change) + "."
            ),
            evidence=evidence,
            changes=[change],
            expected_impact=f"Fewer doubled calls: up to {total_retries:,} retries per {minutes} minutes avoided.",
            risk="low",
        )

    def _second_403(
        self,
        ctx: InsightContext,
        window: Window,
        template: str,
        failed: int,
        retries: int,
        writes: Mapping[str, Any] | None,
        egresses: set[str],
    ) -> Recommendation:
        never_settles = failed >= retries
        evidence = Evidence(window_from=window.start, window_to=window.end, sample_size=failed)
        evidence.add("second_403", failed, "calls")
        evidence.add("csrf_retries", retries, "calls")
        evidence.add("write_requests", int(number(writes, "requests")), "requests")
        evidence.details["egress"] = sorted(egresses)
        evidence.details["rotator_session_mode"] = ctx.setting("rotator_session_mode")
        evidence.links.append(endpoint_link(template))
        changes: list[ProposedChange] = []
        if never_settles:
            pattern = simulate.template_pattern(template)
            existing = next((row for row in ctx.rules.endpoint_blocks if row.pattern == pattern), None)
            message = "Roblox does not accept writes to this endpoint through Roxy right now; please try again later."
            if existing is None:
                changes.append(
                    ProposedChange(
                        "rule_upsert",
                        table="rules_endpoint_block",
                        match={"pattern": pattern, "type": "glob"},
                        current=None,
                        proposed={"pattern": pattern, "type": "glob", "message": message, "note": "UP-CSRF-LOOP"},
                    )
                )
            elif not existing.enabled:
                changes.append(
                    ProposedChange(
                        "rule_upsert",
                        table="rules_endpoint_block",
                        match={"pattern": existing.pattern, "type": existing.type},
                        current=rule_columns(existing),
                        proposed={"enabled": True},
                    )
                )
        if not changes:
            token = self._token_cache_change(ctx)
            changes.append(token or manual(f"Investigate why the CSRF handshake for {template} does not settle."))
        rotator_note = (
            " Its calls go through the rotator, where each call may leave from a different exit, and Roblox rejects a "
            "token fetched on another one."
            if ROTATOR in egresses
            else ""
        )
        return self.recommendation(
            ctx,
            subject=template,
            title=f"Writes to {template} get a second CSRF 403 with a new token",
            severity="warn",
            confidence="medium",
            explanation=(
                f"{failed:,} of {retries:,} CSRF retries to {template} in the last {round(window.span / 60)} minutes "
                "were answered 403 with yet another token: the handshake never settles and every such write costs two "
                f"calls for nothing.{rotator_note} "
                + (
                    "No retry succeeded, so callers cannot succeed this way; the block answers them at once."
                    if never_settles
                    else "Some retries succeeded, so the token cache is shortened instead."
                )
            ),
            evidence=evidence,
            changes=changes,
            expected_impact=f"Fewer doubled calls: about {2 * failed:,} calls per {round(window.span / 60)} minutes.",
            risk="medium" if never_settles else "low",
        )


# --------------------------------------------------------------------------------------------- UP-CHALLENGE


@register
class UpChallenge(Rule):
    """Roblox is answering with challenge or block pages.

    Counts upstream answers that carried a challenge header or an HTML page where the endpoint answers JSON, per
    endpoint and egress, over the last `window_min` minutes. At `min_pages` or more, Roblox is challenging that
    egress: the recommendation prefers the other anonymous egress for the endpoint (a `routing_rule`;
    `prefer_direct` when the rotator is challenged, `prefer_rotator` when the direct path is and the rotator is
    available), never the credential. Lowering the rate of the challenged egress is advice for the admin, never
    an automatic setting change.
    """

    id = "UP-CHALLENGE"
    triggers = frozenset({"settings_change"})

    async def evaluate(self, ctx: InsightContext) -> list[Recommendation]:
        window = ctx.window(minutes=self.param(ctx, "window_min"))
        pages: dict[tuple[str, str], dict[str, Any]] = {}
        for row in await ctx.attempts(window):
            if not (row["challenge"] or row["html_body"]) or not real_template(row["endpoint_template"]):
                continue
            slot = pages.setdefault(
                (str(row["endpoint_template"]), str(row["egress"])),
                {"pages": 0, "challenge": 0, "html": 0, "statuses": {}, "exits": set()},
            )
            count = int(row["count"])
            slot["pages"] += count
            slot["challenge"] += count if row["challenge"] else 0
            slot["html"] += count if row["html_body"] else 0
            status = str(row["status"]) if row["status"] is not None else "timeout"
            slot["statuses"][status] = slot["statuses"].get(status, 0) + count
            if row["exit_id"]:
                slot["exits"].add(str(row["exit_id"]))
        minimum = self.int_param(ctx, "min_pages")
        rotator: RotatorStatus | None = None
        out: list[Recommendation] = []
        for (template, egress), slot in sorted(pages.items()):
            if slot["pages"] < minimum:
                continue
            if egress == DIRECT and rotator is None:
                rotator = await rotator_status(ctx)
            out.append(self._recommend(ctx, window, template, egress, slot, rotator))
        return out

    def _recommend(
        self,
        ctx: InsightContext,
        window: Window,
        template: str,
        egress: str,
        slot: Mapping[str, Any],
        rotator: RotatorStatus | None,
    ) -> Recommendation:
        evidence = Evidence(window_from=window.start, window_to=window.end, sample_size=int(slot["pages"]))
        evidence.add("challenge_or_block_pages", slot["pages"], "responses")
        evidence.add("challenge_header", slot["challenge"], "responses")
        evidence.add("html_body", slot["html"], "responses")
        evidence.details["egress"] = egress
        evidence.details["statuses"] = dict(slot["statuses"])
        evidence.details["exits"] = sorted(slot["exits"])[:MAX_LISTED]
        evidence.links.append(endpoint_link(template))
        note = f"UP-CHALLENGE: Roblox challenges {egress} calls"
        change: ProposedChange | None = None
        advice = f"Lower the request rate of the {egress} path"
        if egress == ROTATOR:
            change = routing_change(ctx, template, "prefer_direct", note)
        elif (
            egress == DIRECT
            and rotator is not None
            and rotator.available
            and routing_mode(ctx, template) != "direct_only"
        ):
            change = routing_change(ctx, template, "prefer_rotator", note)
        changes = [change] if change is not None else [manual(f"{advice} for {template}; no other egress can take it.")]
        minutes = round(window.span / 60)
        return self.recommendation(
            ctx,
            subject=f"{template} via {egress}",
            title=f"Roblox answers {template} on the {egress} path with challenge or block pages",
            severity="warn",
            confidence="medium",
            explanation=(
                f"In the last {minutes} minutes {slot['pages']:,} answers to {template} on the {egress} path were "
                f"challenge or block pages ({slot['challenge']:,} with a challenge header, {slot['html']:,} HTML pages "
                "where the endpoint answers JSON). Callers get no usable answer from that path. "
                + (
                    f"The endpoint moves to the other anonymous egress ({change_summary(change)}). {advice} as well."
                    if change is not None
                    else "No other anonymous egress can take it, so the admin lowers that path's rate by hand."
                )
            ),
            evidence=evidence,
            changes=changes,
            expected_impact=f"The path is restored for {template}: about {slot['pages']:,} failed answers per "
            f"{minutes} minutes avoided.",
            risk="low",
        )


# ------------------------------------------------------------------------------------- UP-UA-EXPERIMENT


@register
class UpUaExperiment(Rule):
    """Which upstream User-Agent gets fewer Roblox 429s (the D23 experiment).

    While `ua_experiment_enabled` is 1, direct calls are split between `direct_user_agent` and
    `ua_experiment_alt_user_agent` by a hash of the cache key. Once both arms have at least `min_calls_per_arm`
    calls, the rule compares their Roblox 429 rates with a two-proportion test at the 95% level, and recommends the
    better User-Agent as `direct_user_agent` only when the difference is significant and the better one is not
    already in use. Evidence: each arm's 429 rate with its 95% confidence interval.
    """

    id = "UP-UA-EXPERIMENT"
    triggers = frozenset({"settings_change"})

    async def evaluate(self, ctx: InsightContext) -> list[Recommendation]:
        if not ctx.flag("ua_experiment_enabled"):
            return []
        data = await ua_experiment_arms(ctx)
        arms = [arm for arm in (data or {}).get("arms") or [] if int(arm.get("calls") or 0) > 0]
        if len(arms) != len(EXPERIMENT_ARMS):
            return []  # an arm without calls cannot be compared yet
        minimum = self.param(ctx, "min_calls_per_arm")
        if any(int(arm["calls"]) < minimum for arm in arms):
            return []
        current_ua = str(ctx.setting("direct_user_agent"))
        if current_ua not in {str(arm["user_agent"]) for arm in arms}:
            return []  # the experiment no longer describes the live setting
        rated = sorted(arms, key=lambda arm: int(arm["roblox_429"]) / int(arm["calls"]))
        better, worse = rated[0], rated[-1]
        z = two_proportion_z(
            int(better["roblox_429"]), int(better["calls"]), int(worse["roblox_429"]), int(worse["calls"])
        )
        if z < SIGNIFICANCE_Z or str(better["user_agent"]) == current_ua:
            return []
        evidence = Evidence(sample_size=min(int(arm["calls"]) for arm in arms))
        details = []
        for arm in arms:
            rate, low, high = proportion_interval(int(arm["roblox_429"]), int(arm["calls"]))
            details.append(
                {
                    "user_agent": arm["user_agent"],
                    "calls": int(arm["calls"]),
                    "roblox_429": int(arm["roblox_429"]),
                    "rate_pct": round(rate * 100, 3),
                    "ci95_pct": [round(low * 100, 3), round(high * 100, 3)],
                    "current": str(arm["user_agent"]) == current_ua,
                }
            )
        better_rate = int(better["roblox_429"]) / int(better["calls"])
        worse_rate = int(worse["roblox_429"]) / int(worse["calls"])
        evidence.add("current_429_rate_pct", round(worse_rate * 100, 3), "percent")
        evidence.add("candidate_429_rate_pct", round(better_rate * 100, 3), "percent")
        evidence.add("z", round(z, 2))
        evidence.details["arms"] = details
        evidence.details["source"] = (data or {}).get("source")
        evidence.links.append("/admin/upstream#routing")
        return [
            self.recommendation(
                ctx,
                subject="direct_user_agent",
                title="The experiment's alternative User-Agent draws fewer Roblox 429s",
                severity="info",
                confidence="medium",
                explanation=(
                    f"Over {int(better['calls']):,} and {int(worse['calls']):,} direct calls, the alternative "
                    f"User-Agent drew Roblox 429s on {better_rate:.2%} of calls against {worse_rate:.2%} for the "
                    f"current one; the difference is significant (z = {z:.1f}, 95% level). Making it the "
                    "direct_user_agent keeps the lower rate for all direct traffic."
                ),
                evidence=evidence,
                changes=[setting_change(ctx, "direct_user_agent", str(better["user_agent"]))],
                expected_impact=(
                    f"Lower 429 rate, measured: about {worse_rate:.2%} to {better_rate:.2%} of direct calls."
                ),
                risk="low",
            )
        ]


def two_proportion_z(hits_a: int, n_a: int, hits_b: int, n_b: int) -> float:
    """The pooled two-proportion z statistic of rate b over rate a (0 when it cannot be computed)."""
    if not n_a or not n_b:
        return 0.0
    pooled = (hits_a + hits_b) / (n_a + n_b)
    spread = math.sqrt(pooled * (1 - pooled) * (1 / n_a + 1 / n_b))
    return (hits_b / n_b - hits_a / n_a) / spread if spread else 0.0


def proportion_interval(hits: int, n: int) -> tuple[float, float, float]:
    """`(rate, low, high)`: the normal approximation interval at `SIGNIFICANCE_Z` (95%), clipped to [0, 1]."""
    rate = hits / n if n else 0.0
    half = SIGNIFICANCE_Z * math.sqrt(rate * (1 - rate) / n) if n else 0.0
    return rate, max(0.0, rate - half), min(1.0, rate + half)


# ----------------------------------------------------------------------------------------------- UP-5XX


@register
class Up5xx(Rule):
    """Roblox server errors (5xx) are spiking.

    Measures the share of upstream calls Roblox answered with a 5xx over the last `window_min` minutes. Each
    endpoint whose own share exceeds `rate_pct` gets a recommendation when it had at least `min_calls` calls, or
    when the whole window did and its overall share exceeds `rate_pct` too. The change shields callers on that
    endpoint: a longer stale-while-revalidate window on its cache rule (served at once while Roxy refreshes in the
    background), never a global cache default. Opening breakers sooner is noted for the admin.
    """

    id = "UP-5XX"
    triggers = frozenset({"breaker_open", "settings_change"})

    async def evaluate(self, ctx: InsightContext) -> list[Recommendation]:
        window = ctx.window(minutes=self.param(ctx, "window_min"))
        rows = await ctx.by_template(window)
        errors: dict[str, int] = {}
        for attempt in await ctx.attempts(window):
            if attempt["status"] in SERVER_ERRORS:
                template = str(attempt["endpoint_template"])
                errors[template] = errors.get(template, 0) + int(attempt["count"])
        failed = await ctx.by_template(window, {"reason_code": ReasonCode.UPSTREAM_5XX.value})
        for template, row in failed.items():
            errors[str(template)] = max(errors.get(str(template), 0), int(number(row, "upstream_calls")))
        if not errors:
            return []
        calls = {str(t): max(number(rows.get(t), "upstream_calls"), float(errors.get(str(t), 0))) for t in rows}
        for template, n in errors.items():
            calls[template] = max(calls.get(template, 0.0), float(n))
        total_calls = sum(calls.values())
        total_errors = sum(errors.values())
        threshold = self.param(ctx, "rate_pct")
        min_calls = self.param(ctx, "min_calls")
        overall = total_calls >= min_calls and pct(total_errors, total_calls) > threshold
        out: list[Recommendation] = []
        for template, n in sorted(errors.items(), key=lambda kv: (-kv[1], kv[0])):
            if not real_template(template) or not n or len(out) >= MAX_LISTED:
                continue
            rate = pct(n, calls[template])
            if rate <= threshold or not (calls[template] >= min_calls or overall):
                continue
            out.append(
                await self._recommend(ctx, window, template, n, calls[template], rate, total_errors, total_calls)
            )
        return out

    async def _recommend(
        self,
        ctx: InsightContext,
        window: Window,
        template: str,
        errors: int,
        calls: float,
        rate: float,
        total_errors: int,
        total_calls: float,
    ) -> Recommendation:
        calls_by_minute = await ctx.per_minute(window, {"endpoint_template": template})
        failing = await ctx.per_minute(
            window, {"endpoint_template": template, "reason_code": ReasonCode.UPSTREAM_5XX.value}
        )
        evidence = Evidence(window_from=window.start, window_to=window.end, sample_size=int(calls))
        evidence.add("roblox_5xx_calls", errors, "calls")
        evidence.add("upstream_calls", int(calls), "calls")
        evidence.add("roblox_5xx_rate_pct", round(rate, 2), "percent")
        evidence.add("all_endpoints_5xx_rate_pct", round(pct(total_errors, total_calls), 2), "percent")
        evidence.details["timeline_calls"] = timeline(calls_by_minute, "upstream_calls")
        evidence.details["timeline_failed_requests"] = timeline(failing, "requests")
        evidence.links.append(endpoint_link(template))
        method = await dominant_method(ctx, window, template)
        change = await cache_change(ctx, template, raise_ttl=False, raise_swr=True, method=method, evidence=evidence)
        changes = (
            [change]
            if change is not None
            else [
                manual(
                    f"Roblox is failing {template} and its answers cannot be cached; consider opening breakers sooner."
                )
            ]
        )
        minutes = round(window.span / 60)
        return self.recommendation(
            ctx,
            subject=template,
            title=f"Roblox answers {rate:.0f}% of calls to {template} with a server error",
            severity="warn",
            confidence="medium",
            explanation=(
                f"In the last {minutes} minutes Roblox answered {errors:,} of {int(calls):,} calls to {template} "
                f"with a 5xx error ({rate:.1f}%; {pct(total_errors, total_calls):.1f}% over every endpoint). A longer "
                "stale-while-revalidate window lets callers get the cached answer at once while Roxy retries in the "
                "background. "
                + (change_summary(change) + ". " if change is not None else "")
                + "If the errors last, lowering breaker_failure_threshold opens the breaker sooner."
            ),
            evidence=evidence,
            changes=changes,
            expected_impact=(
                f"Callers shielded: requests to {template} are served from the cache while Roblox fails "
                f"({errors:,} failed calls in {minutes} minutes)."
            ),
            risk="low",
        )


# --------------------------------------------------------------------------------------------- UP-TIMEOUT


@register
class UpTimeout(Rule):
    """Upstream requests are timing out.

    Measures, per egress, the share of upstream calls that ran out of time (`request_timeout`) without an answer
    over the last `window_min` minutes, and fires for each egress above `rate_pct`. On the rotator the fix is a
    lower `rotator_weight` (halved) or, when it is already 0, a `rotator_session_mode` that leaves a slow exit
    behind sooner. On the direct path (or the credential) it is a modest raise of `request_timeout` (by half, only
    as far as the request deadline allows); the Check Proxy Health button tests the network. All of these are
    global settings, so this is never applied automatically.
    """

    id = "UP-TIMEOUT"
    triggers = frozenset({"breaker_open", "settings_change"})

    async def evaluate(self, ctx: InsightContext) -> list[Recommendation]:
        window = ctx.window(minutes=self.param(ctx, "window_min"))
        timeouts: dict[str, int] = {}
        hosts: dict[str, dict[str, int]] = {}
        for attempt in await ctx.attempts(window):
            if attempt["status"] is None and attempt["egress"] in UPSTREAM_EGRESSES:
                egress = str(attempt["egress"])
                timeouts[egress] = timeouts.get(egress, 0) + int(attempt["count"])
                host = host_of(str(attempt["endpoint_template"]))
                hosts.setdefault(egress, {})[host] = hosts.setdefault(egress, {}).get(host, 0) + int(attempt["count"])
        failed = await ctx.by(window, "egress", {"reason_code": ReasonCode.UPSTREAM_TIMEOUT.value})
        for egress, row in failed.items():
            if egress in UPSTREAM_EGRESSES:
                timeouts[str(egress)] = max(timeouts.get(str(egress), 0), int(number(row, "upstream_calls")))
        if not timeouts:
            return []
        rows = await ctx.by(window, "egress")
        threshold = self.param(ctx, "rate_pct")
        out: list[Recommendation] = []
        for egress, n in sorted(timeouts.items()):
            calls = max(number(rows.get(egress), "upstream_calls"), float(n))
            rate = pct(n, calls)
            if n and rate > threshold:
                out.append(self._recommend(ctx, window, egress, n, calls, rate, hosts.get(egress, {})))
        return out

    def _recommend(
        self,
        ctx: InsightContext,
        window: Window,
        egress: str,
        timeouts: int,
        calls: float,
        rate: float,
        hosts: Mapping[str, int],
    ) -> Recommendation:
        evidence = Evidence(window_from=window.start, window_to=window.end, sample_size=int(calls))
        evidence.add("timed_out_calls", timeouts, "calls")
        evidence.add("upstream_calls", int(calls), "calls")
        evidence.add("timeout_rate_pct", round(rate, 2), "percent")
        evidence.add("request_timeout_s", float(ctx.setting("request_timeout")), "seconds")
        evidence.details["egress"] = egress
        evidence.details["per_host"] = dict(sorted(hosts.items(), key=lambda kv: -kv[1])[:MAX_LISTED])
        evidence.links.extend(["/admin/upstream#cooldowns", "/admin/health"])
        if egress == ROTATOR:
            changes = self._rotator_changes(ctx)
            cause = (
                "The timeouts happen on rotator calls: the provider's exits are slow or overloaded, so less traffic "
                "should go through them."
            )
        else:
            changes = self._timeout_changes(ctx)
            cause = (
                f"The timeouts happen on the {egress} path (the server's own connection). Roblox may be slow to "
                "answer, so a modestly longer request_timeout lets those answers arrive; if the network is the "
                "problem, the Check Proxy Health button shows it."
            )
        minutes = round(window.span / 60)
        return self.recommendation(
            ctx,
            subject=egress,
            title=f"{rate:.1f}% of {egress} calls to Roblox time out",
            severity="warn",
            confidence="medium",
            explanation=(
                f"In the last {minutes} minutes {timeouts:,} of {int(calls):,} {egress} calls ran out of time "
                f"({ctx.setting('request_timeout')} s) without an answer. {cause} " + proposal_text(changes)
            ).strip(),
            evidence=evidence,
            changes=changes,
            expected_impact=f"Fewer failures: about {timeouts:,} timed-out calls per {minutes} minutes on {egress}.",
            risk="low",
        )

    def _rotator_changes(self, ctx: InsightContext) -> list[ProposedChange]:
        weight = int(ctx.setting("rotator_weight"))
        if weight > 0:
            return [setting_change(ctx, "rotator_weight", math.floor(weight * WEIGHT_CUT_FACTOR))]
        mode = str(ctx.setting("rotator_session_mode"))
        # sticky_until_429 keeps an exit until Roblox answers it 429, so a slow exit is kept; `sticky` moves on after
        # rotator_sticky_seconds whatever happens, and `per_request` takes a new exit for every call.
        following = {"sticky_until_429": "sticky", "sticky": "per_request"}.get(mode)
        if following is not None:
            return [setting_change(ctx, "rotator_session_mode", following)]
        return [manual("The rotator's exits are slow with every session mode: check the provider's plan and region.")]

    def _timeout_changes(self, ctx: InsightContext) -> list[ProposedChange]:
        current = float(ctx.setting("request_timeout"))
        target = int(clamp_setting("request_timeout", math.floor(current * TIMEOUT_RAISE_FACTOR)))
        for value in range(target, int(current), -1):
            if settings_valid(ctx, {"request_timeout": value}):
                return [setting_change(ctx, "request_timeout", value)]
        return [
            manual("Check the server's network to Roblox (Check Proxy Health); request_timeout cannot rise further.")
        ]


# --------------------------------------------------------------------------------------------- UP-LATENCY


@dataclass(slots=True)
class LatencyView:
    """UP-LATENCY's reading of one window: overall percentiles plus per endpoint and per egress rows."""

    calls: float
    p50: float
    p95: float
    p99: float
    queue_p95: float
    per_template: Mapping[Any, Mapping[str, Any]] = field(default_factory=dict)
    rotator: Mapping[Any, Mapping[str, Any]] = field(default_factory=dict)
    direct: Mapping[Any, Mapping[str, Any]] = field(default_factory=dict)
    per_egress: Mapping[Any, Mapping[str, Any]] = field(default_factory=dict)


@register
class UpLatency(Rule):
    """Upstream responses are slow.

    Over the last `window_min` minutes (at least `min_calls` upstream calls), the latency of requests that went to
    Roblox fires the rule when its p95 exceeds `p95_ms` or its p99 exceeds `p99_ms`. The fix follows the cause:
    endpoints whose rotator calls are slow and faster on direct get a `prefer_direct` routing rule; when queue
    wait dominates (requests wait for a bucket slot), the endpoints that queue most get a longer TTL and
    stale-while-revalidate window (fewer calls need slots), and a bucket is raised only on UP-BUCKET-TUNE's
    evidence (no 429s for `clean_hours`, real demand above it), never as a latency fix alone; when Roblox itself
    is slow, the slowest endpoints get the longer TTL and SWR.
    """

    id = "UP-LATENCY"
    triggers = frozenset({"settings_change"})

    def minimum_evidence(self, ctx: InsightContext) -> int:
        return self.int_param(ctx, "min_calls")

    async def evaluate(self, ctx: InsightContext) -> list[Recommendation]:
        window = ctx.window(minutes=self.param(ctx, "window_min"))
        totals = await ctx.totals(window, WENT_UPSTREAM)
        view = LatencyView(
            calls=number(totals, "upstream_calls"),
            p50=number(totals, "p50_ms"),
            p95=number(totals, "p95_ms"),
            p99=number(totals, "p99_ms"),
            queue_p95=number(totals, "queue_wait_p95_ms"),
        )
        if view.calls < self.param(ctx, "min_calls"):
            return []
        p95_limit, p99_limit = self.param(ctx, "p95_ms"), self.param(ctx, "p99_ms")
        if not (view.p95 > p95_limit or view.p99 > p99_limit):
            return []
        view.per_template = await ctx.by_template(window, WENT_UPSTREAM)
        view.rotator = await ctx.by_template(window, {"egress": ROTATOR})
        view.direct = await ctx.by_template(window, {"egress": DIRECT})
        view.per_egress = await ctx.by(window, "egress", WENT_UPSTREAM)
        changes: list[ProposedChange] = []
        routed = self._rotator_slow(ctx, view, p95_limit, p99_limit)
        changes.extend(change for change in routed.values())
        queue_bound = view.queue_p95 >= QUEUE_DOMINANCE * view.p95
        candidates = self._candidates(view, queue_bound, p95_limit, p99_limit, exclude=set(routed))
        if not candidates and not routed:
            candidates = self._slowest(view, exclude=set())
        evidence = Evidence(window_from=window.start, window_to=window.end, sample_size=int(view.calls))
        for template in candidates:
            if len(changes) >= MAX_CHANGES:
                break
            method = await dominant_method(ctx, window, template)
            change = await cache_change(ctx, template, raise_ttl=True, raise_swr=True, method=method, evidence=evidence)
            if change is not None:
                changes.append(change)
            if queue_bound:
                for key in (ctx.endpoint_bucket(template), ctx.host_bucket(host_of(template))):
                    tight = await tight_bucket(ctx, key)
                    if tight is not None and len(changes) < MAX_CHANGES:
                        changes.append(bucket_change(ctx, key, tight.proposed))
        evidence.add("upstream_calls", int(view.calls), "calls")
        evidence.add("p50_ms", round(view.p50), "ms")
        evidence.add("p95_ms", round(view.p95), "ms")
        evidence.add("p99_ms", round(view.p99), "ms")
        evidence.add("queue_wait_p95_ms", round(view.queue_p95), "ms")
        evidence.add("queue_wait_share_of_p95", round(view.queue_p95 / view.p95, 3) if view.p95 else None)
        evidence.details["per_egress_p95_ms"] = {str(e): number(row, "p95_ms") for e, row in view.per_egress.items()}
        evidence.details["slow_endpoints"] = [
            {
                "endpoint_template": t,
                "calls": int(number(view.per_template.get(t), "upstream_calls")),
                "p95_ms": number(view.per_template.get(t), "p95_ms"),
                "queue_wait_p95_ms": number(view.per_template.get(t), "queue_wait_p95_ms"),
            }
            for t in [*routed, *candidates][:MAX_LISTED]
        ]
        evidence.links.append("/admin/upstream#queue")
        if routed:
            cause = "the rotator is slow for some endpoints that answer quickly on direct"
        elif queue_bound:
            cause = "most of the time is spent waiting in Roxy's queue for a bucket slot"
        else:
            cause = "Roblox itself answers slowly"
        if not changes:
            changes.append(manual("The slow endpoints cannot be cached; check them on the Upstream page."))
        queue_text = (
            f"queue wait was {view.queue_p95:,.0f} ms at p95"
            if view.queue_p95 > WAIT_RESOLUTION_MS
            else f"queue wait was under {WAIT_RESOLUTION_MS:g} ms at p95"
        )
        minutes = round(window.span / 60)
        return [
            self.recommendation(
                ctx,
                subject="upstream_latency",
                title=f"Upstream responses are slow: p95 {view.p95:,.0f} ms, p99 {view.p99:,.0f} ms",
                severity="warn",
                confidence="medium",
                explanation=(
                    f"Over the last {minutes} minutes the {int(view.calls):,} requests that went to Roblox took "
                    f"{view.p95:,.0f} ms at p95 and {view.p99:,.0f} ms at p99 (limits {p95_limit:,.0f} and "
                    f"{p99_limit:,.0f} ms); {queue_text}. The main cause: {cause}. "
                    + proposal_text(changes)
                    + " A bucket is raised only when it had no Roblox 429s for UP-BUCKET-TUNE's clean period."
                ),
                evidence=evidence,
                changes=changes,
                expected_impact=(
                    "Faster responses without more 429 risk: fewer requests need an upstream slot, and slow paths "
                    "are avoided."
                ),
                risk="low",
            )
        ]

    def _rotator_slow(
        self, ctx: InsightContext, view: LatencyView, p95_limit: float, p99_limit: float
    ) -> dict[str, ProposedChange]:
        out: dict[str, ProposedChange] = {}
        for template, row in sorted(view.rotator.items(), key=lambda kv: -number(kv[1], "p95_ms")):
            if not real_template(template) or len(out) >= TOP_ENDPOINTS:
                continue
            slow = number(row, "p95_ms") > p95_limit or number(row, "p99_ms") > p99_limit
            direct = view.direct.get(template)
            faster_direct = direct is None or number(direct, "p95_ms") < number(row, "p95_ms")
            if not (slow and faster_direct and number(row, "upstream_calls")):
                continue
            if routing_mode(ctx, str(template)) == "rotator_only":
                continue  # an admin pinned it to the rotator
            change = routing_change(ctx, str(template), "prefer_direct", "UP-LATENCY: the rotator is slow here")
            if change is not None:
                out[str(template)] = change
        return out

    def _candidates(
        self, view: LatencyView, queue_bound: bool, p95_limit: float, p99_limit: float, *, exclude: set[str]
    ) -> list[str]:
        rows = [(str(t), row) for t, row in view.per_template.items() if real_template(t) and str(t) not in exclude]
        if queue_bound:
            ranked = [
                (number(row, "queue_wait_p95_ms") * number(row, "upstream_calls"), t)
                for t, row in rows
                if number(row, "queue_wait_p95_ms") > WAIT_RESOLUTION_MS
            ]
        else:
            ranked = [
                (number(row, "p95_ms") * number(row, "upstream_calls"), t)
                for t, row in rows
                if number(row, "p95_ms") > p95_limit or number(row, "p99_ms") > p99_limit
            ]
        return [t for _score, t in sorted(ranked, reverse=True)[:TOP_ENDPOINTS]]

    def _slowest(self, view: LatencyView, *, exclude: set[str]) -> list[str]:
        ranked = [
            (number(row, "p95_ms") * number(row, "upstream_calls"), str(t))
            for t, row in view.per_template.items()
            if real_template(t) and str(t) not in exclude and number(row, "p95_ms")
        ]
        return [t for _score, t in sorted(ranked, reverse=True)[:1]]


# -------------------------------------------------------------------------------------------- UP-QUEUE-SAT


@register
class UpQueueSat(Rule):
    """Requests wait too long or are dropped in the upstream queue.

    Over the last hour, fires when requests dropped from Roxy's upstream queue (the queue cap was full, or no
    bucket slot came within the wait budget) exceed `drop_pct` percent of the requests that needed an upstream
    call, or when the p95 queue wait of requests that went upstream exceeds `p95_wait_ms`. The endpoints with the
    most misses among those that queued get a longer TTL (fewer calls need a slot); a bucket is raised only where
    UP-BUCKET-TUNE's 429-free headroom exists. Global queue settings are never changed.
    """

    id = "UP-QUEUE-SAT"
    triggers = frozenset({"settings_change"})

    async def evaluate(self, ctx: InsightContext) -> list[Recommendation]:
        window = ctx.window(seconds=EPISODE_LOOKBACK_S)
        went = await ctx.totals(window, WENT_UPSTREAM)
        dropped_rows = await ctx.by_template(window, {"reason_code": list(DROP_REASONS)})
        dropped = sum(number(row, "requests") for row in dropped_rows.values())
        needed = number(went, "requests") + dropped
        if not needed:
            return []
        drop_pct = pct(dropped, needed)
        wait_p95 = number(went, "queue_wait_p95_ms")
        by_drops = drop_pct > self.param(ctx, "drop_pct")
        if not (by_drops or wait_p95 > self.param(ctx, "p95_wait_ms")):
            return []
        upstream = await ctx.by_template(window, WENT_UPSTREAM)
        ranked: list[tuple[float, str]] = []
        for template in set(upstream) | set(dropped_rows):
            if not real_template(template):
                continue
            drops = number(dropped_rows.get(template), "requests")
            queued = number(upstream.get(template), "queue_wait_p95_ms") > WAIT_RESOLUTION_MS
            if drops or queued:
                ranked.append((number(upstream.get(template), "requests") + drops, str(template)))
        top = [t for _misses, t in sorted(ranked, reverse=True)[:TOP_ENDPOINTS]]
        evidence = Evidence(window_from=window.start, window_to=window.end, sample_size=int(needed))
        changes: list[ProposedChange] = []
        for template in top:
            method = await dominant_method(ctx, window, template)
            change = await cache_change(
                ctx, template, raise_ttl=True, raise_swr=False, method=method, evidence=evidence
            )
            if change is not None:
                changes.append(change)
            for key in (ctx.endpoint_bucket(template), ctx.host_bucket(host_of(template))):
                tight = await tight_bucket(ctx, key)
                if tight is not None and len(changes) < MAX_CHANGES:
                    changes.append(bucket_change(ctx, key, tight.proposed))
        evidence.add("dropped_requests", int(dropped), "requests")
        evidence.add("drop_pct", round(drop_pct, 3), "percent")
        evidence.add("queue_wait_p95_ms", round(wait_p95), "ms")
        evidence.add("requests_needing_a_call", int(needed), "requests")
        evidence.details["dropped_by_reason"] = {
            str(reason): int(number(row, "requests"))
            for reason, row in (await ctx.by(window, "reason_code", {"reason_code": list(DROP_REASONS)})).items()
        }
        evidence.details["top_miss_endpoints"] = [
            {
                "endpoint_template": t,
                "upstream_requests": int(number(upstream.get(t), "requests")),
                "dropped": int(number(dropped_rows.get(t), "requests")),
                "queue_wait_p95_ms": number(upstream.get(t), "queue_wait_p95_ms"),
            }
            for t in top
        ]
        evidence.links.append("/admin/upstream#queue")
        if not changes:
            changes.append(manual("The queued endpoints cannot be cached longer; review their buckets by hand."))
        return [
            self.recommendation(
                ctx,
                subject="upstream_queue",
                title=(
                    f"The upstream queue dropped {drop_pct:.2f}% of requests in the last hour"
                    if by_drops
                    else f"Requests wait {wait_p95:,.0f} ms at p95 for an upstream slot"
                ),
                severity="warn",
                confidence="medium",
                explanation=(
                    f"In the last hour {int(dropped):,} of {int(needed):,} requests that needed an upstream call were "
                    f"dropped from the queue ({drop_pct:.2f}%), and requests that went upstream waited "
                    f"{wait_p95:,.0f} ms at p95 for a slot. Fewer misses on the busiest queued endpoints free slots. "
                    + proposal_text(changes)
                    + " Buckets rise only where they had no Roblox 429s for UP-BUCKET-TUNE's clean period."
                ),
                evidence=evidence,
                changes=changes,
                expected_impact=(
                    f"Fewer 429 busy answers to callers (about {int(dropped):,} dropped requests per hour now), and "
                    f"shorter waits than {wait_p95:,.0f} ms at p95."
                    if by_drops
                    else f"Shorter waits for an upstream slot than {wait_p95:,.0f} ms at p95, and fewer 429 busy "
                    "answers when demand grows."
                ),
                risk="low",
            )
        ]


# ------------------------------------------------------------------------------------------ UP-BUCKET-TUNE


@register
class UpBucketTune(Rule):
    """A pacing bucket is too tight or too loose (plan 7.3 bounded probing).

    Too loose: a Roblox 429 in the last hour attributed to the bucket by the 7.3 correlation check (several hosts
    on one egress within `cooldown_host_escalation_window_s` blame the egress; `cooldown_host_escalation_endpoints`
    templates of one host blame the host; otherwise the endpoint) lowers that bucket by `lower_pct` percent. Too
    tight: `clean_hours` without a Roblox 429 on the bucket and rejections above `rejection_pct` percent of its
    attempts (real demand above the cap) raise it by `raise_pct` percent. Only that key changes (an
    `upstream_limits` override, or the egress bucket's setting); a bucket that never turns anyone away is never
    raised. While the adaptive controller runs, buckets it manages itself are left to it.
    """

    id = "UP-BUCKET-TUNE"
    safe_auto = True
    triggers = frozenset({"roblox_429_burst", "settings_change"})

    async def evaluate(self, ctx: InsightContext) -> list[Recommendation]:
        out: list[Recommendation] = []
        loose = await self._too_loose(ctx)
        for key, rows in sorted(loose.items()):
            rec = await self._loose(ctx, key, rows)
            if rec is not None:
                out.append(rec)
        window = ctx.window(hours=self.param(ctx, "clean_hours"))
        for key in sorted(await ctx.bucket_summary(window)):
            if key in loose:
                continue
            tight = await tight_bucket(ctx, key)
            if tight is not None:
                out.append(await self._tight(ctx, tight))
        return out

    async def _too_loose(self, ctx: InsightContext) -> dict[str, list[dict[str, Any]]]:
        """Roblox 429s of the last hour, attributed to bucket keys the way the 7.3 adaptive controller does
        (`upstream/adaptive.py attribute`), over the 429 log instead of the live cooldown rows: the neighbors of a
        429 are the 429s on the same egress within `cooldown_host_escalation_window_s` either side of it."""
        window = ctx.window(seconds=EPISODE_LOOKBACK_S)
        span_ms = float(ctx.setting("cooldown_host_escalation_window_s")) * 1000
        threshold = int(ctx.setting("cooldown_host_escalation_endpoints"))
        rows = await ctx.upstream_429_rows(span_window(window.start - span_ms / 1000, window.end))
        by_egress: dict[str, list[dict[str, Any]]] = {}
        for row in rows[-MAX_ATTRIBUTED_429S:]:
            if row.get("egress") in ACCOUNT_EGRESSES:
                by_egress.setdefault(str(row["egress"]), []).append(row)
        out: dict[str, list[dict[str, Any]]] = {}
        for egress, items in by_egress.items():
            items.sort(key=lambda r: int(r["at_ms"]))
            times = [int(r["at_ms"]) for r in items]
            for row in items:
                at = int(row["at_ms"])
                if at < window.start * 1000:
                    continue  # a neighbor for attribution only
                near = items[bisect.bisect_left(times, at - span_ms) : bisect.bisect_right(times, at + span_ms)]
                hosts = {str(r["host"]) for r in near}
                templates = {str(r["endpoint_template"]) for r in near if r["host"] == row["host"]}
                if len(hosts) >= adaptive.EGRESS_ATTRIBUTION_MIN_HOSTS:
                    key = egress_bucket_key(egress)
                elif len(templates) >= threshold:
                    key = ctx.host_bucket(str(row["host"]))
                elif real_template(row["endpoint_template"]):
                    key = ctx.endpoint_bucket(str(row["endpoint_template"]))
                else:
                    continue
                out.setdefault(key, []).append(row)
        return out

    async def _loose(self, ctx: InsightContext, key: str, rows: Sequence[Mapping[str, Any]]) -> Recommendation | None:
        current = bucket_rate(ctx, key)
        if current is None:
            return None
        if ctx.flag("adaptive_rate_enabled") and key.startswith(("endpoint:", "host:")):
            row = ctx.rules.upstream_limit(key)
            first = min(int(r["at_ms"]) for r in rows) / 1000
            if row is not None and row.origin == "adaptive" and (row.updated_at or 0) >= first:
                return None  # the controller already cut it for these 429s
        proposed = lowered_rate(ctx, key, current, self.param(ctx, "lower_pct"))
        if proposed is None:
            return None
        change = bucket_change(ctx, key, proposed)
        if change.kind == "setting" and not settings_valid(ctx, {str(change.key): proposed}):
            return None
        window = ctx.window(seconds=EPISODE_LOOKBACK_S)
        templates = sorted({str(r["endpoint_template"]) for r in rows})
        evidence = Evidence(window_from=window.start, window_to=window.end, sample_size=len(rows))
        evidence.add("attributed_429", len(rows), "responses")
        evidence.add("current_per_min", current, "per minute")
        evidence.add("proposed_per_min", proposed, "per minute")
        evidence.details["attribution"] = {
            "kind": key.split(":", 1)[0],
            "templates": templates[:MAX_LISTED],
            "window_s": float(ctx.setting("cooldown_host_escalation_window_s")),
        }
        evidence.details["first_429_at"] = iso(min(int(r["at_ms"]) for r in rows) / 1000)
        evidence.details["fill_history"] = await fill_history(ctx, key, ctx.window(hours=HISTORY_HOURS))
        evidence.links.append("/admin/upstream#buckets")
        return self.recommendation(
            ctx,
            subject=key,
            title=f"Bucket {key} is too loose: lower it from {current:g} to {proposed} per minute",
            severity="warn",
            confidence="medium",
            explanation=(
                f"Roblox answered {len(rows):,} calls with 429 in the last hour, and the 7.3 correlation check "
                f"attributes them to {key} ({', '.join(templates[:NAMES_SHOWN])}). Lowering it by "
                f"{self.param(ctx, 'lower_pct'):g}% keeps its calls under the rate that drew them; no other bucket "
                "changes."
            ),
            evidence=evidence,
            changes=[change],
            expected_impact=f"Balanced throughput: fewer Roblox 429s on {key}, at {proposed} calls per minute.",
            risk="low",
        )

    async def _tight(self, ctx: InsightContext, tight: TightBucket) -> Recommendation:
        window = ctx.window(hours=tight.clean_hours)
        evidence = Evidence(window_from=window.start, window_to=window.end, sample_size=tight.attempts)
        evidence.add("attempts", tight.attempts, "attempts")
        evidence.add("rejections", tight.rejections, "attempts")
        evidence.add("rejection_pct", round(tight.rejection_pct, 3), "percent")
        evidence.add("fill_pct_peak", tight.fill_pct_peak, "percent")
        evidence.add("roblox_429", 0, "responses")
        evidence.add("current_per_min", tight.current, "per minute")
        evidence.add("proposed_per_min", tight.proposed, "per minute")
        evidence.details["fill_history"] = await fill_history(ctx, tight.key, window)
        evidence.links.append("/admin/upstream#buckets")
        return self.recommendation(
            ctx,
            subject=tight.key,
            title=f"Bucket {tight.key} is too tight: raise it from {tight.current:g} to {tight.proposed} per minute",
            severity="info",
            confidence="medium",
            explanation=(
                f"For the last {tight.clean_hours:g} hours Roblox sent no 429 for {tight.key}, while the bucket "
                f"turned away {tight.rejections:,} of {tight.attempts:,} attempts ({tight.rejection_pct:.2f}%): real "
                f"demand is above its rate. A raise of {self.param(ctx, 'raise_pct'):g}% is a bounded probe; a 429 "
                "lowers it again."
            ),
            evidence=evidence,
            changes=[bucket_change(ctx, tight.key, tight.proposed)],
            expected_impact=(
                f"Balanced throughput: about {tight.rejections:,} fewer busy answers per {tight.clean_hours:g} hours."
            ),
            risk="low",
        )


# --------------------------------------------------------------------------------------- UP-BREAKER-FLAP


@register
class UpBreakerFlap(Rule):
    """A circuit breaker keeps opening and closing.

    Counts the openings of each circuit breaker key (an endpoint or a host on one egress) in the last hour. More
    than `openings_per_hour` means the breaker probes too soon and opens again: the recommendation raises
    `breaker_open_s` (doubled, at most 600 s; a single global setting, so never applied automatically) and, for an
    endpoint no cache rule covers, adds one so callers get stale answers while the breaker is open.
    """

    id = "UP-BREAKER-FLAP"
    triggers = frozenset({"breaker_open"})

    async def evaluate(self, ctx: InsightContext) -> list[Recommendation]:
        window = ctx.window(seconds=EPISODE_LOOKBACK_S)
        openings: dict[str, list[int]] = {}
        for event in await ctx.events(["breaker_open"], window):
            key = str((event.get("detail") or {}).get("key") or "")
            if key:
                openings.setdefault(key, []).extend([int(event["at_ms"])] * int(event.get("count") or 1))
        threshold = self.param(ctx, "openings_per_hour")
        out: list[Recommendation] = []
        for key, times in sorted(openings.items()):
            if len(times) > threshold:
                out.append(await self._recommend(ctx, window, key, sorted(times)))
        return out

    async def _recommend(self, ctx: InsightContext, window: Window, key: str, times: list[int]) -> Recommendation:
        evidence = Evidence(window_from=window.start, window_to=window.end, sample_size=len(times))
        evidence.add("openings_last_hour", len(times), "openings")
        evidence.add("breaker_open_s", float(ctx.setting("breaker_open_s")), "seconds")
        evidence.details["timeline"] = [iso(at / 1000) for at in times[-MAX_LISTED:]]
        state = next((row for row in await ctx.breakers() if row.get("key") == key), None)
        if state is not None:
            evidence.details["state"] = {k: state.get(k) for k in ("state", "failures", "opened_at") if k in state}
        changes: list[ProposedChange] = []
        current = float(ctx.setting("breaker_open_s"))
        cap = min(breaker.MAX_OPEN_S, clamp_setting("breaker_open_s", breaker.MAX_OPEN_S))
        proposed = int(min(cap, current * BREAKER_OPEN_RAISE_FACTOR))
        if proposed > current:
            changes.append(setting_change(ctx, "breaker_open_s", proposed))
        template = key[len("endpoint:") :].rsplit(":", 1)[0] if key.startswith("endpoint:") else ""
        if template and real_template(template):
            evidence.links.append(endpoint_link(template))
            if ctx.cache_rule_for(template) is None:
                method = await dominant_method(ctx, window, template)
                change = await cache_change(
                    ctx, template, raise_ttl=False, raise_swr=True, method=method, evidence=evidence
                )
                if change is not None:
                    changes.append(change)
        if not changes:
            changes.append(manual(f"Find out why {key} keeps failing; breaker_open_s is already at its maximum."))
        return self.recommendation(
            ctx,
            subject=key,
            title=f"Circuit breaker {key} opened {len(times)} times in the last hour",
            severity="warn",
            confidence="medium",
            explanation=(
                f"The breaker for {key} opened {len(times)} times in the last hour: it closed after each "
                f"{current:g} s open period and failed again soon after. A longer open time lets the upstream recover "
                "before Roxy tries again"
                + (", and a cache rule lets callers get stale answers meanwhile." if len(changes) > 1 else ".")
            ),
            evidence=evidence,
            changes=changes,
            expected_impact="Stability: fewer open and close cycles and fewer failed calls between them.",
            risk="low",
        )


__all__ = [
    "BASELINE_DAYS",
    "EPISODE_LOOKBACK_S",
    "TightBucket",
    "Up4xxSpike",
    "Up5xx",
    "Up429Amplify",
    "Up429Credential",
    "Up429Host",
    "UpBreakerFlap",
    "UpBucketTune",
    "UpChallenge",
    "UpCsrfLoop",
    "UpLatency",
    "UpQueueSat",
    "UpRetryAfterIgnored",
    "UpTimeout",
    "UpUaExperiment",
    "cache_change",
    "lowered_rate",
    "minute_runs",
    "proportion_interval",
    "raised_rate",
    "tight_bucket",
    "two_proportion_z",
]
