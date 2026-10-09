"""Dry-run simulation (plan 11.3): replay request samples under a proposed change, deterministically.

What this is
    The 11.3 algorithms over `request_samples` rows:
    - `cache_replay`: a cache rule or TTL change. Walk the samples of the affected templates in time order keeping
      `key -> (stored_at, body_hash)`: a sample is a hit when its key is stored and younger than the TTL, a
      REVALIDATING hit plus one refresh call inside the stale-while-revalidate window, otherwise a miss that stores
      the entry. Reports the simulated hit ratio, avoided calls (requests minus simulated upstream calls) and the
      staleness risk (the share of simulated hits whose stored body differs from the real later fetch of the key).
    - `estimate_change_interval` and `proposed_ttl`: the TTL tuner (CACHE-TTL-TUNE, F10). For each key with at least
      two fetches with a body, a body change is placed halfway between the last fetch with the old body and the
      first with the new one; the intervals between consecutive changes of a key estimate how long a body lives,
      and the median over all keys is the proposal, capped by `ttl_tuner_max_s`.
    - `limit_replay`: a per-IP, place or endpoint rule limit, through the abuse limiter's own GCRA or fixed window
      (`abuse/limiter.py`), with a fresh state at the window start.
    - `bucket_replay`: an upstream bucket, through the upstream GCRA (`upstream/buckets.py`), reporting refusals
      and the simulated queue wait distribution.
    - `dry_run(ctx, recommendation)`: the report for one recommendation's changes over the default window (1 h).

Why it exists
    An admin should see "this would have saved about 2,500 upstream calls in the last hour, with 3% of hits served
    a body Roblox had already changed" before applying anything (plan P2, P4), and the numbers must come from the
    same code the proxy runs (cache keys, limiter, buckets), not from a second implementation that drifts.

How it works
    Pure functions over plain sample dicts (`at_ms`, `key_id`, `endpoint_template`, `method`, `body_hash`,
    `upstream_status`, `egress`, ...), sorted by `(at_ms, id)`, with no randomness, so the same samples always give
    the same report (unit-tested on fixtures, 19.10 row 11: within 10% of a replayed ground truth). Re-keying under
    new normalization flags or ignored parameters rebuilds keys with `cache/keys.py build_key` from the stored key
    text of each entry (`cache/read_observations.py key_texts`); a sample whose key text is no longer stored keeps
    its key id.

What to read next
    `roxy/insights/actions.py` (Preview calls `dry_run`), `roxy/insights/rules/core.py` (CACHE-TTL-TUNE and
    UP-429-ENDPOINT use the tuner).
"""

from __future__ import annotations

import bisect
import itertools
import json
import math
import re
import statistics
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass, field
from typing import TYPE_CHECKING, Any, Final
from urllib.parse import unquote

from roxy.abuse.limiter import LimiterRow, fixed, gcra
from roxy.cache.keys import build_key
from roxy.cache.keys import key_id as key_id_of
from roxy.cache.policy import post_allowed
from roxy.core.reasons import AuthClass
from roxy.insights.models import ProposedChange, Recommendation
from roxy.rules.match import compile_pattern
from roxy.rules.models import CacheRuleRow
from roxy.upstream.buckets import BucketSpec, gcra_advance_ms, gcra_earliest_ms

if TYPE_CHECKING:
    from roxy.insights.context import InsightContext

DEFAULT_WINDOW_S: Final = 3600
"""Plan 11.3: replay the last hour by default (up to `request_sample_hours` on request)."""
MAX_SAMPLES: Final = 500_000
"""Most samples one replay reads (P9; a day of samples at the default rate is far less for one template)."""

Sample = Mapping[str, Any]


# --------------------------------------------------------------------------------------------- cache replay


@dataclass(slots=True)
class CacheReplay:
    """What one cache replay found (plan 11.3)."""

    requests: int = 0
    upstream_calls: int = 0
    hits: int = 0
    revalidating: int = 0
    misses: int = 0
    uncacheable: int = 0
    stale_hits: int = 0
    compared_hits: int = 0

    @property
    def avoided_calls(self) -> int:
        return self.requests - self.upstream_calls

    @property
    def simulated_hit_ratio(self) -> float | None:
        lookups = self.hits + self.revalidating + self.misses
        return round((self.hits + self.revalidating) / lookups, 4) if lookups else None

    @property
    def staleness_risk(self) -> float | None:
        return round(self.stale_hits / self.compared_hits, 4) if self.compared_hits else None

    def to_dict(self) -> dict[str, Any]:
        out = asdict(self)
        out.update(
            avoided_calls=self.avoided_calls,
            simulated_hit_ratio=self.simulated_hit_ratio,
            staleness_risk=self.staleness_risk,
            sample_size=self.requests,
        )
        return out


def _ordered(samples: Iterable[Sample]) -> list[Sample]:
    return sorted(samples, key=lambda s: (int(s["at_ms"]), int(s.get("id") or 0)))


def cache_replay(
    samples: Iterable[Sample],
    *,
    ttl_s: float,
    swr_s: float = 0.0,
    cacheable: Callable[[Sample], bool] = lambda _s: True,
    key_of: Callable[[Sample], str | None] = lambda s: s.get("key_id"),
) -> CacheReplay:
    """The 11.3 cache replay (see the module docstring)."""
    ordered = _ordered(samples)
    report = CacheReplay()
    ttl_ms = max(0.0, float(ttl_s)) * 1000
    swr_ms = max(0.0, float(swr_s)) * 1000
    # The real fetches of each key, for the staleness check: (at_ms list, body_hash list).
    fetched: dict[str, tuple[list[int], list[str]]] = {}
    for sample in ordered:
        key = key_of(sample)
        body = sample.get("body_hash")
        if key is not None and body:
            times, bodies = fetched.setdefault(key, ([], []))
            times.append(int(sample["at_ms"]))
            bodies.append(str(body))
    stored: dict[str, tuple[int, str | None]] = {}
    for sample in ordered:
        report.requests += 1
        at = int(sample["at_ms"])
        key = key_of(sample)
        if key is None or ttl_ms <= 0 or not cacheable(sample):
            report.uncacheable += 1
            report.upstream_calls += 1
            continue
        body = str(sample["body_hash"]) if sample.get("body_hash") else None
        entry = stored.get(key)
        age = at - entry[0] if entry is not None else math.inf
        if entry is not None and age < ttl_ms:
            report.hits += 1
            _compare(report, fetched.get(key), at, entry[1])
        elif entry is not None and age < ttl_ms + swr_ms:
            report.revalidating += 1
            report.upstream_calls += 1  # the background refresh
            _compare(report, fetched.get(key), at, entry[1])
            stored[key] = (at, body or entry[1])
        else:
            report.misses += 1
            report.upstream_calls += 1
            stored[key] = (at, body)
    return report


def _compare(report: CacheReplay, fetched: tuple[list[int], list[str]] | None, at: int, served: str | None) -> None:
    """Staleness: compare the served body with the first real fetch of the key at or after `at`."""
    if fetched is None or served is None:
        return
    times, bodies = fetched
    index = bisect.bisect_left(times, at)
    if index >= len(times):
        return
    report.compared_hits += 1
    if bodies[index] != served:
        report.stale_hits += 1


# --------------------------------------------------------------------------------------------- TTL tuner


@dataclass(slots=True)
class ChangeEstimate:
    """The tuner's view of how long bodies live (plan 11.3, F10)."""

    keys: int = 0  # keys with at least two fetches carrying a body
    keys_with_changes: int = 0
    changes: int = 0
    intervals: list[float] = field(default_factory=list)  # seconds between consecutive changes of one key
    observed_s: float = 0.0  # summed span between first and last fetch of each key

    @property
    def never_changed(self) -> bool:
        """Bodies were fetched at least twice and never changed: the evidence says "longer than observed"."""
        return self.keys > 0 and self.changes == 0

    @property
    def change_interval_s(self) -> float | None:
        """The median interval between body changes, or None when it cannot be told."""
        if self.intervals:
            return float(statistics.median(self.intervals))
        if self.changes:
            return self.observed_s / self.changes  # one change per key: the rate is the best estimate left
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "keys": self.keys,
            "keys_with_changes": self.keys_with_changes,
            "changes": self.changes,
            "intervals": len(self.intervals),
            "observed_s": round(self.observed_s, 1),
            "change_interval_s": None if self.change_interval_s is None else round(self.change_interval_s, 1),
            "never_changed": self.never_changed,
        }


def estimate_change_interval(
    samples: Iterable[Sample], *, key_of: Callable[[Sample], str | None] = lambda s: s.get("key_id")
) -> ChangeEstimate:
    """The 11.3 tuner estimate over the fetches (samples with a body hash) of each key."""
    per_key: dict[str, list[tuple[int, str]]] = {}
    for sample in _ordered(samples):
        key = key_of(sample)
        body = sample.get("body_hash")
        if key is None or not body:
            continue
        per_key.setdefault(key, []).append((int(sample["at_ms"]), str(body)))
    estimate = ChangeEstimate()
    for fetches in per_key.values():
        if len(fetches) < 2:
            continue
        estimate.keys += 1
        estimate.observed_s += (fetches[-1][0] - fetches[0][0]) / 1000
        points: list[float] = []
        for (t0, h0), (t1, h1) in itertools.pairwise(fetches):
            if h0 != h1:
                points.append((t0 + t1) / 2000)  # the change happened somewhere between: take the midpoint
        if points:
            estimate.keys_with_changes += 1
            estimate.changes += len(points)
            estimate.intervals += [b - a for a, b in itertools.pairwise(points)]
    return estimate


def proposed_ttl(estimate: ChangeEstimate, *, cap_s: float) -> int | None:
    """The tuner's TTL: the median change interval capped by `ttl_tuner_max_s`, the cap itself when bodies never
    changed, or None when the samples cannot tell."""
    if estimate.never_changed:
        return int(cap_s)
    interval = estimate.change_interval_s
    if interval is None:
        return None
    return int(max(1, min(round(interval), cap_s)))


# ------------------------------------------------------------------------------------------- limit replay


@dataclass(slots=True)
class LimitReplay:
    requests: int = 0
    refused: int = 0
    refused_by_key: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "requests": self.requests,
            "refused_requests": self.refused,
            "refused_keys": len(self.refused_by_key),
            "top_refused": sorted(self.refused_by_key.items(), key=lambda kv: -kv[1])[:20],
        }


def limit_replay(
    arrivals: Iterable[tuple[int, str]], *, limit: int, window_s: float, algorithm: str = "gcra"
) -> LimitReplay:
    """Replay `(at_ms, limiter_key)` arrivals through the abuse limiter (fresh state at the window start)."""
    decide = gcra if algorithm == "gcra" else fixed
    rows: dict[str, LimiterRow] = {}
    report = LimitReplay()
    for at_ms, key in sorted(arrivals):
        report.requests += 1
        row = rows.get(key) or LimiterRow(key)
        decision = decide(row, limit, window_s, int(at_ms))
        if decision.admitted:
            rows[key] = decision.row
        else:
            report.refused += 1
            report.refused_by_key[key] = report.refused_by_key.get(key, 0) + 1
    return report


# ------------------------------------------------------------------------------------------ bucket replay


@dataclass(slots=True)
class BucketReplay:
    requests: int = 0
    refused: int = 0
    waits_ms: list[float] = field(default_factory=list)

    def percentile(self, q: float) -> float | None:
        if not self.waits_ms:
            return None
        ordered = sorted(self.waits_ms)
        index = min(len(ordered) - 1, max(0, math.ceil(q * len(ordered)) - 1))
        return round(ordered[index], 1)

    def to_dict(self) -> dict[str, Any]:
        return {
            "requests": self.requests,
            "refused_requests": self.refused,
            "queue_wait_p50_ms": self.percentile(0.5),
            "queue_wait_p95_ms": self.percentile(0.95),
            "queue_wait_max_ms": round(max(self.waits_ms), 1) if self.waits_ms else None,
        }


def bucket_replay(
    arrivals_ms: Iterable[int], *, per_min: float, burst: int, max_wait_ms: float, key: str = "bucket"
) -> BucketReplay:
    """Replay upstream call times through one GCRA bucket (`upstream/buckets.py`): a call waits for its slot, or is
    refused when the wait is longer than `max_wait_ms` (the interactive queue budget)."""
    spec = BucketSpec(key, float(per_min), int(burst))
    tat = 0.0
    report = BucketReplay()
    for at in sorted(int(a) for a in arrivals_ms):
        report.requests += 1
        slot = gcra_earliest_ms(tat, spec, float(at))
        wait = slot - at
        if wait > max_wait_ms:
            report.refused += 1
            continue
        report.waits_ms.append(wait)
        tat = gcra_advance_ms(tat, spec, slot)
    return report


# ---------------------------------------------------------------------------------------------- dry run


def template_pattern(template: str) -> str:
    """The glob that names one endpoint template in a rule: each `{placeholder}` segment becomes `*`."""
    parts = [("*" if part.startswith("{") and part.endswith("}") else part) for part in template.split("/")]
    return "/".join(parts)


def _matcher(change: ProposedChange) -> Callable[[str], bool] | None:
    match = change.match or {}
    pattern = match.get("pattern")
    if pattern is None and isinstance(change.proposed, Mapping):
        pattern = change.proposed.get("pattern")
    if not pattern:
        return None
    compiled = compile_pattern(str(pattern), str(match.get("type") or "glob"))
    return compiled.matches


def _cache_rule(change: ProposedChange) -> CacheRuleRow:
    """The proposed rule as the cache would hold it (current columns overlaid with the proposed ones)."""
    columns: dict[str, Any] = {"id": 0, "pattern": "", "type": "glob", "ttl": 0}
    if isinstance(change.current, Mapping):
        columns.update({k: v for k, v in change.current.items() if k in CacheRuleRow.model_fields})
    if isinstance(change.proposed, Mapping):
        columns.update({k: v for k, v in change.proposed.items() if k in CacheRuleRow.model_fields})
    match = change.match or {}
    columns["pattern"] = match.get("pattern") or columns.get("pattern") or ""
    columns["type"] = match.get("type") or columns.get("type") or "glob"
    if isinstance(columns.get("methods"), list | tuple):
        columns["methods"] = ",".join(str(m) for m in columns["methods"])
    return CacheRuleRow.model_validate(columns)


_VARY_RE: Final = re.compile(r" \^([a-z0-9-]+)=([^ ]*)")
_BODY_RE: Final = re.compile(r" #([0-9a-f]{64})")


def _rekey(
    rule: CacheRuleRow | None,
    texts: Mapping[str, Mapping[str, Any]],
    ignored: frozenset[str],
    *,
    rebuild: bool,
) -> Callable[[Sample], str | None]:
    """Key ids under a proposed rule or ignored-parameter set.

    Without `rebuild` (the proposal does not change how keys are built) every sample keeps its key id. Otherwise
    the key is rebuilt with `cache/keys.py build_key` from the entry's stored parts (method, host, path, kept
    parameters, the forwarded headers and the body hash written in the key text), so normalization flags and newly
    ignored parameters merge keys exactly as the cache would. A sample whose entry is no longer stored keeps its id.
    """

    def key_of(sample: Sample) -> str | None:
        key_id = sample.get("key_id")
        if key_id is None:
            return None
        stored = texts.get(str(key_id))
        if stored is None or not rebuild:
            return str(key_id)
        text = str(stored.get("key") or "")
        vary = [(name, unquote(value)) for name, value in _VARY_RE.findall(text)]
        body = _BODY_RE.search(text)
        rebuilt = build_key(
            str(stored.get("method") or sample.get("method") or "GET"),
            str(stored.get("host") or ""),
            str(stored.get("path") or ""),
            list(stored.get("params") or []),
            None,
            rule,
            ignored=ignored,
            auth_class=AuthClass(str(sample.get("auth_class") or "anon")),
            vary=vary,
        )
        # The request body is not stored; its hash in the old key text still separates POST bodies.
        return rebuilt.id if body is None else key_id_of(rebuilt.text + " #" + body.group(1))

    return key_of


def _flags_change(change: ProposedChange) -> bool:
    current = change.current.get("normalize_flags") if isinstance(change.current, Mapping) else None
    proposed = change.proposed.get("normalize_flags") if isinstance(change.proposed, Mapping) else None
    return proposed is not None and _flag_list(proposed) != _flag_list(current)


def _flag_list(value: Any) -> list[str]:
    if value is None or value == "":
        return []
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            return [value]
    return sorted(str(item) for item in value)


@dataclass(slots=True)
class DryRunReport:
    """The Preview panel of one recommendation (plan 11.3)."""

    available: bool
    window_s: int = DEFAULT_WINDOW_S
    sample_size: int = 0
    sample_pct: float = 100.0
    note: str = ""
    avoided_calls: int | None = None
    simulated_hit_ratio: float | None = None
    staleness_risk: float | None = None
    refused_requests: int | None = None
    queue_wait_p95_ms: float | None = None
    baseline_requests: int = 0
    baseline_upstream_calls: int = 0
    parts: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


SIMULATED_KINDS: Final[frozenset[str]] = frozenset({"rule_upsert", "bucket_override", "ignored_param_add", "setting"})


def can_simulate(rec: Recommendation) -> bool:
    """Whether `dry_run` models at least one of the recommendation's changes."""
    for change in rec.changes:
        if change.kind in ("bucket_override", "ignored_param_add"):
            return True
        if change.kind == "rule_upsert" and change.table in ("rules_cache", "rules_endpoint_limit"):
            return True
        if change.kind == "setting" and change.key in ("cache_post_requests", *LIMIT_SETTINGS):
            return True
    return False


async def dry_run(ctx: InsightContext, rec: Recommendation, *, window_s: int = DEFAULT_WINDOW_S) -> DryRunReport:
    """Replay the last `window_s` seconds of samples under the recommendation's changes (see the module docstring).

    Cache changes are replayed first; a bucket override then replays the upstream calls that would remain.
    """
    hours = float(ctx.setting("request_sample_hours"))
    window_s = int(min(max(60, window_s), hours * 3600))
    report = DryRunReport(available=can_simulate(rec), window_s=window_s)
    report.sample_pct = float(ctx.setting("request_sample_pct"))
    if report.sample_pct < 100:
        report.note = f"Samples cover {report.sample_pct:g}% of requests; counts are scaled estimates."
    if not report.available:
        return report
    window = ctx.window(seconds=window_s)
    post_mode = str(ctx.setting("cache_post_requests"))
    ignored: frozenset[str] = frozenset(ctx.rules.cache_ignored_params)
    added: set[str] = set()
    for change in rec.changes:
        if change.kind == "setting" and change.key == "cache_post_requests":
            post_mode = str(change.proposed)
        if change.kind == "ignored_param_add" and isinstance(change.proposed, Mapping):
            added.add(str(change.proposed.get("name")))
    ignored = ignored | added
    all_samples = await ctx.samples(window)
    templates = {str(s["endpoint_template"]) for s in all_samples}
    call_times: list[int] | None = None
    affected_templates: set[str] = set()
    plan: list[tuple[ProposedChange, set[str]]] = []
    for change in rec.changes:
        if change.kind == "rule_upsert" and change.table == "rules_cache":
            matches = _matcher(change)
            if matches is not None:
                plan.append((change, {t for t in templates if matches(t)}))
    if added and not plan:
        # An ignored parameter alone: replay every template under the rule it has today, with merged keys.
        plan = [(_current_rule_change(ctx, template), {template}) for template in sorted(templates)]
    for change, affected in plan:
        affected_templates |= affected
        rows = [s for s in all_samples if s["endpoint_template"] in affected]
        rule = _cache_rule(change)
        texts = await ctx.key_texts(str(s["key_id"]) for s in rows if s.get("key_id"))
        key_of = _rekey(rule, texts, ignored, rebuild=bool(added) or _flags_change(change))
        swr = rule.stale_ttl if rule.stale_ttl > 0 else int(ctx.setting("cache_swr_seconds"))

        def cacheable(sample: Sample, rule: CacheRuleRow = rule) -> bool:
            method = str(sample.get("method") or "GET").upper()
            if method == "GET":
                return "GET" in rule.methods
            if method == "POST":
                return post_allowed(str(sample["endpoint_template"]), rule, post_mode)
            return False

        replay = cache_replay(rows, ttl_s=rule.ttl, swr_s=swr, cacheable=cacheable, key_of=key_of)
        report.parts[change.target] = replay.to_dict()
        report.sample_size += replay.requests
        report.avoided_calls = (report.avoided_calls or 0) + replay.avoided_calls
        report.simulated_hit_ratio = replay.simulated_hit_ratio
        report.staleness_risk = replay.staleness_risk
        report.baseline_requests += replay.requests
        report.baseline_upstream_calls += sum(1 for s in rows if s.get("egress") not in (None, "none"))
        call_times = _call_times(rows, rule.ttl, cacheable, key_of)
    for change in rec.changes:
        limit = _limit_replay_for(ctx, change, all_samples, templates)
        if limit is not None:
            report.parts[change.target] = limit.to_dict()
            report.refused_requests = (report.refused_requests or 0) + limit.refused
            report.sample_size = max(report.sample_size, limit.requests)
    for change in rec.changes:
        if change.kind != "bucket_override" or not isinstance(change.proposed, Mapping) or not change.bucket_key:
            continue
        template = change.bucket_key.split(":", 1)[1] if change.bucket_key.startswith("endpoint:") else None
        rows = [s for s in all_samples if template is None or s["endpoint_template"] == template]
        times = (
            call_times
            if call_times is not None and template in affected_templates
            else [int(s["at_ms"]) for s in rows if s.get("egress") not in (None, "none")]
        )
        replay_b = bucket_replay(
            times,
            per_min=float(change.proposed.get("per_min") or 1),
            burst=int(change.proposed.get("burst") or 1),
            max_wait_ms=float(ctx.setting("queue_wait_interactive_ms")),
            key=change.bucket_key,
        )
        report.parts[change.target] = replay_b.to_dict()
        report.refused_requests = (report.refused_requests or 0) + replay_b.refused
        report.queue_wait_p95_ms = replay_b.percentile(0.95)
        report.sample_size = max(report.sample_size, replay_b.requests)
    return report


def _current_rule_change(ctx: InsightContext, template: str) -> ProposedChange:
    """A no-op cache change for one template: the rule (or global lifetime) the cache applies to it today."""
    rule = ctx.cache_rule_for(template)
    if rule is not None:
        columns = rule.model_dump()
        columns["methods"] = ",".join(rule.methods)
        return ProposedChange(
            "rule_upsert",
            table="rules_cache",
            match={"pattern": rule.pattern, "type": rule.type},
            current=columns,
            proposed={},
        )
    pattern = template_pattern(template)
    ttl = int(ctx.setting("cache_ttl_seconds"))
    return ProposedChange(
        "rule_upsert",
        table="rules_cache",
        match={"pattern": pattern, "type": "glob"},
        current=None,
        proposed={"pattern": pattern, "type": "glob", "ttl": ttl},
    )


LIMIT_SETTINGS: Final[dict[str, str]] = {
    "allowed_requests_per_minute": "client_hash",
    "place_limit_per_minute": "place",
}
"""Limit settings the replay models, and the sample column that is their limiter key (plan 11.3 "Limit change")."""


def _limit_replay_for(
    ctx: InsightContext, change: ProposedChange, samples: Sequence[Sample], templates: set[str]
) -> LimitReplay | None:
    """A per-IP or place limit setting, or an endpoint rule, replayed over the samples' arrival times."""
    if change.kind == "setting" and change.key in LIMIT_SETTINGS:
        key_column = LIMIT_SETTINGS[change.key]
        algorithm = str(ctx.setting("throttle_window_mode")) if key_column == "client_hash" else "gcra"
        arrivals = [(int(s["at_ms"]), str(s[key_column])) for s in samples if s.get(key_column)]
        return limit_replay(arrivals, limit=int(change.proposed), window_s=60, algorithm=algorithm)
    if change.kind == "rule_upsert" and change.table == "rules_endpoint_limit" and isinstance(change.proposed, Mapping):
        matches = _matcher(change)
        if matches is None:
            return None
        affected = {t for t in templates if matches(t)}
        scope = str(change.proposed.get("scope") or "ip")
        column = {"ip": "client_hash", "place": "place"}.get(scope)
        arrivals = [
            (int(s["at_ms"]), "global" if column is None else str(s.get(column) or ""))
            for s in samples
            if s["endpoint_template"] in affected
        ]
        # Endpoint rules use v1's fixed window (abuse/limiter.py `fixed`).
        return limit_replay(
            arrivals,
            limit=int(change.proposed.get("limit") or 1),
            window_s=float(change.proposed.get("period") or 60),
            algorithm="fixed",
        )
    return None


def _call_times(
    rows: Sequence[Sample],
    ttl_s: float,
    cacheable: Callable[[Sample], bool],
    key_of: Callable[[Sample], str | None],
) -> list[int]:
    """The times of the upstream calls left under a cache rule, for a bucket replay after it.

    A refresh inside the stale-while-revalidate window is a call at the same moment as the miss it replaces, so
    the call times are the same with or without SWR; only who waits for them differs.
    """
    times: list[int] = []
    stored: dict[str, int] = {}
    ttl_ms = ttl_s * 1000
    for sample in _ordered(rows):
        at = int(sample["at_ms"])
        key = key_of(sample)
        if key is None or ttl_ms <= 0 or not cacheable(sample):
            times.append(at)
            continue
        stored_at = stored.get(key)
        if stored_at is not None and at - stored_at < ttl_ms:
            continue
        times.append(at)
        stored[key] = at
    return times


__all__ = [
    "DEFAULT_WINDOW_S",
    "BucketReplay",
    "CacheReplay",
    "ChangeEstimate",
    "DryRunReport",
    "LimitReplay",
    "bucket_replay",
    "cache_replay",
    "can_simulate",
    "dry_run",
    "estimate_change_interval",
    "limit_replay",
    "proposed_ttl",
    "template_pattern",
]
