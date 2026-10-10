"""Dry-run simulation (plan 11.3): replay request samples under a proposed change, deterministically.

What this is
    The 11.3 algorithms over `request_samples` rows:
    - `cache_replay`: a cache rule or TTL change. Walk the samples of the affected templates in time order keeping
      `key -> (stored_at, body_hash, lifetime)`: a sample is a hit when its key is stored and younger than the
      entry's lifetime, a REVALIDATING hit plus one refresh call inside the stale-while-revalidate window, otherwise
      a miss. A miss stores the answer only when the real cache would keep it (`stored_as`, the status rows of
      `cache/policy.py store_decision`): a 2xx as content for the TTL, a Roblox 400, 403, 404 or 410 as a negative
      entry for the error lifetime, and nothing for a 5xx, a 429 or any other answer, so the next request calls
      Roblox again. Reports the simulated hit ratio, avoided calls (requests minus simulated upstream calls) and the
      staleness risk (the share of simulated hits whose stored body differs from the real later fetch of the key).
    - `estimate_change_interval` and `proposed_ttl`: the TTL tuner (CACHE-TTL-TUNE, F10). For each key with at least
      two fetches with a body, a body change is placed halfway between the last fetch with the old body and the
      first with the new one; the intervals between consecutive changes of a key estimate how long a body lives,
      and the median over all keys is the proposal, capped by `ttl_tuner_max_s`.
    - `limit_replay`: a per-IP, place or endpoint rule limit, through the abuse limiter's own GCRA or fixed window
      (`abuse/limiter.py`), with a fresh state at the window start. The per-IP limit is `allowed_requests_per_minute`
      per `throttle_reset_duration` seconds (`abuse/throttle.py`), the place limit `place_limit_per_minute` per 60 s
      (`abuse/checks/place_limit.py`).
    - `bucket_replay`: an upstream bucket, through the upstream GCRA (`upstream/buckets.py`), reporting refusals
      and the simulated queue wait distribution.
    - `template_pattern` and `template_match`: the pattern a rule uses to name an endpoint template. The first is the
      v1 glob (the template and every path below it); the second names exactly the template, for a proposal meant
      for one endpoint (`endpoint_scoped` tells whether a change touches one endpoint only, plan 11.2).
    - `dry_run(ctx, recommendation)`: the report for one recommendation's changes over the default window (1 h).

Why it exists
    An admin should see "this would have saved about 2,500 upstream calls in the last hour, with 3% of hits served
    a body Roblox had already changed" before applying anything (plan P2, P4), and the numbers must come from the
    same code the proxy runs (cache keys, store policy, limiter, buckets), not from a second implementation that
    drifts.

How it works
    Pure functions over plain sample dicts (`at_ms`, `key_id`, `endpoint_template`, `method`, `body_hash`,
    `upstream_status`, `egress`, ...), sorted by `(at_ms, id)`, with no randomness, so the same samples always give
    the same report (unit-tested on fixtures, 19.10 row 11: within 10% of a replayed ground truth). Re-keying under
    new normalization flags or ignored parameters rebuilds keys with `cache/keys.py build_key` from the stored key
    text of each entry (`cache/read_observations.py key_texts`); a sample whose key text is no longer stored keeps
    its key id.
    Below 100% sampling (`request_sample_pct` p) the samples are a p share of the requests, so `dry_run` scales its
    request and call counts by 100 / p (`DryRunReport.scale`) and says so in its note. A limit or bucket replay
    first thins its rate by the same share (a p sample of a client sending r requests a minute arrives at p x r), so
    the sample meets the limit the whole stream met, then scales the refusals. Ratios, waits and `sample_size` are
    never scaled; `parts` hold the unscaled replay of the samples.

What to read next
    `roxy/insights/actions.py` (Preview calls `dry_run`), `roxy/insights/rules/core.py` (CACHE-TTL-TUNE and
    UP-429-ENDPOINT use the tuner), `roxy/cache/policy.py` (the store policy the replay follows).
"""

from __future__ import annotations

import bisect
import functools
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
from roxy.config.constants import CACHEABLE_ERROR_STATUSES
from roxy.core.reasons import AuthClass
from roxy.insights.models import ProposedChange, Recommendation
from roxy.metrics.samples import reasons_from
from roxy.rules.match import PatternValidationError, compile_pattern, validate_pattern
from roxy.rules.models import CacheRuleRow
from roxy.upstream.buckets import BucketSpec, gcra_advance_ms, gcra_earliest_ms

if TYPE_CHECKING:
    from roxy.insights.context import InsightContext

DEFAULT_WINDOW_S: Final = 3600
"""Plan 11.3: replay the last hour by default (up to `request_sample_hours` on request)."""
MAX_SAMPLES: Final = 500_000
"""Most samples one replay reads (P9; a day of samples at the default rate is far less for one template)."""

Sample = Mapping[str, Any]


# ------------------------------------------------------------------------------------------- store policy

CONTENT: Final = "content"
NEGATIVE: Final = "negative"
CACHE_SERVE_STATES: Final[frozenset[str]] = frozenset({"HIT", "STALE", "REVALIDATING", "COALESCED"})
"""Cache states of a request the cache answered from an entry it had kept (`proxy/respond.py CACHE_SERVE_STATES`)."""


def stored_as(sample: Sample) -> str | None:
    """What the cache keeps from the answer a sample records (`cache/policy.py store_decision`, judged by status).

    A Roblox 2xx is `CONTENT`; a Roblox 400, 403, 404 or 410 is a `NEGATIVE` entry (kept only while the request has
    an error lifetime); anything else is None: a 5xx and every Roxy-side failure are never content, a 429 is at most
    a per-key marker that is never served, and other statuses are not cacheable. A sample without an upstream status
    is content only when the cache answered it (`cache_state` HIT, STALE, REVALIDATING or COALESCED: the entry it
    served had been kept) or it carries the hash of a body fetched from Roblox (`body_hash` is set only for a 2xx
    Roxy fetched); with MISS, OFF or no state and no body it is a request Roblox never answered (a connect error, a
    timeout), and `store_decision` keeps nothing for those (review round 4, finding LOGICFIX-4: reading them as
    content put an outage episode's dry run 25% over the real cache). (A CSRF 403 cannot be told from a sample;
    production keeps none, so that rare case reads high.)
    """
    status = sample.get("upstream_status")
    if status is None or status == "":
        served = str(sample.get("cache_state") or "").upper() in CACHE_SERVE_STATES
        return CONTENT if served or sample.get("body_hash") else None
    try:
        code = int(status)
    except (TypeError, ValueError):
        return None
    if 200 <= code < 300:
        return CONTENT
    if code in CACHEABLE_ERROR_STATUSES:
        return NEGATIVE
    return None


def _lifetime_ms(sample: Sample, ttl_ms: float, negative_ms: float) -> float:
    """How long the cache keeps this sample's answer (0: not at all)."""
    kind = stored_as(sample)
    if kind == CONTENT:
        return ttl_ms
    if kind == NEGATIVE:
        return negative_ms
    return 0.0


# --------------------------------------------------------------------------------------------- cache replay


@dataclass(slots=True)
class CacheReplay:
    """What one cache replay found (plan 11.3), in samples."""

    requests: int = 0
    upstream_calls: int = 0
    hits: int = 0
    revalidating: int = 0
    misses: int = 0
    uncacheable: int = 0
    stale_hits: int = 0
    compared_hits: int = 0
    not_stored: int = 0
    """Misses whose answer the cache would not keep (a 5xx, a 429, an error without an error lifetime)."""
    weighted_requests: float = 0.0
    """The requests the samples stand for: each counted for its `weight` (100 / the rate it was sampled at)."""
    weighted_calls: float = 0.0
    """The upstream calls among them, weighted the same way."""

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
        for name in ("weighted_requests", "weighted_calls"):  # `parts` are sample counts (DESIGN 14.9)
            out.pop(name, None)
        out.update(
            avoided_calls=self.avoided_calls,
            simulated_hit_ratio=self.simulated_hit_ratio,
            staleness_risk=self.staleness_risk,
            sample_size=self.requests,
        )
        return out


@dataclass(slots=True)
class _Stored:
    at: int
    body: str | None
    life_ms: float
    content: bool


def _ordered(samples: Iterable[Sample]) -> list[Sample]:
    return sorted(samples, key=lambda s: (int(s["at_ms"]), int(s.get("id") or 0)))


def cache_replay(
    samples: Iterable[Sample],
    *,
    ttl_s: float,
    swr_s: float = 0.0,
    negative_ttl_s: float = 0.0,
    cacheable: Callable[[Sample], bool] = lambda _s: True,
    key_of: Callable[[Sample], str | None] = lambda s: s.get("key_id"),
    weight: Callable[[Sample], float] = lambda _s: 1.0,
) -> CacheReplay:
    """The 11.3 cache replay (see the module docstring).

    `ttl_s` is the content lifetime (0 means "never cache": nothing is stored, errors included, as
    `cache/policy.py request_policy`), `swr_s` the stale-while-revalidate window of content entries and
    `negative_ttl_s` the error lifetime of a Roblox 400, 403, 404 or 410 (0: errors are not kept). `weight` is the
    number of requests a sample stands for (`weighted_requests`, `weighted_calls`); the counts stay sample counts.
    """
    ordered = _ordered(samples)
    report = CacheReplay()
    ttl_ms = max(0.0, float(ttl_s)) * 1000
    swr_ms = max(0.0, float(swr_s)) * 1000
    negative_ms = max(0.0, float(negative_ttl_s)) * 1000
    # The real fetches of each key, for the staleness check: (at_ms list, body_hash list).
    fetched: dict[str, tuple[list[int], list[str]]] = {}
    for sample in ordered:
        key = key_of(sample)
        body = sample.get("body_hash")
        if key is not None and body:
            times, bodies = fetched.setdefault(key, ([], []))
            times.append(int(sample["at_ms"]))
            bodies.append(str(body))
    stored: dict[str, _Stored] = {}
    for sample in ordered:
        report.requests += 1
        stands_for = float(weight(sample))
        report.weighted_requests += stands_for
        at = int(sample["at_ms"])
        key = key_of(sample)
        if key is None or ttl_ms <= 0 or not cacheable(sample):
            report.uncacheable += 1
            report.upstream_calls += 1
            report.weighted_calls += stands_for
            continue
        body = str(sample["body_hash"]) if sample.get("body_hash") else None
        life = _lifetime_ms(sample, ttl_ms, negative_ms)
        entry = stored.get(key)
        age = at - entry.at if entry is not None else math.inf
        if entry is not None and age < entry.life_ms:
            report.hits += 1
            if entry.content:
                _compare(report, fetched.get(key), at, entry.body)
        elif entry is not None and entry.content and age < entry.life_ms + swr_ms:
            report.revalidating += 1
            report.upstream_calls += 1  # the background refresh
            report.weighted_calls += stands_for
            _compare(report, fetched.get(key), at, entry.body)
            if life > 0 and stored_as(sample) == CONTENT:
                stored[key] = _Stored(at, body or entry.body, ttl_ms, True)
            # A refresh whose answer the cache would not keep leaves the old entry until its window ends.
        else:
            report.misses += 1
            report.upstream_calls += 1
            report.weighted_calls += stands_for
            if life > 0:
                stored[key] = _Stored(at, body, life, stored_as(sample) == CONTENT)
            else:
                report.not_stored += 1
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
    refused_weight: float = 0.0
    """The requests the refused samples stand for (each counted for its weight); `refused` stays a sample count."""

    def to_dict(self) -> dict[str, Any]:
        return {
            "requests": self.requests,
            "refused_requests": self.refused,
            "refused_keys": len(self.refused_by_key),
            "top_refused": sorted(self.refused_by_key.items(), key=lambda kv: -kv[1])[:20],
        }


def limit_replay(
    arrivals: Iterable[tuple[int, str] | tuple[int, str, float]],
    *,
    limit: int,
    window_s: float,
    algorithm: str = "gcra",
) -> LimitReplay:
    """Replay `(at_ms, limiter_key)` arrivals (optionally `(at_ms, limiter_key, weight)`, the requests a sample stands
    for) through the abuse limiter (fresh state at the window start)."""
    decide = gcra if algorithm == "gcra" else fixed
    rows: dict[str, LimiterRow] = {}
    report = LimitReplay()
    for arrival in sorted(arrivals, key=lambda a: (int(a[0]), str(a[1]))):
        values: tuple[Any, ...] = tuple(arrival)
        at_ms, key = int(values[0]), str(values[1])
        stands_for = float(values[2]) if len(values) > 2 else 1.0
        report.requests += 1
        row = rows.get(key) or LimiterRow(key)
        decision = decide(row, limit, window_s, at_ms)
        if decision.admitted:
            rows[key] = decision.row
        else:
            report.refused += 1
            report.refused_weight += stands_for
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


# -------------------------------------------------------------------------------------- template patterns


TEMPLATE_SEGMENT: Final = "[^/]{1,512}"
"""One `{placeholder}` segment of an exact template pattern: 1 to 512 characters without a slash. Bounded rather
than `+` because the rule validation (`rules/match.py`) allows at most `MAX_UNBOUNDED_REPEATS` open-ended repeats in
a new regex and a template may have more placeholders; a longer segment is simply not covered by the rule (the
cache's default applies to it), which errs on the side of caching less."""
MAX_EXACT_PATTERNS: Final = 1024
"""Templates whose exact pattern (validated once) is remembered per process (P9; the template vocabulary of plan
6.2 is about 2,000 names, and a miss only costs one validation)."""


def _placeholder(segment: str) -> bool:
    return segment.startswith("{") and segment.endswith("}")


def template_pattern(template: str) -> str:
    """The v1 glob that names an endpoint template: each `{placeholder}` segment becomes `*`.

    A glob always covers the paths below it too (`rules/match.py`), so a rule with this pattern also applies to
    every sibling endpoint under the template. A proposal meant for exactly one endpoint uses `template_match`.
    """
    parts = [("*" if _placeholder(part) else part) for part in template.split("/")]
    return "/".join(parts)


def exact_template_pattern(template: str) -> str:
    """The regex that names exactly one endpoint template: `^host/path/?$` with the literal segments escaped and
    each `{placeholder}` one segment without a slash (`TEMPLATE_SEGMENT`). Rule regexes are matched with `search`
    and IGNORECASE on the normalized target (`rules/match.py`), so the anchors make it cover the template itself
    (one trailing slash allowed), never a path below it."""
    parts = [TEMPLATE_SEGMENT if _placeholder(part) else re.escape(part) for part in template.split("/")]
    return "^" + "/".join(parts) + "/?$"


@functools.lru_cache(maxsize=MAX_EXACT_PATTERNS)
def _exact_or_glob(template: str) -> tuple[str, str]:
    """`(pattern, type)` of `template_match`, validated once (as the rules service stores it)."""
    try:
        return validate_pattern(exact_template_pattern(template), "regex"), "regex"
    except PatternValidationError:
        # Only a template far longer than any real endpoint (MAX_PATTERN_LENGTH) gets here: it keeps the glob.
        return template_pattern(template), "glob"


def template_match(template: str) -> dict[str, str]:
    """`{"pattern", "type"}` of a new rule for exactly this template: the anchored regex of
    `exact_template_pattern` (in the stored form `rules/service.py` keeps), or the v1 glob for a template too long to
    spell as a valid regex. A fresh dict each call (the caller may keep it in a change)."""
    pattern, kind = _exact_or_glob(template)
    return {"pattern": pattern, "type": kind}


def names_template(pattern: str, kind: str, template: str) -> bool:
    """Whether a rule row's pattern names exactly `template`: the exact regex of `template_match`, or the v1 glob
    of `template_pattern` (rules admins and earlier recommendations wrote that way; it covers the template and the
    paths below it). Pure string comparisons: nothing is validated or compiled."""
    if kind == "regex":
        return pattern == exact_template_pattern(template)
    return pattern == template_pattern(template)


def own_template_row(rows: Iterable[Any], template: str) -> Any:
    """The rule row among `rows` (models with `pattern` and `type`) whose pattern names exactly `template`
    (`names_template`): the exact regex a recommendation writes first, else the legacy v1 glob; None when no row
    names it. Every rule that updates "the template's own rule" finds it this way, so a second evaluation never
    proposes a duplicate row (finding insights-8)."""
    named = [row for row in rows if names_template(str(row.pattern), str(row.type), template)]
    return next((row for row in named if row.type == "regex"), named[0] if named else None)


_ESCAPED_CHAR: Final = re.compile(r"\\(.)")


def covers_exactly_one_template(match: Mapping[str, Any] | None) -> bool:
    """Whether a change's `match` is an exact template pattern (`exact_template_pattern` of some template), so the
    rule it writes applies to one endpoint only (plan 11.2 "scoped to one endpoint"). The pattern is read back into
    the template it spells and rebuilt; any other regex (a wildcard, an alternative) does not rebuild to itself."""
    if not isinstance(match, Mapping) or str(match.get("type") or "glob") != "regex":
        return False
    pattern = str(match.get("pattern") or "")
    if not (pattern.startswith("^") and pattern.endswith("/?$")):
        return False
    body = pattern[1:-3].replace(TEMPLATE_SEGMENT, "\0")  # the segment itself holds a slash: protect it first
    parts = ["{segment}" if part == "\0" else _ESCAPED_CHAR.sub(r"\1", part) for part in body.split("/")]
    return exact_template_pattern("/".join(parts)) == pattern


PATTERN_RULE_TABLES: Final[frozenset[str]] = frozenset(
    {"rules_cache", "rules_endpoint_limit", "rules_endpoint_block", "rules_routing"}
)
"""Rule tables whose rows name endpoints by pattern (and so may cover more than one)."""


PATTERN_ROW_KINDS: Final[frozenset[str]] = frozenset({"rule_upsert", "routing_rule", "rule_delete"})
"""Change kinds that write or remove one pattern rule row (judged by what that row's pattern covers)."""
WIDE_PATTERN_NOTE: Final = (
    "Auto-apply skips this card: the rule row it changes is a pattern that also covers the endpoints below this "
    "one (an older glob rule), so the change is not limited to one endpoint."
)
"""The sentence the engine adds to a card a rule marked safe to auto-apply when `endpoint_scoped` says a change is
wider than one endpoint (plan 11.2; finding LOGICFIX-2)."""


def endpoint_scoped(change: ProposedChange) -> bool:
    """Whether a change touches one endpoint only (plan 11.2: the condition for `safe_auto`).

    A change to a pattern rule row (`PATTERN_RULE_TABLES`: created, updated or deleted) is scoped only when that row
    names exactly one template (`covers_exactly_one_template`), and so does the pattern it writes, if it writes one:
    a v1 glob also covers every path below it, so updating a template's own LEGACY glob row (every rule the migrator
    imports is one) retimes or reroutes every sibling endpoint below it, which the evidence never looked at (review
    round 4, finding LOGICFIX-2; insights-8 judged only new rows). Any other change is judged by its kind
    (`ProposedChange.scoped`)."""
    if change.kind in PATTERN_ROW_KINDS and change.table in PATTERN_RULE_TABLES:
        if not covers_exactly_one_template(change.match):
            return False
        proposed = change.proposed if isinstance(change.proposed, Mapping) else {}
        if proposed.get("pattern") is not None:
            kind = proposed.get("type") or (change.match or {}).get("type")
            return covers_exactly_one_template({"pattern": proposed["pattern"], "type": kind})
        return True
    return change.scoped


# ---------------------------------------------------------------------------------------------- dry run


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
    """The Preview panel of one recommendation (plan 11.3).

    Request and call counts (`avoided_calls`, `refused_requests`, `baseline_requests`, `baseline_upstream_calls`)
    are estimates for all requests: the replayed sample counts times `scale` (100 / `request_sample_pct`, 1 when
    every request is sampled). `sample_size` and `parts` are the replay of the samples themselves.
    """

    available: bool
    window_s: int = DEFAULT_WINDOW_S
    sample_size: int = 0
    sample_pct: float = 100.0
    scale: float = 1.0
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


LIMIT_SETTINGS: Final[dict[str, str]] = {
    "allowed_requests_per_minute": "client_hash",
    "throttle_reset_duration": "client_hash",
    "place_limit_per_minute": "place",
}
"""Limit settings the replay models, and the sample column that is their limiter key (plan 11.3 "Limit change")."""
PER_IP_LIMIT_KEY: Final = "allowed_requests_per_minute"
PER_IP_WINDOW_KEY: Final = "throttle_reset_duration"
PLACE_LIMIT_WINDOW_S: Final = 60
"""`abuse/checks/place_limit.py`: `place_limit_per_minute` per 60 s, per place."""

SIMULATED_KINDS: Final[frozenset[str]] = frozenset({"rule_upsert", "bucket_override", "ignored_param_add", "setting"})


def can_simulate(rec: Recommendation) -> bool:
    """Whether `dry_run` models at least one of the recommendation's changes."""
    for change in rec.changes:
        if change.kind in ("bucket_override", "ignored_param_add"):
            return True
        if change.kind == "rule_upsert" and change.table in ("rules_cache", "rules_endpoint_limit"):
            return True
        if change.kind == "setting" and change.key in (
            "cache_post_requests",
            "cache_error_ttl_seconds",
            *LIMIT_SETTINGS,
        ):
            return True
    return False


def _sample_scale(pct: float) -> float:
    """100 / `request_sample_pct` below 100 (each sample stands for that many requests), else 1."""
    return 100.0 / pct if 0 < pct < 100 else 1.0


def _scaled(count: int, scale: float) -> int:
    return round(count * scale)


def _thinned(limit: float, scale: float) -> int:
    """A limit of `limit` per window on all requests, as it applies to their 1 / `scale` sample (at least 1)."""
    return max(1, round(float(limit) / scale))


async def dry_run(ctx: InsightContext, rec: Recommendation, *, window_s: int = DEFAULT_WINDOW_S) -> DryRunReport:
    """Replay the last `window_s` seconds of samples under the recommendation's changes (see the module docstring).

    Cache changes are replayed first; a bucket override then replays the upstream calls that would remain.
    """
    hours = float(ctx.setting("request_sample_hours"))
    window_s = int(min(max(60, window_s), hours * 3600))
    report = DryRunReport(available=can_simulate(rec), window_s=window_s)
    report.sample_pct = float(ctx.setting("request_sample_pct"))
    scale = report.scale = _sample_scale(report.sample_pct)
    if report.sample_pct <= 0:
        report.note = "Request sampling is off (request_sample_pct 0), so there are no samples to replay."
    elif report.sample_pct < 100:
        report.note = (
            f"Samples cover {report.sample_pct:g}% of requests; counts are scaled to all requests "
            f"(times {scale:.3g}), so they are estimates."
        )
    if not report.available:
        return report
    window = ctx.window(seconds=window_s)
    post_mode = str(ctx.setting("cache_post_requests"))
    error_ttl = int(ctx.setting("cache_error_ttl_seconds"))
    ignored: frozenset[str] = frozenset(ctx.rules.cache_ignored_params)
    added: set[str] = set()
    for change in rec.changes:
        if change.kind == "setting" and change.key == "cache_post_requests":
            post_mode = str(change.proposed)
        if change.kind == "setting" and change.key == "cache_error_ttl_seconds":
            error_ttl = int(change.proposed)
        if change.kind == "ignored_param_add" and isinstance(change.proposed, Mapping):
            added.add(str(change.proposed.get("name")))
    ignored = ignored | added
    all_samples = await ctx.samples(window)
    # Each sample counts for 100 / the rate it was taken at (its own `sample_pct`, else the rate in force at its
    # time), never the live rate for the whole window (finding LOGICFIX-6).
    weigh = await _sample_weights(ctx, window, report.sample_pct)
    weights = [weigh(s) for s in all_samples]
    if weights:
        rates = sorted({round(100.0 / w, 2) for w in weights})
        if len(rates) > 1:
            scale = report.scale = round(sum(weights) / len(weights), 4)
            report.note = (
                f"Samples in this window were taken at different rates ({rates[0]:g}% to {rates[-1]:g}%); each "
                "counts for 100 / the rate it was taken at, so counts are estimates."
            )
        elif abs(weights[0] - scale) > 1e-9:
            scale = report.scale = weights[0]
            report.note = (
                f"The samples in this window were taken at {rates[0]:g}% (request_sample_pct is "
                f"{report.sample_pct:g}% now); counts are scaled to all requests (times {scale:.3g})."
            )
    refusals = await ctx.refusal_samples(window) if _replays_limits(rec) else []
    templates = {str(s["endpoint_template"]) for s in all_samples}
    call_times: list[int] | None = None
    affected_templates: set[str] = set()
    plan: list[tuple[ProposedChange, set[str]]] = []
    for change in rec.changes:
        if change.kind == "rule_upsert" and change.table == "rules_cache":
            matches = _matcher(change)
            if matches is not None:
                plan.append((change, {t for t in templates if matches(t)}))
    if (added or _changes_setting(rec, "cache_error_ttl_seconds")) and not plan:
        # An ignored parameter or the error lifetime alone: replay every template under the rule it has today.
        plan = [(_current_rule_change(ctx, template), {template}) for template in sorted(templates)]
    avoided = baseline_requests = baseline_calls = 0.0
    for change, affected in plan:
        affected_templates |= affected
        rows = [s for s in all_samples if s["endpoint_template"] in affected]
        rule = _cache_rule(change)
        texts = await ctx.key_texts(str(s["key_id"]) for s in rows if s.get("key_id"))
        key_of = _rekey(rule, texts, ignored, rebuild=bool(added) or _flags_change(change))
        swr = rule.stale_ttl if rule.stale_ttl > 0 else int(ctx.setting("cache_swr_seconds"))
        negative = _negative_ttl(rule, error_ttl)

        def cacheable(sample: Sample, rule: CacheRuleRow = rule) -> bool:
            method = str(sample.get("method") or "GET").upper()
            if method == "GET":
                return "GET" in rule.methods
            if method == "POST":
                return post_allowed(str(sample["endpoint_template"]), rule, post_mode)
            return False

        replay = cache_replay(
            rows, ttl_s=rule.ttl, swr_s=swr, negative_ttl_s=negative, cacheable=cacheable, key_of=key_of, weight=weigh
        )
        report.parts[change.target] = replay.to_dict()
        report.sample_size += replay.requests
        avoided += replay.weighted_requests - replay.weighted_calls
        report.simulated_hit_ratio = replay.simulated_hit_ratio
        report.staleness_risk = replay.staleness_risk
        baseline_requests += replay.weighted_requests
        baseline_calls += sum(weigh(s) for s in rows if s.get("egress") not in (None, "none"))
        call_times = _call_times(rows, rule.ttl, cacheable, key_of, negative)
    if plan:
        report.avoided_calls = round(avoided)
        report.baseline_requests = round(baseline_requests)
        report.baseline_upstream_calls = round(baseline_calls)
    for targets, limit in _limit_replays(ctx, rec, all_samples, refusals, templates, scale, weigh):
        for target in targets:
            report.parts[target] = limit.to_dict()
        report.refused_requests = (report.refused_requests or 0) + round(limit.refused_weight)
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
        # The sample's calls arrive at 1 / scale of the real rate: the bucket is thinned the same way.
        replay_b = bucket_replay(
            times,
            per_min=float(change.proposed.get("per_min") or 1) / scale,
            burst=_thinned(int(change.proposed.get("burst") or 1), scale),
            max_wait_ms=float(ctx.setting("queue_wait_interactive_ms")),
            key=change.bucket_key,
        )
        report.parts[change.target] = replay_b.to_dict()
        report.refused_requests = (report.refused_requests or 0) + _scaled(replay_b.refused, scale)
        report.queue_wait_p95_ms = replay_b.percentile(0.95)
        report.sample_size = max(report.sample_size, replay_b.requests)
    return report


def _changes_setting(rec: Recommendation, key: str) -> bool:
    return any(change.kind == "setting" and change.key == key for change in rec.changes)


def _negative_ttl(rule: CacheRuleRow, error_ttl: int) -> int:
    """The error lifetime a request under `rule` gets (`cache/policy.py request_policy`): none under a "never cache"
    rule (TTL 0), the rule's own `negative_ttl` when it has one, else `cache_error_ttl_seconds`."""
    if rule.ttl == 0:
        return 0
    return int(rule.negative_ttl) if rule.negative_ttl > 0 else max(0, int(error_ttl))


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
    # Replayed only, never applied: the exact pattern needs no validation (`template_match` validates once per
    # template, which a replay of every template would pay for each of up to 2,000 names).
    match = {"pattern": exact_template_pattern(template), "type": "regex"}
    ttl = int(ctx.setting("cache_ttl_seconds"))
    return ProposedChange(
        "rule_upsert",
        table="rules_cache",
        match=match,
        current=None,
        proposed={**match, "ttl": ttl},
    )


def _proposed_or(rec: Recommendation, key: str, current: Any) -> Any:
    """The value the recommendation proposes for setting `key`, else `current`."""
    for change in rec.changes:
        if change.kind == "setting" and change.key == key:
            return change.proposed
    return current


def _replays_limits(rec: Recommendation) -> bool:
    """Whether `dry_run` replays a limit for this recommendation (and so reads the refusal samples)."""
    return any(
        (change.kind == "setting" and change.key in LIMIT_SETTINGS)
        or (change.kind == "rule_upsert" and change.table == "rules_endpoint_limit")
        for change in rec.changes
    )


async def _sample_weights(ctx: InsightContext, window: Any, live_pct: float) -> Callable[[Sample], float]:
    """How many requests one sample stands for: 100 / the rate it was taken at (`_sample_scale`).

    The rate is the sample's own `sample_pct` (metrics.db schema 7 rows carry it); for an older row, the
    `request_sample_pct` in force at its time, from the settings history (`InsightContext.setting_timeline`). The
    live rate applied to the whole window counted the samples taken before a rate change at the new rate (finding
    LOGICFIX-6: 50% over the ground truth for an hour after halving the rate)."""
    timeline = await ctx.setting_timeline("request_sample_pct", window.start)
    starts = [int(at) for at, _value in timeline]
    rates = [float(value) for _at, value in timeline]

    def rate_at(at_ms: int) -> float:
        if not rates:
            return float(live_pct)
        return rates[max(0, bisect.bisect_right(starts, at_ms // 1000) - 1)]

    def weigh(sample: Sample) -> float:
        own = sample.get("sample_pct")
        pct = float(own) if isinstance(own, int | float) and own > 0 else rate_at(int(sample["at_ms"]))
        return _sample_scale(pct)

    return weigh


def _limit_replays(
    ctx: InsightContext,
    rec: Recommendation,
    samples: Sequence[Sample],
    refusals: Sequence[Sample],
    templates: set[str],
    scale: float,
    weigh: Callable[[Sample], float],
) -> list[tuple[list[str], LimitReplay]]:
    """The limit replays of a recommendation: `(targets of the changes it models, replay)`.

    Each replays the stream the limiter SAW: the request samples (admitted requests) and the refusal samples of the
    requests that reached it and were refused there or later (`metrics/samples.py reasons_from`; production never
    sampled a refused request, so a raised limit previewed about zero refusals, finding LOGICFIX-5).
    - The per-IP limit is one replay for both of its settings: `allowed_requests_per_minute` per
      `throttle_reset_duration` seconds, each the proposed value when the recommendation changes it, else today's
      (`abuse/throttle.py`), in `throttle_window_mode`, per sample `client_hash`, over every refusal from the per-IP
      throttle on. The replay is a lower bound: it counts what the limit itself refuses, not the escalation
      penalties that refuse a struck client for longer, it keys by address while the limiter groups IPv6 addresses
      by `ipv6_limit_prefix`, and a worker keeps at most `MAX_REFUSAL_SAMPLES_PER_MINUTE` refusal samples a minute.
    - The place limit: `place_limit_per_minute` per 60 s per place (GCRA), over the refusals from the place limit on.
    - An endpoint rule: its `limit` per `period` per scope, in v1's fixed window (`abuse/limiter.py fixed`), over its
      own refusals.
    Below 100% sampling each limit is thinned to the sample's share before the replay (`_thinned`), and a refused
    sample counts for the requests it stands for (`weigh`).
    """
    out: list[tuple[list[str], LimitReplay]] = []

    def refused_from(check: str) -> list[Sample]:
        reasons = reasons_from(check)
        return [r for r in refusals if str(r.get("reason")) in reasons]

    per_ip = [c for c in rec.changes if c.kind == "setting" and c.key in (PER_IP_LIMIT_KEY, PER_IP_WINDOW_KEY)]
    if per_ip:
        limit = int(_proposed_or(rec, PER_IP_LIMIT_KEY, ctx.setting(PER_IP_LIMIT_KEY)))
        window_s = float(_proposed_or(rec, PER_IP_WINDOW_KEY, ctx.setting(PER_IP_WINDOW_KEY)))
        algorithm = "fixed" if str(ctx.setting("throttle_window_mode")) == "fixed" else "gcra"
        arrivals = [
            (int(s["at_ms"]), str(s["client_hash"]), weigh(s))
            for s in (*samples, *refused_from("throttle"))
            if s.get("client_hash")
        ]
        replay = limit_replay(arrivals, limit=_thinned(limit, scale), window_s=max(1.0, window_s), algorithm=algorithm)
        out.append(([c.target for c in per_ip], replay))
    for change in rec.changes:
        if change.kind == "setting" and change.key == "place_limit_per_minute":
            arrivals = [
                (int(s["at_ms"]), str(s["place"]), weigh(s))
                for s in (*samples, *refused_from("place_limit"))
                if s.get("place")
            ]
            replay = limit_replay(
                arrivals, limit=_thinned(int(change.proposed), scale), window_s=PLACE_LIMIT_WINDOW_S, algorithm="gcra"
            )
            out.append(([change.target], replay))
        elif (
            change.kind == "rule_upsert"
            and change.table == "rules_endpoint_limit"
            and isinstance(change.proposed, Mapping)
        ):
            matches = _matcher(change)
            if matches is None:
                continue
            affected = {t for t in templates if matches(t)}
            affected |= {
                str(r["endpoint_template"])
                for r in refused_from("endpoint_rule")
                if matches(str(r["endpoint_template"]))
            }
            scope = str(change.proposed.get("scope") or "ip")
            column = {"ip": "client_hash", "place": "place"}.get(scope)
            rule_arrivals = [
                (int(s["at_ms"]), "global" if column is None else str(s.get(column) or ""), weigh(s))
                for s in (*samples, *refused_from("endpoint_rule"))
                if s["endpoint_template"] in affected
            ]
            # Endpoint rules use v1's fixed window (abuse/limiter.py `fixed`).
            replay = limit_replay(
                rule_arrivals,
                limit=_thinned(int(change.proposed.get("limit") or 1), scale),
                window_s=float(change.proposed.get("period") or 60),
                algorithm="fixed",
            )
            out.append(([change.target], replay))
    return out


def _call_times(
    rows: Sequence[Sample],
    ttl_s: float,
    cacheable: Callable[[Sample], bool],
    key_of: Callable[[Sample], str | None],
    negative_ttl_s: float = 0.0,
) -> list[int]:
    """The times of the upstream calls left under a cache rule, for a bucket replay after it.

    The same store policy as `cache_replay` (`stored_as`): an answer the cache would not keep leaves the next
    request a call too. A refresh inside the stale-while-revalidate window is a call at the same moment as the miss
    it replaces, so the call times are the same with or without SWR; only who waits for them differs.
    """
    times: list[int] = []
    stored: dict[str, tuple[int, float]] = {}
    ttl_ms = max(0.0, float(ttl_s)) * 1000
    negative_ms = max(0.0, float(negative_ttl_s)) * 1000
    for sample in _ordered(rows):
        at = int(sample["at_ms"])
        key = key_of(sample)
        if key is None or ttl_ms <= 0 or not cacheable(sample):
            times.append(at)
            continue
        entry = stored.get(key)
        if entry is not None and at - entry[0] < entry[1]:
            continue
        times.append(at)
        life = _lifetime_ms(sample, ttl_ms, negative_ms)
        if life > 0:
            stored[key] = (at, life)
    return times


__all__ = [
    "CONTENT",
    "DEFAULT_WINDOW_S",
    "LIMIT_SETTINGS",
    "NEGATIVE",
    "PATTERN_RULE_TABLES",
    "TEMPLATE_SEGMENT",
    "BucketReplay",
    "CacheReplay",
    "ChangeEstimate",
    "DryRunReport",
    "LimitReplay",
    "bucket_replay",
    "cache_replay",
    "can_simulate",
    "covers_exactly_one_template",
    "dry_run",
    "endpoint_scoped",
    "estimate_change_interval",
    "exact_template_pattern",
    "limit_replay",
    "names_template",
    "own_template_row",
    "proposed_ttl",
    "stored_as",
    "template_match",
    "template_pattern",
]
