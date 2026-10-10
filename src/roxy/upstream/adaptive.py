"""Adaptive rate: lower a bucket's rate when Roblox says 429, raise it slowly when demand proves it too low.

What this is
    The default rate controller of plan 7.3 (F4): attribution of a 429 to the right bucket (endpoint, host or the
    whole egress), the decrease and increase arithmetic, and `AdaptiveController`, which writes the new rates to
    control.db `upstream_limits` with origin `adaptive` (audited, so every worker reloads them within a second and
    the admin sees who changed what). A leader job (`increase_job`) does the bounded upward probing.

Why it exists
    Roblox limits request RATE per endpoint, not concurrency, so the right knob is each endpoint's bucket rate.
    Fixed rates are either too high (429s) or too low (needless queuing); measured feedback finds the real limit.
    v1 had no control loop at all.

How it works
    - Decrease (on a Roblox 429 through direct or the credential, never the rotator, whose exits differ): the rate
      drops by `adaptive_decrease_pct` (30 %) from the LOWER of the bucket's current limit and the calls Roxy
      actually made through that bucket in the last minute (`buckets.observed_calls`, the bucket's window meter,
      fleet-wide). That count is the rate Roblox just refused; cutting only the configured rate (120 to 84) left an
      endpoint that ran at 61 a minute against a limit of 60 exactly where it was, so Roblox had to say 429 again
      (finding LOAD-1). The burst is cut by the same ratio, so the burst keeps its share of the window (host and
      endpoint buckets are window buckets: rate plus burst fit inside one minute, `buckets.py`). A count at or below
      the floor is no evidence about the rate (Roblox refusing the first call of a quiet minute is not a limit Roxy
      could keep), so it leaves the plan's cut of the current rate. The result is floored at
      `adaptive_min_per_min` (6) and never raised by the floor. Only the first 429 of a cooldown episode
      counts (requests already in flight when the cooldown opened do not cut the rate again), and a key cut within
      the attribution window is not cut twice.
    - Attribution (before blaming the endpoint): if 429s reached `EGRESS_ATTRIBUTION_MIN_HOSTS` (2) different hosts
      through this egress within `cooldown_host_escalation_window_s` (60 s), the whole egress is being limited:
      an egress cooldown opens (in `effects.py`) and no per-endpoint rate is lowered. Otherwise, if
      `cooldown_host_escalation_endpoints` (3) templates of the host got 429s in the window, `host:<host>` is
      lowered instead of the endpoint. The evidence is the `set_at` time of the endpoint cooldown rows.
      "Across hosts" in plan 7.3 means more than one host, so 2 is definitional rather than a tunable.
    - Increase (leader job, hourly): after `adaptive_probe_after_h` (24) hours with zero 429s on the key, and
      bucket rejections (`upstream_busy` and `queue_overflow` answers) above 1 % of its attempts, the rate rises by
      `adaptive_increase_pct` (10 %), capped at `adaptive_max_per_min` (600). The burst recovers carefully: at most
      one call per raise, never beyond the default burst's share of the new rate, never beyond the default burst.
      A cap that is never reached is never raised: without rejections there is no evidence. The key's last change
      must also be that old, which makes
      the job idempotent (a duplicate run finds the fresh change and does nothing). A rate set by an admin or an
      applied recommendation is never raised automatically (a decrease on a 429 still applies: safety first), and
      a host bucket is raised only to undo a cut this controller made, because rejections cannot tell which of a
      request's buckets bound it.
    - `adaptive_rate_enabled=0` freezes all of it; admins and applied recommendations still change rates.

What to read next
    `roxy/upstream/effects.py` (where attribution runs, inside the post-call transaction), `roxy/rules/service.py`
    (`upsert`, the audited write), and the UP-BUCKET-TUNE recommendation rule.
"""

from __future__ import annotations

import logging
import math
import sqlite3
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Final, Protocol

from roxy.core.reasons import Egress, ReasonCode
from roxy.upstream import cooldowns
from roxy.upstream.buckets import (
    WINDOW_MS,
    BucketDefaults,
    LimitPair,
    LimitsLookup,
    endpoint_bucket_key,
    host_bucket_key,
)

log = logging.getLogger(__name__)

EGRESS_ATTRIBUTION_MIN_HOSTS: Final = 2
REJECTION_SHARE: Final = 0.01
"""Plan 7.3: raise only when bucket rejections exceed 1 % of the key's attempts (real demand above the cap)."""

MAX_RECENT_KEYS: Final = 1024
"""Per-worker memory of recently lowered keys (bounded, plan P9)."""

MAX_STATS_ROWS: Final = 20_000
ADAPTIVE_ACTOR_NAME: Final = "adaptive"
REJECTION_REASONS: Final = (ReasonCode.UPSTREAM_BUSY.value, ReasonCode.QUEUE_OVERFLOW.value)


class AttributionKind(StrEnum):
    ENDPOINT = "endpoint"
    HOST = "host"
    EGRESS = "egress"


@dataclass(frozen=True, slots=True)
class Attribution:
    """Which bucket a 429 is blamed on, and the evidence."""

    kind: AttributionKind
    bucket_key: str | None  # None for EGRESS: nothing per endpoint is lowered
    templates_429: int
    hosts_429: int
    window_s: float

    def evidence(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "bucket_key": self.bucket_key,
            "templates_with_429": self.templates_429,
            "hosts_with_429": self.hosts_429,
            "window_s": self.window_s,
        }


def attribute(
    conn: sqlite3.Connection,
    host: str,
    template: str,
    egress: Egress,
    now_s: float,
    window_s: float,
    host_threshold: int,
) -> Attribution:
    """Blame a 429 (already recorded as an endpoint cooldown) on the endpoint, the host or the egress."""
    since = now_s - window_s
    hosts = cooldowns.distinct_hosts_cooling(conn, egress, since)
    templates = cooldowns.distinct_templates_cooling(conn, host, egress, since)
    if hosts >= EGRESS_ATTRIBUTION_MIN_HOSTS:
        return Attribution(AttributionKind.EGRESS, None, templates, hosts, window_s)
    if templates >= host_threshold:
        return Attribution(AttributionKind.HOST, host_bucket_key(host), templates, hosts, window_s)
    return Attribution(AttributionKind.ENDPOINT, endpoint_bucket_key(template), templates, hosts, window_s)


def decreased_rate(current: float, pct: float, floor: float) -> float:
    """`current` lowered by `pct` percent, floored at `floor`, and never raised by the floor."""
    cut = current * (1 - pct / 100)
    return round(min(current, max(floor, cut)), 2)


def increased_rate(current: float, pct: float, ceiling: float) -> float:
    """`current` raised by `pct` percent, capped at `ceiling`, and never lowered by the cap."""
    raised = current * (1 + pct / 100)
    return round(max(current, min(ceiling, raised)), 2)


def scaled_burst(burst: int, old_per_min: float, new_per_min: float) -> int:
    """The burst after a rate cut: scaled by the same ratio (rounded down, at least 1), so it keeps its share of the
    window. Unchanged when the rate did not go down."""
    if old_per_min <= 0 or new_per_min >= old_per_min:
        return burst
    return max(1, math.floor(burst * new_per_min / old_per_min + 1e-9))


def decreased_limit(current: LimitPair, observed: float | None, pct: float, floor: float) -> LimitPair:
    """The rate and burst after a Roblox 429 (plan 7.3 with finding LOAD-1).

    `observed` is how many calls Roxy made through the bucket in the last minute (its window meter), or None when
    unknown. The cut starts from the lower of that and the current rate, so it lands below what Roblox refused. A
    count at or below the floor is not used: Roblox refusing that few calls is not a per-minute limit Roxy could
    learn (the controller never goes below the floor), so it is no evidence about the rate (a refusal on the
    first call of a quiet minute, an address-wide block) and the plan's cut of the current rate applies. The floor
    never raises a rate an admin set below it. The burst shrinks by the same ratio as the rate.
    """
    base = current.per_min
    if observed is not None and observed > floor:
        base = min(base, observed)
    cut = base * (1 - pct / 100)
    per_min = round(min(current.per_min, max(floor, cut)), 2)
    return LimitPair(per_min, scaled_burst(current.burst, current.per_min, per_min))


def increased_limit(current: LimitPair, default: LimitPair, pct: float, ceiling: float) -> LimitPair:
    """The rate and burst after a clean probe period: the rate up by `pct` (capped), the burst back up carefully.

    The burst grows by at most one call per raise, and only up to the share of the window the default burst has
    at the new rate (10 of 120 for an endpoint), never beyond the default burst itself: after a cut, bursts come
    back slowly, behind the rate."""
    per_min = increased_rate(current.per_min, pct, ceiling)
    share = max(1, math.floor(per_min * default.burst / default.per_min + 1e-9)) if default.per_min > 0 else 1
    burst = max(current.burst, min(current.burst + 1, share, default.burst))
    return LimitPair(per_min, burst)


@dataclass(frozen=True, slots=True)
class AdaptivePolicy:
    """The adaptive settings of plan 15.3 C."""

    enabled: bool = True
    decrease_pct: float = 30.0
    increase_pct: float = 10.0
    probe_after_h: float = 24.0
    min_per_min: float = 6.0
    max_per_min: float = 600.0
    window_s: float = 60.0  # the attribution window (cooldown_host_escalation_window_s)
    host_threshold: int = 3

    @classmethod
    def from_settings(cls, settings: Any) -> AdaptivePolicy:
        return cls(
            enabled=bool(settings.get("adaptive_rate_enabled")),
            decrease_pct=float(settings.get("adaptive_decrease_pct")),
            increase_pct=float(settings.get("adaptive_increase_pct")),
            probe_after_h=float(settings.get("adaptive_probe_after_h")),
            min_per_min=float(settings.get("adaptive_min_per_min")),
            max_per_min=float(settings.get("adaptive_max_per_min")),
            window_s=float(settings.get("cooldown_host_escalation_window_s")),
            host_threshold=int(settings.get("cooldown_host_escalation_endpoints")),
        )


@dataclass(frozen=True, slots=True)
class RateChange:
    """One rate the controller changed (`burst` is the new burst, `old_burst` the one before)."""

    bucket_key: str
    old_per_min: float
    new_per_min: float
    burst: int
    direction: str  # "decrease" or "increase"
    evidence: dict[str, Any] = field(default_factory=dict)
    old_burst: int | None = None


class LimitsWriter(Protocol):
    """Writes an `upstream_limits` row with origin `adaptive` (audited)."""

    async def write_limit(self, bucket_key: str, per_min: float, burst: int, reason: str) -> None: ...


class RulesLimitsWriter:
    """The production writer: `RulesService.upsert` on `upstream_limits`, as the system actor `adaptive`."""

    def __init__(self, rules_service: Any) -> None:
        self._service = rules_service

    async def write_limit(self, bucket_key: str, per_min: float, burst: int, reason: str) -> None:
        from roxy.config.audit import Actor  # local import: audit pulls in control-plane modules

        row = {"bucket_key": bucket_key, "per_min": per_min, "burst": burst, "origin": "adaptive", "note": ""}
        await self._service.upsert("upstream_limits", row, Actor("system", ADAPTIVE_ACTOR_NAME), reason[:200])


def _current(limits: LimitsLookup | None, key: str, default: LimitPair) -> tuple[LimitPair, Any]:
    row = limits.upstream_limit(key) if limits is not None else None
    if row is None:
        return default, None
    return LimitPair(float(row.per_min), int(row.burst)), row


def _default_for(key: str, defaults: BucketDefaults) -> LimitPair:
    return defaults.host if key.startswith("host:") else defaults.endpoint


@dataclass(slots=True)
class KeyStats:
    """Demand evidence for one bucket key over the probe window (from metrics.db)."""

    key: str
    attempts: int = 0
    rejections: int = 0
    rate_limited: int = 0
    last_429_ms: int | None = None

    @property
    def rejection_share(self) -> float:
        return self.rejections / self.attempts if self.attempts > 0 else 0.0


def should_increase(stats: KeyStats, last_change_s: float | None, now_s: float, policy: AdaptivePolicy) -> bool:
    """Plan 7.3 bounded upward probing: a clean probe window, real demand above the cap, no recent change."""
    window_s = policy.probe_after_h * 3600
    if stats.rate_limited > 0:
        return False
    if stats.last_429_ms is not None and stats.last_429_ms / 1000 > now_s - window_s:
        return False
    if last_change_s is not None and last_change_s > now_s - window_s:
        return False
    return stats.attempts > 0 and stats.rejection_share > REJECTION_SHARE


def collect_stats(conn: sqlite3.Connection, since_s: float) -> dict[str, KeyStats]:
    """Per endpoint and per host bucket key: attempts, rejections and 429s since `since_s` (metrics.db)."""
    stats: dict[str, KeyStats] = {}

    def entry(key: str) -> KeyStats:
        found = stats.get(key)
        if found is None:
            found = stats[key] = KeyStats(key)
        return found

    rows = conn.execute(
        "SELECT d.endpoint_template, d.host, d.reason_code, SUM(r.requests), SUM(r.upstream_calls) "
        "FROM rollup_hour r JOIN dims d ON d.dim_hash = r.dim_hash WHERE r.bucket_start >= ? "
        "GROUP BY d.endpoint_template, d.host, d.reason_code LIMIT ?",
        (int(since_s), MAX_STATS_ROWS),
    ).fetchall()
    for template, host, reason, requests, calls in rows:
        rejections = int(requests or 0) if reason in REJECTION_REASONS else 0
        for key in (endpoint_bucket_key(str(template)), host_bucket_key(str(host))):
            item = entry(key)
            item.attempts += int(calls or 0) + rejections
            item.rejections += rejections
    for template, host, count, last in conn.execute(
        "SELECT endpoint_template, host, COUNT(*), MAX(at_ms) FROM upstream_429 WHERE at_ms >= ? "
        "GROUP BY endpoint_template, host LIMIT ?",
        (int(since_s * 1000), MAX_STATS_ROWS),
    ).fetchall():
        for key in (endpoint_bucket_key(str(template)), host_bucket_key(str(host))):
            item = entry(key)
            item.rate_limited += int(count or 0)
            last_ms = int(last) if last is not None else None
            if last_ms is not None and (item.last_429_ms is None or last_ms > item.last_429_ms):
                item.last_429_ms = last_ms
    return stats


EventFn = Callable[[str, str, str, dict[str, Any]], None]


class AdaptiveController:
    """Applies rate changes. One per worker; the decrease runs on the request path (after the response)."""

    def __init__(self, writer: LimitsWriter, *, event: EventFn | None = None) -> None:
        self._writer = writer
        self._event = event
        self._recent: dict[str, float] = {}  # bucket key -> when this worker last lowered it

    def _remember(self, key: str, now_s: float) -> None:
        if len(self._recent) >= MAX_RECENT_KEYS:
            oldest = min(self._recent, key=self._recent.__getitem__)
            del self._recent[oldest]
        self._recent[key] = now_s

    async def on_rate_limited(
        self,
        *,
        attribution: Attribution,
        egress: Egress,
        first_in_episode: bool,
        policy: AdaptivePolicy,
        limits: LimitsLookup | None,
        defaults: BucketDefaults,
        now_s: float,
        observed: Mapping[str, float] | None = None,
    ) -> RateChange | None:
        """Lower the attributed bucket after a Roblox 429, when the rules above allow it.

        `observed` maps bucket keys to the calls Roxy made through them in the last minute (`effects.CallEffects
        .observed`, read from the window meters in the 429's own transaction); the cut starts from it when it is
        below the current rate."""
        if not policy.enabled or egress not in (Egress.DIRECT, Egress.CREDENTIAL):
            return None
        key = attribution.bucket_key
        if attribution.kind is AttributionKind.EGRESS or key is None:
            return None
        if attribution.kind is AttributionKind.ENDPOINT and not first_in_episode:
            return None
        last = self._recent.get(key)
        if last is not None and now_s - last < policy.window_s:
            return None
        current, row = _current(limits, key, _default_for(key, defaults))
        if row is not None and getattr(row, "origin", "") == "adaptive":
            updated = getattr(row, "updated_at", None)
            if updated is not None and now_s - float(updated) < policy.window_s:
                return None  # another worker lowered it moments ago
        seen = None if observed is None else observed.get(key)
        new = decreased_limit(current, seen, policy.decrease_pct, policy.min_per_min)
        if new.per_min >= current.per_min:
            return None
        evidence = attribution.evidence() | {
            "egress": egress.value,
            "observed_calls": seen,  # calls Roxy made through the bucket in the last minute (None: unknown)
            "observed_window_s": WINDOW_MS / 1000,
            "cut_from": "observed" if seen is not None and policy.min_per_min < seen < current.per_min else "limit",
        }
        reason = (
            f"Roblox 429 attributed to {attribution.kind.value}: {current.per_min:g} per minute (burst "
            f"{current.burst}) -> {new.per_min:g} (burst {new.burst})"
        )
        if seen is not None:
            reason += f"; {seen:g} calls in the last minute"
        await self._writer.write_limit(key, new.per_min, new.burst, reason)
        self._remember(key, now_s)
        change = RateChange(key, current.per_min, new.per_min, new.burst, "decrease", evidence, current.burst)
        self._emit("adaptive_rate_decrease", change)
        return change

    async def run_increases(
        self,
        stats: Mapping[str, KeyStats],
        *,
        policy: AdaptivePolicy,
        limits: LimitsLookup | None,
        defaults: BucketDefaults,
        now_s: float,
    ) -> list[RateChange]:
        """Raise every key whose evidence says its cap is too low (leader job)."""
        if not policy.enabled:
            return []
        changes: list[RateChange] = []
        for key in sorted(stats):
            item = stats[key]
            current, row = _current(limits, key, _default_for(key, defaults))
            origin = None if row is None else str(getattr(row, "origin", ""))
            if origin is not None and origin not in ("adaptive", "default"):
                continue  # an admin's or an applied recommendation's deliberate rate is never raised automatically
            if key.startswith("host:") and origin != "adaptive":
                continue  # rejections cannot say which bucket bound; only undo host cuts this controller made
            last_change = None if row is None else getattr(row, "updated_at", None)
            if not should_increase(item, None if last_change is None else float(last_change), now_s, policy):
                continue
            new = increased_limit(current, _default_for(key, defaults), policy.increase_pct, policy.max_per_min)
            if new.per_min <= current.per_min:
                continue
            reason = (
                f"{policy.probe_after_h:g} h without a 429 and {item.rejection_share:.1%} of attempts rejected by "
                f"the bucket: {current.per_min:g} per minute (burst {current.burst}) -> {new.per_min:g} (burst "
                f"{new.burst})"
            )
            await self._writer.write_limit(key, new.per_min, new.burst, reason)
            change = RateChange(
                key,
                current.per_min,
                new.per_min,
                new.burst,
                "increase",
                {"attempts": item.attempts, "rejections": item.rejections},
                current.burst,
            )
            changes.append(change)
            self._emit("adaptive_rate_increase", change)
        return changes

    def _emit(self, event_type: str, change: RateChange) -> None:
        detail = {
            "bucket_key": change.bucket_key,
            "old_per_min": change.old_per_min,
            "new_per_min": change.new_per_min,
            "old_burst": change.old_burst,
            "new_burst": change.burst,
            "evidence": change.evidence,
        }
        log.info(event_type, extra={"fields": detail})
        if self._event is not None:
            try:
                self._event(event_type, "info", ReasonCode.UPSTREAM_COOLDOWN.value, detail)
            except Exception:  # metrics degrade open (plan C7)
                log.warning("adaptive_event_failed", exc_info=True)


async def increase_job(
    controller: AdaptiveController,
    *,
    metrics_read: Callable[[Callable[[sqlite3.Connection], dict[str, KeyStats]]], Awaitable[dict[str, KeyStats]]],
    policy: AdaptivePolicy,
    limits: LimitsLookup | None,
    defaults: BucketDefaults,
    now_s: float,
) -> list[RateChange]:
    """The hourly leader job body: read the evidence from metrics.db, then raise what deserves it."""
    since = now_s - policy.probe_after_h * 3600
    stats = await metrics_read(lambda conn: collect_stats(conn, since))
    return await controller.run_increases(stats, policy=policy, limits=limits, defaults=defaults, now_s=now_s)


__all__ = [
    "ADAPTIVE_ACTOR_NAME",
    "EGRESS_ATTRIBUTION_MIN_HOSTS",
    "REJECTION_SHARE",
    "AdaptiveController",
    "AdaptivePolicy",
    "Attribution",
    "AttributionKind",
    "KeyStats",
    "LimitsWriter",
    "RateChange",
    "RulesLimitsWriter",
    "attribute",
    "collect_stats",
    "decreased_limit",
    "decreased_rate",
    "increase_job",
    "increased_limit",
    "increased_rate",
    "scaled_burst",
    "should_increase",
]
