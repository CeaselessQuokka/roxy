"""Facts the UP-* recommendation rules need that `InsightContext` does not offer: rotator budget and health, the
User-Agent experiment arms, and a window helper.

What this is
    - `rotator_status(ctx) -> RotatorStatus`: whether the rotator could take more traffic right now (switched on,
      not parked, not disabled by the leak guard, a monthly quota configured and not used up, daily cap not hit),
      read with the rotator's own budget arithmetic (`egress/rotator.py usage_since` and `cycle_start_for`), so a
      recommendation and the hard stop never disagree about the bytes of this billing cycle.
    - `ua_experiment_arms(ctx)`: the two arms of the User-Agent experiment (D23): calls and Roblox 429s per
      User-Agent. The provider seam `InsightProviders.ua_experiment()` wins when it knows the numbers (the fixture
      harness fills it; a future per-arm counter in the upstream recorder would too). Otherwise the arms are
      estimated from `request_samples`: each direct call's arm is recomputed with the egress layer's own
      assignment (`egress/headers.py HeaderProfiles.ua_variant`, keyed by the cache key id, else the template, the
      way `upstream/service.py _identity` keys it).
    - `span_window(start, end, granularity)`: a `metrics/queries.Window` for spans `ctx.window` does not build
      (a week of hour-level rollups, a run of 429 minutes, a billing cycle).

Why it exists
    The task brief of the UP-* family: data no provider gives yet is added through the engine's provider interface
    in a module the family owns, instead of editing `insights/context.py` (owned by the engine author). Every read
    here goes through an existing read model on a reader thread (`Database.read`), never through new SQL, and
    nothing is written.

How it works
    `rotator_status` reads two numbers from metrics.db (this cycle's and today's rotator bytes) and two facts the
    context already memoizes (active cooldown rows, for the park key, and the leak guard's `service_state` row).
    `ua_experiment_arms` reads the samples since the experiment (or one of its User-Agent strings) last changed,
    bounded by `request_sample_hours` and by `read_history.MAX_ROWS` rows: an estimate, labeled as one, whose call
    counts are sampled calls (a lower bound when `request_sample_pct` is below 100).

What to read next
    `roxy/insights/rules/upstream.py` (the rules that use these), `roxy/egress/rotator.py` (the budget),
    `roxy/egress/headers.py` (the experiment's arm assignment).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from http import HTTPStatus
from typing import Any, Final

from roxy.core.reasons import Egress
from roxy.egress.clients import DISABLED_KEY_PREFIX
from roxy.egress.headers import HeaderProfiles
from roxy.egress.rotator import DECIMAL_GB, DECIMAL_MB, PARK_KEY, cycle_start_for, day_start_for, usage_since
from roxy.insights.context import InsightContext
from roxy.metrics.queries import Window

UA_EXPERIMENT_KEYS: Final[tuple[str, ...]] = (
    "ua_experiment_enabled",
    "direct_user_agent",
    "ua_experiment_alt_user_agent",
)
"""A change to any of these starts a new comparison: older samples belong to another experiment."""
SAMPLE_SOURCE: Final = "request_samples"
"""`source` of arms estimated from request samples (the provider's own numbers carry `provider`)."""
TOO_MANY_REQUESTS: Final = int(HTTPStatus.TOO_MANY_REQUESTS)


def span_window(start: float, end: float, granularity: str = "minute") -> Window:
    """A half open `[start, end)` window in UTC. `hour` makes long spans read compacted hour rollups first and
    only the newest minutes from the minute table (`metrics/queries.level_pieces`)."""
    return Window(int(start), int(end), granularity, "UTC")


# --------------------------------------------------------------------------------------------- rotator


@dataclass(slots=True)
class RotatorStatus:
    """Whether the rotator could take more traffic, and why not (each reason is admin-facing text)."""

    enabled: bool
    parked: bool
    guard_disabled: bool
    quota_bytes: int
    hard_stop_bytes: int
    daily_cap_bytes: int
    cycle_bytes: int
    day_bytes: int
    reasons: list[str] = field(default_factory=list)

    @property
    def available(self) -> bool:
        """Switched on, not parked or disabled, and inside a configured quota."""
        return not self.reasons

    @property
    def quota_used_pct(self) -> float | None:
        return round(self.cycle_bytes * 100.0 / self.quota_bytes, 2) if self.quota_bytes > 0 else None

    def to_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "parked": self.parked,
            "guard_disabled": self.guard_disabled,
            "quota_bytes": self.quota_bytes,
            "cycle_bytes": self.cycle_bytes,
            "day_bytes": self.day_bytes,
            "quota_used_pct": self.quota_used_pct,
            "reasons": list(self.reasons),
        }


async def rotator_status(ctx: InsightContext) -> RotatorStatus:
    """The rotator's availability for a share shift (UP-429-HOST, UP-CHALLENGE)."""
    enabled = ctx.flag("rotator_enabled")
    now_ms = int(ctx.now * 1000)
    parked = any(row.key == PARK_KEY and row.active(now_ms) for row in await ctx.cooldowns())
    guard_disabled = bool(await ctx.service_state(DISABLED_KEY_PREFIX + Egress.ROTATOR.value))
    quota = int(float(ctx.setting("rotator_quota_gb_per_month")) * DECIMAL_GB)
    stop_pct = float(ctx.setting("rotator_hard_stop_pct"))
    hard_stop = int(quota * stop_pct / 100) if quota > 0 and stop_pct > 0 else 0
    cap = int(float(ctx.setting("rotator_daily_cap_mb")) * DECIMAL_MB)
    cycle = cycle_start_for(ctx.now, int(ctx.setting("rotator_billing_day")))
    day = day_start_for(ctx.now)

    def read(conn: Any) -> tuple[int, int]:
        # The rotator's own budget read (finest rows first), so this agrees with its hard stop byte for byte.
        return usage_since(conn, Egress.ROTATOR.value, cycle), usage_since(conn, Egress.ROTATOR.value, day)

    cycle_bytes, day_bytes = await ctx.dbs.metrics.read(read)
    status = RotatorStatus(enabled, parked, guard_disabled, quota, hard_stop, cap, cycle_bytes, day_bytes)
    if not enabled:
        status.reasons.append("the rotator is switched off (rotator_enabled is 0)")
    if parked:
        status.reasons.append("the rotator is parked after repeated failures")
    if guard_disabled:
        status.reasons.append("the credential leak guard disabled the rotator")
    if quota <= 0:
        status.reasons.append("no monthly rotator quota is configured, so its budget cannot be checked")
    elif cycle_bytes >= quota or (hard_stop and cycle_bytes >= hard_stop):
        status.reasons.append("the rotator has used its monthly quota")
    if cap and day_bytes >= cap:
        status.reasons.append("the rotator reached its daily cap")
    return status


# ------------------------------------------------------------------------------------ UA experiment


async def experiment_started_at(ctx: InsightContext, since: float) -> float:
    """When the running User-Agent comparison started: the newest change of `UA_EXPERIMENT_KEYS` after `since`,
    else `since` (the experiment ran unchanged for the whole span)."""
    started = since
    for change in await ctx.recent_changes(since):
        if change.get("kind") == "setting" and change.get("key") in UA_EXPERIMENT_KEYS:
            started = max(started, float(change["at"]))
    return started


async def ua_experiment_arms(ctx: InsightContext) -> dict[str, Any] | None:
    """`{arms: [{user_agent, calls, roblox_429}], source, ...}` while the experiment runs, or None."""
    found = await ctx.providers.ua_experiment()
    if found is not None:
        return {**found, "source": found.get("source", "provider")}
    if not ctx.flag("ua_experiment_enabled"):
        return None
    window = ctx.window(hours=float(ctx.setting("request_sample_hours")))
    started = await experiment_started_at(ctx, window.start)
    if started >= window.end:
        return None
    samples = await ctx.samples(span_window(started, window.end))
    return arms_from_samples(samples, ctx.settings)


def arms_from_samples(samples: Sequence[Mapping[str, Any]], settings: Mapping[str, Any]) -> dict[str, Any]:
    """Direct calls and Roblox 429s per experiment arm (see the module docstring). Pure, so it is unit tested."""
    profiles = HeaderProfiles(settings, "")
    counts: dict[str, list[int]] = {"primary": [0, 0], "alt": [0, 0]}
    for sample in samples:
        if sample.get("egress") != Egress.DIRECT.value or sample.get("upstream_status") is None:
            continue  # only calls that reached Roblox on the direct path are part of the experiment
        identity = str(sample.get("key_id") or sample.get("endpoint_template") or "")
        arm = profiles.ua_variant(Egress.DIRECT, identity)
        counts[arm][0] += 1
        if int(sample["upstream_status"]) == TOO_MANY_REQUESTS:
            counts[arm][1] += 1
    labels = {"primary": str(settings["direct_user_agent"]), "alt": str(settings["ua_experiment_alt_user_agent"])}
    return {
        "arms": [
            {"arm": arm, "user_agent": labels[arm], "calls": calls, "roblox_429": limited}
            for arm, (calls, limited) in counts.items()
        ],
        "source": SAMPLE_SOURCE,
        "sample_pct": float(settings["request_sample_pct"]),
    }


__all__ = [
    "SAMPLE_SOURCE",
    "UA_EXPERIMENT_KEYS",
    "RotatorStatus",
    "arms_from_samples",
    "experiment_started_at",
    "rotator_status",
    "span_window",
    "ua_experiment_arms",
]
