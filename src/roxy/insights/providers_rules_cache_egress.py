"""Context reads for the cache, host, egress and credential rules (plan 11.5) that `InsightContext` does not offer yet.

What this is
    Async functions that take the rule's `InsightContext` and return one fact each, memoized for the evaluation
    run exactly like the context's own methods (one read per run, however many rules ask):
    - `spread(ctx)`: cache.db entries as `cache/spread.py SpreadRow`s (CACHE-KEYSPLIT, CACHE-LOW-HIT);
    - `error_refetches(ctx, window)`: samples of repeated Roblox 404/400 answers per cache key (CACHE-NEG);
    - `host_callers(ctx, window)`: distinct callers of hosts refused as `host_not_allowed` (HOST-ADD);
    - `credential_calls(ctx, window)`: Roxy's own credential calls by trigger and purpose (CRED-PROBE-COST);
    - `egress_split(ctx, egress, start, end)` and `rotator_budget(ctx)`: metered usage of the billing cycle and the
      plan 8.4 projection (EGR-BURN, EGR-UNDERUSE, EGR-CALIBRATE);
    - `leak_trips(ctx)`: egresses the leak guard disabled (CRED-ROTATOR-GUARD);
    - `credential_comparisons(ctx, window)`: anonymous versus credential answers to the same request (CRED-UNUSED),
      from the provider seam (`x_credential_comparisons`, the fixtures) and from `credential_comparison` events.

Why it exists
    The engine report asks rule authors to add data the context lacks through a module of their own instead of
    editing `insights/context.py` (owned by the engine author). Each read here calls a read model of the package
    that owns the data (DESIGN.md section 13: `cache/read_spread.py`, `metrics/read_refetch.py`,
    `metrics/read_hosts.py`, `metrics/read_internal.py`, `egress/read_usage.py`, `egress/read_state.py`,
    `egress/rotator.py`, `metrics/read_upstream.py`); nothing here holds SQL or business logic of another package.
    These functions are candidates for `InsightContext` methods (see the P10 rules_cache_egress report).

How it works
    `_memo` uses the context's own per-run memo and lock (`InsightContext._cached`), so concurrent rules of one run
    share one database read; every database call goes through `Database.read` on a reader thread (never on the
    event loop). Nothing is ever written.

    Production source of credential comparisons: no module records them yet (README extensions,
    `x_credential_comparisons`). This module defines the event that a comparison producer (the 18.4 shadow
    comparison kept running for allowlisted templates) writes through `MetricsRecorder.record_event`: type
    `credential_comparison`, detail `{endpoint_template, method, anon_status, cred_status, identical}` with
    `identical` true when both paths answered 2xx with the same body hash. Until it exists, CRED-UNUSED only sees
    what a provider supplies.

What to read next
    `roxy/insights/rules/cache.py`, `roxy/insights/rules/egress.py`, `roxy/insights/rules/credential.py`.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Awaitable, Callable
from dataclasses import asdict, dataclass
from typing import Any, Final

from roxy.cache import read_spread
from roxy.cache.spread import DEFAULT_MAX_ROWS, SpreadRow, rows_from_db
from roxy.egress import read_state, read_usage
from roxy.egress.rotator import DECIMAL_GB, day_start_for
from roxy.insights.context import InsightContext
from roxy.metrics import read_hosts, read_internal, read_refetch, read_upstream
from roxy.metrics.queries import Window

COMPARISON_EVENT: Final = "credential_comparison"
"""`events.type` of one anonymous versus credential comparison (see the module docstring)."""
COMPARISON_SECTION: Final = "x_credential_comparisons"
"""The provider seam (README extensions) that carries the same comparisons in fixtures."""
MAX_COMPARISON_EVENTS: Final = 20_000
"""Most comparison events one read takes (P9)."""
ROTATOR: Final = "rotator"
DAY_S: Final = 86_400


async def _memo[T](ctx: InsightContext, key: tuple[Any, ...], make: Callable[[], Awaitable[T]]) -> T:
    """The context's per-run memo, under this module's own key prefix."""
    return await ctx._cached(("rules_cache_egress", *key), make)


# ------------------------------------------------------------------------------------------------- cache


async def spread(ctx: InsightContext, max_rows: int = DEFAULT_MAX_ROWS) -> list[SpreadRow]:
    """The newest cache.db content entries as `SpreadRow`s (the input of `cache/spread.py compute_spread`)."""

    async def make() -> list[SpreadRow]:
        raw = await ctx.dbs.cache.read(lambda c: read_spread.spread_rows(c, max_rows))
        return rows_from_db(raw)  # decoded once per run, however many rules group the rows

    return await _memo(ctx, ("spread", int(max_rows)), make)


# ----------------------------------------------------------------------------------------------- metrics


async def error_refetches(ctx: InsightContext, window: Window) -> list[dict[str, Any]]:
    """Repeated Roblox error answers per (template, cache key, status) in the window (`metrics/read_refetch.py`)."""
    return await _memo(
        ctx,
        ("refetch", window.start, window.end),
        lambda: ctx.dbs.metrics.read(lambda c: read_refetch.error_refetches(c, window.start, window.end)),
    )


async def host_callers(ctx: InsightContext, window: Window) -> dict[str, dict[str, Any]]:
    """Distinct callers of each host refused as `host_not_allowed` in the window (`metrics/read_hosts.py`)."""
    return await _memo(
        ctx,
        ("hosts", window.start, window.end),
        lambda: ctx.dbs.metrics.read(lambda c: read_hosts.unknown_host_callers(c, window.start, window.end)),
    )


async def credential_calls(ctx: InsightContext, window: Window) -> list[dict[str, Any]]:
    """Roxy's own credential calls by trigger and purpose in the window (`metrics/read_internal.py`)."""
    return await _memo(
        ctx,
        ("credential_calls", window.start, window.end),
        lambda: ctx.dbs.metrics.read(lambda c: read_internal.credential_calls(c, window.start, window.end)),
    )


# ------------------------------------------------------------------------------------------------ egress


async def egress_split(ctx: InsightContext, egress: str, start: int, end: int | None = None) -> dict[str, int]:
    """Metered usage of one egress in `[start, end)`, split into its parts (`egress/read_usage.py`)."""
    return await _memo(
        ctx,
        ("egress_split", egress, int(start), end),
        lambda: ctx.dbs.metrics.read(lambda c: read_usage.usage_split(c, egress, start, end)),
    )


@dataclass(frozen=True, slots=True)
class RotatorBudget:
    """This billing cycle of the rotator: what was used, the plan 8.4 projection, and the quota (decimal bytes)."""

    cycle_start: int
    cycle_end: int
    used_bytes: int
    overhead_bytes: int
    requests: int
    quota_bytes: int
    projection: read_state.Projection

    @property
    def used_pct(self) -> float | None:
        """Used as a percent of the quota (None while no quota is set, plan D12)."""
        return read_state.pct_of(self.used_bytes, self.quota_bytes)

    @property
    def projected_pct(self) -> float | None:
        return read_state.pct_of(self.projection.projected_bytes, self.quota_bytes)

    def to_dict(self) -> dict[str, Any]:
        out = asdict(self)
        out["projection"] = self.projection.as_dict()
        out["used_pct"] = self.used_pct
        out["projected_pct"] = self.projected_pct
        return out


async def rotator_budget(ctx: InsightContext) -> RotatorBudget:
    """The rotator's billing cycle at the context's `now`, computed like the Egress page budget panel
    (`admin/api/egress.py rotator_budget`): `egress/read_state.py billing_cycle` and `project_cycle`, the cycle's
    usage from `egress_usage`, and the trailing complete UTC days from `metrics/read_upstream.py`."""
    now = ctx.now
    billing_day = int(ctx.setting("rotator_billing_day"))
    start, end = read_state.billing_cycle(now, billing_day)
    today = day_start_for(now)
    trailing_from = today - read_state.TRAILING_DAYS * DAY_S
    split = await egress_split(ctx, ROTATOR, start)
    trailing = await _memo(
        ctx,
        ("rotator_days", trailing_from, today),
        lambda: ctx.dbs.metrics.read(lambda c: read_upstream.rotator_daily_bytes(c, trailing_from, today)),
    )
    projection = read_state.project_cycle(
        cycle_start=start, cycle_end=end, now_s=now, used_bytes=split["total_bytes"], trailing=trailing
    )
    quota = int(float(ctx.setting("rotator_quota_gb_per_month")) * DECIMAL_GB)
    return RotatorBudget(
        cycle_start=start,
        cycle_end=end,
        used_bytes=split["total_bytes"],
        overhead_bytes=split["overhead_bytes"],
        requests=split["requests"],
        quota_bytes=quota,
        projection=projection,
    )


async def leak_trips(ctx: InsightContext) -> dict[str, dict[str, Any]]:
    """`{egress: {reason, since, location, purpose, request_id, worker}}` for egresses the leak guard disabled."""
    return await _memo(ctx, ("leak_trips",), lambda: ctx.dbs.control.read(read_state.leak_trips))


# -------------------------------------------------------------------------------------------- credential


async def credential_comparisons(ctx: InsightContext, window: Window) -> list[dict[str, Any]]:
    """Anonymous versus credential comparisons: the provider seam's rows plus `credential_comparison` events in the
    window, each `{endpoint_template, method, anon_status, cred_status, identical}` (module docstring)."""

    async def make() -> list[dict[str, Any]]:
        # `extra` is the provider seam for `x_` sections (insights/context.py), not Django's QuerySet.extra.
        rows = [dict(row) for row in await ctx.providers.extra(COMPARISON_SECTION)]  # noqa: S610
        for event in await ctx.events([COMPARISON_EVENT], window, limit=MAX_COMPARISON_EVENTS):
            detail = dict(event.get("detail") or {})
            detail.setdefault("endpoint_template", event.get("endpoint_template"))
            detail["count"] = int(event.get("count") or 1)
            rows.append(detail)
        return rows

    return await _memo(ctx, ("comparisons", window.start, window.end), make)


def utc_text(ts: float) -> str:
    """A Unix time as `YYYY-MM-DD HH:MM UTC` for explanations."""
    return dt.datetime.fromtimestamp(float(ts), dt.UTC).strftime("%Y-%m-%d %H:%M UTC")


def counted(n: float, noun: str) -> str:
    """`1 key`, `2 keys`, `3 entries`: a count with its noun in the right number, for explanations."""
    value = round(n) if float(n).is_integer() else n
    if value == 1:
        return f"1 {noun}"
    if noun.endswith("y") and noun[-2:-1] not in ("a", "e", "i", "o", "u"):
        word = noun[:-1] + "ies"
    elif noun.endswith(("s", "x", "ch", "sh")):
        word = noun + "es"
    else:
        word = noun + "s"
    return f"{value:,} {word}"


__all__ = [
    "COMPARISON_EVENT",
    "COMPARISON_SECTION",
    "RotatorBudget",
    "counted",
    "credential_calls",
    "credential_comparisons",
    "egress_split",
    "error_refetches",
    "host_callers",
    "leak_trips",
    "rotator_budget",
    "spread",
    "utc_text",
]
