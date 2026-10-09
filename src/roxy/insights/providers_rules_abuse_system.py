"""Context extensions for the abuse, filter, system and security rules: memoized per-caller reads (plan 11.5).

What this is
    Async functions that take the evaluation's `InsightContext` and return facts its own methods do not expose yet:
    refusals grouped by reason, place and template (`refusal_groups`), request samples that reached Roblox grouped by
    place or client hash (`sampled_upstream`, `sampled_place_templates`, `sampled_upstream_minutes`), the
    fingerprinted User-Agent texts (`recent_user_agents`), and `long_window`, an hour-granularity window for
    look-backs longer than the minute rollups keep.

Why it exists
    Rules never open a database themselves (`rules/base.py`, step 4). FILTER-COLLATERAL, PLACE-HEAVY, THROTTLE-TUNE
    and ABUSE-DIST need per-caller numbers that live in existing tables (`events` refusal rows, `request_samples`,
    `fingerprint_user_agents`) but that `InsightContext` has no method for. Keeping the extension in one module of
    its own, reached only through the context's databases and memo, leaves `insights/context.py` (owned by the
    engine) untouched; the integrator may fold these into `InsightContext` later without changing any rule.

How it works
    - Each function memoizes its answer in the context (`InsightContext._cached`, keyed under `abuse_system`), so
      every rule of one run that asks the same question costs one read, exactly like the context's own methods.
    - The SQL lives in `roxy/metrics/read_caller_facts.py` (read models next to their data, DESIGN 13) and runs on a
      reader thread through `Database.read`, never on the event loop.
    - Nothing here is a provider of facts without a table: production and the fixture harness read the same tables.

What to read next
    `roxy/metrics/read_caller_facts.py` (the queries), `roxy/insights/rules/abuse.py` (the rules that use them),
    `roxy/insights/context.py` (the context's own methods).
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import TYPE_CHECKING, Any, Final

from roxy.metrics import read_caller_facts
from roxy.metrics.queries import Window

if TYPE_CHECKING:
    from roxy.insights.context import InsightContext

MEMO_PREFIX: Final = "abuse_system"
"""First element of every memo key this module adds to a context (no clash with the context's own keys)."""
HOUR_S: Final = 3600


def long_window(start: float, end: float) -> Window:
    """`[start, end)` at hour granularity, so a read covers the hour and day rollups the minute level no longer
    holds (plan 6.10: minute rollups are kept `retention_minute_days`, hours and days much longer)."""
    lo = int(start) // 60 * 60
    hi = int(end) // 60 * 60
    return Window(lo, max(hi, lo + 60), "hour", "UTC")


async def refusal_groups(
    ctx: InsightContext,
    window: Window,
    *,
    reasons: Iterable[str] | None = None,
    places: Iterable[str] | None = None,
) -> list[dict[str, Any]]:
    """Refused requests in the window by (reason, place, endpoint template), largest first (memoized)."""
    wanted_reasons = tuple(sorted(set(reasons))) if reasons is not None else None
    wanted_places = tuple(sorted(set(places))) if places is not None else None
    key = (MEMO_PREFIX, "refusals", window.start, window.end, wanted_reasons, wanted_places)

    def read(conn: Any) -> list[dict[str, Any]]:
        return read_caller_facts.refusal_groups(
            conn, window.start, window.end, reasons=wanted_reasons, places=wanted_places
        )

    found: list[dict[str, Any]] = await ctx._cached(key, lambda: ctx.dbs.metrics.read(read))
    return found


async def sampled_upstream(ctx: InsightContext, window: Window, column: str) -> dict[str, Any]:
    """`{rows, total, groups}`: sampled requests that reached Roblox in the window, by `place`, `client_hash` or
    `endpoint_template` (memoized)."""
    key = (MEMO_PREFIX, "sampled", window.start, window.end, column)
    found: dict[str, Any] = await ctx._cached(
        key,
        lambda: ctx.dbs.metrics.read(
            lambda conn: read_caller_facts.sampled_upstream_by(conn, window.start, window.end, column)
        ),
    )
    return found


async def sampled_place_templates(ctx: InsightContext, window: Window, place: str) -> dict[str, int]:
    """`{template: sampled requests that reached Roblox}` of one place (memoized)."""
    key = (MEMO_PREFIX, "place_templates", window.start, window.end, place)
    found: dict[str, int] = await ctx._cached(
        key,
        lambda: ctx.dbs.metrics.read(
            lambda conn: read_caller_facts.sampled_place_templates(conn, window.start, window.end, place)
        ),
    )
    return found


async def sampled_upstream_minutes(ctx: InsightContext, window: Window, place: str, template: str) -> dict[int, int]:
    """`{minute: sampled requests that reached Roblox}` of one place on one template (memoized)."""
    key = (MEMO_PREFIX, "place_minutes", window.start, window.end, place, template)
    found: dict[int, int] = await ctx._cached(
        key,
        lambda: ctx.dbs.metrics.read(
            lambda conn: read_caller_facts.sampled_upstream_minutes(
                conn, window.start, window.end, place=place, template=template
            )
        ),
    )
    return found


async def recent_user_agents(ctx: InsightContext) -> list[str]:
    """Fingerprinted User-Agent texts, newest first (memoized)."""
    found: list[str] = await ctx._cached(
        (MEMO_PREFIX, "user_agents"), lambda: ctx.dbs.metrics.read(read_caller_facts.recent_user_agents)
    )
    return found


__all__ = [
    "MEMO_PREFIX",
    "long_window",
    "recent_user_agents",
    "refusal_groups",
    "sampled_place_templates",
    "sampled_upstream",
    "sampled_upstream_minutes",
]
