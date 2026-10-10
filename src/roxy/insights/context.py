"""InsightContext: everything a recommendation rule may read, in one read-only object built per evaluation.

What this is
    `InsightContext` (plan 11.1 `ctx`) gives rules read access to rollups through `metrics/queries.py` (`totals`,
    `by`, `by_template`, `per_minute`), Roblox 429 rows, request samples, cache change observations and stored key
    texts, settings (`setting`), the rule tables (`rules`, `rule_rows`, `cache_rule_for`, `bucket_limit`), hot.db
    state (cooldowns, breakers, bucket fill), the insight history tables (bucket history, worker samples, cache
    evictions, rule hits, error occurrences, upstream attempts), events, egress usage, anomalies, recent config
    changes, the latest health run and the credential's metadata, plus the producer history of schema version 5
    (rule hits per minute, tarpit statistics, recorded bot scores: `rule_hit_counts`, `tarpit_summary`,
    `recorded_scores`). `InsightProviders` is the seam for facts the fixtures give directly (disk sizes and growth,
    DNS answers and the address classifier, tarpit totals, bot scores, the UA experiment, the metrics drop counter,
    egress metering mode, and `x_` extras); `DefaultProviders` is the production implementation and the fixture
    harness supplies its own.

Why it exists
    Rules must be pure decisions over data (plan 11.1): no rule opens a database, writes anything, or knows how a
    number is stored. One context also lets one evaluation run share reads: every method memoizes its answer for
    the context's lifetime (one run), so 50 rules asking "429s per template in the last hour" cost one query.

How it works
    - `now` is fixed when the context is built (the evaluation time); windows are half open `[start, end)` in Unix
      seconds, minute granularity, built by `window(minutes=...)`.
    - Every database read runs on a reader thread through `Database.read` (never on the event loop), and every
      result is bounded by the read model it comes from (plan P9).
    - `settings` is the immutable `SettingsSnapshot` of the run and `rules` the `RulesSnapshot`, so all rules of
      one run see the same configuration.
    - `DefaultProviders` reads what the producers recorded (`metrics/read_producers.py`): tarpit totals and the
      arrival gaps after a hold and after an instant refusal for the last hour (TARPIT-TUNE), the latest recorded
      bot score of every client seen in the last 25 hours (ABUSE-BOT, THROTTLE-TUNE, ABUSE-DIST), the items every
      worker dropped in the last hour (SYS-METRICS-DROP; one worker's lifetime counter only when the table cannot
      be read), and disk growth, table sizes and rollup rows per minute from the hourly disk samples (SYS-DISK).
      Each answer is kept `PROVIDER_MEMO_S` seconds, so the rules of one run that ask the same seam cost one read.

What to read next
    `roxy/insights/rules/base.py` (how rules use this), `roxy/metrics/queries.py` and `roxy/metrics/read_history.py`
    (the read models behind the methods).
"""

from __future__ import annotations

import asyncio
import copy
import ipaddress
import logging
import sqlite3
import time
from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final, TypeVar

from roxy.cache import read_observations
from roxy.cache.policy import select_rule
from roxy.config import catalog, read_changes, read_settings
from roxy.core.clock import SYSTEM_CLOCK, Clock
from roxy.egress import read_credential
from roxy.metrics import disk_history, queries, read_history, read_producers
from roxy.metrics.queries import Page, Window
from roxy.rules.models import RULE_TABLES, CacheRuleRow
from roxy.rules.service import fetch_all
from roxy.storage.db import SharedStateUnavailable
from roxy.upstream import breaker, buckets, cooldowns
from roxy.upstream.buckets import endpoint_bucket_key, host_bucket_key

log = logging.getLogger(__name__)

T = TypeVar("T")

MAX_GROUPS: Final = 10_000
"""Most groups `by()` returns (40 pages of 250): far above the 2,000-template vocabulary (plan 6.2)."""
_PAGE: Final = 250
DAY_S: Final = 86_400
PROVIDER_MEMO_S: Final = 10.0
"""How long `DefaultProviders` keeps an answer (one evaluation run asks the same seam from several rules)."""
TARPIT_WINDOW_S: Final = 3600
"""TARPIT-TUNE reads the tarpit totals of the last hour (fixture README `state.tarpit`)."""
PIPELINE_WINDOW_S: Final = 3600
"""SYS-METRICS-DROP counts the items every worker dropped in the last hour (fixture README)."""
SCORE_WINDOW_S: Final = 25 * 3600
"""Recorded bot scores of clients seen in the last 25 hours (THROTTLE-TUNE reads 24 h; one hour of margin)."""
DIMS_WINDOW_DAYS: Final = 7
"""SYS-DISK `dims_per_minute_7d_avg`: the mean over the disk samples of the last 7 days."""


# --------------------------------------------------------------------------------------------- providers


class InsightProviders:
    """Facts without a table (README "Provider seams"). Every method may return None for "not known here"; a rule
    then treats the fact as unknown and does not fire on it. This base class knows nothing; see `DefaultProviders`.
    """

    async def disk(self) -> dict[str, Any] | None:
        """`{total_bytes, free_bytes, files: {name: {bytes, wal_bytes}}, tables: {...}, growth: [{at, total_bytes}],
        dims_per_minute_7d_avg}` for SYS-DISK."""
        return None

    async def dns(self, host: str) -> dict[str, Any] | None:
        """`{answers: [address, ...], latency_ms, error}` for one host name (HOST-ADD)."""
        del host
        return None

    def classify_address(self, address: str) -> str:
        """`public` or `private` for one DNS answer (HOST-ADD, H-DNS). Production: Python's `is_global`."""
        try:
            return "public" if ipaddress.ip_address(address).is_global else "private"
        except ValueError:
            return "private"

    async def tarpit(self) -> dict[str, Any] | None:
        """`{eligible_holds, skipped, holds, gap_with_hold_s, gap_without_hold_s}` for the last hour (TARPIT-TUNE)."""
        return None

    async def client_scores(self) -> dict[str, float]:
        """`{ip: bot_score}` for the clients that have one (ABUSE-BOT, THROTTLE-TUNE). Missing means unknown."""
        return {}

    async def ua_experiment(self) -> dict[str, Any] | None:
        """`{arms: [{user_agent, calls, roblox_429}]}` while the UA experiment runs (UP-UA-EXPERIMENT)."""
        return None

    async def metrics_pipeline(self) -> dict[str, Any] | None:
        """`{dropped}`: metrics items dropped by the batch writers in the last hour (SYS-METRICS-DROP)."""
        return None

    async def egress_metering(self) -> dict[str, Any]:
        """`{metering_mode: socket|estimate, provider_reported_bytes, provider_reported_at}` (EGR-CALIBRATE)."""
        return {"metering_mode": "socket"}

    async def extra(self, name: str) -> list[dict[str, Any]]:
        """Rows of an `x_` section that no module records yet (for example `x_credential_comparisons`)."""
        del name
        return []

    async def row_extra(self, table: str, key: Any) -> dict[str, Any]:
        """`x_` columns of one control.db row that no table stores yet."""
        del table, key
        return {}


class DefaultProviders(InsightProviders):
    """Production providers: what a worker can measure itself, plus what the producers recorded in metrics.db
    (module docstring). A fact nothing records stays unknown (None); the fixture format does not change when a
    module starts recording one.

    `dbs` (the worker's `Databases`) and `clock` default to the recorder's, so `InsightsEngine.from_context` needs
    no change to read the producer history.
    """

    def __init__(
        self,
        *,
        state_dir: Path | None = None,
        db_paths: Mapping[str, Path] | None = None,
        recorder: Any = None,
        dns_timeout_s: float = 2.0,
        dbs: Any = None,
        clock: Clock | None = None,
        memo_s: float = PROVIDER_MEMO_S,
    ) -> None:
        self.state_dir = state_dir
        self.db_paths = dict(db_paths or {})
        self.recorder = recorder
        self.dns_timeout_s = dns_timeout_s
        self.dbs = dbs if dbs is not None else getattr(recorder, "dbs", None)
        self.clock: Clock = clock or getattr(recorder, "clock", None) or SYSTEM_CLOCK
        self.memo_s = float(memo_s)
        self._memo: dict[str, tuple[float, Any]] = {}

    # ---- helpers ----

    async def _remember(self, name: str, make: Callable[[], Awaitable[T]]) -> T:
        """`make()`, kept `memo_s` seconds (monotonic), so the rules of one run asking one seam cost one read."""
        found = self._memo.get(name)
        moment = time.monotonic()
        if found is not None and moment - found[0] < self.memo_s:
            return found[1]  # type: ignore[no-any-return]
        value = await make()
        self._memo[name] = (moment, value)
        return value

    async def _read_metrics(self, fn: Callable[[Any], T]) -> T | None:
        """`fn(conn)` on a metrics.db reader, or None when there is no database or it cannot answer (a table a
        newer migration adds, a locked or missing file): a provider then says "not known here"."""
        db = getattr(self.dbs, "metrics", None)
        if db is None:
            return None
        try:
            return await db.read(fn)  # type: ignore[no-any-return]
        except (SharedStateUnavailable, sqlite3.Error) as exc:
            log.debug("insights_provider_read_failed", extra={"fields": {"error": f"{type(exc).__name__}: {exc}"}})
            return None

    # ---- disk (SYS-DISK) ----

    def _disk_now(self) -> dict[str, Any] | None:
        if self.state_dir is None:
            return None
        measure = disk_history.measure_files(self.state_dir, self.db_paths)
        return {
            "total_bytes": measure.total_bytes,
            "free_bytes": measure.free_bytes,
            "files": measure.files,
            "tables": {},
            "growth": [],
        }

    async def _disk(self) -> dict[str, Any] | None:
        # stat() calls touch the disk: on a thread, never on the event loop (AGENT_BRIEF).
        current = await asyncio.to_thread(self._disk_now)
        if current is None:
            return None
        now = self.clock.now()
        since = int(now - disk_history.GROWTH_DAYS * DAY_S)
        week = int(now - DIMS_WINDOW_DAYS * DAY_S)
        history = await self._read_metrics(
            lambda conn: (
                read_producers.disk_growth(conn, since),
                read_producers.latest_table_sizes(conn),
                read_producers.rollup_rows_avg(conn, week),
            )
        )
        if history is None:
            return current
        growth, tables, dims = history
        storage = sum(int(v.get("bytes") or 0) + int(v.get("wal_bytes") or 0) for v in current["files"].values())
        if growth and now - float(growth[0]["at"]) >= disk_history.MIN_GROWTH_SPAN_S:
            # The samples plus a point now that equals today's storage (the fixture README growth shape).
            current["growth"] = [*growth, {"at": int(now), "total_bytes": storage}]
        current["tables"] = dict(tables.get("tables") or {})
        current["tables_sampled_at"] = tables.get("at")
        current["dims_per_minute_7d_avg"] = dims
        return current

    async def disk(self) -> dict[str, Any] | None:
        return copy.deepcopy(await self._remember("disk", self._disk))  # a rule may change its copy

    # ---- tarpit (TARPIT-TUNE) ----

    async def _tarpit(self) -> dict[str, Any] | None:
        now = int(self.clock.now())
        summary = await self._read_metrics(
            lambda conn: read_producers.tarpit_summary(conn, now - TARPIT_WINDOW_S, now + 1)
        )
        if summary is None:
            return None
        return {
            "eligible_holds": summary["eligible"],
            "skipped": summary["skipped"],
            "holds": summary["holds"],
            "gap_with_hold_s": summary["gap_after_hold_s"],
            "gap_without_hold_s": summary["gap_after_instant_s"],
            "mean_hold_s": summary["mean_hold_s"],
            "p95_hold_s": summary["p95_hold_s"],
            "by_category": summary["by_category"],
            "window_s": TARPIT_WINDOW_S,
        }

    async def tarpit(self) -> dict[str, Any] | None:
        return copy.deepcopy(await self._remember("tarpit", self._tarpit))

    # ---- bot scores (ABUSE-BOT, THROTTLE-TUNE, ABUSE-DIST) ----

    async def _scores(self) -> dict[str, float]:
        since = int(self.clock.now()) - SCORE_WINDOW_S
        found = await self._read_metrics(lambda conn: read_producers.client_scores(conn, since))
        return {ip: float(value) for ip, value in (found or {}).items()}

    async def client_scores(self) -> dict[str, float]:
        return dict(await self._remember("scores", self._scores))

    async def dns(self, host: str) -> dict[str, Any] | None:
        loop = asyncio.get_running_loop()
        started = loop.time()
        try:
            infos = await asyncio.wait_for(loop.getaddrinfo(host, 443), timeout=self.dns_timeout_s)
        except (OSError, TimeoutError) as exc:
            return {"answers": [], "latency_ms": round((loop.time() - started) * 1000, 1), "error": type(exc).__name__}
        answers = sorted({str(info[4][0]) for info in infos})
        return {"answers": answers, "latency_ms": round((loop.time() - started) * 1000, 1), "error": None}

    # ---- metrics drops (SYS-METRICS-DROP) ----

    def _worker_drops(self) -> dict[str, Any] | None:
        """The fallback: this worker's lifetime counter (scope `worker`), when the fleet table cannot be read."""
        stats = getattr(self.recorder, "stats", None)
        if stats is None:
            return None
        try:
            return {"dropped": int(stats().get("metrics_dropped", 0)), "scope": "worker"}
        except Exception:
            return None

    async def _pipeline(self) -> dict[str, Any] | None:
        now = int(self.clock.now())
        drops = await self._read_metrics(
            lambda conn: read_producers.pipeline_drops(conn, now - PIPELINE_WINDOW_S, now + 1)
        )
        if drops is None:
            return self._worker_drops()
        return {
            "dropped": drops["dropped"],
            "scope": "fleet",
            "window_s": PIPELINE_WINDOW_S,
            "history_dropped": drops["history_dropped"],
            "capture_dropped": drops["capture_dropped"],
            "workers": len(drops["workers"]),
        }

    async def metrics_pipeline(self) -> dict[str, Any] | None:
        return copy.deepcopy(await self._remember("pipeline", self._pipeline))


# ----------------------------------------------------------------------------------------------- context


def minute_floor(ts: float) -> int:
    return int(ts) // 60 * 60


@dataclass(slots=True)
class InsightContext:
    """Read-only view for one evaluation run (see the module docstring)."""

    now: float
    dbs: Any  # roxy.storage.db.Databases
    settings: Mapping[str, Any]  # SettingsSnapshot of this run
    rules: Any  # roxy.rules.store.RulesSnapshot of this run
    providers: InsightProviders = field(default_factory=InsightProviders)
    clock: Clock = SYSTEM_CLOCK
    trigger: str = "schedule"
    _memo: dict[tuple[Any, ...], Any] = field(default_factory=dict)
    _locks: dict[tuple[Any, ...], asyncio.Lock] = field(default_factory=dict)

    # ---- memo ----

    async def _cached(self, key: tuple[Any, ...], make: Callable[[], Awaitable[T]]) -> T:
        if key in self._memo:
            return self._memo[key]  # type: ignore[no-any-return]
        lock = self._locks.setdefault(key, asyncio.Lock())
        async with lock:
            if key not in self._memo:
                self._memo[key] = await make()
        return self._memo[key]  # type: ignore[no-any-return]

    async def _metrics(self, key: tuple[Any, ...], fn: Callable[[Any], T]) -> T:
        return await self._cached(("metrics", *key), lambda: self.dbs.metrics.read(fn))

    # ---- settings ----

    def setting(self, key: str) -> Any:
        """The value of a catalog setting in this run's snapshot. Unknown keys raise KeyError (a typo is a bug)."""
        return self.settings[key]

    def flag(self, key: str) -> bool:
        return bool(int(self.setting(key)))

    # ---- windows ----

    def window(
        self,
        minutes: float | None = None,
        *,
        hours: float | None = None,
        days: float | None = None,
        seconds: float | None = None,
        end: float | None = None,
    ) -> Window:
        """`[end - span, end)` at minute granularity, `end` defaulting to `now` (floored to the minute when the
        evaluation time is not on a minute, so the window holds whole minutes of rollups)."""
        span = float(seconds or 0) + float(minutes or 0) * 60 + float(hours or 0) * 3600 + float(days or 0) * 86_400
        if span <= 0:
            raise ValueError("a window needs a positive length")
        stop = int(self.now if end is None else end)
        stop = stop if stop % 60 == 0 else minute_floor(stop) + 60
        return Window(int(stop - span), stop, "minute", "UTC")

    # ---- rollups (metrics/queries.py) ----

    async def totals(self, window: Window, filters: Mapping[str, Any] | None = None) -> dict[str, Any]:
        """Every measure of `metrics/queries.py` summed over the window (with `roblox_429` when filterable)."""
        frozen = _freeze(filters)
        return await self._metrics(
            ("totals", window, frozen), lambda c: queries.totals_sync(c, window, filters=filters)
        )

    async def by(
        self, window: Window, dimension: str, filters: Mapping[str, Any] | None = None
    ) -> dict[Any, dict[str, Any]]:
        """`{value: measures}` for every value of one dimension (`queries.top_n_sync`, all pages)."""
        frozen = _freeze(filters)

        def read(conn: Any) -> dict[Any, dict[str, Any]]:
            out: dict[Any, dict[str, Any]] = {}
            page = 1
            while True:
                result = queries.top_n_sync(
                    conn, window, dimension, page=Page(page=page, size=_PAGE, sort="requests"), filters=filters
                )
                for row in result["rows"]:
                    out[row["key"]] = row
                if page * _PAGE >= result["total"] or len(out) >= MAX_GROUPS:
                    return out
                page += 1

        return await self._metrics(("by", window, dimension, frozen), read)

    async def by_template(self, window: Window, filters: Mapping[str, Any] | None = None) -> dict[Any, dict[str, Any]]:
        """`by(window, "endpoint_template")`."""
        return await self.by(window, "endpoint_template", filters)

    async def per_minute(self, window: Window, filters: Mapping[str, Any] | None = None) -> dict[int, dict[str, Any]]:
        """`{minute_start: measures}` for every minute of the window that has rows (`queries.collect`)."""
        frozen = _freeze(filters)

        def read(conn: Any) -> dict[int, dict[str, Any]]:
            data = queries.collect(conn, window, filters=filters)
            return {int(bucket or 0): totals.derived() for (bucket, _g), totals in data.items()}

        return await self._metrics(("per_minute", window, frozen), read)

    async def roblox_429(
        self,
        window: Window,
        *,
        group_by: Iterable[str] = ("endpoint_template",),
        per_minute: bool = False,
        where: Mapping[str, Any] | None = None,
    ) -> dict[tuple[Any, ...], int]:
        """Roblox 429s from the `upstream_429` log, grouped (keys are tuples in `group_by` order)."""
        groups = tuple(group_by)
        frozen = _freeze(where)
        return await self._metrics(
            ("429", window, groups, per_minute, frozen),
            lambda c: read_history.roblox_429_counts(
                c, window.start, window.end, group_by=groups, per_minute=per_minute, where=dict(where or {})
            ),
        )

    async def upstream_429_rows(self, window: Window, template: str | None = None) -> list[dict[str, Any]]:
        return await self._metrics(
            ("429rows", window, template),
            lambda c: read_history.upstream_429_rows(c, window.start, window.end, template),
        )

    async def samples(self, window: Window, templates: Iterable[str] | None = None) -> list[dict[str, Any]]:
        """`request_samples` rows in the window, in time order (the input of plan 11.3 replay and tuning)."""
        wanted = tuple(sorted(set(templates))) if templates is not None else None
        return await self._metrics(
            ("samples", window, wanted),
            lambda c: read_history.samples_between(c, window.start, window.end, wanted),
        )

    async def refusal_samples(self, window: Window) -> list[dict[str, Any]]:
        """`refusal_samples` rows in the window, in time order: requests a limiter refused (metrics.db schema 7), the
        refused part of the stream a limit dry run replays (finding LOGICFIX-5)."""
        return await self._metrics(
            ("refusal_samples", window),
            lambda c: read_history.refusal_samples_between(c, window.start, window.end),
        )

    async def internal_calls(self, window: Window) -> list[dict[str, Any]]:
        return await self._metrics(("internal", window), lambda c: queries.internal_calls(c, window))

    async def egress_bytes(self, window: Window) -> dict[str, int]:
        return await self._metrics(("egress_bytes", window), lambda c: queries.egress_bytes(c, window))

    async def egress_usage(self, window: Window) -> dict[str, Any]:
        return await self._metrics(("egress_usage", window), lambda c: queries.egress_usage_series(c, window))

    async def clients(self, window: Window, client_type: str) -> list[dict[str, Any]]:
        """Every client of a type (`ip` or `place`) in the window with requests, refused and served."""

        def read(conn: Any) -> list[dict[str, Any]]:
            rows: list[dict[str, Any]] = []
            page = 1
            while True:
                result = queries.client_table_sync(
                    conn, window, client_type, now=self.now, page=Page(page=page, size=_PAGE, sort="requests")
                )
                rows += result["rows"]
                if page * _PAGE >= result["total"] or len(rows) >= MAX_GROUPS:
                    return rows
                page += 1

        return await self._metrics(("clients", window, client_type), read)

    # ---- insight history (metrics/read_history.py) ----

    async def bucket_summary(self, window: Window, keys: Iterable[str] | None = None) -> dict[str, dict[str, float]]:
        wanted = tuple(sorted(set(keys))) if keys is not None else None
        return await self._metrics(
            ("bucket_summary", window, wanted),
            lambda c: read_history.bucket_summary(c, window.start, window.end, wanted),
        )

    async def bucket_history(self, bucket_key: str, window: Window) -> list[dict[str, Any]]:
        return await self._metrics(
            ("bucket_history", bucket_key, window),
            lambda c: read_history.bucket_history(c, bucket_key, window.start, window.end),
        )

    async def worker_history(self, window: Window) -> dict[str, list[dict[str, Any]]]:
        return await self._metrics(
            ("workers", window), lambda c: read_history.worker_history(c, window.start, window.end)
        )

    async def heartbeats(self, fresh_s: float) -> list[dict[str, Any]]:
        since = int(self.now - fresh_s)
        return await self._metrics(("heartbeats", since), lambda c: read_history.heartbeats(c, since))

    async def cache_summary(self, window: Window) -> dict[str, Any]:
        return await self._metrics(
            ("cache_summary", window), lambda c: read_history.cache_summary(c, window.start, window.end)
        )

    async def eviction_passes(self, window: Window) -> list[dict[str, Any]]:
        return await self._metrics(
            ("passes", window), lambda c: read_history.eviction_passes(c, window.start, window.end)
        )

    async def rule_hits(self, table: str | None = None) -> dict[tuple[str, str], dict[str, int | None]]:
        return await self._metrics(("rule_hits", table), lambda c: read_history.rule_hits(c, table))

    async def rule_last_hit(self, table: str, key: Any) -> int | None:
        """When a rule row last matched a request (None: never since it was created)."""
        hits = await self.rule_hits(table)
        entry = hits.get((table, str(key)))
        return None if entry is None else entry.get("last_hit_at")

    # ---- producer history (metrics/read_producers.py, schema version 5) ----

    async def rule_hit_counts(self, window: Window, table: str | None = None) -> dict[tuple[str, str], int]:
        """`{(table, rule key): hits}` in the window, from the per-minute rule hit history (plan 10.9)."""
        return await self._metrics(
            ("rule_hit_counts", window, table),
            lambda c: read_producers.rule_hit_counts(c, window.start, window.end, table),
        )

    async def tarpit_summary(self, window: Window) -> dict[str, Any]:
        """Tarpit holds, skips, mean and p95 hold and arrival gaps in the window (`read_producers.tarpit_summary`)."""
        return await self._metrics(
            ("tarpit_summary", window), lambda c: read_producers.tarpit_summary(c, window.start, window.end)
        )

    async def recorded_scores(self, since: float) -> dict[str, int]:
        """`{client address: bot score}` recorded since `since` (each client's latest hour)."""
        return await self._metrics(
            ("recorded_scores", int(since)), lambda c: read_producers.client_scores(c, int(since))
        )

    async def error_signatures(self) -> list[dict[str, Any]]:
        return await self._metrics(("error_signatures",), read_history.error_signatures)

    async def error_counts(self, start: float, end: float) -> dict[str, int]:
        return await self._metrics(
            ("error_counts", int(start), int(end)), lambda c: read_history.error_counts(c, int(start), int(end))
        )

    async def error_series(self, signature: str, start: float, end: float) -> list[tuple[int, int]]:
        return await self._metrics(
            ("error_series", signature, int(start), int(end)),
            lambda c: read_history.error_series(c, signature, int(start), int(end)),
        )

    async def attempts(self, window: Window, template: str | None = None) -> list[dict[str, Any]]:
        return await self._metrics(
            ("attempts", window, template), lambda c: read_history.attempt_rows(c, window.start, window.end, template)
        )

    async def events(self, types: Iterable[str], window: Window, limit: int | None = None) -> list[dict[str, Any]]:
        """`events` rows of the given types in the window (breaker openings, probes, spam detections, logins, ...)."""
        wanted = tuple(sorted(set(types)))
        return await self._metrics(
            ("events", wanted, window, limit),
            lambda c: read_history.events_between(c, wanted, window.start, window.end, limit),
        )

    async def anomalies(self, window: Window) -> list[dict[str, Any]]:
        return await self._metrics(
            ("anomalies", window), lambda c: read_history.anomalies_between(c, window.start, window.end)
        )

    async def health_latest(self) -> dict[str, Any] | None:
        return await self._metrics(("health",), read_history.latest_health_run)

    async def provider_report(self) -> dict[str, Any] | None:
        return await self._metrics(("provider_report",), read_history.latest_provider_report)

    # ---- cache.db ----

    async def change_observations(self, start: float, end: float) -> dict[str, tuple[int, int]]:
        """`{template: (refetches, identical_bodies)}` over the day rows overlapping `[start, end)` (plan F10)."""
        return await self._cached(
            ("observations", int(start), int(end)),
            lambda: self.dbs.cache.read(lambda c: read_observations.change_observations(c, start, end)),
        )

    async def key_texts(self, ids: Iterable[str]) -> dict[str, dict[str, Any]]:
        wanted = tuple(sorted(set(ids)))
        return await self._cached(
            ("key_texts", wanted), lambda: self.dbs.cache.read(lambda c: read_observations.key_texts(c, wanted))
        )

    # ---- control.db ----

    async def rule_rows(self, table: str) -> list[dict[str, Any]]:
        """Every stored row of a rule table (`rules/service.py fetch_all`), including disabled rows."""
        spec = RULE_TABLES[table]
        return await self._cached(("rule_rows", table), lambda: self.dbs.control.read(lambda c: fetch_all(c, spec)))

    async def recent_changes(self, since: float, until: float | None = None) -> list[dict[str, Any]]:
        """Settings and rule changes in `[since, until)` (default until now), oldest first."""
        end = self.now + 1 if until is None else until
        return await self._cached(
            ("changes", int(since), int(end)),
            lambda: self.dbs.control.read(lambda c: read_changes.recent_changes(c, since, end)),
        )

    async def setting_timeline(self, key: str, since: float) -> list[tuple[int, Any]]:
        """The values setting `key` had from `since` on: `[(from_s, value)]`, oldest first, the first entry the value
        in force at `since` (`config/read_settings.py value_timeline`; the dry run's sampling rate per sample time,
        finding LOGICFIX-6)."""
        spec = catalog.CATALOG[key]
        default = catalog.DEFAULTS.get(key, spec.default)
        live = self.setting(key)
        return await self._cached(
            ("timeline", key, int(since)),
            lambda: self.dbs.control.read(
                lambda c: read_settings.value_timeline(c, key, since, default=default, live=live)
            ),
        )

    async def service_state(self, key: str) -> Any:
        return await self._cached(
            ("service_state", key), lambda: self.dbs.control.read(lambda c: read_changes.service_state(c, key))
        )

    async def credential_meta(self) -> dict[str, Any] | None:
        return await self._cached(("credential",), lambda: self.dbs.control.read(read_credential.credential_meta))

    # ---- hot.db (upstream state) ----

    async def cooldowns(self) -> list[Any]:
        """Active cooldown rows (`upstream/cooldowns.py active_rows`)."""
        now_ms = int(self.now * 1000)
        return await self._cached(("cooldowns",), lambda: self.dbs.hot.read(lambda c: cooldowns.active_rows(c, now_ms)))

    async def breakers(self) -> list[dict[str, Any]]:
        """Breakers that are open, half open or counting failures (`upstream/breaker.py snapshot`)."""
        return await self._cached(("breakers",), lambda: self.dbs.hot.read(lambda c: breaker.snapshot(c, self.now)))

    async def bucket_states(self) -> list[buckets.BucketState]:
        """Stored buckets with their fill level now (`upstream/buckets.py bucket_states`)."""
        now_ms = int(self.now * 1000)
        return await self._cached(
            ("bucket_states",), lambda: self.dbs.hot.read(lambda c: buckets.bucket_states(c, now_ms))
        )

    # ---- rules snapshot helpers ----

    def cache_rule_for(self, target: str, method: str = "GET") -> CacheRuleRow | None:
        """The cache rule the cache would apply to `target` (`host/path` or a template) for `method`
        (`cache/policy.py select_rule`, honoring `cache_default_rules_enabled`)."""
        return select_rule(self.rules, target, method.upper(), bool(int(self.setting("cache_default_rules_enabled"))))

    def bucket_limit(self, bucket_key: str) -> dict[str, Any]:
        """`{per_min, burst, overridden, origin}` of a `host:` or `endpoint:` bucket: its `upstream_limits` row, or
        the catalog default it runs at (`endpoint_bucket_default_*`, `host_bucket_default_*`)."""
        row = self.rules.upstream_limit(bucket_key)
        if row is not None:
            return {"per_min": float(row.per_min), "burst": int(row.burst), "overridden": True, "origin": row.origin}
        kind = "endpoint" if bucket_key.startswith("endpoint:") else "host"
        return {
            "per_min": float(self.setting(f"{kind}_bucket_default_per_min")),
            "burst": int(self.setting(f"{kind}_bucket_default_burst")),
            "overridden": False,
            "origin": "default",
        }

    @staticmethod
    def endpoint_bucket(template: str) -> str:
        return endpoint_bucket_key(template)

    @staticmethod
    def host_bucket(host: str) -> str:
        return host_bucket_key(host)


def _freeze(value: Any) -> Any:
    """A hashable copy of a filter mapping (memo keys)."""
    if value is None:
        return None
    if isinstance(value, Mapping):
        return tuple(sorted((str(k), _freeze(v)) for k, v in value.items()))
    if isinstance(value, list | tuple | set | frozenset):
        return tuple(_freeze(v) for v in value)
    return value


__all__ = ["DefaultProviders", "InsightContext", "InsightProviders", "minute_floor"]
