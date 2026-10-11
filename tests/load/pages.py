"""Dashboard page latency under real gunicorn: plan 6.7's "first render under 300 ms, a 90 day chart under 500 ms".

What this is
    `python -m load.pages [--runs quiet,quiet@0-1,load@0-1,load] [--rounds N] [--rounds-90d N] [--json PATH]
    [--work DIR] [--keep] [--tree DIR] [--requests-per-day N] [--history-days N] [--load-rate R]`, run from the
    `tests/` directory like `load.harness` (and inside the same private network namespace). It builds ONE state
    directory with realistic data, then for every run copies it, starts gunicorn the way production does
    (`deploy/gunicorn.conf.py`, 2 `RoxyUvicornWorker` workers, `ROXY_WORKERS=2`; a run written `mode@0-1` pins the
    master and its workers to CPUs 0 and 1 with `taskset`, the production server's 2 vCPU), signs an admin in
    through the real password and TOTP steps, and measures the main dashboard pages (Overview, Traffic, Upstream,
    Cache, Clients, Protection, Live, Security, Settings, Audit):
    - the default pass loads each page (the shell plus every eager card) and then each of its cards' fragments one
      at a time, as `static/js/cards.js` does after the page loaded (lazy cards) and on a refresh (eager cards);
    - the 90 day pass loads every page and fragment again with `range=90d`, and every chart series route of the
      admin API over 90 days (`SERIES_ROUTES`), once at the automatic granularity (days) and once at the finest a
      90 day chart allows (`granularity=hour`, 2,160 points);
    - `load` runs keep the `steady` scenario's proxy mix flowing (200 requests a second by default) from separate
      processes for the whole measurement.
    Every request's server time is read from Roxy's own `http_request` log line (the app time and time to first
    byte measured by `core/middleware.py TimingMiddleware`, joined on `Roxy-Request-Id`); the client's time, the
    HTML bytes and the first-paint size (the HTML plus the render-blocking stylesheets) are recorded beside it.

Why it exists
    Plan 6.7 sets the dashboard targets and plan 19.4 wants them measured on the production size; P11_INPUTS left
    "plan 6.7 dashboard latency targets are measured once the pages exist" open. The numbers are only honest with
    data at realistic volume: an empty metrics.db answers every query in a millisecond. Hence the seeding below,
    through Roxy's own writers wherever one exists.

How it works
    Seeding (`seed_state`, once per command; `--work DIR --keep` keeps the template for a rerun with
    `--reuse-template`):
    - a day of proxy traffic at plan 6.6's sizing (500,000 requests, a daily curve, the v1-like endpoint mix,
      2,000 game server addresses calling for 150 places, cache hits, misses, refusals, pacing answers and Roblox
      failures in realistic shares) fed through the real `MetricsRecorder` on a fake clock that walks the day, so
      rollups, client activity, events, request samples, egress usage, fingerprints, 429s, retries, internal
      calls, bucket history and the security tables (probes, logins, crawls, visits) are written by the code that
      writes them in production;
    - that day copied back over the retention of each level: minute rows for 14 days (`retention_minute_days`),
      client minutes for 3, then the real compaction (`rollups.compact_all`), then hour rows for `--history-days`
      (90) and the day and month levels compacted again from them; events and Roblox 429s copied over 90 days and
      cut to their caps by the real retention pass, ids kept in time order;
    - the audit log at plan 6.6's estimate (200 actions a day for 400 days, settings changes through the real
      `SettingsService`), 30 daily health runs with every check, and a few recommendations in each state;
    - a 60 s warm phase of real traffic through gunicorn (the cache, hot.db limiter rows, the live tail).
    Each run starts from a copy of that template, waits `scenarios.WARMUP_S` like every scenario (the leader's
    first jobs), then measures. `ROXY_LOG_LEVEL=debug` makes every request log its `http_request` line (at INFO
    only requests over 10 s do); nothing else in the request path logs at DEBUG.

What to read next
    docs/PERFORMANCE.md "Dashboard pages", `fleet.py` (the system under test), `src/roxy/admin/pages/kit.py` (how a
    page and its fragments render).
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import dataclasses
import gzip
import html
import json
import multiprocessing
import os
import random
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import traceback
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Final
from urllib.parse import parse_qsl, urlencode, urlsplit

import httpx

from load.client import percentile
from load.fleet import (
    AdminProbe,
    Fleet,
    ResourceSampler,
    base_env,
    fake_credentials,
    prepare_state,
    query,
    unit_environment,
    unit_memory_limits,
)
from load.harness import (
    EXIT_NO_NAMESPACE,
    NAMESPACE_ENV,
    TESTS_DIR,
    absolute_paths,
    can_unshare,
    loopback_up,
    machine,
    option_value,
    python_path,
)
from load.harness import table as text_table
from load.mock_roblox import MockRoblox
from load.scenarios import STEADY_BUCKETS, STEADY_MISS_LATENCY_S, WARMUP_S, mock_endpoints
from load.traffic import (
    ROBLOX_UA,
    V1_LIKE_MIX,
    EndpointMix,
    MixPicker,
    Zipf,
    benchmark_addresses,
    build_request,
    documentation_addresses,
)

DAY_S: Final = 86_400
HOUR_S: Final = 3_600

PAGE_IDS: Final[tuple[str, ...]] = (
    "overview", "traffic", "upstream", "cache", "clients", "protection", "live", "security", "settings", "audit",
)  # fmt: skip
"""The pages the lead named for plan 6.7 (the busiest ones an owner opens)."""

FIRST_RENDER_TARGET_MS: Final = 300.0
"""Plan 6.7: "Dashboard page first render under 300 ms"."""
CHART_TARGET_MS: Final = 500.0
"""Plan 6.7: "any chart query over 90 days under 500 ms"."""

GZIP_LEVEL: Final = 1
"""nginx's default `gzip_comp_level`: what a first visit downloads for the static files (`deploy/nginx`; admin HTML
is never compressed there, BREACH)."""


# =============================================================================================== seeding


@dataclass(frozen=True, slots=True)
class Volume:
    """How much data the template holds (defaults: plan 6.6's sizing, 10 times v1's scale)."""

    requests_per_day: int = 500_000
    history_days: int = 90
    minute_days: int = 14
    client_minute_days: int = 3
    servers: int = 2_000
    """Game server addresses (D11: one experience reaches Roxy from hundreds of servers)."""
    places: int = 150
    probes_per_day: int = 6_000
    """Exploit and probe attempts in the day (the table keeps `max_exploit_records`, 5,000)."""
    crawls_per_day: int = 400
    logins_per_day: int = 30
    audit_per_day: int = 200
    """Plan 6.6: "audit (400 days x maybe 200 actions/day x 1 KB)"."""
    audit_days: int = 400
    settings_changes: int = 240
    health_runs: int = 30
    seed: int = 2026


@dataclass(frozen=True, slots=True)
class Kind:
    """One kind of answer a caller gets, with its share of the traffic (percent) and its recorded dimensions."""

    weight: float
    outcome: str
    reason: str
    status: int
    source: str
    cache_state: str
    calls: int
    check: str = ""


KINDS: Final[tuple[Kind, ...]] = (
    Kind(38.0, "served_cache", "cache_hit", 200, "cache", "HIT", 0),
    Kind(3.0, "served_cache", "cache_coalesced", 200, "cache", "COALESCED", 0),
    Kind(2.0, "served_cache", "cache_revalidating", 200, "cache", "REVALIDATING", 0),
    Kind(0.5, "served_cache", "cache_stale_cooldown", 200, "cache", "STALE", 0),
    Kind(40.0, "served_upstream", "upstream_ok", 200, "roblox", "MISS", 1),
    Kind(2.5, "served_upstream", "upstream_4xx", 404, "roblox", "MISS", 1),
    Kind(1.5, "served_upstream", "upstream_4xx", 400, "roblox", "MISS", 1),
    Kind(0.3, "failed", "upstream_5xx", 503, "roxy", "MISS", 2),
    Kind(0.2, "failed", "upstream_timeout", 504, "roxy", "MISS", 1),
    Kind(2.5, "failed", "upstream_cooldown", 429, "roxy", "MISS", 0),
    Kind(1.0, "failed", "upstream_busy", 429, "roxy", "MISS", 0),
    Kind(4.5, "refused", "throttle", 429, "roxy", "NA", 0, "throttle"),
    Kind(0.4, "refused", "place_limit", 429, "roxy", "NA", 0, "place_limit"),
    Kind(0.3, "refused", "header_rule", 403, "roxy", "NA", 0, "header_rule"),
    Kind(0.2, "refused", "endpoint_blocked", 403, "roxy", "NA", 0, "endpoint_blocked"),
    Kind(0.1, "refused", "user_agent_rule", 403, "roxy", "NA", 0, "user_agent_rule"),
    Kind(0.1, "refused", "flood", 429, "roxy", "NA", 0, "flood"),
)
"""The answer mix of the seeded day (relative weights, drawn by `pick`): about 45 percent from the cache, 45 percent
fetched, 5.8 percent refused by the abuse layer, 3.6 percent paced and 0.5 percent failed (plan 2.5 and the replay's
shares)."""

USER_AGENTS: Final[tuple[tuple[str, float], ...]] = (
    (ROBLOX_UA, 94.0), ("Roblox/WinInet", 3.0), ("python-requests/2.32.3", 1.5), ("curl/8.5.0", 1.0),
    ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36", 0.5),
)  # fmt: skip
PROBE_UAS: Final = ("Mozilla/5.0 zgrab/0.x", "python-requests/2.31.0", "Go-http-client/1.1", "masscan/1.3")
PROBE_PATHS: Final = ("/wp-login.php", "/.env", "/admin.php", "/phpmyadmin/", "/.git/config", "/cgi-bin/luci")
CRAWLERS: Final = ("Googlebot/2.1 (+http://www.google.com/bot.html)", "bingbot/2.0", "AhrefsBot/7.0")


def diurnal(total: int, rng: random.Random) -> list[int]:
    """Requests per minute over one day that add up to `total`: a quiet night, a busy evening, a little noise."""
    import math

    weights = [
        max(0.05, 1.0 + 0.55 * math.sin(2 * math.pi * (m / 1440 - 0.35)) + rng.uniform(-0.08, 0.08))
        for m in range(1440)
    ]
    scale = total / sum(weights)
    counts = [int(w * scale) for w in weights]
    for m in rng.sample(range(1440), k=max(0, total - sum(counts))):
        counts[m] += 1
    return counts


def pick(rng: random.Random, weighted: Sequence[tuple[Any, float]]) -> Any:
    """One item of `(item, weight)` pairs, drawn by weight."""
    point = rng.random() * sum(w for _, w in weighted)
    for item, weight in weighted:
        point -= weight
        if point < 0:
            return item
    return weighted[-1][0]


class _ClosedGate:
    """Stands in for the recorder's live-row gate while the backfill walks the day: live rows older than 15 minutes
    are deleted by the leader (`metrics/live.py LIVE_KEEP_S`), so writing them would only be undone."""

    def allow(self) -> bool:
        return False


def _advance(clock: Any, at: float) -> None:
    gap = at - clock.now()
    if gap > 0:
        clock.advance(gap)


async def backfill_day(dbs: Any, settings: Any, key: bytes | None, *, end_s: int, volume: Volume) -> dict[str, int]:
    """One day of traffic, `[end_s - 1 day, end_s)`, through the real `MetricsRecorder` on a fake clock."""
    from roxy.core.clock import FakeClock
    from roxy.core.reasons import AuthClass, CacheState, Egress, Outcome, ReasonCode, Source
    from roxy.metrics.recorder import MetricsRecorder, OutcomeEvent
    from roxy.metrics.templating import template_for

    start_s = end_s - DAY_S
    clock = FakeClock(float(start_s))
    recorder = MetricsRecorder(dbs, settings, clock, worker_id="seed:1:pages", ip_hash_key=key)
    live_gate = getattr(recorder, "_live_gate", None)
    if live_gate is not None:
        recorder._live_gate = _ClosedGate()  # type: ignore[assignment]  # restored for the last 15 minutes
    rng = random.Random(volume.seed)
    picker = MixPicker(V1_LIKE_MIX)
    servers = benchmark_addresses(volume.servers)
    places = [str(9_100_000 + n) for n in range(volume.places)]
    place_of = [places[Zipf(len(places), 1.0).draw(rng) - 1] for _ in servers]
    others = documentation_addresses(300)
    kinds = [(kind, kind.weight) for kind in KINDS]
    templates = {item.name: template_for(item.host, item.path.format(id=item.id_base + 1)) for item in V1_LIKE_MIX}
    counts: Counter[str] = Counter()
    per_minute = diurnal(volume.requests_per_day, rng)

    def outcome_event(at: float, item: EndpointMix, ident: int, kind: Kind, n: int) -> OutcomeEvent:
        server = rng.randrange(len(servers))
        ua = pick(rng, USER_AGENTS)
        path, body = build_request(item, ident, rng)
        concrete, _, query_string = path[1:].partition("?")
        calls = kind.calls
        egress = Egress.NONE
        if calls or kind.reason in ("upstream_cooldown", "upstream_busy"):
            egress = Egress.ROTATOR if rng.random() < 0.7 else Egress.DIRECT
        upstream_ms = item.latency_ms * rng.uniform(0.7, 1.8) if calls else 0.0
        latency = upstream_ms + rng.lognormvariate(1.1, 0.6)
        out_bytes = item.body_bytes + 350 if kind.status == 200 else 120
        return OutcomeEvent(
            at_ms=int(at * 1000),
            request_id=f"SEED{n:022d}",
            endpoint_template=templates[item.name],
            host=item.host,
            method=item.method,
            egress=egress,
            outcome=Outcome(kind.outcome),
            reason=ReasonCode(kind.reason),
            status=kind.status,
            source=Source(kind.source),
            cache_state=CacheState(kind.cache_state),
            auth_class=AuthClass.ANON,
            caller_bytes_in=len(body or b""),
            caller_bytes_out=out_bytes,
            upstream_calls=calls,
            upstream_bytes_in=(item.body_bytes + 900) * calls,
            upstream_bytes_out=(len(body or b"") + 700) * calls,
            latency_ms=latency,
            queue_wait_ms=rng.uniform(0, 4) if calls else 0.0,
            upstream_ms=upstream_ms,
            client_ip=servers[server],
            place_id=place_of[server] if ua.startswith("Roblox") else None,
            user_agent=ua,
            bypass=False,
            error=kind.outcome == "failed" and calls > 0,
            path=concrete,
            query=query_string,
            upstream_status=kind.status if calls else None,
            attempts=calls,
            retries=max(0, calls - 1),
            upstream_error="Roblox answered 503" if kind.reason == "upstream_5xx" else "",
            message_source="default" if kind.outcome == "refused" else "",
            check=kind.check,
        )

    n = 0
    for minute, count in enumerate(per_minute):
        base = start_s + minute * 60
        if live_gate is not None and minute == 1440 - 15:
            recorder._live_gate = live_gate  # the last 15 minutes keep their live rows, as in production
        for offset in sorted(rng.random() * 60 for _ in range(count)):
            at = base + offset
            _advance(clock, at)
            item, ident = picker.draw(rng)
            kind = pick(rng, kinds)
            ev = outcome_event(at, item, ident, kind, n)
            n += 1
            recorder.record_outcome(ev)
            counts[kind.outcome] += 1
            if kind.outcome != "refused":
                headers = [("user-agent", ev.user_agent), ("accept", "*/*"), ("accept-encoding", "gzip")]
                if ev.place_id:
                    headers.append(("roblox-id", ev.place_id))
                if item.method == "POST":
                    headers.append(("content-type", "application/json"))
                recorder.record_fingerprint(headers, ev.user_agent)
            for _ in range(ev.upstream_calls):
                egress = str(ev.egress)
                recorder.record_egress_usage(
                    egress, req_bytes=ev.upstream_bytes_out, resp_bytes=ev.upstream_bytes_in, overhead_bytes=900,
                    at_ms=ev.at_ms,
                )  # fmt: skip
                for bucket in ("global", f"egress:{egress}", f"host:{item.host}", f"endpoint:{ev.endpoint_template}"):
                    recorder.record_bucket(bucket, fill_pct=rng.uniform(5, 60), at_ms=ev.at_ms)
                if rng.random() < 0.001:
                    recorder.record_upstream_429(
                        endpoint_template=ev.endpoint_template, host=item.host, egress=egress,
                        retry_after_s=None if rng.random() < 0.8 else 30.0, at_ms=ev.at_ms,
                        request_id=ev.request_id,
                    )  # fmt: skip
                    counts["roblox_429"] += 1
                if rng.random() < 0.004:
                    recorder.record_retry(
                        status=503, reason="Roblox answered 503", egress=egress,
                        endpoint_template=ev.endpoint_template, at_ms=ev.at_ms,
                    )  # fmt: skip
            if kind.reason == "throttle" and rng.random() < 0.02:
                recorder.record_throttled(ev.client_ip, tier=rng.randint(1, 3), strikes=rng.randint(1, 5))
        # The per-minute side traffic: probes, crawls, visits, logins, Roxy's own calls, worker samples.
        _advance(clock, base + 59.5)
        for _ in range(_spread(volume.probes_per_day, rng)):
            target = rng.choice(PROBE_PATHS)
            reason = pick(
                rng,
                [
                    (f'Non-Roblox URL: "scanner.example.invalid{target}"', 4.0),
                    (f'Invalid URL: "{target}?x=%00"', 1.0),
                    ("Host not allowed", 1.0),
                    (f"HTTP 404 via GET {target}", 3.0),
                ],
            )
            recorder.record_probe(rng.choice(others), reason, rng.choice(PROBE_UAS), target)
            counts["probe"] += 1
        for _ in range(_spread(volume.crawls_per_day, rng)):
            crawler = rng.choice(CRAWLERS)
            recorder.record_crawl(rng.choice(others), rng.choice(("/robots.txt", "/sitemap.xml")), crawler)
            recorder.record_visit("robots", crawler, at_ms=int((base + 59) * 1000))
        recorder.record_visit("home", "Mozilla/5.0", count=rng.randint(0, 3), at_ms=int((base + 30) * 1000))
        for _ in range(_spread(volume.logins_per_day, rng)):
            ok = rng.random() < 0.85
            recorder.record_login(rng.choice(others[:5]), ok, username="owner", method="totp" if ok else "password")
            counts["login"] += 1
        if minute % 10 == 0:
            recorder.record_internal_call(
                "credential liveness", ok=True, status=200, duration_ms=rng.uniform(60, 140),
                endpoint="https://users.roblox.com/v1/users/authenticated", egress=Egress.CREDENTIAL,
                auth_class=AuthClass.CRED, trigger="scheduled", at_ms=int((base + 5) * 1000),
            )  # fmt: skip
        if minute % 30 == 7:
            recorder.record_internal_call(
                "place lookup", ok=True, status=200, duration_ms=rng.uniform(80, 200),
                endpoint="https://apis.roblox.com/universes/v1/places/9100001/universe", trigger="admin",
                at_ms=int((base + 9) * 1000),
            )  # fmt: skip
        if minute % 240 == 13:
            recorder.record_error("TimeoutError: read timed out", detail="upstream read", source="upstream")
        for worker in ("seed:1:pages", "seed:2:pages"):
            for second in (0, 15, 30, 45):
                recorder.record_worker_sample(
                    worker_id=worker, cpu_pct=rng.uniform(4, 30), loop_lag_ms_p99=rng.uniform(1, 12),
                    open_conns=rng.randint(5, 60), rss=160 * 2**20, at_ms=int((base + second) * 1000),
                )  # fmt: skip
        await recorder.flush()
    _advance(clock, float(end_s))
    await recorder.aclose()
    counts["requests"] = n
    return dict(counts)


def _spread(per_day: int, rng: random.Random) -> int:
    """How many of `per_day` events fall in one minute (a Bernoulli draw around the mean)."""
    mean = per_day / 1440
    whole = int(mean)
    return whole + (1 if rng.random() < mean - whole else 0)


ROLLUP_COLUMNS: Final = (
    "bucket_start, dim_hash, requests, caller_bytes_in, caller_bytes_out, upstream_calls, upstream_bytes_in, "
    "upstream_bytes_out, errors, latency_hist, queue_wait_hist"
)
CLIENT_COLUMNS: Final = "bucket_start, client_type, client_key, requests, refused, served, bytes, top_endpoint"
EGRESS_COLUMNS: Final = "bucket_start, egress, granularity, requests, req_bytes, resp_bytes, overhead_bytes"
EVENT_COLUMNS: Final = "at_ms, type, severity, reason_code, ip_hash, place, endpoint_template, detail_json"
ROBLOX_429_COLUMNS: Final = "at_ms, endpoint_template, host, egress, retry_after_s, ratelimit_headers_json, request_id"


def copy_back(
    conn: sqlite3.Connection, table: str, columns: str, *, lo: int, hi: int, days: Iterable[int], where: str = ""
) -> int:
    """Copy the rows of `table` whose `bucket_start` is in `[lo, hi)` to the same times `days` days earlier
    (`INSERT OR IGNORE`: a bucket that already exists keeps its row). Returns the rows written."""
    rest = columns.split(", ", 1)[1]
    written = 0
    for day in days:
        shift = int(day) * DAY_S
        sql = (
            f"INSERT OR IGNORE INTO {table} ({columns}) SELECT bucket_start - ?, {rest} FROM {table} "
            f"WHERE bucket_start >= ? AND bucket_start < ?{where}"
        )
        written += conn.execute(sql, (shift, lo, hi)).rowcount
    return written


def copy_back_by_id(
    conn: sqlite3.Connection, table: str, columns: str, *, lo_ms: int, hi_ms: int, days: int, where: str = ""
) -> int:
    """`events` and `upstream_429` hold ids that readers order by: rewrite the whole table so the copies of the day
    `[lo_ms, hi_ms)` over `days - 1` earlier days and every original row take ids in time order."""
    conn.execute(f"CREATE TEMP TABLE seed_orig AS SELECT {columns} FROM {table} ORDER BY at_ms")
    conn.execute(f"DELETE FROM {table}")
    conn.execute("CREATE TEMP TABLE seed_days (k INTEGER PRIMARY KEY)")
    conn.executemany("INSERT INTO seed_days (k) VALUES (?)", [(k,) for k in range(1, days)])
    rest = columns.split(", ", 1)[1]
    written = conn.execute(
        f"INSERT INTO {table} ({columns}) SELECT at_ms, {rest} FROM ("
        f"SELECT at_ms, {rest} FROM seed_orig UNION ALL "
        f"SELECT o.at_ms - d.k * {DAY_S * 1000}, {', '.join('o.' + c for c in rest.split(', '))} "
        f"FROM seed_orig o, seed_days d WHERE o.at_ms >= ? AND o.at_ms < ?{where}) ORDER BY at_ms",
        (lo_ms, hi_ms),
    ).rowcount
    conn.execute("DROP TABLE seed_orig")
    conn.execute("DROP TABLE seed_days")
    return written


COPIED_EVENT_TYPES: Final = ("refusal", "failure", "internal_call", "retry", "visit", "throttled")
"""Event types with a row per occurrence over the whole retention (90 days); probes, logins and crawls are capped at
5,000 rows each (`security_events.CAP_SETTINGS`), so a day of them already fills the table."""
EVENTS_MAX_ROWS: Final = 2_000_000
"""`storage/retention.py RetentionPolicy.events_max_rows` (plan 6.6: "events capped 2,000,000 rows")."""


async def stretch_history(dbs: Any, *, end_s: int, volume: Volume, tz: str) -> dict[str, int]:
    """Copy the backfilled day back over each level's retention and compact the levels (see the module docstring)."""
    from roxy.metrics.rollups import CompactionConfig, compact_all

    day_lo, day_hi = end_s - DAY_S, end_s
    written: dict[str, int] = {}

    def minutes(conn: sqlite3.Connection) -> None:
        span = range(1, volume.minute_days)
        written["rollup_minute"] = copy_back(conn, "rollup_minute", ROLLUP_COLUMNS, lo=day_lo, hi=day_hi, days=span)
        written["egress_minute"] = copy_back(
            conn, "egress_usage", EGRESS_COLUMNS, lo=day_lo, hi=day_hi, days=span, where=" AND granularity = 'minute'"
        )
        written["client_minute"] = copy_back(
            conn, "client_minute", CLIENT_COLUMNS, lo=day_lo, hi=day_hi, days=range(1, volume.client_minute_days)
        )

    await dbs.metrics.write(minutes)

    async def write(fn: Any) -> Any:
        return await dbs.metrics.write(fn)

    config = CompactionConfig(
        tz_name=tz,
        minute_retention_days=volume.minute_days,
        client_minute_retention_days=volume.client_minute_days,
        max_buckets=100_000,
    )
    await compact_all(write, end_s + 180, config)

    # Hours: one whole compacted day (the day before the backfilled one is a copy of it) copied back to fill the
    # hour retention; then the day and month levels are rebuilt from every hour.
    src_lo = (day_lo - DAY_S) // HOUR_S * HOUR_S
    src_hi = src_lo + DAY_S

    def hours(conn: sqlite3.Connection) -> None:
        span = range(1, volume.history_days - 1)
        written["rollup_hour"] = copy_back(conn, "rollup_hour", ROLLUP_COLUMNS, lo=src_lo, hi=src_hi, days=span)
        written["egress_hour"] = copy_back(
            conn, "egress_usage", EGRESS_COLUMNS, lo=src_lo, hi=src_hi, days=span, where=" AND granularity = 'hour'"
        )
        written["client_hour"] = copy_back(conn, "client_hour", CLIENT_COLUMNS, lo=src_lo, hi=src_hi, days=span)
        for name in ("rollup_day", "rollup_month", "client_day"):
            conn.execute(f"DELETE FROM {name}")
        conn.execute("DELETE FROM egress_usage WHERE granularity IN ('day', 'month')")
        types = ", ".join(repr(t) for t in COPIED_EVENT_TYPES)
        per_day = conn.execute(
            f"SELECT count(*) FROM events WHERE type IN ({types}) AND at_ms >= ? AND at_ms < ?",
            (day_lo * 1000, day_hi * 1000),
        ).fetchone()[0]
        # Copies past the events cap would be deleted by the retention pass at once: stop at the cap.
        event_days = max(1, min(volume.history_days, EVENTS_MAX_ROWS // max(1, int(per_day))))
        written["event_days"] = event_days
        written["events"] = copy_back_by_id(
            conn, "events", EVENT_COLUMNS, lo_ms=day_lo * 1000, hi_ms=day_hi * 1000, days=event_days,
            where=f" AND o.type IN ({types})",
        )  # fmt: skip
        written["upstream_429"] = copy_back_by_id(
            conn, "upstream_429", ROBLOX_429_COLUMNS, lo_ms=day_lo * 1000, hi_ms=day_hi * 1000,
            days=volume.history_days,
        )  # fmt: skip

    await dbs.metrics.write(hours)
    await compact_all(write, end_s + 180, config)
    return written


async def seed_audit(dbs: Any, *, now_s: int, volume: Volume) -> int:
    """The audit log at plan 6.6's estimate, oldest first (ids in time order), with settings changes made through
    the real `SettingsService` at their own times (fake clock), so the settings history agrees with the log."""
    from roxy.config import audit
    from roxy.config.audit import Actor
    from roxy.config.settings_service import SettingsService
    from roxy.core.clock import FakeClock

    rng = random.Random(volume.seed + 7)
    total = volume.audit_per_day * volume.audit_days
    start = now_s - volume.audit_days * DAY_S
    times = sorted(start + rng.random() * (now_s - 600 - start) for _ in range(total))
    change_at = set(rng.sample(range(total), k=min(total, volume.settings_changes)))
    owner = Actor("admin", "owner", "203.0.113.10")
    system = Actor("system", "spam-detector", None)
    clock = FakeClock(float(start))
    service = SettingsService(dbs.control, clock=clock)
    actions = (
        ("rule.create", "rules_user_agent", owner), ("rule.update", "rules_endpoint_limit", owner),
        ("ban.create", "bans", system), ("ban.delete", "bans", owner), ("cache.purge", "cache", owner),
        ("export.download", "table", owner), ("recommendation.apply", "recommendation", owner),
        ("access.create", "access_list", owner), ("data.reset", "data", owner),
    )  # fmt: skip
    batch: list[tuple[Any, ...]] = []
    toggles = 0

    def flush(rows: list[tuple[Any, ...]]) -> Any:
        def write(conn: sqlite3.Connection) -> None:
            for actor, action, target, after, reason, at in rows:
                audit.record(conn, actor, action, target, None, after, reason, None, at=at)

        return dbs.control.write(write)

    for index, at in enumerate(times):
        if index in change_at:
            if batch:
                await flush(batch)
                batch = []
            _advance(clock, at)
            toggles += 1
            value = 150 if toggles % 2 else 120  # ends on the default when the count is even
            await service.update({"cache_ttl_seconds": value}, owner, "seeded change", "admin")
            continue
        action, kind, actor = actions[rng.randrange(len(actions))]
        target = f"{kind}:{rng.randint(1, 400)}"
        after = {"pattern": f"games.roblox.com/v1/games/{rng.randint(1, 900)}/*", "note": "seeded"}
        batch.append((actor, action, target, after, "seeded audit row", int(at)))
        if len(batch) >= 5_000:
            await flush(batch)
            batch = []
    if batch:
        await flush(batch)
    if toggles % 2:
        _advance(clock, float(now_s - 300))
        await service.update({"cache_ttl_seconds": 120}, owner, "seeded change", "admin")
    return total


async def seed_health_and_recommendations(dbs: Any, *, now_s: int, volume: Volume) -> dict[str, int]:
    """A health run a day with every check (the health store's writers), and recommendations in each state."""
    from roxy import __version__
    from roxy.config.insight_params import INSIGHT_RULES
    from roxy.core.clock import FakeClock
    from roxy.core.ids import new_id
    from roxy.health import store
    from roxy.health.checks import SPECS
    from roxy.health.model import CheckResult, Status
    from roxy.insights.engine import write_recommendation
    from roxy.insights.models import Evidence, ProposedChange, Recommendation, make_fingerprint

    rng = random.Random(volume.seed + 11)

    def runs(conn: sqlite3.Connection) -> int:
        for day in range(volume.health_runs, 0, -1):
            started = now_s - day * DAY_S + 4 * HOUR_S
            results = [
                CheckResult(
                    spec.id,
                    pick(rng, [(Status.PASS, 90.0), (Status.WARN, 7.0), (Status.FAIL, 1.0), (Status("n/a"), 2.0)]),
                    "ok",
                    "see the check",
                    "Seeded result.",
                    "",
                    duration_ms=rng.uniform(5, 900),
                )
                for spec in SPECS
            ]
            run_id = store.insert_run(
                conn, started_at=started, trigger="schedule", version=__version__,
                options={"include_credential": False}, actor="system", at_ms=started * 1000, planned=len(results),
            )  # fmt: skip
            for result in results:
                store.insert_result(conn, run_id, result, at_ms=(started + 20) * 1000)
            store.finish_run(
                conn, run_id, finished_at=started + 45, summary=store.summarize(results), at_ms=(started + 45) * 1000,
                trigger="schedule",
            )  # fmt: skip
        return volume.health_runs

    made = await dbs.metrics.write(runs)
    states = ("open",) * 8 + ("applied",) * 4 + ("dismissed",) * 4 + ("expired",) * 6
    rule_ids = sorted(INSIGHT_RULES)
    clock = FakeClock(float(now_s))
    recs = []
    for index, state in enumerate(states):
        rule_id = rule_ids[(index * 7) % len(rule_ids)]
        spec = INSIGHT_RULES[rule_id]
        subject = f"games.roblox.com/v1/games/{index}"
        created = now_s - rng.randint(1, 60) * DAY_S // 2
        rec = Recommendation(
            rule_id=rule_id, family=spec.family, subject=subject, title=f"Seeded recommendation {index}",
            severity=rng.choice(("info", "warn", "critical")), confidence="medium",
            explanation="A seeded recommendation for the page latency scenario.",
            evidence=Evidence(window_from=created - HOUR_S, window_to=created, sample_size=500).add(
                "roblox_429", 12, "responses"
            ),
            changes=[ProposedChange("setting", key="cache_ttl_seconds", current=120, proposed=300)],
            expected_impact="Fewer calls to Roblox.", risk="low",
        )  # fmt: skip
        rec.id = new_id("rec", clock)
        rec.fingerprint = make_fingerprint(rule_id, subject)
        rec.computed_severity = rec.severity
        rec.state = state
        rec.created_at = created
        rec.updated_at = created + 60
        rec.expires_at = created + 7 * DAY_S
        recs.append(rec)

    def write_recs(conn: sqlite3.Connection) -> None:
        for rec in recs:
            write_recommendation(conn, rec)

    await dbs.metrics.write(write_recs)
    return {"health_runs": made, "recommendations": len(recs)}


async def prune_like_the_leader(dbs: Any, settings: Any, *, now_s: int) -> dict[str, int]:
    """The leader's retention pass (caps included) and the live-row prune, so the template starts where a running
    server would be."""
    from roxy.metrics.live import prune_live_events
    from roxy.storage.retention import RETENTION_TASKS, RetentionPolicy, run_tasks

    while await dbs.metrics.write(lambda conn: prune_live_events(conn, float(now_s))) > 0:
        pass
    policy = RetentionPolicy.from_settings(settings.get)
    return await run_tasks(dbs, RETENTION_TASKS, policy, float(now_s), max_batches=10_000)


async def _seed(env: Mapping[str, str], volume: Volume, end_s: int) -> dict[str, Any]:
    from roxy.config.env import EnvSettings
    from roxy.config.runtime import load_runtime_settings
    from roxy.core.iphash import load_ip_hash_key
    from roxy.storage.db import open_databases

    dbs = open_databases(EnvSettings())
    report: dict[str, Any] = {}
    try:
        settings = await load_runtime_settings(dbs)
        key = load_ip_hash_key(Path(env["CREDENTIALS_DIRECTORY"]))
        tz = str(settings.get("ui_timezone") or "UTC")
        started = time.monotonic()
        report["day"] = await backfill_day(dbs, settings, key, end_s=end_s, volume=volume)
        report["day_s"] = round(time.monotonic() - started, 1)
        report.update(await seed_health_and_recommendations(dbs, now_s=end_s, volume=volume))
        report["copied"] = await stretch_history(dbs, end_s=end_s, volume=volume, tz=tz)
        report["audit_rows"] = await seed_audit(dbs, now_s=end_s, volume=volume)
        report["pruned"] = {k: v for k, v in (await prune_like_the_leader(dbs, settings, now_s=end_s)).items() if v}
        report["rows"] = await dbs.metrics.read(_row_counts)
        report["rows"]["audit_log"] = await dbs.control.read(
            lambda conn: int(conn.execute("SELECT count(*) FROM audit_log").fetchone()[0])
        )
        report["seconds"] = round(time.monotonic() - started, 1)
    finally:
        await dbs.close_all()
    return report


COUNTED_TABLES: Final = (
    "rollup_minute", "rollup_hour", "rollup_day", "rollup_month", "dims", "client_minute", "client_hour",
    "client_day", "egress_usage", "events", "request_samples", "refusal_samples", "upstream_429",
    "fingerprint_headers", "fingerprint_values", "fingerprint_user_agents", "bucket_minute", "worker_minute",
    "health_runs", "recommendations",
)  # fmt: skip


def _row_counts(conn: sqlite3.Connection) -> dict[str, int]:
    return {name: int(conn.execute(f"SELECT count(*) FROM {name}").fetchone()[0]) for name in COUNTED_TABLES}


def file_sizes(state: Path) -> dict[str, float]:
    """MiB of each database file (with its WAL) in a state directory."""
    out: dict[str, float] = {}
    for name in ("control", "hot", "metrics", "cache"):
        size = sum(p.stat().st_size for p in state.glob(f"{name}.db*") if p.is_file())
        out[name] = round(size / 2**20, 1)
    return out


# ================================================================================================ the run


class PinnedFleet(Fleet):
    """`Fleet`, started under `taskset -c <cpus>` when `cpus` is set: the master and every worker it forks inherit the
    affinity, so the color has the production server's 2 vCPU however many the machine has."""

    def __init__(self, work: Path, env: Mapping[str, str], *, tree: Path | None = None, cpus: str = "") -> None:
        super().__init__(work, env, tree=tree)
        self.cpus = cpus

    def start(self) -> None:
        if not self.cpus:
            super().start()
            return
        from load.fleet import GUNICORN_CONF, REPO, VENV_BIN

        handle = open(self.log, "ab")  # noqa: SIM115 (kept open for the child's lifetime)
        conf = self.tree / GUNICORN_CONF.relative_to(REPO)
        taskset = shutil.which("taskset") or "/usr/bin/taskset"
        self.proc = subprocess.Popen(
            [taskset, "-c", self.cpus, str(VENV_BIN / "gunicorn"), "-c", str(conf), "roxy.asgi:app"],
            env=self.env,
            cwd=self.tree,
            stdout=handle,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )


def _load_process(base_url: str, rate: float, seed: int, stop: Any, results: Any) -> None:
    """A spawned process sending the `steady` mix (Poisson arrivals at `rate`) until `stop` is set."""
    asyncio.run(_drive_load(base_url, rate, seed, stop, results))


async def _drive_load(base_url: str, rate: float, seed: int, stop: Any, results: Any) -> None:
    rng = random.Random(seed)
    picker = MixPicker(V1_LIKE_MIX, unique_share=0.10, hot_keys=50)
    addresses = benchmark_addresses(4000)
    statuses: Counter[int] = Counter()
    latencies: list[float] = []
    limits = httpx.Limits(max_connections=96, max_keepalive_connections=96)
    async with httpx.AsyncClient(base_url=base_url, limits=limits, timeout=30, trust_env=False) as client:
        gate = asyncio.Semaphore(512)
        tasks: set[asyncio.Task[None]] = set()

        async def one(method: str, path: str, body: bytes | None, ip: str) -> None:
            async with gate:
                started = time.monotonic()
                headers = {"X-Forwarded-For": ip, "User-Agent": ROBLOX_UA}
                if body is not None:
                    headers["Content-Type"] = "application/json"
                try:
                    answer = await client.request(method, path, content=body, headers=headers)
                    statuses[answer.status_code] += 1
                except httpx.HTTPError:
                    statuses[0] += 1
                if len(latencies) < 200_000:
                    latencies.append(time.monotonic() - started)

        began = time.monotonic()
        due = began
        while not stop.is_set():
            due += rng.expovariate(rate)
            delay = due - time.monotonic()
            if delay > 0:
                await asyncio.sleep(delay)
            item, key = picker.draw(rng)
            path, body = build_request(item, key, rng)
            task = asyncio.create_task(one(item.method, path, body, rng.choice(addresses)))
            tasks.add(task)
            task.add_done_callback(tasks.discard)
        elapsed = time.monotonic() - began
        await asyncio.gather(*tasks, return_exceptions=True)
    ordered = sorted(latencies)
    results.put(
        {
            "sent": sum(statuses.values()),
            "seconds": round(elapsed, 1),
            "statuses": {str(k): v for k, v in sorted(statuses.items())},
            "p50_ms": None if not ordered else round(ordered[len(ordered) // 2] * 1000, 1),
            "p99_ms": None
            if not ordered
            else round(ordered[min(len(ordered) - 1, int(len(ordered) * 0.99))] * 1000, 1),
        }
    )


class BackgroundLoad:
    """The proxy load of a `load` run: `processes` spawned senders, `rate` requests a second in total."""

    def __init__(self, base_url: str, rate: float, *, processes: int = 2, seed: int = 2026) -> None:
        context = multiprocessing.get_context("spawn")
        self.stop_event = context.Event()
        self.results = context.Queue()
        share = rate / processes
        self.procs = [
            context.Process(target=_load_process, args=(base_url, share, seed + n, self.stop_event, self.results))
            for n in range(processes)
        ]

    def start(self) -> BackgroundLoad:
        for proc in self.procs:
            proc.start()
        return self

    def stop(self) -> dict[str, Any]:
        self.stop_event.set()
        found = []
        for _ in self.procs:
            with contextlib.suppress(Exception):
                found.append(self.results.get(timeout=60))
        for proc in self.procs:
            proc.join(timeout=30)
            if proc.is_alive():
                proc.kill()
        statuses: Counter[str] = Counter()
        for item in found:
            statuses.update(item["statuses"])
        seconds = max((item["seconds"] for item in found), default=0.0)
        sent = sum(item["sent"] for item in found)
        return {
            "sent": sent,
            "answered_per_s": round(sent / seconds, 1) if seconds else None,
            "statuses": dict(statuses),
            "client_p50_ms": [item["p50_ms"] for item in found],
            "client_p99_ms": [item["p99_ms"] for item in found],
        }


class _PageParser(HTMLParser):
    """The cards of a page (`section[data-card]`), and the assets the browser loads before and after first paint."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.cards: list[tuple[str, str, bool]] = []
        self.stylesheets: list[str] = []
        self.modules: list[str] = []
        self._importmap = False
        self.importmap = ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {name: value or "" for name, value in attrs}
        if tag == "section" and "data-card" in values and values.get("data-card-src"):
            lazy = "page-card--lazy" in values.get("class", "").split()
            self.cards.append((values["data-card"], values["data-card-src"], lazy))
        elif tag == "link" and values.get("rel") == "stylesheet" and values.get("media", "all") != "print":
            self.stylesheets.append(values.get("href", ""))
        elif tag == "script" and values.get("type") == "module" and values.get("src"):
            self.modules.append(values["src"])
        elif tag == "script" and values.get("type") == "importmap":
            self._importmap = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "script":
            self._importmap = False

    def handle_data(self, data: str) -> None:
        if self._importmap:
            self.importmap += data


def parse_page(text: str) -> _PageParser:
    parser = _PageParser()
    parser.feed(text)
    return parser


def with_params(url: str, **params: str) -> str:
    """`url` with `params` set (replacing any value they had)."""
    parts = urlsplit(url)
    kept = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k not in params]
    kept += list(params.items())
    return parts.path + ("?" + urlencode(kept) if kept else "")


@dataclass(slots=True)
class Sample:
    """One request of the page client, with Roxy's own timing joined on its request id."""

    phase: str  # "default" or "90d"
    kind: str  # "page", "fragment", "series", "static"
    page: str
    name: str  # the card id, the series name or the asset path
    url: str
    status: int = 0
    client_ms: float = 0.0
    client_ttfb_ms: float = 0.0
    bytes: int = 0
    request_id: str = ""
    server_ms: float | None = None
    server_ttfb_ms: float | None = None
    pid: int | None = None
    round: int = 0


class PageClient:
    """One signed-in admin sending one request at a time (like a browser tab's card loader), each on a new
    connection: the kernel's `reuse_port` hash then spreads the requests over both workers, as nginx's pool of
    upstream connections does, so a run measures the leader (which also runs the scheduled jobs) and the other
    worker. One keep-alive connection would pin a whole run to one worker."""

    def __init__(self, base_url: str, cookie: str, headers: Mapping[str, str]) -> None:
        self.client = httpx.Client(
            base_url=base_url,
            timeout=60,
            trust_env=False,
            headers={**headers, "Cookie": cookie},
            limits=httpx.Limits(max_keepalive_connections=0),
        )
        self.samples: list[Sample] = []

    def get(self, sample: Sample, extra: Mapping[str, str] | None = None) -> str:
        started = time.perf_counter()
        with self.client.stream("GET", sample.url, headers=dict(extra or {})) as answer:
            first = time.perf_counter()
            body = answer.read()
        done = time.perf_counter()
        sample.status = answer.status_code
        sample.client_ms = round((done - started) * 1000, 2)
        sample.client_ttfb_ms = round((first - started) * 1000, 2)
        sample.bytes = len(body)
        sample.request_id = answer.headers.get("roxy-request-id", "")
        self.samples.append(sample)
        return body.decode("utf-8", "replace")

    def close(self) -> None:
        self.client.close()


def admin_headers(env: Mapping[str, str]) -> dict[str, str]:
    """What a browser on the dashboard sends besides the cookie (the same as `fleet.AdminProbe`'s sign-in)."""
    from roxy.admin.auth.testing import TEST_UA

    return {"Origin": env["ROXY_SITE_ORIGIN"], "Sec-Fetch-Site": "same-origin", "User-Agent": TEST_UA}


def series_routes(env: Mapping[str, str]) -> list[tuple[str, str, dict[str, str]]]:
    """Every chart series route of the admin API (`common.series_answer` and the KPI sparklines), with the
    parameters a drawer would pass; rows found in the seeded state stand in for the ids."""
    from roxy.metrics.templating import template_for

    avatar = V1_LIKE_MIX[0]
    template = template_for(avatar.host, avatar.path.format(id=avatar.id_base + 1))
    routes: list[tuple[str, str, dict[str, str]]] = [
        ("overview chart", "overview/chart", {}),
        ("overview KPI tiles and sparklines", "overview/kpis", {}),
        ("traffic requests", "traffic/requests", {}),
        ("traffic bytes", "traffic/bytes", {}),
        ("traffic verbs", "traffic/verbs", {}),
        ("traffic status classes", "traffic/status", {"view": "class"}),
        ("traffic status by source", "traffic/status", {"view": "source"}),
        ("traffic latency", "traffic/latency", {"split": "none"}),
        ("traffic latency by egress", "traffic/latency", {"split": "egress"}),
        ("traffic heatmap", "traffic/heatmap", {}),
        ("cache hit and avoided ratios", "cache/ratios", {}),
        ("cache states", "cache/states", {}),
        ("cache KPI tiles and sparklines", "cache/stats", {}),
        ("egress call share", "egress/share", {}),
        ("upstream 429 timeline", "upstream/429-timeline", {}),
        ("upstream latency", "upstream/latency", {}),
        ("upstream bucket history", "upstream/buckets/history", {"key": "global"}),
        ("endpoint drill-down", "endpoints/detail", {"template": template}),
    ]
    with contextlib.suppress(sqlite3.Error, IndexError):
        ip = query(
            env["ROXY_METRICS_DB"],
            "SELECT client_key FROM client_day WHERE client_type = 'ip' AND client_key != 'other' "
            "ORDER BY requests DESC LIMIT 1",
        )[0][0]
        routes.append(("client address timeline", f"clients/ips/{ip}", {}))
    with contextlib.suppress(sqlite3.Error, IndexError):
        place = query(
            env["ROXY_METRICS_DB"],
            "SELECT client_key FROM client_day WHERE client_type = 'place' AND client_key != 'other' "
            "ORDER BY requests DESC LIMIT 1",
        )[0][0]
        routes.append(("client place timeline", f"clients/places/{place}", {}))
    with contextlib.suppress(sqlite3.Error, IndexError):
        rule = query(env["ROXY_CONTROL_DB"], "SELECT id FROM rules_user_agent ORDER BY id LIMIT 1")[0][0]
        routes.append(("rule hit history", "protection/rule-hits", {"table": "ua-rules", "rule_id": str(rule)}))
    return routes


def load_page(client: PageClient, phase: str, page: str, round_no: int, params: Mapping[str, str]) -> _PageParser:
    """One page, then each of its cards' fragments one at a time (the order `cards.js` loads lazy cards in)."""
    url = f"/admin/{page}" + (f"?{urlencode(dict(params))}" if params else "")
    text = client.get(Sample(phase, "page", page, "(page)", url, round=round_no))
    found = parse_page(text)
    for card, src, lazy in found.cards:
        fragment = html.unescape(src)
        client.get(
            Sample(phase, "fragment", page, card + ("" if lazy else " (refresh)"), fragment, round=round_no),
            {"HX-Request": "true", "HX-Target": card},
        )
    return found


def static_sizes(client: PageClient, parsed: Mapping[str, _PageParser]) -> dict[str, dict[str, Any]]:
    """Per page: the bytes the browser needs before first paint (stylesheets) and after it (module scripts), raw
    and gzipped as nginx serves the static files."""
    cache: dict[str, tuple[int, int]] = {}

    def size(path: str) -> tuple[int, int]:
        if path not in cache:
            answer = client.client.get(path)
            body = answer.content if answer.status_code == 200 else b""
            cache[path] = (len(body), len(gzip.compress(body, compresslevel=GZIP_LEVEL)))
        return cache[path]

    out: dict[str, dict[str, Any]] = {}
    for page, found in parsed.items():
        css = [size(path) for path in found.stylesheets if path]
        scripts = list(found.modules)
        with contextlib.suppress(ValueError, AttributeError):
            scripts += list(json.loads(found.importmap or "{}").get("imports", {}).values())
        js = [size(path) for path in dict.fromkeys(scripts) if path.startswith("/")]
        out[page] = {
            "css_bytes": sum(raw for raw, _ in css),
            "css_gzip_bytes": sum(packed for _, packed in css),
            "js_bytes": sum(raw for raw, _ in js),
            "js_gzip_bytes": sum(packed for _, packed in js),
            "stylesheets": len(css),
            "scripts": len(js),
        }
    return out


def server_times(log: Path) -> dict[str, dict[str, Any]]:
    """Roxy's `http_request` lines by request id: app time, time to first byte, bytes, worker pid."""
    out: dict[str, dict[str, Any]] = {}
    with contextlib.suppress(OSError), open(log, encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if not line.startswith("{") or '"http_request"' not in line:
                continue
            with contextlib.suppress(ValueError):
                row = json.loads(line)
                if row.get("event") == "http_request" and row.get("request_id"):
                    out[str(row["request_id"])] = row
    return out


def join_server_times(samples: Iterable[Sample], log: Path) -> int:
    """Fill each sample's server fields from the log; returns how many found their line."""
    found = server_times(log)
    joined = 0
    for sample in samples:
        row = found.get(sample.request_id)
        if row is None:
            continue
        sample.server_ms = float(row.get("ms") or 0.0)
        ttfb = row.get("ttfb_ms")
        sample.server_ttfb_ms = None if ttfb is None else float(ttfb)
        sample.pid = int(row["pid"]) if row.get("pid") is not None else None
        joined += 1
    return joined


@dataclass(frozen=True, slots=True)
class RunSpec:
    """One run: `quiet` or `load`, and the CPUs gunicorn is pinned to ("" for none)."""

    mode: str
    cpus: str = ""

    @property
    def name(self) -> str:
        return self.mode + (f"@{self.cpus}" if self.cpus else "")

    @classmethod
    def parse(cls, text: str) -> RunSpec:
        mode, _, cpus = text.partition("@")
        if mode not in ("quiet", "load") or (
            cpus and not all(part.isdigit() for part in cpus.replace("-", ",").split(","))
        ):
            raise ValueError(f"a run is quiet or load, optionally @<cpus> such as @0-1, not {text!r}")
        return cls(mode, cpus)


@dataclass(slots=True)
class Options:
    work: Path
    credentials: Path
    template: Path
    rounds: int = 10
    rounds_90d: int = 3
    load_rate: float = 200.0
    tree: Path | None = None
    keep: bool = False
    seed: int = 2026


def build_template(opts: Options, volume: Volume) -> dict[str, Any]:
    """The seeded state every run copies (see the module docstring), and what went into it."""
    work = opts.template
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)
    mock = MockRoblox(mock_endpoints(V1_LIKE_MIX, limits=False, latency_s=STEADY_MISS_LATENCY_S)).start()
    try:
        env = base_env(work, opts.credentials, mock.base, workers=2, tree=opts.tree)
        began = time.monotonic()
        prepare_state(env, dict(STEADY_BUCKETS), [])
        end_s = int(time.time()) // 60 * 60 - 120
        report = asyncio.run(_seed(env, volume, end_s))
        report["prepare_s"] = round(time.monotonic() - began, 1)
        report["warm"] = warm_phase(opts, work, env)
        report["files_mib"] = file_sizes(Path(env["ROXY_STATE_DIR"]))
        report["end_s"] = end_s
        (work / "seed.json").write_text(json.dumps(report, indent=2, sort_keys=True))
        return report
    finally:
        mock.stop()


def warm_phase(opts: Options, work: Path, env: dict[str, str], *, seconds: float = 60.0) -> dict[str, Any]:
    """Real traffic through gunicorn for `seconds` (the steady mix at 100 a second): the cache, hot.db, the live
    rows and the fingerprints come from the request path itself."""
    fleet = Fleet(work, env, tree=opts.tree)
    fleet.start()
    try:
        if not fleet.wait_ready():
            raise RuntimeError("gunicorn did not start for the warm phase:\n" + fleet.log_tail())
        load = BackgroundLoad(fleet.base_url, 100.0, seed=opts.seed + 99).start()
        time.sleep(seconds)
        result = load.stop()
    finally:
        code, stop_s = fleet.stop()
    result["stop_code"] = code
    result["stop_s"] = stop_s
    return result


def copy_template(opts: Options, work: Path) -> int:
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)
    shutil.copytree(opts.template / "state", work / "state")
    (work / "state").chmod(0o750)
    return refresh_cache_entries(work / "state" / "cache.db", time.time())


def migrate_copy(state: Path) -> dict[str, Any]:
    """Bring a copied state up to the measured Roxy's schema the way a deploy does (`deploy/prestart.py` runs
    `python -m roxy.storage.migrate --expand` before a color starts): a template seeded by an older release (or kept
    across a schema change) then still starts, and the time the expand migrations take on this volume is recorded.
    This process imports the measured tree (`enter_namespace` puts its `src` first on `PYTHONPATH`)."""
    started = time.monotonic()
    done = subprocess.run(
        [sys.executable, "-m", "roxy.storage.migrate", "--expand", "--state-dir", str(state)],
        capture_output=True,
        text=True,
        check=False,
        timeout=1800,
    )
    if done.returncode != 0:
        raise RuntimeError(f"migrating the copied state failed: {done.stderr.strip()[-2000:]}")
    applied = [line.strip() for line in done.stdout.splitlines() if "applied" in line]
    return {"seconds": round(time.monotonic() - started, 1), "applied": applied}


CACHE_ENTRIES: Final = 3_000
"""Shared cache entries a run starts with: about what plan 6.6's volume keeps alive (an entry lives for its rule's
TTL plus its stale window, 15 s to a day, and the dead ones are deleted by `CacheStore.maintain`)."""


def refresh_cache_entries(path: Path, now: float, *, target: int = CACHE_ENTRIES) -> int:
    """Bring a copied cache.db to `target` live entries: the warm phase's entries moved forward in time (the
    template was built minutes before, so they would be dead and deleted at once) and, while short of `target`,
    copies of them under other keys (`id` is `sha256(key)[:24]`, as `cache/keys.py` makes it). Returns the count."""
    import hashlib

    conn = sqlite3.connect(path)
    try:
        newest = conn.execute("SELECT max(stored_at) FROM entries").fetchone()[0]
        if newest is None:
            return 0
        shift = int(now) - int(newest)
        conn.execute(
            "UPDATE entries SET stored_at = stored_at + ?, expires_at = expires_at + ?, "
            "stale_until = stale_until + ?, last_hit_at = last_hit_at + ?",
            (shift, shift, shift, shift),
        )
        columns = [row[1] for row in conn.execute("PRAGMA table_info(entries)")]
        rows = conn.execute(f"SELECT {', '.join(columns)} FROM entries").fetchall()
        count = len(rows)
        copy = 0
        marks = ", ".join("?" for _ in columns)
        while count < target and rows:
            copy += 1
            batch = []
            for row in rows[: target - count]:
                values = dict(zip(columns, row, strict=True))
                values["key"] = f"{values['key']}&roxy_load_copy={copy}"
                values["id"] = hashlib.sha256(values["key"].encode()).hexdigest()[:24]
                batch.append(tuple(values[name] for name in columns))
            conn.executemany(f"INSERT OR IGNORE INTO entries ({', '.join(columns)}) VALUES ({marks})", batch)
            count += len(batch)
        conn.commit()
        return int(conn.execute("SELECT count(*) FROM entries").fetchone()[0])
    finally:
        conn.close()


def run_once(opts: Options, spec: RunSpec) -> dict[str, Any]:
    """One run of the measurement (see the module docstring); returns every sample and the summaries."""
    work = opts.work / spec.name.replace("@", "_cpus_")
    entries = copy_template(opts, work)
    migrated = migrate_copy(work / "state")
    mock = MockRoblox(mock_endpoints(V1_LIKE_MIX, limits=False, latency_s=STEADY_MISS_LATENCY_S)).start()
    fleet: PinnedFleet | None = None
    sampler: ResourceSampler | None = None
    load: BackgroundLoad | None = None
    out: dict[str, Any] = {
        "run": spec.name,
        "mode": spec.mode,
        "cpus": spec.cpus or "all",
        "cache_entries": entries,
        "migrated": migrated,
    }
    try:
        env = base_env(work, opts.credentials, mock.base, workers=2, tree=opts.tree)
        env["ROXY_LOG_LEVEL"] = "debug"  # every request writes its http_request line (module docstring)
        (work / "run").mkdir(parents=True, exist_ok=True)
        (work / "run").chmod(0o750)
        fleet = PinnedFleet(work, env, tree=opts.tree, cpus=spec.cpus)
        started = time.monotonic()
        fleet.start()
        if not fleet.wait_ready():
            raise RuntimeError("gunicorn did not become ready:\n" + fleet.log_tail())
        out["ready_s"] = round(time.monotonic() - started, 1)
        sampler = ResourceSampler(fleet.master_pid).start()
        time.sleep(WARMUP_S)
        probe = AdminProbe(fleet, opts.credentials)
        if not probe.sign_in():
            raise RuntimeError(f"admin sign-in failed: {probe.error}")
        client = PageClient(fleet.base_url, probe.cookie, admin_headers(env))
        if spec.mode == "load":
            load = BackgroundLoad(fleet.base_url, opts.load_rate, seed=opts.seed).start()
            time.sleep(10.0)  # the senders spawn and the rate settles before the first page
        measured_at = time.monotonic()
        parsed: dict[str, _PageParser] = {}
        for round_no in range(opts.rounds):
            for page in PAGE_IDS:
                parsed[page] = load_page(client, "default", page, round_no, {})
        routes = series_routes(env)
        for round_no in range(opts.rounds_90d):
            for page in PAGE_IDS:
                load_page(client, "90d", page, round_no, {"range": "90d"})
            for name, path, params in routes:
                for granularity in ("", "hour"):
                    values = {"range": "90d", **params, **({"granularity": granularity} if granularity else {})}
                    label = name + (" (hourly points)" if granularity else "")
                    client.get(Sample("90d", "series", "api", label, f"/admin/api/v1/{path}?{urlencode(values)}",
                                      round=round_no))  # fmt: skip
        out["measure_s"] = round(time.monotonic() - measured_at, 1)
        out["assets"] = static_sizes(client, parsed)
        client.close()
        if load is not None:
            out["load"] = load.stop()
            load = None
        leader = query(env["ROXY_METRICS_DB"], "SELECT pid FROM worker_heartbeat WHERE is_leader = 1 LIMIT 1")
        out["leader_pid"] = int(leader[0][0]) if leader else None
        sampler.stop()
        out["memory"] = sampler.summary()
        sampler = None
        code, stop_s = fleet.stop()
        out["stop_code"], out["stop_s"] = code, stop_s
        out["joined"] = join_server_times(client.samples, fleet.log)
        out["tracebacks"] = fleet.log_count("Traceback")
        out["unit_environment"] = unit_environment(fleet.tree)
        out["unit_memory"] = unit_memory_limits(fleet.tree)
        out["samples"] = [sample_dict(s) for s in client.samples]
        out["summary"] = summarize(client.samples, out["assets"], out.get("leader_pid"))
        return out
    finally:
        if load is not None:
            load.stop()
        if sampler is not None:
            sampler.stop()
        if fleet is not None:
            fleet.kill()
        mock.stop()
        if not opts.keep:
            shutil.rmtree(work / "state", ignore_errors=True)


def sample_dict(sample: Sample) -> dict[str, Any]:
    return dataclasses.asdict(sample)


# ============================================================================================== summaries


def stats(values: Sequence[float]) -> dict[str, Any]:
    """Count, p50, p95 and max (nearest rank), rounded to 0.1 ms."""

    def r(value: float | None) -> float | None:
        return None if value is None else round(value, 1)

    return {
        "n": len(values),
        "p50": r(percentile(values, 0.5)),
        "p95": r(percentile(values, 0.95)),
        "max": r(max(values) if values else None),
    }


def summarize(samples: Sequence[Sample], assets: Mapping[str, Mapping[str, Any]], leader: int | None) -> dict[str, Any]:
    """Per page, per fragment and per series route: server and client times, sizes, statuses and verdicts."""
    by: dict[tuple[str, str, str, str], list[Sample]] = defaultdict(list)
    for s in samples:
        by[(s.phase, s.kind, s.page, s.name)].append(s)
    pages: dict[str, dict[str, Any]] = {}
    fragments: list[dict[str, Any]] = []
    series: list[dict[str, Any]] = []
    for (phase, kind, page, name), group in sorted(by.items()):
        server = [s.server_ms for s in group if s.server_ms is not None]
        first = min(group, key=lambda s: s.round)
        entry: dict[str, Any] = {
            "phase": phase,
            "page": page,
            "name": name,
            "server_ms": stats(server),
            # The run's first load of it (cold SQLite page caches in that worker), and every later one.
            "first_server_ms": first.server_ms,
            "warm_server_ms": stats([s.server_ms for s in group if s.server_ms is not None and s is not first]),
            "client_ms": stats([s.client_ms for s in group]),
            "bytes": int(percentile([float(s.bytes) for s in group], 0.5) or 0),
            "statuses": dict(Counter(str(s.status) for s in group)),
            "on_leader_share": round(sum(1 for s in group if leader and s.pid == leader) / len(group), 2),
        }
        if kind == "page":
            entry["first_paint_bytes"] = entry["bytes"] + int((assets.get(page) or {}).get("css_gzip_bytes") or 0)
            pages[f"{phase}:{page}"] = entry
        elif kind == "fragment":
            fragments.append(entry)
        elif kind == "series":
            series.append(entry)
    # The whole view: a page plus every fragment it loads, summed per round (what the cards cost the server).
    views: dict[str, list[float]] = defaultdict(list)
    per_round: dict[tuple[str, str, int], float] = defaultdict(float)
    for s in samples:
        if s.kind in ("page", "fragment") and s.server_ms is not None:
            per_round[(s.phase, s.page, s.round)] += s.server_ms
    for (phase, page, _), total in per_round.items():
        views[f"{phase}:{page}"].append(total)
    for key, totals in views.items():
        if key in pages:
            pages[key]["view_total_server_ms"] = stats(totals)

    def over(entries: Iterable[Mapping[str, Any]], target: float) -> list[str]:
        return [
            f"{e['page']} {e['name']} p95 {e['server_ms']['p95']} ms"
            for e in entries
            if e["server_ms"]["p95"] is not None and e["server_ms"]["p95"] > target
        ]

    default_pages = [e for e in pages.values() if e["phase"] == "default"]
    return {
        "pages": pages,
        "fragments": fragments,
        "series": series,
        "pages_over_300ms": over(default_pages, FIRST_RENDER_TARGET_MS),
        "fragments_over_300ms": over([f for f in fragments if f["phase"] == "default"], FIRST_RENDER_TARGET_MS),
        "charts_over_500ms": over(
            [
                *series,
                *[f for f in fragments if f["phase"] == "90d"],
                *[e for e in pages.values() if e["phase"] == "90d"],
            ],
            CHART_TARGET_MS,
        ),
        "non_200": sorted({f"{s.kind} {s.page} {s.name}: {s.status}" for s in samples if s.status != 200}),
    }


def kib(value: float | int | None) -> str:
    return "n/a" if value is None else f"{value / 1024:,.1f} KiB"


def ms(entry: Mapping[str, Any]) -> str:
    if not entry.get("n"):
        return "n/a"
    return f"{entry['p50']} / {entry['p95']} ms"


def result_rows(run: Mapping[str, Any]) -> list[tuple[str, str, str]]:
    """The results table of one run (metric, measured, target or note)."""
    summary = run["summary"]
    rows: list[tuple[str, str, str]] = []
    for page in PAGE_IDS:
        entry = summary["pages"].get(f"default:{page}")
        if entry is None:
            continue
        frags = [f for f in summary["fragments"] if f["phase"] == "default" and f["page"] == page]
        slow = max(frags, key=lambda f: f["server_ms"]["p95"] or 0.0, default=None)
        slow_text = "" if slow is None else f"; slowest card {slow['name']} {ms(slow['server_ms'])}"
        rows.append(
            (
                f"{page}: page server p50 / p95",
                f"{ms(entry['server_ms'])} (first load {entry['first_server_ms']} ms; client {ms(entry['client_ms'])})"
                f"; HTML {kib(entry['bytes'])}, first paint {kib(entry['first_paint_bytes'])}",
                f"under {FIRST_RENDER_TARGET_MS:g} ms (6.7)",
            )
        )
        view = entry.get("view_total_server_ms") or {}
        rows.append(
            (
                f"{page}: page and its {len(frags)} fragments",
                f"server total {ms(view)} per view{slow_text}",
                "every card loaded",
            )
        )
    for entry in summary["series"]:
        rows.append((f"90 d series: {entry['name']}", ms(entry["server_ms"]), f"under {CHART_TARGET_MS:g} ms (6.7)"))
    for page in PAGE_IDS:
        entry = summary["pages"].get(f"90d:{page}")
        if entry is not None:
            frags = [f for f in summary["fragments"] if f["phase"] == "90d" and f["page"] == page]
            slow = max(frags, key=lambda f: f["server_ms"]["p95"] or 0.0, default=None)
            rows.append(
                (
                    f"{page} at range=90d",
                    f"page {ms(entry['server_ms'])}"
                    + ("" if slow is None else f"; slowest card {slow['name']} {ms(slow['server_ms'])}"),
                    f"charts under {CHART_TARGET_MS:g} ms (6.7)",
                )
            )
    rows.append(
        (
            "pages over 300 ms at p95",
            str(len(summary["pages_over_300ms"])),
            "; ".join(summary["pages_over_300ms"])[:300],
        )
    )
    rows.append(
        (
            "fragments over 300 ms at p95",
            str(len(summary["fragments_over_300ms"])),
            "; ".join(summary["fragments_over_300ms"])[:300],
        )
    )
    rows.append(
        (
            "90 d charts over 500 ms at p95",
            str(len(summary["charts_over_500ms"])),
            "; ".join(summary["charts_over_500ms"])[:300],
        )
    )
    rows.append(("answers other than 200", str(len(summary["non_200"])), "; ".join(summary["non_200"])[:300]))
    if run.get("load"):
        load = run["load"]
        rows.append(("proxy load alongside", f"{load['answered_per_s']} answered/s, {load['statuses']}", "steady mix"))
    memory = run.get("memory") or {}
    rows.append(("peak RSS per worker", ", ".join(f"{v} MiB" for v in memory.get("worker_peak_rss_mib", [])), ""))
    rows.append(("joined to Roxy's log", f"{run.get('joined')} of {len(run.get('samples') or [])}", "every request"))
    migrated = run.get("migrated") or {}
    rows.append(
        (
            "expand migrations of the copy",
            f"{migrated.get('seconds')} s",
            "; ".join(migrated.get("applied") or ()) or "none pending",
        )
    )
    rows.append(("cache entries at the start", str(run.get("cache_entries")), "live entries (`CACHE_ENTRIES`)"))
    workers = {s["pid"] for s in run.get("samples") or () if s.get("pid")}
    on_leader = run.get("leader_pid") in workers
    rows.append(("workers that answered the pages", str(len(workers)), "the leader" if on_leader else "not the leader"))
    rows.append(("graceful stop; tracebacks", f"exit {run.get('stop_code')}; {run.get('tracebacks')}", "exit 0; 0"))
    return rows


# ============================================================================================ command line


def enter_namespace(argv: list[str]) -> None:
    """Re-run this command inside `unshare -rn` (never returns), as `load.harness` does."""
    if not can_unshare():
        print("load.pages: unprivileged user and network namespaces (unshare -rn) are not available", file=sys.stderr)
        sys.exit(EXIT_NO_NAMESPACE)
    argv = absolute_paths(argv)
    env = {**os.environ, NAMESPACE_ENV: "1", "PYTHONPATH": python_path(option_value(argv, "--tree"))}
    os.chdir(TESTS_DIR)
    os.execvpe("unshare", ["unshare", "-rn", sys.executable, "-m", "load.pages", *argv], env)


def parse(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="python -m load.pages", description="Roxy dashboard page latency (6.7)")
    parser.add_argument(
        "--runs",
        default="quiet,quiet@0-1,load@0-1,load",
        help="comma list of runs: quiet or load, optionally @<cpus> to pin gunicorn (default: %(default)s)",
    )
    parser.add_argument("--rounds", type=int, default=10, help="rounds of the default pass (every page, every card)")
    parser.add_argument("--rounds-90d", type=int, default=3, help="rounds of the 90 day pass")
    parser.add_argument("--load-rate", type=float, default=200.0, help="requests a second of a load run's proxy mix")
    defaults = Volume()
    parser.add_argument("--requests-per-day", type=int, default=defaults.requests_per_day)
    parser.add_argument("--history-days", type=int, default=defaults.history_days)
    parser.add_argument("--json", type=Path, help="write every number (and every sample) to this file")
    parser.add_argument("--work", type=Path, help="work directory (default: a new temporary directory)")
    parser.add_argument("--keep", action="store_true", help="keep the template and each run's state and log")
    parser.add_argument("--reuse-template", action="store_true", help="use the template already in --work")
    parser.add_argument("--tree", type=Path, help="measure the Roxy of this repository copy (see load.harness)")
    parser.add_argument("--seed", type=int, default=2026)
    args = parser.parse_args(argv)
    try:
        args.run_specs = [RunSpec.parse(text) for text in args.runs.split(",") if text]
    except ValueError as exc:
        parser.error(str(exc))
    if args.history_days < 15 or args.requests_per_day < 1000:
        parser.error("--history-days must be at least 15 and --requests-per-day at least 1000")
    if args.reuse_template and args.work is None:
        parser.error("--reuse-template needs --work")
    return args


def main(argv: list[str]) -> int:
    if os.environ.get(NAMESPACE_ENV) != "1":
        enter_namespace(argv)
    loopback_up()
    args = parse(argv)
    work = args.work or Path(tempfile.mkdtemp(prefix="roxy-pages-"))
    work.mkdir(parents=True, exist_ok=True)
    credentials = work / "credentials"
    if not (args.reuse_template and credentials.is_dir()):
        credentials = fake_credentials(credentials)
    opts = Options(
        work=work, credentials=credentials, template=work / "template", rounds=args.rounds,
        rounds_90d=args.rounds_90d, load_rate=args.load_rate, tree=args.tree, keep=args.keep, seed=args.seed,
    )  # fmt: skip
    volume = Volume(requests_per_day=args.requests_per_day, history_days=args.history_days, seed=args.seed)
    info = machine()
    info["tree"] = str(args.tree or "working tree")
    print(f"Roxy page latency: {info['cpu']}, {info['logical_cpus']} logical CPUs, {info['memory_gib']} GiB")
    print(f"Roxy measured: {info['tree']}; work directory {work}; load {info['load_average_at_start']}\n", flush=True)
    report: dict[str, Any] = {"machine": info, "volume": vars_of(volume), "runs": {}}
    if args.reuse_template and (opts.template / "seed.json").is_file():
        report["seed"] = json.loads((opts.template / "seed.json").read_text())
    else:
        report["seed"] = build_template(opts, volume)
    seed = report["seed"]
    rows, files = seed.get("rows"), seed.get("files_mib")
    print(f"== seeded in {seed.get('seconds')} s (and the warm phase): rows {rows}; MiB {files}\n", flush=True)
    failed = 0
    for spec in args.run_specs:
        try:
            run = run_once(opts, spec)
        except Exception as exc:
            failed += 1
            run = {"run": spec.name, "error": f"{type(exc).__name__}: {exc}", "traceback": traceback.format_exc()}
            print(f"== {spec.name}: FAILED {run['error']}\n{run['traceback']}", flush=True)
        else:
            print(f"== {spec.name} (gunicorn 2 workers, CPUs {run['cpus']}, measured {run.get('measure_s')} s)")
            print(text_table(result_rows(run)), end="\n\n", flush=True)
        report["runs"][spec.name] = run
        if args.json is not None:
            args.json.write_text(json.dumps(report, indent=1, sort_keys=True, default=str))
    if not args.keep and args.work is None:
        shutil.rmtree(work, ignore_errors=True)
    return 1 if failed else 0


def vars_of(volume: Volume) -> dict[str, Any]:
    return dataclasses.asdict(volume)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
