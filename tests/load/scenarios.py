"""The load scenarios of plan 19.4 and the replay of plan 19.10 row 7, each returning its results table.

What this is
    `SCENARIOS` maps a name to a function `(Options) -> ScenarioResult`:
    - `steady`: mixed cacheable traffic at 200 requests a second (plan 6.7's proxy overhead targets).
    - `cold_burst`: an empty cache, then 500 addresses ask for 100 hot keys at once (single-flight and pacing).
    - `cooldown_429`: the mock answers 429 with `Retry-After: 30` on one endpoint for the whole run; the upstream
      call rate to it must drop to the cooldown rate while callers keep getting quick answers.
    - `flood`: 50 addresses send 1000 requests a second (per-IP and flood limits, the tarpit's fleet cap, CPU).
    - `replay`: the v1-like profile against realistic per-endpoint Roblox limits (the 19.10 row 7 numbers).
    Each result has `rows` (metric, measured value, target or note) for the table and `data` for JSON and tests.

Why it exists
    Plan 19.4 lists these scenarios and plan 6.7 the targets; docs/PERFORMANCE.md records what they measured.
    Keeping each scenario a plain function of its options lets the command line run any subset and lets
    test_replay_profile.py run exactly the replay with production settings.

How it works
    Every scenario gets its own state directory, mock and gunicorn master (`System`), so one scenario's cache,
    limiter rows and adaptive bucket rates never leak into the next. Settings are production defaults except where
    a scenario says otherwise, and each such change is listed in its table:
    - `steady` raises the upstream buckets so 20 or more misses a second can flow (plan 6.7 states its miss
      targets at 20 misses a second, above the default direct bucket of 300 a minute) and gives every endpoint
      the same 30 ms latency, so a miss's Roxy overhead is its latency minus 30 ms;
    - `flood` turns on `tarpit_on_throttle`, so throttle and flood refusals are held and the fleet cap is used.
    Client addresses come from ranges that belong to no real system (RFC 5737 and RFC 2544). Latency figures are
    indicative: the client, the mock and both workers share one machine with whatever else runs on it.

What to read next
    `harness.py` (the command line and the table), `test_replay_profile.py` (the acceptance test).
"""

from __future__ import annotations

import contextlib
import math
import shutil
import time
from collections import Counter
from collections.abc import Callable, Iterable, Iterator, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Final

from load.client import ClientOptions, Outcome, lag_ms, latency_ms, max_overlap, per_second, percentile, run_plan
from load.fleet import (
    AdminProbe,
    Fleet,
    ResourceSampler,
    SlotSampler,
    base_env,
    prepare_state,
    roblox_429_rows,
    roxy_totals,
    upstream_limits,
    worker_history,
    write_rates,
)
from load.mock_roblox import CallRecord, Endpoint, MockRoblox
from load.traffic import (
    V1_LIKE_MIX,
    EndpointMix,
    MixPicker,
    PlannedRequest,
    benchmark_addresses,
    burst_plan,
    documentation_addresses,
    hot_keys,
    poisson_plan,
)

Row = tuple[str, str, str]

ABUSE_REFUSALS: Final = frozenset(
    {
        "paused", "banned", "deny_list", "flood", "spam", "throttle_all", "throttle", "place_limit",
        "user_agent_rule", "ignored_path", "unsafe_url", "not_roblox", "host_not_allowed", "auth_smuggling",
        "header_rule", "endpoint_blocked", "endpoint_rule", "body_too_large", "headers_too_large", "url_too_long",
        "method_not_allowed", "challenge", "bot_score",
    }
)  # fmt: skip
"""`Roxy-Refusal` values of the abuse layer (`core/reasons.py`). Roxy never tried to serve these requests, so they
are not caller demand (plan P6); pacing answers (`upstream_busy`, `upstream_cooldown`, ...) are demand."""

PACING_REFUSALS: Final = frozenset({"upstream_busy", "upstream_cooldown", "queue_overflow", "coalesce_timeout"})
"""Answers that tell a caller to come back later because Roxy is pacing Roblox (plan 7.13): no data, no call."""

CACHE_SERVED: Final = frozenset({"HIT", "STALE", "REVALIDATING", "COALESCED"})
"""`Roxy-Cache` values of an answer that came from the cache or from another caller's fetch."""

TIMELINE_STEP_S: Final = 20.0

WARMUP_S: Final = 20.0
"""Idle time between "ready" and the first request. A new worker's first seconds are busy with one-time work (the
leader's first insights evaluation and LLM export file, template warming, the first upstream connections); the
heartbeat's loop lag sampler saw p99 lags around 360 ms in that window and under 25 ms after it. In production a
new color gets the same quiet time while the deploy's health gate runs."""

STEADY_MISS_LATENCY_S: Final = 0.030
HOLD_MIN_S: Final = 7.5
"""A refusal that took this long was held by the tarpit (the shortest hold is `tarpit_min_seconds`, 8 s)."""


@dataclass(frozen=True, slots=True)
class Options:
    work: Path
    credentials: Path
    workers: int = 2
    scale: float = 1.0
    """Multiplies every duration (0.25 for a quick look)."""
    seed: int = 2026
    keep: bool = False
    steady_rate: float = 200.0
    """Requests a second of the `steady` scenario (plan 6.7 states its targets at 200)."""
    overrides: tuple[tuple[str, Any], ...] = ()
    """Settings applied on top of every scenario's own (`--set key=value`), for "what if" runs. A run with
    overrides is not the reference measurement; the table says which ones applied."""


@dataclass(slots=True)
class ScenarioResult:
    name: str
    title: str
    ok: bool
    rows: list[Row] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)


class NotReady(RuntimeError):
    """The gunicorn master did not become ready."""


@dataclass(slots=True)
class System:
    env: dict[str, str]
    fleet: Fleet
    mock: MockRoblox
    sampler: ResourceSampler
    wall_start: float

    def finish(self) -> dict[str, Any]:
        """Stop gunicorn gracefully (every worker flushes), then read Roxy's own numbers."""
        code, seconds = self.fleet.stop()
        self.sampler.stop()
        out: dict[str, Any] = {"stop_code": code, "stop_s": seconds, "memory": self.sampler.summary()}
        out["roxy"] = roxy_totals(self.env, self.wall_start - 120, time.time() + 120)
        out["roblox_429_rows"] = roblox_429_rows(self.env)
        out["upstream_limits"] = [row for row in upstream_limits(self.env) if row["origin"] != "default"]
        out["workers"] = worker_history(self.env, self.wall_start)
        out["tracebacks"] = self.fleet.log_count("Traceback")
        # Signs of a saturated hot.db writer: a hot-path write whose 500 ms budget ran out in the queue.
        out["abuse_degraded"] = self.fleet.log_count('"event":"abuse_degraded"')
        out["singleflight_publish_failed"] = self.fleet.log_count('"event":"singleflight_publish_failed"')
        return out


@contextlib.contextmanager
def system(
    opts: Options, name: str, endpoints: list[Endpoint], settings: dict[str, Any],
    rules: Sequence[tuple[str, dict[str, Any]]] = (),
) -> Iterator[System]:  # fmt: skip
    """A fresh state directory, the mock, and a ready gunicorn master for one scenario."""
    work = opts.work / name
    shutil.rmtree(work, ignore_errors=True)  # every scenario starts from an empty state and a new log
    work.mkdir(parents=True)
    mock = MockRoblox(endpoints).start()
    fleet: Fleet | None = None
    sampler: ResourceSampler | None = None
    try:
        env = base_env(work, opts.credentials, mock.base, workers=opts.workers)
        prepare_state(env, {**settings, **dict(opts.overrides)}, list(rules))
        fleet = Fleet(work, env)
        fleet.start()
        if not fleet.wait_ready():
            raise NotReady(fleet.log_tail())
        sampler = ResourceSampler(fleet.master_pid).start()
        wall_start = time.time()
        time.sleep(WARMUP_S)
        yield System(env, fleet, mock, sampler, wall_start)
    finally:
        if sampler is not None:
            sampler.stop()
        if fleet is not None:
            fleet.kill()
        mock.stop()
        if not opts.keep:
            # The cache and metrics files of a long run can reach hundreds of megabytes.
            shutil.rmtree(work / "state", ignore_errors=True)


# ------------------------------------------------------------------------------------------------ helpers


def mock_endpoints(mix: Iterable[EndpointMix], *, limits: bool, latency_s: float | None = None) -> list[Endpoint]:
    out = []
    for item in mix:
        endpoint = item.mock_endpoint(limits=limits)
        out.append(endpoint if latency_s is None else replace(endpoint, latency_s=latency_s))
    return out


def fmt(value: Any, unit: str = "") -> str:
    if value is None:
        return "n/a"
    if isinstance(value, float):
        text = f"{value:,.2f}" if abs(value) < 100 else f"{value:,.0f}"
    elif isinstance(value, int):
        text = f"{value:,}"
    else:
        text = str(value)
    return f"{text} {unit}".strip()


def lat(summary: dict[str, Any]) -> str:
    if not summary.get("n"):
        return "n/a"
    return f"p50 {fmt(summary['p50'])} / p99 {fmt(summary['p99'])} ms (n={summary['n']:,})"


def statuses(outcomes: Iterable[Outcome]) -> dict[str, int]:
    return dict(sorted(Counter(str(o.status) for o in outcomes).items()))


def refusals(outcomes: Iterable[Outcome]) -> dict[str, int]:
    return dict(sorted(Counter(o.refusal or "-" for o in outcomes).items()))


def caller_calls(records: Iterable[CallRecord], start: float, end: float) -> list[CallRecord]:
    """Mock calls made for caller traffic in [start, end): Roxy's credential probes (with a cookie) excluded."""
    return [r for r in records if not r.cookie and start <= r.at < end]


def missing_retry_after(outcomes: Iterable[Outcome]) -> int:
    return sum(1 for o in outcomes if o.status in (429, 503) and not o.retry_after)


def common_rows(result: dict[str, Any], opts: Options | None = None) -> list[Row]:
    memory = result["memory"]
    overrides: list[Row] = []
    if opts is not None and opts.overrides:
        text = ", ".join(f"{key}={value}" for key, value in opts.overrides)
        overrides.append(("settings overridden (--set)", text, "not the reference run"))
    workers = memory["worker_peak_rss_mib"]
    uss = memory["worker_peak_uss_mib"]
    return [
        ("peak RSS per worker", ", ".join(f"{v} MiB" for v in workers) or "n/a", f"USS {uss} MiB"),
        (
            "peak memory of the color",
            f"PSS {memory['color_peak_pss_mib']} MiB (RSS sum {memory['color_peak_rss_sum_mib']} MiB)",
            "MemoryHigh 320M, MemoryMax 420M",
        ),
        (
            "event loop lag p99 (worst heartbeat)",
            ", ".join(f"{w['loop_lag_p99_ms_max']} ms" for w in result["workers"].values()) or "n/a",
            "per worker (heartbeat sampler)",
        ),
        (
            "Roxy's own latency",
            f"p50 {fmt(result['roxy']['p50_ms'])} / p95 {fmt(result['roxy']['p95_ms'])} / "
            f"p99 {fmt(result['roxy']['p99_ms'])} ms",
            "metrics.db histogram, inside the app",
        ),
        (
            "hot.db budget overruns (log lines)",
            f"abuse_degraded {result['abuse_degraded']}, singleflight_publish_failed "
            f"{result['singleflight_publish_failed']}",
            "0 (a 500 ms write budget ran out)",
        ),
        ("graceful stop", f"exit {result['stop_code']} in {result['stop_s']} s", "exit 0"),
        ("tracebacks in the log", str(result["tracebacks"]), "0"),
        *overrides,
    ]


# ------------------------------------------------------------------------------------------------- steady


STEADY_BUCKETS: Final[dict[str, Any]] = {
    "global_bucket_per_min": 10_000,
    "global_bucket_burst": 500,
    "direct_bucket_per_min": 10_000,
    "direct_bucket_burst": 500,
    "host_bucket_default_per_min": 6_000,
    "host_bucket_default_burst": 200,
    "endpoint_bucket_default_per_min": 6_000,
    "endpoint_bucket_default_burst": 200,
}


def steady(opts: Options, *, rate: float | None = None, duration_s: float = 60.0) -> ScenarioResult:
    rate = rate or opts.steady_rate
    duration_s *= opts.scale
    out = ScenarioResult("steady", f"Steady mixed cacheable traffic, {rate:g} requests/s", ok=False)
    endpoints = mock_endpoints(V1_LIKE_MIX, limits=False, latency_s=STEADY_MISS_LATENCY_S)
    # 90 percent of requests ask for one of 50 hot keys per endpoint, 10 percent for a key never seen before.
    picker = MixPicker(V1_LIKE_MIX, unique_share=0.10, hot_keys=50)
    plan = poisson_plan(picker, rate=rate, duration_s=duration_s, addresses=benchmark_addresses(4000), seed=opts.seed)
    with system(opts, out.name, endpoints, dict(STEADY_BUCKETS)) as sys_:
        probe = AdminProbe(sys_.fleet, opts.credentials)
        signed_in = probe.sign_in()
        probe.start()
        sys_.sampler.mark("start")
        started = time.monotonic()
        t0, outcomes = run_plan(sys_.fleet.base_url, plan, processes=2, options=ClientOptions(connections=96))
        sys_.sampler.mark("end")
        cpu = sys_.sampler.cpu_percent("start", "end", time.monotonic() - started)
        probe.stop()
        calls = caller_calls(sys_.mock.records(), t0, t0 + duration_s + 30)
        result = sys_.finish()
    window = [o for o in outcomes if 5.0 <= o.at < duration_s]  # the first 5 s warm the hot keys
    by_state = {
        state: latency_ms(o for o in window if o.status == 200 and o.cache in states)
        for state, states in (("hit", {"HIT"}), ("miss", {"MISS", "REVALIDATING"}), ("coalesced", {"COALESCED"}))
    }
    misses = [o.latency - STEADY_MISS_LATENCY_S for o in window if o.status == 200 and o.cache == "MISS"]
    overhead = {"p50": percentile(misses, 0.5), "p99": percentile(misses, 0.99)}
    flush = [s["last_flush_ms"] for s in probe.samples if s.get("flushes")]
    hot_writes = [s["hot_last_write_ms"] for s in probe.samples if s.get("hot_last_write_ms") is not None]
    done = [o.done for o in outcomes]
    roxy = result["roxy"]
    out.data = {
        **result,
        "planned": len(plan),
        "statuses": statuses(outcomes),
        "refusals": refusals(outcomes),
        "latency_all": latency_ms(window),
        "latency_by_state": by_state,
        "miss_overhead_ms": {k: None if v is None else round(v * 1000, 2) for k, v in overhead.items()},
        "achieved_rps": round(per_second(done, start=5.0, end=duration_s), 1),
        "upstream_calls_per_s": round(len(calls) / duration_s, 1),
        "client_lag_ms": lag_ms(outcomes),
        "cpu_percent_per_worker": cpu,
        "admin_signed_in": signed_in,
        "admin_error": probe.error,
        "flush_ms_samples": {"n": len(flush), "p50": percentile(flush, 0.5), "max": max(flush, default=None)},
        "hot_write_ms_samples": {
            "n": len(hot_writes),
            "p50": percentile(hot_writes, 0.5),
            "p99": percentile(hot_writes, 0.99),
        },
        "metrics_dropped": max((s.get("metrics_dropped") or 0 for s in probe.samples), default=None),
        "hot_pending_max": max((s.get("hot_pending") or 0 for s in probe.samples), default=None),
        "hot_writes_per_s": write_rates(probe.samples),
    }
    d = out.data
    out.rows = [
        ("offered and achieved rate", f"{rate:g} offered, {d['achieved_rps']} answered/s", "200 requests/s"),
        ("statuses", str(d["statuses"]), "all 200"),
        ("cache hit latency (Roxy overhead)", lat(by_state["hit"]), "p99 under 8 ms (6.7)"),
        ("miss latency (30 ms mock included)", lat(by_state["miss"]), ""),
        (
            "miss overhead (latency minus 30 ms)",
            f"p50 {fmt(d['miss_overhead_ms']['p50'])} / p99 {fmt(d['miss_overhead_ms']['p99'])} ms",
            "p99 under 15 ms (6.7)",
        ),
        ("coalesced latency", lat(by_state["coalesced"]), ""),
        ("upstream calls", f"{d['upstream_calls_per_s']} calls/s", "about 20 misses/s (6.7)"),
        ("CPU per worker", ", ".join(f"{v} %" for v in cpu.values()) or "n/a", "percent of one core"),
        (
            "metrics flush (sampled)",
            f"p50 {fmt(d['flush_ms_samples']['p50'])} / max {fmt(d['flush_ms_samples']['max'])} ms "
            f"(n={d['flush_ms_samples']['n']})",
            "under 50 ms per 2 s of traffic (6.7)",
        ),
        (
            "hot.db write time (sampled)",
            f"p50 {fmt(d['hot_write_ms_samples']['p50'])} / p99 {fmt(d['hot_write_ms_samples']['p99'])} ms "
            f"(n={d['hot_write_ms_samples']['n']})",
            "abuse and bucket transactions, p99 under 3 ms (6.7)",
        ),
        (
            "hot.db writer",
            f"{list(d['hot_writes_per_s'].values())} writes/s per worker; queue up to {fmt(d['hot_pending_max'])}",
            "one writer thread per worker",
        ),
        ("recorded by Roxy", f"{fmt(roxy['requests'])} of {len(outcomes):,} sent", "equal"),
        ("client lag", f"p50 {fmt(d['client_lag_ms']['p50'])} / p99 {fmt(d['client_lag_ms']['p99'])} ms", ""),
        ("settings changed", "upstream buckets raised (10,000 per min global and direct)", "see 6.7"),
        *common_rows(result, opts),
    ]
    out.ok = result["stop_code"] == 0
    return out


# --------------------------------------------------------------------------------------------- cold burst


def cold_burst(opts: Options, *, keys: int = 100, addresses: int = 500, per_address: int = 5) -> ScenarioResult:
    out = ScenarioResult("cold_burst", f"Cold cache burst: {keys} hot keys from {addresses} addresses", ok=False)
    endpoints = mock_endpoints(V1_LIKE_MIX, limits=True)
    hot = hot_keys(V1_LIKE_MIX, keys)
    plan = burst_plan(
        MixPicker(V1_LIKE_MIX),
        keys=hot,
        per_address=per_address,
        addresses=documentation_addresses(addresses),
        seed=opts.seed,
    )
    options = ClientOptions(connections=256, max_inflight=4096, retry_429_max_s=30.0)
    with system(opts, out.name, endpoints, {}) as sys_:
        t0, outcomes = run_plan(sys_.fleet.base_url, plan, processes=2, options=options)
        calls = caller_calls(sys_.mock.records(), t0 - 1, t0 + 120)
        result = sys_.finish()
    first = [o for o in outcomes if o.attempt == 0]
    retries = [o for o in outcomes if o.attempt == 1]
    served_first = [o for o in first if o.status == 200]
    asked = {o.label for o in first}
    final_ok = len(served_first) + sum(1 for o in retries if o.status == 200)
    everything = max((o.done for o in outcomes), default=0.0)
    out.data = {
        **result,
        "requests": len(first),
        "distinct_keys": keys,
        "endpoints": len(asked),
        "upstream_calls": len(calls),
        "upstream_429": sum(1 for c in calls if c.status == 429),
        "first_statuses": statuses(first),
        "first_refusals": refusals(first),
        "first_cache": dict(Counter(o.cache or "-" for o in first)),
        "served_first_latency": latency_ms(served_first),
        "refused_first_latency": latency_ms(o for o in first if o.status != 200),
        "retries": len(retries),
        "retry_statuses": statuses(retries),
        "served_in_the_end": final_ok,
        "all_answered_s": round(everything, 2),
        "missing_retry_after": missing_retry_after(first),
        "max_retry_after": max((float(o.retry_after) for o in first if o.retry_after), default=None),
    }
    d = out.data
    out.rows = [
        ("burst", f"{d['requests']:,} requests at once for {keys} keys on {d['endpoints']} endpoints", ""),
        ("upstream calls", f"{d['upstream_calls']} ({d['upstream_429']} answered 429)", f"at most {keys}: one per key"),
        ("first answers", str(d["first_statuses"]), "production pacing (default buckets)"),
        ("first refusals", str(d["first_refusals"]), ""),
        ("cache states", str(d["first_cache"]), ""),
        ("served latency", lat(d["served_first_latency"]), "the client queues on 512 connections"),
        ("refused latency", lat(d["refused_first_latency"]), "includes waiting for a client connection"),
        ("Retry-After", f"max {fmt(d['max_retry_after'])} s; missing on {d['missing_retry_after']}", "never missing"),
        ("after one retry", f"{final_ok:,} of {d['requests']:,} served; {d['retry_statuses']}", ""),
        ("every answer in", f"{d['all_answered_s']} s", ""),
        *common_rows(result, opts),
    ]
    out.ok = result["stop_code"] == 0
    return out


# ------------------------------------------------------------------------------------------ cooldown 429


LIMITED: Final = "badge_details"
LIMITED_LATENCY_S: Final = next(item.latency_ms for item in V1_LIKE_MIX if item.name == LIMITED) / 1000


def cooldown_429(opts: Options, *, limited_rate: float = 20.0, other_rate: float = 10.0) -> ScenarioResult:
    duration_s = 90.0 * opts.scale
    out = ScenarioResult("cooldown_429", "Roblox answers 429 (Retry-After: 30) on one endpoint", ok=False)
    endpoints = [
        replace(e, always_429=True, retry_after="30") if e.name == LIMITED else e
        for e in mock_endpoints(V1_LIKE_MIX, limits=False)
    ]
    others = [item for item in V1_LIKE_MIX if item.name != LIMITED]
    limited = [item for item in V1_LIKE_MIX if item.name == LIMITED]
    addresses = documentation_addresses(762)
    # Every limited request asks for a new badge id: no cache entry and no stale copy can answer for Roblox.
    # The background traffic on the other endpoints is kept below the default direct bucket (300 calls a minute;
    # 20 hot keys per endpoint and 5 percent new keys), so whatever happens to it is caused by the 429 endpoint
    # and not by Roxy's own pacing (a first run with 30 a second and 50 hot keys was paced by the direct bucket).
    plan = poisson_plan(
        MixPicker(limited, unique_share=1.0), rate=limited_rate, duration_s=duration_s, addresses=addresses,
        seed=opts.seed,
    ) + poisson_plan(
        MixPicker(others, unique_share=0.05, hot_keys=20), rate=other_rate, duration_s=duration_s,
        addresses=addresses, seed=opts.seed + 1,
    )  # fmt: skip
    with system(opts, out.name, endpoints, {}) as sys_:
        t0, outcomes = run_plan(sys_.fleet.base_url, plan, processes=1, options=ClientOptions(connections=64))
        everything = sys_.mock.records()
        result = sys_.finish()
    records = caller_calls(everything, t0 - 1, t0 + duration_s + 30)
    hits = [r.at - t0 for r in records if r.endpoint == LIMITED]
    to_limited = [o for o in outcomes if o.label == LIMITED]
    to_others = [o for o in outcomes if o.label != LIMITED]
    windows = [sum(1 for t in hits if k * 30 <= t < (k + 1) * 30) for k in range(math.ceil(duration_s / 30))]
    # Calls made before Roblox's first 429 came back cannot know about it; what matters is the rate after it.
    first_answer = min(hits, default=0.0) + LIMITED_LATENCY_S
    after_first = [t for t in hits if t > first_answer]
    out.data = {
        **result,
        "limited_requests": len(to_limited),
        "limited_calls": len(hits),
        "limited_calls_after_first_429": len(after_first),
        "limited_window_after_first_429_s": round(max(0.0, duration_s - first_answer), 1),
        "limited_call_times_s": [round(t, 2) for t in hits],
        "limited_calls_per_30s": windows,
        "limited_statuses": statuses(to_limited),
        "limited_refusals": refusals(to_limited),
        "limited_latency": latency_ms(to_limited),
        "limited_missing_retry_after": missing_retry_after(to_limited),
        "other_requests": len(to_others),
        "other_statuses": statuses(to_others),
        "other_refusals": refusals(to_others),
        "other_latency": latency_ms(o for o in to_others if o.status == 200),
        "cookie_calls": sum(1 for r in everything if r.cookie and r.endpoint == LIMITED),
    }
    d = out.data
    out.rows = [
        (
            "caller demand on the 429 endpoint",
            f"{d['limited_requests']:,} requests ({limited_rate * 60:g}/min, each a new key)",
            "",
        ),
        ("upstream calls to it", f"{d['limited_calls']} in {duration_s:g} s; per 30 s: {windows}", ""),
        (
            "after Roblox's first 429 came back",
            f"{d['limited_calls_after_first_429']} calls in {d['limited_window_after_first_429_s']} s "
            f"(times {d['limited_call_times_s'][:12]})",
            "about 1 per Retry-After (30 s)",
        ),
        ("caller answers there", f"{d['limited_statuses']} {d['limited_refusals']}", "429 with Retry-After"),
        ("caller latency there", lat(d["limited_latency"]), "bounded (no wait for Roblox)"),
        ("missing Retry-After", str(d["limited_missing_retry_after"]), "0"),
        (
            "other endpoints",
            f"{d['other_statuses']} {d['other_refusals']}; {lat(d['other_latency'])}",
            "unaffected",
        ),
        *common_rows(result, opts),
    ]
    out.ok = result["stop_code"] == 0
    return out


# --------------------------------------------------------------------------------------------------- flood


def flood(opts: Options, *, addresses: int = 50, rate: float = 1000.0) -> ScenarioResult:
    duration_s = 20.0 * opts.scale
    out = ScenarioResult("flood", f"Flood: {addresses} addresses at {rate:g} requests/s", ok=False)
    endpoints = mock_endpoints(V1_LIKE_MIX, limits=False)
    picker = MixPicker([item for item in V1_LIKE_MIX if item.method == "GET"], hot_keys=2)
    plan = poisson_plan(
        picker, rate=rate, duration_s=duration_s, addresses=documentation_addresses(addresses), seed=opts.seed
    )
    settings = {"tarpit_on_throttle": 1}
    options = ClientOptions(connections=256, max_inflight=4096)
    with system(opts, out.name, endpoints, settings) as sys_:
        slots = SlotSampler(sys_.env["ROXY_HOT_DB"]).start()
        sys_.sampler.mark("start")
        started = time.monotonic()
        t0, outcomes = run_plan(sys_.fleet.base_url, plan, processes=4, options=options)
        flood_end = time.monotonic()
        sys_.sampler.mark("end")
        slots.stop()
        cpu = sys_.sampler.cpu_percent("start", "end", flood_end - started)
        calls = caller_calls(sys_.mock.records(), t0 - 1, t0 + duration_s + 60)
        result = sys_.finish()
    # Client side, a refusal that took at least the shortest hold was probably held; when the server is saturated a
    # plain refusal can be that slow too, so the server-side slot count is the authoritative figure for the cap.
    slow = [o for o in outcomes if o.status != 200 and o.latency >= HOLD_MIN_S]
    quick = [o for o in outcomes if o.status != 200 and o.latency < HOLD_MIN_S]
    served = [o for o in outcomes if o.status == 200]
    per_ip = Counter(o.ip for o in served)
    sent = [o.sent for o in outcomes]
    out.data = {
        **result,
        "planned": len(plan),
        "offered_rps": round(per_second(sent, start=0, end=duration_s), 1),
        "all_answered_s": round(max((o.done for o in outcomes), default=0.0), 1),
        "answered_rps": round(len(outcomes) / max(1e-9, max((o.done for o in outcomes), default=0.0)), 1),
        "statuses": statuses(outcomes),
        "refusals": refusals(outcomes),
        "served": len(served),
        "served_per_address_max": max(per_ip.values(), default=0),
        "tarpit_slots_peak": slots.peak,
        "tarpit_slot_samples": slots.samples,
        "refusals_over_8s": len(slow),
        "refusals_over_8s_overlap": max_overlap((o.sent, o.done) for o in slow),
        "refusal_latency_under_8s": latency_ms(quick),
        "refusal_latency_all": latency_ms(o for o in outcomes if o.status != 200),
        "upstream_calls": len(calls),
        "cpu_percent_per_worker": cpu,
        "client_lag_ms": lag_ms(outcomes),
        "errors": dict(Counter(o.error for o in outcomes if o.error)),
    }
    d = out.data
    # GCRA 10 per 50 s with a burst of 10, per address: at most 10 + duration / 5 requests served.
    allowed = 10 + math.floor(duration_s / 5)
    out.rows = [
        ("offered rate", f"{d['offered_rps']} requests/s ({d['planned']:,} planned)", f"{rate:g} requests/s"),
        (
            "answered",
            f"all {len(outcomes):,} in {d['all_answered_s']} s ({d['answered_rps']} answers/s overall)",
            "the flood's own length",
        ),
        ("answers", str(d["statuses"]), ""),
        ("refusals", str(d["refusals"]), ""),
        ("served per address (max)", str(d["served_per_address_max"]), f"at most {allowed} (10 per 50 s, burst 10)"),
        (
            "tarpit holds at once (hot.db slots)",
            f"peak {d['tarpit_slots_peak']} ({d['tarpit_slot_samples']} samples)",
            "fleet cap 50",
        ),
        (
            "refusals that took 8 s or more",
            f"{d['refusals_over_8s']:,}, up to {d['refusals_over_8s_overlap']} open at once",
            "holds, plus refusals slowed by load",
        ),
        ("refusal latency", lat(d["refusal_latency_all"]), ""),
        ("refusal latency under 8 s", lat(d["refusal_latency_under_8s"]), "the refusals not held"),
        ("CPU per worker", ", ".join(f"{v} %" for v in cpu.values()) or "n/a", "percent of one core"),
        ("upstream calls", str(d["upstream_calls"]), "few (hot keys are cached)"),
        ("client lag", f"p50 {fmt(d['client_lag_ms']['p50'])} / p99 {fmt(d['client_lag_ms']['p99'])} ms", ""),
        ("transport errors", str(d["errors"] or 0), "0"),
        ("settings changed", "tarpit_on_throttle 1", "so the cap is exercised"),
        *common_rows(result, opts),
    ]
    out.ok = result["stop_code"] == 0
    return out


# -------------------------------------------------------------------------------------------------- replay


REPLAY_RATE: Final = 10.0
"""Requests a second. Plan 6.6 sizes v2 for 500,000 requests a day (10 times v1's scale), about 5.8 a second on
average; a busy hour at that scale runs above the average, so the replay sends 10 a second."""
REPLAY_DURATION_S: Final = 200.0
REPLAY_ADDRESSES: Final = 300
"""Game server addresses: one experience reaches Roxy from hundreds of servers (D11), each sending 2 a minute."""


def replay(opts: Options, *, rate: float = REPLAY_RATE, duration_s: float = REPLAY_DURATION_S) -> ScenarioResult:
    duration_s *= opts.scale
    out = ScenarioResult("replay", "Replay of the v1-like profile against realistic Roblox limits", ok=False)
    endpoints = mock_endpoints(V1_LIKE_MIX, limits=True)
    plan = poisson_plan(
        MixPicker(V1_LIKE_MIX),
        rate=rate,
        duration_s=duration_s,
        addresses=documentation_addresses(REPLAY_ADDRESSES),
        seed=opts.seed,
    )
    with system(opts, out.name, endpoints, {}) as sys_:
        t0, outcomes = run_plan(sys_.fleet.base_url, plan, processes=1, options=ClientOptions(connections=64))
        records = sys_.mock.records()
        result = sys_.finish()
    calls = caller_calls(records, t0 - 1, t0 + duration_s + 60)
    cookie_calls = [r for r in records if r.cookie and r.endpoint != "other"]
    out.data = {**result, **replay_numbers(plan, outcomes, calls, t0, duration_s)}
    out.data["cookie_calls_on_caller_endpoints"] = len(cookie_calls)
    d = out.data
    roxy = result["roxy"]
    out.rows = [
        ("traffic", f"{len(plan):,} requests at {rate:g}/s for {duration_s:g} s from {REPLAY_ADDRESSES} addresses", ""),
        ("answers", str(d["statuses"]), ""),
        ("Roxy refusals and pacing", str(d["refusals"]), ""),
        ("caller demand", f"{d['demand']:,}", "requests Roxy tried to serve"),
        ("upstream calls (mock)", f"{d['upstream_calls']:,} ({d['roblox_429']} answered 429)", ""),
        ("Roblox 429 share", f"{d['roblox_429_pct']:.3f} %", "below 0.1 % (19.10 row 7)"),
        ("avoided-call share (mock)", f"{d['avoided_pct']:.1f} %", "at least 40 % (19.10 row 7)"),
        ("avoided-call share, second half", f"{d['avoided_pct_second_half']:.1f} %", "warm cache"),
        ("avoided-call share (Roxy's own)", f"{fmt(roxy['avoided_pct'])} %", "metrics.db rollups (P6)"),
        (
            "served from the cache or a shared fetch",
            f"{d['cache_served_pct']:.1f} % (second half {d['cache_served_pct_second_half']:.1f} %)",
            "data served without a call",
        ),
        ("deferred by pacing (no data)", f"{d['deferred']:,} ({d['deferred_pct']:.1f} % of demand)", "counted avoided"),
        ("Roxy's own upstream calls", f"{fmt(roxy['upstream_calls'])}", "equals the mock's count"),
        (
            "per 20 s: requests / calls / deferred",
            " ".join(f"{w['requests']}/{w['calls']}/{w['deferred']}" for w in d["timeline"]),
            "",
        ),
        ("429 times (s after start)", str(d["roblox_429_times_s"][:20]), ""),
        ("adaptive bucket rates", str([f"{r['bucket']} {r['per_min']}/min" for r in result["upstream_limits"]]), ""),
        ("calls with the credential", str(d["cookie_calls_on_caller_endpoints"]), "0 (D1, C2)"),
        ("caller latency", lat(d["latency"]), ""),
        *common_rows(result, opts),
    ]
    out.ok = result["stop_code"] == 0
    return out


def replay_numbers(
    plan: Sequence[PlannedRequest], outcomes: Sequence[Outcome], calls: Sequence[CallRecord], t0: float,
    duration_s: float,
) -> dict[str, Any]:  # fmt: skip
    """Demand, upstream calls, 429s and avoided share, overall, per endpoint, per window and for the second half.

    Two shares, because plan P6's "avoided" (demand minus upstream calls) also counts a caller Roxy told to come
    back later (a pacing answer: `upstream_busy`, `upstream_cooldown`, ...) as a call avoided: Roblox was spared
    the call, but the caller got no data. `cache_served_pct` counts only answers with data from the cache or a
    shared fetch, so the two together show how much of "avoided" was served and how much was deferred.
    """

    def demand_of(items: Iterable[Outcome]) -> int:
        return sum(1 for o in items if o.status != 0 and o.refusal not in ABUSE_REFUSALS)

    def avoided(demand: int, upstream: int) -> float:
        return (demand - upstream) * 100.0 / demand if demand else 0.0

    def from_cache(items: Iterable[Outcome]) -> int:
        return sum(1 for o in items if o.status != 0 and not o.refusal and o.cache in CACHE_SERVED)

    def deferred(items: Iterable[Outcome]) -> int:
        return sum(1 for o in items if o.refusal in PACING_REFUSALS)

    demand = demand_of(outcomes)
    rejected = [c for c in calls if c.status == 429]
    half = duration_s / 2
    second = [o for o in outcomes if o.at >= half]
    second_half_demand = demand_of(second)
    second_half_calls = sum(1 for c in calls if c.at - t0 >= half)
    windows = max(1, math.ceil(duration_s / TIMELINE_STEP_S))
    timeline = []
    for k in range(windows):
        lo, hi = k * TIMELINE_STEP_S, (k + 1) * TIMELINE_STEP_S
        here = [o for o in outcomes if lo <= o.at < hi]
        timeline.append(
            {
                "from_s": lo,
                "requests": len(here),
                "calls": sum(1 for c in calls if lo <= c.at - t0 < hi),
                "from_cache": from_cache(here),
                "deferred": deferred(here),
                "roblox_429": sum(1 for c in rejected if lo <= c.at - t0 < hi),
            }
        )
    per_endpoint = {}
    for name in sorted({request.label for request in plan}):
        mine = [o for o in outcomes if o.label == name]
        mine_calls = [c for c in calls if c.endpoint == name]
        mine_demand = demand_of(mine)
        per_endpoint[name] = {
            "requests": len(mine),
            "demand": mine_demand,
            "calls": len(mine_calls),
            "roblox_429": sum(1 for c in mine_calls if c.status == 429),
            "avoided_pct": round(avoided(mine_demand, len(mine_calls)), 1),
            "cache_served_pct": round(from_cache(mine) * 100.0 / mine_demand, 1) if mine_demand else 0.0,
            "deferred": deferred(mine),
            "statuses": statuses(mine),
        }
    return {
        "cache_served": from_cache(outcomes),
        "cache_served_pct": from_cache(outcomes) * 100.0 / demand if demand else 0.0,
        "cache_served_pct_second_half": from_cache(second) * 100.0 / second_half_demand if second_half_demand else 0.0,
        "deferred": deferred(outcomes),
        "deferred_pct": deferred(outcomes) * 100.0 / demand if demand else 0.0,
        "timeline": timeline,
        "requests": len(outcomes),
        "statuses": statuses(outcomes),
        "refusals": refusals(outcomes),
        "demand": demand,
        "upstream_calls": len(calls),
        "roblox_429": len(rejected),
        "roblox_429_pct": len(rejected) * 100.0 / len(calls) if calls else 0.0,
        "roblox_429_times_s": [round(c.at - t0, 1) for c in rejected],
        "roblox_429_by_endpoint": dict(Counter(c.endpoint for c in rejected)),
        "avoided_pct": avoided(demand, len(calls)),
        "avoided_pct_second_half": avoided(second_half_demand, second_half_calls),
        "per_endpoint": per_endpoint,
        "latency": latency_ms(o for o in outcomes if o.status != 0),
        "missing_retry_after": missing_retry_after(outcomes),
        "transport_errors": sum(1 for o in outcomes if o.status == 0),
    }


SCENARIOS: Final[dict[str, Callable[[Options], ScenarioResult]]] = {
    "steady": steady,
    "cold_burst": cold_burst,
    "cooldown_429": cooldown_429,
    "flood": flood,
    "replay": replay,
}


__all__ = ["SCENARIOS", "NotReady", "Options", "Row", "ScenarioResult", "replay_numbers"]
