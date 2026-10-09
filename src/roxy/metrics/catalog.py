"""The metric catalog: one `MetricSpec` per number on the dashboard, with its plain-English, honest definition.

What this is
    `METRICS: dict[str, MetricSpec]`, keyed by the names `metrics/queries.py` returns (`requests`, `demand`,
    `avoided`, `roblox_429`, `p95_ms`, ...). Each spec has a label, a unit, a one-paragraph description, the exact
    definition (which rows and columns are counted), where the data comes from, which dashboard cards show it,
    and whether higher is better. `GLOSSARY_TERMS` explains the words the definitions use.

Why it exists
    Plan P2 (explain everything) and P6 (honest numbers). Help text for every metric comes from one source
    (plan 14.7), and the definitions are written down next to the code that computes them, so a tile can never
    quietly mean something kinder than what it counts. The two headline definitions the plan pins:
    - "Avoided upstream calls" is caller demand minus the upstream calls made for caller traffic (calls caused
      by callers, background refreshes, and the retries of both); Roxy's own probes are counted separately, so
      the headline can never exceed reality.
    - Stale serves after an upstream failure are counted as "errors hidden from callers", not as successes.

How it works
    Plain data. `catalog_self_check()` runs at import: unique keys, every text present, no dash characters (plan
    C5). The dashboard renders `label`, `description` and `definition` in the tooltip; the LLM export embeds the
    specs of the metrics it reports.

What to read next
    `roxy/metrics/queries.py` (the code behind each definition), `roxy/config/catalog.py` (the same idea for
    settings).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from roxy.metrics.histograms import BUCKET_ERROR_NOTE


@dataclass(frozen=True, slots=True)
class MetricSpec:
    """Metadata for one metric."""

    key: str
    label: str
    unit: str  # requests, calls, bytes, ms, percent, ratio, rows, count
    description: str  # what it means, for the tooltip
    definition: str  # exactly what is counted
    source: str  # tables the value is read from
    pages: tuple[str, ...]  # `<page>#<card>` anchors (DESIGN.md section 9)
    better: str = "neutral"  # "higher", "lower" or "neutral" (for delta arrows; color is never the only signal)
    notes: str = ""


_ROLLUPS = "rollup_minute, rollup_hour, rollup_day, rollup_month joined with dims"
_REFUSED_OR_DEMAND = (
    "Demand is every caller proxy request that Roxy tried to serve: outcome served from Roblox, served from the "
    "cache, or failed, excluding refusals, OPTIONS requests answered locally, and Roxy's own internal calls."
)

_SPECS: tuple[MetricSpec, ...] = (
    MetricSpec(
        "requests",
        "Requests",
        "requests",
        "Every proxy request a caller sent to Roxy, whatever happened to it: served, refused or failed.",
        "Sum of `requests` over every rollup row in the range. Roxy's own probes and background refreshes add "
        "zero requests.",
        _ROLLUPS,
        ("overview#kpis", "traffic#requests"),
    ),
    MetricSpec(
        "demand",
        "Caller demand",
        "requests",
        "Requests Roxy actually tried to answer for callers. Refused requests are left out, so an attack that "
        "Roxy turned away can never make the cache look better than it is.",
        _REFUSED_OR_DEMAND,
        _ROLLUPS,
        ("overview#kpis", "cache#stats"),
    ),
    MetricSpec(
        "avoided",
        "Avoided upstream calls",
        "calls",
        "Calls Roblox did not have to answer because Roxy served callers from its cache or shared one fetch "
        "between several callers.",
        "Caller demand minus the upstream calls made for caller traffic: calls made while a caller waited, "
        "background stale-while-revalidate refreshes, and the CSRF and other retries of both. Roxy's own probes "
        "and health checks are not caller traffic and are reported as internal calls. The value can be negative "
        "when retries made more calls than callers asked for; it is shown as it is.",
        _ROLLUPS,
        ("overview#kpis", "cache#stats"),
        better="higher",
        notes="Plan principle P6. v1 counted cache hits as saved requests without subtracting refresh calls.",
    ),
    MetricSpec(
        "avoided_pct",
        "Avoided upstream calls (percent)",
        "percent",
        "The share of caller demand that never reached Roblox.",
        "Avoided upstream calls divided by caller demand, times 100. Empty when there was no demand.",
        _ROLLUPS,
        ("overview#kpis", "cache#stats"),
        better="higher",
    ),
    MetricSpec(
        "upstream_calls",
        "Upstream calls for callers",
        "calls",
        "How many requests Roxy sent to Roblox on behalf of callers, including retries and background refreshes.",
        "Sum of `upstream_calls` over rollup rows whose source is not `internal`.",
        _ROLLUPS,
        ("overview#kpis", "upstream#calls"),
        better="lower",
    ),
    MetricSpec(
        "internal_calls",
        "Internal calls",
        "calls",
        "Roxy's own calls to Roblox: credential probes, health checks and admin lookups. Reported apart from "
        "caller traffic.",
        "Sum of `upstream_calls` over rollup rows whose source is `internal`.",
        _ROLLUPS,
        ("upstream#internal-calls",),
    ),
    MetricSpec(
        "errors_hidden",
        "Errors hidden from callers",
        "requests",
        "Requests where Roblox (or the path to it) failed, but Roxy still answered with an older cached copy. "
        "The caller got data; the failure is counted here so it is not mistaken for a success.",
        "Sum of `requests` over rollup rows with reason `cache_stale_error` (a stale entry served after an "
        "upstream failure).",
        _ROLLUPS,
        ("overview#kpis", "cache#stats"),
        better="lower",
        notes="Plan principle P6.",
    ),
    MetricSpec(
        "errors",
        "Errors",
        "requests",
        "Caller requests during which an upstream or internal error happened, whether or not the caller saw it.",
        "Sum of `errors` over rollup rows whose source is not `internal`.",
        _ROLLUPS,
        ("traffic#requests", "upstream#calls"),
        better="lower",
    ),
    MetricSpec(
        "served_upstream",
        "Served from Roblox",
        "requests",
        "Requests answered with a fresh response from Roblox. OPTIONS requests, which Roxy answers itself without "
        "contacting Roblox, are not counted.",
        "Sum of `requests` where outcome is `served_upstream` and the reason is not `options_local` (the router "
        "records a local OPTIONS answer with outcome `served_upstream`, the closest value of the closed enum).",
        _ROLLUPS,
        ("traffic#requests",),
    ),
    MetricSpec(
        "served_cache",
        "Served from cache",
        "requests",
        "Requests answered from Roxy's cache, fresh or stale, including callers that shared another caller's fetch.",
        "Sum of `requests` where outcome is `served_cache`.",
        _ROLLUPS,
        ("overview#kpis", "cache#stats"),
        better="higher",
    ),
    MetricSpec(
        "refused",
        "Refused",
        "requests",
        "Requests Roxy turned away on purpose: limits, bans, filters, blocks, pause.",
        "Sum of `requests` where outcome is `refused`.",
        _ROLLUPS,
        ("protection#refusals", "traffic#requests"),
    ),
    MetricSpec(
        "failed",
        "Failed",
        "requests",
        "Requests Roxy tried to serve but could not: Roblox errors, timeouts, cooldowns, an exhausted deadline.",
        "Sum of `requests` where outcome is `failed`.",
        _ROLLUPS,
        ("traffic#requests", "upstream#failures"),
        better="lower",
    ),
    MetricSpec(
        "roblox_429",
        "Roblox 429s",
        "count",
        "Times Roblox answered one of Roxy's calls with 429 Too Many Requests. This is the number to keep near "
        "zero: it means Roblox is rate limiting Roxy's address or account.",
        "Rows of the `upstream_429` log in the range: every 429 Roblox sent, counted once per upstream attempt, "
        "even when Roxy then served the caller from the cache or retried successfully.",
        "upstream_429",
        ("overview#kpis", "upstream#429s"),
        better="lower",
    ),
    MetricSpec(
        "roblox_429_per_10k",
        "Roblox 429s per 10,000 requests",
        "ratio",
        "Roblox 429s relative to traffic, so a quiet day and a busy day can be compared.",
        "Roblox 429s divided by caller demand, times 10,000. Empty when there was no demand.",
        "upstream_429 and rollups",
        ("overview#kpis",),
        better="lower",
    ),
    MetricSpec(
        "roxy_429",
        "429s from Roxy",
        "requests",
        "Times Roxy itself answered 429 (its own throttles and limits). These are Roxy protecting Roblox, not "
        "Roblox rate limiting Roxy.",
        "Sum of `requests` with status 429 and source `roxy`.",
        _ROLLUPS,
        ("overview#kpis", "traffic#status-codes"),
    ),
    MetricSpec(
        "status_5xx",
        "Caller 5xx",
        "requests",
        "Server error statuses (500 to 599) sent to callers, whoever produced them.",
        "Sum of `requests` with a caller status from 500 to 599.",
        _ROLLUPS,
        ("overview#kpis", "traffic#status-codes"),
        better="lower",
    ),
    MetricSpec(
        "roblox_5xx",
        "5xx from Roblox",
        "requests",
        "Server errors that came from Roblox and were passed to the caller.",
        "Sum of `requests` with a caller status from 500 to 599 and source `roblox` or `relay`.",
        _ROLLUPS,
        ("overview#kpis", "traffic#status-codes"),
        better="lower",
    ),
    MetricSpec(
        "status_2xx",
        "2xx responses",
        "requests",
        "Successful responses sent to callers.",
        "Sum of `requests` with a caller status from 200 to 299.",
        _ROLLUPS,
        ("overview#kpis", "traffic#status-codes"),
        better="higher",
    ),
    MetricSpec(
        "status_4xx",
        "4xx responses",
        "requests",
        "Client error responses sent to callers, from Roblox (for example 404) or from Roxy (refusals).",
        "Sum of `requests` with a caller status from 400 to 499.",
        _ROLLUPS,
        ("overview#kpis", "traffic#status-codes"),
    ),
    MetricSpec(
        "timeouts",
        "Upstream timeouts",
        "requests",
        "Requests that failed because Roblox did not answer in time.",
        "Sum of `requests` with reason `upstream_timeout`.",
        _ROLLUPS,
        ("upstream#calls",),
        better="lower",
    ),
    MetricSpec(
        "paused",
        "Pause drops",
        "requests",
        "Requests refused because the proxy was paused (the top bar banner counts these since the pause began).",
        "Sum of `requests` with reason `paused`.",
        _ROLLUPS,
        ("topbar#pause",),
        notes="Parity row 114.",
    ),
    MetricSpec(
        "throttle_all",
        "Emergency limit drops",
        "requests",
        "Requests refused by the emergency limit (throttle-all), counted since it was switched on.",
        "Sum of `requests` with reason `throttle_all`.",
        _ROLLUPS,
        ("topbar#throttle-all",),
        notes="Parity rows 114 and 115.",
    ),
    MetricSpec(
        "hit_ratio",
        "Cache hit ratio",
        "ratio",
        "Of the requests that looked in the cache, the share answered from it.",
        "(HIT + STALE + REVALIDATING + COALESCED) divided by those plus MISS, by the `Roxy-Cache` state of each "
        "request.",
        _ROLLUPS,
        ("cache#stats", "endpoints#table"),
        better="higher",
    ),
    MetricSpec(
        "cache_bytes_out",
        "Bytes served from cache",
        "bytes",
        "Response bytes delivered to callers from the cache (v1 BytesServed).",
        "Sum of `caller_bytes_out` where outcome is `served_cache`.",
        _ROLLUPS,
        ("cache#stats",),
    ),
    MetricSpec(
        "caller_bytes_in",
        "Bytes from callers",
        "bytes",
        "Request bytes Roxy received for proxy requests.",
        "Request line, headers and body as delivered by nginx over the loopback connection (after nginx removed "
        "TLS and HTTP/2 framing). Plan 14.3.",
        _ROLLUPS,
        ("traffic#bytes",),
    ),
    MetricSpec(
        "caller_bytes_out",
        "Bytes to callers",
        "bytes",
        "Response bytes Roxy sent back to callers, from Roblox or from the cache.",
        "Status line, headers and body as sent to nginx, uncompressed (before nginx gzip). Cache serves count "
        "like upstream serves. Plan 14.3.",
        _ROLLUPS,
        ("traffic#bytes",),
    ),
    MetricSpec(
        "upstream_bytes_out",
        "Bytes to Roblox",
        "bytes",
        "Bytes Roxy wrote to Roblox for caller traffic.",
        "Wire bytes written to the socket for each egress as metered by the egress transport, including TLS and, "
        "for the rotator, the CONNECT exchange. Cache serves add nothing. Plan 14.3 and 8.3.",
        _ROLLUPS,
        ("traffic#bytes", "egress#usage"),
    ),
    MetricSpec(
        "upstream_bytes_in",
        "Bytes from Roblox",
        "bytes",
        "Bytes Roxy read from Roblox for caller traffic.",
        "Wire bytes read from the socket for each egress as metered by the egress transport, including TLS. "
        "Plan 14.3 and 8.3.",
        _ROLLUPS,
        ("traffic#bytes", "egress#usage"),
    ),
    MetricSpec(
        "rotator_bytes",
        "Rotator bytes",
        "bytes",
        "Bytes that went through the DataImpulse rotator, an estimate of what the provider bills.",
        "Sum of request, response and overhead bytes of `egress_usage` rows for egress `rotator`.",
        "egress_usage",
        ("overview#kpis", "egress#usage"),
        better="lower",
    ),
    MetricSpec(
        "p50_ms",
        "Latency p50",
        "ms",
        "Half of the caller requests took at most this long (Roxy time plus Roblox time).",
        "50th percentile of the caller latency histogram (source not `internal`). " + BUCKET_ERROR_NOTE,
        _ROLLUPS,
        ("traffic#latency",),
        better="lower",
    ),
    MetricSpec(
        "p95_ms",
        "Latency p95",
        "ms",
        "95 out of 100 caller requests took at most this long.",
        "95th percentile of the caller latency histogram. " + BUCKET_ERROR_NOTE,
        _ROLLUPS,
        ("overview#kpis", "traffic#latency"),
        better="lower",
    ),
    MetricSpec(
        "p99_ms",
        "Latency p99",
        "ms",
        "99 out of 100 caller requests took at most this long: the slow tail.",
        "99th percentile of the caller latency histogram. " + BUCKET_ERROR_NOTE,
        _ROLLUPS,
        ("traffic#latency",),
        better="lower",
    ),
    MetricSpec(
        "queue_wait_p95_ms",
        "Queue wait p95",
        "ms",
        "How long requests waited for an upstream slot before being sent (pacing that keeps Roblox happy).",
        "95th percentile of the queue wait histogram. " + BUCKET_ERROR_NOTE,
        _ROLLUPS,
        ("upstream#queue",),
        better="lower",
    ),
    MetricSpec(
        "requests_last_hour",
        "Requests (last hour)",
        "requests",
        "Requests in the last 60 minutes, whatever range is selected.",
        "Sum of `requests` in minute rows of the trailing hour.",
        "rollup_minute",
        ("overview#kpis",),
    ),
    MetricSpec(
        "metrics_dropped",
        "Metrics dropped",
        "count",
        "Statistics items a worker had to throw away because its queue was full. Anything above zero means some "
        "charts have small gaps.",
        "Sum of the batch writer drop counters of every worker since it started (System page).",
        "worker memory",
        ("system#metrics-pipeline",),
        better="lower",
    ),
    MetricSpec(
        "capture_errors",
        "Capture errors",
        "count",
        "Captures that could not be made. Capture never fails a request; failures are only counted here.",
        "Per-worker counter of exceptions inside capture, plus `capture_error` events per minute.",
        "worker memory, events",
        ("system#metrics-pipeline", "live#capture"),
        better="lower",
        notes="Parity row 127.",
    ),
    MetricSpec(
        "dims_per_minute",
        "Dimension rows per minute",
        "rows",
        "How many distinct combinations of endpoint, status, outcome and other dimensions appear per minute; it "
        "drives the size of the statistics database.",
        "Rows of `rollup_minute` divided by the number of distinct minutes in the range.",
        "rollup_minute",
        ("system#metrics-pipeline",),
        better="lower",
        notes="Recommendation SYS-DISK fires when the 7 day average exceeds 1,500 (plan 6.2).",
    ),
    MetricSpec(
        "human_visitors",
        "Human visitors",
        "count",
        "Visits to the home page from browsers that do not look like bots.",
        "Visit events for page `home` whose User-Agent matched no crawler marker.",
        "events",
        ("overview#visitors",),
    ),
    MetricSpec(
        "crawler_visitors",
        "Crawler visitors",
        "count",
        "Visits to the home page from search engines, scripts and other bots.",
        "Visit events for page `home` whose User-Agent contains a crawler marker (bot, crawl, spider, curl, ...).",
        "events",
        ("overview#visitors",),
    ),
    MetricSpec(
        "unknown_visitors",
        "Unknown visitors",
        "count",
        "Visits to the home page that sent no User-Agent at all, so nothing can be said about them.",
        "Visit events for page `home` with an empty User-Agent (v1 counted these as crawlers).",
        "events",
        ("overview#visitors",),
    ),
    # --- insight history (schema version 2, `metrics/read_history.py`) ---
    MetricSpec(
        "bucket_attempts",
        "Bucket reservations",
        "count",
        "How many upstream calls asked one pacing bucket for a slot.",
        "Sum of `bucket_minute.attempts` for the bucket key: one per reservation that reached the buckets "
        "(a cooldown or open breaker refusal asks no bucket and is not counted).",
        "bucket_minute",
        ("upstream#buckets",),
    ),
    MetricSpec(
        "bucket_rejections",
        "Bucket rejections",
        "count",
        "Upstream calls refused because this bucket had no slot within the allowed queue wait: real demand above "
        "the bucket's rate.",
        "Sum of `bucket_minute.rejections`: reservations denied with this bucket as the binding one.",
        "bucket_minute",
        ("upstream#buckets",),
        better="lower",
    ),
    MetricSpec(
        "bucket_fill_peak_pct",
        "Bucket fill peak",
        "percent",
        "The fullest the bucket's burst was seen in the time range: 100 means callers had to wait for a slot.",
        "Largest `bucket_minute.fill_pct_peak`: the burst share in use right after a granted reservation, or 100 "
        "for a denial that this bucket caused.",
        "bucket_minute",
        ("upstream#buckets",),
    ),
    MetricSpec(
        "worker_cpu_pct",
        "Worker CPU",
        "percent",
        "CPU use of a worker process, as a share of the CPU time it can get.",
        "`worker_minute.cpu_pct_sum / samples` per minute (the mean of the samples the worker reported).",
        "worker_minute",
        ("system#metrics-pipeline",),
        better="lower",
    ),
    MetricSpec(
        "cache_young_evictions",
        "Evictions before expiry",
        "count",
        "Cached answers thrown out to make room while they were still fresh: a sign the cache is too small.",
        "Sum of `cache_minute.young_evictions`: entries evicted for space whose age was below their lifetime "
        "(entries removed because they expired are not counted).",
        "cache_minute",
        ("cache#settings",),
        better="lower",
    ),
    MetricSpec(
        "cache_stores",
        "Entries stored",
        "count",
        "Answers written to the shared cache tier.",
        "Sum of `cache_minute.stores`: successful writes to cache.db (memory-only answers are not counted).",
        "cache_minute",
        ("cache#settings",),
    ),
    MetricSpec(
        "error_occurrences",
        "Error occurrences",
        "count",
        "How often one of Roxy's own error signatures happened.",
        "Sum of `error_minute.count` for the signature: one per error recorded (`record_error`).",
        "error_minute, errors",
        ("system#metrics-pipeline",),
        better="lower",
    ),
    MetricSpec(
        "upstream_attempts",
        "Upstream calls by attempt",
        "calls",
        "Every call to Roblox, split into first calls, CSRF retries, 429 fallbacks, other retries and redirects.",
        "Sum of `upstream_attempt_minute.count`, grouped by `kind`.",
        "upstream_attempt_minute",
        ("upstream#retries",),
    ),
)

METRICS: Final[dict[str, MetricSpec]] = {spec.key: spec for spec in _SPECS}

GLOSSARY_TERMS: Final[dict[str, str]] = {
    "caller": "A program that sends requests through Roxy, usually a Roblox game server.",
    "upstream call": "A request Roxy sends to Roblox.",
    "egress": "The network path an upstream call takes: direct, credential (direct with the account cookie) or "
    "rotator (through the DataImpulse proxy).",
    "rollup": "A row of pre-summed counters for one minute, hour, day or month and one combination of dimensions.",
    "dimension": "A property every request is counted by: endpoint template, host, method, egress, outcome, reason, "
    "status, source, cache state and credential use.",
    "percentile": "The value below which that share of requests falls: p95 = 300 ms means 95 out of 100 requests "
    "took 300 ms or less.",
    "stale": "A cached response past its normal lifetime, served because Roblox could not be asked right now.",
}

_DASHES = (chr(0x2014), chr(0x2013))  # built at runtime so this file never contains the characters it bans


def catalog_self_check() -> None:
    """Unique keys, text present, no em or en dash anywhere (plan C5). Raises AssertionError on a problem."""
    if len(METRICS) != len(_SPECS):
        raise AssertionError("duplicate metric keys in the catalog")
    for spec in _SPECS:
        for name in ("key", "label", "unit", "description", "definition", "source"):
            text = getattr(spec, name)
            if not text or not text.strip():
                raise AssertionError(f"metric {spec.key!r} lacks {name}")
        if spec.better not in ("higher", "lower", "neutral"):
            raise AssertionError(f"metric {spec.key!r} has an unknown `better` value")
        joined = " ".join(str(getattr(spec, f)) for f in spec.__dataclass_fields__)
        if any(dash in joined for dash in _DASHES):
            raise AssertionError(f"metric {spec.key!r} contains a dash character")
    for term, text in GLOSSARY_TERMS.items():
        if any(dash in term + text for dash in _DASHES):
            raise AssertionError(f"glossary term {term!r} contains a dash character")


catalog_self_check()
