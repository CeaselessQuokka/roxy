import config
import copy
import hashlib
import itertools
import json
import re
import secrets
import threading
import time

import runtime
import storage

# Map an ID's parent collection segment to a friendly placeholder, so a path
# like .../users/29371917/outfits collapses to .../users/{userId}/outfits.
_ID_COLLECTION_NAMES = {
    "users": "userId",
    "user": "userId",
    "games": "gameId",
    "universes": "universeId",
    "universe": "universeId",
    "places": "placeId",
    "place": "placeId",
    "groups": "groupId",
    "group": "groupId",
    "assets": "assetId",
    "asset": "assetId",
    "badges": "badgeId",
    "badge": "badgeId",
    "bundles": "bundleId",
    "outfits": "outfitId",
    "items": "itemId",
    "passes": "passId",
    "gamepasses": "gamePassId",
    "servers": "serverId",
    "thumbnails": "thumbnailId",
}
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)
_HEX_RE = re.compile(r"^[0-9a-f]+$", re.IGNORECASE)
_TOKENISH_RE = re.compile(r"^[A-Za-z0-9_-]+$")
MAX_CONCRETE_PER_TEMPLATE = 100  # How many distinct real paths to keep under one template.


def _is_id_segment(seg: str) -> bool:
    """Heuristic: does this path segment look like a volatile ID rather than a route word?"""
    if seg.isdigit():
        return True
    if _UUID_RE.match(seg):
        return True
    if len(seg) >= 16 and _HEX_RE.match(seg):  # long hex hash/token
        return True
    if len(seg) >= 24 and _TOKENISH_RE.match(seg) and any(c.isdigit() for c in seg):  # opaque token
        return True
    return False


def _templatize(path: str) -> str:
    """Collapse ID-like path segments into placeholders so similar paths group.

    e.g. avatar.roblox.com/v2/avatar/users/29371917/outfits
      -> avatar.roblox.com/v2/avatar/users/{userId}/outfits
    """
    segments = path.split("/")
    out = []
    for i, seg in enumerate(segments):
        if _is_id_segment(seg):
            prev = segments[i - 1].lower() if i > 0 else ""
            out.append("{" + _ID_COLLECTION_NAMES.get(prev, "id") + "}")
        else:
            out.append(seg)
    return "/".join(out)


# Guards all reads/writes of the shared in-memory stat structures below. Without
# it, concurrent request threads (e.g. bots hammering a blocked endpoint) can
# mutate a dict while another thread iterates it for eviction or JSON
# serialization, raising "dictionary changed size during iteration". Reentrant
# so a locked function can safely call another locked one.
_state_lock = threading.RLock()

exploit_attempts = list()
login_attempts = list()

throttled_ips = dict(
    {
        # [IP]: {LastThrottleTime: float, Count: int}, # Count = nTimesThrottled
    }
)

request_counts = dict(
    {
        "GET": dict({"Successful": 0, "Failed": 0}),
        "POST": dict({"Successful": 0, "Failed": 0}),
        "PATCH": dict({"Successful": 0, "Failed": 0}),
        "PUT": dict({"Successful": 0, "Failed": 0}),
        "DELETE": dict({"Successful": 0, "Failed": 0}),
    }
)

status_code_counts = dict(
    {
        "2xx": 0,
        "4xx": 0,
    }
)

crawls = dict(
    {
        # [IP]: {LastRequestTime: float, Count: int},
    }
)


# A latency record. "Outcome" splits the same numbers by whether the upstream
# call succeeded, because the two populations answer different questions: a
# failure that takes 15s is a timeout, a failure that takes 0.2s is Roblox saying
# no. Averaged together they hide both. The nested shape merges across workers
# for free — the cross-worker merge keys off leaf NAMES (Min/Max/Total/Count),
# so a nested Min is still min-merged, not summed.
def _outcome_stat():
    return dict({"TotalTime": 0, "Count": 0, "Min": 0, "Max": 0, "LastRequestTime": 0})


def _timing_record():
    record = _outcome_stat()
    record["Success"] = _outcome_stat()
    record["Failed"] = _outcome_stat()
    return record


proxy_request_counts = dict(
    {
        "GET": _timing_record(),  # Count = nRequests.
        "POST": _timing_record(),
        "PATCH": _timing_record(),
        "PUT": _timing_record(),
        "DELETE": _timing_record(),
    }
)

# Token INVENTORY (how many tokens are loaded right now, plus validation/expiry
# bookkeeping). Maintained by update_token/remove_token/clear_tokens. Per-worker,
# but identical across workers since they all load the same token file.
proxy_health = dict(
    {
        "Tokens": dict({"Count": 0, "ExpiredCount": 0, "BeingValidatedCount": 0}),
    }
)


# Per-method request tallies (Token / Rotate), MERGED across workers so the
# dashboard shows true global totals. Requests = total; Failed = non-200 /
# proxy errors; Timeouts = upstream timeouts.
#
# Both methods keep the same liveness fields (last request / last success / last
# error). They used to differ — only Rotate tracked them — which is why the Token
# card had nothing to say beyond three counters while the Rotate card could show
# when it last actually worked.
def _method_stat():
    return dict(
        {
            "Requests": 0,
            "Failed": 0,
            "Timeouts": 0,
            "LastRequestTime": 0,
            "LastSuccessAt": 0,
            "LastErrorAt": 0,
            "LastError": "",
        }
    )


method_stats = dict(
    {
        "Token": _method_stat(),
        "Rotate": _method_stat(),
    }
)

tokens = dict(
    {
        # [full_token]: {Masked: str, BeingValidated: bool, Uses: int}
    }
)

# Per-token usage, keyed by an irreversible fingerprint of the token (NOT the
# secret) so it can be persisted + MERGED across workers. The full token is never
# written to disk; the inventory above stays per-worker. The displayed "Auth
# Tokens → Uses" is read from here so it matches the merged Token method Requests.
#   fingerprint -> {"Uses": int, "LastUsedAt": float}
token_usage = dict()


# Per-requester upstream timings (Token / Rotate), MERGED across workers.
# Parallel to proxy_request_counts (which is per HTTP verb); this one answers
# "how fast is each requester?" with a running total derived in the UI. Split by
# outcome for the same reason — see _timing_record.
method_timings = dict(
    {
        "Token": _timing_record(),
        "Rotate": _timing_record(),
    }
)

# Every failed routed upstream request, deduped by "Method: reason" so the admin
# can diagnose WHY each requester (Token/Rotate) is being rejected.
#   "Method: signature" -> {Method, Count, FirstSeen, LastSeen, LastStatus,
#                           LastEndpoint, LastDetail}
request_failures = dict()

# Ring buffer of the most recent rotation exit IPs we observed (via the IP-echo
# probe on health-check / force-revalidate), so the admin can verify rotation is
# truly handing out different IPs. {"IP", "Date", "Source"}.
rotate_ips = list()

page_visits = dict(
    {
        "home": 0,
        "admin": 0,
        "robots": 0,
    }
)

# Visitor classification: separate likely-bot traffic from likely-human traffic.
visitor_counts = dict(
    {
        "Human": 0,
        "Crawler": 0,
    }
)

# Detailed per-status-code counts, e.g. {"200": 1234, "429": 12, ...}.
status_codes_detailed = dict()

# Endpoint popularity: "service.roblox.com/path" -> {Count, LastRequestTime, Methods: {GET: n, ...}}.
endpoints = dict()

# Attempts to reach a blocked endpoint: path -> {Count, LastRequestTime, Pattern, LastIP, Methods, IPs}.
blocked_endpoint_attempts = dict()

# Requests rejected by a per-endpoint rate rule: path -> {Count, LastRequestTime, Pattern, LastIP, Methods, IPs}.
rate_limited_attempts = dict()

# Requests denied by a header rule (exploit fingerprints, etc.):
# rule_id -> {Count, LastRequestTime, Scope, Mode, Needle, LastIP, LastHeader, LastPath, IPs}.
header_blocked_attempts = dict()

# Retry metrics: how often requests were retried, by status code and reason.
retry_counts = dict(
    {
        "Total": 0,
        "ByStatusCode": dict(),  # "429": n
        "Reasons": dict(),  # "reason": n
    }
)

# Where returned error reasons came from: our own messages vs. Roblox's passthrough.
reason_counts = dict(
    {
        "Custom": 0,
        "Roblox": 0,
    }
)

# Aggregated exploit/probe reasons that persist beyond the recent-list cap.
exploit_summary = dict()  # reason -> {Count, LastSeen}

# Ring buffer of the most recent proxied requests for the live feed.
live_requests = list()

# Proxied requests per minute bucket: {"<epoch_minute>": {"Successful": n, "Failed": n}}.
# Keys are strings because the JSON persistence round-trip stringifies them anyway.
traffic_minutes = dict()

# Requests refused because the internal token hit its safety budget.
token_budget = dict({"Rejections": 0})

# Requests dropped during downtime (reset at the start of each downtime via clear_stats).
pause_drops = dict({"Count": 0})
throttle_drops = dict({"Count": 0})


# --- Tarpit ------------------------------------------------------------------
# Refusals that were deliberately held open (see tarpit.py). Three views, because
# three different questions are being asked of them:
#   tarpit_stats   - the totals: how many, for how long, split by which kind of
#                    refusal was held, plus how many had to be let through
#                    instantly because the concurrency cap was full.
#   tarpit_ips     - per caller: how often each one comes back. "Gaps"/"TotalGap"
#                    accumulate the interval between a caller's successive
#                    tarpitted requests, which is the number that answers
#                    "is the tarpit actually slowing them down?".
#   tarpit_minutes - the same question over time: per-minute arrival counts, so
#                    the trend is visible rather than inferred from an average
#                    that includes every request since the counter was cleared.
def _tarpit_bucket():
    return dict({"Count": 0, "TotalHeld": 0.0, "Min": 0, "Max": 0, "Skipped": 0, "LastRequestTime": 0})


tarpit_stats = dict(
    {
        "Count": 0,  # Requests actually held.
        "Skipped": 0,  # Eligible, but the concurrency cap was full -> answered instantly.
        "TotalHeld": 0.0,  # Seconds of exploiter time spent waiting.
        "Min": 0,
        "Max": 0,
        "FirstSeen": 0,
        "LastRequestTime": 0,
        "TotalGap": 0.0,  # Summed interval between successive tarpitted requests...
        "Gaps": 0,  # ...over this many measured intervals (first-ever request has none).
        "Categories": {},  # category -> _tarpit_bucket()
    }
)

tarpit_ips = dict()  # ip -> {Count, Skipped, TotalHeld, TotalGap, Gaps, Min, Max, FirstSeen, LastRequestTime}

# Per-minute tarpit arrivals: {"<epoch_minute>": {"Count": n, "Held": seconds}}.
tarpit_minutes = dict()

# Server/upstream errors, deduped by signature: sig -> {Count, FirstSeen, LastSeen, LastDetail}.
# Distinct errors are retained until the admin clears them (high cap as an OOM guard only).
errors = dict()

# Request fingerprints for spotting abusive clients. Each header name keeps a
# breakdown of the distinct VALUES seen under it (secret values are stored as a
# short fingerprint, never raw — see _value_for_storage):
#   header_names: header NAME -> {Count, FirstSeen, LastSeen, Values: {value -> {Count, FirstSeen, LastSeen}}}
#   user_agents:  full User-Agent VALUE -> {Count, FirstSeen, LastSeen}
header_names = dict()
user_agents = dict()
# Same shape, but ONLY for requests blocked by a header rule — so the admin can
# review exactly what got blocked and catch false positives.
blocked_header_names = dict()
blocked_user_agents = dict()

# Per-minute PEAK of the token's sliding-window usage:
# {"<epoch_minute>": {"Max": peak_usage}}. "Max" leaf so cross-worker merges take
# the max, not a sum. Used to report the worst budget pressure over 1h / 24h.
token_budget_minutes = dict()

# When this worker process started (not persisted; for the dashboard uptime card).
_started_at = time.time()

# Identity for events appended to the recent-event lists. Unique per worker
# process, so the cross-worker merge can tell two identical-looking events apart
# instead of collapsing them (see _merge_list).
_event_prefix = secrets.token_hex(4)
_event_counter = itertools.count(1)


def _event_id() -> str:
    return f"{_event_prefix}-{next(_event_counter)}"


def _cap(setting_name: str, fallback: int) -> int:
    """A runtime-tunable record cap. NOTE: 0 is a valid configured value (it
    disables the record type), so this must not use `or fallback`."""
    value = runtime.get_setting(setting_name)
    return fallback if value is None else value


# --- Record caps -------------------------------------------------------------
# EVERY dict-shaped store below has a hard ceiling, and the ceiling is re-applied
# after each cross-worker merge (see _trim_all). A per-worker cap on its own is
# not enough: merging N workers' individually-capped sets produces an uncapped
# union, which is exactly how the data file grew until the workers were
# OOM-killed. Nothing here may grow without a ceiling.
#
#   cap      how many entries may survive (None = the store itself isn't capped,
#            only its children)
#   by       which entries win when trimming:
#              "count"  - busiest first (records with a Count field)
#              "recent" - newest first (records with a timestamp field)
#              "value"  - plain numeric leaves, largest first
#   time     the record's timestamp field, used by "recent" and as a tiebreak
#   children (key, cap, by) trimmed inside every surviving record
def _caps() -> dict:
    endpoint_cap = _cap("max_endpoint_records", config.MAX_ENDPOINT_RECORDS)
    ips = ("IPs", config.MAX_IPS_PER_ATTEMPT_RECORD, "value")
    value_cap = _cap("max_header_value_records", config.MAX_HEADER_VALUE_RECORDS)
    fingerprint_children = (("Values", value_cap, "count"),)
    return {
        "exploit_summary": dict(cap=config.MAX_EXPLOIT_SUMMARY, by="count", time="LastSeen"),
        "crawls": dict(cap=_cap("max_crawl_records", config.MAX_CRAWL_RECORDS), by="recent", time="LastRequestTime"),
        "throttled_ips": dict(
            cap=_cap("max_throttle_records", config.MAX_THROTTLE_RECORDS), by="recent", time="LastThrottleTime"
        ),
        "endpoints": dict(
            cap=endpoint_cap,
            by="count",
            time="LastRequestTime",
            children=(("Concrete", MAX_CONCRETE_PER_TEMPLATE, "count"),),
        ),
        "blocked_endpoint_attempts": dict(cap=endpoint_cap, by="count", time="LastRequestTime", children=(ips,)),
        "rate_limited_attempts": dict(cap=endpoint_cap, by="count", time="LastRequestTime", children=(ips,)),
        "header_blocked_attempts": dict(cap=endpoint_cap, by="count", time="LastRequestTime", children=(ips,)),
        "errors": dict(cap=_cap("max_error_records", config.MAX_ERROR_RECORDS), by="count", time="LastSeen"),
        "request_failures": dict(cap=config.MAX_REQUEST_FAILURE_RECORDS, by="count", time="LastSeen"),
        "header_names": dict(
            cap=_cap("max_header_name_records", config.MAX_HEADER_NAME_RECORDS),
            by="count",
            time="LastSeen",
            children=fingerprint_children,
        ),
        "blocked_header_names": dict(
            cap=_cap("max_header_name_records", config.MAX_HEADER_NAME_RECORDS),
            by="count",
            time="LastSeen",
            children=fingerprint_children,
        ),
        "user_agents": dict(
            cap=_cap("max_user_agent_records", config.MAX_USER_AGENT_RECORDS), by="count", time="LastSeen"
        ),
        "blocked_user_agents": dict(
            cap=_cap("max_user_agent_records", config.MAX_USER_AGENT_RECORDS), by="count", time="LastSeen"
        ),
        "status_codes_detailed": dict(cap=config.MAX_STATUS_CODES, by="value"),
        "token_usage": dict(cap=config.MAX_TOKEN_USAGE_RECORDS, by="count", time="LastUsedAt"),
        # Newest-first: an exploiter who stopped is less interesting than one
        # still knocking, and a spoofed-IP flood must not push the live one out.
        "tarpit_ips": dict(cap=config.MAX_TARPIT_IP_RECORDS, by="recent", time="LastRequestTime"),
        "retry_counts": dict(
            cap=None,
            by="count",
            children=(
                ("ByStatusCode", config.MAX_STATUS_CODES, "value"),
                ("Reasons", config.MAX_RETRY_REASONS, "value"),
            ),
        ),
    }


# Minute-bucketed stores are bounded by age rather than by rank.
_MINUTE_STORES = {
    "traffic_minutes": lambda: config.TRAFFIC_HISTORY_MINUTES,
    "token_budget_minutes": lambda: config.MAX_BUDGET_MINUTES,
    "tarpit_minutes": lambda: config.TARPIT_HISTORY_MINUTES,
}


def _trim_store(store: dict, cap, by: str, time_key: str = "") -> int:
    """Drop the lowest-ranked entries until `store` fits `cap`, in place.

    Returns how many were removed. Mirrors the eviction policy each writer
    already uses locally, so trimming a merged result never surprises a reader.
    """
    if cap is None or not isinstance(store, dict) or len(store) <= cap:
        return 0

    def rank(item):
        record = item[1]
        if by == "value":
            return (float(record) if isinstance(record, (int, float)) else 0.0, 0.0)
        if not isinstance(record, dict):
            return (0.0, 0.0)
        stamp = float(record.get(time_key, 0) or 0) if time_key else 0.0
        count = float(record.get("Count", record.get("Uses", 0)) or 0)
        return (stamp, count) if by == "recent" else (count, stamp)

    doomed = sorted(store.items(), key=rank)[: len(store) - cap]
    for key, _ in doomed:
        store.pop(key, None)
    return len(doomed)


def _prune_minute_store(store: dict, keep_minutes: int):
    """Drop minute buckets older than `keep_minutes`, plus any non-numeric key."""
    if not isinstance(store, dict):
        return
    cutoff = int(time.time() // 60) - keep_minutes
    for key in [k for k in store if not str(k).isdigit() or int(k) < cutoff]:
        store.pop(key, None)


def _trim_all(container) -> int:
    """Apply every cap to a mapping of store-name -> store, in place.

    `container` is either the merged "Diagnostics" blob or a view of this
    worker's module-level stores; both are plain dicts of the same shape.
    """
    removed = 0
    for name, spec in _caps().items():
        store = container.get(name)
        if not isinstance(store, dict):
            continue
        removed += _trim_store(store, spec.get("cap"), spec["by"], spec.get("time", ""))
        for child_key, child_cap, child_by in spec.get("children", ()):
            for record in store.values():
                if isinstance(record, dict) and isinstance(record.get(child_key), dict):
                    removed += _trim_store(record[child_key], child_cap, child_by, "LastSeen")
    for name, keep in _MINUTE_STORES.items():
        _prune_minute_store(container.get(name), keep())
    return removed


def _local_view() -> dict:
    """This worker's live stores by name (references, so trimming edits them)."""
    g = globals()
    return {name: g[name] for name in _PERSISTED_NAMES}


def trim_local() -> int:
    """Re-apply every cap to this worker's in-memory stores. Cheap once the
    stores are already at size; the point is to shrink an oversized set adopted
    from disk (e.g. the first boot after this cap system was added)."""
    with _state_lock:
        return _trim_all(_local_view())


def _is_crawler(user_agent: str) -> bool:
    ua = (user_agent or "").lower()
    if not ua:
        return True  # No User-Agent is itself a strong bot signal.
    return any(marker in ua for marker in config.CRAWLER_USER_AGENT_MARKERS)


def log_page_visit(page: str):
    global page_visits
    with _state_lock:
        if page in page_visits:
            page_visits[page] += 1
        else:
            page_visits[page] = 1


def log_visitor(user_agent: str):
    """Classify a page visitor as likely-human or likely-crawler."""
    with _state_lock:
        if _is_crawler(user_agent):
            visitor_counts["Crawler"] += 1
        else:
            visitor_counts["Human"] += 1


def decrement_admin_visit():
    """Subtract one admin page visit (used after a successful login to discount self-visits)."""
    with _state_lock:
        page_visits["admin"] = max(0, page_visits.get("admin", 0) - 1)


def log_throttle(ip: str):
    global throttled_ips
    now = time.time()
    cap = _cap("max_throttle_records", config.MAX_THROTTLE_RECORDS)
    with _state_lock:
        if ip in throttled_ips:
            throttled_ips[ip]["Count"] += 1
            throttled_ips[ip]["LastThrottleTime"] = now
        else:
            throttled_ips[ip] = dict(LastThrottleTime=now, Count=1)
        if len(throttled_ips) > cap:
            oldest_ip = min(throttled_ips.items(), key=lambda x: x[1]["LastThrottleTime"])[0]
            throttled_ips.pop(oldest_ip, None)


def log_crawl(ip: str):
    global crawls
    now = time.time()
    cap = _cap("max_crawl_records", config.MAX_CRAWL_RECORDS)
    with _state_lock:
        if ip in crawls:
            crawls[ip]["Count"] += 1
            crawls[ip]["LastRequestTime"] = now
        else:
            crawls[ip] = dict(LastRequestTime=now, Count=1)
        if len(crawls) > cap:
            oldest_ip = min(crawls.items(), key=lambda x: x[1]["LastRequestTime"])[0]
            crawls.pop(oldest_ip, None)


def log_exploit_attempt(ip: str, reason: str, user_agent: str):
    cap = _cap("max_exploit_records", config.MAX_EXPLOIT_RECORDS)
    with _state_lock:
        exploit_attempts.append(dict(Id=_event_id(), IP=ip, Date=time.time(), Reason=reason, UserAgent=user_agent))
        while len(exploit_attempts) > cap:
            exploit_attempts.pop(0)
        # Aggregate the reason so popular probes persist beyond the recent-list cap.
        summary = exploit_summary.get(reason)
        if summary:
            summary["Count"] += 1
            summary["LastSeen"] = time.time()
        else:
            exploit_summary[reason] = dict(Count=1, LastSeen=time.time())
            if len(exploit_summary) > config.MAX_EXPLOIT_SUMMARY:
                least = min(exploit_summary.items(), key=lambda kv: kv[1]["Count"])[0]
                exploit_summary.pop(least, None)


def log_endpoint(path: str, method: str, last_headers: str = "", last_ip: str = ""):
    """Record which Roblox endpoint was requested, keeping the most-frequent ones.

    Paths are grouped under an ID-collapsed template so volatile IDs don't blow
    up cardinality; the real paths seen under each template are kept (capped) so
    the dashboard can drill into the specific IDs — and each concrete path keeps
    the last sanitized headers/IP that were sent to it.

    `last_headers` is a pre-sanitized JSON string (secrets already redacted by the
    caller); stored as-is so the cross-worker merge treats it as last-writer-wins.
    """
    # Strip query string and normalize so similar paths group together.
    path = (path or "").split("?", 1)[0].strip("/")
    if not path:
        return
    template = _templatize(path)
    cap = _cap("max_endpoint_records", config.MAX_ENDPOINT_RECORDS)
    now = time.time()
    with _state_lock:
        record = endpoints.get(template)
        if record:
            record["Count"] += 1
            record["LastRequestTime"] = now
            record["Methods"][method] = record["Methods"].get(method, 0) + 1
        else:
            if len(endpoints) >= cap:
                # Evict the least-frequent template to make room.
                least = min(endpoints.items(), key=lambda kv: kv[1]["Count"])[0]
                endpoints.pop(least, None)
            record = endpoints[template] = dict(Count=1, LastRequestTime=now, Methods={method: 1}, Concrete={})
        # Track the concrete path only when the template actually collapsed an ID.
        if template != path:
            concrete = record.setdefault("Concrete", {})
            c = concrete.get(path)
            if c:
                c["Count"] += 1
                c["LastRequestTime"] = now
                c["Methods"][method] = c["Methods"].get(method, 0) + 1
                if last_headers:
                    c["LastHeaders"] = last_headers
                    c["LastIP"] = last_ip
            else:
                if len(concrete) >= MAX_CONCRETE_PER_TEMPLATE:
                    least = min(concrete.items(), key=lambda kv: kv[1]["Count"])[0]
                    concrete.pop(least, None)
                concrete[path] = dict(
                    Count=1, LastRequestTime=now, Methods={method: 1}, LastHeaders=last_headers, LastIP=last_ip
                )


def log_blocked_endpoint(path: str, method: str, ip: str, pattern: str):
    """Record an attempt to reach a blocked endpoint, keeping the most-frequent ones."""
    _log_rejected_endpoint(blocked_endpoint_attempts, path, method, ip, pattern)


def log_rate_limited_endpoint(path: str, method: str, ip: str, pattern: str):
    """Record a request rejected by a per-endpoint rate rule, keeping the most-frequent ones."""
    _log_rejected_endpoint(rate_limited_attempts, path, method, ip, pattern)


def _log_rejected_endpoint(store: dict, path: str, method: str, ip: str, pattern: str):
    path = (path or "").split("?", 1)[0].strip("/")
    if not path:
        return
    now = time.time()
    cap = _cap("max_endpoint_records", config.MAX_ENDPOINT_RECORDS)
    with _state_lock:
        record = store.get(path)
        if record:
            record["Count"] += 1
            record["LastRequestTime"] = now
            record["LastIP"] = ip
            record["Pattern"] = pattern
            record["Methods"][method] = record["Methods"].get(method, 0) + 1
            record["IPs"][ip] = record["IPs"].get(ip, 0) + 1
            if len(record["IPs"]) > config.MAX_IPS_PER_ATTEMPT_RECORD:  # Keep only the busiest IPs per endpoint.
                least = min(record["IPs"].items(), key=lambda kv: kv[1])[0]
                record["IPs"].pop(least, None)
        else:
            if len(store) >= cap:
                least = min(store.items(), key=lambda kv: kv[1]["Count"])[0]
                store.pop(least, None)
            store[path] = dict(
                Count=1, LastRequestTime=now, Pattern=pattern, LastIP=ip, Methods={method: 1}, IPs={ip: 1}
            )


def log_header_blocked(rule: dict, path: str, method: str, ip: str):
    """Record a request denied by a header rule, keyed by the rule that caught it.

    The admin sees exactly which rule is catching exploiters and which header
    tripped it; the client only ever sees a generic error.
    """
    rule_id = str(rule.get("Id", "?"))
    path = (path or "").split("?", 1)[0].strip("/")
    now = time.time()
    cap = _cap("max_endpoint_records", config.MAX_ENDPOINT_RECORDS)
    header = rule.get("MatchedHeader", "")
    field = rule.get("MatchedField", "")  # "key" or "value" — what tripped the rule
    snippet = _snippet_for(header, rule.get("MatchedText", ""))
    with _state_lock:
        record = header_blocked_attempts.get(rule_id)
        if record:
            record["Count"] += 1
            record["LastRequestTime"] = now
            record["LastIP"] = ip
            record["LastHeader"] = header
            record["LastField"] = field
            record["LastMatch"] = snippet
            record["LastPath"] = path
            record["Methods"][method] = record["Methods"].get(method, 0) + 1
            record["IPs"][ip] = record["IPs"].get(ip, 0) + 1
            if len(record["IPs"]) > config.MAX_IPS_PER_ATTEMPT_RECORD:  # Keep only the busiest IPs per rule.
                least = min(record["IPs"].items(), key=lambda kv: kv[1])[0]
                record["IPs"].pop(least, None)
        else:
            if len(header_blocked_attempts) >= cap:
                least = min(header_blocked_attempts.items(), key=lambda kv: kv[1]["Count"])[0]
                header_blocked_attempts.pop(least, None)
            header_blocked_attempts[rule_id] = dict(
                Count=1,
                LastRequestTime=now,
                Scope=rule.get("Scope", ""),
                Mode=rule.get("Mode", ""),
                Needle=rule.get("Needle", ""),
                LastIP=ip,
                LastHeader=header,
                LastField=field,
                LastMatch=snippet,
                LastPath=path,
                Methods={method: 1},
                IPs={ip: 1},
            )


# Header names whose VALUES must never be surfaced on the dashboard.
_SENSITIVE_HEADER_NAMES = {"x-roblox-token", "cookie", "authorization", "x-csrf-token"}


def _snippet_for(header_name: str, text: str) -> str:
    """A short, safe snippet of what tripped a header rule (sensitive values redacted)."""
    if (header_name or "").lower() in _SENSITIVE_HEADER_NAMES:
        return "[redacted]"
    text = str(text or "")
    return text if len(text) <= 120 else text[:120] + "…"


def log_budget_rejection():
    """Record a request refused because the internal token hit its safety budget."""
    with _state_lock:
        token_budget["Rejections"] = token_budget.get("Rejections", 0) + 1


def record_token_budget_usage(usage: int):
    """Record the token's current sliding-window usage, keeping a per-minute peak.

    Lets the dashboard show the worst budget pressure over the last hour / day."""
    bucket = str(int(time.time() // 60))
    with _state_lock:
        entry = token_budget_minutes.get(bucket)
        if entry is None:
            # Keep ~24h of minute buckets.
            cutoff = int(time.time() // 60) - 1440
            for key in [k for k in token_budget_minutes if not str(k).isdigit() or int(k) < cutoff]:
                token_budget_minutes.pop(key, None)
            token_budget_minutes[bucket] = {"Max": int(usage)}
        elif int(usage) > entry.get("Max", 0):
            entry["Max"] = int(usage)


def _budget_peak_since(minutes: int) -> int:
    cutoff = int(time.time() // 60) - minutes
    peak = 0
    with _state_lock:
        for key, entry in token_budget_minutes.items():
            if str(key).isdigit() and int(key) >= cutoff:
                peak = max(peak, int(entry.get("Max", 0)))
    return peak


_METHOD_NAMES = {"token": "Token", "rotate": "Rotate"}


def log_method(method: str, success: bool):
    """Count an upstream request by method (token/rotate) + whether it failed."""
    name = _METHOD_NAMES.get(method)
    if not name:
        return
    now = time.time()
    with _state_lock:
        stat = method_stats[name]
        stat["Requests"] = stat.get("Requests", 0) + 1
        stat["LastRequestTime"] = now
        if success:
            stat["LastSuccessAt"] = now
        else:
            stat["Failed"] = stat.get("Failed", 0) + 1


def log_method_error(method: str, error: str = ""):
    """Record WHEN a requester last failed and why, for its health card.

    Rotate had this from the start (via log_rotate_health) and Token did not,
    which is the whole reason the Token card could only ever say "OK" — it had no
    liveness information to show.
    """
    name = _METHOD_NAMES.get(method)
    if not name:
        return
    with _state_lock:
        method_stats[name]["LastErrorAt"] = time.time()
        if error:
            method_stats[name]["LastError"] = str(error)[:200]


def log_method_timeout(method: str):
    """Count an upstream timeout for a method (transient; never emailed)."""
    name = _METHOD_NAMES.get(method)
    if not name:
        return
    with _state_lock:
        method_stats[name]["Timeouts"] = method_stats[name].get("Timeouts", 0) + 1


def log_rotate_health(ok: bool, error: str = ""):
    """Track the rotation proxy's last success / last proxy-level error."""
    now = time.time()
    with _state_lock:
        if ok:
            method_stats["Rotate"]["LastSuccessAt"] = now
        else:
            method_stats["Rotate"]["LastErrorAt"] = now
            if error:
                method_stats["Rotate"]["LastError"] = str(error)[:200]


def _fold_timing(record: dict, duration: float, now: float):
    """Add one latency sample to a {TotalTime, Count, Min, Max, LastRequestTime}."""
    record["TotalTime"] = float(record.get("TotalTime", 0) or 0) + duration
    record["Count"] = int(record.get("Count", 0) or 0) + 1
    record["LastRequestTime"] = now
    if duration < record.get("Min", 0) or not record.get("Min"):
        record["Min"] = duration
    if duration > record.get("Max", 0):
        record["Max"] = duration


def _record_timing(store: dict, key: str, duration: float, success: bool):
    """Record a latency sample in both the combined row and its outcome split.

    setdefault rather than direct access on purpose: a stats file written before
    the split existed restores a record with no Success/Failed children, and this
    heals it on the next sample instead of raising.
    """
    record = store.get(key)
    if record is None:
        return
    now = time.time()
    _fold_timing(record, duration, now)
    _fold_timing(record.setdefault("Success" if success else "Failed", _outcome_stat()), duration, now)


def log_method_timing(method: str, duration: float, success: bool = True):
    """Record an upstream timing sample for a requester (Token/Rotate)."""
    name = _METHOD_NAMES.get(method)
    if not name:
        return
    with _state_lock:
        _record_timing(method_timings, name, duration, success)


def log_request_failure(method: str, status, reason: str, endpoint: str = "", detail: str = ""):
    """Record a failed routed upstream request so the admin can see WHY a given
    requester is being rejected (deduped by method + reason, with a frequency
    count and the last status/endpoint/detail)."""
    name = _METHOD_NAMES.get(method, (method or "?").title())
    reason = (reason or "Unknown")[:120]
    sig = f"{name}: {reason}"
    endpoint = (endpoint or "").split("?", 1)[0][:200]
    now = time.time()
    with _state_lock:
        rec = request_failures.get(sig)
        if rec:
            rec["Count"] += 1
            rec["LastSeen"] = now
            rec["LastStatus"] = str(status)  # string so the cross-worker merge treats it as last-writer
            if endpoint:
                rec["LastEndpoint"] = endpoint
            if detail:
                rec["LastDetail"] = str(detail)[:2000]
        else:
            if len(request_failures) >= config.MAX_REQUEST_FAILURE_RECORDS:
                least = min(request_failures.items(), key=lambda kv: kv[1]["Count"])[0]
                request_failures.pop(least, None)
            request_failures[sig] = dict(
                Method=name,
                Count=1,
                FirstSeen=now,
                LastSeen=now,
                LastStatus=str(status),
                LastEndpoint=endpoint,
                LastDetail=str(detail)[:2000],
            )


def log_rotate_ip(ip: str, source: str = ""):
    """Append a verified rotation exit IP to the ring buffer (newest kept)."""
    ip = str(ip or "").strip()[:64]
    if not ip:
        return
    with _state_lock:
        rotate_ips.append(dict(Id=_event_id(), IP=ip, Date=time.time(), Source=str(source)[:40]))
        while len(rotate_ips) > config.MAX_ROTATE_IPS:
            rotate_ips.pop(0)


def reset_method_counters():
    """Zero the per-method request tallies (used when clearing request stats)."""
    with _state_lock:
        for name in ("Token", "Rotate"):
            method_stats[name] = _method_stat()  # Pristine, so added fields reset too.
        proxy_health["Tokens"]["ExpiredCount"] = 0


def log_error(signature: str, detail: str = ""):
    """Record a server/upstream error, deduped by signature with a frequency count.

    Distinct errors are kept until the admin clears them (capped only to guard
    against an attacker deliberately generating unbounded error variety)."""
    signature = (signature or "Unknown error")[:200]
    now = time.time()
    with _state_lock:
        rec = errors.get(signature)
        if rec:
            rec["Count"] += 1
            rec["LastSeen"] = now
            if detail:
                rec["LastDetail"] = str(detail)[:2000]
        else:
            if len(errors) >= _cap("max_error_records", config.MAX_ERROR_RECORDS):
                least = min(errors.items(), key=lambda kv: kv[1]["Count"])[0]
                errors.pop(least, None)
            errors[signature] = dict(Count=1, FirstSeen=now, LastSeen=now, LastDetail=str(detail)[:2000])


def _bump_fingerprint(store: dict, key: str, cap: int) -> dict | None:
    """Increment (or create) a {Count, FirstSeen, LastSeen} record. Returns it."""
    if not key:
        return None
    now = time.time()
    rec = store.get(key)
    if rec:
        rec["Count"] += 1
        rec["LastSeen"] = now
        return rec
    if len(store) >= cap:
        least = min(store.items(), key=lambda kv: kv[1]["Count"])[0]
        store.pop(least, None)
    rec = store[key] = dict(Count=1, FirstSeen=now, LastSeen=now)
    return rec


def _value_for_storage(header_name_lower: str, value: str) -> str:
    """The value to record for a header. Secret headers are stored as a short
    irreversible fingerprint (so distinct values can still be counted/compared)
    rather than the raw secret."""
    value = "" if value is None else str(value)
    if header_name_lower in _SENSITIVE_HEADER_NAMES:
        if not value:
            return "(empty)"
        return "fp:" + hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:12]
    return value[:200] if value else "(empty)"


def _should_skip_values(name_lower: str, record: dict, value_cap: int) -> bool:
    """Whether to stop enumerating this header's distinct values.

    True when the admin has listed the header, or when the header has proved by
    observation that its values are unique per request -- at which point the
    "distinct values" list is just a slow, expensive way of recounting requests.
    Auto-detections are written to the shared ignore list so every worker agrees
    and the admin can see (and undo) the decision on the dashboard.
    """
    if runtime.ignores_header_values(name_lower):
        return True
    if not runtime.get_setting("auto_ignore_high_cardinality", 1):
        return False
    seen = int(record.get("Count", 0) or 0)
    if seen < config.AUTO_IGNORE_MIN_REQUESTS:
        return False
    # Distinct values are capped, so once the cap is reached the true unique
    # count is unknown -- but "we hit the ceiling and kept finding new ones" is
    # itself the signal. Unique/seen is measured against everything recorded so
    # far, tracked in UniqueSeen (which is not capped, it's one integer).
    # Clamped to `seen`: UniqueSeen accumulates per worker, so the same value
    # observed on two workers counts twice and could otherwise exceed the
    # request count it is being compared against.
    unique = min(int(record.get("UniqueSeen", len(record.get("Values", {}))) or 0), seen)
    if unique < value_cap or seen <= 0:
        return False
    if unique / seen < config.AUTO_IGNORE_UNIQUE_RATIO:
        return False
    ok, _ = runtime.add_ignored_value_header(
        name_lower, note=f"auto: {unique} distinct values in {seen} requests", auto=True
    )
    if ok:
        record["Values"] = {}
        record["ValuesIgnored"] = True
    return ok


def log_request_fingerprint(
    header_pairs, user_agent: str, blocked: bool = False, last_headers: str = "", last_path: str = "", last_ip: str = ""
):
    """Track the distinct header names + their values + the user-agent of a request.

    `header_pairs` is an iterable of (name, value). When `blocked` is True the data
    goes into the blocked-request stores instead (for false-positive review).

    Headers whose values are unique per request (traceparent and friends) keep
    their name and count but skip the value breakdown -- see _should_skip_values.

    `last_headers` (a pre-sanitized JSON string), `last_path` and `last_ip` are
    attached to the user-agent record so the admin can drill into exactly what a
    given UA (including the "(none)" UA) last sent and where."""
    names_store = blocked_header_names if blocked else header_names
    ua_store = blocked_user_agents if blocked else user_agents
    pairs = list(header_pairs.items()) if hasattr(header_pairs, "items") else list(header_pairs)
    name_cap = _cap("max_header_name_records", config.MAX_HEADER_NAME_RECORDS)
    value_cap = _cap("max_header_value_records", config.MAX_HEADER_VALUE_RECORDS)
    ua_cap = _cap("max_user_agent_records", config.MAX_USER_AGENT_RECORDS)
    with _state_lock:
        for name, value in pairs:
            name_l = str(name).lower()[:120]
            rec = _bump_fingerprint(names_store, name_l, name_cap)
            if rec is None:
                continue
            if _should_skip_values(name_l, rec, value_cap):
                rec["ValuesIgnored"] = True
                rec.pop("Values", None)
                continue
            rec.pop("ValuesIgnored", None)
            values = rec.setdefault("Values", {})
            stored = _value_for_storage(name_l, value)
            if stored not in values:
                # Counts distinct values EVER seen, including ones since evicted
                # by the cap. One integer, so it stays cheap while telling us
                # what the capped Values dict no longer can.
                rec["UniqueSeen"] = int(rec.get("UniqueSeen", 0) or 0) + 1
            _bump_fingerprint(values, stored, value_cap)
        ua_rec = _bump_fingerprint(ua_store, (user_agent or "(none)")[:400], ua_cap)
        if ua_rec is not None and last_headers:
            ua_rec["LastHeaders"] = last_headers
            ua_rec["LastPath"] = (last_path or "")[:300]
            ua_rec["LastIP"] = (last_ip or "")[:64]


def _apply_key_clear(container: dict, store_name: str, key: str, values_only: bool):
    """Erase one record (or just its Values) from a store inside `container`."""
    store = container.get(store_name)
    if not isinstance(store, dict):
        return
    if not values_only:
        store.pop(key, None)
        return
    record = store.get(key)
    if isinstance(record, dict):
        record["Values"] = {}


def clear_fingerprint_header(blocked: bool, name: str, values_only: bool = False) -> tuple[bool, int]:
    """Clear one header's record everywhere: this worker, the data file, and —
    via KeyClearEpochs — every other worker at its next flush.

    That last part is the whole point. Popping the key locally and from the file
    is not enough: every OTHER worker still holds the header in memory and in its
    merge baseline, so its next autosave merges the record straight back, values
    and all. Section clears already solve this with ClearEpochs; per-key clears
    need the same protection, keyed per record instead of per store.

    `values_only` keeps the header and its request count but drops the
    per-value breakdown. Returns (ok, values_removed).
    """
    store_name = "blocked_header_names" if blocked else "header_names"
    key = str(name).lower()[:120]
    epoch_key = f"{store_name}/{key}" + ("/Values" if values_only else "")
    now = time.time()

    with _state_lock:
        existing = globals()[store_name].get(key) or {}
        removed = len(existing.get("Values", {})) if isinstance(existing, dict) else 0

        _apply_key_clear(_local_view(), store_name, key, values_only)
        if isinstance(_baseline, dict):
            _apply_key_clear(_baseline, store_name, key, values_only)
        _applied_key_clear_epochs[epoch_key] = now

        def mutate(data):
            diag = data.setdefault("Diagnostics", {})
            if not isinstance(diag, dict):
                diag = data["Diagnostics"] = {}
            _apply_key_clear(diag, store_name, key, values_only)
            epochs = diag.setdefault("KeyClearEpochs", {})
            epochs[epoch_key] = now
            _prune_key_clear_epochs(epochs)
            return data

        try:
            storage.update_data(mutate)
            return True, removed
        except OSError:
            return False, removed


def _prune_key_clear_epochs(epochs: dict):
    """Forget per-key clear markers once every worker must have applied them.

    A worker that was down through the whole window rejoins by loading the file,
    which already reflects the clear, so nothing can be resurrected afterwards.
    """
    if not isinstance(epochs, dict):
        return
    cutoff = time.time() - KEY_CLEAR_EPOCH_TTL
    for key in [k for k, ts in epochs.items() if float(ts or 0) < cutoff]:
        epochs.pop(key, None)
    if len(epochs) > MAX_KEY_CLEAR_EPOCHS:
        for key, _ in sorted(epochs.items(), key=lambda kv: float(kv[1] or 0))[: len(epochs) - MAX_KEY_CLEAR_EPOCHS]:
            epochs.pop(key, None)


def log_pause_drop():
    with _state_lock:
        pause_drops["Count"] = pause_drops.get("Count", 0) + 1


def log_throttle_all_drop():
    with _state_lock:
        throttle_drops["Count"] = throttle_drops.get("Count", 0) + 1


def _bump_span(record: dict, seconds: float):
    """Fold one duration sample into a {Min, Max} pair, in place."""
    if seconds <= 0:
        return
    if seconds < record.get("Min", 0) or not record.get("Min"):
        record["Min"] = seconds
    if seconds > record.get("Max", 0):
        record["Max"] = seconds


def _log_tarpit_event(ip: str, category: str, held: float, gap: float, arrived: float, skipped: bool):
    """Record one tarpit-eligible refusal.

    `arrived` is when the request LANDED, not when we let go of it — so the
    measured interval between a caller's requests reflects how often they knock,
    undistorted by how long each hold lasted. `gap` is that interval, computed
    once in the shared tarpit file (see tarpit._admit) rather than per worker.
    """
    ip = (ip or "unknown")[:64]
    category = (category or "other")[:40]
    with _state_lock:
        tarpit_stats["LastRequestTime"] = max(float(tarpit_stats.get("LastRequestTime", 0) or 0), arrived)
        if not tarpit_stats.get("FirstSeen"):
            tarpit_stats["FirstSeen"] = arrived
        if gap > 0:
            tarpit_stats["TotalGap"] = float(tarpit_stats.get("TotalGap", 0) or 0) + gap
            tarpit_stats["Gaps"] = int(tarpit_stats.get("Gaps", 0) or 0) + 1
        bucket = tarpit_stats.setdefault("Categories", {}).setdefault(category, _tarpit_bucket())
        bucket["LastRequestTime"] = max(float(bucket.get("LastRequestTime", 0) or 0), arrived)

        record = tarpit_ips.get(ip)
        if record is None:
            if len(tarpit_ips) >= config.MAX_TARPIT_IP_RECORDS:
                stale = min(tarpit_ips.items(), key=lambda kv: float(kv[1].get("LastRequestTime", 0) or 0))[0]
                tarpit_ips.pop(stale, None)
            record = tarpit_ips[ip] = dict(
                Count=0, Skipped=0, TotalHeld=0.0, TotalGap=0.0, Gaps=0, Min=0, Max=0, FirstSeen=arrived
            )
        record["LastRequestTime"] = max(float(record.get("LastRequestTime", 0) or 0), arrived)
        if gap > 0:
            record["TotalGap"] = float(record.get("TotalGap", 0) or 0) + gap
            record["Gaps"] = int(record.get("Gaps", 0) or 0) + 1

        if skipped:
            tarpit_stats["Skipped"] = int(tarpit_stats.get("Skipped", 0) or 0) + 1
            bucket["Skipped"] = int(bucket.get("Skipped", 0) or 0) + 1
            record["Skipped"] = int(record.get("Skipped", 0) or 0) + 1
        else:
            tarpit_stats["Count"] = int(tarpit_stats.get("Count", 0) or 0) + 1
            tarpit_stats["TotalHeld"] = float(tarpit_stats.get("TotalHeld", 0) or 0) + held
            _bump_span(tarpit_stats, held)
            bucket["Count"] = int(bucket.get("Count", 0) or 0) + 1
            bucket["TotalHeld"] = float(bucket.get("TotalHeld", 0) or 0) + held
            _bump_span(bucket, held)
            record["Count"] = int(record.get("Count", 0) or 0) + 1
            record["TotalHeld"] = float(record.get("TotalHeld", 0) or 0) + held
            _bump_span(record, held)

        # Per-minute arrivals, so a falling request rate is visible as a trend
        # rather than having to be inferred from a lifetime average.
        minute = str(int(arrived // 60))
        entry = tarpit_minutes.get(minute)
        if entry is None:
            _prune_minute_store(tarpit_minutes, config.TARPIT_HISTORY_MINUTES)
            entry = tarpit_minutes[minute] = {"Count": 0, "Held": 0.0}
        entry["Count"] += 1
        entry["Held"] = float(entry.get("Held", 0) or 0) + held


def log_tarpit(ip: str, category: str, held: float, gap: float, arrived: float):
    """A refusal that was held open for `held` seconds."""
    _log_tarpit_event(ip, category, held, gap, arrived, skipped=False)


def log_tarpit_skipped(ip: str, category: str, gap: float, arrived: float):
    """A refusal that WOULD have been held, but every tarpit slot was taken.

    Tracked separately and deliberately: if this number climbs, the limit on the
    tarpit is our own concurrency cap, not the caller's patience.
    """
    _log_tarpit_event(ip, category, 0.0, gap, arrived, skipped=True)


def _tarpit_rate(minutes: int) -> dict:
    """Tarpitted requests over the last `minutes`, and the mean interval between
    them. This is the "are they backing off?" number: compare a short window with
    a long one and a caller that is slowing down shows a widening gap."""
    cutoff = int(time.time() // 60) - minutes
    count = 0
    held = 0.0
    with _state_lock:
        for key, entry in tarpit_minutes.items():
            if str(key).isdigit() and int(key) >= cutoff:
                count += int(entry.get("Count", 0) or 0)
                held += float(entry.get("Held", 0) or 0)
    return {
        "Minutes": minutes,
        "Count": count,
        "Held": held,
        # Seconds between requests, averaged over the window. 0 when nothing
        # arrived, which the UI renders as "—" rather than "0s apart".
        "AvgGap": round((minutes * 60) / count, 2) if count else 0,
    }


def log_retry(status_code: int, reason: str = ""):
    """Record that a proxied request was retried, with the triggering status/reason."""
    with _state_lock:
        retry_counts["Total"] += 1
        code = str(status_code)
        retry_counts["ByStatusCode"][code] = retry_counts["ByStatusCode"].get(code, 0) + 1
        _cap_counter_map(retry_counts["ByStatusCode"], config.MAX_STATUS_CODES)
        if reason:
            retry_counts["Reasons"][reason[:120]] = retry_counts["Reasons"].get(reason[:120], 0) + 1
            _cap_counter_map(retry_counts["Reasons"], config.MAX_RETRY_REASONS)


def log_reason(is_custom: bool):
    """Record whether a returned error reason was our own message or Roblox's passthrough."""
    with _state_lock:
        if is_custom:
            reason_counts["Custom"] += 1
        else:
            reason_counts["Roblox"] += 1


def log_live_request(entry: dict):
    """Append a recent request to the live feed ring buffer."""
    cap = _cap("max_live_requests", config.MAX_LIVE_REQUESTS)
    with _state_lock:
        entry.setdefault("Id", _event_id())
        live_requests.append(entry)
        while len(live_requests) > cap:
            live_requests.pop(0)


def log_login_attempt(ip: str, successful: bool):
    cap = _cap("max_login_records", config.MAX_LOGIN_RECORDS)
    with _state_lock:
        login_attempts.append(dict(Id=_event_id(), IP=ip, Date=time.time(), Successful=successful))
        while len(login_attempts) > cap:
            login_attempts.pop(0)


def _prune_traffic_unlocked(store: dict):
    cutoff = int(time.time() // 60) - config.TRAFFIC_HISTORY_MINUTES
    for key in [k for k in store if not str(k).isdigit() or int(k) < cutoff]:
        store.pop(key, None)


def log_request(method: str, successful: bool):
    with _state_lock:
        if method in request_counts:
            if successful:
                request_counts[method]["Successful"] += 1
            else:
                request_counts[method]["Failed"] += 1
        # Per-minute traffic series for the dashboard chart.
        bucket = str(int(time.time() // 60))
        entry = traffic_minutes.get(bucket)
        if entry is None:
            _prune_traffic_unlocked(traffic_minutes)
            entry = traffic_minutes[bucket] = {"Successful": 0, "Failed": 0}
        entry["Successful" if successful else "Failed"] += 1


def _cap_counter_map(store: dict, cap: int):
    """Bound a {key: count} map by dropping the smallest counts. Real traffic
    stays far under these ceilings; they exist so a hostile or buggy upstream
    can't turn a counter map into an unbounded one."""
    if len(store) > cap:
        for key, _ in sorted(store.items(), key=lambda kv: kv[1])[: len(store) - cap]:
            store.pop(key, None)


def log_status_code(status_code: int):
    with _state_lock:
        if 200 <= status_code < 300:
            status_code_counts["2xx"] += 1
        elif 400 <= status_code < 500:
            status_code_counts["4xx"] += 1
        # Detailed per-code breakdown (covers 1xx/3xx/5xx too).
        code = str(status_code)
        status_codes_detailed[code] = status_codes_detailed.get(code, 0) + 1
        _cap_counter_map(status_codes_detailed, config.MAX_STATUS_CODES)


def log_proxy_request(method: str, duration: float, success: bool = True):
    with _state_lock:
        _record_timing(proxy_request_counts, method, duration, success)


def _token_fp(token: str) -> str:
    """An irreversible fingerprint of a token — safe to persist (unlike the token)."""
    return hashlib.sha256((token or "").encode("utf-8", "replace")).hexdigest()[:16]


def _masked(token: str) -> str:
    """A short label for a token. Kept deliberately brief: it is rendered on the
    dashboard and ends up in CSV/JSON exports, so it must not carry enough of a
    live credential to matter. Mirrors proxy.mask_token (duplicated rather than
    imported because proxy imports this module)."""
    return f"…{(token or '')[-6:]}"


def update_token(token: str, being_validated: bool = False, used: bool = False):
    global tokens
    masked = _masked(token)
    with _state_lock:
        if token in tokens:
            tokens[token]["BeingValidated"] = being_validated
            if used:
                tokens[token]["Uses"] += 1
        else:
            tokens[token] = dict(
                Masked=masked,
                BeingValidated=being_validated,
                Uses=tokens.get(token, {}).get("Uses", 0) + (1 if used else 0),
            )
        # Cross-worker-mergeable usage, keyed by fingerprint (never the secret).
        if used:
            fp = _token_fp(token)
            rec = token_usage.get(fp)
            if rec:
                rec["Uses"] += 1
                rec["LastUsedAt"] = time.time()
            else:
                # Retired tokens leave their fingerprint behind, so this grows
                # with token churn rather than staying at the token count.
                if len(token_usage) >= config.MAX_TOKEN_USAGE_RECORDS:
                    stale = min(token_usage.items(), key=lambda kv: kv[1].get("LastUsedAt", 0))[0]
                    token_usage.pop(stale, None)
                token_usage[fp] = dict(Uses=1, LastUsedAt=time.time())
        proxy_health["Tokens"]["Count"] = len(tokens)
        proxy_health["Tokens"]["BeingValidatedCount"] = sum(1 for t in tokens.values() if t["BeingValidated"])


def remove_token(token: str, expired: bool = False):
    """Remove a token from the diagnostics view (thread-safe). Used by the proxy."""
    with _state_lock:
        if token in tokens:
            tokens.pop(token, None)
        if expired:
            proxy_health["Tokens"]["ExpiredCount"] += 1
        proxy_health["Tokens"]["Count"] = len(tokens)
        proxy_health["Tokens"]["BeingValidatedCount"] = sum(1 for t in tokens.values() if t["BeingValidated"])


def clear_tokens():
    """Drop all tokens from the diagnostics view (thread-safe)."""
    with _state_lock:
        tokens.clear()
        proxy_health["Tokens"]["Count"] = 0
        proxy_health["Tokens"]["BeingValidatedCount"] = 0


def _tokens_view() -> list:
    """The Auth Tokens table: current inventory + MERGED usage (so per-token Uses
    matches the cross-worker Token method Requests). Call under _state_lock and
    after a flush so token_usage holds the global totals."""
    out = []
    for full, info in tokens.items():
        usage = token_usage.get(_token_fp(full), {})
        out.append(
            {
                "Masked": info.get("Masked", "…***"),
                "BeingValidated": bool(info.get("BeingValidated")),
                "Uses": int(usage.get("Uses", 0)),
                "LastUsedAt": usage.get("LastUsedAt", 0),
            }
        )
    return out


# --- Dashboard views ---------------------------------------------------------
# The dashboard polls often, so what it receives has to stay small. The bulky
# parts of each record -- a header's distinct values, a user-agent's last full
# header dump, an endpoint template's concrete paths -- are summarised here and
# fetched on demand by the drill-down endpoints below. This keeps the poll
# response roughly two orders of magnitude smaller than the underlying state.
def _summarise_header_names(store: dict) -> dict:
    out = {}
    for name, rec in store.items():
        seen = int(rec.get("Count", 0) or 0)
        unique = min(int(rec.get("UniqueSeen", len(rec.get("Values", {}))) or 0), seen) if seen else 0
        out[name] = {
            "Count": seen,
            "FirstSeen": rec.get("FirstSeen", 0),
            "LastSeen": rec.get("LastSeen", 0),
            "ValueCount": len(rec.get("Values", {})),
            "UniqueSeen": unique,
            # 1.0 means every request carried a different value, i.e. the header
            # is unbounded by nature and its values are not worth enumerating.
            "UniqueRatio": round(unique / seen, 3) if seen else 0,
            "ValuesIgnored": bool(rec.get("ValuesIgnored")),
        }
    return out


def _summarise_user_agents(store: dict) -> dict:
    return {
        ua: {
            "Count": rec.get("Count", 0),
            "FirstSeen": rec.get("FirstSeen", 0),
            "LastSeen": rec.get("LastSeen", 0),
            "HasDetail": bool(rec.get("LastHeaders")),
        }
        for ua, rec in store.items()
    }


def _summarise_endpoints(store: dict) -> dict:
    return {
        template: {
            "Count": rec.get("Count", 0),
            "LastRequestTime": rec.get("LastRequestTime", 0),
            "Methods": dict(rec.get("Methods", {})),
            "ConcreteCount": len(rec.get("Concrete", {})),
        }
        for template, rec in store.items()
    }


def get_header_values(blocked: bool, name: str, limit: int = 200) -> dict:
    """The distinct values recorded under one header name, busiest first."""
    store = blocked_header_names if blocked else header_names
    with _state_lock:
        rec = copy.deepcopy(store.get(str(name).lower()[:120]) or {})
    values = rec.get("Values", {})
    ordered = sorted(values.items(), key=lambda kv: kv[1].get("Count", 0), reverse=True)[:limit]
    return {
        "Name": name,
        "Count": rec.get("Count", 0),
        "Total": len(values),
        "Shown": len(ordered),
        "ValuesIgnored": bool(rec.get("ValuesIgnored")),
        "Values": dict(ordered),
    }


def get_user_agent_detail(blocked: bool, user_agent: str) -> dict:
    """The last headers/path/IP recorded for one user-agent."""
    store = blocked_user_agents if blocked else user_agents
    with _state_lock:
        rec = copy.deepcopy(store.get(str(user_agent)[:400]) or {})
    return {
        "UserAgent": user_agent,
        "Count": rec.get("Count", 0),
        "LastHeaders": rec.get("LastHeaders", ""),
        "LastPath": rec.get("LastPath", ""),
        "LastIP": rec.get("LastIP", ""),
    }


def get_endpoint_detail(template: str, limit: int = 100) -> dict:
    """The concrete paths recorded under one endpoint template, busiest first."""
    with _state_lock:
        rec = copy.deepcopy(endpoints.get(template) or {})
    concrete = rec.get("Concrete", {})
    ordered = sorted(concrete.items(), key=lambda kv: kv[1].get("Count", 0), reverse=True)[:limit]
    return {"Template": template, "Total": len(concrete), "Concrete": dict(ordered)}


_last_flush_at = 0.0


def _maybe_flush(force: bool = False):
    """Merge with the other workers, but no more often than the configured
    interval. The merge is the most expensive operation in the app and the
    dashboard polls far faster than the data meaningfully changes; polls in
    between are served from already-merged memory. `force` is for an explicit
    Refresh, where the admin is asking for the current truth."""
    global _last_flush_at
    interval = runtime.get_setting("diagnostics_flush_interval", config.DIAGNOSTICS_FLUSH_INTERVAL)
    now = time.time()
    if not force and interval and now - _last_flush_at < interval:
        return
    _last_flush_at = now
    try:
        _flush()
    except Exception:
        pass  # If persistence is briefly unavailable, fall back to local memory.


def get_diagnostics(force_flush: bool = False) -> dict:
    global tokens
    # Push this worker's pending stats into the shared file and adopt the merged
    # global totals, so the dashboard shows the true aggregate across all gunicorn
    # workers (not just the slice this worker happened to handle).
    _maybe_flush(force=force_flush)
    with _state_lock:
        # Deep-copy the whole snapshot under the lock so no other thread can
        # mutate a structure while Flask iterates it during JSON serialization.
        snapshot = copy.deepcopy(
            {
                "PageVisits": page_visits,
                "VisitorCounts": visitor_counts,
                "ThrottledIPs": throttled_ips,
                "ExploitAttempts": exploit_attempts,
                "ExploitSummary": exploit_summary,
                "LoginAttempts": login_attempts,
                "RequestCounts": request_counts,
                "StatusCodeCounts": status_code_counts,
                "StatusCodesDetailed": status_codes_detailed,
                "ProxyRequestCounts": proxy_request_counts,
                "MethodTimings": method_timings,
                "ProxyHealth": proxy_health,
                "MethodStats": method_stats,
                "RequestFailures": request_failures,
                "RotateIps": list(reversed(rotate_ips)),  # Most-recent first.
                "Crawls": crawls,
                "Endpoints": _summarise_endpoints(endpoints),
                "BlockedEndpointAttempts": blocked_endpoint_attempts,
                "RateLimitedAttempts": rate_limited_attempts,
                "HeaderBlockedAttempts": header_blocked_attempts,
                "RetryCounts": retry_counts,
                "ReasonCounts": reason_counts,
                "LiveRequests": list(reversed(live_requests)),  # Most-recent first.
                "Tokens": _tokens_view(),
                "TrafficMinutes": traffic_minutes,
                "TokenBudgetRejections": token_budget.get("Rejections", 0),
                "BudgetPeak1h": _budget_peak_since(60),
                "BudgetPeak24h": _budget_peak_since(1440),
                "PauseDrops": pause_drops.get("Count", 0),
                "ThrottleAllDrops": throttle_drops.get("Count", 0),
                "TarpitStats": tarpit_stats,
                "TarpitIps": tarpit_ips,
                "Errors": errors,
                "HeaderNames": _summarise_header_names(header_names),
                "UserAgents": _summarise_user_agents(user_agents),
                "BlockedHeaderNames": _summarise_header_names(blocked_header_names),
                "BlockedUserAgents": _summarise_user_agents(blocked_user_agents),
                "ServerTime": time.time(),
                "WorkerStartedAt": _started_at,
                # Tarpit arrival rate over three windows. Comparing them is the
                # answer to "are they knocking less often than they used to?" —
                # a lifetime average alone can't show a change.
                "TarpitRates": [_tarpit_rate(15), _tarpit_rate(60), _tarpit_rate(1440)],
                # Record counts, so the dashboard can show what is actually
                # accumulating instead of only what it is currently rendering.
                "StoreSizes": {name: len(globals()[name]) for name in _PERSISTED_NAMES},
            }
        )
    # Live cross-worker routing state (token budget + per-method cooldowns) and
    # the rotation proxy's status. Computed outside the lock; imported lazily to
    # avoid an import cycle (routing/rotate import runtime, not diagnostics).
    try:
        import routing

        snapshot["Routing"] = routing.get_state()
    except Exception:
        snapshot["Routing"] = {}
    try:
        import rotate

        snapshot["Rotate"] = {
            "Configured": rotate.is_configured(),
            "Enabled": rotate.is_enabled(),
            "ProxyUrl": rotate.masked_url(),
        }
    except Exception:
        snapshot["Rotate"] = {"Configured": False, "Enabled": False, "ProxyUrl": ""}
    # Live tarpit capacity and the worker fleet. Both read shared files rather
    # than this worker's memory, and both are lazily imported for the same reason
    # as the two above (they import runtime/config, not diagnostics).
    try:
        import tarpit

        snapshot["Tarpit"] = tarpit.get_state()
    except Exception:
        snapshot["Tarpit"] = {}
    try:
        import workers

        snapshot["WorkerFleet"] = workers.get_state()
    except Exception:
        snapshot["WorkerFleet"] = {}
    return snapshot


# --- Persistence ------------------------------------------------------------
# Token full-values are secrets and are intentionally NOT serialized to disk.
_PERSISTED_NAMES = (
    "page_visits",
    "visitor_counts",
    "exploit_attempts",
    "exploit_summary",
    "login_attempts",
    "request_counts",
    "status_code_counts",
    "status_codes_detailed",
    "proxy_request_counts",
    "method_timings",
    "method_stats",
    "token_usage",
    "request_failures",
    "rotate_ips",
    "crawls",
    "throttled_ips",
    "endpoints",
    "blocked_endpoint_attempts",
    "rate_limited_attempts",
    "header_blocked_attempts",
    "retry_counts",
    "reason_counts",
    "live_requests",
    "traffic_minutes",
    "token_budget",
    "token_budget_minutes",
    "pause_drops",
    "throttle_drops",
    "tarpit_stats",
    "tarpit_ips",
    "tarpit_minutes",
    "errors",
    "header_names",
    "user_agents",
    "blocked_header_names",
    "blocked_user_agents",
)

# Pristine copies of every persisted structure, captured at import (before any
# saved data is restored), so "clear" can reset a structure to its true initial
# shape (e.g. request_counts keeps its method keys at 0).
_INITIAL_SHAPES = {name: copy.deepcopy(globals()[name]) for name in _PERSISTED_NAMES}

# ClearEpochs this worker has already applied (name -> epoch timestamp). The
# shared file carries the authoritative ClearEpochs map; every flush applies
# any epochs newer than these before merging, so a "clear" on one worker can
# never be resurrected by another worker's stale in-memory copy.
_applied_clear_epochs = dict()

# The same idea at single-record granularity ("header_names/traceparent"), for
# the per-header Clear buttons on the dashboard. Kept only long enough for every
# worker to have flushed at least once; see _prune_key_clear_epochs.
_applied_key_clear_epochs = dict()
KEY_CLEAR_EPOCH_TTL = 3600  # In seconds; far longer than any autosave interval.
MAX_KEY_CLEAR_EPOCHS = 500

# Section-clear targets exposed to the admin API: target -> structures it wipes.
CLEAR_TARGETS = {
    "probes": ("exploit_attempts", "exploit_summary"),
    "requests": (
        "request_counts",
        "status_code_counts",
        "status_codes_detailed",
        "method_stats",
        "token_usage",
        "retry_counts",
        "reason_counts",
        "traffic_minutes",
        "token_budget",
        "token_budget_minutes",
    ),
    # Proxy timings clear INDEPENDENTLY of the request counters above.
    "proxy_timings": ("proxy_request_counts", "method_timings"),
    "request_failures": ("request_failures",),
    "rotate_ips": ("rotate_ips",),
    "endpoints": ("endpoints",),
    "blocked_attempts": ("blocked_endpoint_attempts",),
    "rate_limited_attempts": ("rate_limited_attempts",),
    "header_blocked_attempts": ("header_blocked_attempts",),
    "pause_drops": ("pause_drops",),
    "throttle_drops": ("throttle_drops",),
    "tarpit": ("tarpit_stats", "tarpit_ips", "tarpit_minutes"),
    "live": ("live_requests",),
    "logins": ("login_attempts",),
    "crawls": ("crawls",),
    "throttled": ("throttled_ips",),
    "visits": ("page_visits", "visitor_counts"),
    "errors": ("errors",),
    "fingerprints": ("header_names", "user_agents"),
    "blocked_fingerprints": ("blocked_header_names", "blocked_user_agents"),
}

# "all" clears every distinct structure exactly once (no cross-clear, no repeats).
CLEAR_ALL_NAMES = tuple(dict.fromkeys(name for names in CLEAR_TARGETS.values() for name in names))


def _reset_name_unlocked(name: str):
    """Reset one persisted structure to its pristine shape, in place."""
    target = globals()[name]
    pristine = copy.deepcopy(_INITIAL_SHAPES[name])
    if isinstance(target, dict):
        target.clear()
        target.update(pristine)
    elif isinstance(target, list):
        target.clear()
        target.extend(pristine)


def clear_stats(names: tuple) -> bool:
    """Manually wipe the given structures everywhere: this worker's memory, the
    shared file, and (via ClearEpochs) every other worker at its next flush.
    Returns False if the file write failed (memory is still cleared locally)."""
    global _baseline
    now = time.time()
    with _state_lock:
        for name in names:
            _reset_name_unlocked(name)
            if isinstance(_baseline, dict):
                _baseline[name] = copy.deepcopy(_INITIAL_SHAPES[name])
            _applied_clear_epochs[name] = now

        def mutate(data):
            diag = data.setdefault("Diagnostics", {})
            if not isinstance(diag, dict):
                diag = data["Diagnostics"] = {}
            epochs = diag.setdefault("ClearEpochs", {})
            for name in names:
                diag[name] = copy.deepcopy(_INITIAL_SHAPES[name])
                epochs[name] = now
            return data

        ok = True
        try:
            storage.update_data(mutate)
        except OSError:
            ok = False
    # The token-inventory ExpiredCount in proxy_health isn't persisted, so reset
    # it here too when the request stats are being cleared (and on "clear all").
    if "request_counts" in names:
        reset_method_counters()
    return ok


def serialize() -> dict:
    g = globals()
    with _state_lock:
        # Deep-copy so callers serialize a stable snapshot.
        return {name: copy.deepcopy(g[name]) for name in _PERSISTED_NAMES}


def restore(data: dict):
    if not isinstance(data, dict):
        return
    g = globals()
    with _state_lock:
        for name in _PERSISTED_NAMES:
            value = data.get(name)
            if value is None:
                continue
            existing = g[name]
            # Merge into the existing container so module-level references stay valid.
            if isinstance(existing, dict) and isinstance(value, dict):
                existing.clear()
                existing.update(value)
            elif isinstance(existing, list) and isinstance(value, list):
                existing.clear()
                existing.extend(value)
        # Adopted data is capped like everything else. Normally a no-op (the
        # merge already trimmed it); it matters on the first boot after an
        # upgrade, when the file on disk predates the caps.
        _trim_all(_local_view())


# --- Cross-worker stat merging ----------------------------------------------
# Counters are additive, so each worker tracks how much it has counted since the
# last flush (the "baseline") and merges only that delta into the shared file.
# Min/Max/Last* fields combine idempotently; recent-event lists union + dedup + cap.
_baseline = None

_MAX_KEYS = {"Max", "LastRequestTime", "LastThrottleTime", "LastSeen", "LastSuccessAt", "LastErrorAt", "LastUsedAt"}
_MIN_KEYS = {"Min", "FirstSeen"}
_LIST_CAP_SETTINGS = {
    "exploit_attempts": ("max_exploit_records", config.MAX_EXPLOIT_RECORDS),
    "login_attempts": ("max_login_records", config.MAX_LOGIN_RECORDS),
    "live_requests": ("max_live_requests", config.MAX_LIVE_REQUESTS),
    "rotate_ips": (None, config.MAX_ROTATE_IPS),
}


def _list_cap(key: str) -> int:
    setting, fallback = _LIST_CAP_SETTINGS.get(key, (None, 50))
    if setting is None:
        return fallback
    return _cap(setting, fallback)


def _merge_list(key, shared_list, local_list):
    """Union two event lists, newest first, deduped, capped.

    Dedupe is by the per-event Id stamped at creation. Falling back to the whole
    record as a signature (as this used to do) silently merges two genuinely
    distinct events that happen to look identical -- two probes from the same IP
    in the same second with the same reason are two probes, not one.
    """
    cap = _list_cap(key)
    combined = list(local_list) + list(shared_list)
    combined.sort(key=lambda item: item.get("Date", 0) if isinstance(item, dict) else 0, reverse=True)
    seen = set()
    out = []
    for item in combined:
        if isinstance(item, dict) and item.get("Id"):
            sig = ("id", item["Id"])
        else:  # Pre-upgrade records have no Id; fall back to the old behaviour.
            sig = ("raw", json.dumps(item, sort_keys=True, separators=(",", ":"), default=str))
        if sig in seen:
            continue
        seen.add(sig)
        out.append(item)
        if cap and len(out) >= cap:
            break
    out.reverse()  # Store oldest-first to match append/pop(0) semantics.
    return out


def _merge_value(key, shared_v, local_v, base_v):
    if isinstance(local_v, dict):
        shared = shared_v if isinstance(shared_v, dict) else {}
        base = base_v if isinstance(base_v, dict) else {}
        merged = copy.deepcopy(shared)
        for k in set(local_v) | set(merged):
            lv = local_v.get(k)
            if lv is None:
                continue  # Key only the shared file has; keep it as-is.
            merged[k] = _merge_value(k, merged.get(k), lv, base.get(k))
        return merged
    if isinstance(local_v, list):
        return _merge_list(key, shared_v if isinstance(shared_v, list) else [], local_v)
    if key in _MAX_KEYS:
        return max(shared_v or 0, local_v or 0)
    if key in _MIN_KEYS:
        candidates = [v for v in (shared_v, local_v) if v]
        return min(candidates) if candidates else 0
    if isinstance(local_v, bool):
        return bool(shared_v) or local_v
    if isinstance(local_v, (int, float)):
        return (shared_v or 0) + (local_v - (base_v or 0))
    return local_v


def _merge_stats(shared: dict, local: dict, base: dict) -> dict:
    merged = copy.deepcopy(shared) if isinstance(shared, dict) else {}
    for name in _PERSISTED_NAMES:
        local_v = local.get(name)
        if local_v is None:
            continue
        merged[name] = _merge_value(name, merged.get(name), local_v, base.get(name))
    # The merge above unions keys, so N workers each holding a different capped
    # set produce a union that is N times the cap. Re-apply every ceiling here or
    # the shared file grows forever -- this is the line that keeps the data file
    # (and therefore each worker's memory) bounded.
    _trim_all(merged)
    return merged


def _flush():
    """Merge this worker's stats into the shared file, then adopt the global totals.

    The entire operation is held under _state_lock — including the file I/O — so no
    request thread can mutate a counter between the snapshot and the readback. Under
    multi-worker `flock` contention the I/O window can be non-trivial, and without
    this an increment landing in that window would be silently overwritten on
    readback (the cause of counters appearing to "not count").
    """
    global _baseline
    with _state_lock:
        local = serialize()
        base = _baseline if _baseline is not None else {name: None for name in _PERSISTED_NAMES}

        def mutate(data):
            shared = data.get("Diagnostics", {})
            if not isinstance(shared, dict):
                shared = {}
            # Apply any clears other workers issued since our last flush BEFORE
            # merging, so our stale in-memory copies can't resurrect wiped data.
            epochs = shared.get("ClearEpochs", {})
            if isinstance(epochs, dict):
                for name, epoch in epochs.items():
                    if name in _PERSISTED_NAMES and float(epoch) > _applied_clear_epochs.get(name, 0.0):
                        _reset_name_unlocked(name)
                        local[name] = copy.deepcopy(_INITIAL_SHAPES[name])
                        base[name] = copy.deepcopy(_INITIAL_SHAPES[name])
                        _applied_clear_epochs[name] = float(epoch)
            # Same, one record at a time (a per-header Clear on the dashboard).
            # Must clear our live store, the snapshot being merged, AND the
            # baseline: leaving the record in any of the three lets the delta
            # arithmetic put it back.
            key_epochs = shared.get("KeyClearEpochs", {})
            if isinstance(key_epochs, dict):
                live = _local_view()
                for marker, epoch in key_epochs.items():
                    if float(epoch or 0) <= _applied_key_clear_epochs.get(marker, 0.0):
                        continue
                    store_name, _, remainder = str(marker).partition("/")
                    if store_name not in _PERSISTED_NAMES or not remainder:
                        continue
                    values_only = remainder.endswith("/Values")
                    key = remainder[: -len("/Values")] if values_only else remainder
                    for container in (live, local, base, shared):
                        _apply_key_clear(container, store_name, key, values_only)
                    _applied_key_clear_epochs[marker] = float(epoch)
                _prune_key_clear_epochs(key_epochs)
            # _merge_stats deep-copies `shared` as its starting point and only
            # overwrites _PERSISTED_NAMES, so both epoch maps carry through.
            data["Diagnostics"] = _merge_stats(shared, local, base)
            return data

        merged = storage.update_data(mutate)
        restore(merged.get("Diagnostics", {}))  # Adopt the combined global totals.
        _baseline = serialize()  # New baseline = what we just adopted.


def _bootstrap():
    """Load persisted stats on import and start the cross-worker autosave flush."""
    global _baseline
    saved = storage.load_data()
    diag = saved.get("Diagnostics", {})
    if isinstance(diag, dict):
        # The loaded data already reflects past clears; adopt their epochs so we
        # don't re-apply them, and so we can't resurrect what they removed.
        epochs = diag.get("ClearEpochs", {})
        if isinstance(epochs, dict):
            _applied_clear_epochs.update({str(k): float(v) for k, v in epochs.items()})
        key_epochs = diag.get("KeyClearEpochs", {})
        if isinstance(key_epochs, dict):
            _applied_key_clear_epochs.update({str(k): float(v) for k, v in key_epochs.items()})
        restore(diag)  # Also re-applies every cap to what was on disk.
    _baseline = serialize()  # Loaded state is the baseline so the first flush only adds new events.
    storage.start_autosave(_flush)


_bootstrap()
