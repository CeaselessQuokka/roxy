import config
import copy
import json
import re
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

proxy_request_counts = dict(
    {
        "GET": dict({"TotalTime": 0, "Count": 0, "Min": 0, "Max": 0, "LastRequestTime": 0}),  # Count = nRequests.
        "POST": dict({"TotalTime": 0, "Count": 0, "Min": 0, "Max": 0, "LastRequestTime": 0}),  # Count = nRequests.
        "PATCH": dict({"TotalTime": 0, "Count": 0, "Min": 0, "Max": 0, "LastRequestTime": 0}),  # Count = nRequests.
        "PUT": dict({"TotalTime": 0, "Count": 0, "Min": 0, "Max": 0, "LastRequestTime": 0}),  # Count = nRequests.
        "DELETE": dict({"TotalTime": 0, "Count": 0, "Min": 0, "Max": 0, "LastRequestTime": 0}),  # Count = nRequests.
    }
)

proxy_health = dict(
    {
        # Count = nRequests; Failed = nNon-200 responses from that route.
        "DirectAPI": dict({"Count": 0, "Failed": 0, "LastRequestTime": 0, "IsInCooldown": False}),
        "RoProxy": dict({"Count": 0, "Failed": 0, "LastRequestTime": 0, "IsInCooldown": False}),
        "Tokens": dict({"Count": 0, "ExpiredCount": 0, "BeingValidatedCount": 0}),  # Count = nTokens.
    }
)

tokens = dict(
    {
        # [full_token]: {Masked: str, BeingValidated: bool, Uses: int}
    }
)

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

# Per-minute PEAK of the token's sliding-window usage:
# {"<epoch_minute>": {"Max": peak_usage}}. "Max" leaf so cross-worker merges take
# the max, not a sum. Used to report the worst budget pressure over 1h / 24h.
token_budget_minutes = dict()

# When this worker process started (not persisted; for the dashboard uptime card).
_started_at = time.time()


def _cap(setting_name: str, fallback: int) -> int:
    """A runtime-tunable record cap. NOTE: 0 is a valid configured value (it
    disables the record type), so this must not use `or fallback`."""
    value = runtime.get_setting(setting_name)
    return fallback if value is None else value


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
        exploit_attempts.append(dict(IP=ip, Date=time.time(), Reason=reason, UserAgent=user_agent))
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


def log_endpoint(path: str, method: str):
    """Record which Roblox endpoint was requested, keeping the most-frequent ones.

    Paths are grouped under an ID-collapsed template so volatile IDs don't blow
    up cardinality; the real paths seen under each template are kept (capped) so
    the dashboard can drill into the specific IDs on demand.
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
            else:
                if len(concrete) >= MAX_CONCRETE_PER_TEMPLATE:
                    least = min(concrete.items(), key=lambda kv: kv[1]["Count"])[0]
                    concrete.pop(least, None)
                concrete[path] = dict(Count=1, LastRequestTime=now, Methods={method: 1})


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
            if len(record["IPs"]) > 50:  # Keep only the busiest IPs per endpoint.
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
    with _state_lock:
        record = header_blocked_attempts.get(rule_id)
        if record:
            record["Count"] += 1
            record["LastRequestTime"] = now
            record["LastIP"] = ip
            record["LastHeader"] = rule.get("MatchedHeader", "")
            record["LastPath"] = path
            record["Methods"][method] = record["Methods"].get(method, 0) + 1
            record["IPs"][ip] = record["IPs"].get(ip, 0) + 1
            if len(record["IPs"]) > 50:
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
                LastHeader=rule.get("MatchedHeader", ""),
                LastPath=path,
                Methods={method: 1},
                IPs={ip: 1},
            )


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


def log_route_result(is_roproxy: bool, success: bool):
    """Count a Direct-API or RoProxy call and whether it failed (non-200)."""
    route = "RoProxy" if is_roproxy else "DirectAPI"
    with _state_lock:
        proxy_health[route]["Count"] = proxy_health[route].get("Count", 0) + 1
        proxy_health[route]["LastRequestTime"] = time.time()
        if not success:
            proxy_health[route]["Failed"] = proxy_health[route].get("Failed", 0) + 1


def log_retry(status_code: int, reason: str = ""):
    """Record that a proxied request was retried, with the triggering status/reason."""
    with _state_lock:
        retry_counts["Total"] += 1
        code = str(status_code)
        retry_counts["ByStatusCode"][code] = retry_counts["ByStatusCode"].get(code, 0) + 1
        if reason:
            retry_counts["Reasons"][reason] = retry_counts["Reasons"].get(reason, 0) + 1


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
        live_requests.append(entry)
        while len(live_requests) > cap:
            live_requests.pop(0)


def log_login_attempt(ip: str, successful: bool):
    cap = _cap("max_login_records", config.MAX_LOGIN_RECORDS)
    with _state_lock:
        login_attempts.append(dict(IP=ip, Date=time.time(), Successful=successful))
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


def log_status_code(status_code: int):
    with _state_lock:
        if 200 <= status_code < 300:
            status_code_counts["2xx"] += 1
        elif 400 <= status_code < 500:
            status_code_counts["4xx"] += 1
        # Detailed per-code breakdown (covers 1xx/3xx/5xx too).
        code = str(status_code)
        status_codes_detailed[code] = status_codes_detailed.get(code, 0) + 1


def log_proxy_request(method: str, duration: float):
    with _state_lock:
        if method in proxy_request_counts:
            proxy_request_counts[method]["TotalTime"] += duration
            proxy_request_counts[method]["Count"] += 1
            proxy_request_counts[method]["LastRequestTime"] = time.time()
            if duration < proxy_request_counts[method]["Min"] or proxy_request_counts[method]["Min"] == 0:
                proxy_request_counts[method]["Min"] = duration
            if duration > proxy_request_counts[method]["Max"]:
                proxy_request_counts[method]["Max"] = duration


def update_token(token: str, being_validated: bool = False, used: bool = False):
    global tokens
    masked = f"...{token[-20:]}"
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


def get_diagnostics() -> dict:
    global tokens
    # Push this worker's pending stats into the shared file and adopt the merged
    # global totals, so the dashboard shows the true aggregate across all gunicorn
    # workers (not just the slice this worker happened to handle).
    try:
        _flush()
    except Exception:
        pass  # If persistence is briefly unavailable, fall back to local memory.
    with _state_lock:
        # Deep-copy the whole snapshot under the lock so no other thread can
        # mutate a structure while Flask iterates it during JSON serialization.
        return copy.deepcopy(
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
                "ProxyHealth": proxy_health,
                "Crawls": crawls,
                "Endpoints": endpoints,
                "BlockedEndpointAttempts": blocked_endpoint_attempts,
                "RateLimitedAttempts": rate_limited_attempts,
                "HeaderBlockedAttempts": header_blocked_attempts,
                "RetryCounts": retry_counts,
                "ReasonCounts": reason_counts,
                "LiveRequests": list(reversed(live_requests)),  # Most-recent first.
                "Tokens": list(tokens.values()),
                "TrafficMinutes": traffic_minutes,
                "TokenBudgetRejections": token_budget.get("Rejections", 0),
                "BudgetPeak1h": _budget_peak_since(60),
                "BudgetPeak24h": _budget_peak_since(1440),
                "ServerTime": time.time(),
                "WorkerStartedAt": _started_at,
            }
        )


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

# Section-clear targets exposed to the admin API: target -> structures it wipes.
CLEAR_TARGETS = {
    "probes": ("exploit_attempts", "exploit_summary"),
    "requests": (
        "request_counts",
        "status_code_counts",
        "status_codes_detailed",
        "proxy_request_counts",
        "retry_counts",
        "reason_counts",
        "traffic_minutes",
        "token_budget",
        "token_budget_minutes",
    ),
    "endpoints": ("endpoints",),
    "blocked_attempts": ("blocked_endpoint_attempts",),
    "rate_limited_attempts": ("rate_limited_attempts",),
    "header_blocked_attempts": ("header_blocked_attempts",),
    "live": ("live_requests",),
    "logins": ("login_attempts",),
    "crawls": ("crawls",),
    "throttled": ("throttled_ips",),
    "visits": ("page_visits", "visitor_counts"),
}


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

        try:
            storage.update_data(mutate)
            return True
        except OSError:
            return False


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


# --- Cross-worker stat merging ----------------------------------------------
# Counters are additive, so each worker tracks how much it has counted since the
# last flush (the "baseline") and merges only that delta into the shared file.
# Min/Max/Last* fields combine idempotently; recent-event lists union + dedup + cap.
_baseline = None

_MAX_KEYS = {"Max", "LastRequestTime", "LastThrottleTime", "LastSeen"}
_MIN_KEYS = {"Min"}
_LIST_CAP_SETTINGS = {
    "exploit_attempts": ("max_exploit_records", config.MAX_EXPLOIT_RECORDS),
    "login_attempts": ("max_login_records", config.MAX_LOGIN_RECORDS),
    "live_requests": ("max_live_requests", config.MAX_LIVE_REQUESTS),
}


def _list_cap(key: str) -> int:
    setting, fallback = _LIST_CAP_SETTINGS.get(key, (None, 50))
    if setting is None:
        return fallback
    return _cap(setting, fallback)


def _merge_list(key, shared_list, local_list):
    cap = _list_cap(key)
    combined = list(local_list) + list(shared_list)
    combined.sort(key=lambda item: item.get("Date", 0) if isinstance(item, dict) else 0, reverse=True)
    seen = set()
    out = []
    for item in combined:
        sig = json.dumps(item, sort_keys=True, separators=(",", ":"), default=str)
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
            data["Diagnostics"] = _merge_stats(shared, local, base)
            # Old minute buckets only the file still has would otherwise live forever.
            merged_traffic = data["Diagnostics"].get("traffic_minutes")
            if isinstance(merged_traffic, dict):
                _prune_traffic_unlocked(merged_traffic)
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
        # The loaded data already reflects past clears; adopt their epochs.
        epochs = diag.get("ClearEpochs", {})
        if isinstance(epochs, dict):
            _applied_clear_epochs.update({str(k): float(v) for k, v in epochs.items()})
        restore(diag)
    _baseline = serialize()  # Loaded state is the baseline so the first flush only adds new events.
    storage.start_autosave(_flush)


_bootstrap()
