import config
import copy
import time

import storage

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
        "DirectAPI": dict({"Count": 0, "LastRequestTime": 0, "IsInCooldown": False}),  # Count = nRequests.
        "RoProxy": dict({"Count": 0, "LastRequestTime": 0, "IsInCooldown": False}),  # Count = nRequests.
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


def _is_crawler(user_agent: str) -> bool:
    ua = (user_agent or "").lower()
    if not ua:
        return True  # No User-Agent is itself a strong bot signal.
    return any(marker in ua for marker in config.CRAWLER_USER_AGENT_MARKERS)



def log_page_visit(page: str):
    global page_visits
    if page in page_visits:
        page_visits[page] += 1
    else:
        page_visits[page] = 1


def log_visitor(user_agent: str):
    """Classify a page visitor as likely-human or likely-crawler."""
    if _is_crawler(user_agent):
        visitor_counts["Crawler"] += 1
    else:
        visitor_counts["Human"] += 1


def decrement_admin_visit():
    """Subtract one admin page visit (used after a successful login to discount self-visits)."""
    page_visits["admin"] = max(0, page_visits.get("admin", 0) - 1)



def log_throttle(ip: str):
    global throttled_ips
    now = time.time()
    if ip in throttled_ips:
        throttled_ips[ip]["Count"] += 1
        throttled_ips[ip]["LastThrottleTime"] = now
    else:
        throttled_ips[ip] = dict(LastThrottleTime=now, Count=1)
    if len(throttled_ips) > config.MAX_THROTTLE_RECORDS:
        oldest_ip = min(throttled_ips.items(), key=lambda x: x[1]["LastThrottleTime"])[0]
        throttled_ips.pop(oldest_ip, None)


def log_crawl(ip: str):
    global crawls
    now = time.time()
    if ip in crawls:
        crawls[ip]["Count"] += 1
        crawls[ip]["LastRequestTime"] = now
    else:
        crawls[ip] = dict(LastRequestTime=now, Count=1)
    if len(crawls) > config.MAX_CRAWL_RECORDS:
        oldest_ip = min(crawls.items(), key=lambda x: x[1]["LastRequestTime"])[0]
        crawls.pop(oldest_ip, None)


def log_exploit_attempt(ip: str, reason: str, user_agent: str):
    exploit_attempts.append(dict(IP=ip, Date=time.time(), Reason=reason, UserAgent=user_agent))
    if len(exploit_attempts) > config.MAX_EXPLOIT_RECORDS:
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
    """Record which Roblox endpoint was requested, keeping the most-frequent ones."""
    # Strip query string and normalize so similar paths group together.
    path = (path or "").split("?", 1)[0].strip("/")
    if not path:
        return
    record = endpoints.get(path)
    if record:
        record["Count"] += 1
        record["LastRequestTime"] = time.time()
        record["Methods"][method] = record["Methods"].get(method, 0) + 1
    else:
        if len(endpoints) >= config.MAX_ENDPOINT_RECORDS:
            # Evict the least-frequent endpoint to make room.
            least = min(endpoints.items(), key=lambda kv: kv[1]["Count"])[0]
            endpoints.pop(least, None)
        endpoints[path] = dict(Count=1, LastRequestTime=time.time(), Methods={method: 1})


def log_retry(status_code: int, reason: str = ""):
    """Record that a proxied request was retried, with the triggering status/reason."""
    retry_counts["Total"] += 1
    code = str(status_code)
    retry_counts["ByStatusCode"][code] = retry_counts["ByStatusCode"].get(code, 0) + 1
    if reason:
        retry_counts["Reasons"][reason] = retry_counts["Reasons"].get(reason, 0) + 1


def log_reason(is_custom: bool):
    """Record whether a returned error reason was our own message or Roblox's passthrough."""
    if is_custom:
        reason_counts["Custom"] += 1
    else:
        reason_counts["Roblox"] += 1


def log_live_request(entry: dict):
    """Append a recent request to the live feed ring buffer."""
    live_requests.append(entry)
    while len(live_requests) > config.MAX_LIVE_REQUESTS:
        live_requests.pop(0)


def log_login_attempt(ip: str, successful: bool):
    login_attempts.append(dict(IP=ip, Date=time.time(), Successful=successful))
    if len(login_attempts) > config.MAX_LOGIN_RECORDS:
        login_attempts.pop(0)


def log_request(method: str, successful: bool):
    if method in request_counts:
        if successful:
            request_counts[method]["Successful"] += 1
        else:
            request_counts[method]["Failed"] += 1


def log_status_code(status_code: int):
    if 200 <= status_code < 300:
        status_code_counts["2xx"] += 1
    elif 400 <= status_code < 500:
        status_code_counts["4xx"] += 1
    # Detailed per-code breakdown (covers 1xx/3xx/5xx too).
    code = str(status_code)
    status_codes_detailed[code] = status_codes_detailed.get(code, 0) + 1


def log_proxy_request(method: str, duration: float):
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


def get_diagnostics() -> dict:
    global tokens
    return dict(
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
            "RetryCounts": retry_counts,
            "ReasonCounts": reason_counts,
            "LiveRequests": list(reversed(live_requests)),  # Most-recent first.
            "Tokens": copy.deepcopy(list(tokens.values())),
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
    "retry_counts",
    "reason_counts",
    "live_requests",
)


def serialize() -> dict:
    g = globals()
    # Deep-copy so the autosave thread serializes a stable snapshot.
    return {name: copy.deepcopy(g[name]) for name in _PERSISTED_NAMES}


def restore(data: dict):
    if not isinstance(data, dict):
        return
    g = globals()
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


def _bootstrap():
    """Load persisted diagnostics + runtime state on import and start autosaving."""
    import runtime  # Imported here to avoid an import cycle at module load.

    saved = storage.load_data()
    restore(saved.get("Diagnostics", {}))
    runtime.restore(saved.get("Runtime", {}))
    storage.start_autosave(lambda: {"Diagnostics": serialize(), "Runtime": runtime.serialize()})


_bootstrap()
