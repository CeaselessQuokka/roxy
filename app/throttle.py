import diagnostics
import runtime
import time
from threading import Thread

throttled_ips = dict(
    {
        # [IP]: {Requests: int, Throttled: bool, ThrottleResetTime: float, LastRequestTime: float},
    }
)

# Per-(IP, endpoint) rate limiting for endpoints that have a runtime rule set.
endpoint_buckets = dict(
    {
        # "ip|pattern": {Count: int, ResetTime: float},
    }
)


def is_throttled(ip: str) -> bool:
    global throttled_ips
    throttled_ip = throttled_ips.get(ip, None)
    return throttled_ip and throttled_ip["Throttled"]


def get_requests_left(ip: str) -> int:
    global throttled_ips
    allowed = runtime.get_setting("allowed_requests_per_minute")
    throttled_ip = throttled_ips.get(ip, None)
    if throttled_ip:
        return max(0, allowed - throttled_ip["Requests"])
    return allowed


def get_throttle_reset_time_left(ip: str) -> int:
    global throttled_ips
    throttled_ip = throttled_ips.get(ip, None)
    if throttled_ip:
        return int(max(0, throttled_ip["ThrottleResetTime"] - time.time()))
    return 0


def reset_throttle(ip: str):
    global throttled_ips
    if ip in throttled_ips:
        throttled_ips[ip]["Throttled"] = False
        throttled_ips[ip]["Requests"] = 0
        throttled_ips[ip]["ThrottleResetTime"] = time.time() + runtime.get_setting("throttle_reset_duration")


def check_endpoint_limit(ip: str, path: str) -> tuple[bool, int]:
    """Enforce a per-(IP, endpoint) rate rule, if one matches the path.

    Counts the request when allowed. Returns (allowed, seconds_until_reset).
    The effective limit is clamped to the global per-IP limit, so an endpoint
    rule can only ever make access MORE restrictive — never bypass the max.
    """
    global endpoint_buckets
    rule = runtime.match_endpoint_rule(path)
    if not rule:
        return True, 0
    pattern = rule["Pattern"]
    limit = int(rule.get("Limit", 1))
    period = int(rule.get("Period", 60))
    global_allowed = runtime.get_setting("allowed_requests_per_minute")
    if global_allowed:
        limit = min(limit, global_allowed)

    now = time.time()
    key = f"{ip}|{pattern}"
    bucket = endpoint_buckets.get(key)
    if not bucket or now > bucket["ResetTime"]:
        bucket = dict(Count=0, ResetTime=now + period)
        endpoint_buckets[key] = bucket
    if bucket["Count"] >= limit:
        return False, int(max(0, bucket["ResetTime"] - now))
    bucket["Count"] += 1
    return True, 0


def update_throttling(ip, made_request: bool = False):
    global throttled_ips
    now = time.time()
    allowed = runtime.get_setting("allowed_requests_per_minute")
    throttle_reset_duration = runtime.get_setting("throttle_reset_duration")
    stale_ip_duration = runtime.get_setting("stale_ip_duration")
    throttled_ip = throttled_ips.get(ip, None)
    if throttled_ip:
        if throttled_ip["Throttled"]:
            return
        if now > throttled_ip["LastRequestTime"] + stale_ip_duration:
            throttled_ips.pop(ip, None)
            return

        if now > throttled_ip["ThrottleResetTime"]:
            throttled_ip["Throttled"] = False
            throttled_ip["Requests"] = 0
            throttled_ip["ThrottleResetTime"] = now + throttle_reset_duration
        if made_request:
            throttled_ip["Requests"] += 1
            throttled_ip["ThrottleResetTime"] += 1
            throttled_ip["LastRequestTime"] = now
        if throttled_ip["Requests"] > allowed:
            throttled_ip["Throttled"] = True
            diagnostics.log_throttle(ip)
    else:
        throttled_ips[ip] = dict(
            Requests=1 if made_request else 0,
            Throttled=False,
            LastRequestTime=now,
            ThrottleResetTime=now + throttle_reset_duration,
        )


def run_throttle_loop():
    global throttled_ips, endpoint_buckets
    while True:
        ips = list(throttled_ips.keys())
        for ip in ips:
            update_throttling(ip)
        # Drop expired per-endpoint buckets so memory doesn't grow unbounded.
        now = time.time()
        for key in [k for k, b in list(endpoint_buckets.items()) if now > b["ResetTime"] + 60]:
            endpoint_buckets.pop(key, None)
        time.sleep(1)


Thread(target=run_throttle_loop).start()
