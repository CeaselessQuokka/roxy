import config
import diagnostics
import runtime
import time
from threading import Lock, Thread

# Guards every read-modify-write of the dicts below; request threads and the
# cleanup loop touch them concurrently.
_lock = Lock()

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

# Failed admin-login attempts per IP (credentials or 2FA), for temporary lockout.
login_failures = dict(
    {
        # [IP]: {Count: int, WindowStart: float},
    }
)
MAX_TRACKED_LOGIN_IPS = 10000  # Hard cap so a spoofed-IP flood can't grow this unbounded.


def is_throttled(ip: str) -> bool:
    with _lock:
        throttled_ip = throttled_ips.get(ip, None)
        return bool(throttled_ip and throttled_ip["Throttled"])


def get_requests_left(ip: str) -> int:
    allowed = runtime.get_setting("allowed_requests_per_minute", config.ALLOWED_REQUESTS_PER_MINUTE)
    with _lock:
        throttled_ip = throttled_ips.get(ip, None)
        if throttled_ip:
            return max(0, allowed - throttled_ip["Requests"])
        return allowed


def get_throttle_reset_time_left(ip: str) -> int:
    with _lock:
        throttled_ip = throttled_ips.get(ip, None)
        if throttled_ip:
            return int(max(0, throttled_ip["ThrottleResetTime"] - time.time()))
        return 0


def reset_throttle(ip: str):
    duration = runtime.get_setting("throttle_reset_duration", config.THROTTLE_RESET_DURATION)
    with _lock:
        if ip in throttled_ips:
            throttled_ips[ip]["Throttled"] = False
            throttled_ips[ip]["Requests"] = 0
            throttled_ips[ip]["ThrottleResetTime"] = time.time() + duration


def check_endpoint_limit(ip: str, path: str) -> tuple[bool, int, str | None]:
    """Enforce a per-(IP, endpoint) rate rule, if one matches the path.

    Counts the request when allowed. Returns (allowed, seconds_until_reset, pattern).
    `pattern` is the matched rule pattern (or None when no rule applies), so the
    caller can record which rule rejected the request.
    The effective limit is clamped to the global per-IP limit, so an endpoint
    rule can only ever make access MORE restrictive — never bypass the max.
    """
    rule = runtime.match_endpoint_rule(path)
    if not rule:
        return True, 0, None
    pattern = rule["Pattern"]
    limit = int(rule.get("Limit", 1))
    period = int(rule.get("Period", 60))
    global_allowed = runtime.get_setting("allowed_requests_per_minute", config.ALLOWED_REQUESTS_PER_MINUTE)
    if global_allowed:
        limit = min(limit, global_allowed)

    now = time.time()
    key = f"{ip}|{pattern}"
    with _lock:
        bucket = endpoint_buckets.get(key)
        if not bucket or now > bucket["ResetTime"]:
            bucket = dict(Count=0, ResetTime=now + period)
            endpoint_buckets[key] = bucket
        if bucket["Count"] >= limit:
            return False, int(max(0, bucket["ResetTime"] - now)), pattern
        bucket["Count"] += 1
    return True, 0, pattern


def update_throttling(ip, made_request: bool = False):
    now = time.time()
    allowed = runtime.get_setting("allowed_requests_per_minute", config.ALLOWED_REQUESTS_PER_MINUTE)
    throttle_reset_duration = runtime.get_setting("throttle_reset_duration", config.THROTTLE_RESET_DURATION)
    stale_ip_duration = runtime.get_setting("stale_ip_duration", config.STALE_IP_DURATION)
    just_throttled = False
    with _lock:
        throttled_ip = throttled_ips.get(ip, None)
        if throttled_ip:
            if throttled_ip["Throttled"]:
                if now > throttled_ip["ThrottleResetTime"]:
                    throttled_ip["Throttled"] = False
                    throttled_ip["Requests"] = 0
                    throttled_ip["ThrottleResetTime"] = now + throttle_reset_duration
                else:
                    return
            if now > throttled_ip["LastRequestTime"] + stale_ip_duration:
                throttled_ips.pop(ip, None)
                if not made_request:
                    return
                throttled_ip = None  # Stale entry dropped; fall through and recreate below.

        if throttled_ip:
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
                just_throttled = True
        else:
            throttled_ips[ip] = dict(
                Requests=1 if made_request else 0,
                Throttled=False,
                LastRequestTime=now,
                ThrottleResetTime=now + throttle_reset_duration,
            )
    # Log outside the lock; diagnostics takes its own lock.
    if just_throttled:
        diagnostics.log_throttle(ip)


# --- Admin login lockout ------------------------------------------------------
# Tracked per worker (not shared): with N workers an attacker gets at most
# N * MAX_LOGIN_FAILURES tries per window, which is still a handful.
def register_login_failure(ip: str):
    now = time.time()
    with _lock:
        entry = login_failures.get(ip)
        if not entry or now - entry["WindowStart"] > config.LOGIN_FAILURE_WINDOW:
            if len(login_failures) >= MAX_TRACKED_LOGIN_IPS:
                oldest = min(login_failures.items(), key=lambda kv: kv[1]["WindowStart"])[0]
                login_failures.pop(oldest, None)
            login_failures[ip] = dict(Count=1, WindowStart=now)
        else:
            entry["Count"] += 1


def is_login_blocked(ip: str) -> tuple[bool, int]:
    """Whether this IP has burned its login attempts. Returns (blocked, seconds_until_retry)."""
    now = time.time()
    with _lock:
        entry = login_failures.get(ip)
        if not entry:
            return False, 0
        if now - entry["WindowStart"] > config.LOGIN_FAILURE_WINDOW:
            login_failures.pop(ip, None)
            return False, 0
        if entry["Count"] >= config.MAX_LOGIN_FAILURES:
            return True, int(max(1, entry["WindowStart"] + config.LOGIN_FAILURE_WINDOW - now))
        return False, 0


def reset_login_failures(ip: str):
    with _lock:
        login_failures.pop(ip, None)


# --- Cleanup loop ---------------------------------------------------------------
def run_throttle_loop():
    while True:
        try:
            with _lock:
                ips = list(throttled_ips.keys())
            for ip in ips:
                update_throttling(ip)
            now = time.time()
            with _lock:
                # Drop expired per-endpoint buckets so memory doesn't grow unbounded.
                for key in [k for k, b in endpoint_buckets.items() if now > b["ResetTime"] + 60]:
                    endpoint_buckets.pop(key, None)
                # Drop login-failure windows that have lapsed.
                for ip in [
                    i for i, e in login_failures.items() if now - e["WindowStart"] > config.LOGIN_FAILURE_WINDOW
                ]:
                    login_failures.pop(ip, None)
        except Exception:
            pass  # The cleanup loop must never die.
        time.sleep(1)


Thread(target=run_throttle_loop, daemon=True).start()
