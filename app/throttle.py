"""Per-IP request throttling — shared across ALL gunicorn workers.

Every counter here (per-IP request counts, per-endpoint and global rate-limit
buckets, and admin login-failure windows) lives in a single flock-guarded file,
NOT in per-worker memory. With N workers, per-worker memory would let an IP make
N x the configured limit (each worker counting only the requests it happened to
handle). Backing the counters with one shared file means the 4 workers enforce a
single, correct limit.

Reads that only feed response headers / gate decisions use a lock-free snapshot
(atomic writes make torn reads impossible). The authoritative increments use a
flock'd read-modify-write. Runtime settings are read BEFORE taking the lock so the
critical section never does nested file I/O.
"""

import config
import diagnostics
import runtime
import time
from threading import Thread

from lockfile import LockedJSON

# The shared store. Keys: "Ips", "Endpoint", "Global", "Login" (see module docs).
_store = LockedJSON(lambda: config.THROTTLE_FILE)

MAX_TRACKED_LOGIN_IPS = 10000  # Hard cap so a spoofed-IP flood can't grow this unbounded.


def _ip_entry(ip: str):
    return _store.read().get("Ips", {}).get(ip)


def is_throttled(ip: str) -> bool:
    entry = _ip_entry(ip)
    if not entry:
        return False
    # Self-expiring: once the reset time passes the IP is no longer throttled,
    # even if no request has come in to clear the flag yet.
    return bool(entry.get("Throttled")) and time.time() < float(entry.get("ThrottleResetTime", 0))


def get_requests_left(ip: str) -> int:
    allowed = runtime.get_setting("allowed_requests_per_minute", config.ALLOWED_REQUESTS_PER_MINUTE)
    entry = _ip_entry(ip)
    if entry:
        return max(0, allowed - int(entry.get("Requests", 0)))
    return allowed


def get_throttle_reset_time_left(ip: str) -> int:
    entry = _ip_entry(ip)
    if entry:
        return int(max(0, float(entry.get("ThrottleResetTime", 0)) - time.time()))
    return 0


def headers_snapshot(ip: str) -> dict:
    """All three throttle header values from ONE read (used on every response)."""
    allowed = runtime.get_setting("allowed_requests_per_minute", config.ALLOWED_REQUESTS_PER_MINUTE)
    now = time.time()
    entry = _ip_entry(ip)
    if not entry:
        return {"RequestsLeft": allowed, "ResetIn": 0, "Throttled": False}
    return {
        "RequestsLeft": max(0, allowed - int(entry.get("Requests", 0))),
        "ResetIn": int(max(0, float(entry.get("ThrottleResetTime", 0)) - now)),
        "Throttled": bool(entry.get("Throttled")) and now < float(entry.get("ThrottleResetTime", 0)),
    }


def reset_throttle(ip: str):
    duration = runtime.get_setting("throttle_reset_duration", config.THROTTLE_RESET_DURATION)
    now = time.time()

    def mutate(data):
        entry = data.setdefault("Ips", {}).get(ip)
        if entry:
            entry["Throttled"] = 0
            entry["Requests"] = 0
            entry["ThrottleResetTime"] = now + duration

    _store.update(mutate)


def check_global_throttle(ip: str) -> tuple[bool, int]:
    """Enforce the global throttle-all rate limit for one IP (shared across workers).

    Each IP may make `global_throttle_limit` requests per `global_throttle_period`
    seconds (both admin-configurable). Counts the request when allowed.
    Returns (allowed, seconds_until_reset).
    """
    limit = int(runtime.get_setting("global_throttle_limit", config.GLOBAL_THROTTLE_LIMIT))
    period = int(runtime.get_setting("global_throttle_period", config.GLOBAL_THROTTLE_PERIOD))
    now = time.time()

    def mutate(data):
        buckets = data.setdefault("Global", {})
        bucket = buckets.get(ip)
        if not bucket or now > bucket["ResetTime"]:
            bucket = dict(Count=0, ResetTime=now + period)
            buckets[ip] = bucket
        if bucket["Count"] >= limit:
            return (False, int(max(0, bucket["ResetTime"] - now)))
        bucket["Count"] += 1
        _cap_buckets(buckets)
        return (True, 0)

    return _store.update(mutate)


def check_endpoint_limit(ip: str, path: str) -> tuple[bool, int, str | None]:
    """Enforce a per-(IP, endpoint) rate rule, if one matches the path (shared).

    Counts the request when allowed. Returns (allowed, seconds_until_reset, pattern).
    The effective limit is clamped to the global per-IP limit, so an endpoint rule
    can only ever make access MORE restrictive — never bypass the max.
    """
    rule = runtime.match_endpoint_rule(path)  # resolved before the lock (no nested I/O)
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

    def mutate(data):
        buckets = data.setdefault("Endpoint", {})
        bucket = buckets.get(key)
        if not bucket or now > bucket["ResetTime"]:
            bucket = dict(Count=0, ResetTime=now + period)
            buckets[key] = bucket
        if bucket["Count"] >= limit:
            return (False, int(max(0, bucket["ResetTime"] - now)), pattern)
        bucket["Count"] += 1
        _cap_buckets(buckets)
        return (True, 0, pattern)

    return _store.update(mutate)


def _cap_buckets(buckets: dict):
    """Bound a bucket dict so a spoofed-IP flood can't grow the file unbounded."""
    if len(buckets) > config.MAX_TRACKED_THROTTLE_IPS:
        oldest = min(buckets.items(), key=lambda kv: kv[1].get("ResetTime", 0))[0]
        buckets.pop(oldest, None)


def update_throttling(ip, made_request: bool = False):
    now = time.time()
    allowed = runtime.get_setting("allowed_requests_per_minute", config.ALLOWED_REQUESTS_PER_MINUTE)
    throttle_reset_duration = runtime.get_setting("throttle_reset_duration", config.THROTTLE_RESET_DURATION)
    stale_ip_duration = runtime.get_setting("stale_ip_duration", config.STALE_IP_DURATION)

    def mutate(data):
        ips = data.setdefault("Ips", {})
        entry = ips.get(ip)
        if entry:
            if entry.get("Throttled"):
                if now > entry["ThrottleResetTime"]:
                    entry["Throttled"] = 0
                    entry["Requests"] = 0
                    entry["ThrottleResetTime"] = now + throttle_reset_duration
                else:
                    return False  # still throttled; nothing to count
            if now > entry["LastRequestTime"] + stale_ip_duration:
                ips.pop(ip, None)
                if not made_request:
                    return False
                entry = None  # stale entry dropped; recreate below
        if entry:
            if now > entry["ThrottleResetTime"]:
                entry["Throttled"] = 0
                entry["Requests"] = 0
                entry["ThrottleResetTime"] = now + throttle_reset_duration
            if made_request:
                entry["Requests"] += 1
                entry["ThrottleResetTime"] += 1
                entry["LastRequestTime"] = now
            if entry["Requests"] > allowed:
                entry["Throttled"] = 1
                return True  # just throttled
        else:
            if len(ips) >= config.MAX_TRACKED_THROTTLE_IPS:
                oldest = min(ips.items(), key=lambda kv: kv[1].get("LastRequestTime", 0))[0]
                ips.pop(oldest, None)
            ips[ip] = dict(
                Requests=1 if made_request else 0,
                Throttled=0,
                LastRequestTime=now,
                ThrottleResetTime=now + throttle_reset_duration,
            )
        return False

    just_throttled = _store.update(mutate)
    # Log outside the lock; diagnostics takes its own lock + flushes to a different file.
    if just_throttled:
        diagnostics.log_throttle(ip)


# --- Admin login lockout (now shared across workers too) ----------------------
def register_login_failure(ip: str):
    now = time.time()

    def mutate(data):
        failures = data.setdefault("Login", {})
        entry = failures.get(ip)
        if not entry or now - entry["WindowStart"] > config.LOGIN_FAILURE_WINDOW:
            if len(failures) >= MAX_TRACKED_LOGIN_IPS:
                oldest = min(failures.items(), key=lambda kv: kv[1]["WindowStart"])[0]
                failures.pop(oldest, None)
            failures[ip] = dict(Count=1, WindowStart=now)
        else:
            entry["Count"] += 1

    _store.update(mutate)


def is_login_blocked(ip: str) -> tuple[bool, int]:
    """Whether this IP has burned its login attempts. Returns (blocked, seconds_until_retry)."""
    now = time.time()
    entry = _store.read().get("Login", {}).get(ip)
    if not entry:
        return False, 0
    if now - entry["WindowStart"] > config.LOGIN_FAILURE_WINDOW:
        return False, 0  # expired; the cleanup loop will drop it
    if entry["Count"] >= config.MAX_LOGIN_FAILURES:
        return True, int(max(1, entry["WindowStart"] + config.LOGIN_FAILURE_WINDOW - now))
    return False, 0


def reset_login_failures(ip: str):
    _store.update(lambda data: data.get("Login", {}).pop(ip, None))


# --- Cleanup loop ---------------------------------------------------------------
# One flock'd pass that prunes stale/expired entries so the shared file stays
# small. Expiry of the throttle itself is lazy (handled on read/next request), so
# this loop is only about bounding memory — it can run infrequently.
def _prune_once():
    stale_ip_duration = runtime.get_setting("stale_ip_duration", config.STALE_IP_DURATION)
    now = time.time()

    def mutate(data):
        ips = data.get("Ips", {})
        for ip in [i for i, e in ips.items() if now > e.get("LastRequestTime", 0) + stale_ip_duration]:
            ips.pop(ip, None)
        endpoint = data.get("Endpoint", {})
        for key in [k for k, b in endpoint.items() if now > b.get("ResetTime", 0) + 60]:
            endpoint.pop(key, None)
        glob = data.get("Global", {})
        for ip in [i for i, b in glob.items() if now > b.get("ResetTime", 0) + 60]:
            glob.pop(ip, None)
        login = data.get("Login", {})
        for ip in [i for i, e in login.items() if now - e.get("WindowStart", 0) > config.LOGIN_FAILURE_WINDOW]:
            login.pop(ip, None)

    _store.update(mutate)


def run_throttle_loop():
    while True:
        time.sleep(30)  # Infrequent: expiry is lazy; this only bounds file size.
        try:
            _prune_once()
        except Exception:
            pass  # The cleanup loop must never die.


Thread(target=run_throttle_loop, daemon=True).start()
