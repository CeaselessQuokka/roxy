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


def effective_strikes(entry: dict, now: float, decay: float) -> int:
    """How many strikes an IP still carries, after good behavior has worn some off.

    Decay is applied on READ rather than by a sweep: a caller who went quiet for
    an hour has served their time whether or not a background job happened to
    notice, and computing it here means the number the dashboard shows and the
    number the next throttle uses can never disagree.
    """
    strikes = int(entry.get("Strikes", 0) or 0)
    if strikes <= 0:
        return 0
    last = float(entry.get("LastStrikeAt", 0) or 0)
    if not decay or not last:
        return strikes
    return max(0, strikes - int(max(0.0, now - last) // decay))


def get_throttle_state(ip: str) -> dict:
    """Everything the refusal needs to know about this IP's standing.

    One read for the whole picture — how long they are out, which rung of the
    ladder they are on, and what that rung says to tell them.
    """
    decay = runtime.get_setting("throttle_strike_decay_seconds", config.THROTTLE_STRIKE_DECAY)
    now = time.time()
    entry = _ip_entry(ip) or {}
    strikes = effective_strikes(entry, now, decay)
    reset_in = int(max(0, float(entry.get("ThrottleResetTime", 0) or 0) - now))
    throttled = bool(entry.get("Throttled")) and reset_in > 0
    # Rung 1 is what a first-time offender is told, so an IP with no strikes yet
    # still has a message to be given if something else refuses it.
    tier = runtime.throttle_tier_for(max(1, strikes))
    return {
        "Throttled": throttled,
        "ResetIn": reset_in,
        "Strikes": strikes,
        "Tier": tier.get("Index", 0),
        "Message": tier.get("Message", ""),
        "Multiplier": float(tier.get("Multiplier", 1.0) or 1.0),
        "LastStrikeAt": float(entry.get("LastStrikeAt", 0) or 0),
    }


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


def clear_strikes(ip: str = None) -> int:
    """Wipe the escalation history for one IP, or for everyone.

    The admin's undo. Escalation is deliberately sticky, so there has to be a
    way to say "that was me load-testing" without waiting out the decay.
    Returns how many IPs were forgiven.
    """
    result = {"n": 0}

    def mutate(data):
        ips = data.get("Ips", {})
        targets = [ip] if ip else list(ips)
        for key in targets:
            entry = ips.get(key)
            if not entry or not int(entry.get("Strikes", 0) or 0):
                continue
            entry["Strikes"] = 0
            entry["LastStrikeAt"] = 0.0
            entry["Tier"] = 0
            result["n"] += 1

    _store.update(mutate)
    return result["n"]


def strike_board(limit: int = 100) -> list:
    """Who is currently carrying strikes, worst first — the "who is escalating?"
    view. Read-only and lock-free; decay is applied as it is read."""
    decay = runtime.get_setting("throttle_strike_decay_seconds", config.THROTTLE_STRIKE_DECAY)
    now = time.time()
    rows = []
    for ip, entry in (_store.read().get("Ips", {}) or {}).items():
        if not isinstance(entry, dict):
            continue
        strikes = effective_strikes(entry, now, decay)
        if strikes <= 0:
            continue
        reset_in = int(max(0, float(entry.get("ThrottleResetTime", 0) or 0) - now))
        tier = runtime.throttle_tier_for(strikes)
        rows.append(
            {
                "IP": ip,
                "Strikes": strikes,
                "Tier": tier.get("Index", 0),
                "Multiplier": float(tier.get("Multiplier", 1.0) or 1.0),
                "Message": tier.get("Message", ""),
                "Throttled": bool(entry.get("Throttled")) and reset_in > 0,
                "ResetIn": reset_in,
                "LastStrikeAt": float(entry.get("LastStrikeAt", 0) or 0),
                "LastRequestTime": float(entry.get("LastRequestTime", 0) or 0),
                # When this caller drops a rung if they simply stop.
                "DecaysIn": int(max(0, float(entry.get("LastStrikeAt", 0) or 0) + decay - now)) if decay else 0,
            }
        )
    rows.sort(key=lambda row: (row["Strikes"], row["LastStrikeAt"]), reverse=True)
    return rows[: max(1, int(limit))]


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


def check_user_agent_rule(ip: str, user_agent: str) -> tuple:
    """Enforce a per-User-Agent rate rule, if one matches (shared across workers).

    Returns (allowed, retry_after_seconds, rule). `rule` is None when no rule
    applies, and is returned even when the request IS allowed so the caller can
    report which rule is governing it.

    Two shapes, because two different bots need different medicine:

      burst     N requests per P seconds. Right for a scraper that works in
                batches and then sleeps — it gets its batch, then waits.
      cooldown  A minimum gap between requests. Right for a bot that hammers
                steadily; it converts "as fast as I can" into a fixed rate
                without ever refusing it outright for long.

    Unlike the endpoint rules this is NOT clamped to the global per-IP limit,
    because a User-Agent rule is allowed to be the more permissive one: the
    point may well be to give a cooperative bot a predictable lane rather than
    to squeeze it.
    """
    rule = runtime.match_user_agent_rule(user_agent)  # resolved before the lock
    if not rule:
        return True, 0, None
    rule_id = rule.get("Id", "")
    # A "global" rule pools every IP using that User-Agent into one budget,
    # which is the only thing that works on a bot that rotates addresses.
    who = ip if rule.get("Scope", "ip") == "ip" else "*"
    key = f"{rule_id}|{who}"
    now = time.time()

    if rule.get("Kind") == "cooldown":
        cooldown = float(rule.get("Cooldown", config.DEFAULT_USER_AGENT_RULE_COOLDOWN) or 0)

        def mutate_cooldown(data):
            buckets = data.setdefault("UserAgent", {})
            bucket = buckets.get(key)
            last = float(bucket.get("LastAt", 0)) if bucket else 0.0
            waited = now - last
            if last and waited < cooldown:
                # Deliberately does NOT push LastAt forward. Otherwise a bot
                # that ignores the cooldown and retries in a tight loop would
                # reset its own timer on every attempt and never get through —
                # a rate limit that turns into a ban the moment it is disobeyed.
                return (False, max(1, int(cooldown - waited + 0.999)), rule)
            buckets[key] = {"LastAt": now, "ResetTime": now + max(cooldown, 1.0)}
            _cap_buckets(buckets)
            return (True, 0, rule)

        return _store.update(mutate_cooldown)

    limit = max(1, int(rule.get("Limit", config.DEFAULT_USER_AGENT_RULE_LIMIT)))
    period = max(1, int(rule.get("Period", config.DEFAULT_USER_AGENT_RULE_PERIOD)))

    def mutate_burst(data):
        buckets = data.setdefault("UserAgent", {})
        bucket = buckets.get(key)
        if not bucket or now > bucket.get("ResetTime", 0):
            bucket = dict(Count=0, ResetTime=now + period)
            buckets[key] = bucket
        if bucket.get("Count", 0) >= limit:
            return (False, max(1, int(bucket["ResetTime"] - now + 0.999)), rule)
        bucket["Count"] = bucket.get("Count", 0) + 1
        _cap_buckets(buckets)
        return (True, 0, rule)

    return _store.update(mutate_burst)


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
    # The escalation ladder is resolved BEFORE the lock, like every other
    # setting here: the critical section must never do nested file I/O.
    escalating = runtime.escalation_enabled()
    tiers = runtime.get_throttle_tiers() if escalating else []
    decay = runtime.get_setting("throttle_strike_decay_seconds", config.THROTTLE_STRIKE_DECAY)
    tier_reached = {"Index": 0, "Strikes": 0, "Multiplier": 1.0}

    def punish(entry):
        """Turn a limit breach into a timeout, escalating for repeat offenders.

        The strike count is what makes this more than a fixed timeout: a caller
        who trips the limit once is probably just fast, and one who trips it
        every window is not — giving both the identical short wait teaches the
        second one that waiting it out works.
        """
        entry["Throttled"] = 1
        strikes = effective_strikes(entry, now, decay) + 1
        multiplier = 1.0
        index = 0
        if tiers:
            rung = tiers[min(strikes, len(tiers)) - 1]
            try:
                multiplier = max(0.0, float(rung.get("Multiplier", 1.0)))
            except (TypeError, ValueError):
                multiplier = 1.0
            index = min(strikes, len(tiers))
        entry["Strikes"] = strikes
        entry["LastStrikeAt"] = now
        entry["Tier"] = index
        entry["ThrottleResetTime"] = now + throttle_reset_duration * (multiplier or 1.0)
        tier_reached.update(Index=index, Strikes=strikes, Multiplier=multiplier or 1.0)

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
                # An idle entry is normally dropped to keep the shared file
                # small. One still carrying STRIKES is not: the escalation
                # history has to outlive the request counters, or a caller who
                # simply pauses for a minute is forgiven everything and the
                # ladder never climbs past its first rung. Strikes have their
                # own, much longer, decay — that is what expires them.
                if effective_strikes(entry, now, decay) > 0:
                    entry["Requests"] = 0
                    entry["Throttled"] = 0
                    entry["ThrottleResetTime"] = now + throttle_reset_duration
                else:
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
                # The reset time is fixed when the window opens and is NOT
                # extended per request. Nudging it forward on every request made
                # a busy caller's window outlast the configured duration, so the
                # Roxy-Throttle-Reset header we hand back understated the wait.
                entry["LastRequestTime"] = now
            if entry["Requests"] > allowed:
                punish(entry)
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
                Strikes=0,
                LastStrikeAt=0.0,
                Tier=0,
            )
        return False

    just_throttled = _store.update(mutate)
    # Log outside the lock; diagnostics takes its own lock + flushes to a different file.
    if just_throttled:
        diagnostics.log_throttle(ip)
        if tier_reached["Index"]:
            diagnostics.log_throttle_tier(
                tier_reached["Index"], ip, tier_reached["Strikes"], tier_reached["Multiplier"]
            )


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
    decay = runtime.get_setting("throttle_strike_decay_seconds", config.THROTTLE_STRIKE_DECAY)
    now = time.time()

    def mutate(data):
        ips = data.get("Ips", {})
        # Same rule as the request path: an idle entry goes, unless it is still
        # carrying strikes. Sweeping those away would quietly undo escalation
        # for any caller patient enough to pause between bursts.
        stale = [
            ip
            for ip, entry in ips.items()
            if now > entry.get("LastRequestTime", 0) + stale_ip_duration
            and effective_strikes(entry, now, decay) <= 0
        ]
        for ip in stale:
            ips.pop(ip, None)
        endpoint = data.get("Endpoint", {})
        for key in [k for k, b in endpoint.items() if now > b.get("ResetTime", 0) + 60]:
            endpoint.pop(key, None)
        glob = data.get("Global", {})
        for ip in [i for i, b in glob.items() if now > b.get("ResetTime", 0) + 60]:
            glob.pop(ip, None)
        agents = data.get("UserAgent", {})
        for key in [k for k, b in agents.items() if now > b.get("ResetTime", 0) + 60]:
            agents.pop(key, None)
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
