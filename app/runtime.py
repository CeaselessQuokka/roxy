"""Runtime-adjustable state for the proxy.

Holds the "control plane": values the admin can change at runtime without
restarting the server — the paused flag, throttling/cooldown limits, blocked
endpoints, per-endpoint rate rules, the admin "session epoch" (a server-side
kill switch), and short-lived session-invalidation tokens.

The persisted data file is the single source of truth so this works across
multiple gunicorn workers: every change is written through (under an
inter-process lock) and every read reloads from disk when the file changes.
"""

import config
import re
import secrets
import time
from functools import lru_cache
from threading import Lock

import storage

_lock = Lock()

# --- Proxy pause flag -------------------------------------------------------
_paused = False
_paused_since = 0.0

# --- Admin session epoch ----------------------------------------------------
# Every admin session records the epoch it was created under. Bumping the epoch
# invalidates every existing admin session at once (a server-side kill switch).
_session_epoch = 1

# --- Emailed single-use session-invalidation tokens -------------------------
_invalidation_tokens = dict()  # token -> expiration_time

# --- Short-lived login secrets (shared across workers) -----------------------
# 2FA codes are stored hashed; challenges are random hex. Both live in the
# shared file so a login started on one gunicorn worker can finish on another.
_two_fa_codes = dict()  # hashed_code -> expiration_time
_challenges = dict()  # challenge -> expiration_time


# --- Blocked endpoints ------------------------------------------------------
_endpoint_blocks = dict()  # pattern -> {"Added": ts, "Note": str}

# --- Per-endpoint per-IP rate rules -----------------------------------------
_endpoint_rules = dict()  # pattern -> {"Limit": int, "Period": int, "Added": ts}

# --- Header block rules -----------------------------------------------------
# Deny a request outright based on its headers (e.g. exploit fingerprints like
# "Xeno"). id -> {"Scope": key|value|either, "Mode": contains|exact,
#                 "Needle": str, "Note": str, "Added": ts}
_header_rules = dict()
HEADER_RULE_SCOPES = ("key", "value", "either")
HEADER_RULE_MODES = ("contains", "exact")

# --- Cross-worker reload bookkeeping ----------------------------------------
_last_mtime = 0.0
_last_check = 0.0
RELOAD_CHECK_INTERVAL = 1.0  # In seconds, how often a read will re-check the file mtime.


# --- Runtime-adjustable settings --------------------------------------------
# Each entry: key -> {"value", "default", "min", "max", "type", "updated"}.
def _setting(default, minimum, maximum, kind):
    return {"value": default, "default": default, "min": minimum, "max": maximum, "type": kind, "updated": 0.0}


_settings = {
    "allowed_requests_per_minute": _setting(config.ALLOWED_REQUESTS_PER_MINUTE, 1, 100000, "int"),
    "throttle_reset_duration": _setting(config.THROTTLE_RESET_DURATION, 1, 86400, "int"),
    "stale_ip_duration": _setting(config.STALE_IP_DURATION, 1, 86400, "int"),
    "direct_api_cooldown": _setting(config.DIRECT_API_COOLDOWN, 0, 86400, "int"),
    "roproxy_cooldown": _setting(config.ROPROXY_COOLDOWN, 0, 86400, "int"),
    "max_retries_per_request": _setting(config.MAX_RETRIES_PER_REQUEST, 0, 20, "int"),
    "two_fa_expiration": _setting(config.TWO_FA_EXPIRATION, 5, 600, "int"),
    "challenge_expiration": _setting(config.CHALLENGE_EXPIRATION, 5, 600, "int"),
    "token_expiration_cooldown": _setting(config.TOKEN_EXPIRATION_COOLDOWN, 1, 86400, "int"),
    "request_timeout": _setting(config.REQUEST_TIMEOUT, 1, 120, "int"),
    "email_cooldown": _setting(config.EMAIL_COOLDOWN, 0, 86400, "int"),
    "error_email_cooldown": _setting(config.ERROR_EMAIL_COOLDOWN, 0, 86400, "int"),
    "autosave_interval": _setting(config.AUTOSAVE_INTERVAL, 1, 3600, "int"),
    "max_live_requests": _setting(config.MAX_LIVE_REQUESTS, 0, 1000, "int"),
    "max_exploit_records": _setting(config.MAX_EXPLOIT_RECORDS, 1, 1000, "int"),
    "max_login_records": _setting(config.MAX_LOGIN_RECORDS, 1, 1000, "int"),
    "max_crawl_records": _setting(config.MAX_CRAWL_RECORDS, 1, 5000, "int"),
    "max_throttle_records": _setting(config.MAX_THROTTLE_RECORDS, 1, 5000, "int"),
    "max_endpoint_records": _setting(config.MAX_ENDPOINT_RECORDS, 1, 5000, "int"),
    # Hard safety budget for the internal token: at most N token-authenticated
    # requests to Roblox per window, so the server never looks like a bot burst.
    "token_budget_requests": _setting(config.TOKEN_BUDGET_REQUESTS, 1, 10000, "int"),
    "token_budget_window": _setting(config.TOKEN_BUDGET_WINDOW, 1, 3600, "int"),
}


# --- Endpoint pattern helpers -----------------------------------------------
def _norm(pattern: str) -> str:
    return (pattern or "").strip().lstrip("/").lower()


@lru_cache(maxsize=1024)
def _compile_pattern(pattern: str):
    """Compile an endpoint pattern into a regex.

    - `*` is a wildcard for a run of characters WITHIN one path segment; it never
      spans a `/`. So `games.roblox.com/v1/games/*/servers` matches
      `games.roblox.com/v1/games/694768217/servers` (and, via the implied
      trailing wildcard below, `.../servers/0`) but NOT `.../games/123/votes`.
    - A trailing path is always allowed: a pattern matches the path it names and
      everything nested under it (the historical behavior).
    - A host-only pattern (no slash) matches that whole service.

    Cached because patterns are few and reused across many requests.
    """
    base = pattern.rstrip("/")
    # Escape everything literally, then turn the escaped '*' back into a
    # single-segment wildcard. re.escape turns '*' into r'\*'.
    escaped = re.escape(base).replace(r"\*", r"[^/]*")
    return re.compile(rf"^{escaped}(?:/.*)?$")


def _matches(pattern: str, path: str) -> bool:
    """Whether a normalized request path is covered by an endpoint pattern."""
    if not pattern:
        return False
    try:
        return _compile_pattern(pattern).match(path) is not None
    except re.error:
        return False


def _specificity(pattern: str):
    """Sort key for "most specific match wins". More path segments rank higher;
    among equals, more literal (non-wildcard) characters rank higher, so a
    concrete rule beats a wildcard one covering the same path."""
    return (pattern.count("/"), len(pattern) - pattern.count("*"))


# --- Cross-worker reload ----------------------------------------------------
def _restore_from(data: dict):
    """Apply a persisted Runtime blob into memory (no re-persist). Locked by caller.

    Dicts are mutated IN PLACE (never rebound): helpers capture references to
    them, and a rebind would silently disconnect those helpers from the state
    that actually gets persisted.
    """
    global _paused, _paused_since, _session_epoch
    if not isinstance(data, dict) or not data:
        return
    _paused = bool(data.get("Paused", _paused))
    _paused_since = float(data.get("PausedSince", _paused_since) or 0.0)
    _session_epoch = int(data.get("SessionEpoch", _session_epoch) or 1)

    stored_values = data.get("Settings", {}) or {}
    stored_updated = data.get("SettingsUpdated", {}) or {}
    for key, value in stored_values.items():
        entry = _settings.get(key)
        if not entry:
            continue
        try:
            value = int(value) if entry["type"] == "int" else float(value)
        except (TypeError, ValueError):
            continue
        entry["value"] = max(entry["min"], min(entry["max"], value))
        entry["updated"] = float(stored_updated.get(key, entry["updated"]) or 0.0)

    def replace_in_place(store: dict, fresh: dict):
        store.clear()
        store.update(fresh)

    blocks = data.get("EndpointBlocks", {})
    if isinstance(blocks, dict):
        replace_in_place(_endpoint_blocks, {str(k): dict(v) for k, v in blocks.items() if isinstance(v, dict)})
    rules = data.get("EndpointRules", {})
    if isinstance(rules, dict):
        replace_in_place(_endpoint_rules, {str(k): dict(v) for k, v in rules.items() if isinstance(v, dict)})
    header_rules = data.get("HeaderRules", {})
    if isinstance(header_rules, dict):
        replace_in_place(_header_rules, {str(k): dict(v) for k, v in header_rules.items() if isinstance(v, dict)})

    tokens = data.get("InvalidationTokens", {})
    if isinstance(tokens, dict):
        replace_in_place(_invalidation_tokens, {str(k): float(v) for k, v in tokens.items()})
    codes = data.get("TwoFACodes", {})
    if isinstance(codes, dict):
        replace_in_place(_two_fa_codes, {str(k): float(v) for k, v in codes.items()})
    challenges = data.get("Challenges", {})
    if isinstance(challenges, dict):
        replace_in_place(_challenges, {str(k): float(v) for k, v in challenges.items()})
    _prune_expirables()


def _maybe_reload():
    """If another worker changed the file, pull the latest control-plane state."""
    global _last_mtime, _last_check
    now = time.time()
    if now - _last_check < RELOAD_CHECK_INTERVAL:
        return
    _last_check = now
    mtime = storage.get_mtime()
    if mtime and mtime != _last_mtime:
        _last_mtime = mtime
        data = storage.load_data()
        with _lock:
            _restore_from(data.get("Runtime", {}))


def _persist_change(apply_change):
    """Atomically read the file, sync memory to it, apply a change, write it back.

    Re-syncing from the file first means a worker with slightly stale memory
    won't clobber another worker's recent change.
    """
    global _last_mtime

    def mutate(data):
        with _lock:
            _restore_from(data.get("Runtime", {}))
            apply_change()
            data["Runtime"] = _serialize_unlocked()
        return data

    try:
        storage.update_data(mutate)
        _last_mtime = storage.get_mtime()
    except OSError:
        # Disk hiccup: apply the change in memory anyway so this worker keeps
        # working; cross-worker sync catches up on the next successful write.
        with _lock:
            apply_change()


# --- Pause controls ---------------------------------------------------------
def is_paused() -> bool:
    _maybe_reload()
    return _paused


def get_pause_state() -> dict:
    _maybe_reload()
    return {"Paused": _paused, "PausedSince": _paused_since}


def set_paused(paused: bool):
    def change():
        global _paused, _paused_since
        _paused = bool(paused)
        _paused_since = time.time() if _paused else 0.0

    _persist_change(change)
    return _paused


def toggle_paused() -> bool:
    return set_paused(not is_paused())


# --- Settings ---------------------------------------------------------------
def get_setting(key: str, default=None):
    """Current value of a runtime setting, or `default` for unknown keys.

    Callers must NOT use `get_setting(k) or fallback` — that silently swaps in
    the fallback when the configured value is a legitimate 0 (e.g. a cooldown
    of 0 meaning "disabled"). Pass the fallback as `default` instead.
    """
    _maybe_reload()
    entry = _settings.get(key)
    return entry["value"] if entry else default


def get_settings() -> dict:
    _maybe_reload()
    return {k: dict(v) for k, v in _settings.items()}


def set_setting(key: str, value) -> tuple[bool, str]:
    entry = _settings.get(key)
    if entry is None:
        return False, f"Unknown setting: {key}"
    try:
        value = int(value) if entry["type"] == "int" else float(value)
    except (TypeError, ValueError):
        return False, f"Invalid value for {key}"
    if value < entry["min"] or value > entry["max"]:
        return False, f"{key} must be between {entry['min']} and {entry['max']}"

    def change():
        entry["value"] = value
        entry["updated"] = time.time()

    _persist_change(change)
    return True, "Success"


# --- Blocked endpoints ------------------------------------------------------
def get_endpoint_blocks() -> dict:
    _maybe_reload()
    return {k: dict(v) for k, v in _endpoint_blocks.items()}


def is_endpoint_blocked(path: str) -> bool:
    _maybe_reload()
    p = _norm(path)
    return any(_matches(pattern, p) for pattern in _endpoint_blocks)


def get_matching_block(path: str):
    """Return the most specific block pattern matching a path, or None."""
    _maybe_reload()
    p = _norm(path)
    best = None
    best_score = None
    for pattern in _endpoint_blocks:
        if _matches(pattern, p):
            score = _specificity(pattern)
            if best_score is None or score > best_score:
                best = pattern
                best_score = score
    return best


def block_endpoint(pattern: str, note: str = "") -> tuple[bool, str]:
    pattern = _norm(pattern)
    if not pattern:
        return False, "Empty endpoint pattern"
    if pattern not in _endpoint_blocks and len(_endpoint_blocks) >= config.MAX_ENDPOINT_BLOCKS:
        return False, "Too many blocked endpoints"

    def change():
        _endpoint_blocks[pattern] = {"Added": time.time(), "Note": str(note)[:200]}

    _persist_change(change)
    return True, "Success"


def unblock_endpoint(pattern: str) -> tuple[bool, str]:
    pattern = _norm(pattern)

    def change():
        _endpoint_blocks.pop(pattern, None)

    _persist_change(change)
    return True, "Success"


# --- Per-endpoint rate rules ------------------------------------------------
def get_endpoint_rules() -> dict:
    _maybe_reload()
    return {k: dict(v) for k, v in _endpoint_rules.items()}


def set_endpoint_rule(pattern: str, limit, period=config.DEFAULT_ENDPOINT_RULE_PERIOD) -> tuple[bool, str]:
    pattern = _norm(pattern)
    if not pattern:
        return False, "Empty endpoint pattern"
    try:
        limit = int(limit)
        period = int(period)
    except (TypeError, ValueError):
        return False, "Limit and period must be whole numbers"
    hard_max = _settings["allowed_requests_per_minute"]["max"]
    if limit < 1 or limit > hard_max:
        return False, f"Limit must be between 1 and {hard_max}"
    if period < 1 or period > 86400:
        return False, "Period must be between 1 and 86400 seconds"
    if pattern not in _endpoint_rules and len(_endpoint_rules) >= config.MAX_ENDPOINT_RULES:
        return False, "Too many endpoint rules"

    def change():
        _endpoint_rules[pattern] = {"Limit": limit, "Period": period, "Added": time.time()}

    _persist_change(change)
    return True, "Success"


def clear_endpoint_rule(pattern: str) -> tuple[bool, str]:
    pattern = _norm(pattern)

    def change():
        _endpoint_rules.pop(pattern, None)

    _persist_change(change)
    return True, "Success"


def match_endpoint_rule(path: str):
    """Return the most specific (longest-prefix) rate rule matching a path, or None.

    The returned dict includes a "Pattern" key. The caller is still subject to the
    global per-IP limit, so this can only ever make an endpoint MORE restrictive.
    """
    _maybe_reload()
    p = _norm(path)
    best = None
    best_score = None
    for pattern, rule in _endpoint_rules.items():
        if _matches(pattern, p):
            score = _specificity(pattern)
            if best_score is None or score > best_score:
                best = dict(rule)
                best["Pattern"] = pattern
                best_score = score
    return best


# --- Header block rules -----------------------------------------------------
def _header_rule_id(scope: str, mode: str, needle: str) -> str:
    """Canonical id so the same rule can't be added twice and is easy to remove."""
    return f"{scope}|{mode}|{needle.lower()}"


def get_header_rules() -> dict:
    _maybe_reload()
    return {k: dict(v) for k, v in _header_rules.items()}


def add_header_rule(scope: str, mode: str, needle: str, note: str = "") -> tuple[bool, str]:
    scope = (scope or "either").strip().lower()
    mode = (mode or "contains").strip().lower()
    needle = (needle or "").strip()
    if scope not in HEADER_RULE_SCOPES:
        return False, f"Scope must be one of: {', '.join(HEADER_RULE_SCOPES)}"
    if mode not in HEADER_RULE_MODES:
        return False, f"Mode must be one of: {', '.join(HEADER_RULE_MODES)}"
    if not needle:
        return False, "Empty match text"
    rule_id = _header_rule_id(scope, mode, needle)
    if rule_id not in _header_rules and len(_header_rules) >= config.MAX_HEADER_RULES:
        return False, "Too many header rules"

    def change():
        _header_rules[rule_id] = {
            "Scope": scope,
            "Mode": mode,
            "Needle": needle,
            "Note": str(note)[:200],
            "Added": time.time(),
        }

    _persist_change(change)
    return True, "Success"


def remove_header_rule(rule_id: str) -> tuple[bool, str]:
    def change():
        _header_rules.pop(str(rule_id), None)

    _persist_change(change)
    return True, "Success"


def _header_field_matches(mode: str, needle_lower: str, target: str) -> bool:
    target = (target or "").lower()
    if mode == "exact":
        return target == needle_lower
    return needle_lower in target  # contains


def match_header_rule(headers) -> dict | None:
    """Return the first header rule a request's headers trip, or None.

    `headers` is any iterable of (name, value) pairs (e.g. request.headers.items()).
    The returned dict includes an "Id" key for diagnostics; it intentionally does
    NOT get shown to the client (a blocked caller only sees a generic error).
    """
    _maybe_reload()
    if not _header_rules:
        return None
    pairs = list(headers.items()) if hasattr(headers, "items") else list(headers)
    for rule_id, rule in _header_rules.items():
        scope = rule.get("Scope", "either")
        mode = rule.get("Mode", "contains")
        needle_lower = str(rule.get("Needle", "")).lower()
        if not needle_lower:
            continue
        for name, value in pairs:
            key_hit = scope in ("key", "either") and _header_field_matches(mode, needle_lower, name)
            value_hit = scope in ("value", "either") and _header_field_matches(mode, needle_lower, value)
            if key_hit or value_hit:
                hit = dict(rule)
                hit["Id"] = rule_id
                hit["MatchedHeader"] = name
                return hit
    return None


# --- Admin session epoch ----------------------------------------------------
def get_session_epoch() -> int:
    _maybe_reload()
    return _session_epoch


def bump_session_epoch() -> int:
    def change():
        global _session_epoch
        _session_epoch += 1

    _persist_change(change)
    return _session_epoch


# --- Short-lived secrets (invalidation tokens, 2FA codes, challenges) --------
def _store_expirable(store: dict, key: str, expires_at: float):
    def change():
        store[key] = expires_at
        _prune_expirables()

    _persist_change(change)


def _consume_expirable(store: dict, key: str) -> bool:
    """Validate and remove a single-use entry. Returns True if it was present and unexpired."""
    result = {"valid": False}

    def change():
        expiration = store.pop(key, None)
        _prune_expirables()
        result["valid"] = expiration is not None and time.time() < expiration

    _persist_change(change)
    return result["valid"]


def create_invalidation_token() -> str:
    token = secrets.token_urlsafe(32)
    _store_expirable(_invalidation_tokens, token, time.time() + config.INVALIDATION_TOKEN_EXPIRATION)
    return token


def consume_invalidation_token(token: str) -> bool:
    """Validate and remove an invalidation token. Returns True if it was valid."""
    return _consume_expirable(_invalidation_tokens, str(token))


def store_two_fa_code(hashed_code: str, expires_at: float):
    _store_expirable(_two_fa_codes, hashed_code, expires_at)


def consume_two_fa_code(hashed_code: str) -> bool:
    return _consume_expirable(_two_fa_codes, hashed_code)


def store_challenge(challenge: str, expires_at: float):
    _store_expirable(_challenges, challenge, expires_at)


def consume_challenge(challenge: str) -> bool:
    return _consume_expirable(_challenges, str(challenge))


def _prune_expirables():
    now = time.time()
    for store in (_invalidation_tokens, _two_fa_codes, _challenges):
        for key in [k for k, exp in store.items() if exp < now]:
            store.pop(key, None)


# --- Persistence ------------------------------------------------------------
def _serialize_unlocked() -> dict:
    # Copies, not references: the caller JSON-serializes this blob after the
    # lock is released, and the live dicts are mutated in place by reloads.
    return {
        "Paused": _paused,
        "PausedSince": _paused_since,
        "SessionEpoch": _session_epoch,
        "Settings": {k: v["value"] for k, v in _settings.items()},
        "SettingsUpdated": {k: v["updated"] for k, v in _settings.items()},
        "EndpointBlocks": {k: dict(v) for k, v in _endpoint_blocks.items()},
        "EndpointRules": {k: dict(v) for k, v in _endpoint_rules.items()},
        "HeaderRules": {k: dict(v) for k, v in _header_rules.items()},
        "InvalidationTokens": dict(_invalidation_tokens),
        "TwoFACodes": dict(_two_fa_codes),
        "Challenges": dict(_challenges),
    }


def serialize() -> dict:
    with _lock:
        return _serialize_unlocked()


def restore(data: dict):
    with _lock:
        _restore_from(data)


def _load_from_disk():
    """Load control-plane state from the shared file on startup."""
    global _last_mtime
    data = storage.load_data()
    with _lock:
        _restore_from(data.get("Runtime", {}))
    _last_mtime = storage.get_mtime()


_load_from_disk()
