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
import secrets
import time
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

# --- Blocked endpoints ------------------------------------------------------
_endpoint_blocks = dict()  # pattern -> {"Added": ts, "Note": str}

# --- Per-endpoint per-IP rate rules -----------------------------------------
_endpoint_rules = dict()  # pattern -> {"Limit": int, "Period": int, "Added": ts}

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
}


# --- Endpoint pattern helpers -----------------------------------------------
def _norm(pattern: str) -> str:
    return (pattern or "").strip().lstrip("/").lower()


def _matches(pattern: str, path: str) -> bool:
    """Whether a normalized request path is covered by an endpoint pattern.

    - No slash in the pattern => match the whole service host (e.g. "games.roblox.com").
    - Otherwise => exact match or prefix match on a path boundary.
    """
    if not pattern:
        return False
    if "/" not in pattern:
        return path.split("/", 1)[0] == pattern
    base = pattern.rstrip("/")
    return path == base or path.startswith(base + "/")


# --- Cross-worker reload ----------------------------------------------------
def _restore_from(data: dict):
    """Apply a persisted Runtime blob into memory (no re-persist). Locked by caller."""
    global _paused, _paused_since, _session_epoch, _invalidation_tokens, _endpoint_blocks, _endpoint_rules
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

    blocks = data.get("EndpointBlocks", {})
    if isinstance(blocks, dict):
        _endpoint_blocks = {str(k): dict(v) for k, v in blocks.items() if isinstance(v, dict)}
    rules = data.get("EndpointRules", {})
    if isinstance(rules, dict):
        _endpoint_rules = {str(k): dict(v) for k, v in rules.items() if isinstance(v, dict)}

    tokens = data.get("InvalidationTokens", {})
    if isinstance(tokens, dict):
        _invalidation_tokens = {str(k): float(v) for k, v in tokens.items()}
        _prune_invalidation_tokens()


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

    storage.update_data(mutate)
    _last_mtime = storage.get_mtime()


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
def get_setting(key: str):
    _maybe_reload()
    entry = _settings.get(key)
    return entry["value"] if entry else None


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
    """Return the most specific (longest) block pattern matching a path, or None."""
    _maybe_reload()
    p = _norm(path)
    best = None
    best_len = -1
    for pattern in _endpoint_blocks:
        if _matches(pattern, p) and len(pattern) > best_len:
            best = pattern
            best_len = len(pattern)
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
    best_len = -1
    for pattern, rule in _endpoint_rules.items():
        if _matches(pattern, p) and len(pattern) > best_len:
            best = dict(rule)
            best["Pattern"] = pattern
            best_len = len(pattern)
    return best


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


# --- Invalidation tokens ----------------------------------------------------
def create_invalidation_token() -> str:
    token = secrets.token_urlsafe(32)

    def change():
        _invalidation_tokens[token] = time.time() + config.INVALIDATION_TOKEN_EXPIRATION
        _prune_invalidation_tokens()

    _persist_change(change)
    return token


def consume_invalidation_token(token: str) -> bool:
    """Validate and remove an invalidation token. Returns True if it was valid."""
    result = {"valid": False}

    def change():
        expiration = _invalidation_tokens.pop(token, None)
        _prune_invalidation_tokens()
        result["valid"] = expiration is not None and time.time() < expiration

    _persist_change(change)
    return result["valid"]


def _prune_invalidation_tokens():
    now = time.time()
    for tok in [t for t, exp in _invalidation_tokens.items() if exp < now]:
        _invalidation_tokens.pop(tok, None)


# --- Persistence ------------------------------------------------------------
def _serialize_unlocked() -> dict:
    return {
        "Paused": _paused,
        "PausedSince": _paused_since,
        "SessionEpoch": _session_epoch,
        "Settings": {k: v["value"] for k, v in _settings.items()},
        "SettingsUpdated": {k: v["updated"] for k, v in _settings.items()},
        "EndpointBlocks": _endpoint_blocks,
        "EndpointRules": _endpoint_rules,
        "InvalidationTokens": _invalidation_tokens,
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
