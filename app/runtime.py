"""Runtime-adjustable state for the proxy.

Holds values that the admin can change at runtime without restarting the server:
the paused flag, throttling/cooldown limits, the admin "session epoch" (used to
invalidate all admin sessions at once), and short-lived session-invalidation tokens.

State here is persisted via `storage` so it survives restarts.
"""

import config
import secrets
import time
from threading import Lock

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
}


# --- Pause controls ---------------------------------------------------------
def is_paused() -> bool:
    return _paused


def get_pause_state() -> dict:
    return {"Paused": _paused, "PausedSince": _paused_since}


def set_paused(paused: bool):
    global _paused, _paused_since
    with _lock:
        _paused = bool(paused)
        _paused_since = time.time() if _paused else 0.0
    return _paused


def toggle_paused() -> bool:
    return set_paused(not _paused)


# --- Settings ---------------------------------------------------------------
def get_setting(key: str):
    entry = _settings.get(key)
    return entry["value"] if entry else None


def get_settings() -> dict:
    # Deep-ish copy so callers can't mutate internal state.
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
    with _lock:
        entry["value"] = value
        entry["updated"] = time.time()
    return True, "Success"


# --- Admin session epoch ----------------------------------------------------
def get_session_epoch() -> int:
    return _session_epoch


def bump_session_epoch() -> int:
    global _session_epoch
    with _lock:
        _session_epoch += 1
    return _session_epoch


# --- Invalidation tokens ----------------------------------------------------
def create_invalidation_token() -> str:
    token = secrets.token_urlsafe(32)
    with _lock:
        _invalidation_tokens[token] = time.time() + config.INVALIDATION_TOKEN_EXPIRATION
        _prune_invalidation_tokens()
    return token


def consume_invalidation_token(token: str) -> bool:
    """Validate and remove an invalidation token. Returns True if it was valid."""
    with _lock:
        expiration = _invalidation_tokens.pop(token, None)
        _prune_invalidation_tokens()
    return expiration is not None and time.time() < expiration


def _prune_invalidation_tokens():
    now = time.time()
    for tok in [t for t, exp in _invalidation_tokens.items() if exp < now]:
        _invalidation_tokens.pop(tok, None)


# --- Persistence ------------------------------------------------------------
def serialize() -> dict:
    return {
        "Paused": _paused,
        "PausedSince": _paused_since,
        "SessionEpoch": _session_epoch,
        "Settings": {k: v["value"] for k, v in _settings.items()},
        "SettingsUpdated": {k: v["updated"] for k, v in _settings.items()},
        "InvalidationTokens": _invalidation_tokens,
    }


def restore(data: dict):
    global _paused, _paused_since, _session_epoch, _invalidation_tokens
    if not isinstance(data, dict):
        return
    _paused = bool(data.get("Paused", False))
    _paused_since = float(data.get("PausedSince", 0.0) or 0.0)
    _session_epoch = int(data.get("SessionEpoch", 1) or 1)
    stored_values = data.get("Settings", {}) or {}
    stored_updated = data.get("SettingsUpdated", {}) or {}
    for key, value in stored_values.items():
        if key in _settings:
            ok, _ = set_setting(key, value)
            if ok:
                _settings[key]["updated"] = float(stored_updated.get(key, 0.0) or 0.0)
    tokens = data.get("InvalidationTokens", {})
    if isinstance(tokens, dict):
        _invalidation_tokens = {str(k): float(v) for k, v in tokens.items()}
        _prune_invalidation_tokens()
