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
import hashlib
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
_pause_reason = ""  # Optional admin message shown to users while paused.

# --- Global throttle-all flag -----------------------------------------------
# A softer alternative to pausing: when on, every IP is rate-limited to
# global_throttle_limit requests per global_throttle_period seconds (configurable
# below). Allowed requests still proceed (and remain subject to the normal per-IP
# and per-endpoint limits); the rest get a friendly 429.
_throttle_all = False
_throttle_all_since = 0.0
_throttle_all_reason = ""  # Optional admin message shown to throttled users.

DEFAULT_DOWNTIME_MESSAGE = "Service down for maintenance."

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

# --- Trusted devices --------------------------------------------------------
# A trusted device may skip the 2FA step for config.TRUSTED_DEVICE_DURATION.
# token (hashed) -> {"Expires": ts, "IP": str, "UserAgent": str, "Added": ts}
_trusted_devices = dict()


# --- Throttle-bypass allowlist ----------------------------------------------
# IPs that skip the rate-limit 429s (per-IP throttle, throttle-all, per-endpoint
# rate rules) — handy for load/spam testing. Does NOT bypass pause, endpoint
# blocks, header rules, or the Token safety budget. Optional per-IP expiry.
# ip -> {"Added": ts, "Expires": ts (0 = never), "Note": str}
_throttle_bypass_ips = dict()

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
HEADER_RULE_MODES = ("contains", "exact", "regex")

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
    # When global throttle-all is ON: each IP may make this many requests per window.
    "global_throttle_limit": _setting(config.GLOBAL_THROTTLE_LIMIT, 1, 100000, "int"),
    "global_throttle_period": _setting(config.GLOBAL_THROTTLE_PERIOD, 1, 86400, "int"),
    # Upstream method routing weights + the token "danger zone".
    "roproxy_weight": _setting(config.ROPROXY_WEIGHT, 0, 1000, "int"),
    "token_weight": _setting(config.TOKEN_WEIGHT, 0, 1000, "int"),
    "rotate_weight": _setting(config.ROTATE_WEIGHT, 0, 1000, "int"),
    "token_danger_zone": _setting(config.TOKEN_DANGER_ZONE, 0, 100000, "int"),
    # IP rotation (DataImpulse): master on/off + cooldown after proxy failures.
    "rotate_enabled": _setting(1, 0, 1, "int"),
    "rotate_cooldown": _setting(config.ROTATE_COOLDOWN, 0, 86400, "int"),
    "rotate_max_failures": _setting(config.ROTATE_MAX_FAILURES, 1, 100, "int"),
}


# --- Endpoint pattern helpers -----------------------------------------------
def _norm(pattern: str) -> str:
    """Normalize a GLOB pattern: trim, drop leading slashes, lowercase."""
    return (pattern or "").strip().lstrip("/").lower()


def _norm_regex(pattern: str) -> str:
    """Normalize a REGEX pattern: trim and drop leading slashes only.

    Crucially does NOT lowercase — lowercasing would corrupt regex escapes like
    \\D, \\W, \\S, \\B into their opposites. Case-insensitivity is handled by the
    re.IGNORECASE flag at compile time instead.
    """
    return (pattern or "").strip().lstrip("/")


def normalize_pattern(pattern: str, kind: str) -> str:
    return _norm_regex(pattern) if kind == "regex" else _norm(pattern)


def valid_regex(pattern: str) -> bool:
    try:
        re.compile(pattern)
        return True
    except re.error:
        return False


@lru_cache(maxsize=2048)
def _compile_pattern(pattern: str, kind: str):
    """Compile an endpoint pattern into a regex.

    kind == "glob" (default):
      - `*` is a wildcard for a run of characters WITHIN one path segment; it
        never spans a `/`. So `games.roblox.com/v1/games/*/servers` matches
        `games.roblox.com/v1/games/694768217/servers`.
      - A trailing path is always allowed: a pattern matches the path it names
        and everything nested under it.
      - A host-only pattern (no slash) matches that whole service.

    kind == "regex":
      - The pattern is a raw Python regex, matched with re.search (so the admin
        anchors it themselves with ^ / $). No implied trailing wildcard.

    Both are case-insensitive. Cached because patterns are few and reused.
    """
    if kind == "regex":
        return re.compile(pattern, re.IGNORECASE)
    base = pattern.rstrip("/")
    # Escape everything literally, then turn the escaped '*' back into a
    # single-segment wildcard. re.escape turns '*' into r'\*'.
    escaped = re.escape(base).replace(r"\*", r"[^/]*")
    return re.compile(rf"^{escaped}(?:/.*)?$", re.IGNORECASE)


def _matches(pattern: str, path: str, kind: str = "glob") -> bool:
    """Whether a normalized request path is covered by an endpoint pattern."""
    if not pattern:
        return False
    try:
        rx = _compile_pattern(pattern, kind)
    except re.error:
        return False
    return (rx.search(path) if kind == "regex" else rx.match(path)) is not None


def _specificity(pattern: str, kind: str = "glob"):
    """Sort key for "most specific match wins". More path segments rank higher;
    among equals, more literal (non-wildcard) characters rank higher, so a
    concrete rule beats a wildcard one covering the same path. Regex patterns
    sort by length only (they have no clean segment notion)."""
    if kind == "regex":
        return (pattern.count("/"), len(pattern))
    return (pattern.count("/"), len(pattern) - pattern.count("*"))


# --- Cross-worker reload ----------------------------------------------------
def _restore_from(data: dict):
    """Apply a persisted Runtime blob into memory (no re-persist). Locked by caller.

    Dicts are mutated IN PLACE (never rebound): helpers capture references to
    them, and a rebind would silently disconnect those helpers from the state
    that actually gets persisted.
    """
    global _paused, _paused_since, _session_epoch, _throttle_all, _throttle_all_since
    global _pause_reason, _throttle_all_reason
    if not isinstance(data, dict) or not data:
        return
    _paused = bool(data.get("Paused", _paused))
    _paused_since = float(data.get("PausedSince", _paused_since) or 0.0)
    _pause_reason = str(data.get("PauseReason", _pause_reason) or "")
    _throttle_all = bool(data.get("ThrottleAll", _throttle_all))
    _throttle_all_since = float(data.get("ThrottleAllSince", _throttle_all_since) or 0.0)
    _throttle_all_reason = str(data.get("ThrottleAllReason", _throttle_all_reason) or "")
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

    bypass = data.get("ThrottleBypassIps", {})
    if isinstance(bypass, dict):
        replace_in_place(_throttle_bypass_ips, {str(k): dict(v) for k, v in bypass.items() if isinstance(v, dict)})
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
    devices = data.get("TrustedDevices", {})
    if isinstance(devices, dict):
        replace_in_place(_trusted_devices, {str(k): dict(v) for k, v in devices.items() if isinstance(v, dict)})
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
    return {"Paused": _paused, "PausedSince": _paused_since, "Reason": _pause_reason}


def pause_message() -> str:
    _maybe_reload()
    return _pause_reason or DEFAULT_DOWNTIME_MESSAGE


def set_paused(paused: bool, reason: str = None):
    def change():
        global _paused, _paused_since, _pause_reason
        _paused = bool(paused)
        _paused_since = time.time() if _paused else 0.0
        # The message persists (so it survives refreshes/restarts and is reused
        # next time); it is only changed when a new value is explicitly supplied.
        if reason is not None:
            _pause_reason = str(reason)[:300]

    _persist_change(change)
    return _paused


def toggle_paused() -> bool:
    return set_paused(not is_paused())


# --- Global throttle-all controls -------------------------------------------
def is_throttle_all() -> bool:
    _maybe_reload()
    return _throttle_all


def get_throttle_all_state() -> dict:
    _maybe_reload()
    return {
        "ThrottleAll": _throttle_all,
        "ThrottleAllSince": _throttle_all_since,
        "Reason": _throttle_all_reason,
        "Limit": get_setting("global_throttle_limit", config.GLOBAL_THROTTLE_LIMIT),
        "Period": get_setting("global_throttle_period", config.GLOBAL_THROTTLE_PERIOD),
    }


def throttle_all_message() -> str:
    _maybe_reload()
    return _throttle_all_reason or DEFAULT_DOWNTIME_MESSAGE


def set_throttle_all(enabled: bool, reason: str = None):
    def change():
        global _throttle_all, _throttle_all_since, _throttle_all_reason
        _throttle_all = bool(enabled)
        _throttle_all_since = time.time() if _throttle_all else 0.0
        # The message persists (reused next time); only changed when explicitly supplied.
        if reason is not None:
            _throttle_all_reason = str(reason)[:300]

    _persist_change(change)
    return _throttle_all


def toggle_throttle_all() -> bool:
    return set_throttle_all(not is_throttle_all())


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


# --- Throttle-bypass allowlist ----------------------------------------------
def _bypass_active(entry: dict, now: float) -> bool:
    expires = float(entry.get("Expires", 0) or 0)
    return expires == 0 or now < expires


def is_throttle_bypassed(ip: str) -> bool:
    """Whether this IP is on the (unexpired) throttle-bypass allowlist."""
    if not ip:
        return False
    _maybe_reload()
    entry = _throttle_bypass_ips.get(ip)
    return bool(entry) and _bypass_active(entry, time.time())


def get_throttle_bypass_ips() -> dict:
    _maybe_reload()
    now = time.time()
    # Surface only currently-active entries (an expired one is effectively gone).
    return {k: dict(v) for k, v in _throttle_bypass_ips.items() if _bypass_active(v, now)}


def add_throttle_bypass(ip: str, expires_in: float = 0, note: str = "") -> tuple[bool, str]:
    """Allowlist an IP to skip rate-limit 429s. `expires_in` is seconds from now
    (0 = never expires). Re-adding an IP updates its expiry/note."""
    ip = (ip or "").strip()
    if not ip or len(ip) > 64:
        return False, "Enter a valid IP address"
    try:
        expires_in = float(expires_in or 0)
    except (TypeError, ValueError):
        return False, "Expiry must be a number of seconds"
    if expires_in < 0:
        return False, "Expiry cannot be negative"
    if ip not in _throttle_bypass_ips and len(_throttle_bypass_ips) >= config.MAX_THROTTLE_BYPASS_IPS:
        return False, "Too many bypass IPs"
    expires_at = time.time() + expires_in if expires_in > 0 else 0

    def change():
        _throttle_bypass_ips[ip] = {"Added": time.time(), "Expires": expires_at, "Note": str(note)[:200]}

    _persist_change(change)
    return True, "Success"


def remove_throttle_bypass(ip: str) -> tuple[bool, str]:
    def change():
        _throttle_bypass_ips.pop((ip or "").strip(), None)

    _persist_change(change)
    return True, "Success"


# --- Blocked endpoints ------------------------------------------------------
def get_endpoint_blocks() -> dict:
    _maybe_reload()
    return {k: dict(v) for k, v in _endpoint_blocks.items()}


def is_endpoint_blocked(path: str) -> bool:
    _maybe_reload()
    p = _norm(path)
    return any(_matches(pattern, p, rule.get("Type", "glob")) for pattern, rule in _endpoint_blocks.items())


def get_matching_block(path: str):
    """Return the most specific block pattern matching a path, or None."""
    _maybe_reload()
    p = _norm(path)
    best = None
    best_score = None
    for pattern, rule in _endpoint_blocks.items():
        kind = rule.get("Type", "glob")
        if _matches(pattern, p, kind):
            score = _specificity(pattern, kind)
            if best_score is None or score > best_score:
                best = pattern
                best_score = score
    return best


def block_endpoint(pattern: str, note: str = "", kind: str = "glob") -> tuple[bool, str]:
    kind = "regex" if kind == "regex" else "glob"
    pattern = normalize_pattern(pattern, kind)
    if not pattern:
        return False, "Empty endpoint pattern"
    if kind == "regex" and not valid_regex(pattern):
        return False, "Invalid regular expression"
    if pattern not in _endpoint_blocks and len(_endpoint_blocks) >= config.MAX_ENDPOINT_BLOCKS:
        return False, "Too many blocked endpoints"

    def change():
        _endpoint_blocks[pattern] = {"Added": time.time(), "Note": str(note)[:200], "Type": kind}

    _persist_change(change)
    return True, "Success"


def unblock_endpoint(pattern: str) -> tuple[bool, str]:
    # The caller passes back the exact stored key; also tolerate glob/regex
    # normalization differences so either form removes the rule.
    candidates = {(pattern or "").strip(), _norm(pattern), _norm_regex(pattern)}

    def change():
        for key in candidates:
            _endpoint_blocks.pop(key, None)

    _persist_change(change)
    return True, "Success"


# --- Per-endpoint rate rules ------------------------------------------------
def get_endpoint_rules() -> dict:
    _maybe_reload()
    return {k: dict(v) for k, v in _endpoint_rules.items()}


def set_endpoint_rule(
    pattern: str, limit, period=config.DEFAULT_ENDPOINT_RULE_PERIOD, kind: str = "glob"
) -> tuple[bool, str]:
    kind = "regex" if kind == "regex" else "glob"
    pattern = normalize_pattern(pattern, kind)
    if not pattern:
        return False, "Empty endpoint pattern"
    if kind == "regex" and not valid_regex(pattern):
        return False, "Invalid regular expression"
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
        _endpoint_rules[pattern] = {"Limit": limit, "Period": period, "Added": time.time(), "Type": kind}

    _persist_change(change)
    return True, "Success"


def clear_endpoint_rule(pattern: str) -> tuple[bool, str]:
    candidates = {(pattern or "").strip(), _norm(pattern), _norm_regex(pattern)}

    def change():
        for key in candidates:
            _endpoint_rules.pop(key, None)

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
        kind = rule.get("Type", "glob")
        if _matches(pattern, p, kind):
            score = _specificity(pattern, kind)
            if best_score is None or score > best_score:
                best = dict(rule)
                best["Pattern"] = pattern
                best_score = score
    return best


# --- Header block rules -----------------------------------------------------
def _header_rule_id(scope: str, mode: str, needle: str, header: str = "") -> str:
    """Canonical id so the same rule can't be added twice and is easy to remove."""
    return f"{header.lower()}|{scope}|{mode}|{needle.lower()}"


def get_header_rules() -> dict:
    _maybe_reload()
    return {k: dict(v) for k, v in _header_rules.items()}


def add_header_rule(scope: str, mode: str, needle: str, note: str = "", header: str = "") -> tuple[bool, str]:
    scope = (scope or "either").strip().lower()
    mode = (mode or "contains").strip().lower()
    needle = (needle or "").strip()
    header = (header or "").strip()
    if scope not in HEADER_RULE_SCOPES:
        return False, f"Scope must be one of: {', '.join(HEADER_RULE_SCOPES)}"
    if mode not in HEADER_RULE_MODES:
        return False, f"Mode must be one of: {', '.join(HEADER_RULE_MODES)}"
    if not needle:
        return False, "Empty match text"
    if mode == "regex" and not valid_regex(needle):
        return False, "Invalid regular expression"
    # Targeting a specific header means we match its VALUE.
    if header:
        scope = "value"
    rule_id = _header_rule_id(scope, mode, needle, header)
    if rule_id not in _header_rules and len(_header_rules) >= config.MAX_HEADER_RULES:
        return False, "Too many header rules"

    def change():
        _header_rules[rule_id] = {
            "Header": header,
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


@lru_cache(maxsize=512)
def _compile_header_regex(needle: str):
    return re.compile(needle, re.IGNORECASE)


def _header_field_matches(mode: str, needle: str, target: str) -> bool:
    target = target or ""
    if mode == "regex":
        try:
            return _compile_header_regex(needle).search(target) is not None
        except re.error:
            return False
    target_lower = target.lower()
    needle_lower = needle.lower()
    if mode == "exact":
        return target_lower == needle_lower
    return needle_lower in target_lower  # contains


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
        needle = str(rule.get("Needle", ""))
        target_header = str(rule.get("Header", "")).lower()
        if not needle:
            continue
        for name, value in pairs:
            if target_header:
                # Rule targets one specific header: match only that header's value.
                if name.lower() != target_header:
                    continue
                if _header_field_matches(mode, needle, value):
                    hit = dict(rule)
                    hit["Id"] = rule_id
                    hit["MatchedHeader"] = name
                    hit["MatchedField"] = "value"
                    hit["MatchedText"] = value
                    return hit
                continue
            key_hit = scope in ("key", "either") and _header_field_matches(mode, needle, name)
            value_hit = scope in ("value", "either") and _header_field_matches(mode, needle, value)
            if key_hit or value_hit:
                hit = dict(rule)
                hit["Id"] = rule_id
                hit["MatchedHeader"] = name
                # Which side tripped it, and the offending text (the caller redacts secrets).
                hit["MatchedField"] = "key" if key_hit else "value"
                hit["MatchedText"] = name if key_hit else value
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
    for key in [k for k, v in _trusted_devices.items() if float(v.get("Expires", 0)) < now]:
        _trusted_devices.pop(key, None)
    # Throttle-bypass entries with a set expiry (Expires > 0) that has lapsed.
    for key in [k for k, v in _throttle_bypass_ips.items() if 0 < float(v.get("Expires", 0)) < now]:
        _throttle_bypass_ips.pop(key, None)


# --- Trusted devices --------------------------------------------------------
def _hash_device_token(token: str) -> str:
    # Stored hashed so a leaked data file can't be used to forge a trusted device.
    return hashlib.sha256((token or "").encode()).hexdigest()


def create_trusted_device(ip: str, user_agent: str) -> str:
    """Mint a trusted-device token (returned in clear; only its hash is stored)."""
    token = secrets.token_urlsafe(32)

    def change():
        _trusted_devices[_hash_device_token(token)] = {
            "Expires": time.time() + config.TRUSTED_DEVICE_DURATION,
            "IP": str(ip)[:64],
            "UserAgent": str(user_agent)[:300],
            "Added": time.time(),
        }
        _prune_expirables()

    _persist_change(change)
    return token


def is_trusted_device(token: str) -> bool:
    """Whether a device token is currently trusted (valid + unexpired)."""
    if not token:
        return False
    _maybe_reload()
    entry = _trusted_devices.get(_hash_device_token(token))
    return bool(entry) and time.time() < float(entry.get("Expires", 0))


def get_trusted_device_count() -> int:
    _maybe_reload()
    now = time.time()
    return sum(1 for v in _trusted_devices.values() if time.time() < float(v.get("Expires", 0)) and now)


def revoke_trusted_devices() -> int:
    """Revoke every trusted device (e.g. after losing one). Returns how many were removed."""
    removed = {"n": 0}

    def change():
        removed["n"] = len(_trusted_devices)
        _trusted_devices.clear()

    _persist_change(change)
    return removed["n"]


# --- Persistence ------------------------------------------------------------
def _serialize_unlocked() -> dict:
    # Copies, not references: the caller JSON-serializes this blob after the
    # lock is released, and the live dicts are mutated in place by reloads.
    return {
        "Paused": _paused,
        "PausedSince": _paused_since,
        "PauseReason": _pause_reason,
        "ThrottleAll": _throttle_all,
        "ThrottleAllSince": _throttle_all_since,
        "ThrottleAllReason": _throttle_all_reason,
        "SessionEpoch": _session_epoch,
        "Settings": {k: v["value"] for k, v in _settings.items()},
        "SettingsUpdated": {k: v["updated"] for k, v in _settings.items()},
        "ThrottleBypassIps": {k: dict(v) for k, v in _throttle_bypass_ips.items()},
        "EndpointBlocks": {k: dict(v) for k, v in _endpoint_blocks.items()},
        "EndpointRules": {k: dict(v) for k, v in _endpoint_rules.items()},
        "HeaderRules": {k: dict(v) for k, v in _header_rules.items()},
        "InvalidationTokens": dict(_invalidation_tokens),
        "TwoFACodes": dict(_two_fa_codes),
        "Challenges": dict(_challenges),
        "TrustedDevices": {k: dict(v) for k, v in _trusted_devices.items()},
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
