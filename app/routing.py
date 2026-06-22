"""Cross-worker request routing state.

Every proxied request (without a user-supplied token) picks ONE upstream method:
  - "roproxy": via games.roproxy.com (RoProxy's IPs)
  - "token":   to games.roblox.com with our .ROBLOSECURITY (our STATIC IP)
  - "rotate":  to games.roblox.com via the rotating proxy (DataImpulse's IPs)

Because there are multiple gunicorn workers, the safety-critical constraints —
the token's global request budget and RoProxy's cooldown — MUST be shared, or 4
workers would each independently burst our static IP and get it shadow-banned.

This module keeps that shared state in a tiny dedicated JSON file guarded by an
inter-process flock (separate from the big data file so the per-request
read-modify-write stays cheap). choose() atomically reads the state, picks a
method by weighted random among those currently available, and reserves the
pick — all under the lock — so the global budget/cooldowns are never exceeded.
"""

import config
import fcntl
import json
import os
import random
import tempfile
import time
from contextlib import contextmanager
from threading import Lock

import runtime

# Guards this process's writers; the flock guards across processes.
_io_lock = Lock()

METHODS = ("roproxy", "token", "rotate")


def _lock_path() -> str:
    return config.ROUTING_FILE + ".lock"


@contextmanager
def _interprocess_lock():
    directory = os.path.dirname(config.ROUTING_FILE) or "."
    os.makedirs(directory, exist_ok=True)
    lock_file = open(_lock_path(), "a+")
    try:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
        finally:
            lock_file.close()


def _load_unlocked() -> dict:
    try:
        with open(config.ROUTING_FILE, "r", encoding="utf-8") as file:
            data = json.load(file)
            if isinstance(data, dict):
                return data
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        pass
    return {}


def _write_unlocked(data: dict):
    directory = os.path.dirname(config.ROUTING_FILE) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".roxy_routing_", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as file:
            json.dump(data, file, separators=(",", ":"))
        os.replace(tmp_path, config.ROUTING_FILE)
    finally:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass


def _update(mutator):
    """Atomically read-modify-write the routing file. On disk failure, degrade to
    an in-memory decision so requests still flow (rare; surfaced via persistence
    health). Returns whatever the mutator returns."""
    with _io_lock:
        try:
            with _interprocess_lock():
                data = _load_unlocked()
                result = mutator(data)
                _write_unlocked(data)
                return result
        except OSError:
            return mutator({})


def _budget():
    limit = int(runtime.get_setting("token_budget_requests", config.TOKEN_BUDGET_REQUESTS))
    window = int(runtime.get_setting("token_budget_window", config.TOKEN_BUDGET_WINDOW))
    return limit, window


def _weights(available, token_used, limit):
    """Weighted preference among available methods. Below the danger zone the base
    weights apply; past it, the token's share shifts to Rotate and (increasingly,
    the deeper in) RoProxy, hitting zero token weight at the hard cap."""
    rw = float(runtime.get_setting("roproxy_weight", config.ROPROXY_WEIGHT))
    tw = float(runtime.get_setting("token_weight", config.TOKEN_WEIGHT))
    rotw = float(runtime.get_setting("rotate_weight", config.ROTATE_WEIGHT))
    danger = int(runtime.get_setting("token_danger_zone", config.TOKEN_DANGER_ZONE))

    base = {"roproxy": rw, "token": tw, "rotate": rotw}
    if token_used > danger and limit > danger:
        progress = min(1.0, (token_used - danger) / (limit - danger))  # 0 at danger → 1 at cap
        freed = tw * progress
        base["token"] = tw - freed
        roproxy_frac = 0.2 + 0.4 * progress  # RoProxy takes a growing share of the freed weight
        base["roproxy"] = rw + freed * roproxy_frac
        base["rotate"] = rotw + freed * (1.0 - roproxy_frac)
    if token_used >= limit:
        base["token"] = 0.0

    weights = [max(0.0, base[m]) for m in available]
    if sum(weights) <= 0:
        weights = [1.0] * len(available)  # all-zero (e.g. weights misconfigured) → uniform
    return weights


def choose(exclude: set, has_tokens: bool, rotate_enabled: bool):
    """Pick and reserve one available method, or None if none are available.

    `exclude` is the set of methods already tried this request (so we fall down
    the chain on failure). Returns (method, token_used) — token_used is the global
    in-window token count, for diagnostics/weighting visibility.
    """
    exclude = exclude or set()

    def mutate(data):
        now = time.time()
        limit, window = _budget()
        uses = [t for t in data.get("TokenUses", []) if isinstance(t, (int, float)) and t > now - window]
        token_used = len(uses)
        roproxy_until = float(data.get("RoProxyUntil", 0) or 0)
        rotate_until = float(data.get("RotateUntil", 0) or 0)

        available = []
        if "roproxy" not in exclude and now >= roproxy_until:
            available.append("roproxy")
        if "token" not in exclude and has_tokens and token_used < limit:
            available.append("token")
        if "rotate" not in exclude and rotate_enabled and now >= rotate_until:
            available.append("rotate")

        data["TokenUses"] = uses  # persist the prune regardless
        if not available:
            return (None, token_used)

        choice = random.choices(available, weights=_weights(available, token_used, limit), k=1)[0]
        if choice == "token":
            uses.append(now)
            data["TokenUses"] = uses
            token_used += 1
        elif choice == "roproxy":
            data["RoProxyUntil"] = now + int(runtime.get_setting("roproxy_cooldown", config.ROPROXY_COOLDOWN))
        # rotate: each request is a fresh exit IP, so no reservation/cooldown here
        # (failures are handled by record_rotate_result).
        return (choice, token_used)

    return _update(mutate)


def record_token_use():
    """Count a token-authenticated request that didn't go through choose() (e.g. a
    background token-validation ping) against the shared budget."""

    def mutate(data):
        now = time.time()
        _, window = _budget()
        uses = [t for t in data.get("TokenUses", []) if isinstance(t, (int, float)) and t > now - window]
        uses.append(now)
        data["TokenUses"] = uses
        return len(uses)

    return _update(mutate)


def record_rotate_result(ok: bool):
    """Track proxy-level rotate health. A streak of failures parks Rotate on a
    short cooldown so we stop hammering a down proxy."""

    def mutate(data):
        now = time.time()
        if ok:
            data["RotateFails"] = 0
        else:
            fails = int(data.get("RotateFails", 0)) + 1
            max_fails = config.ROTATE_MAX_FAILURES
            if fails >= max_fails:
                data["RotateUntil"] = now + int(runtime.get_setting("rotate_cooldown", config.ROTATE_COOLDOWN))
                data["RotateFails"] = 0
            else:
                data["RotateFails"] = fails
        return None

    _update(mutate)


def get_state() -> dict:
    """Live routing state for the dashboard (also prunes the token window)."""

    def mutate(data):
        now = time.time()
        limit, window = _budget()
        uses = [t for t in data.get("TokenUses", []) if isinstance(t, (int, float)) and t > now - window]
        data["TokenUses"] = uses
        return {
            "TokenUsed": len(uses),
            "TokenLimit": limit,
            "TokenWindow": window,
            "TokenResetIn": int(max(0, (min(uses) + window - now))) if uses else 0,
            "RoProxyResetIn": int(max(0, float(data.get("RoProxyUntil", 0) or 0) - now)),
            "RotateResetIn": int(max(0, float(data.get("RotateUntil", 0) or 0) - now)),
        }

    return _update(mutate)


def reset():
    """Clear all routing state (used by the admin 'force revalidate' / clear)."""
    _update(lambda data: data.clear())
