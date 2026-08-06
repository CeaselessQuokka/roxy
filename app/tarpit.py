"""Slow-drip refusals for callers we are already turning away.

A request that is going to be refused can be held open for a while before the
error is written. For a SYNCHRONOUS client — which is what exploit HTTP wrappers
generally are — the hold is itself a rate limiter: they cannot issue the next
request until this one returns, so a caller that used to sit in a hot retry loop
against an instant 429 now manages one attempt per hold. Whether or not that
annoys anyone into dropping the proxy, the request rate falls either way.

Two things make this safe rather than a way to take ourselves down:

  Concurrency.  gunicorn serves `workers x threads` requests at once (4 x 4 = 16
      today) and a held request occupies one slot for the entire hold. So the
      number of simultaneous holds is capped FLEET-wide, in a flock-guarded file,
      not per worker — a per-worker cap of N would really be N x workers. Past
      the cap the caller gets the same instant refusal as before, so the worst
      case is "the tarpit stops working", never "the proxy stops working".

  Leases.  A slot is taken with a deadline, not a promise to give it back. A
      worker killed mid-hold (a deploy, an OOM, gunicorn's max_requests recycle)
      would otherwise leak its slot forever; instead the lease simply expires.

The sleep itself holds NO lock — neither the flock nor any in-process lock — so
a held request never blocks another worker's throttle accounting.

Which refusals are eligible is per-category and admin-controlled; see
config.TARPIT_CATEGORIES. Nothing about the response tells the caller they were
held: they get the byte-identical error they would have got instantly.
"""

import config
import diagnostics
import itertools
import os
import random
import runtime
import secrets
import threading
import time

from lockfile import LockedJSON

# Slot leases + per-IP arrival times. Written once on the way in and once on the
# way out of a hold, so its write rate is bounded by the concurrency cap.
_store = LockedJSON(lambda: config.TARPIT_FILE)

CATEGORIES = config.TARPIT_CATEGORIES

# Unique per (process, hold) so a lease can never be released by the wrong thread.
_lease_prefix = f"{os.getpid()}-{secrets.token_hex(3)}"
_lease_counter = itertools.count(1)


def _lease_id() -> str:
    return f"{_lease_prefix}-{next(_lease_counter)}-{threading.get_ident()}"


def _setting(name: str, default):
    return runtime.get_setting(name, default)


def is_enabled() -> bool:
    return bool(_setting("tarpit_enabled", 0))


def category_enabled(category: str) -> bool:
    """Whether this kind of refusal is eligible to be held."""
    if category not in CATEGORIES:
        return False
    return bool(_setting(f"tarpit_on_{category}", 0))


def enabled_categories() -> list:
    return [name for name in CATEGORIES if category_enabled(name)]


def _bounds() -> tuple[float, float]:
    low = float(_setting("tarpit_min_seconds", config.TARPIT_MIN_SECONDS))
    high = float(_setting("tarpit_max_seconds", config.TARPIT_MAX_SECONDS))
    if high < low:
        low, high = high, low  # Tolerate a min set above the max rather than raising.
    return low, high


def _pick_duration() -> float:
    """A randomised hold. Fixed delays are learnable — a client that knows the
    hold is exactly 15s can set a 1s timeout and never wait; a spread means the
    only way to avoid waiting is to stop sending."""
    low, high = _bounds()
    return random.uniform(low, high) if high > low else low


def _admit(ip: str, lease: str, hold_for: float, now: float) -> tuple[bool, float]:
    """One locked pass: reclaim expired leases, measure this caller's arrival gap,
    and take a slot if one is free.

    The gap is computed HERE, inside the shared file, rather than from per-worker
    memory. Four workers each remembering "when I last saw this IP" would each
    measure a gap four times too long; the shared arrival time measures the real
    interval between their requests no matter which worker handles them.

    Returns (admitted, seconds_since_this_IP's_previous_tarpitted_request).
    """
    limit = max(0, int(_setting("tarpit_max_concurrent", config.TARPIT_MAX_CONCURRENT)))

    def mutate(data):
        slots = data.setdefault("Slots", {})
        if not isinstance(slots, dict):
            slots = data["Slots"] = {}
        # A lease is a deadline, not a promise: whatever failed to release its
        # slot (killed worker, recycled worker) frees it by simply expiring.
        for key in [k for k, expires in list(slots.items()) if float(expires or 0) <= now]:
            slots.pop(key, None)

        arrivals = data.setdefault("Arrivals", {})
        if not isinstance(arrivals, dict):
            arrivals = data["Arrivals"] = {}
        previous = float(arrivals.get(ip, 0) or 0)
        gap = max(0.0, now - previous) if previous else 0.0
        arrivals[ip] = now
        # Bounded like every other IP-keyed map here: a spoofed-IP flood must not
        # be able to grow the file.
        if len(arrivals) > config.MAX_TARPIT_ARRIVALS:
            for key, _ in sorted(arrivals.items(), key=lambda kv: float(kv[1] or 0))[
                : len(arrivals) - config.MAX_TARPIT_ARRIVALS
            ]:
                arrivals.pop(key, None)

        if len(slots) >= limit:
            return (False, gap)
        # Grace on top of the planned hold so a slot outlives a slow release
        # rather than being handed out twice.
        slots[lease] = now + hold_for + config.TARPIT_SLOT_GRACE
        return (True, gap)

    return _store.update(mutate)


def _lease_landed(lease: str) -> bool:
    """Whether our lease is actually in the shared file.

    LockedJSON.update degrades to mutating a throwaway dict when the disk is
    unavailable. For the throttle counters that costs one uncoordinated request;
    here it would mean every worker believing it holds the only slot, i.e. the
    concurrency cap silently ceasing to exist — the one failure this whole design
    is built to prevent. So the tarpit fails CLOSED: if the lease didn't land,
    we don't hold. Costs one cheap read, on a path that runs at most a handful of
    times a second by construction.
    """
    slots = _store.read().get("Slots")
    return isinstance(slots, dict) and lease in slots


def _release(lease: str):
    _store.update(lambda data: (data.get("Slots") or {}).pop(lease, None))


def active_holds() -> int:
    """Slots currently leased across the fleet (expired leases don't count)."""
    now = time.time()
    slots = _store.read().get("Slots", {})
    if not isinstance(slots, dict):
        return 0
    return sum(1 for expires in slots.values() if float(expires or 0) > now)


def hold(ip: str, category: str) -> float:
    """Delay a refusal that is about to be returned. Returns the seconds held (0 if not).

    Call this immediately BEFORE building the error response, never while holding
    a lock, and never on a path that reaches Roblox.
    """
    if not is_enabled() or not category_enabled(category):
        return 0.0
    planned = _pick_duration()
    if planned <= 0:
        return 0.0
    lease = _lease_id()
    now = time.time()
    admitted, gap = _admit(ip, lease, planned, now)
    if admitted and not _lease_landed(lease):
        admitted = False  # Shared state is unavailable; hold nothing rather than everything.
    if not admitted:
        # At capacity: refuse instantly, exactly as before the tarpit existed.
        # Counted, because a rising number here is the signal that the cap (not
        # the caller) is what's limiting the tarpit.
        diagnostics.log_tarpit_skipped(ip, category, gap, now)
        return 0.0
    started = time.monotonic()
    try:
        time.sleep(planned)
    finally:
        held = time.monotonic() - started
        _release(lease)
    # Recorded against the ARRIVAL time, not the release time, so the measured
    # interval between a caller's requests isn't distorted by how long we held them.
    diagnostics.log_tarpit(ip, category, held, gap, now)
    return held


def get_state() -> dict:
    """Live tarpit configuration + capacity for the dashboard."""
    low, high = _bounds()
    limit = max(0, int(_setting("tarpit_max_concurrent", config.TARPIT_MAX_CONCURRENT)))
    active = active_holds()
    return {
        "Enabled": is_enabled(),
        "Categories": enabled_categories(),
        "AllCategories": list(CATEGORIES),
        "MinSeconds": low,
        "MaxSeconds": high,
        "MaxConcurrent": limit,
        "ActiveHolds": active,
        "SlotsFree": max(0, limit - active),
    }


def reset():
    """Drop every lease and arrival record (admin 'clear tarpit stats')."""
    _store.update(lambda data: data.clear())
