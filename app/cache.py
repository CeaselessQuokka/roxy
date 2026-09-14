"""Cached upstream responses — answering a repeat request without asking Roblox.

The problem this exists for: a single Roblox experience polling one endpoint
(games.roblox.com/v1/games/votes?universeIds=...) generates hundreds of requests
for an answer that does not change between them. Throttling cannot fix it,
because a Roblox game reaches us from hundreds of game-server IPs and every
per-IP limit is applied to a fresh IP. Roblox, meanwhile, sees ONE proxy asking
the same question hundreds of times and rate-limits us for it.

A cache fixes exactly that shape of traffic: the first caller pays for the
upstream request, everyone asking the same question inside the TTL is answered
from what we already hold, and Roblox sees one request instead of hundreds.

Where the bytes live
--------------------
Two tiers, because the two failure modes pull in opposite directions.

  Memory (per worker).  An LRU of the hottest entries. Zero I/O, so the flood
      case — the same key over and over — costs a dict lookup. Deliberately
      SMALL: this is the tier that can OOM the box, so it is capped by entry
      count AND by total bytes, and it is per worker (4 workers = 4 copies).

  Disk (shared by every worker).  The "mass JSON file", split into
      config.CACHE_SHARDS files under config.CACHE_DIR. Sharding is the whole
      trick: a single file would have to be parsed in full to answer one lookup
      and rewritten in full to store one entry, so a 32 MB cache would cost
      32 MB of parsing per request — the cache would use more memory than it
      saves. One shard is a sixteenth of that, chosen by the key's hash, so both
      the read and the write stay small and two workers writing different keys
      usually don't even contend on the same lock.

Nothing here is precious. Every file can be deleted at any moment; the only
consequence is that the next request for each key goes upstream once.

How a lookup avoids touching the disk at all
--------------------------------------------
Each worker remembers, per shard, the set of keys that shard held and the mtime
it saw. If the file has not changed and the key is not in that set, the answer
is "miss" with no parse. That matters because a MISS is the common case for
anything that is not being flooded, and paying a file parse for every miss would
make the cache a tax on ordinary traffic instead of a saving.

Why one caller's answer may be given to another
-----------------------------------------------
Because there is only ever one answer. Roxy proxies UNAUTHENTICATED requests
only — it rejects any request carrying a Roblox session cookie before this
module is reached (see index._detect_auth_attempt), and it sends its own fixed
headers upstream rather than the caller's. So two requests with the same method,
path, query and body get the same bytes from Roblox no matter who asked, and the
cache key needs nothing about the caller in it. If Roxy ever gained
authenticated proxying, this assumption would have to be revisited first.

Bounded three ways, like every other store here
-----------------------------------------------
Entry count, total bytes, and TTL — see config.CACHE_*. A count cap alone says
nothing about size, a byte cap alone lets one quiet hour pin stale data, and a
TTL alone is unbounded under a flood. A response larger than cache_max_body is
NOT stored (as opposed to stored truncated): half a JSON body served as though
it were whole is worse than no cache at all.
"""

import config
import hashlib
import json
import os
import threading
import time
from collections import OrderedDict

import runtime
from lockfile import LockedJSON

# --- Shard files -------------------------------------------------------------
# One LockedJSON per shard, created on first use. The key's hash picks the
# shard, so a hot key always lands in the same file and the spread is even.
_shards: dict = {}
_shards_lock = threading.Lock()

# Small shared file holding per-shard counts/bytes, so the dashboard can describe
# the store without parsing every shard on every poll.
_meta = LockedJSON(lambda: os.path.join(config.CACHE_DIR, "meta.json"))

SHARD_NAMES = tuple(f"{i:x}" for i in range(config.CACHE_SHARDS))


def _shard_path(name: str) -> str:
    return os.path.join(config.CACHE_DIR, f"shard_{name}.json")


def _shard(name: str) -> LockedJSON:
    with _shards_lock:
        store = _shards.get(name)
        if store is None:
            store = _shards[name] = LockedJSON(lambda n=name: _shard_path(n))
        return store


def _shard_of(entry_id: str) -> str:
    """Which shard a key lives in. First hex nibble of the id, so the spread is
    uniform and stable across workers and restarts."""
    return f"{int(entry_id[0], 16) % config.CACHE_SHARDS:x}"


# --- Per-worker memory tier --------------------------------------------------
# LRU. Guarded by a plain thread lock: no file I/O happens under it, so the hot
# path is a dict move plus a couple of integer updates.
_mem_lock = threading.Lock()
_mem = OrderedDict()
_mem_bytes = 0

# Per-shard key index: shard -> {"MTime": float, "Keys": set}. Lets a miss be
# answered without parsing the shard file (see the module docstring).
_index_lock = threading.Lock()
_index = {}

# Hit counters not yet written back to disk. A hit must not cost a shard
# rewrite — that would make the cheap path the expensive one — so per-entry hit
# accounting is buffered and folded in on an interval.
_hits_lock = threading.Lock()
_pending_hits = {}
_last_hit_flush = 0.0
HIT_FLUSH_INTERVAL = 15.0  # Seconds between folding buffered hit counts into the shards.
MAX_PENDING_HITS = 5000  # Bound the buffer itself; past this the oldest deltas are dropped.

# In-flight fetches, for request coalescing (see begin_fetch).
_inflight_lock = threading.Lock()
_inflight = {}

# --- Disk-tier health --------------------------------------------------------
# LockedJSON.update() swallows an OSError and quietly applies the change to a
# throwaway dict so the request still flows. That is the right call for a
# counter — but for the cache it means a directory the service cannot write
# turns the shared store into four private in-memory ones, the hit rate
# collapses to whatever one worker manages on its own, and NOTHING anywhere
# says so. The dashboard showed "0 stored responses" next to a Stores counter
# climbing, which is a contradiction with no explanation attached.
#
# So every store confirms its own write landed, and what it finds is reported.
_health_lock = threading.Lock()
_health = {"Writes": 0, "Failures": 0, "LastWriteAt": 0.0, "LastError": "", "LastErrorAt": 0.0}


def _record_write(ok: bool, error: str = ""):
    with _health_lock:
        if ok:
            _health["Writes"] += 1
            _health["LastWriteAt"] = time.time()
        else:
            _health["Failures"] += 1
            _health["LastError"] = str(error)[:300]
            _health["LastErrorAt"] = time.time()


def disk_status() -> dict:
    """Whether the shared disk tier is actually usable, and what went wrong.

    Checked rather than assumed: the failure mode this exists for is silent by
    construction, and "is the directory writable?" is one stat call.
    """
    directory = config.CACHE_DIR
    exists = os.path.isdir(directory)
    writable = False
    error = ""
    try:
        if exists:
            writable = os.access(directory, os.W_OK | os.X_OK)
        else:
            # Not created yet is normal before the first store; what matters is
            # whether its parent would let us create it.
            parent = os.path.dirname(directory.rstrip("/")) or "/"
            writable = os.path.isdir(parent) and os.access(parent, os.W_OK | os.X_OK)
    except OSError as problem:
        error = f"{type(problem).__name__}: {problem}"
    with _health_lock:
        health = dict(_health)
    shards = 0
    try:
        if exists:
            shards = sum(1 for name in os.listdir(directory) if name.startswith("shard_") and name.endswith(".json"))
    except OSError:
        pass
    return {
        "Dir": directory,
        "Exists": exists,
        "Writable": bool(writable),
        "ShardFiles": shards,
        "Error": error or health["LastError"],
        "LastErrorAt": health["LastErrorAt"],
        "LastWriteAt": health["LastWriteAt"],
        "Writes": health["Writes"],
        "Failures": health["Failures"],
        # The one sentence the dashboard needs: is the shared store working?
        # A past failure does not count against it once a write has succeeded
        # since — otherwise fixing the permissions leaves the warning up until
        # the next restart, and a warning that will not clear gets ignored.
        "OK": bool(writable) and (health["Failures"] == 0 or health["LastWriteAt"] >= health["LastErrorAt"]),
    }

# Statuses that may be cached when error caching is switched on. 429 and 5xx are
# deliberately absent: they are transient upstream failures, and caching one
# would pin the outage in place long after Roblox had recovered.
CACHEABLE_ERROR_STATUSES = (400, 403, 404, 410)


def _setting(name: str, default):
    return runtime.get_setting(name, default)


def is_enabled() -> bool:
    return bool(_setting("cache_enabled", 1))


def disk_enabled() -> bool:
    return bool(_setting("cache_disk_enabled", 1))


def _limits() -> dict:
    return {
        "MaxEntries": max(0, int(_setting("cache_max_entries", config.CACHE_MAX_ENTRIES))),
        "MaxBytes": max(0, int(_setting("cache_max_bytes", config.CACHE_MAX_BYTES))),
        "MaxBody": max(0, int(_setting("cache_max_body", config.CACHE_MAX_BODY))),
        "MemEntries": max(0, int(_setting("cache_memory_entries", config.CACHE_MEMORY_ENTRIES))),
        "MemBytes": max(0, int(_setting("cache_memory_bytes", config.CACHE_MEMORY_BYTES))),
        "TTL": max(0, int(_setting("cache_ttl_seconds", config.CACHE_TTL_SECONDS))),
        "ErrorTTL": max(0, int(_setting("cache_error_ttl_seconds", config.CACHE_ERROR_TTL_SECONDS))),
        "Stale": max(0, int(_setting("cache_stale_seconds", config.CACHE_STALE_SECONDS))),
    }


# --- Keys --------------------------------------------------------------------
def canonical_query(params, ignored=frozenset()) -> str:
    """A stable text form of the query string.

    Parameter NAMES are sorted so ?a=1&b=2 and ?b=2&a=1 are one cache entry;
    repeated VALUES keep their order, because ?ids=1&ids=2 and ?ids=2&ids=1 can
    legitimately come back differently ordered and collapsing them would hand a
    caller someone else's ordering.

    `ignored` names parameters left out of the key entirely — see
    runtime.get_cache_ignored_params. A caller that appends a timestamp to every
    request otherwise produces a brand-new key every time, so the cache fills up
    and never once serves anything out of it.
    """
    if not params:
        return ""
    parts = []
    for name in sorted(params):
        if name in ignored:
            continue
        value = params[name]
        values = value if isinstance(value, (list, tuple)) else [value]
        for item in values:
            parts.append(f"{name}={item}")
    return "&".join(parts)


def ignored_params() -> frozenset:
    try:
        return runtime.cache_ignored_param_names()
    except Exception:
        return frozenset()


def readable_key(method: str, path: str, params, body=None) -> str:
    """The human-facing key, exactly what the dashboard shows.

    The host is lowercased (hosts are case-insensitive, and GAMES.roblox.com is
    the same upstream as games.roblox.com); the path is not, because Roblox
    paths are case-sensitive.
    """
    host, _, rest = (path or "").partition("/")
    normalized = f"{host.lower()}/{rest}" if rest else host.lower()
    key = f"{(method or 'GET').upper()} {normalized}"
    query = canonical_query(params, ignored_params())
    if query:
        key += f"?{query}"
    if body:
        # A POST body can be megabytes; its fingerprint is what identifies the
        # request, and it is a fingerprint rather than the bytes so the key stays
        # short and no request body lands in the dashboard's key column.
        raw = body if isinstance(body, (bytes, bytearray)) else str(body).encode("utf-8", "replace")
        key += f" #{hashlib.sha256(raw).hexdigest()[:12]}"
    return key


def key_id(readable: str) -> str:
    """The storage id for a readable key. Short, stable, filename-safe."""
    return hashlib.sha256(readable.encode("utf-8", "replace")).hexdigest()[:24]


def make_key(method: str, path: str, params, body=None) -> dict:
    """Everything the rest of the module needs to address one cache slot.

    `Params` rides along so a stored entry can be re-fetched later (the admin's
    Refresh button) without parsing them back out of the display key — which
    would quietly corrupt any value containing an "=" or an "&".
    """
    readable = readable_key(method, path, params, body)
    skip = ignored_params()
    kept = {}
    for name, value in (params or {}).items():
        if name in skip:
            continue  # Not part of the key, so not part of what a refetch sends.
        values = value if isinstance(value, (list, tuple)) else [value]
        kept[str(name)] = [str(item) for item in values]
    return {
        "Id": key_id(readable),
        "Key": readable,
        "Path": path,
        "Method": (method or "GET").upper(),
        "Params": kept,
    }


# --- Policy ------------------------------------------------------------------
def method_allowed(method: str) -> bool:
    """Which verbs may be cached.

    GET always. POST only when explicitly enabled: a POST is a write by
    convention, and although Roblox uses several of them as batch lookups,
    caching one that ISN'T is how a cache starts answering a mutation with
    yesterday's result.
    """
    method = (method or "").upper()
    if method == "GET":
        return True
    return method == "POST" and bool(_setting("cache_post_requests", 0))


def ttl_for(path: str, upstream_status, successful: bool) -> tuple:
    """How long this response may be cached, and which rule decided it.

    Returns (seconds, rule_label). 0 means "do not cache". A per-endpoint rule
    always wins over the default — including a rule of 0, which is how a single
    endpoint is excluded from caching entirely.
    """
    rule = runtime.match_cache_rule(path)
    if rule is not None:
        return max(0, int(rule.get("TTL", 0) or 0)), str(rule.get("Pattern", ""))
    limits = _limits()
    if successful:
        return limits["TTL"], ""
    try:
        status = int(upstream_status)
    except (TypeError, ValueError):
        return 0, ""
    if status in CACHEABLE_ERROR_STATUSES:
        return limits["ErrorTTL"], ""
    return 0, ""


def wants_fresh(headers) -> bool:
    """Whether the caller asked to skip the cache.

    Off by default, and that default is deliberate: honoring Cache-Control from
    the request hands the caller who is flooding us a one-header way around the
    very thing stopping them from reaching Roblox. It exists for the admin who
    wants a cooperative integration to be able to force a refresh.
    """
    if not _setting("cache_respect_no_cache", 0):
        return False
    try:
        control = (headers.get("Cache-Control") or "").lower()
    except Exception:
        return False
    return "no-cache" in control or "no-store" in control


# --- Entry helpers -----------------------------------------------------------
def _entry_bytes(entry: dict) -> int:
    """What this record actually costs once serialized. Measured rather than
    estimated, because the byte budget is the ceiling that binds and it has to
    be enforced against real size, not against a character count of the body."""
    try:
        return len(json.dumps(entry, separators=(",", ":"), default=str).encode("utf-8", "replace"))
    except (TypeError, ValueError):
        return config.CACHE_MAX_BODY


def age_of(entry: dict, now: float = None) -> float:
    return max(0.0, (now if now is not None else time.time()) - float(entry.get("StoredAt", 0) or 0))


def is_fresh(entry: dict, now: float = None) -> bool:
    return float(entry.get("ExpiresAt", 0) or 0) > (now if now is not None else time.time())


def is_servable_stale(entry: dict, now: float = None) -> bool:
    """Whether an EXPIRED entry may still be served because the upstream just
    failed. A stale vote count beats an error for a caller that only wants a
    number, and it is the difference between "Roblox rate-limited us" being a
    visible outage and being invisible."""
    grace = _limits()["Stale"]
    if not grace:
        return False
    now = now if now is not None else time.time()
    return float(entry.get("ExpiresAt", 0) or 0) + grace > now


# --- Memory tier -------------------------------------------------------------
def _mem_get(entry_id: str):
    with _mem_lock:
        entry = _mem.get(entry_id)
        if entry is not None:
            _mem.move_to_end(entry_id)
        return entry


def _mem_put(entry_id: str, entry: dict):
    """Insert into the LRU, evicting oldest-first until both ceilings hold."""
    global _mem_bytes
    limits = _limits()
    size = int(entry.get("Bytes", 0) or 0)
    with _mem_lock:
        existing = _mem.pop(entry_id, None)
        if existing is not None:
            _mem_bytes -= int(existing.get("Bytes", 0) or 0)
        if not limits["MemEntries"] or not limits["MemBytes"] or size > limits["MemBytes"]:
            _mem_bytes = max(0, _mem_bytes)
            return  # Memory tier switched off, or one entry that would fill it alone.
        _mem[entry_id] = entry
        _mem_bytes += size
        while _mem and (len(_mem) > limits["MemEntries"] or _mem_bytes > limits["MemBytes"]):
            _, dropped = _mem.popitem(last=False)
            _mem_bytes -= int(dropped.get("Bytes", 0) or 0)
        _mem_bytes = max(0, _mem_bytes)


def _mem_drop(entry_id: str):
    global _mem_bytes
    with _mem_lock:
        dropped = _mem.pop(entry_id, None)
        if dropped is not None:
            _mem_bytes = max(0, _mem_bytes - int(dropped.get("Bytes", 0) or 0))


def _mem_clear():
    global _mem_bytes
    with _mem_lock:
        _mem.clear()
        _mem_bytes = 0


def memory_state() -> dict:
    with _mem_lock:
        return {"Count": len(_mem), "Bytes": _mem_bytes}


# --- Shard index -------------------------------------------------------------
def _shard_signature(shard: str):
    """A value that changes whenever a shard file's contents could have changed.

    Nanosecond mtime AND size, not the float mtime this used to compare. Two
    reasons, both of which produced a key that was on disk being reported as
    absent — a MISS on an entry we were holding all along:

      Granularity. A float mtime can round to the same value for two writes in
      the same second, and four workers writing sixteen shards hit that
      constantly. The nanosecond field does not, and the size is a second
      witness for the rare case where it somehow did.

      Staleness. See _index_remember: the signature has to be taken BEFORE the
      read it describes, never after.
    """
    try:
        stat = os.stat(_shard_path(shard))
        return (stat.st_mtime_ns, stat.st_size)
    except OSError:
        return (0, 0)


def _index_says_absent(shard: str, entry_id: str) -> bool:
    """True when this worker can prove the key is not on disk without a parse."""
    with _index_lock:
        cached = _index.get(shard)
    if not cached:
        return False
    if cached["Signature"] != _shard_signature(shard):
        return False  # Someone wrote to the shard; what we remember may be short.
    return entry_id not in cached["Keys"]


def _index_remember(shard: str, keys, signature=None):
    """Remember which keys a shard held, against the signature it had AT THE TIME.

    `signature` must be sampled BEFORE the read that produced `keys`. Sampling
    it afterwards records a newer file against an older key set, so a key
    another worker added in between is then treated as proven-absent until the
    shard happens to change again — which, for a quiet shard, can be a very long
    time. That is a cached entry that exists and is never once served.
    """
    with _index_lock:
        _index[shard] = {
            "Signature": _shard_signature(shard) if signature is None else signature,
            "Keys": set(keys),
        }


def _index_forget(shard: str = None):
    with _index_lock:
        if shard is None:
            _index.clear()
        else:
            _index.pop(shard, None)


# --- Pruning -----------------------------------------------------------------
def _prune(records: dict, now: float, max_entries: int, max_bytes: int) -> int:
    """Apply the per-shard ceilings in place: expired first, then oldest-first.

    Returns how many entries were dropped, so eviction pressure is a number the
    admin can see rather than something that silently happens.
    """
    removed = 0
    for key in [k for k, r in records.items() if not isinstance(r, dict) or float(r.get("ExpiresAt", 0) or 0) <= now]:
        records.pop(key, None)
        removed += 1
    ordered = sorted(records.items(), key=lambda kv: float(kv[1].get("StoredAt", 0) or 0))
    while len(ordered) > max_entries:
        key, _ = ordered.pop(0)
        records.pop(key, None)
        removed += 1
    total = sum(int(r.get("Bytes", 0) or 0) for _, r in ordered)
    while ordered and total > max_bytes:
        key, record = ordered.pop(0)
        total -= int(record.get("Bytes", 0) or 0)
        records.pop(key, None)
        removed += 1
    return removed


def _shard_budget() -> tuple:
    """The per-shard slice of the global ceilings. Keys hash uniformly, so an
    even split is the right approximation and it keeps every prune O(one shard)
    instead of needing a global view no single write can afford."""
    limits = _limits()
    shards = max(1, config.CACHE_SHARDS)
    return (
        max(1, limits["MaxEntries"] // shards) if limits["MaxEntries"] else 0,
        max(1, limits["MaxBytes"] // shards) if limits["MaxBytes"] else 0,
    )


def _write_meta(shard: str, records: dict):
    """Record this shard's size in the shared meta file.

    Exists so the dashboard can say how big the cache is without parsing all
    sixteen shards on every poll — the poll runs every few seconds and the
    shards are the one thing here that is allowed to be large.
    """
    count = len(records)
    total = sum(int(r.get("Bytes", 0) or 0) for r in records.values() if isinstance(r, dict))
    oldest = min((float(r.get("StoredAt", 0) or 0) for r in records.values() if isinstance(r, dict)), default=0.0)

    def mutate(data):
        shards = data.setdefault("Shards", {})
        if not isinstance(shards, dict):
            shards = data["Shards"] = {}
        shards[shard] = {"Count": count, "Bytes": total, "Oldest": oldest, "At": time.time()}

    try:
        _meta.update(mutate)
    except Exception:
        pass  # Only the dashboard's size readout suffers.


# --- Read --------------------------------------------------------------------
def get(key: dict):
    """The stored entry for a key, fresh or stale, or None.

    Freshness is the CALLER's decision (is_fresh / is_servable_stale), because
    "expired" and "unusable" are not the same thing here: an expired entry is
    exactly what should be served when the upstream has just refused us.
    """
    if not key:
        return None
    entry_id = key["Id"]
    entry = _mem_get(entry_id)
    if entry is not None:
        return entry
    if not disk_enabled():
        return None
    shard = _shard_of(entry_id)
    if _index_says_absent(shard, entry_id):
        return None
    # Sampled first, so a write that lands during the read is recorded as a
    # signature mismatch (re-read next time) rather than as fresh knowledge.
    signature = _shard_signature(shard)
    try:
        records = _shard(shard).read().get("Records")
    except Exception:
        return None
    if not isinstance(records, dict):
        _index_remember(shard, (), signature)
        return None
    _index_remember(shard, records.keys(), signature)
    entry = records.get(entry_id)
    if not isinstance(entry, dict):
        return None
    _mem_put(entry_id, entry)  # Promote: a key read once is likely to be read again.
    return entry


def record_hit(entry_id: str):
    """Count a hit against an entry without paying a shard rewrite for it."""
    global _last_hit_flush
    now = time.time()
    with _hits_lock:
        pending = _pending_hits.setdefault(entry_id, {"Hits": 0, "LastHit": 0.0})
        pending["Hits"] += 1
        pending["LastHit"] = now
        while len(_pending_hits) > MAX_PENDING_HITS:
            _pending_hits.pop(next(iter(_pending_hits)), None)
        due = now - _last_hit_flush >= HIT_FLUSH_INTERVAL
        if due:
            _last_hit_flush = now
    if due:
        flush_hits()


def flush_hits():
    """Fold buffered hit counts into the shard files (one write per shard)."""
    global _last_hit_flush
    with _hits_lock:
        batch = dict(_pending_hits)
        _pending_hits.clear()
        _last_hit_flush = time.time()
    if not batch or not disk_enabled():
        return
    by_shard = {}
    for entry_id, delta in batch.items():
        by_shard.setdefault(_shard_of(entry_id), {})[entry_id] = delta
    for shard, deltas in by_shard.items():

        def mutate(data, deltas=deltas):
            records = data.get("Records")
            if not isinstance(records, dict):
                return
            for entry_id, delta in deltas.items():
                entry = records.get(entry_id)
                if isinstance(entry, dict):
                    entry["Hits"] = int(entry.get("Hits", 0) or 0) + int(delta.get("Hits", 0) or 0)
                    entry["LastHit"] = max(float(entry.get("LastHit", 0) or 0), float(delta.get("LastHit", 0) or 0))

        try:
            _shard(shard).update(mutate)
        except Exception:
            pass  # Hit counts are bookkeeping; losing some never costs a response.


# --- Write -------------------------------------------------------------------
def store(key: dict, body, ttl: int, **fields):
    """Cache one upstream response. Returns the stored entry, or None.

    Refuses (rather than truncates) a body over cache_max_body: a JSON document
    cut in half is not a cheaper answer, it is a wrong one.
    """
    if not key or ttl <= 0 or not is_enabled():
        return None
    limits = _limits()
    text = body if isinstance(body, str) else ("" if body is None else str(body))
    if limits["MaxBody"] and len(text) > limits["MaxBody"]:
        return None
    now = time.time()
    entry = {
        "Id": key["Id"],
        "Key": key["Key"],
        "Path": key.get("Path", ""),
        "Method": key.get("Method", "GET"),
        "Params": key.get("Params", {}),
        "Body": text,
        "BodyLength": len(text),
        "StoredAt": now,
        "ExpiresAt": now + ttl,
        "TTL": int(ttl),
        "Hits": 0,
        "LastHit": 0.0,
        "Successful": bool(fields.get("successful", True)),
        "UpstreamStatus": fields.get("upstream_status", ""),
        "UpstreamMethod": fields.get("upstream_method", ""),
        "Rule": fields.get("rule", ""),
    }
    entry["Bytes"] = _entry_bytes(entry)
    _mem_put(key["Id"], entry)
    if not disk_enabled():
        return entry
    max_entries, max_bytes = _shard_budget()
    if not max_entries or not max_bytes:
        # A ceiling of zero means "hold nothing on disk". It must NOT mean "hold
        # everything": skipping the prune because there is no budget to prune
        # against is how a bounded store becomes an unbounded file.
        return entry
    shard = _shard_of(key["Id"])
    outcome = {"Evicted": 0, "Records": None}

    def mutate(data):
        records = data.setdefault("Records", {})
        if not isinstance(records, dict):
            records = data["Records"] = {}
        records[key["Id"]] = entry
        outcome["Evicted"] = _prune(records, now, max_entries, max_bytes)
        outcome["Records"] = dict(records)

    # Sampled before the write so the two can be compared afterwards.
    before = _shard_signature(shard)
    try:
        _shard(shard).update(mutate)
    except Exception as problem:
        _record_write(False, problem)
        return entry  # It is still in memory; the disk tier missing one entry is survivable.
    # LockedJSON reports success even when it fell back to mutating a throwaway
    # dict, so "did it raise?" is not the question. Nor is "does the file
    # exist?" — a shard written successfully last week still exists after a
    # store that failed today. A real write always changes the signature and a
    # failed one never does, which is the only reliable answer available here.
    # Without it, a cache directory the service cannot write looks, from every
    # counter on the dashboard, exactly like a working one.
    landed = _shard_signature(shard) != before
    _record_write(landed, "" if landed else f"{_shard_path(shard)} was not written (check permissions)")
    if outcome["Records"] is not None and landed:
        _index_remember(shard, outcome["Records"].keys())
        _write_meta(shard, outcome["Records"])
    if outcome["Evicted"]:
        try:
            import diagnostics

            diagnostics.log_cache_evictions(outcome["Evicted"])
        except Exception:
            pass
    return entry


# --- Coalescing --------------------------------------------------------------
def begin_fetch(key: dict) -> tuple:
    """Claim the right to fetch this key upstream.

    Returns (True, None) if this thread should go upstream, or (False, event) if
    another thread in this worker already is. Without it, N concurrent requests
    for one uncached key are N identical upstream calls — precisely the burst
    the cache exists to prevent, arriving in the one moment the cache is empty.
    Per worker rather than fleet-wide: a cross-process lease would put an flock
    on the hot path to save at most a 4x burst, and 4 is not the number that got
    us rate-limited.
    """
    if not key or not _setting("cache_coalesce", 1):
        return True, None
    with _inflight_lock:
        event = _inflight.get(key["Id"])
        if event is None:
            _inflight[key["Id"]] = threading.Event()
            return True, None
        return False, event


def end_fetch(key: dict):
    if not key:
        return
    with _inflight_lock:
        event = _inflight.pop(key["Id"], None)
    if event is not None:
        event.set()  # Release everyone waiting on this key at once.


def await_fetch(key: dict, event):
    """Wait (briefly) for whoever owns this fetch, then re-read the cache.

    The wait is bounded well under the upstream timeout, so a stuck upstream
    delays the owner and never the followers.
    """
    wait = max(0.0, float(_setting("cache_coalesce_wait_ms", config.CACHE_COALESCE_WAIT_MS)) / 1000.0)
    if wait and event is not None:
        event.wait(wait)
    entry = get(key)
    return entry if entry is not None and is_fresh(entry) else None


# --- Admin: browse, purge, inspect -------------------------------------------
def _all_records() -> dict:
    """Every entry on disk, keyed by id.

    Admin-only: this is the one operation that parses the whole cache, so it is
    never on a request path and never part of the dashboard's poll.
    """
    out = {}
    if not disk_enabled():
        return out
    for shard in SHARD_NAMES:
        if not os.path.exists(_shard_path(shard)):
            continue
        try:
            records = _shard(shard).read().get("Records")
        except Exception:
            continue
        if isinstance(records, dict):
            for entry_id, entry in records.items():
                if isinstance(entry, dict):
                    out[entry_id] = entry
    return out


# Bounds on the key-spread scan: it groups every entry in the store, and the
# point is to notice a runaway parameter, not to enumerate its values.
MAX_SPREAD_VALUES = 500
MIN_SPREAD_ENTRIES = 5  # Below this, "many keys, no hits" is just a quiet endpoint.

SORT_FIELDS = {
    "hits": lambda e: int(e.get("Hits", 0) or 0),
    "bytes": lambda e: int(e.get("Bytes", 0) or 0),
    "stored": lambda e: float(e.get("StoredAt", 0) or 0),
    "expires": lambda e: float(e.get("ExpiresAt", 0) or 0),
    "key": lambda e: str(e.get("Key", "")).lower(),
}


def _row(entry: dict, now: float) -> dict:
    """One entry WITHOUT its body — everything the browser table renders."""
    return {
        "Id": entry.get("Id", ""),
        "Key": entry.get("Key", ""),
        "Path": entry.get("Path", ""),
        "Method": entry.get("Method", ""),
        "Bytes": int(entry.get("Bytes", 0) or 0),
        "BodyLength": int(entry.get("BodyLength", 0) or 0),
        "Hits": int(entry.get("Hits", 0) or 0),
        "LastHit": float(entry.get("LastHit", 0) or 0),
        "StoredAt": float(entry.get("StoredAt", 0) or 0),
        "ExpiresAt": float(entry.get("ExpiresAt", 0) or 0),
        "TTL": int(entry.get("TTL", 0) or 0),
        "Age": age_of(entry, now),
        "Fresh": is_fresh(entry, now),
        "Rule": entry.get("Rule", ""),
        "Successful": bool(entry.get("Successful", True)),
        "UpstreamStatus": entry.get("UpstreamStatus", ""),
        "UpstreamMethod": entry.get("UpstreamMethod", ""),
    }


def list_entries(query: str = "", offset: int = 0, limit: int = 50, sort: str = "hits", order: str = "desc") -> dict:
    """A page of cache entries without their bodies, for the dashboard browser.

    Paged on the SERVER because the cache can hold thousands of entries whose
    bodies are the whole point of the store: shipping them all to a browser in
    order to render twenty rows would move megabytes per refresh.
    """
    flush_hits()  # So the Hits column is the current truth, not fifteen seconds old.
    now = time.time()
    records = _all_records()
    with _mem_lock:
        for entry_id, entry in _mem.items():
            records.setdefault(entry_id, entry)  # Memory-only entries (disk tier off) still list.
    needle = (query or "").strip().lower()
    rows = [_row(e, now) for e in records.values() if not needle or needle in str(e.get("Key", "")).lower()]
    rows.sort(key=lambda row: SORT_FIELDS.get(sort, SORT_FIELDS["hits"])(row), reverse=(order != "asc"))
    total = len(rows)
    offset = max(0, int(offset or 0))
    limit = max(1, min(int(limit or 50), config.CACHE_PAGE_MAX))
    return {
        "Total": total,
        "Offset": offset,
        "Limit": limit,
        "Entries": rows[offset : offset + limit],
        "Query": query or "",
        "Sort": sort,
        "Order": order,
        "FreshCount": sum(1 for row in rows if row["Fresh"]),
    }


def key_spread(limit: int = 25) -> list:
    """Endpoints that are filling the cache without ever being served from it.

    This is the diagnostic for the one failure that looks identical to success
    on every other number: a caller that appends a changing value to each
    request — a timestamp, a random cache-buster — makes every request a
    different key. Entries climb, Stores climbs, and the hit count stays at
    zero, because no two requests ever ask the same question.

    Grouping by method + path (query excluded) makes it obvious: one path with
    four hundred entries behind it and no hits is not a busy endpoint, it is one
    parameter that should not be part of the key. So the varying parameter is
    named too, which turns "why is this not working" into one click.
    """
    flush_hits()
    groups = {}
    records = _all_records()
    with _mem_lock:
        for entry_id, entry in _mem.items():
            records.setdefault(entry_id, entry)
    for entry in records.values():
        path = str(entry.get("Path", ""))
        key = f"{entry.get('Method', 'GET')} {path.split('?', 1)[0]}"
        group = groups.setdefault(
            key,
            {"Key": key, "Path": path.split("?", 1)[0], "Method": entry.get("Method", "GET"),
             "Entries": 0, "Hits": 0, "Bytes": 0, "Params": {}},
        )
        group["Entries"] += 1
        group["Hits"] += int(entry.get("Hits", 0) or 0)
        group["Bytes"] += int(entry.get("Bytes", 0) or 0)
        for name, values in (entry.get("Params") or {}).items():
            seen = group["Params"].setdefault(str(name), set())
            if len(seen) <= MAX_SPREAD_VALUES:
                seen.add("\u0000".join(str(v) for v in values))

    rows = []
    for group in groups.values():
        # A parameter with (nearly) as many distinct values as there are entries
        # is the one splitting them apart. Reported with its count so the admin
        # can judge it rather than take our word for it.
        varying = sorted(
            ({"Name": name, "Values": len(values)} for name, values in group["Params"].items()),
            key=lambda item: item["Values"],
            reverse=True,
        )
        top = varying[0] if varying else None
        rows.append(
            {
                "Key": group["Key"],
                "Path": group["Path"],
                "Method": group["Method"],
                "Entries": group["Entries"],
                "Hits": group["Hits"],
                "Bytes": group["Bytes"],
                "Varying": varying[:4],
                # Only flagged when a single parameter explains nearly all of the
                # spread AND the entries are not being reused. Two entries and no
                # hits is a quiet endpoint, not a problem.
                "Suspect": bool(
                    top
                    and group["Entries"] >= MIN_SPREAD_ENTRIES
                    and top["Values"] >= group["Entries"] * 0.8
                    and group["Hits"] <= group["Entries"] * 0.1
                ),
                "SuspectParam": top["Name"] if top else "",
            }
        )
    rows.sort(key=lambda row: (row["Suspect"], row["Entries"]), reverse=True)
    return rows[: max(1, int(limit))]


def get_entry(entry_id: str):
    """One entry WITH its body, for the inspector."""
    entry_id = str(entry_id or "")
    if not entry_id:
        return None
    entry = _mem_get(entry_id)
    if entry is None and disk_enabled():
        try:
            records = _shard(_shard_of(entry_id)).read().get("Records")
        except (ValueError, IndexError, OSError):
            records = None  # Malformed id, or the shard is unreadable: treat it as gone.
        entry = records.get(entry_id) if isinstance(records, dict) else None
    if not isinstance(entry, dict):
        return None
    view = dict(entry)
    # Fold in this worker's unflushed hits. The memory tier holds the entry
    # object itself and hit counts are only written back to the shard on an
    # interval, so an entry read straight out of memory would otherwise always
    # report zero hits — on exactly the entries being hit most.
    with _hits_lock:
        pending = _pending_hits.get(entry_id)
    if pending:
        view["Hits"] = int(view.get("Hits", 0) or 0) + int(pending.get("Hits", 0) or 0)
        view["LastHit"] = max(float(view.get("LastHit", 0) or 0), float(pending.get("LastHit", 0) or 0))
    view["Age"] = age_of(entry)
    view["Fresh"] = is_fresh(entry)
    view["ServableStale"] = is_servable_stale(entry)
    return view


def purge_entry(entry_id: str) -> bool:
    """Drop one entry everywhere. The next request for it goes upstream."""
    entry_id = str(entry_id or "")
    if not entry_id:
        return False
    _mem_drop(entry_id)
    with _hits_lock:
        _pending_hits.pop(entry_id, None)
    if not disk_enabled():
        return True
    try:
        shard = _shard_of(entry_id)
    except ValueError:
        return False  # Ids come from an admin request; a malformed one is a 400, not a 500.
    outcome = {"Records": None}

    def mutate(data):
        records = data.get("Records")
        if isinstance(records, dict):
            records.pop(entry_id, None)
            outcome["Records"] = dict(records)

    try:
        _shard(shard).update(mutate)
    except Exception:
        return False
    if outcome["Records"] is not None:
        _index_remember(shard, outcome["Records"].keys())
        _write_meta(shard, outcome["Records"])
    return True


def purge_matching(predicate) -> int:
    """Drop every entry `predicate(entry)` accepts. Returns how many went."""
    with _mem_lock:
        doomed = [k for k, entry in _mem.items() if predicate(entry)]
    for entry_id in doomed:
        _mem_drop(entry_id)
    if not disk_enabled():
        return len(doomed)
    removed = 0
    for shard in SHARD_NAMES:
        if not os.path.exists(_shard_path(shard)):
            continue
        outcome = {"Removed": 0, "Records": None}

        def mutate(data, outcome=outcome):
            records = data.get("Records")
            if not isinstance(records, dict):
                return
            gone = [k for k, entry in records.items() if isinstance(entry, dict) and predicate(entry)]
            for key in gone:
                records.pop(key, None)
            outcome["Removed"] = len(gone)
            outcome["Records"] = dict(records)

        try:
            _shard(shard).update(mutate)
        except Exception:
            continue
        removed += outcome["Removed"]
        if outcome["Records"] is not None:
            _index_remember(shard, outcome["Records"].keys())
            _write_meta(shard, outcome["Records"])
    return removed


def purge_pattern(pattern: str, kind: str = "glob") -> int:
    """Drop every entry whose PATH matches an endpoint pattern — the same glob /
    regex forms the block and rate rules use, so one mental model covers all of
    them."""
    pattern = runtime.normalize_pattern(pattern, kind)
    if not pattern:
        return 0
    return purge_matching(lambda entry: runtime.path_matches(pattern, str(entry.get("Path", "")), kind))


def purge_expired() -> int:
    now = time.time()
    return purge_matching(lambda entry: float(entry.get("ExpiresAt", 0) or 0) <= now)


def clear() -> int:
    """Empty the cache completely."""
    _mem_clear()
    with _hits_lock:
        _pending_hits.clear()
    removed = 0
    for shard in SHARD_NAMES:
        # Skip shards that were never written. Taking the lock on all sixteen
        # regardless would create sixteen empty files (and sixteen lock files)
        # every time an empty cache is cleared, which is most of the time.
        if not os.path.exists(_shard_path(shard)):
            continue
        outcome = {"Removed": 0}

        def mutate(data, outcome=outcome):
            records = data.get("Records")
            outcome["Removed"] = len(records) if isinstance(records, dict) else 0
            data.clear()

        try:
            _shard(shard).update(mutate)
        except Exception:
            continue
        removed += outcome["Removed"]
    _index_forget()
    try:
        _meta.update(lambda data: data.clear())
    except Exception:
        pass
    return removed


# --- Dashboard state ---------------------------------------------------------
def get_state() -> dict:
    """What the cache is holding, and against which ceilings.

    Reads the small meta file rather than the shards, so this is cheap enough to
    sit in the dashboard's regular poll.
    """
    limits = _limits()
    shards = {}
    try:
        stored = _meta.read().get("Shards")
        if isinstance(stored, dict):
            shards = {k: v for k, v in stored.items() if isinstance(v, dict)}
    except Exception:
        shards = {}
    count = sum(int(s.get("Count", 0) or 0) for s in shards.values())
    total = sum(int(s.get("Bytes", 0) or 0) for s in shards.values())
    oldest = min((float(s.get("Oldest", 0) or 0) for s in shards.values() if s.get("Oldest")), default=0.0)
    memory = memory_state()
    disk = disk_status()
    # "0 stored responses" next to a climbing Stores counter is a contradiction,
    # and it is what a broken disk tier looks like from here — the entries are
    # real, they are just in this worker's memory and nowhere else. Say so
    # rather than reporting a zero that reads as "nothing is being cached".
    memory_only = disk_enabled() and not disk["OK"]
    if memory_only and not count:
        count, total = memory["Count"], memory["Bytes"]
    return {
        "Enabled": is_enabled(),
        "DiskEnabled": disk_enabled(),
        "Disk": disk,
        # True when entries exist but only inside individual workers, so the
        # admin knows why the hit rate is a quarter of what it should be.
        "MemoryOnly": memory_only,
        "Entries": count,
        "Bytes": total,
        "MaxEntries": limits["MaxEntries"],
        "MaxBytes": limits["MaxBytes"],
        "MaxBody": limits["MaxBody"],
        "TTL": limits["TTL"],
        "ErrorTTL": limits["ErrorTTL"],
        "StaleGrace": limits["Stale"],
        "Memory": {
            "Count": memory["Count"],
            "Bytes": memory["Bytes"],
            "MaxEntries": limits["MemEntries"],
            "MaxBytes": limits["MemBytes"],
        },
        "Shards": config.CACHE_SHARDS,
        "OldestAt": oldest,
        "WindowSeconds": max(0.0, time.time() - oldest) if oldest else 0.0,
        "Dir": config.CACHE_DIR,
        "ServeThrottled": bool(_setting("cache_serve_throttled", 0)),
        "Coalesce": bool(_setting("cache_coalesce", 1)),
        "PostCached": bool(_setting("cache_post_requests", 0)),
        "RespectNoCache": bool(_setting("cache_respect_no_cache", 0)),
    }
