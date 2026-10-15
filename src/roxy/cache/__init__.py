"""The response cache: keys, policy, the memory and cache.db tiers, stale-while-revalidate and key spread.

What this is
    The package behind `ctx.cache` (`service.CacheService`, DESIGN 11.2). It decides which requests share a stored
    Roblox answer, keeps those answers in each worker's memory and in the shared cache.db, serves them (HIT,
    REVALIDATING, STALE, COALESCED), refreshes them in the background, and purges them fleet-wide.

Why it exists
    The cache is the only protection against Roblox rate limits that works no matter how many different callers
    ask for the same thing (plan 2.5). v1's version leaked purges between workers, evicted the hottest keys
    first, served stale data only after a failed call, and could be poisoned through its key format; this
    package is the v2 replacement (parity rows 52 to 67).

How it works
    `keys.py` builds the key, `policy.py` decides what is cacheable and for how long, `store.py` holds entries,
    `swr.py` runs background refreshes, `spread.py` finds keys that split on a cache buster, and `service.py`
    ties them to the request flow, with `roxy/upstream/singleflight.py` making sure one fetch per key runs at a
    time across all workers. `testing.py` holds the fakes the cache tests (and other packages' tests) use.

What to read next
    `roxy/cache/keys.py`, then `roxy/cache/policy.py` and `roxy/cache/service.py`.
"""
