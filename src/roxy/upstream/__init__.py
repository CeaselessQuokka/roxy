"""The upstream package: how Roxy talks to Roblox without getting rate limited.

What this is
    Everything between "the cache missed" and "an HTTP call left through an egress": choosing the egress path
    (routing), pacing calls with shared token buckets (GCRA), honoring Roblox's Retry-After with fleet-wide
    cooldowns, circuit breakers, retries with jittered backoff, the CSRF handshake, the outcome policy that decides
    what each answer means, and Roxy's own internal calls (probes and lookups). `UpstreamService.fetch` is the one
    entry point the cache layer uses.

Why it exists
    v1 had no pacing (a count, not a rate), fell through to the other method on every 429 (amplification), never
    read Retry-After, and kept its cooldowns per worker, so Roblox rate limited it hundreds of times (plan 2.5,
    root causes R1 to R10). This package implements the fixes F2, F3, F4, F7, F8, F9, F11 and F12 of plan 2.5,
    with every limit shared by all workers through hot.db (plan C6).

How it works
    One caller miss goes through: `routing` (which egress, plan 7.2) -> `buckets.reserve` (one hot.db transaction
    that checks cooldowns and breakers and takes a slot in every bucket, plan 7.3) -> a short wait for the slot in
    the per-worker `queue` -> the egress client -> `status` classification and the 7.9 policy table -> `effects`
    (breaker, cooldown, rotator health, in one more transaction only when something changed) -> an
    `UpstreamResult` whose reason is a row of the 7.13 table (`messages`).

What to read next
    `roxy/upstream/buckets.py` (GCRA with a worked example), then `roxy/upstream/routing.py`,
    `roxy/upstream/status.py` and finally `roxy/upstream/service.py`, which ties them together.
"""
