"""Cache settings: the catalog entries for group D of the settings catalog (plan 15.3 D).

What this is
    The `SettingSpec` declarations for every runtime setting that shapes Roxy's response cache: the master
    switch, lifetimes (TTL, stale-while-revalidate, stale-if-error), the size caps of the shared tier in
    `cache.db` and of each worker's memory tier, eviction and compression, request coalescing, POST caching,
    429 markers, the built-in rules and the TTL tuner, plus the request samples that recommendation previews
    replay. The module exports `SETTINGS: list[SettingSpec]`.

Why it exists
    The cache is Roxy's strongest defense against Roblox rate limits (429 responses): it is the only control
    that works no matter how many different callers ask for the same thing. Its knobs therefore need the
    clearest explanations in the catalog (plan principle P3, one declaration per setting, from which the
    API, validation, the settings editor, docs/SETTINGS.md and the LLM export are generated).

How it works
    Plain data, no logic. `roxy/config/catalog.py` imports `SETTINGS`, merges it with the other groups and
    checks it at import time. Conventions used here:
    - Defaults are the v2 defaults of plan 15.3 D, except `cache_memory_entries` and `cache_memory_bytes`,
      which use the lead's low-memory defaults (DESIGN.md section 0: the production box has about 900 MB of
      RAM, so 1000 entries and 16 MiB per worker instead of 2000 and 64 MiB).
    - Byte values are integers (16 MiB is 16777216); `_KIB`, `_MIB` and `_GIB` only make them readable.
    - A cap of 0 always means "hold nothing", never "unlimited", so every store stays bounded (plan P9).
    - `high_risk_if` marks values that effectively switch caching off, let callers bypass it, or can exhaust
      memory or disk. The default value is never high risk.
    - `related_recommendations` lists the plan 11.5 rules that may propose changing this key, plus rules that
      propose the same knob for one endpoint through a cache rule (shown so the admin sees the narrower fix
      first). SEC-DEFAULTS appears on every key that has a high-risk value, because it proposes restoring it.
    - `related_rules` names rule tables by their `RulesSnapshot` field names (DESIGN.md section 5).
    - `auto_apply_bounds` exists only where a recommendation proposes this exact key (CACHE-NEG,
      CACHE-PRESSURE) and moving it inside the bounds is harmless; the upper bounds stay below the
      high-risk thresholds.

What to read next
    `roxy/config/spec.py` (the field meanings), `roxy/config/catalog.py` (assembly and validation), then the
    code that reads these values: `roxy/cache/policy.py`, `roxy/cache/store.py`, `roxy/cache/swr.py` and
    `roxy/upstream/singleflight.py`.
"""

from __future__ import annotations

from roxy.config.spec import (
    Apply,
    Group,
    OptionSpec,
    Risk,
    RiskCondition,
    RiskOp,
    SettingSpec,
    SettingType,
)

# Readability helpers for byte sizes. The values stay plain integers.
_KIB = 1024
_MIB = 1024 * _KIB
_GIB = 1024 * _MIB

# Every key in this group lives on Cache > Settings (plan 15.6); coalescing keys also on Cache > Coalescing,
# and request samples on Recommendations > Preview settings and Data > Retention.
_CACHE_PAGE = ("cache#settings",)
_COALESCE_PAGES = ("cache#settings", "cache#coalescing")
_SAMPLE_PAGES = ("recommendations#preview-settings", "data#retention")


SETTINGS: list[SettingSpec] = [
    # --- Master switch and lifetimes ------------------------------------------------------------------
    SettingSpec(
        key="cache_enabled",
        group=Group.CACHE,
        label="Response cache",
        type=SettingType.BOOL,
        default=1,
        description=(
            "Master switch for the response cache. When on, Roxy answers a repeat request for the same Roblox "
            "URL from a stored copy instead of calling Roblox again. This is the strongest protection against "
            "Roblox rate limits (429 responses), because it works no matter how many different callers ask."
        ),
        pages=_CACHE_PAGE,
        if_enabled=(
            "Repeat requests are answered from the cache according to the lifetime settings and the cache rules, "
            "so Roblox sees about one call per distinct request per lifetime instead of one per caller."
        ),
        if_disabled=(
            "Every caller request goes to Roblox. Upstream calls, Roblox 429s and response times rise sharply, "
            "and no stale copy exists to hide Roblox errors or cooldowns from callers. Use only briefly, for "
            "debugging."
        ),
        risk=Risk.MEDIUM,
        high_risk_if=(
            RiskCondition(
                RiskOp.EQ,
                0,
                "Every request goes to Roblox, the traffic pattern that got v1 rate-limited 579 times in under "
                "50,000 requests.",
            ),
        ),
        apply=Apply.LIVE,
        related_settings=("cache_disk_enabled", "cache_ttl_seconds", "cache_stale_seconds", "cache_coalesce"),
        related_recommendations=("CACHE-OFF", "SEC-DEFAULTS"),
        v1_default=1,
        notes="Migration from v1 imports this value only when it differs from the v1 default (1).",
    ),
    SettingSpec(
        key="cache_ttl_seconds",
        group=Group.CACHE,
        label="Default cache lifetime",
        type=SettingType.DURATION,
        default=120,
        unit="seconds",
        min=0,
        max=86400,
        step=1,
        description=(
            "How long a successful (2xx) Roblox response stays fresh in the cache when no cache rule matches its "
            "endpoint (this lifetime is often called the TTL, time to live). Cache rules on the Cache page "
            "override it per endpoint, including a rule of 0 that turns caching off for one endpoint."
        ),
        pages=_CACHE_PAGE,
        if_raised=(
            "Fewer upstream calls and fewer Roblox 429s for endpoints without a rule, but callers may see data up "
            "to this many seconds old (plus the stale-while-revalidate window)."
        ),
        if_lowered=(
            "Callers see fresher data, at the cost of more upstream calls and more 429 risk. 0 stops caching "
            "every endpoint that has no cache rule of its own."
        ),
        risk=Risk.LOW,
        high_risk_if=(
            RiskCondition(
                RiskOp.EQ,
                0,
                "Endpoints without their own cache rule are never cached, so every repeat request for them goes "
                "to Roblox.",
            ),
            RiskCondition(
                RiskOp.GT,
                3600,
                "Endpoints without their own cache rule can serve data more than an hour old, which breaks "
                "callers that expect live values such as player counts or presence. Give long lifetimes to "
                "specific endpoints with cache rules instead.",
            ),
        ),
        apply=Apply.LIVE,
        related_settings=(
            "cache_swr_seconds",
            "cache_stale_seconds",
            "cache_error_ttl_seconds",
            "cache_default_rules_enabled",
            "ttl_tuner_enabled",
        ),
        related_rules=("cache_rules",),
        related_recommendations=(
            "CACHE-TTL-TUNE",
            "CACHE-LOW-HIT",
            "HOT-ENDPOINT",
            "UP-429-ENDPOINT",
            "SEC-DEFAULTS",
        ),
        v1_default=60,
        notes=(
            "The v2 default doubles the v1 default of 60 seconds. Migration imports a v1 value only when it "
            "differs from 60."
        ),
    ),
    SettingSpec(
        key="cache_error_ttl_seconds",
        group=Group.CACHE,
        label="Error answer lifetime",
        type=SettingType.DURATION,
        default=60,
        unit="seconds",
        min=0,
        max=3600,
        step=1,
        description=(
            "How long Roxy remembers a Roblox error answer of 400, 403, 404 or 410 for the same request and "
            "replays it, with the original status, instead of asking Roblox again. A 403 is cached only when it "
            "means permission denied (not a CSRF security-token challenge), and 429 and 5xx answers are never "
            "cached as content."
        ),
        pages=_CACHE_PAGE,
        if_raised=(
            "Callers that keep asking for something that does not exist cost fewer upstream calls; a resource "
            "that starts to exist (for example a newly created item) is noticed later."
        ),
        if_lowered=(
            "Errors are rechecked with Roblox sooner, so repeated bad lookups cost more upstream calls and more "
            "429 risk. 0 sends every repeat of a failing request to Roblox."
        ),
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("cache_ttl_seconds", "cache_negative_429"),
        related_rules=("cache_rules",),
        related_recommendations=("CACHE-NEG", "UP-4XX-SPIKE"),
        auto_apply_bounds=(30, 600),
        v1_default=0,
        notes=(
            "v1 did not cache errors by default (0). Migration imports a v1 value only when it differs from 0. "
            "Cache rules can set their own error lifetime (negative TTL) per endpoint."
        ),
    ),
    SettingSpec(
        key="cache_swr_seconds",
        group=Group.CACHE,
        label="Stale-while-revalidate window",
        type=SettingType.DURATION,
        default=60,
        unit="seconds",
        min=0,
        max=86400,
        step=1,
        description=(
            "For this many seconds after an entry expires, Roxy still serves it instantly (header Roxy-Cache: "
            "REVALIDATING) and starts one background refresh, so the next caller gets new data and nobody waits. "
            "This is called stale-while-revalidate; cache rules can set their own window."
        ),
        pages=_CACHE_PAGE,
        if_raised=(
            "More callers get an instant answer that may be slightly old, and fewer callers wait on a fetch when "
            "a popular entry expires."
        ),
        if_lowered=(
            "Served data is fresher, but more callers wait for the refetch when an entry expires. 0 turns "
            "stale-while-revalidate off."
        ),
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("cache_ttl_seconds", "cache_stale_seconds", "swr_max_inflight", "queue_wait_background_ms"),
        related_rules=("cache_rules",),
        related_recommendations=("UP-429-ENDPOINT", "UP-5XX", "UP-LATENCY"),
        notes=(
            "Each background refresh is one upstream call at low priority, shared by all workers (only one worker "
            "refreshes a given entry)."
        ),
    ),
    SettingSpec(
        key="cache_stale_seconds",
        group=Group.CACHE,
        label="Stale serving window",
        type=SettingType.DURATION,
        default=600,
        unit="seconds",
        min=0,
        max=86400,
        step=1,
        description=(
            "How long after expiry an entry may still be served when Roblox cannot be asked: the endpoint is "
            "cooling down after a 429, its circuit breaker is open (calls paused after repeated failures), or the "
            "upstream attempt failed. The caller gets the old copy (Roxy-Cache: STALE) instead of an error."
        ),
        pages=_CACHE_PAGE,
        if_raised=(
            "Callers ride out longer Roblox outages and cooldowns with old data instead of errors, and the data "
            "they get can be older. Entries also stay in the shared cache longer, using more disk."
        ),
        if_lowered=(
            "Old data is never served past this limit, so callers see more 429 and 5xx errors during cooldowns "
            "and outages. 0 never serves a stale copy."
        ),
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=(
            "cache_swr_seconds",
            "cache_ttl_seconds",
            "queue_wait_stale_ms",
            "cooldown_default_s",
            "breaker_open_s",
        ),
        related_rules=("cache_rules",),
        related_recommendations=("UP-5XX",),
        v1_default=600,
        notes=(
            "Measured from the moment the entry expires, so keep it at least as long as cache_swr_seconds. "
            "Migration imports a v1 value only when it differs from the v1 default (600)."
        ),
    ),
    # --- Tiers and size caps ----------------------------------------------------------------------------
    SettingSpec(
        key="cache_disk_enabled",
        group=Group.CACHE,
        label="Shared disk cache",
        type=SettingType.BOOL,
        default=1,
        description=(
            "Use the shared cache tier stored in cache.db, an SQLite database on disk. Every worker process reads "
            "and writes it, so one fetch serves callers on all workers and cached data survives restarts and "
            "deploys."
        ),
        pages=_CACHE_PAGE,
        if_enabled=(
            "One shared copy per request for the whole fleet, up to cache_max_entries and cache_max_bytes; each "
            "worker keeps a small memory tier in front of it for the hottest entries."
        ),
        if_disabled=(
            "Memory only: each worker keeps its own small cache (cache_memory_entries, cache_memory_bytes), so the "
            "same request is fetched once per worker, far fewer entries fit, and everything is lost on restart "
            "or deploy. Concurrent requests for one missing entry are still coalesced fleet-wide while cache.db "
            "can be written (short-lived single-flight handoff rows). Useful only while cache.db is failing."
        ),
        risk=Risk.MEDIUM,
        high_risk_if=(
            RiskCondition(
                RiskOp.EQ,
                0,
                "The hit ratio drops sharply and upstream calls multiply by the number of workers, raising the "
                "risk of Roblox 429s.",
            ),
        ),
        apply=Apply.LIVE,
        related_settings=("cache_max_entries", "cache_max_bytes", "cache_memory_entries", "cache_memory_bytes"),
        related_recommendations=("SEC-DEFAULTS",),
        v1_default=1,
        notes="Migration from v1 imports this value only when it differs from the v1 default (1).",
    ),
    SettingSpec(
        key="cache_max_entries",
        group=Group.CACHE,
        label="Shared cache entry limit",
        type=SettingType.INT,
        default=200000,
        unit="entries",
        min=0,
        max=5000000,
        step=1,
        description=(
            "The most entries the shared cache tier (cache.db) may hold across all workers. When it is full, the "
            "eviction policy decides which entries are removed. 0 holds nothing in the shared tier."
        ),
        pages=_CACHE_PAGE,
        if_raised=(
            "More distinct requests stay cached, so fewer misses and upstream calls; the database and its index "
            "grow a little."
        ),
        if_lowered=(
            "More evictions, so more misses and upstream calls. 0 stores nothing on disk, the same as turning "
            "cache_disk_enabled off."
        ),
        risk=Risk.LOW,
        high_risk_if=(
            RiskCondition(
                RiskOp.EQ,
                0,
                "Nothing is stored in the shared tier, so each worker only has its small memory cache and upstream "
                "calls multiply.",
            ),
        ),
        apply=Apply.LIVE,
        related_settings=("cache_max_bytes", "cache_eviction_policy", "cache_disk_enabled"),
        related_recommendations=("CACHE-PRESSURE", "SEC-DEFAULTS"),
        auto_apply_bounds=(100000, 2000000),
        v1_default=3000,
        notes=(
            "v1 caps were sized for JSON shard files. Migration imports a v1 value only when it differs from the "
            "v1 default (3000) and is larger than this default; a smaller v1 value is reported, not imported."
        ),
    ),
    SettingSpec(
        key="cache_max_bytes",
        group=Group.CACHE,
        label="Shared cache size limit",
        type=SettingType.BYTES,
        default=512 * _MIB,
        unit="bytes",
        min=0,
        max=16 * _GIB,
        step=1,
        description=(
            "Total size budget of the shared cache tier in cache.db, counting bodies as stored on disk "
            "(compressed when cache_compress is on). When it is exceeded, the eviction policy removes entries "
            "until it fits. 0 holds nothing in the shared tier."
        ),
        pages=_CACHE_PAGE,
        if_raised=(
            "More data stays cached and the hit ratio rises, using more disk (counted toward storage_total_budget_gb)."
        ),
        if_lowered="Less disk, more evictions and misses. 0 stores nothing on disk.",
        risk=Risk.LOW,
        high_risk_if=(
            RiskCondition(
                RiskOp.EQ,
                0,
                "Nothing is stored in the shared tier, so each worker only has its small memory cache and upstream "
                "calls multiply.",
            ),
            RiskCondition(
                RiskOp.GT,
                4 * _GIB,
                "The cache alone would take more than a third of the default 12 GB storage budget; if the disk "
                "fills, every database write fails and Roxy degrades.",
            ),
        ),
        apply=Apply.LIVE,
        related_settings=("cache_max_entries", "cache_compress", "cache_eviction_policy", "storage_total_budget_gb"),
        related_recommendations=("CACHE-PRESSURE", "SYS-DISK", "SEC-DEFAULTS"),
        auto_apply_bounds=(256 * _MIB, 4 * _GIB),
        v1_default=32 * _MIB,
        notes=(
            "Migration imports a v1 value only when it differs from the v1 default (32 MiB) and is larger than "
            "this default."
        ),
    ),
    SettingSpec(
        key="cache_max_body",
        group=Group.CACHE,
        label="Largest cacheable response",
        type=SettingType.BYTES,
        default=1 * _MIB,
        unit="bytes",
        min=0,
        max=8 * _MIB,
        step=1,
        description=(
            "The largest response body, in bytes of the uncompressed body, that may be cached. Bigger responses "
            "are passed to the caller but never stored, and never stored cut short, because half a JSON document "
            "is worse than no cache. 0 caches nothing."
        ),
        pages=_CACHE_PAGE,
        if_raised=(
            "Large responses (big batch lookups, long lists) get cached too; each one uses more memory and disk, "
            "so fewer entries fit in the same budget."
        ),
        if_lowered=(
            "Large responses always go to Roblox, leaving more room for small entries. 0 caches nothing, so the "
            "cache is effectively off."
        ),
        risk=Risk.LOW,
        high_risk_if=(
            RiskCondition(
                RiskOp.EQ,
                0,
                "No response fits, so the cache is effectively off and every request goes to Roblox.",
            ),
        ),
        apply=Apply.LIVE,
        related_settings=("cache_max_bytes", "cache_memory_bytes"),
        related_recommendations=("SEC-DEFAULTS",),
        v1_default=256 * _KIB,
        notes=(
            "v1 counted characters and treated 0 as no limit; v2 counts bytes and keeps every store bounded, so "
            "0 now caches nothing. Migration imports a v1 value only when it differs from the v1 default "
            "(256 KiB) and is larger than this default."
        ),
    ),
    SettingSpec(
        key="cache_memory_entries",
        group=Group.CACHE,
        label="Memory cache entries per worker",
        type=SettingType.INT,
        default=1000,
        unit="entries",
        min=0,
        max=100000,
        step=1,
        description=(
            "The most entries each worker keeps in its own in-memory cache tier, a small fast layer in front of "
            "cache.db. It is per worker, so the fleet holds up to this many times the number of workers. 0 turns "
            "the memory tier off."
        ),
        pages=_CACHE_PAGE,
        if_raised=(
            "More hits are answered from RAM without a database read; this only helps while cache_memory_bytes "
            "still has room."
        ),
        if_lowered=(
            "More lookups read cache.db, which is still fast but slower than RAM. 0 sends every lookup to cache.db."
        ),
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("cache_memory_bytes", "cache_disk_enabled"),
        v1_default=400,
        notes=(
            "The default (1000) is sized for a server with about 1 GB of RAM running 2 workers; the plan's "
            "2000 suits a 2 GB server. Migration imports a v1 value only when it differs from the v1 default "
            "(400) and is larger than this default."
        ),
    ),
    SettingSpec(
        key="cache_memory_bytes",
        group=Group.CACHE,
        label="Memory cache size per worker",
        type=SettingType.BYTES,
        default=16 * _MIB,
        unit="bytes",
        min=0,
        max=1 * _GIB,
        step=1,
        description=(
            "RAM budget of each worker's in-memory cache tier. It is per worker, so total use is this times "
            "ROXY_WORKERS (2 by default), and it doubles during a deploy while both colors (old and new release) "
            "run. This is the cache setting that can run the server out of memory."
        ),
        pages=_CACHE_PAGE,
        if_raised=(
            "More hits are served from RAM, but each worker uses more memory and gets closer to the systemd "
            "memory cap (MemoryMax), past which the kernel kills and restarts workers."
        ),
        if_lowered=(
            "Less RAM and more reads from cache.db. This is the first knob to lower when memory is tight. 0 turns "
            "the memory tier off."
        ),
        risk=Risk.MEDIUM,
        high_risk_if=(
            RiskCondition(
                RiskOp.GT,
                32 * _MIB,
                "With 2 workers and the default systemd cap of MemoryMax=420M per color, more than 32 MiB per "
                "worker can push a color over its cap, and the kernel then kills workers mid-request.",
            ),
        ),
        apply=Apply.LIVE,
        related_settings=("cache_memory_entries", "cache_max_body", "cache_disk_enabled"),
        related_recommendations=("SEC-DEFAULTS",),
        v1_default=8 * _MIB,
        notes=(
            "The default (16 MiB) is sized for a server with about 1 GB of RAM (systemd MemoryHigh=320M and "
            "MemoryMax=420M per color); the plan's 64 MiB suits a 2 GB server with a higher cap. Migration "
            "imports a v1 value only when it differs from the v1 default (8 MiB) and is larger than this default."
        ),
    ),
    SettingSpec(
        key="cache_eviction_policy",
        group=Group.CACHE,
        label="Eviction policy",
        type=SettingType.ENUM,
        default="hybrid",
        options=(
            OptionSpec(
                value="lru",
                label="Least recently used (LRU)",
                description=(
                    "When the cache is over a limit, remove the entry that has gone longest without being served. "
                    "Simple, and good when the set of popular requests keeps changing."
                ),
            ),
            OptionSpec(
                value="lfu",
                label="Least frequently used (LFU)",
                description=(
                    "Remove the entry with the fewest hits. Keeps long-term favorites, but an entry that was "
                    "popular yesterday can linger after demand moves on."
                ),
            ),
            OptionSpec(
                value="hybrid",
                label="Hybrid (LFU with recency decay)",
                description=(
                    "Count hits but let old hits fade over time, so entries that are both popular and recent stay. "
                    "Recommended for Roxy's mix of steady hot endpoints and short bursts."
                ),
            ),
        ),
        description=(
            "How the shared cache tier chooses which entries to remove when it is over cache_max_entries or "
            "cache_max_bytes. Entries whose stale window has ended are always removed first; this choice decides "
            "which still-useful entries go next."
        ),
        pages=_CACHE_PAGE,
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("cache_max_entries", "cache_max_bytes"),
        notes="v1 always removed the oldest stored entries first (first in, first out).",
    ),
    SettingSpec(
        key="cache_compress",
        group=Group.CACHE,
        label="Compress cached bodies",
        type=SettingType.BOOL,
        default=1,
        description=(
            "Store response bodies in cache.db compressed with zstd, a fast compression format. Roblox JSON "
            "usually shrinks several times over, so the same disk budget holds many more entries."
        ),
        pages=_CACHE_PAGE,
        if_enabled=(
            "New entries are stored compressed, so cache_max_bytes holds several times more of them; each store "
            "and each disk read costs a little CPU."
        ),
        if_disabled=(
            "New entries are stored uncompressed: more disk per entry, so the byte limit fills sooner, and "
            "slightly less CPU per store and read. Entries already stored compressed stay readable."
        ),
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("cache_max_bytes",),
    ),
    # --- Coalescing -------------------------------------------------------------------------------------
    SettingSpec(
        key="cache_coalesce",
        group=Group.CACHE,
        label="Request coalescing",
        type=SettingType.BOOL,
        default=1,
        description=(
            "Fleet-wide request coalescing, also called single-flight. When many callers ask for the same "
            "uncached URL at once, one worker fetches it from Roblox and the others wait for that answer instead "
            "of each making its own call."
        ),
        pages=_COALESCE_PAGES,
        if_enabled=(
            "A burst of requests for one missing or expired entry makes a single Roblox call, and the waiting "
            "callers get the shared answer (Roxy-Cache: COALESCED)."
        ),
        if_disabled=(
            "Every concurrent caller of a missing entry makes its own Roblox call, so a popular endpoint expiring "
            "produces a burst of identical calls, the pattern that triggers Roblox 429s."
        ),
        risk=Risk.MEDIUM,
        high_risk_if=(
            RiskCondition(
                RiskOp.EQ,
                0,
                "A cold or expired popular entry sends one Roblox call per waiting caller at the same moment, "
                "which is exactly the burst the cache exists to prevent.",
            ),
        ),
        apply=Apply.LIVE,
        related_settings=("cache_coalesce_wait_ms", "cache_enabled"),
        related_recommendations=("SEC-DEFAULTS",),
        v1_default=1,
        notes=(
            "v1 coalesced only within one worker; v2 coalesces across all workers. Credential and anonymous "
            "fetches of the same URL are never coalesced together."
        ),
    ),
    SettingSpec(
        key="cache_coalesce_wait_ms",
        group=Group.CACHE,
        label="Coalescing wait limit",
        type=SettingType.DURATION,
        default=0,
        unit="ms",
        min=0,
        max=60000,
        step=1,
        description=(
            "The longest a waiting caller (a follower) waits for the worker that is already fetching the same URL "
            "(the owner). 0 means wait as long as the owner is allowed to take, about 36 seconds with default "
            "settings (queue_wait_interactive_ms plus request_timeout times upstream_max_attempts plus "
            "backoff_cap_ms)."
        ),
        pages=_COALESCE_PAGES,
        if_raised=(
            "Followers wait longer for the shared answer, so fewer of them give up; values above the owner's own "
            "deadline change nothing."
        ),
        if_lowered=(
            "Followers give up sooner and get a stale copy or a 503 with Retry-After (reason coalesce_timeout). "
            "They never call Roblox themselves, so this never adds upstream calls. Setting exactly 0 means the "
            "full owner deadline, not zero wait."
        ),
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=(
            "cache_coalesce",
            "queue_wait_interactive_ms",
            "request_timeout",
            "upstream_max_attempts",
            "backoff_cap_ms",
            "request_deadline_s",
        ),
        v1_default=1500,
        notes=(
            "The meaning changed: in v1, 1500 ms was a short wait inside one worker. The v1 value is therefore "
            "never imported."
        ),
    ),
    # --- What may be cached, and who may skip the cache ---------------------------------------------------
    SettingSpec(
        key="cache_post_requests",
        group=Group.CACHE,
        label="POST caching",
        type=SettingType.ENUM,
        default="allowlist",
        options=(
            OptionSpec(
                value="off",
                label="Off",
                description=(
                    "Never cache POST responses. Every POST goes to Roblox, including read-only batch lookups such "
                    "as users by id, which are among the most called endpoints."
                ),
            ),
            OptionSpec(
                value="allowlist",
                label="Allowlisted lookups",
                description=(
                    "Cache POST only for the built-in read-only batch lookups (users by id, usernames, thumbnails "
                    "batch, presence, place details) and for cache rules that explicitly allow POST. Recommended."
                ),
            ),
            OptionSpec(
                value="all",
                label="All POST requests (risky)",
                description=(
                    "Cache every POST response. POST usually means a write (sending, buying, changing something), "
                    "and caching one replays an old answer to a later caller instead of performing the action."
                ),
            ),
        ),
        description=(
            "Which POST requests may be cached. Roblox uses POST for some read-only batch lookups that are safe "
            "and valuable to cache, while other POSTs are writes. A cached POST answer is keyed on a hash of the "
            "request body, so different lookups never share an answer."
        ),
        pages=_CACHE_PAGE,
        risk=Risk.MEDIUM,
        high_risk_if=(
            RiskCondition(
                RiskOp.EQ,
                "all",
                "Write requests can be answered from the cache, so a caller gets someone else's earlier result "
                "and the write never reaches Roblox.",
            ),
        ),
        apply=Apply.LIVE,
        related_settings=("cache_ttl_seconds",),
        related_rules=("cache_rules",),
        related_recommendations=("UP-429-ENDPOINT", "CACHE-LOW-HIT", "SEC-DEFAULTS"),
        v1_default=0,
        notes=(
            "v1 had an on/off switch (default off). Migration maps v1 on to all, with a high-risk warning in its "
            "report, and does not import v1 off, so the allowlist default applies."
        ),
    ),
    SettingSpec(
        key="cache_respect_no_cache",
        group=Group.CACHE,
        label="Honor caller no-cache headers",
        type=SettingType.BOOL,
        default=0,
        description=(
            "Whether a caller can skip the cache by sending the header Cache-Control: no-cache (or no-store). Off "
            "by default, because it would give anyone flooding Roxy a one-header way past the cache straight to "
            "Roblox."
        ),
        pages=_CACHE_PAGE,
        if_enabled=(
            "Any caller that sends the header bypasses the cache and makes a fresh Roblox call, adding upstream "
            "load and 429 risk. Use only when every caller is a trusted integration that needs forced refreshes."
        ),
        if_disabled="Caller cache headers are ignored, and every caller is served by the cache rules. Recommended.",
        risk=Risk.MEDIUM,
        high_risk_if=(
            RiskCondition(
                RiskOp.EQ,
                1,
                "Any caller, including an abusive one, can force every request to reach Roblox by adding one header.",
            ),
        ),
        apply=Apply.LIVE,
        related_settings=("cache_enabled",),
        related_recommendations=("SEC-DEFAULTS",),
        v1_default=0,
        notes="Migration from v1 imports this value only when it differs from the v1 default (0).",
    ),
    SettingSpec(
        key="cache_serve_throttled",
        group=Group.CACHE,
        label="Serve throttled callers from cache",
        type=SettingType.BOOL,
        default=0,
        description=(
            "When a caller is over its rate limit, answer from a fresh cached copy (if one exists) instead of "
            "refusing with 429. Roblox never sees these requests either way, so this only decides how strict the "
            "limit feels to the caller."
        ),
        pages=_CACHE_PAGE,
        if_enabled=(
            "Throttled callers keep getting fresh cached data, so their game keeps working; the limit becomes "
            "softer for cached endpoints, and Roxy still spends the work of serving them. Misses and stale "
            "entries are still refused."
        ),
        if_disabled=(
            "Throttled callers get the normal throttle refusal even when a fresh copy is cached, so the limit is "
            "strict."
        ),
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("allowed_requests_per_minute", "cache_enabled"),
        related_rules=("throttle_tiers",),
        v1_default=0,
        notes="Migration from v1 imports this value only when it differs from the v1 default (0).",
    ),
    SettingSpec(
        key="cache_negative_429",
        group=Group.CACHE,
        label="Remember Roblox 429s per request",
        type=SettingType.BOOL,
        default=1,
        description=(
            "When Roblox answers a request with 429 (rate limited), store a marker for that exact request until "
            "the cooldown ends. Until then the request is answered from a stale copy, or with 429 and "
            "Retry-After, without contacting Roblox; the marker itself is never served as content."
        ),
        pages=_CACHE_PAGE,
        if_enabled=(
            "Repeat requests for a rate-limited request never reach Roblox during its cooldown; callers get stale "
            "data or a 429 telling them when to retry."
        ),
        if_disabled=(
            "Only the endpoint and host cooldowns hold calls back, so repeats of the same request can reach "
            "Roblox again (for example through another egress path) and earn new 429s."
        ),
        risk=Risk.MEDIUM,
        high_risk_if=(
            RiskCondition(
                RiskOp.EQ,
                0,
                "Callers can re-trigger Roblox 429s for a request that was just rate-limited, which lengthens "
                "Roblox's limits on Roxy.",
            ),
        ),
        apply=Apply.LIVE,
        related_settings=("cache_stale_seconds", "cooldown_default_s", "cache_error_ttl_seconds"),
        related_recommendations=("SEC-DEFAULTS",),
    ),
    SettingSpec(
        key="cache_default_rules_enabled",
        group=Group.CACHE,
        label="Built-in cache rules",
        type=SettingType.BOOL,
        default=1,
        description=(
            "Use the cache rules Roxy ships for Roblox data with known change rates: game details and votes 5 "
            "minutes, universe from place 1 day, thumbnails batch, user profiles, group info and catalog items "
            "10 minutes, badge metadata 1 hour, presence 15 seconds. Each rule is shown and editable on the "
            "Cache page."
        ),
        pages=_CACHE_PAGE,
        if_enabled=(
            "Those endpoints get lifetimes that match how often their data really changes: long for static data, "
            "short for presence."
        ),
        if_disabled=(
            "Those endpoints fall back to cache_ttl_seconds, so static data such as universe ids is refetched far "
            "more often, and presence may be cached longer than it should."
        ),
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("cache_ttl_seconds", "cache_post_requests"),
        related_rules=("cache_rules",),
    ),
    # --- TTL tuner and background refresh -----------------------------------------------------------------
    SettingSpec(
        key="ttl_tuner_enabled",
        group=Group.CACHE,
        label="TTL tuner",
        type=SettingType.BOOL,
        default=1,
        description=(
            "Let the TTL tuner measure how often each endpoint's response really changes (from the request "
            "samples) and propose matching cache rule lifetimes through the CACHE-TTL-TUNE recommendation. It "
            "only proposes; nothing changes until a proposal is applied."
        ),
        pages=_CACHE_PAGE,
        if_enabled=(
            "Measured lifetime suggestions appear on the Recommendations page, and rules that propose new cache "
            "rules (UP-429-ENDPOINT, HOT-ENDPOINT) use the measured lifetime."
        ),
        if_disabled=(
            "No lifetime tuning proposals; rules that propose new cache rules use the standard new-rule lifetime "
            "of 300 seconds instead of a measured one."
        ),
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("ttl_tuner_max_s", "request_sample_pct", "request_sample_hours"),
        related_rules=("cache_rules",),
    ),
    SettingSpec(
        key="ttl_tuner_max_s",
        group=Group.CACHE,
        label="Longest tuned lifetime",
        type=SettingType.DURATION,
        default=3600,
        unit="seconds",
        min=60,
        max=86400,
        step=1,
        description=(
            "The longest cache lifetime the TTL tuner may propose for an endpoint, whatever it measures. It caps "
            "suggestions only; admins can still set longer lifetimes by hand."
        ),
        pages=_CACHE_PAGE,
        if_raised=(
            "The tuner can propose longer lifetimes for data that rarely changes, saving more calls, at the risk "
            "of serving old data when a rare change does happen."
        ),
        if_lowered="Proposals stay short and conservative: fresher data, fewer avoided upstream calls.",
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("ttl_tuner_enabled", "cache_ttl_seconds"),
        related_rules=("cache_rules",),
    ),
    SettingSpec(
        key="swr_max_inflight",
        group=Group.CACHE,
        label="Background refreshes per worker",
        type=SettingType.INT,
        default=50,
        unit="refreshes",
        min=0,
        max=1000,
        step=1,
        description=(
            "The most stale-while-revalidate background refreshes one worker runs at the same time. Each refresh "
            "is one upstream call made after a caller was already served a slightly old copy."
        ),
        pages=_CACHE_PAGE,
        if_raised=(
            "Expired popular entries are refreshed sooner under load, but more upstream calls can run at once "
            "(they still pass through the rate buckets)."
        ),
        if_lowered=(
            "Fewer refreshes run at once, so some entries stay old a little longer while they wait for a slot. 0 "
            "turns background refreshes off, so expired entries are refetched while the caller waits."
        ),
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("cache_swr_seconds", "queue_wait_background_ms"),
    ),
    # --- Request samples (dry-run previews and TTL tuning) ------------------------------------------------
    SettingSpec(
        key="request_sample_pct",
        group=Group.CACHE,
        label="Request sampling rate",
        type=SettingType.PERCENT,
        default=100,
        unit="percent",
        min=0,
        max=100,
        step=1,
        description=(
            "Share of proxied requests recorded as request samples, one small row each (endpoint, cache key id, "
            "status, body hash). Recommendations replay these rows to preview a change before it is applied "
            "(dry run), and the TTL tuner uses them to measure how often data changes."
        ),
        pages=_SAMPLE_PAGES,
        if_raised=(
            "More accurate previews and lifetime measurements; more rows written, so more disk and database "
            "writes (about 150 bytes per row)."
        ),
        if_lowered=(
            "Less disk and write load; previews become rougher estimates and show a sampling note. 0 records "
            "nothing, which disables dry-run previews and TTL tuning."
        ),
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("request_sample_hours", "request_sample_max_rows", "ttl_tuner_enabled"),
    ),
    SettingSpec(
        key="request_sample_hours",
        group=Group.CACHE,
        label="Request sample history",
        type=SettingType.INT,
        default=24,
        unit="hours",
        min=1,
        max=168,
        step=1,
        description=(
            "How many hours of request samples are kept. Previews can replay up to this much history (the "
            "default preview uses the last hour), and older rows are deleted."
        ),
        pages=_SAMPLE_PAGES,
        if_raised=(
            "Previews can look further back and catch daily patterns; more rows are kept, so more disk, up to "
            "request_sample_max_rows."
        ),
        if_lowered=(
            "Less disk; previews and lifetime measurements see less history. Below 24 hours, CACHE-TTL-TUNE cannot "
            "gather the full day of evidence it needs to propose a longer lifetime."
        ),
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("request_sample_pct", "request_sample_max_rows"),
        related_recommendations=("SYS-DISK",),
    ),
    SettingSpec(
        key="request_sample_max_rows",
        group=Group.CACHE,
        label="Request sample row limit",
        type=SettingType.INT,
        default=3000000,
        unit="rows",
        min=10000,
        max=50000000,
        step=1,
        description=(
            "Hard cap on stored request samples, whatever request_sample_hours allows. When it is reached, the "
            "oldest rows are deleted first."
        ),
        pages=_SAMPLE_PAGES,
        if_raised=(
            "The full history window survives busy days; costs about 150 bytes of disk per row (3,000,000 rows is "
            "about 450 MB)."
        ),
        if_lowered=(
            "Less disk; on busy days the oldest samples are dropped before request_sample_hours is reached, which "
            "shortens the history previews can use."
        ),
        risk=Risk.LOW,
        high_risk_if=(
            RiskCondition(
                RiskOp.GT,
                20000000,
                "At about 150 bytes per row this is more than 3 GB, a quarter of the default 12 GB storage budget; "
                "if the disk fills, every database write fails and Roxy degrades.",
            ),
        ),
        apply=Apply.LIVE,
        related_settings=("request_sample_hours", "request_sample_pct", "storage_total_budget_gb"),
        related_recommendations=("SYS-DISK", "SEC-DEFAULTS"),
    ),
]
