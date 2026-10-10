"""Settings catalog content for the Upstream pacing and resilience group (plan 15.3 C).

What this is
    The `SettingSpec` declarations for every runtime setting that decides how fast Roxy may call Roblox and
    what it does when Roblox pushes back: the rate buckets (global, per egress path, per Roblox host, per
    endpoint), the adaptive rate controller, optional adaptive concurrency (AIMD), cooldowns after a 429,
    circuit breakers, retry backoff, the priority queue, the overall request deadline, and Roblox CSRF token
    reuse.

Why it exists
    Plan section 7's goal is that Roxy almost never receives a 429 from Roblox, and that when it does it backs
    off for every worker and protects callers with cached data. v1 had none of these controls (plan 2.5, root
    causes R2, R3, R4 and R7). Each mechanism has numbers an admin may need to tune, and plan P3 requires each
    number to be declared once, with its range and a plain-English explanation of what raising or lowering it
    does.

How it works
    `SETTINGS` is a plain list of frozen `SettingSpec` objects, one per key, in the order of the plan table.
    `roxy/config/catalog.py` collects it, checks defaults and texts at import time, and serves it to the
    settings API, the editor, the docs and the LLM export. Rules that span settings (aimd_min <= aimd_initial
    <= aimd_max, cooldown_min_s <= cooldown_max_s, adaptive_min_per_min <= adaptive_max_per_min, backoff_base_ms
    <= backoff_cap_ms, and the request deadline budget of plan 5.2) live in `catalog.validate_cross`, because a
    single spec cannot see another setting's value.

    A short glossary used in the texts below. A "bucket" (GCRA, plan 7.3) lets calls through at a steady rate
    per minute plus a small burst that may leave back to back; every call to Roblox must get a slot from all of
    its buckets at once (global, its egress path, its Roblox host, its endpoint), and the buckets are shared by
    all workers through hot.db. The host and endpoint buckets stand for Roblox's own limits, which Roblox counts
    per rolling minute, so for them the burst fits inside the per-minute number (`roxy/upstream/buckets.py`). An
    "egress path" is how a call leaves the server: direct (the server's own IP, anonymous), credential (the
    server's IP with the account cookie) or rotator (DataImpulse exit IPs, anonymous, billed per byte). An
    "endpoint template" is one Roblox API path with ids replaced by placeholders.

What to read next
    `roxy/config/spec.py` (field meanings), `roxy/config/settings/credential.py` (the account's own bucket),
    then `roxy/upstream/buckets.py`, `roxy/upstream/adaptive.py`, `roxy/upstream/cooldowns.py` and
    `roxy/upstream/queue.py` (where these values are used).
"""

from roxy.config.spec import Apply, Group, Risk, RiskCondition, RiskOp, SettingSpec, SettingType

# Dashboard anchors (DESIGN.md section 9, plan 15.6).
_BUCKETS = "upstream#buckets"
_CONCURRENCY = "upstream#concurrency"
_COOLDOWNS = "upstream#cooldowns"
_BREAKERS = "upstream#breakers"
_QUEUE = "upstream#queue"
_RETRIES = "upstream#retries"
_ROTATOR = "egress#rotator"

_PER_MIN = "requests per minute"

SETTINGS: list[SettingSpec] = [
    # ---- Rate buckets (plan 7.3) -------------------------------------------------------------------------
    SettingSpec(
        key="global_bucket_per_min",
        group=Group.UPSTREAM,
        label="Global upstream rate",
        type=SettingType.INT,
        default=600,
        unit=_PER_MIN,
        min=1,
        max=10000,
        step=1,
        description=(
            "The ceiling on how many calls Roxy makes to Roblox per minute in total, across every egress path "
            "and every worker. Every upstream call counts, including retries, CSRF handshakes, background "
            "refreshes and health checks. When it is used up, calls wait in the queue, are answered from an "
            "older cached copy, or get a 429 with Retry-After."
        ),
        pages=(_BUCKETS,),
        if_raised=(
            "More total throughput before queuing starts, but more calls reach Roblox, so the server IP and "
            "the rotator exits are more likely to be rate limited (429) on many endpoints at once."
        ),
        if_lowered=(
            "Fewer calls reach Roblox and 429s are rarer, but more requests wait, more answers come from older "
            "cached copies, and callers get more 429 'busy' answers when no cached copy exists."
        ),
        risk=Risk.MEDIUM,
        high_risk_if=(
            RiskCondition(
                RiskOp.GT,
                1200,
                "More than 20 calls per second to Roblox in total, twice the default. The egress, host and "
                "endpoint buckets still apply, but this ceiling stops being a safety net against a flood of "
                "cache misses.",
            ),
        ),
        apply=Apply.LIVE,
        related_settings=(
            "global_bucket_burst",
            "direct_bucket_per_min",
            "rotator_bucket_per_min",
            "credential_bucket_per_min",
            "queue_wait_interactive_ms",
        ),
        related_recommendations=("UP-BUCKET-TUNE", "UP-QUEUE-SAT", "UP-LATENCY", "SEC-DEFAULTS"),
        notes=(
            "Background cache refreshes only take global slots while this bucket is less than half reserved, "
            "so they never take a slot a caller could use soon."
        ),
    ),
    SettingSpec(
        key="global_bucket_burst",
        group=Group.UPSTREAM,
        label="Global upstream burst",
        type=SettingType.INT,
        default=30,
        unit="requests",
        min=1,
        max=500,
        step=1,
        description=(
            "How many upstream calls, in total, may leave back to back before the steady pace of "
            "global_bucket_per_min applies. A small burst absorbs short spikes without making callers wait."
        ),
        pages=(_BUCKETS,),
        if_raised=(
            "Larger spikes go straight to Roblox without waiting; sudden clumps of calls are the shape Roblox's "
            "rate limiters punish most."
        ),
        if_lowered="Spikes are smoothed into an even stream, so more calls wait briefly in the queue during a spike.",
        risk=Risk.LOW,
        high_risk_if=(
            RiskCondition(
                RiskOp.GT,
                100,
                "More than 100 calls may hit Roblox in the same instant. Unpaced bursts were a main cause of "
                "v1's Roblox 429s.",
            ),
        ),
        apply=Apply.LIVE,
        related_settings=("global_bucket_per_min",),
        related_recommendations=("UP-BUCKET-TUNE", "SEC-DEFAULTS"),
    ),
    SettingSpec(
        key="direct_bucket_per_min",
        group=Group.UPSTREAM,
        label="Direct path rate",
        type=SettingType.INT,
        default=300,
        unit=_PER_MIN,
        min=1,
        max=10000,
        step=1,
        description=(
            "How many anonymous calls per minute Roxy may send to Roblox from the server's own IP address (the "
            "direct path), across all workers. The direct path carries all public traffic by default, so this "
            "is usually the bucket that fills first."
        ),
        pages=(_BUCKETS,),
        if_raised=(
            "More public traffic is served from the server IP before Roxy queues it or shifts it to the "
            "rotator. Roblox limits each IP, so the server IP is more likely to get 429s."
        ),
        if_lowered=(
            "The server IP is gentler on Roblox and less likely to be rate limited, but more requests wait, "
            "are answered from older cached copies, or spill to the rotator (billed per byte) when it is "
            "enabled and within budget."
        ),
        risk=Risk.MEDIUM,
        high_risk_if=(
            RiskCondition(
                RiskOp.GT,
                600,
                "More than 10 anonymous calls per second from one IP address. Roblox limits traffic per IP, so "
                "the server IP is likely to be rate limited on many endpoints, which hurts every caller.",
            ),
        ),
        apply=Apply.LIVE,
        related_settings=(
            "direct_bucket_burst",
            "global_bucket_per_min",
            "direct_shift_threshold_pct",
            "direct_weight",
            "rotator_bucket_per_min",
        ),
        related_recommendations=("UP-BUCKET-TUNE", "UP-QUEUE-SAT", "SEC-DEFAULTS"),
        notes=(
            "When this bucket is fuller than direct_shift_threshold_pct, routing shifts weight toward the "
            "rotator, but only if the rotator is enabled and within its byte budget."
        ),
    ),
    SettingSpec(
        key="direct_bucket_burst",
        group=Group.UPSTREAM,
        label="Direct path burst",
        type=SettingType.INT,
        default=20,
        unit="requests",
        min=1,
        max=500,
        step=1,
        description=(
            "How many direct path calls may leave the server IP back to back before the steady pace of "
            "direct_bucket_per_min applies."
        ),
        pages=(_BUCKETS,),
        if_raised="Bigger clumps of calls leave the server IP at once, making Roblox's per-IP limits easier to trip.",
        if_lowered=(
            "Smoother traffic from the server IP; short spikes wait briefly or spill to the rotator when it is enabled."
        ),
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("direct_bucket_per_min", "global_bucket_burst"),
        related_recommendations=("UP-BUCKET-TUNE",),
    ),
    SettingSpec(
        key="rotator_bucket_per_min",
        group=Group.UPSTREAM,
        label="Rotator rate",
        type=SettingType.INT,
        default=300,
        unit=_PER_MIN,
        min=1,
        max=10000,
        step=1,
        description=(
            "How many calls per minute Roxy may send through the rotating proxy service (DataImpulse), whose "
            "exits use many different IP addresses, across all workers. The rotator only ever carries anonymous "
            "traffic, never the credential, and every byte through it is billed."
        ),
        pages=(_BUCKETS, _ROTATOR),
        if_raised=(
            "The rotator can take more load when the direct path is busy or cooling down, at the cost of more "
            "billed bytes and faster use of the monthly quota."
        ),
        if_lowered=(
            "Less rotator spending and quota use. When the direct path is also busy, more requests wait, are "
            "answered from older cached copies, or get 429 'busy' answers."
        ),
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=(
            "rotator_bucket_burst",
            "rotator_enabled",
            "rotator_weight",
            "rotator_daily_cap_mb",
            "rotator_quota_gb_per_month",
            "global_bucket_per_min",
        ),
        related_recommendations=("UP-BUCKET-TUNE",),
        notes=(
            "With the default rotator_weight of 0 the rotator is used only when the direct path cannot serve a "
            "request in time or an endpoint rule prefers it, so this limit rarely binds. The monthly byte quota "
            "and the daily cap apply on top of it."
        ),
    ),
    SettingSpec(
        key="rotator_bucket_burst",
        group=Group.UPSTREAM,
        label="Rotator burst",
        type=SettingType.INT,
        default=20,
        unit="requests",
        min=1,
        max=500,
        step=1,
        description=(
            "How many rotator calls may leave back to back before the steady pace of rotator_bucket_per_min applies."
        ),
        pages=(_BUCKETS, _ROTATOR),
        if_raised="Bigger spikes go through the rotator at once, spending billed bytes faster during a spike.",
        if_lowered=(
            "Rotator use is smoother; during a spike more requests wait or are answered from older cached copies."
        ),
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("rotator_bucket_per_min",),
        related_recommendations=("UP-BUCKET-TUNE",),
    ),
    SettingSpec(
        key="host_bucket_default_per_min",
        group=Group.UPSTREAM,
        label="Default rate per Roblox host",
        type=SettingType.INT,
        default=240,
        unit=_PER_MIN,
        min=1,
        max=10000,
        step=1,
        description=(
            "The most calls Roxy makes to one Roblox service host (for example games.roblox.com or "
            "users.roblox.com) in any minute, unless it has its own limit on Upstream > Buckets. Roblox runs each "
            "service separately, so this keeps one busy service from being hammered even when the overall rate is "
            "fine. The burst counts inside the same minute: no rolling minute ever holds more than this."
        ),
        pages=(_BUCKETS,),
        if_raised="More throughput for each Roblox service, with more risk of 429s from that service.",
        if_lowered=(
            "Each service is called more gently; requests to a busy host wait longer or are answered from older "
            "cached copies."
        ),
        risk=Risk.MEDIUM,
        apply=Apply.LIVE,
        related_settings=("host_bucket_default_burst", "endpoint_bucket_default_per_min", "global_bucket_per_min"),
        related_recommendations=("UP-429-HOST", "UP-BUCKET-TUNE"),
        notes=(
            "Per-host limits (set by an admin, by an applied recommendation, or lowered by the adaptive "
            "controller when several endpoints of one host get 429s together) win over this default. Changing "
            "the default affects every host without its own limit."
        ),
    ),
    SettingSpec(
        key="host_bucket_default_burst",
        group=Group.UPSTREAM,
        label="Default burst per Roblox host",
        type=SettingType.INT,
        default=15,
        unit="requests",
        min=1,
        max=500,
        step=1,
        description=(
            "How many calls to one Roblox host may leave back to back before the steady pace applies, for hosts "
            "without their own limit on Upstream > Buckets. The burst is part of the host's per-minute limit, not "
            "added to it: at 240 a minute with a burst of 15, 15 calls may go at once and the rest of the minute "
            "is paced so no minute holds more than 240."
        ),
        pages=(_BUCKETS,),
        if_raised="Bigger spikes reach one Roblox service at once, with more risk of 429s from that service.",
        if_lowered="Calls to each host are spread out more evenly; spikes on one host wait briefly.",
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("host_bucket_default_per_min",),
        related_recommendations=("UP-429-HOST", "UP-BUCKET-TUNE"),
    ),
    SettingSpec(
        key="endpoint_bucket_default_per_min",
        group=Group.UPSTREAM,
        label="Default rate per endpoint",
        type=SettingType.INT,
        default=120,
        unit=_PER_MIN,
        min=1,
        max=10000,
        step=1,
        description=(
            "The most calls Roxy makes to one endpoint template (one Roblox API path with ids replaced by "
            "placeholders, such as users.roblox.com/v1/users/{id}) in any minute, unless it has its own limit on "
            "Upstream > Buckets. Roblox limits many APIs per endpoint and counts calls in a rolling minute, so this "
            "is the bucket that most often matches Roblox's own limit, and the burst counts inside the same minute: "
            "no rolling minute ever holds more than this."
        ),
        pages=(_BUCKETS,),
        if_raised=(
            "More throughput for every endpoint without its own limit, and more per-endpoint 429s on endpoints "
            "whose real Roblox limit is lower."
        ),
        if_lowered=(
            "Smoother pacing on every endpoint without its own limit; busy endpoints wait more and are answered "
            "from older cached copies more often."
        ),
        risk=Risk.MEDIUM,
        apply=Apply.LIVE,
        related_settings=(
            "endpoint_bucket_default_burst",
            "adaptive_rate_enabled",
            "adaptive_min_per_min",
            "adaptive_max_per_min",
            "host_bucket_default_per_min",
        ),
        related_recommendations=("UP-429-ENDPOINT", "UP-BUCKET-TUNE"),
        notes=(
            "Per-endpoint limits come from an admin, an applied recommendation, or the adaptive rate "
            "controller, and win over this default. Recommendations change one endpoint's limit, never this "
            "default, because a change here throttles every endpoint at once. Because the burst fits inside the "
            "minute, the steady pace is a little lower than the limit: at 120 with a burst of 10, 10 calls may go "
            "at once and then about 109 a minute (Roxy paces over 61 s, a 1 s margin for network delays)."
        ),
    ),
    SettingSpec(
        key="endpoint_bucket_default_burst",
        group=Group.UPSTREAM,
        label="Default burst per endpoint",
        type=SettingType.INT,
        default=10,
        unit="requests",
        min=1,
        max=500,
        step=1,
        description=(
            "How many calls to one endpoint template may leave back to back before the steady pace applies, for "
            "endpoints without their own limit on Upstream > Buckets. The burst is part of the endpoint's "
            "per-minute limit, not added to it, and the adaptive controller cuts it together with the rate."
        ),
        pages=(_BUCKETS,),
        if_raised="Bigger spikes reach one Roblox endpoint at once, with more risk of per-endpoint 429s.",
        if_lowered="Calls to each endpoint are spread out more evenly; spikes on one endpoint wait briefly.",
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("endpoint_bucket_default_per_min",),
        related_recommendations=("UP-429-ENDPOINT", "UP-BUCKET-TUNE"),
    ),
    # ---- Adaptive per-endpoint rate (plan 7.3) -----------------------------------------------------------
    SettingSpec(
        key="adaptive_rate_enabled",
        group=Group.UPSTREAM,
        label="Adaptive per-endpoint rate",
        type=SettingType.BOOL,
        default=1,
        description=(
            "Lets Roxy tune each endpoint's rate by itself: after a Roblox 429 it lowers that endpoint's rate, "
            "and after a long clean period with real demand above the limit it raises it a little. Every change "
            "is written as a per-endpoint limit you can see and edit on Upstream > Buckets."
        ),
        pages=(_BUCKETS,),
        if_enabled=(
            "On a Roblox 429 the endpoint's rate and burst drop by adaptive_decrease_pct, counted from the calls "
            "it actually made in the last minute when that is lower than its rate (never below "
            "adaptive_min_per_min); after adaptive_probe_after_h clean hours with demand above the limit it "
            "rises by adaptive_increase_pct (never above adaptive_max_per_min), its burst by at most one call. "
            "When several endpoints of one host get 429s together, the host's rate is lowered instead."
        ),
        if_disabled=(
            "Rates stay exactly where they are and change only when an admin edits them or applies a "
            "recommendation. Cooldowns after a 429 still happen; only the automatic rate tuning stops, so "
            "repeated 429s on one endpoint are more likely."
        ),
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=(
            "adaptive_decrease_pct",
            "adaptive_increase_pct",
            "adaptive_probe_after_h",
            "adaptive_min_per_min",
            "adaptive_max_per_min",
            "endpoint_bucket_default_per_min",
        ),
        related_recommendations=("UP-BUCKET-TUNE",),
        notes="Every adjustment is logged with its evidence and shown in UP-BUCKET-TUNE recommendations.",
    ),
    SettingSpec(
        key="adaptive_decrease_pct",
        group=Group.UPSTREAM,
        label="Adaptive cut after a 429",
        type=SettingType.PERCENT,
        default=30,
        unit="percent",
        min=5,
        max=90,
        step=1,
        description=(
            "How much the adaptive controller cuts an endpoint's rate each time Roblox answers it with 429. The cut "
            "starts from the calls the endpoint actually made in the last minute when that is lower than its "
            "rate, because that is the rate Roblox refused: at 30, an endpoint at 120 per minute that made 61 "
            "calls drops to 42.7 (its burst from 10 to 3), and one that Roxy cannot measure, or that made no more "
            "calls than adaptive_min_per_min, drops to 84 (burst 7)."
        ),
        pages=(_BUCKETS,),
        if_raised=(
            "Roxy backs off harder after a 429, so a repeat 429 is less likely, but the endpoint queues more and "
            "serves older cached copies until its rate climbs back, which is slow (see adaptive_increase_pct)."
        ),
        if_lowered=(
            "Gentler cuts keep more throughput after a 429, but Roxy may need several 429s in a row to find a "
            "rate Roblox accepts."
        ),
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("adaptive_rate_enabled", "adaptive_increase_pct", "adaptive_min_per_min"),
        related_recommendations=("UP-BUCKET-TUNE",),
    ),
    SettingSpec(
        key="adaptive_increase_pct",
        group=Group.UPSTREAM,
        label="Adaptive raise after a clean period",
        type=SettingType.PERCENT,
        default=10,
        unit="percent",
        min=1,
        max=50,
        step=1,
        description=(
            "How much the adaptive controller raises an endpoint's rate after a clean period "
            "(adaptive_probe_after_h hours with no 429s while callers wanted more than the limit allowed). At "
            "10, an endpoint at 84 per minute rises to about 92. Its burst comes back more slowly: at most one "
            "call per raise, and never beyond the default burst."
        ),
        pages=(_BUCKETS,),
        if_raised=(
            "Rates recover faster after a cut, but each step can overshoot Roblox's real limit by more, "
            "earning a 429 and another cut."
        ),
        if_lowered="Slower, safer climbs; an endpoint that was cut stays slower for longer.",
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("adaptive_rate_enabled", "adaptive_decrease_pct", "adaptive_probe_after_h"),
        related_recommendations=("UP-BUCKET-TUNE",),
    ),
    SettingSpec(
        key="adaptive_probe_after_h",
        group=Group.UPSTREAM,
        label="Clean hours before a raise",
        type=SettingType.INT,
        default=24,
        unit="hours",
        min=1,
        max=168,
        step=1,
        description=(
            "How many hours in a row an endpoint must go with zero Roblox 429s, while more than 1% of its calls "
            "were held back by its limit, before the adaptive controller raises its rate. An endpoint whose "
            "limit is never reached is never raised, because there is no evidence it needs more."
        ),
        pages=(_BUCKETS,),
        if_raised="Raises are rarer and need longer proof, so rates stay conservative after a cut.",
        if_lowered=(
            "Raises come sooner and rates recover faster, but a period shorter than a day may miss Roblox "
            "limits that only show at the busiest time of day."
        ),
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("adaptive_rate_enabled", "adaptive_increase_pct"),
        related_recommendations=("UP-BUCKET-TUNE",),
    ),
    SettingSpec(
        key="adaptive_min_per_min",
        group=Group.UPSTREAM,
        label="Adaptive floor",
        type=SettingType.INT,
        default=6,
        unit=_PER_MIN,
        min=1,
        max=600,
        step=1,
        description=(
            "The lowest rate the adaptive controller may set for an endpoint, however many 429s it sees. It "
            "keeps an endpoint from being slowed almost to a stop by automatic tuning."
        ),
        pages=(_BUCKETS,),
        if_raised="A 429-prone endpoint keeps more throughput, but Roxy may keep pushing it into Roblox's limit.",
        if_lowered=(
            "Roxy may slow an endpoint almost to a stop, which can starve that endpoint's callers (they get "
            "older cached copies or 429 'busy' answers)."
        ),
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("adaptive_max_per_min", "adaptive_decrease_pct", "endpoint_bucket_default_per_min"),
        related_recommendations=("UP-BUCKET-TUNE",),
        notes="Checked when saved: must be no higher than adaptive_max_per_min.",
    ),
    SettingSpec(
        key="adaptive_max_per_min",
        group=Group.UPSTREAM,
        label="Adaptive ceiling",
        type=SettingType.INT,
        default=600,
        unit=_PER_MIN,
        min=10,
        max=10000,
        step=1,
        description=(
            "The highest rate the adaptive controller may raise an endpoint to. The global, egress and host "
            "rates still apply above it."
        ),
        pages=(_BUCKETS,),
        if_raised="More headroom for busy endpoints that prove, hour after hour, that Roblox accepts more.",
        if_lowered="Caps how far automatic tuning can grow any endpoint; busy endpoints stop growing sooner.",
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("adaptive_min_per_min", "adaptive_increase_pct", "global_bucket_per_min"),
        related_recommendations=("UP-BUCKET-TUNE",),
        notes="Checked when saved: must be no lower than adaptive_min_per_min.",
    ),
    # ---- Adaptive concurrency, AIMD (plan 7.4, Tier 3, off by default) -----------------------------------
    SettingSpec(
        key="aimd_enabled",
        group=Group.UPSTREAM,
        label="Adaptive concurrency (AIMD)",
        type=SettingType.BOOL,
        default=0,
        description=(
            "An optional extra limit on how many calls may be in flight at the same time to each Roblox host on "
            "each egress path. It grows the limit slowly while calls succeed and cuts it sharply on a 429, a "
            "timeout or a server error. Off by default, because Roblox limits request rate rather than parallel "
            "calls, and the rate buckets already handle rate."
        ),
        pages=(_CONCURRENCY,),
        if_enabled=(
            "Each host and egress pair starts at aimd_initial parallel calls, gains 1 after every "
            "aimd_increase_after successes in a row up to aimd_max, and is multiplied by aimd_decrease_factor "
            "on trouble (never below aimd_min). Calls beyond the limit wait in the queue, and the Upstream page "
            "charts the limit against calls in flight."
        ),
        if_disabled=(
            "Only the rate buckets pace upstream calls; the number of calls in flight is bounded only by the "
            "connection pools."
        ),
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("aimd_initial", "aimd_min", "aimd_max", "aimd_increase_after", "aimd_decrease_factor"),
        notes=(
            "Useful only for a host whose response time collapses under parallel load. AIMD stands for "
            "additive increase, multiplicative decrease, the same idea TCP uses to avoid network congestion. "
            "In-flight slots expire on their own, so a crashed worker cannot leak them."
        ),
    ),
    SettingSpec(
        key="aimd_initial",
        group=Group.UPSTREAM,
        label="AIMD starting limit",
        type=SettingType.INT,
        default=8,
        unit="concurrent requests",
        min=1,
        max=256,
        step=1,
        description=(
            "The number of parallel calls each host and egress pair starts with when adaptive concurrency "
            "(aimd_enabled) is on."
        ),
        pages=(_CONCURRENCY,),
        if_raised="More parallel calls at the start, before Roxy has learned how much each host tolerates.",
        if_lowered="A cautious start; parallelism grows as calls succeed.",
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("aimd_enabled", "aimd_min", "aimd_max"),
        notes="Checked when saved: must be between aimd_min and aimd_max. Used only when aimd_enabled is 1.",
    ),
    SettingSpec(
        key="aimd_min",
        group=Group.UPSTREAM,
        label="AIMD lowest limit",
        type=SettingType.INT,
        default=1,
        unit="concurrent requests",
        min=1,
        max=256,
        step=1,
        description=(
            "The lowest parallel call limit adaptive concurrency may cut a host and egress pair down to, "
            "however much trouble it sees."
        ),
        pages=(_CONCURRENCY,),
        if_raised="Hosts keep more parallel calls even after repeated trouble, so a struggling host gets less relief.",
        if_lowered="A struggling host can be cut to very few parallel calls, which protects it but makes callers wait.",
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("aimd_enabled", "aimd_initial", "aimd_max"),
        notes="Checked when saved: must be no higher than aimd_initial. Used only when aimd_enabled is 1.",
    ),
    SettingSpec(
        key="aimd_max",
        group=Group.UPSTREAM,
        label="AIMD highest limit",
        type=SettingType.INT,
        default=32,
        unit="concurrent requests",
        min=1,
        max=256,
        step=1,
        description="The highest parallel call limit adaptive concurrency may grow a host and egress pair to.",
        pages=(_CONCURRENCY,),
        if_raised="Healthy hosts may get more parallel calls, which means more open connections and sockets.",
        if_lowered="Caps parallelism; under heavy load more calls wait in the queue.",
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("aimd_enabled", "aimd_initial", "aimd_min"),
        notes="Checked when saved: must be no lower than aimd_initial. Used only when aimd_enabled is 1.",
    ),
    SettingSpec(
        key="aimd_increase_after",
        group=Group.UPSTREAM,
        label="AIMD successes before a raise",
        type=SettingType.INT,
        default=50,
        unit="successes",
        min=1,
        max=10000,
        step=1,
        description=(
            "How many successful calls in a row a host and egress pair needs before adaptive concurrency allows "
            "one more parallel call."
        ),
        pages=(_CONCURRENCY,),
        if_raised="Slower ramp up: the limit grows only after a long run of successes.",
        if_lowered="Faster ramp up toward aimd_max, with more risk of overshooting what the host tolerates.",
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("aimd_enabled", "aimd_max"),
    ),
    SettingSpec(
        key="aimd_decrease_factor",
        group=Group.UPSTREAM,
        label="AIMD cut factor",
        type=SettingType.FLOAT,
        default=0.5,
        unit="multiplier",
        min=0.1,
        max=0.95,
        step=0.05,
        description=(
            "What the parallel call limit is multiplied by after a 429, a timeout or a server error when "
            "adaptive concurrency is on. At 0.5 a limit of 16 drops to 8."
        ),
        pages=(_CONCURRENCY,),
        if_raised="Gentler cuts (0.9 turns 16 into about 14), so throughput recovers faster but trouble lasts longer.",
        if_lowered=(
            "Harsher cuts (0.25 turns 16 into 4), relieving a struggling host quickly at the cost of throughput."
        ),
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("aimd_enabled", "aimd_min"),
    ),
    # ---- Cooldowns after a 429 (plan 7.5) ----------------------------------------------------------------
    SettingSpec(
        key="cooldown_default_s",
        group=Group.UPSTREAM,
        label="Default cooldown after a 429",
        type=SettingType.DURATION,
        default=30,
        unit="seconds",
        min=1,
        max=3600,
        step=1,
        description=(
            "How long Roxy stops calling an endpoint through one egress path, on every worker, after Roblox "
            "answers 429 without a Retry-After header. Repeated 429s on the same endpoint double it (30, 60, "
            "120 seconds and so on, with a little randomness) up to cooldown_max_s. During a cooldown callers "
            "get an older cached copy when one exists, otherwise a 429 with Retry-After."
        ),
        pages=(_COOLDOWNS,),
        if_raised=(
            "Roxy rests a limited endpoint longer, which makes a repeat 429 less likely; callers see older "
            "cached data or 429 answers for longer."
        ),
        if_lowered=(
            "Roxy returns to a limited endpoint sooner. If Roblox's limit has not reset yet, the next call earns "
            "another 429 and a longer cooldown."
        ),
        risk=Risk.MEDIUM,
        high_risk_if=(
            RiskCondition(
                RiskOp.LT,
                5,
                "Coming back within seconds of a 429 with no Retry-After nearly always earns another 429, and "
                "turns a short limit into a long one for every caller.",
            ),
        ),
        apply=Apply.LIVE,
        related_settings=(
            "cooldown_min_s",
            "cooldown_max_s",
            "credential_cooldown_default_s",
            "cooldown_host_escalation_endpoints",
        ),
        related_recommendations=("SEC-DEFAULTS",),
        notes=(
            "When Roblox does send Retry-After, or an x-ratelimit-remaining of 0 with a reset time, Roxy waits "
            "as long as Roblox asks instead, kept between cooldown_min_s and cooldown_max_s. A credential 429 "
            "uses credential_cooldown_default_s instead of this value."
        ),
    ),
    SettingSpec(
        key="cooldown_min_s",
        group=Group.UPSTREAM,
        label="Shortest cooldown",
        type=SettingType.DURATION,
        default=1,
        unit="seconds",
        min=1,
        max=3600,
        step=1,
        description=(
            "The shortest cooldown Roxy will use after a 429, even when Roblox's Retry-After header asks for "
            "less (or for zero)."
        ),
        pages=(_COOLDOWNS,),
        if_raised=(
            "Roxy rests endpoints longer than Roblox asked, which is safer for the server IP but serves older "
            "cached data or 429 answers for longer than necessary."
        ),
        if_lowered="Roxy follows short Retry-After values closely; 1 second is the most faithful setting.",
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("cooldown_max_s", "cooldown_default_s"),
        notes="Checked when saved: must be no higher than cooldown_max_s.",
    ),
    SettingSpec(
        key="cooldown_max_s",
        group=Group.UPSTREAM,
        label="Longest cooldown",
        type=SettingType.DURATION,
        default=600,
        unit="seconds",
        min=1,
        max=3600,
        step=1,
        description=(
            "The longest cooldown Roxy will use after a 429. It caps both Roblox's Retry-After value and the "
            "doubling of cooldown_default_s for repeated 429s, so one odd header cannot park an endpoint for "
            "hours."
        ),
        pages=(_COOLDOWNS,),
        if_raised=(
            "Roxy honors longer Retry-After values and lets repeated-429 backoff grow further, so persistent "
            "limits are respected; an endpoint may be answered only from cache or with 429s for longer."
        ),
        if_lowered=(
            "Endpoints come back sooner, but Roxy may cut a longer Roblox Retry-After short and call again "
            "before Roblox said it could, which usually earns another 429."
        ),
        risk=Risk.MEDIUM,
        high_risk_if=(
            RiskCondition(
                RiskOp.LT,
                60,
                "Any Retry-After longer than this is cut short, so Roxy calls Roblox again before Roblox said "
                "it could. Ignoring Retry-After is what turned v1's 429s into repeated blocks.",
            ),
        ),
        apply=Apply.LIVE,
        related_settings=("cooldown_min_s", "cooldown_default_s"),
        related_recommendations=("SEC-DEFAULTS",),
        notes="Checked when saved: must be no lower than cooldown_min_s.",
    ),
    SettingSpec(
        key="cooldown_host_escalation_endpoints",
        group=Group.UPSTREAM,
        label="Endpoints that escalate to a host cooldown",
        type=SettingType.INT,
        default=3,
        unit="endpoint templates",
        min=2,
        max=50,
        step=1,
        description=(
            "How many different endpoints of one Roblox host must get a 429 within "
            "cooldown_host_escalation_window_s before Roxy cools down the whole host on that egress path, "
            "instead of each endpoint alone. Several endpoints failing together usually means Roblox is "
            "limiting the host or the IP, not one API."
        ),
        pages=(_COOLDOWNS,),
        if_raised=(
            "Host-wide cooldowns are rarer, so the host's other endpoints keep flowing, but Roxy may keep "
            "calling a host that is limiting it as a whole."
        ),
        if_lowered=(
            "Host-wide cooldowns happen sooner, which is safer for the server IP but answers more of the host's "
            "healthy endpoints from cache or with 429s."
        ),
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("cooldown_host_escalation_window_s", "cooldown_default_s", "host_bucket_default_per_min"),
        related_recommendations=("UP-429-HOST",),
        notes=(
            "Rotator 429s follow their own rule (rotator_cooldown_distinct_exits), because each rotator session "
            "is a different exit IP."
        ),
    ),
    SettingSpec(
        key="cooldown_host_escalation_window_s",
        group=Group.UPSTREAM,
        label="Host escalation window",
        type=SettingType.DURATION,
        default=60,
        unit="seconds",
        min=10,
        max=3600,
        step=1,
        description=(
            "The time window in which cooldown_host_escalation_endpoints different endpoints of one host must "
            "get a 429 for the cooldown to cover the whole host."
        ),
        pages=(_COOLDOWNS,),
        if_raised=(
            "429s spread further apart still count together, so host-wide cooldowns happen more often (safer, "
            "more answers from cache)."
        ),
        if_lowered=(
            "Only 429s close together count, so host-wide cooldowns are rarer and the host's other endpoints "
            "keep flowing."
        ),
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("cooldown_host_escalation_endpoints",),
        related_recommendations=("UP-429-HOST",),
    ),
    # ---- Circuit breakers (plan 7.10) --------------------------------------------------------------------
    SettingSpec(
        key="breaker_failure_threshold",
        group=Group.UPSTREAM,
        label="Breaker failure count",
        type=SettingType.INT,
        default=5,
        unit="failures",
        min=1,
        max=1000,
        step=1,
        description=(
            "A circuit breaker stops Roxy from calling an endpoint (or a whole host) on one egress path while it "
            "is failing, instead of piling on. It opens when at least this many calls fail within "
            "breaker_window_s and the failed share is above breaker_failure_ratio; failures are timeouts, "
            "connection errors and Roblox server errors (5xx), and a 429 opens it at once for the Retry-After "
            "time."
        ),
        pages=(_BREAKERS,),
        if_raised=(
            "Breakers open less readily, so Roxy keeps calling a failing endpoint longer and callers wait for "
            "errors instead of getting a quick answer from cache."
        ),
        if_lowered=(
            "Breakers open after fewer failures, protecting callers and Roblox sooner, but a few unlucky errors "
            "on a quiet endpoint can trip one."
        ),
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("breaker_window_s", "breaker_failure_ratio", "breaker_open_s"),
        related_recommendations=("UP-5XX", "UP-BREAKER-FLAP"),
    ),
    SettingSpec(
        key="breaker_window_s",
        group=Group.UPSTREAM,
        label="Breaker window",
        type=SettingType.DURATION,
        default=30,
        unit="seconds",
        min=5,
        max=600,
        step=1,
        description="The time window in which a breaker counts failures and the failed share of calls.",
        pages=(_BREAKERS,),
        if_raised=(
            "Failures spread over a longer time add up, so a slowly failing endpoint trips its breaker more readily."
        ),
        if_lowered="Only failures close together count, so breakers open less readily.",
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("breaker_failure_threshold", "breaker_failure_ratio"),
        related_recommendations=("UP-5XX", "UP-BREAKER-FLAP"),
    ),
    SettingSpec(
        key="breaker_failure_ratio",
        group=Group.UPSTREAM,
        label="Breaker failure share",
        type=SettingType.FLOAT,
        default=0.5,
        unit="ratio",
        min=0.05,
        max=1,
        step=0.05,
        description=(
            "The share of calls within breaker_window_s that must fail before a breaker opens, as a fraction "
            "(0.5 means half). It keeps a busy endpoint with a few errors among many successes from tripping."
        ),
        pages=(_BREAKERS,),
        if_raised="Opens less readily: most calls must be failing (at 1, all of them).",
        if_lowered="Opens sooner, even while most calls still succeed.",
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("breaker_failure_threshold", "breaker_window_s"),
        related_recommendations=("UP-5XX", "UP-BREAKER-FLAP"),
    ),
    SettingSpec(
        key="breaker_open_s",
        group=Group.UPSTREAM,
        label="Breaker open time",
        type=SettingType.DURATION,
        default=30,
        unit="seconds",
        min=1,
        max=600,
        step=1,
        description=(
            "How long an open breaker blocks calls before letting a single test call through. If that call "
            "succeeds the breaker closes; if it fails, the breaker reopens for twice as long, up to 600 seconds. "
            "While it is open, callers get an older cached copy when one exists, otherwise a 429 with "
            "Retry-After."
        ),
        pages=(_BREAKERS,),
        if_raised=(
            "A failing endpoint is left alone longer, which helps it recover, but callers keep getting cached "
            "data or errors for a while after it is healthy again."
        ),
        if_lowered=(
            "Roxy tests a failing endpoint sooner and recovers faster, but may keep poking one that is still down."
        ),
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("breaker_failure_threshold", "breaker_window_s", "breaker_failure_ratio"),
        related_recommendations=("UP-BREAKER-FLAP",),
        auto_apply_bounds=(15, 120),
        notes="Only one test call runs at a time across all workers, so a recovering endpoint is not stampeded.",
    ),
    # ---- Retry backoff (plan 7.9) ------------------------------------------------------------------------
    SettingSpec(
        key="backoff_base_ms",
        group=Group.UPSTREAM,
        label="Retry wait, starting value",
        type=SettingType.DURATION,
        default=200,
        unit="ms",
        min=10,
        max=10000,
        step=10,
        description=(
            "Before Roxy retries a call that failed with a Roblox server error (5xx), a timeout or a connection "
            "error, it waits a random time that starts around this value and grows with each retry up to "
            "backoff_cap_ms. The randomness (jitter) keeps workers from retrying in lockstep; 429s are never "
            "retried this way."
        ),
        pages=(_COOLDOWNS, _RETRIES),
        if_raised=(
            "Retries wait longer, giving Roblox more time to recover; each failing request takes longer to finish."
        ),
        if_lowered="Retries come faster, so a briefly failing Roblox service is hit again sooner.",
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("backoff_cap_ms", "upstream_max_attempts", "request_timeout"),
        notes="Checked when saved: must be no higher than backoff_cap_ms.",
    ),
    SettingSpec(
        key="backoff_cap_ms",
        group=Group.UPSTREAM,
        label="Retry wait, longest value",
        type=SettingType.DURATION,
        default=2000,
        unit="ms",
        min=10,
        max=10000,
        step=10,
        description=(
            "The longest wait between retries of a failed upstream call. It is also part of the time budget for "
            "one shared upstream fetch, which must fit inside request_deadline_s."
        ),
        pages=(_COOLDOWNS, _RETRIES),
        if_raised="Retries can spread out more; a request that needs retries may take longer overall.",
        if_lowered="Retries stay close together, so failing requests finish sooner.",
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("backoff_base_ms", "request_deadline_s", "upstream_max_attempts"),
        notes=(
            "Checked when saved: must be no lower than backoff_base_ms, and queue_wait_interactive_ms plus "
            "request_timeout times upstream_max_attempts plus this value must stay at least 2 seconds below "
            "request_deadline_s."
        ),
    ),
    # ---- Priority queue (plan 7.8) -----------------------------------------------------------------------
    SettingSpec(
        key="queue_wait_interactive_ms",
        group=Group.UPSTREAM,
        label="Queue wait for callers with no cached copy",
        type=SettingType.DURATION,
        default=4000,
        unit="ms",
        min=0,
        max=20000,
        step=100,
        description=(
            "When the buckets have no free slot, how long a caller's request may wait for one if Roxy has no "
            "cached copy to fall back on. After that the caller gets a 429 with a Retry-After telling it when "
            "to come back."
        ),
        pages=(_QUEUE,),
        if_raised=(
            "Fewer 429 'busy' answers to callers, but they wait longer, and each waiting request holds a "
            "connection open."
        ),
        if_lowered="Callers hear 'busy, retry after N seconds' sooner instead of waiting.",
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("queue_wait_stale_ms", "request_deadline_s", "backoff_cap_ms", "global_bucket_per_min"),
        related_recommendations=("UP-QUEUE-SAT",),
        notes=(
            "Part of the time budget for one shared upstream fetch: this value plus request_timeout times "
            "upstream_max_attempts plus backoff_cap_ms must stay at least 2 seconds below request_deadline_s."
        ),
    ),
    SettingSpec(
        key="queue_wait_stale_ms",
        group=Group.UPSTREAM,
        label="Queue wait when a cached copy exists",
        type=SettingType.DURATION,
        default=500,
        unit="ms",
        min=0,
        max=5000,
        step=100,
        description=(
            "When the buckets have no free slot and Roxy holds an older cached copy of the answer, how long the "
            "request waits for a fresh call before serving that older copy instead."
        ),
        pages=(_QUEUE,),
        if_raised="Callers get fresh data more often, but wait longer for it.",
        if_lowered="Callers get the older copy almost at once; at 0 they never wait when a cached copy exists.",
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("queue_wait_interactive_ms", "cache_stale_seconds"),
        related_recommendations=("UP-QUEUE-SAT",),
    ),
    SettingSpec(
        key="queue_wait_background_ms",
        group=Group.UPSTREAM,
        label="Queue wait for background refreshes",
        type=SettingType.DURATION,
        default=10000,
        unit="ms",
        min=0,
        max=60000,
        step=100,
        description=(
            "How long a background refresh (Roxy updating an expired cache entry after already serving the old "
            "copy) may wait for a slot. Background work only takes slots while the global bucket is less than "
            "half reserved, and it is the first work dropped when the queue is full."
        ),
        pages=(_QUEUE,),
        if_raised="Background refreshes are more likely to finish during busy periods, keeping cached data fresher.",
        if_lowered=(
            "Background refreshes are dropped sooner under pressure; the entry stays old until the next caller "
            "request refreshes it."
        ),
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("queue_wait_interactive_ms", "global_bucket_per_min"),
        related_recommendations=("UP-QUEUE-SAT",),
    ),
    SettingSpec(
        key="queue_wait_admin_ms",
        group=Group.UPSTREAM,
        label="Queue wait for admin actions",
        type=SettingType.DURATION,
        default=10000,
        unit="ms",
        min=0,
        max=60000,
        step=100,
        description=(
            "How long an admin action that calls Roblox (such as a lookup or a cache refresh from the "
            "dashboard) may wait for a slot."
        ),
        pages=(_QUEUE,),
        if_raised="Admin actions are more likely to finish when Roxy is busy, but the dashboard may spin longer.",
        if_lowered="Admin actions fail sooner with a 'busy' message under load.",
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("queue_wait_internal_ms",),
    ),
    SettingSpec(
        key="queue_wait_internal_ms",
        group=Group.UPSTREAM,
        label="Queue wait for internal checks",
        type=SettingType.DURATION,
        default=30000,
        unit="ms",
        min=0,
        max=60000,
        step=100,
        description=(
            "How long Roxy's own probes and health checks may wait for a slot. Credential checks use their own "
            "reserved share (credential_probe_reserved_per_min), so they rarely wait."
        ),
        pages=(_QUEUE,),
        if_raised="Health checks and probes are more likely to finish under load instead of reporting a false failure.",
        if_lowered="Probes give up sooner under load, which can show a check as failed when Roxy was only busy.",
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("queue_wait_admin_ms", "credential_probe_reserved_per_min"),
    ),
    SettingSpec(
        key="queue_max_length",
        group=Group.UPSTREAM,
        label="Queue length per worker",
        type=SettingType.INT,
        default=500,
        unit="requests",
        min=10,
        max=10000,
        step=10,
        description=(
            "The most requests one worker process may hold waiting for an upstream slot. When it is full the "
            "lowest priority waiter is dropped: background refreshes first, then callers, who get an older "
            "cached copy or a 429 with Retry-After. With 2 workers the whole server can hold twice this many."
        ),
        pages=(_QUEUE,),
        if_raised="Fewer drops during spikes, but more open connections and memory held by waiting requests.",
        if_lowered="Less memory held during spikes; more requests are dropped early with a 'busy' answer.",
        risk=Risk.LOW,
        high_risk_if=(
            RiskCondition(
                RiskOp.GT,
                2000,
                "This server has less than 1 GB of memory. Thousands of waiting requests per worker, each "
                "holding a connection and its request body, can push a worker past its memory limit, and the "
                "system then restarts it, dropping every request it held.",
            ),
        ),
        apply=Apply.LIVE,
        related_settings=("queue_wait_interactive_ms", "queue_wait_background_ms"),
        related_recommendations=("UP-QUEUE-SAT", "SEC-DEFAULTS"),
        notes=(
            "Fairness between workers does not come from this cap but from each priority's maximum wait: a "
            "caller may reserve a slot further ahead than a background refresh can."
        ),
    ),
    SettingSpec(
        key="request_deadline_s",
        group=Group.UPSTREAM,
        label="Request deadline",
        type=SettingType.DURATION,
        default=60,
        unit="seconds",
        min=10,
        max=90,
        step=1,
        description=(
            "The longest any single proxy request may take inside Roxy, from arrival to answer, including queue "
            "waits, retries and backoff. When it runs out the caller gets a 504 with Retry-After. Every inner "
            "time budget is derived from it, so they can never add up past it."
        ),
        pages=(_QUEUE,),
        if_raised=(
            "Slow requests may finish instead of ending in a 504, but each one holds a connection and worker "
            "resources longer."
        ),
        if_lowered="Stuck requests end sooner with a 504; slow but valid upstream calls with retries may be cut off.",
        risk=Risk.MEDIUM,
        apply=Apply.LIVE,
        related_settings=(
            "queue_wait_interactive_ms",
            "backoff_cap_ms",
            "request_timeout",
            "upstream_max_attempts",
            "tarpit_max_seconds",
        ),
        notes=(
            "Saving is refused if queue_wait_interactive_ms plus request_timeout times upstream_max_attempts "
            "plus backoff_cap_ms (36 seconds at the defaults), or tarpit_max_seconds, would exceed this value "
            "minus 2 seconds. The maximum of 90 keeps it at least 10 seconds below nginx's 100 second "
            "proxy_read_timeout, so Roxy always answers before nginx gives up."
        ),
    ),
    # ---- Roblox CSRF tokens (plan 4.2 row 23, 7.9) -------------------------------------------------------
    SettingSpec(
        key="csrf_token_cache_s",
        group=Group.UPSTREAM,
        label="Roblox CSRF token reuse",
        type=SettingType.DURATION,
        default=600,
        unit="seconds",
        min=0,
        max=3600,
        step=1,
        description=(
            "Roblox requires an x-csrf-token header on write requests (POST, PATCH, PUT, DELETE): a write "
            "without a valid one gets a 403 carrying a fresh token, and Roxy retries once with it. This is how "
            "long Roxy keeps reusing that token, so later writes skip the extra 403 round trip. 0 turns reuse "
            "off."
        ),
        pages=(_RETRIES,),
        if_raised=(
            "Fewer extra 403 round trips on write requests, but a token Roblox has already retired is reused "
            "longer, which shows up as repeated 403s (see the UP-CSRF-LOOP recommendation)."
        ),
        if_lowered=(
            "Tokens are refreshed more often: more 403 handshakes, each one an extra upstream call that counts "
            "against the buckets, but fewer failures from old tokens. At 0 every write request first gets a 403."
        ),
        risk=Risk.LOW,
        apply=Apply.LIVE,
        related_settings=("global_bucket_per_min",),
        related_recommendations=("UP-CSRF-LOOP",),
        auto_apply_bounds=(60, 600),
        notes=(
            "Tokens are kept separately for each egress identity (the server IP, the credential, or one rotator "
            "session) and are never sent to callers. The single CSRF retry always uses the same egress path."
        ),
    ),
]
