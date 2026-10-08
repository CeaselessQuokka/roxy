"""Throttling and abuse detection settings (plan 15.3 E, without the per-detector spam keys).

What this is
    The catalog entries for the per-IP limit and its strike ladder, the emergency limit (throttle-all), the
    User-Agent rule master switch, and the detection side of abuse protection: the flood limit, per-experience
    (place) limits, IPv6 grouping, bans, bot scoring, the browser challenge, bypass expiry, ignored paths and
    the request size limits. Each entry is a `SettingSpec` with its type, default, range, plain-English help,
    risk, and the dashboard cards where it can be edited inline.

Why it exists
    Plan principle P3 (single source of truth): every tunable is declared exactly once, with enough text that
    an admin who has never seen Roxy can predict what a change does before making it. Validation, the
    settings editor, the generated docs/SETTINGS.md and the LLM export are all built from these declarations.

How it works
    This module is pure data. `SETTINGS` is a list of frozen `SettingSpec` objects: throttle keys use
    `Group.THROTTLING`, detection keys use `Group.ABUSE`. `roxy/config/catalog.py` collects this list with
    the other group modules and checks the whole catalog at import time. Defaults are the v2 column of plan
    15.3 E. Keys that existed in v1 carry `v1_default`, so the v1 migrator can tell an untouched v1 default
    from a value the owner chose on purpose. None of these keys has `auto_apply_bounds`: they are all
    protection controls, and auto-apply never touches security settings (plan 11.4). The spam detector
    master switches and the seven detectors live next door in `spam.py`.

What to read next
    `roxy/config/spec.py` (what each field means), `roxy/config/settings/spam.py` (the spam detectors),
    then plan section 10 and `roxy/abuse/pipeline.py`, where these values are enforced.
"""

from roxy.config.spec import (
    Group,
    OptionSpec,
    Risk,
    RiskCondition,
    RiskOp,
    SettingSpec,
    SettingType,
)

# Dashboard anchors (DESIGN.md section 9). Named once so a typo cannot hide a setting from its card.
_THROTTLE = "protection#throttle"
_THROTTLE_ALL_DIALOG = "topbar#throttle-all"
_LIMITS = "protection#limits"
_PLACES = "protection#places"
_CLIENT_PLACES = "clients#places"
_UA_RULES = "protection#ua-rules"
_BANS = "protection#bans"
_BOT = "protection#bot"
_CLIENT_SCORE = "clients#client-score"
_CHALLENGE = "protection#challenge"
_BYPASS = "protection#bypass"

# Ignored paths (Protection > Ignored paths) are rows of the control.db `ignored_paths` table, seeded by
# `config/defaults.py`; there is no setting for them (spec review 4: one source, recorded in CHANGES.md).

_BOT_WEIGHT_KEYS = (
    "bot_weight_library_ua",
    "bot_weight_no_roblox_signature",
    "bot_weight_probes",
    "bot_weight_refusals",
    "bot_weight_timing",
    "bot_weight_header_order",
    "bot_weight_cache_busting",
)


def _bot_weight(
    signal: str,
    label: str,
    default: int,
    measured: str,
    if_raised: str,
    if_lowered: str,
) -> SettingSpec:
    """Build one bot score weight (plan 10.7). All seven share a range and the same scoring formula."""
    key = f"bot_weight_{signal}"
    return SettingSpec(
        key=key,
        group=Group.ABUSE,
        label=f"Bot score weight: {label}",
        type=SettingType.INT,
        default=default,
        unit="weight",
        min=0,
        max=100,
        step=1,
        description=(
            f"How much this signal counts in a client's bot score (0 to 100, higher means more bot-like). "
            f"{measured} The score is the weighted average of the seven signals times 100, so a weight only "
            f"matters relative to the other six."
        ),
        if_raised=if_raised,
        if_lowered=if_lowered,
        risk=Risk.LOW,
        related_settings=(
            *(k for k in _BOT_WEIGHT_KEYS if k != key),
            "bot_score_block_threshold",
            "bot_score_abuse_min",
            "bot_score_legit_max",
        ),
        pages=(_BOT, _CLIENT_SCORE),
    )


SETTINGS: list[SettingSpec] = [
    # ------------------------------------------------------------------------------------------------------
    # Per-IP limit and strike ladder (Group.THROTTLING, Protection > Throttle)
    # ------------------------------------------------------------------------------------------------------
    SettingSpec(
        key="allowed_requests_per_minute",
        group=Group.THROTTLING,
        label="Requests per window",
        type=SettingType.INT,
        default=10,
        unit="requests per window",
        min=1,
        max=100000,
        step=1,
        description=(
            "How many requests one client IP address may make in each throttle window before Roxy refuses "
            "it with 429 Too Many Requests. The window length is the separate 'Throttle window length' "
            "setting, so the default is 10 requests per 50 seconds, not per minute."
        ),
        if_raised=(
            "Callers may send more before they are throttled, which is friendlier to busy game servers but "
            "lets one IP put more load on Roxy and take a bigger share of the upstream budget that every "
            "caller shares."
        ),
        if_lowered=(
            "Callers are refused with 429 sooner. Fairer to everyone else, but games whose servers share one "
            "IP address may start seeing throttles at busy times; the THROTTLE-TUNE recommendation reports "
            "when legitimate clients are being throttled."
        ),
        risk=Risk.MEDIUM,
        high_risk_if=(
            RiskCondition(
                RiskOp.GTE,
                1000,
                "At 1000 or more requests per window the per-IP limit barely limits anything, so a single "
                "client can take most of the upstream budget and push Roxy toward Roblox rate limits.",
            ),
        ),
        related_settings=(
            "throttle_reset_duration",
            "throttle_window_mode",
            "throttle_count_cache_hits",
            "flood_limit_per_minute",
            "place_limit_per_minute",
            "spam_rate_threshold",
            "cache_serve_throttled",
        ),
        related_recommendations=("THROTTLE-TUNE", "SEC-DEFAULTS"),
        pages=(_THROTTLE,),
        v1_default=10,
        notes=(
            "The key keeps its v1 name for compatibility even though the window is "
            "'Throttle window length' seconds long. The public home page shows the live value."
        ),
    ),
    SettingSpec(
        key="throttle_reset_duration",
        group=Group.THROTTLING,
        label="Throttle window length",
        type=SettingType.DURATION,
        default=50,
        unit="seconds",
        min=1,
        max=86400,
        step=1,
        description=(
            "Length of the per-IP throttle window in seconds, and also the base penalty: a throttled client "
            "waits this long times the multiplier of its strike ladder rung. In smooth pacing (gcra) mode the "
            "allowance refills evenly over this window, so 10 per 50 seconds means a burst of 10, then one "
            "new request every 5 seconds."
        ),
        if_raised=(
            "The same allowance is spread over more time, so the average allowed rate drops, and every "
            "penalty gets longer (with 300 seconds, an x8 ladder rung means a 40 minute wait)."
        ),
        if_lowered=(
            "The allowance refills faster, so the average allowed rate rises, and penalties get shorter, "
            "which makes the strike ladder a weaker deterrent."
        ),
        risk=Risk.LOW,
        related_settings=(
            "allowed_requests_per_minute",
            "throttle_window_mode",
            "stale_ip_duration",
            "throttle_escalation_enabled",
            "throttle_strike_decay_seconds",
        ),
        related_recommendations=("THROTTLE-TUNE",),
        pages=(_THROTTLE,),
        v1_default=50,
    ),
    SettingSpec(
        key="throttle_window_mode",
        group=Group.THROTTLING,
        label="Window algorithm",
        type=SettingType.ENUM,
        default="gcra",
        options=(
            OptionSpec(
                "fixed",
                "Fixed window (v1)",
                "The v1 behavior: every client gets its full allowance at the start of each window. A client "
                "can spend one allowance at the end of a window and another right after it starts again, so "
                "short bursts of up to twice the limit get through.",
            ),
            OptionSpec(
                "gcra",
                "Smooth pacing (recommended)",
                "A client may burst up to the limit at once, then earns one new request every "
                "(window length / limit) seconds. There is no window edge to exploit, and a client sending at "
                "exactly the limit rate is never refused. GCRA, the generic cell rate algorithm, is the "
                "standard way to pace requests evenly.",
            ),
        ),
        description=(
            "Chooses how the per-IP limit counts requests over time. Both modes allow the same average rate; "
            "smooth pacing removes the doubled burst a fixed window allows at its edges."
        ),
        risk=Risk.LOW,
        related_settings=("allowed_requests_per_minute", "throttle_reset_duration"),
        pages=(_THROTTLE,),
        notes="New in v2. v1 always behaved like 'fixed'.",
    ),
    SettingSpec(
        key="throttle_count_cache_hits",
        group=Group.THROTTLING,
        label="Count cache hits toward the per-IP limit",
        type=SettingType.BOOL,
        default=0,
        description=(
            "Whether a request answered from Roxy's own cache uses up part of the caller's per-IP allowance. "
            "Cache hits cost Roblox nothing, so by default only requests that need a fetch from Roblox count. "
            "The flood limit still counts every request."
        ),
        if_enabled=(
            "Every request counts, cached or not (the v1 behavior), so callers polling popular, already cached "
            "endpoints get 429s for answers that never touched Roblox."
        ),
        if_disabled=(
            "Only requests that are not served from cache count, so callers reading cached data keep working; "
            "the flood limit (300 per minute by default) still caps how fast one IP can send."
        ),
        risk=Risk.LOW,
        related_settings=(
            "allowed_requests_per_minute",
            "flood_limit_per_minute",
            "cache_enabled",
            "cache_serve_throttled",
        ),
        pages=(_THROTTLE,),
        notes="Owner decision D10. In v1 every request counted, cached or not.",
    ),
    SettingSpec(
        key="stale_ip_duration",
        group=Group.THROTTLING,
        label="Forget idle clients after",
        type=SettingType.DURATION,
        default=60,
        unit="seconds",
        min=1,
        max=86400,
        step=1,
        description=(
            "How long Roxy keeps the throttle record of a client IP that has stopped sending requests. After "
            "this much idle time the record is deleted, which keeps the tracking table small. Clients that "
            "still carry strikes are kept until their strikes decay."
        ),
        if_raised=(
            "Idle clients are remembered longer, so a client that pauses and comes back still has its partly "
            "used allowance counted; the tracking table holds more rows (it is capped at 200,000)."
        ),
        if_lowered=(
            "Records are pruned sooner and the table stays smaller. Keep it at or above the throttle window "
            "length: if it is shorter, a client that pauses briefly comes back with a full allowance early."
        ),
        risk=Risk.LOW,
        related_settings=("throttle_reset_duration", "throttle_strike_decay_seconds"),
        pages=(_THROTTLE,),
        v1_default=60,
    ),
    SettingSpec(
        key="throttle_escalation_enabled",
        group=Group.THROTTLING,
        label="Escalating throttles (strike ladder)",
        type=SettingType.BOOL,
        default=1,
        description=(
            "Each time a client trips the per-IP limit it gets a strike, and each strike moves it up a ladder "
            "of longer penalties (by default 1, 2, 4 and 8 times the window length, each rung with its own "
            "message). Repeat offenders then wait longer than a client that was too fast just once."
        ),
        if_enabled=(
            "Repeat offenders get progressively longer throttles and the rung messages; strikes fade again "
            "with good behavior (see 'Strike decay time')."
        ),
        if_disabled=(
            "Every throttle lasts exactly one window length however often the client has been throttled, so a "
            "script that simply waits out each penalty is never slowed further. Strikes are still counted and "
            "shown on the strike board but do not lengthen penalties."
        ),
        risk=Risk.MEDIUM,
        related_settings=(
            "throttle_strike_decay_seconds",
            "throttle_strike_on_retry",
            "throttle_reset_duration",
        ),
        pages=(_THROTTLE,),
        v1_default=1,
        notes="The ladder rungs (multiplier, message, action) are edited on the same card.",
    ),
    SettingSpec(
        key="throttle_strike_decay_seconds",
        group=Group.THROTTLING,
        label="Strike decay time",
        type=SettingType.DURATION,
        default=1800,
        unit="seconds",
        min=0,
        max=604800,
        step=1,
        description=(
            "How long a client must go without a new strike to lose one strike and drop one rung of the "
            "ladder. 0 means strikes never fade on their own; an admin can still forgive them on the strike "
            "board."
        ),
        if_raised=(
            "Strikes last longer, so a client that misbehaves again within that time lands on a higher rung "
            "with a longer penalty. A legitimate caller that tripped the limit once also carries the strike "
            "longer."
        ),
        if_lowered=(
            "Strikes are forgiven sooner, so occasional offenders return to the plain penalty quickly, but a "
            "patient abuser can wait out the ladder and start again at the bottom."
        ),
        risk=Risk.MEDIUM,
        high_risk_if=(
            RiskCondition(
                RiskOp.EQ,
                0,
                "Strikes never decay, so a legitimate caller that tripped the limit a few times stays on the "
                "top rung (the longest penalty) until an admin forgives it by hand.",
            ),
        ),
        related_settings=("throttle_escalation_enabled", "throttle_strike_on_retry", "stale_ip_duration"),
        related_recommendations=("SEC-DEFAULTS",),
        pages=(_THROTTLE,),
        v1_default=1800,
    ),
    SettingSpec(
        key="throttle_strike_on_retry",
        group=Group.THROTTLING,
        label="Retrying while throttled adds a strike",
        type=SettingType.BOOL,
        default=1,
        description=(
            "Whether a client that keeps sending requests while it is already throttled earns an extra "
            "strike. At most one extra strike is added per window, so one impatient retry is not punished "
            "over and over."
        ),
        if_enabled=(
            "Clients that ignore the Retry-After header and keep hammering while throttled climb the ladder "
            "faster and wait longer; clients that wait politely are not affected."
        ),
        if_disabled=(
            "Requests sent while throttled are refused but add no strikes (the v1 behavior), so a script "
            "retrying in a tight loop pays nothing extra."
        ),
        risk=Risk.LOW,
        related_settings=(
            "throttle_escalation_enabled",
            "throttle_strike_decay_seconds",
            "tarpit_on_throttle",
        ),
        related_recommendations=("UP-RETRYAFTER-IGNORED",),
        pages=(_THROTTLE,),
        notes="New in v2. v1 behaved as if this were 0.",
    ),
    # ------------------------------------------------------------------------------------------------------
    # Emergency per-IP limit (throttle-all), also editable from the top bar dialog
    # ------------------------------------------------------------------------------------------------------
    SettingSpec(
        key="global_throttle_limit",
        group=Group.THROTTLING,
        label="Emergency limit: requests per period",
        type=SettingType.INT,
        default=1,
        unit="requests per period",
        min=1,
        max=100000,
        step=1,
        description=(
            "While the emergency per-IP limit (throttle-all, switched on from the top bar during an incident) "
            "is active, each client IP may make this many requests per emergency period. It has no effect "
            "while throttle-all is off."
        ),
        if_raised="The emergency limit is looser, so more caller traffic still gets through during an incident.",
        if_lowered=(
            "The emergency limit is stricter. At 1 request per 60 seconds (the default) almost every caller is "
            "refused with 429 until throttle-all is switched off."
        ),
        risk=Risk.LOW,
        related_settings=("global_throttle_period", "allowed_requests_per_minute", "tarpit_on_throttle_all"),
        pages=(_THROTTLE, _THROTTLE_ALL_DIALOG),
        v1_default=1,
    ),
    SettingSpec(
        key="global_throttle_period",
        group=Group.THROTTLING,
        label="Emergency limit period",
        type=SettingType.DURATION,
        default=60,
        unit="seconds",
        min=1,
        max=86400,
        step=1,
        description=(
            "Length in seconds of the window used by the emergency per-IP limit (throttle-all). Each IP may "
            "make the emergency number of requests per this many seconds while throttle-all is on."
        ),
        if_raised=(
            "Stricter: the same request count is spread over more time, so clients wait longer between "
            "allowed requests during an incident."
        ),
        if_lowered="Looser: the emergency allowance refills sooner, so more traffic gets through.",
        risk=Risk.LOW,
        related_settings=("global_throttle_limit", "throttle_reset_duration"),
        pages=(_THROTTLE, _THROTTLE_ALL_DIALOG),
        v1_default=60,
    ),
    # ------------------------------------------------------------------------------------------------------
    # User-Agent rules master switch
    # ------------------------------------------------------------------------------------------------------
    SettingSpec(
        key="user_agent_rules_enabled",
        group=Group.THROTTLING,
        label="User-Agent rules",
        type=SettingType.BOOL,
        default=1,
        description=(
            "Master switch for the User-Agent rules, which rate limit clients by the User-Agent header they "
            "send (a burst allowance or a minimum gap between requests). Each rule has its own switch too; "
            "this one stops or starts all of them at once."
        ),
        if_enabled="Every enabled User-Agent rule is enforced, in order, and the first matching rule applies.",
        if_disabled=(
            "No User-Agent rule is enforced, including rules that hold back known abusive scripts; their "
            "traffic is limited only by the normal per-IP limit. Useful as a quick off switch when a rule "
            "catches legitimate callers."
        ),
        risk=Risk.MEDIUM,
        related_settings=("allowed_requests_per_minute", "tarpit_on_user_agent_rule"),
        pages=(_UA_RULES,),
        v1_default=1,
    ),
    # ------------------------------------------------------------------------------------------------------
    # Flood limit and IPv6 grouping (Group.ABUSE, Protection > Limits)
    # ------------------------------------------------------------------------------------------------------
    SettingSpec(
        key="flood_limit_per_minute",
        group=Group.ABUSE,
        label="Flood limit per IP",
        type=SettingType.INT,
        default=300,
        unit="requests per minute",
        min=10,
        max=100000,
        step=1,
        description=(
            "An absolute ceiling on requests per minute from one client IP, counting every request including "
            "the ones answered from cache. It is a safety net against raw floods that normal callers should "
            "never reach; requests over it are refused with reason flood."
        ),
        if_raised=(
            "The flood guard triggers later, so one client can push more requests per minute into Roxy (cache "
            "lookups, logging and database work) before being cut off."
        ),
        if_lowered=(
            "Floods are cut off sooner. Keep it well above the per-IP limit's rate (12 per minute with the "
            "defaults) and above what a busy game server reading cached data sends, or legitimate callers "
            "will be refused."
        ),
        risk=Risk.MEDIUM,
        high_risk_if=(
            RiskCondition(
                RiskOp.GTE,
                10000,
                "At 10,000 or more per minute (over 160 requests per second from one IP) the flood guard no "
                "longer protects Roxy's workers and databases from a single flooding client.",
            ),
        ),
        related_settings=(
            "allowed_requests_per_minute",
            "throttle_count_cache_hits",
            "ipv6_limit_prefix",
            "spam_rate_threshold",
        ),
        related_recommendations=("SEC-DEFAULTS",),
        pages=(_LIMITS,),
        notes="New in v2. nginx applies a cheaper, more generous limit in front of this one.",
    ),
    SettingSpec(
        key="ipv6_limit_prefix",
        group=Group.ABUSE,
        label="IPv6 grouping prefix",
        type=SettingType.INT,
        default=64,
        unit="prefix length (bits)",
        min=48,
        max=128,
        step=1,
        description=(
            "Per-IP limits treat all IPv6 addresses that share this many leading bits as one client, so by "
            "default every address in one /64 network shares one allowance. A home or server connection is "
            "usually given a whole /64, which holds billions of addresses, so limiting single IPv6 addresses "
            "would be easy to dodge."
        ),
        if_raised=(
            "Finer grouping. At 128 every single IPv6 address gets its own allowance, so a client can escape "
            "its limits just by switching to another address in its own network."
        ),
        if_lowered=(
            "Coarser grouping. At 48, about 65,000 /64 networks share one allowance, so unrelated users of the "
            "same provider can throttle each other."
        ),
        risk=Risk.MEDIUM,
        high_risk_if=(
            RiskCondition(
                RiskOp.GT,
                64,
                "Most IPv6 users control at least a /64, so a finer prefix lets one client rotate addresses "
                "and get a fresh allowance each time.",
            ),
        ),
        related_settings=("allowed_requests_per_minute", "flood_limit_per_minute", "place_limit_key"),
        related_recommendations=("SEC-DEFAULTS",),
        pages=(_LIMITS,),
        notes="IPv4 addresses are always limited one address at a time.",
    ),
    # ------------------------------------------------------------------------------------------------------
    # Per-experience (place) limits and Roblox game server ranges (Protection > Places, Clients > Places)
    # ------------------------------------------------------------------------------------------------------
    SettingSpec(
        key="place_limit_enabled",
        group=Group.ABUSE,
        label="Enforce per-experience limits",
        type=SettingType.BOOL,
        default=0,
        description=(
            "Whether Roxy enforces a request limit per Roblox experience (place), identified by the Roblox-Id "
            "header that game servers send. One experience can run on hundreds of server IPs, so per-IP "
            "limits cannot bound it, but this limit can. Off by default: Roxy only measures places and "
            "recommends."
        ),
        if_enabled=(
            "Requests over the per-experience limit are refused with 429 and reason place_limit. Experiences "
            "share upstream capacity more fairly, but a large legitimate game can be refused at peak times; "
            "check Clients > Places before turning this on."
        ),
        if_disabled=(
            "Places are only measured. The PLACE-HEAVY recommendation still tells you when one experience "
            "takes a large share of upstream calls."
        ),
        risk=Risk.MEDIUM,
        related_settings=("place_limit_per_minute", "place_limit_key", "allowed_requests_per_minute"),
        related_recommendations=("PLACE-HEAVY", "THROTTLE-TUNE"),
        pages=(_PLACES, _CLIENT_PLACES),
        notes="Owner decision D11. Place ids are claims any caller can forge; see 'Place limit counts by'.",
    ),
    SettingSpec(
        key="place_limit_per_minute",
        group=Group.ABUSE,
        label="Per-experience limit",
        type=SettingType.INT,
        default=600,
        unit="requests per minute",
        min=1,
        max=100000,
        step=1,
        description=(
            "How many requests per minute one experience (place) may send through Roxy while per-experience "
            "limits are on, counted across all of its servers as set by 'Place limit counts by'."
        ),
        if_raised=(
            "Large games can send more before being refused, with less protection against one experience "
            "crowding out the others."
        ),
        if_lowered=(
            "Stricter fairness between experiences, with a higher risk of refusing a big legitimate game "
            "during busy hours."
        ),
        risk=Risk.MEDIUM,
        related_settings=("place_limit_enabled", "place_limit_key"),
        related_recommendations=("PLACE-HEAVY", "THROTTLE-TUNE"),
        pages=(_PLACES, _CLIENT_PLACES),
    ),
    SettingSpec(
        key="place_limit_key",
        group=Group.ABUSE,
        label="Place limit counts by",
        type=SettingType.ENUM,
        default="place_prefix",
        options=(
            OptionSpec(
                "place",
                "Claimed place id only",
                "One shared budget per place id. The Roblox-Id header is a claim anyone can forge, so an "
                "attacker who sends a real game's place id can use up that game's whole budget and get its "
                "players refused.",
            ),
            OptionSpec(
                "place_prefix",
                "Place id and caller network (recommended)",
                "One budget per place id and caller network (a /24 for IPv4, a /48 for IPv6). A forger only "
                "spends the share that belongs to their own network, so a real game's servers keep theirs. A "
                "game spread across many networks gets one budget per network.",
            ),
        ),
        description=(
            "Decides what one per-experience budget belongs to. Place ids come from a header any caller can "
            "set, so counting them together with the caller's network stops a forger from exhausting a real "
            "game's budget."
        ),
        risk=Risk.MEDIUM,
        high_risk_if=(
            RiskCondition(
                RiskOp.EQ,
                "place",
                "Anyone can forge a game's Roblox-Id header and use up that game's whole budget, so its real "
                "players are refused.",
            ),
        ),
        related_settings=("place_limit_enabled", "place_limit_per_minute", "ipv6_limit_prefix"),
        related_recommendations=("SEC-DEFAULTS",),
        pages=(_PLACES, _CLIENT_PLACES),
    ),
    SettingSpec(
        key="roblox_egress_cidrs",
        group=Group.ABUSE,
        label="Roblox game server IP ranges",
        type=SettingType.LIST_CIDR,
        default=[],
        max_length=200,
        item_max_length=49,
        description=(
            "IP address ranges, written in CIDR form (for example 203.0.113.0/24, meaning 256 addresses), that "
            "are known to belong to Roblox game servers. Only callers inside these ranges that also carry the "
            "game server signature (a Roblox-Id header plus a Roblox User-Agent) get bot score credit and are "
            "never auto-banned by the spam detectors. With the list empty, the signature alone earns nothing, "
            "because it is easy to forge."
        ),
        if_raised=(
            "Adding ranges trusts more callers as game servers: they get a lower bot score and immunity from "
            "automatic spam bans. A range that is too broad or wrong shields any abuser inside it."
        ),
        if_lowered=(
            "Removing ranges trusts fewer callers. With an empty list no caller gets game server credit, so "
            "real game servers are scored like any other client and can be auto-banned once the spam "
            "detectors are armed."
        ),
        risk=Risk.MEDIUM,
        related_settings=("bot_weight_no_roblox_signature", "spam_dry_run", "place_limit_key"),
        pages=(_PLACES, _CLIENT_PLACES, _BOT),
        notes="Add only ranges Roblox itself documents; never add a range because one caller asked for it.",
    ),
    # ------------------------------------------------------------------------------------------------------
    # Bans (Protection > Bans)
    # ------------------------------------------------------------------------------------------------------
    SettingSpec(
        key="ban_disguise_as_throttle",
        group=Group.ABUSE,
        label="Disguise bans as throttles",
        type=SettingType.BOOL,
        default=1,
        description=(
            "When on, a banned client gets the same 429 Too Many Requests answer a throttled client gets, "
            "instead of 403 'Access denied.' with the header Roxy-Refusal: banned. Abusers who believe they "
            "are only throttled tend to wait instead of moving to a new IP address."
        ),
        if_enabled=(
            "Banned clients cannot tell they are banned, so they are less likely to switch IPs to escape. A "
            "legitimate caller banned by mistake cannot tell either, so check the bans list when someone "
            "reports endless 429s."
        ),
        if_disabled=(
            "Banned clients get 403 'Access denied.' with Roxy-Refusal: banned. Clearer for a caller banned by "
            "mistake, but it teaches abusers to switch IPs."
        ),
        risk=Risk.LOW,
        related_settings=("tarpit_on_ban",),
        pages=(_BANS,),
    ),
    # ------------------------------------------------------------------------------------------------------
    # Bot score thresholds and weights (Protection > Bot heuristics, Clients > client page)
    # ------------------------------------------------------------------------------------------------------
    SettingSpec(
        key="bot_score_block_threshold",
        group=Group.ABUSE,
        label="Block clients above bot score",
        type=SettingType.INT,
        default=0,
        unit="score (0 to 100)",
        min=0,
        max=100,
        step=1,
        description=(
            "Refuse requests from clients whose bot score (0 to 100, higher means more bot-like) is above this "
            "value, with reason bot_score. 0 turns blocking off; the score is then only shown and used by the "
            "detectors and recommendations."
        ),
        if_raised="Only very bot-like clients are blocked, so fewer legitimate callers are caught.",
        if_lowered=(
            "More clients are blocked. Low values catch ordinary game servers: with the default weights, a "
            "client without a trusted game server signature already starts at 15 points before any bad "
            "behavior."
        ),
        risk=Risk.MEDIUM,
        related_settings=(
            "bot_score_legit_max",
            "bot_score_abuse_min",
            "challenge_trigger_score",
            "roblox_egress_cidrs",
        ),
        related_recommendations=("FILTER-COLLATERAL",),
        pages=(_BOT, _CLIENT_SCORE),
        notes="Off by default: the score never blocks on its own unless this is set (plan 10.7).",
    ),
    SettingSpec(
        key="bot_score_legit_max",
        group=Group.ABUSE,
        label="Legitimate client score ceiling",
        type=SettingType.INT,
        default=30,
        unit="score (0 to 100)",
        min=0,
        max=100,
        step=1,
        description=(
            "Clients with a bot score at or below this value count as legitimate when the THROTTLE-TUNE and "
            "FILTER-COLLATERAL recommendations decide whether a limit or filter is hurting real users. It does "
            "not block or allow anything by itself."
        ),
        if_raised=(
            "More clients count as legitimate, so those rules see more collateral damage and suggest loosening "
            "limits and filters more often."
        ),
        if_lowered=(
            "Fewer clients count as legitimate, so those rules see less collateral damage and suggest "
            "loosening less often."
        ),
        risk=Risk.LOW,
        related_settings=(
            "bot_score_abuse_min",
            "bot_score_block_threshold",
            "insight_throttle_tune_legit_throttled_pct",
            "insight_filter_collateral_served_pct",
        ),
        pages=(_BOT, _CLIENT_SCORE),
    ),
    SettingSpec(
        key="bot_score_abuse_min",
        group=Group.ABUSE,
        label="Abusive client score floor",
        type=SettingType.INT,
        default=80,
        unit="score (0 to 100)",
        min=0,
        max=100,
        step=1,
        description=(
            "The ABUSE-BOT recommendation looks at clients whose bot score is at or above this value and that "
            "send more than 500 requests per hour. It only creates recommendations; it does not block "
            "anything."
        ),
        if_raised="Fewer bot recommendations, each about a client that is more certainly a bot.",
        if_lowered="More bot recommendations, including more false alarms about legitimate clients.",
        risk=Risk.LOW,
        related_settings=(
            "bot_score_legit_max",
            "bot_score_block_threshold",
            "insight_abuse_bot_min_requests_per_hour",
        ),
        pages=(_BOT, _CLIENT_SCORE),
    ),
    _bot_weight(
        "library_ua",
        "library or missing User-Agent",
        25,
        "Signal: 1 when the User-Agent is a programming library (python-requests, curl, Go-http-client) or "
        "is empty, otherwise 0.",
        if_raised="Scripts built on HTTP libraries score higher even when they are well behaved.",
        if_lowered="A library User-Agent matters less; 0 ignores which client software is calling.",
    ),
    _bot_weight(
        "no_roblox_signature",
        "no Roblox game server signature",
        15,
        "Signal: 1 when the request lacks the game server signature (a Roblox-Id header plus a Roblox "
        "User-Agent) or comes from outside the Roblox game server IP ranges, otherwise 0.",
        if_raised=(
            "Callers that are not trusted game servers score higher. With an empty Roblox game server IP "
            "list every caller gets this signal, so it raises everyone's score equally."
        ),
        if_lowered="Being a trusted game server earns less credit; 0 ignores the signature entirely.",
    ),
    _bot_weight(
        "probes",
        "probe history",
        25,
        "Signal: the number of probe requests (paths like .env or wp-login, unsafe characters, non-Roblox "
        "URLs) from the client in the last 24 hours divided by 5, capped at 1.",
        if_raised="Clients that have scanned for weaknesses score higher for a full day afterwards.",
        if_lowered="Past probing matters less; 0 ignores it, so a scanner that behaves for a while looks clean.",
    ),
    _bot_weight(
        "refusals",
        "refusal ratio",
        15,
        "Signal: the share of the client's requests that Roxy refused during the last hour, from 0 to 1.",
        if_raised=(
            "Clients that keep running into limits score higher, including legitimate callers that are simply busy."
        ),
        if_lowered="Hitting limits matters less; 0 ignores refusals entirely.",
    ),
    _bot_weight(
        "timing",
        "timing regularity",
        10,
        "Signal: 1 when the gaps between the client's requests are almost identical (the standard deviation of "
        "the gaps is under 5% of their average, over at least 50 requests), as with a script on a timer.",
        if_raised="Clients that poll on a fixed timer score higher, including game servers that poll on purpose.",
        if_lowered="Machine-like timing matters less; 0 ignores it.",
    ),
    _bot_weight(
        "header_order",
        "unusual header order",
        5,
        "Signal: 1 when the order of the request headers matches no known client family (browsers, Roblox "
        "game servers, common libraries), otherwise 0.",
        if_raised="Hand-built or unusual HTTP clients score higher even when their traffic is normal.",
        if_lowered="Header order matters less; 0 ignores it.",
    ),
    _bot_weight(
        "cache_busting",
        "cache busting",
        5,
        "Signal: the share of unique query values over the client's last 200 requests, from 0 to 1. Unique "
        "values on every request (a random number or timestamp) defeat Roxy's cache.",
        if_raised="Clients whose queries are always different score higher, including ones that look up many ids.",
        if_lowered="Cache busting matters less to the score; 0 ignores it (the SPAM-BUST detector still watches it).",
    ),
    # ------------------------------------------------------------------------------------------------------
    # Browser challenge (Protection > Challenge)
    # ------------------------------------------------------------------------------------------------------
    SettingSpec(
        key="challenge_enabled",
        group=Group.ABUSE,
        label="Browser challenge",
        type=SettingType.BOOL,
        default=0,
        description=(
            "Show a short proof-of-work page to browser clients whose bot score is above the challenge trigger "
            "score. The browser solves a small hashing puzzle in JavaScript and receives a signed cookie; "
            "scrapers that cannot run JavaScript never get through. Roblox game servers are never challenged."
        ),
        if_enabled=(
            "Browser-based scrapers above the trigger score must solve a puzzle (about 0.3 seconds on a laptop "
            "at the default difficulty) before being served; refusals show reason challenge."
        ),
        if_disabled="No challenge page; bot-like browsers are handled only by limits, rules and bans.",
        risk=Risk.LOW,
        related_settings=(
            "challenge_difficulty_bits",
            "challenge_trigger_score",
            "challenge_cookie_minutes",
            "bot_score_block_threshold",
        ),
        pages=(_CHALLENGE,),
    ),
    SettingSpec(
        key="challenge_difficulty_bits",
        group=Group.ABUSE,
        label="Challenge difficulty",
        type=SettingType.INT,
        default=18,
        unit="bits",
        min=10,
        max=26,
        step=1,
        description=(
            "How hard the proof-of-work puzzle is: the browser must find a SHA-256 hash that starts with this "
            "many zero bits. Each extra bit doubles the average solve time; 18 bits takes about 0.3 seconds on "
            "a laptop."
        ),
        if_raised=(
            "Each pass costs scrapers more computing time, but real visitors wait longer: about 1.2 seconds at "
            "20 bits and about 20 seconds at 24 bits on a laptop, and much longer on a phone."
        ),
        if_lowered=(
            "Puzzles solve faster, which is kinder to visitors but makes passing cheap for scrapers (12 bits "
            "takes a few milliseconds)."
        ),
        risk=Risk.MEDIUM,
        high_risk_if=(
            RiskCondition(
                RiskOp.GTE,
                24,
                "About 20 seconds per solve on a laptop and over a minute on a phone, so many real visitors "
                "give up before the page loads.",
            ),
        ),
        related_settings=("challenge_enabled", "challenge_trigger_score", "challenge_cookie_minutes"),
        related_recommendations=("SEC-DEFAULTS",),
        pages=(_CHALLENGE,),
    ),
    SettingSpec(
        key="challenge_trigger_score",
        group=Group.ABUSE,
        label="Challenge above bot score",
        type=SettingType.INT,
        default=80,
        unit="score (0 to 100)",
        min=0,
        max=100,
        step=1,
        description=(
            "Browser clients whose bot score is above this value are shown the challenge page while the "
            "browser challenge is on."
        ),
        if_raised="Only very bot-like browsers are challenged, so fewer real visitors ever see the puzzle.",
        if_lowered=(
            "More browsers are challenged, including more real visitors; at 0 every browser without a valid "
            "challenge cookie is challenged."
        ),
        risk=Risk.LOW,
        related_settings=("challenge_enabled", "bot_score_block_threshold", "bot_score_abuse_min"),
        pages=(_CHALLENGE,),
    ),
    SettingSpec(
        key="challenge_cookie_minutes",
        group=Group.ABUSE,
        label="Challenge pass lasts",
        type=SettingType.INT,
        default=30,
        unit="minutes",
        min=1,
        max=1440,
        step=1,
        description=(
            "How long a browser that solved the challenge may skip it again, remembered with a signed cookie."
        ),
        if_raised=(
            "Real browsers are challenged less often, but a scraper that solves one puzzle can reuse the cookie "
            "for longer."
        ),
        if_lowered="Passes expire sooner, so every browser, real or not, is challenged more often.",
        risk=Risk.LOW,
        related_settings=("challenge_enabled", "challenge_difficulty_bits"),
        pages=(_CHALLENGE,),
    ),
    # ------------------------------------------------------------------------------------------------------
    # Bypass list (Protection > Bypass)
    # ------------------------------------------------------------------------------------------------------
    SettingSpec(
        key="bypass_default_expiry_h",
        group=Group.ABUSE,
        label="Default bypass expiry",
        type=SettingType.INT,
        default=24,
        unit="hours",
        min=0,
        max=8760,
        step=1,
        description=(
            "How long a new bypass entry lasts unless the admin picks another time. A bypassed IP or range "
            "skips throttle-all, the per-IP limit, User-Agent rules, endpoint rate rules and the tarpit, but "
            "is still subject to pause, blocks, filters and auth checks. 0 means new entries never expire."
        ),
        if_raised=(
            "Entries last longer before they must be renewed, so forgotten load-test or office entries keep "
            "unlimited access for longer."
        ),
        if_lowered="Entries expire sooner, so you renew them more often, but nothing stays unlimited by accident.",
        risk=Risk.MEDIUM,
        high_risk_if=(
            RiskCondition(
                RiskOp.EQ,
                0,
                "New bypass entries never expire, so a forgotten load-test entry gives that IP unlimited "
                "access forever.",
            ),
        ),
        related_recommendations=("SEC-BYPASS-FOREVER", "SEC-DEFAULTS"),
        pages=(_BYPASS,),
        notes=(
            "Choosing 'never' for a single entry needs a confirmation. In v1, bypass entries never expired by default."
        ),
    ),
    # ------------------------------------------------------------------------------------------------------
    # Request size limits (Protection > Limits, plan 9.12)
    # ------------------------------------------------------------------------------------------------------
    SettingSpec(
        key="max_body_bytes",
        group=Group.ABUSE,
        label="Largest request body",
        type=SettingType.BYTES,
        default=2097152,
        unit="bytes",
        min=1024,
        max=2097152,
        step=1024,
        description=(
            "The largest request body (for example a POST batch lookup) Roxy accepts; bigger bodies are refused "
            "with 413 and logged as probes. The same size bounds how much of each body the credential leak "
            "guard and the auth smuggling check scan, so it cannot exceed nginx's 2 MiB body limit."
        ),
        if_raised=(
            "Larger batch bodies are accepted, up to the 2 MiB nginx limit; each one costs a little more memory "
            "and scanning time."
        ),
        if_lowered=(
            "Large bodies are refused with 413 sooner, so callers sending big batch lookups (long lists of ids) "
            "must split them."
        ),
        risk=Risk.LOW,
        related_settings=("max_header_count", "max_header_bytes", "max_url_length"),
        pages=(_LIMITS,),
        notes="Replaces Flask's MAX_CONTENT_LENGTH from v1, where only nginx enforced the 2 MiB limit.",
    ),
    SettingSpec(
        key="max_header_count",
        group=Group.ABUSE,
        label="Most request headers",
        type=SettingType.INT,
        default=100,
        unit="headers",
        min=10,
        max=200,
        step=1,
        description=(
            "The most headers one request may carry; requests with more are refused with 431 and logged as probes."
        ),
        if_raised="Clients that send unusually many headers are accepted; each request costs a little more to inspect.",
        if_lowered="More 431 refusals; some browsers and corporate proxies that add many headers may be refused.",
        risk=Risk.LOW,
        related_settings=("max_header_bytes", "max_body_bytes", "max_url_length"),
        pages=(_LIMITS,),
    ),
    SettingSpec(
        key="max_header_bytes",
        group=Group.ABUSE,
        label="Largest single header",
        type=SettingType.BYTES,
        default=8192,
        unit="bytes",
        min=1024,
        max=8192,
        step=256,
        description=(
            "The largest size of any one request header, name plus value; larger headers are refused with 431 "
            "and logged as probes. nginx already caps a header at 8 KiB, so this cannot go higher."
        ),
        if_raised="Longer headers, such as big cookies sent by browsers, are accepted, up to the 8 KiB nginx cap.",
        if_lowered="More 431 refusals, starting with browsers that send large cookies.",
        risk=Risk.LOW,
        related_settings=("max_header_count", "max_body_bytes", "max_url_length"),
        pages=(_LIMITS,),
    ),
    SettingSpec(
        key="max_url_length",
        group=Group.ABUSE,
        label="Longest URL",
        type=SettingType.INT,
        default=4096,
        unit="characters",
        min=256,
        max=8192,
        step=1,
        description=(
            "The longest request URL (path plus query string) Roxy accepts; longer ones are refused with 414 "
            "and logged as probes."
        ),
        if_raised="Longer URLs, such as long lists of ids in the query string, are accepted.",
        if_lowered="More 414 refusals; callers that put many ids in one URL must split their requests.",
        risk=Risk.LOW,
        related_settings=("max_body_bytes", "max_header_count", "max_header_bytes"),
        pages=(_LIMITS,),
    ),
]
